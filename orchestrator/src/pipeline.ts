import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { cp, mkdir, readFile, rm } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { z } from "zod";

import { runRemediation, runReview, runTriage } from "./agents.ts";
import {
  type Check,
  type Ecosystem,
  type Finding,
  type PatchlineEvent,
  type RemediationId,
  type RepoName,
  type Stage,
  remediationId,
} from "./domain.ts";
import * as forge from "./forge.ts";
import { decide } from "./gate.ts";
import { Ledger } from "./ledger.ts";
import { loadPolicy } from "./policy.ts";
import { fold, renderPrBody } from "./report.ts";
import { scanRepo } from "./scan.ts";
import { dependencyChanges, diffScope, runTests } from "./verify.ts";

const sh = promisify(execFile);
const ROOT = fileURLToPath(new URL("../../", import.meta.url));
const WORK = join(ROOT, ".patchline-work");
const MAX_ATTEMPTS = 2;

export const ledger = new Ledger(process.env.LEDGER_PATH ?? join(WORK, "ledger.jsonl"));

/** Host port each service is deployed on. Lives here, not in policy, because ops owns it. */
const DEPLOY_PORT: Record<string, number> = { "telemetry-ingest": 8081, "supplier-portal": 8082 };

const active = new Set<RepoName>();
const deployed = new Set<string>();

export const repos = (): Promise<RepoName[]> => forge.listOrgRepos();

export async function remediate(repo: RepoName): Promise<Stage> {
  if (active.has(repo)) return "queued";
  active.add(repo);
  const id = remediationId(`${repo}@${new Date().toISOString()}`);
  const emit = ledger.emitterFor(id, repo);
  const stage = (s: Stage, note?: string): Stage => (emit({ type: "stage", stage: s, note }), s);
  try {
    return await run(id, repo, emit, stage);
  } catch (err) {
    emit({ type: "error", message: err instanceof Error ? err.message : String(err) });
    return stage("failed");
  } finally {
    active.delete(repo);
  }
}

async function run(
  id: RemediationId,
  repo: RepoName,
  emit: (e: PatchlineEvent) => void,
  stage: (s: Stage, note?: string) => Stage,
): Promise<Stage> {
  const check = (c: Check) => emit({ type: "check", check: c });
  const dir = join(WORK, safe(id));
  const work = join(dir, "repo");
  const base = join(dir, "base");
  await rm(dir, { recursive: true, force: true });
  await mkdir(dir, { recursive: true });

  stage("scanning");
  await forge.cloneRepo(repo, work);
  const policy = await loadPolicy(work);
  emit({ type: "policy", policy });
  check({ name: "policy", state: "pass", detail: policy.failedClosed ? `${policy.rationale}; failing closed to needs_approval` : `${policy.riskClass}, ${policy.approval}, owner ${policy.owner}` });

  const findings = await scanRepo(work);
  emit({ type: "findings", findings });
  const fixable = findings.filter((f) => f.fixed !== null);
  if (fixable.length === 0) return stage("nothing_to_do", findings.length ? "no published fixes" : "no known vulnerabilities");

  const branch = `patchline/${fingerprint(fixable)}`;
  const existing = await forge.findOpenPullRequest(repo, branch);
  if (existing) {
    emit({ type: "pr", url: existing.url, number: existing.number, branch });
    return stage("nothing_to_do", "a pull request for this exact finding set is already open");
  }

  const eco = ecosystemOf(fixable);
  const incident = await forge.createIssue(
    repo,
    `[Patchline] ${fixable.length} fixable vulnerabilities in ${repo}`,
    incidentBody(repo, fixable),
    ["patchline", "security"],
  );
  emit({ type: "incident", url: incident.url, number: incident.number });

  await cp(work, base, { recursive: true });

  stage("triaging");
  const [verdicts, baseline] = await Promise.all([
    runTriage(work, fixable, emit),
    runTests(base, policy, eco),
  ]);
  emit({ type: "triage", verdicts });
  check({ name: "baseline_tests", state: baseline.ok ? "pass" : "fail", detail: `${baseline.passed} passed, ${baseline.failed} failed on the unpatched code` });
  if (!baseline.ok) {
    await forge.commentIssue(repo, incident.number, "Baseline tests fail before any change, so a patch cannot be validated. Escalating to the owning team.");
    return stage("escalated", "baseline tests already failing");
  }

  let feedback: string | undefined;
  let failures: Check[] = [];
  let targets = fixable; // grows with fixable vulnerabilities a previous attempt introduced
  for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
    stage("remediating", attempt > 1 ? `retry ${attempt} with verifier feedback` : undefined);
    await runRemediation({ dir: work, findings: targets, verdicts, policy, eco, emit, feedback, runTests: () => runTests(work, policy, eco) });

    stage("verifying");
    const result = await verify(work, targets, findings, baseline.passed, policy, eco, check);
    failures = result.failures;
    if (failures.length === 0) break;
    targets = [...targets, ...result.introduced.filter((f) => f.fixed !== null)];
    feedback = failures.map((c) => `- ${c.name}: ${c.detail}`).join("\n");
  }
  if (failures.length > 0) {
    await forge.commentIssue(repo, incident.number, `Patchline could not produce a passing patch after ${MAX_ATTEMPTS} attempts:\n\n${feedback}`);
    return stage("escalated", "checks still failing after retry");
  }

  const changes = await dependencyChanges(base, work, eco);
  await git(work, "checkout", "-b", branch);
  await git(work, "add", "-A");
  await git(work, "-c", "user.name=Patchline", "-c", "user.email=patchline@localhost.test", "commit", "-m", commitMessage(fixable, changes));
  // Lockfiles are regenerated by a tool and verified by `npm ci`; the reviewer reads intent, not hashes.
  const { stdout: diff } = await git(work, "diff", "HEAD~1", "HEAD", "--", ".", ":(exclude)package-lock.json");
  const { stdout: stat } = await git(work, "diff", "--stat", "HEAD~1", "HEAD");
  emit({ type: "changes", changes, diffStat: stat });

  stage("reviewing");
  const measured = [
    ...[...fold(ledger.history(id)).checks.values()].filter((c) => c.state === "pass").map((c) => `- ${c.name}: ${c.detail.split("\n")[0]}`),
    ...changes.map((c) => `- resolved ${c.pkg} ${c.from} -> ${c.to}`),
  ].join("\n");
  const review = await runReview(work, diff, targets, emit, measured);
  emit({ type: "review", review });
  check({
    name: "independent_review",
    state: review.verdict === "approve" ? "pass" : "warn",
    detail: `${review.model}: ${review.verdict}${review.verdict === "concerns" ? " (routes to a human)" : ""}`,
  });

  stage("gating");
  const view = fold(ledger.history(id));
  const decision = decide({ policy, checks: [...view.checks.values()], review, changes });
  emit({ type: "gate", decision });

  await forge.pushBranch(work, branch);
  const riskLabel = policy.riskClass === "LOW" ? "risk:low" : "risk:high";
  const pr = await forge.openPullRequest(repo, {
    head: branch,
    base: "main",
    title: `fix(deps): remediate ${fixable.length} vulnerabilities (${policy.riskClass === "LOW" ? "🟢" : "🔴"} ${policy.riskClass})`,
    body: renderPrBody(fold(ledger.history(id)), { repo, riskClass: policy.riskClass, incidentUrl: incident.url }),
    labels: ["patchline", "security", riskLabel, decision.kind === "auto_merge" ? "auto-merged" : "needs-approval"],
  });
  emit({ type: "pr", url: pr.url, number: pr.number, branch });
  await forge.commentIssue(repo, incident.number, `Pull request opened: ${pr.url}\n\nGate: **${decision.kind}**\n${decision.reasons.map((r) => `- ${r}`).join("\n")}`);

  if (decision.kind === "auto_merge") {
    await forge.mergePullRequest(repo, pr.number, { style: "squash", message: commitMessage(fixable, changes) });
    stage("merged");
    return deploy(id, repo, pr.number, incident.number, emit, stage);
  }
  return stage(decision.kind === "blocked" ? "escalated" : "awaiting_approval");
}

async function verify(
  work: string,
  targeted: Finding[],
  before: Finding[],
  baselinePassed: number,
  policy: Awaited<ReturnType<typeof loadPolicy>>,
  eco: Ecosystem,
  check: (c: Check) => void,
): Promise<{ failures: Check[]; introduced: Finding[] }> {
  const results: Check[] = [];
  const record = (c: Check) => (check(c), results.push(c));

  const [tests, after, scope] = await Promise.all([runTests(work, policy, eco), scanRepo(work), diffScope(work, "HEAD")]);
  record({ name: "patched_tests", state: tests.ok ? "pass" : "fail", detail: `${tests.passed} passed, ${tests.failed} failed${tests.ok ? "" : `\n${tests.output.slice(-1500)}`}` });

  const key = (f: Finding) => `${f.id}|${f.pkg}`;
  const afterKeys = new Set(after.map(key));
  const remaining = targeted.filter((f) => afterKeys.has(key(f)));
  record({
    name: "targeted_vulns_cleared",
    state: remaining.length === 0 ? "pass" : "fail",
    detail: remaining.length === 0 ? `${targeted.length} of ${targeted.length} cleared` : `still present: ${remaining.map(describe).join(", ")}`,
  });

  const beforeKeys = new Set(before.map(key));
  const introduced = after.filter((f) => !beforeKeys.has(key(f)));
  record({ name: "no_new_vulns", state: introduced.length === 0 ? "pass" : "fail", detail: introduced.length === 0 ? "rescan shows nothing new" : `introduced: ${introduced.map(describe).join(", ")}` });

  record({ name: "test_count_not_reduced", state: tests.passed + tests.failed >= baselinePassed ? "pass" : "fail", detail: `${baselinePassed} before, ${tests.passed + tests.failed} after` });
  record({ name: "diff_scope", state: scope.ok ? "pass" : "fail", detail: scope.detail });

  return { failures: results.filter((c) => c.state === "fail"), introduced };
}

export async function onMerged(repo: RepoName, prNumber: number): Promise<void> {
  const prEvent = ledger.history().findLast((e) => e.type === "pr" && e.repo === repo && e.number === prNumber);
  if (!prEvent) return;
  const incident = ledger.history(prEvent.remediation).findLast((e) => e.type === "incident");
  const emit = ledger.emitterFor(prEvent.remediation, repo);
  const stage = (s: Stage, note?: string): Stage => (emit({ type: "stage", stage: s, note }), s);
  stage("merged", "merged by a human reviewer");
  await deploy(prEvent.remediation, repo, prNumber, incident?.type === "incident" ? incident.number : null, emit, stage);
}

async function deploy(
  id: RemediationId,
  repo: RepoName,
  prNumber: number,
  incidentNumber: number | null,
  emit: (e: PatchlineEvent) => void,
  stage: (s: Stage, note?: string) => Stage,
): Promise<Stage> {
  const key = `${repo}#${prNumber}`;
  if (deployed.has(key)) return "deployed";
  deployed.add(key);

  stage("deploying");
  const src = join(WORK, safe(id), "deploy");
  await rm(src, { recursive: true, force: true });
  await forge.cloneRepo(repo, src);
  const { stdout: sha } = await git(src, "rev-parse", "--short", "HEAD");
  emit({ type: "deploy", status: "started", detail: `ansible-playbook deploy.yml @ ${sha.trim()}` });

  const result = await ansibleDeploy(repo, src, sha.trim());
  emit({ type: "deploy", status: result.status, detail: result.detail });
  if (incidentNumber !== null) {
    await forge.commentIssue(repo, incidentNumber, `Deploy ${result.status}: ${result.detail}`);
    if (result.status === "healthy") await forge.closeIssue(repo, incidentNumber);
  }
  return stage(result.status === "healthy" ? "deployed" : "rolled_back");
}

async function ansibleDeploy(repo: RepoName, src: string, sha: string): Promise<{ status: "healthy" | "rolled_back"; detail: string }> {
  const port = DEPLOY_PORT[repo] ?? 8090;
  const resultFile = join(src, "..", "deploy-result.json");
  // JSON extra-vars because the checkout path can contain spaces.
  const extra = JSON.stringify({ service: repo, source_dir: src, port, git_sha: `${sha}-${Date.now().toString(36)}`, result_file: resultFile });
  const ansibleDir = join(ROOT, "ansible");
  await sh("ansible-playbook", ["deploy.yml", "-e", extra], {
    cwd: ansibleDir,
    env: { ...process.env, ANSIBLE_CONFIG: join(ansibleDir, "ansible.cfg") },
    maxBuffer: 20e6,
  }).catch(() => undefined); // non-zero exit means not healthy; the result file says why
  const parsed = DeployResult.parse(await readFile(resultFile, "utf8").then((s) => JSON.parse(s), () => ({})));
  if (parsed.status === "healthy") return { status: "healthy", detail: `${parsed.image} healthy on :${port}` };
  return { status: "rolled_back", detail: `${parsed.status ?? "no result"}; running ${parsed.previous ?? "nothing"}` };
}

const DeployResult = z.object({ status: z.string().optional(), image: z.string().optional(), previous: z.string().nullish() });

const describe = (f: Finding) => `${f.id} (${f.pkg} ${f.installed}, ${f.fixed ? `fixed in ${f.fixed}` : "no fix published"})`;

const git = (cwd: string, ...args: string[]) => sh("git", args, { cwd, maxBuffer: 20e6 });
const safe = (id: string) => id.replace(/[^a-zA-Z0-9.-]/g, "_");
const fingerprint = (fs: Finding[]) =>
  createHash("sha256").update(fs.map((f) => `${f.id}|${f.pkg}|${f.installed}`).sort().join("\n")).digest("hex").slice(0, 10);

function ecosystemOf(fs: Finding[]): Ecosystem {
  const ecos = new Set(fs.map((f) => f.ecosystem));
  const [only] = ecos;
  if (ecos.size !== 1 || !only) throw new Error(`mixed ecosystems in one repo are not supported yet: ${[...ecos].join(", ")}`);
  return only;
}

function commitMessage(fs: Finding[], changes: { pkg: string; from: string; to: string }[]): string {
  const ids = [...new Set(fs.map((f) => f.id))];
  return `fix(deps): remediate ${ids.length} vulnerabilities\n\n${changes.map((c) => `- ${c.pkg} ${c.from} -> ${c.to}`).join("\n")}\n\nAdvisories: ${ids.join(", ")}`;
}

function incidentBody(repo: string, fs: Finding[]): string {
  const rows = fs.map((f) => `| ${f.id} | ${f.pkg} ${f.installed} | ${f.fixed} | ${f.severity} |`).join("\n");
  return `Patchline opened this incident before any analysis so every step below is recorded as it happens.\n\nRepository: \`${repo}\`\n\n| Advisory | Installed | Fixed in | Severity |\n|---|---|---|---|\n${rows}`;
}
