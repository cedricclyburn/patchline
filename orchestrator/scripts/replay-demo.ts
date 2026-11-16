// Synthetic ledger for developing and demoing the dashboard without live agents.
//   node scripts/replay-demo.ts                writes .patchline-work/demo-ledger.jsonl
//   node scripts/replay-demo.ts --live [N]     starts the server and streams the same story at N× speed (default 6)
// Scanner data for telemetry-ingest comes from the real Trivy fixture; gate decisions come from the real gate.
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import {
  type AgentRole,
  type Check,
  type CheckName,
  type CheckState,
  type DependencyChange,
  type Finding,
  type PatchlineEvent,
  type Policy,
  type RemediationId,
  type RepoName,
  type ReviewVerdict,
  type StampedEvent,
  type TriageVerdict,
  type VexJustification,
  remediationId,
  repoName,
  vulnId,
} from "../src/domain.ts";
import { decide } from "../src/gate.ts";
import { parseTrivy } from "../src/scan.ts";

const WORK = fileURLToPath(new URL("../../.patchline-work/", import.meta.url));
const FORGE = "http://localhost:3000/patchline";

interface Step {
  t: number; // ms from story start
  rem: RemediationId;
  repo: RepoName;
  event: PatchlineEvent;
}

/** Builds one remediation's timeline; `wait` advances the clock between events. */
function timeline(repo: RepoName, startAt: Date, offset: number) {
  const rem = remediationId(`${repo}@${startAt.toISOString()}`);
  const steps: Step[] = [];
  let t = offset;
  const checks = new Map<CheckName, Check>();
  return {
    steps,
    checks,
    wait: (ms: number) => void (t += ms),
    emit(event: PatchlineEvent, after = 400) {
      t += after;
      steps.push({ t, rem, repo, event });
      if (event.type === "check") checks.set(event.check.name, event.check);
    },
    stage(stage: Extract<PatchlineEvent, { type: "stage" }>["stage"], note?: string, after = 300) {
      this.emit(note ? { type: "stage", stage, note } : { type: "stage", stage }, after);
    },
    check(name: CheckName, state: CheckState, detail: string, after = 700) {
      this.emit({ type: "check", check: { name, state, detail } }, after);
    },
    /** Agent transcript lines: [kind, text, ms before it]. */
    agent(role: AgentRole, model: string, lines: [Extract<PatchlineEvent, { type: "agent" }>["kind"], string, number][]) {
      for (const [kind, text, ms] of lines) this.emit({ type: "agent", role, model, kind, text }, ms);
    },
  };
}

const finding = (id: string, pkg: string, installed: string, fixed: string, severity: Finding["severity"], cvss: number | null, title: string): Finding => ({
  id: vulnId(id),
  pkg,
  ecosystem: "npm",
  installed,
  fixed,
  severity,
  cvss,
  title,
  url: `https://avd.aquasec.com/nvd/${id.toLowerCase()}`,
  target: "package-lock.json",
});

const verdict = (id: string, status: TriageVerdict["status"], evidence: string, justification: VexJustification | null = null): TriageVerdict => ({
  id: vulnId(id),
  status,
  justification,
  evidence,
});

function supplierPortal(start: Date, offset: number): Step[] {
  const repo = repoName("supplier-portal");
  const r = timeline(repo, start, offset);
  const policy: Policy = {
    owner: "supply-chain-eng",
    riskClass: "LOW",
    rationale: "Internal read-mostly portal for supplier part lookups and quote requests; no flight data, no write path into ERP.",
    approval: "auto_approve",
    test: "npm test",
    failedClosed: false,
  };
  const findings = [
    finding("CVE-2021-23337", "lodash", "4.17.20", "4.17.21", "HIGH", 7.2, "lodash: command injection via template"),
    finding("CVE-2020-28500", "lodash", "4.17.20", "4.17.21", "MEDIUM", 5.3, "lodash: ReDoS via the toNumber, trim and trimEnd functions"),
    finding("CVE-2024-45590", "body-parser", "1.19.0", "1.20.3", "HIGH", 7.5, "body-parser: denial of service when url encoding is enabled"),
    finding("CVE-2022-24999", "qs", "6.7.0", "6.7.3", "HIGH", 7.5, "express: qs prototype pollution causes denial of service"),
    finding("CVE-2024-45296", "path-to-regexp", "0.1.7", "0.1.10", "HIGH", 7.5, "path-to-regexp: backtracking regular expressions cause ReDoS"),
    finding("CVE-2024-29041", "express", "4.17.1", "4.19.2", "MEDIUM", 6.1, "express: open redirect in malformed URLs"),
    finding("CVE-2024-43796", "express", "4.17.1", "4.20.0", "LOW", 5.0, "express: improper input handling in redirects"),
    finding("CVE-2024-47764", "cookie", "0.4.0", "0.7.0", "LOW", null, "cookie: accepts cookie name, path and domain with out of bounds characters"),
    finding("CVE-2024-43799", "send", "0.17.1", "0.19.0", "LOW", 5.0, "send: code execution vulnerability in send"),
  ];

  r.stage("scanning", undefined, 0);
  r.emit({ type: "policy", policy }, 1800);
  r.check("policy", "pass", "LOW, auto_approve, owner supply-chain-eng", 50);
  r.emit({ type: "findings", findings }, 4200);
  r.emit({ type: "incident", url: `${FORGE}/supplier-portal/issues/7`, number: 7 }, 900);

  r.stage("triaging");
  r.agent("triage", "grok-4.7", [
    ["thinking", "Nine fixable findings across lodash, express and its transitive deps. Start with direct usage of lodash.", 1600],
    ["tool", "grep _.template src/", 1400],
    ["tool", "read src/app.js:1-40", 900],
    ["text", "src/app.js:10 compiles a fixed template string at module load. No user input reaches the template source, but the options object is library default and the advisory concerns `options.variable` injection.", 2600],
    ["tool", "lookup_advisory CVE-2021-23337", 1100],
    ["thinking", "Template source is constant; still affected in the strict sense because the vulnerable function is called. Mark affected, the fix is a patch bump.", 2200],
    ["tool", "grep toNumber|trim src/", 1000],
    ["text", "_.trim is applied to req.query.q at src/app.js:36, which is attacker controlled. ReDoS in trim applies.", 1900],
    ["tool", "read src/app.js:25-33", 800],
    ["text", "express.json() is used; urlencoded parser is not mounted, so body-parser's urlencoded DoS path is unreachable. qs still parses req.query on every GET.", 2400],
    ["tool", "grep res.redirect|res.cookie|sendFile|static src/", 1200],
    ["text", "No redirects, cookies or static file serving anywhere in src/.", 1300],
    ["tool", "record_triage 9 verdicts", 900],
  ]);
  r.emit({ type: "agent_done", role: "triage", model: "grok-4.7", status: "finished", durationMs: 24100, summary: "5 affected, 4 not affected" }, 400);
  r.emit({
    type: "triage",
    verdicts: [
      verdict("CVE-2021-23337", "affected", "src/app.js:10 calls _.template at module load"),
      verdict("CVE-2020-28500", "affected", "src/app.js:36 _.trim on req.query.q (attacker controlled)"),
      verdict("CVE-2024-45590", "not_affected", "src/app.js:29 mounts express.json only; urlencoded parser never used", "vulnerable_code_not_in_execute_path"),
      verdict("CVE-2022-24999", "affected", "express parses req.query with qs on every request (src/app.js:35)"),
      verdict("CVE-2024-45296", "affected", "src/app.js:51 route /parts/:partNumber compiled by path-to-regexp"),
      verdict("CVE-2024-29041", "not_affected", "no res.redirect or res.location in src/", "vulnerable_code_not_present"),
      verdict("CVE-2024-43796", "not_affected", "no res.redirect in src/", "vulnerable_code_not_present"),
      verdict("CVE-2024-47764", "not_affected", "no cookie parsing or res.cookie in src/", "vulnerable_code_not_present"),
      verdict("CVE-2024-43799", "not_affected", "no res.sendFile or express.static in src/", "vulnerable_code_not_present"),
    ],
  }, 300);
  r.check("baseline_tests", "pass", "7 passed, 0 failed on the unpatched code", 1500);

  r.stage("remediating");
  r.agent("remediate", "composer-2.5", [
    ["thinking", "All findings resolve inside express 4.x and lodash 4.17.x. Prefer the smallest bump that clears every advisory.", 1800],
    ["tool", "lookup_advisory CVE-2024-45296", 1200],
    ["text", "path-to-regexp 0.1.10 and qs 6.13.0 ship with express 4.21.x. express 4.21.2 clears every express-chain finding without leaving the 4.x line.", 2600],
    ["tool", "read package.json", 700],
    ["tool", "edit package.json  express 4.17.1 → 4.21.2", 1500],
    ["tool", "edit package.json  lodash 4.17.20 → 4.17.21", 900],
    ["tool", "write package-lock.json (regenerated, 6 transitive bumps)", 3400],
    ["tool", "run_tests", 1200],
    ["text", "run_tests: 7 passed, 0 failed (npm test, 1.1s)", 3100],
    ["text", "Bumped express to 4.21.2 and lodash to 4.17.21. No source changes required.", 1200],
  ]);
  r.emit({ type: "agent_done", role: "remediate", model: "composer-2.5", status: "finished", durationMs: 31200, summary: "express 4.21.2, lodash 4.17.21; no source changes" }, 400);

  r.stage("verifying");
  r.check("patched_tests", "pass", "7 passed, 0 failed", 3800);
  r.check("targeted_vulns_cleared", "pass", "9 of 9 cleared", 4100);
  r.check("no_new_vulns", "pass", "rescan shows nothing new", 300);
  r.check("test_count_not_reduced", "pass", "7 before, 7 after", 300);
  r.check("diff_scope", "pass", "2 files, manifests only: package.json, package-lock.json", 500);

  const changes: DependencyChange[] = [
    { pkg: "express", from: "4.17.1", to: "4.21.2", major: false },
    { pkg: "lodash", from: "4.17.20", to: "4.17.21", major: false },
    { pkg: "body-parser", from: "1.19.0", to: "1.20.3", major: false },
    { pkg: "qs", from: "6.7.0", to: "6.13.0", major: false },
    { pkg: "path-to-regexp", from: "0.1.7", to: "0.1.12", major: false },
    { pkg: "cookie", from: "0.4.0", to: "0.7.1", major: false },
    { pkg: "send", from: "0.17.1", to: "0.19.0", major: false },
  ];
  r.emit({ type: "changes", changes, diffStat: " package-lock.json | 212 ++++++++++++++-------------\n package.json      |   4 +-\n 2 files changed, 110 insertions(+), 106 deletions(-)" }, 900);

  r.stage("reviewing");
  r.agent("review", "grok-4.7", [
    ["tool", "read package.json", 1300],
    ["thinking", "Author was composer-2.5. Check the lockfile resolves what the manifest claims, and that nothing outside manifests moved.", 2000],
    ["tool", "grep \"version\" package-lock.json", 1200],
    ["text", "Lockfile resolves express 4.21.2 with path-to-regexp 0.1.12 and qs 6.13.0. Manifest-only diff, minor and patch bumps, within the 4.x line.", 2700],
    ["tool", "record_review approve", 900],
  ]);
  const review: ReviewVerdict = { verdict: "approve", notes: "Manifest-only diff; express stays on 4.x; lockfile matches manifest. No behaviour change expected for /parts or /quotes.", model: "grok-4.7" };
  r.emit({ type: "agent_done", role: "review", model: "grok-4.7", status: "finished", durationMs: 9400, summary: "approve" }, 400);
  r.emit({ type: "review", review }, 200);
  r.check("independent_review", "pass", "grok-4.7: approve", 200);

  r.stage("gating");
  r.emit({ type: "gate", decision: decide({ policy, checks: [...r.checks.values()], review, changes }) }, 600);
  r.emit({ type: "pr", url: `${FORGE}/supplier-portal/pulls/8`, number: 8, branch: "patchline/3f9c2a71e0b4" }, 2100);
  r.stage("merged", undefined, 1400);
  r.stage("deploying", undefined, 600);
  r.emit({ type: "deploy", status: "started", detail: "ansible-playbook deploy.yml @ 8c41d07" }, 800);
  r.emit({ type: "deploy", status: "healthy", detail: "GET :8082/healthz 200 in 41 ms, 3 of 3 probes" }, 9200);
  r.stage("deployed", undefined, 200);
  return r.steps;
}

function telemetryIngest(start: Date, offset: number): Step[] {
  const repo = repoName("telemetry-ingest");
  const r = timeline(repo, start, offset);
  const policy: Policy = {
    owner: "flight-software",
    riskClass: "HIGH",
    rationale: "Ingests mission profiles used by flight ops; malformed parsing affects launch-day tooling.",
    approval: "needs_approval",
    test: "pytest -q",
    failedClosed: false,
  };
  const fixture = fileURLToPath(new URL("../src/__fixtures__/trivy-telemetry.json", import.meta.url));
  const findings = parseTrivy(JSON.parse(readFileSync(fixture, "utf8")));
  const notExec = "vulnerable_code_not_in_execute_path" satisfies VexJustification;
  const windowsOnly = "Containerfile:1 python:3.12-slim (Linux); safe_join never called in app/";
  const sandbox = "app/report.py:3 uses Environment, not SandboxedEnvironment; templates are constants";
  const evidence: Record<string, [TriageVerdict["status"], string, VexJustification | null]> = {
    "CVE-2020-14343": ["affected", "app/profiles.py:37 yaml.load(document) on request body from server.py:17 POST /profiles", null],
    "CVE-2024-34069": ["not_affected", "server.py:33 app.run without debug=True; debugger never enabled", notExec],
    "CVE-2024-49766": ["not_affected", windowsOnly, notExec],
    "CVE-2024-49767": ["affected", "server.py:17 request.get_data parses untrusted bodies", null],
    "CVE-2025-66221": ["not_affected", windowsOnly, notExec],
    "CVE-2026-102598": ["not_affected", windowsOnly, notExec],
    "CVE-2026-21860": ["not_affected", windowsOnly, notExec],
    "CVE-2026-27199": ["not_affected", windowsOnly, notExec],
    "CVE-2024-22195": ["not_affected", "xmlattr filter not used in app/report.py", "vulnerable_code_not_present"],
    "CVE-2024-34064": ["not_affected", "xmlattr filter not used in app/report.py", "vulnerable_code_not_present"],
    "CVE-2024-56201": ["not_affected", sandbox, "vulnerable_code_not_present"],
    "CVE-2024-56326": ["not_affected", sandbox, "vulnerable_code_not_present"],
    "CVE-2025-27516": ["not_affected", sandbox, "vulnerable_code_not_present"],
    "CVE-2026-27205": ["under_investigation", "no session use found; caching proxy config lives outside this repo", null],
  };
  const verdicts = findings.map((f) => {
    const [status, ev, justification] = evidence[f.id] ?? ["under_investigation", "not examined", null];
    return verdict(f.id, status, ev, justification);
  });

  r.stage("scanning", undefined, 0);
  r.emit({ type: "policy", policy }, 1600);
  r.check("policy", "pass", "HIGH, needs_approval, owner flight-software", 50);
  r.emit({ type: "findings", findings }, 5200);
  r.emit({ type: "incident", url: `${FORGE}/telemetry-ingest/issues/12`, number: 12 }, 800);

  r.stage("triaging");
  r.agent("triage", "grok-4.7", [
    ["thinking", "14 fixable findings. PyYAML CVE-2020-14343 is CRITICAL; check how profiles are loaded first.", 1500],
    ["tool", "grep yaml\\. app/", 1100],
    ["tool", "read app/profiles.py", 800],
    ["text", "app/profiles.py:37 calls yaml.load(document) with no Loader. On 5.3.1 that is FullLoader, which can construct arbitrary Python objects via !!python/object/new.", 2900],
    ["tool", "read app/server.py", 900],
    ["text", "POST /profiles feeds request.get_data() straight into parse_profile. Untrusted input reaches the vulnerable loader: affected.", 2300],
    ["tool", "lookup_advisory CVE-2024-34069", 1000],
    ["tool", "grep debug|safe_join app/ Containerfile", 1200],
    ["text", "No debug=True and no safe_join. Seven Werkzeug safe_join findings are Windows-only device-name bugs; the image is python:3.12-slim.", 2600],
    ["tool", "read app/report.py", 900],
    ["text", "Jinja2 uses a plain Environment with constant templates and no xmlattr; sandbox breakouts do not apply.", 2100],
    ["thinking", "Flask CVE-2026-27205 concerns caching of session responses. The app sets no session, but proxy caching is configured elsewhere. Leave under_investigation.", 2400],
    ["tool", "record_triage 14 verdicts", 900],
  ]);
  r.emit({ type: "agent_done", role: "triage", model: "grok-4.7", status: "finished", durationMs: 27600, summary: "2 affected, 11 not affected, 1 under investigation" }, 400);
  r.emit({ type: "triage", verdicts }, 300);
  r.check("baseline_tests", "pass", "5 passed, 0 failed on the unpatched code", 1900);

  r.stage("remediating");
  r.agent("remediate", "composer-2.5", [
    ["tool", "lookup_advisory CVE-2020-14343", 1400],
    ["thinking", "Fixed in 5.4, but 6.0.3 is the maintained line and the only one with wheels for 3.12. Werkzeug 3.1.x needs Flask 3.1.", 2400],
    ["tool", "read requirements.txt", 700],
    ["tool", "edit requirements.txt  PyYAML 5.3.1 → 6.0.3", 1300],
    ["tool", "edit requirements.txt  Werkzeug 3.0.1 → 3.1.9", 800],
    ["tool", "edit requirements.txt  Flask 3.0.0 → 3.1.3", 800],
    ["tool", "edit requirements.txt  Jinja2 3.1.2 → 3.1.6", 800],
    ["text", "Version bumps applied. The advisory lists no API change for the loader path, so no source edits.", 1700],
  ]);
  r.emit({ type: "agent_done", role: "remediate", model: "composer-2.5", status: "finished", durationMs: 18900, summary: "4 version bumps; no source changes" }, 400);

  r.stage("verifying");
  r.check("patched_tests", "fail", "2 passed, 3 failed\nFAILED tests/test_profiles.py::test_parses_vector_tags - TypeError: load() missing 1 required positional argument: 'Loader'\nFAILED tests/test_profiles.py::test_rejects_untagged_position - TypeError: load() missing 1 required positional argument: 'Loader'\nFAILED tests/test_profiles.py::test_upload_and_report_roundtrip - TypeError: load() missing 1 required positional argument: 'Loader'", 5600);
  r.check("targeted_vulns_cleared", "pass", "14 of 14 cleared", 4300);
  r.check("no_new_vulns", "pass", "rescan shows nothing new", 300);
  r.check("test_count_not_reduced", "pass", "5 before, 5 after", 300);
  r.check("diff_scope", "pass", "1 file: requirements.txt", 400);

  r.stage("remediating", "retry 2 with verifier feedback", 900);
  r.agent("remediate", "composer-2.5", [
    ["text", "Verifier feedback: patched_tests failed. PyYAML 6 made Loader a required argument to yaml.load.", 1200],
    ["thinking", "Passing FullLoader would restore the vulnerable behaviour. Use a SafeLoader subclass and register !vector on it only, so the custom tag survives and python/* tags are rejected.", 3100],
    ["tool", "read app/profiles.py", 700],
    ["tool", "edit app/profiles.py  class ProfileLoader(yaml.SafeLoader); add_constructor on ProfileLoader", 2200],
    ["tool", "edit app/profiles.py:37  yaml.load(document, Loader=ProfileLoader)", 1100],
    ["tool", "edit tests/test_profiles.py  add test_rejects_python_object_tags", 1900],
    ["tool", "run_tests", 900],
    ["text", "run_tests: 6 passed, 0 failed (pytest -q, 0.43s)", 2700],
    ["text", "Loader is now an explicit SafeLoader subclass. Added a regression test proving !!python/object/apply is rejected.", 1300],
  ]);
  r.emit({ type: "agent_done", role: "remediate", model: "composer-2.5", status: "finished", durationMs: 21400, summary: "SafeLoader subclass for !vector; regression test added" }, 400);

  r.stage("verifying");
  r.check("patched_tests", "pass", "6 passed, 0 failed", 4900);
  r.check("targeted_vulns_cleared", "pass", "14 of 14 cleared", 4000);
  r.check("no_new_vulns", "pass", "rescan shows nothing new", 300);
  r.check("test_count_not_reduced", "pass", "5 before, 6 after", 300);
  r.check("diff_scope", "pass", "3 files: requirements.txt, app/profiles.py, tests/test_profiles.py", 400);

  const changes: DependencyChange[] = [
    { pkg: "PyYAML", from: "5.3.1", to: "6.0.3", major: true },
    { pkg: "Flask", from: "3.0.0", to: "3.1.3", major: false },
    { pkg: "Werkzeug", from: "3.0.1", to: "3.1.9", major: false },
    { pkg: "Jinja2", from: "3.1.2", to: "3.1.6", major: false },
  ];
  r.emit({ type: "changes", changes, diffStat: " app/profiles.py         |  9 +++++++--\n requirements.txt        |  8 ++++----\n tests/test_profiles.py  | 10 ++++++++++\n 3 files changed, 21 insertions(+), 6 deletions(-)" }, 900);

  r.stage("reviewing");
  r.agent("review", "grok-4.7", [
    ["tool", "read app/profiles.py", 1200],
    ["thinking", "Constructor is registered on ProfileLoader, not the global loader. Check nothing else in the repo calls yaml.load.", 2200],
    ["tool", "grep yaml.load|yaml.unsafe_load .", 1000],
    ["text", "Only call site is profiles.py:37 and it now passes Loader=ProfileLoader. The regression test covers !!python/object/apply.", 2600],
    ["thinking", "Behaviour change: any producer emitting python/* tags or YAML 1.1 merge quirks will now get a 400. That is the point of the fix but flight ops should confirm no tooling depends on it.", 2900],
    ["tool", "record_review concerns", 900],
  ]);
  const review: ReviewVerdict = {
    verdict: "concerns",
    notes: "Fix is correct and narrower than FullLoader. Profiles carrying python/* tags will now be rejected with 400; confirm no flight-ops producer emits them before merge.",
    model: "grok-4.7",
  };
  r.emit({ type: "agent_done", role: "review", model: "grok-4.7", status: "finished", durationMs: 12300, summary: "concerns" }, 400);
  r.emit({ type: "review", review }, 200);
  r.check("independent_review", "warn", "grok-4.7: concerns (routes to a human)", 200);

  r.stage("gating");
  r.emit({ type: "gate", decision: decide({ policy, checks: [...r.checks.values()], review, changes }) }, 600);
  r.emit({ type: "pr", url: `${FORGE}/telemetry-ingest/pulls/13`, number: 13, branch: "patchline/b71e04c9d2a6" }, 2300);
  r.stage("awaiting_approval", "PR #13 waits for a flight-software approver", 300);
  return r.steps;
}

function story(now: number): Step[] {
  const start = new Date(now);
  const steps = [...supplierPortal(start, 0), ...telemetryIngest(new Date(now + 9000), 9000)];
  return steps.sort((a, b) => a.t - b.t);
}

const stamp = (s: Step, seq: number, at: Date): StampedEvent => ({ ...s.event, remediation: s.rem, repo: s.repo, at: at.toISOString(), seq });

async function live(speed: number): Promise<void> {
  const path = `${WORK}demo-live.jsonl`;
  mkdirSync(WORK, { recursive: true });
  writeFileSync(path, "");
  process.env.LEDGER_PATH = path;
  const { ledger } = await import("../src/pipeline.ts");
  await import("../src/server.ts");
  const steps = story(Date.now());
  let clock = 0;
  for (const s of steps) {
    await new Promise((r) => setTimeout(r, (s.t - clock) / speed));
    clock = s.t;
    ledger.append(s.rem, s.repo, s.event);
  }
  console.log(`[replay-demo] streamed ${steps.length} events; server keeps running (Ctrl-C to stop)`);
}

function write(): void {
  const total = story(0).at(-1)?.t ?? 0;
  const begin = Date.now() - total - 60_000;
  const lines = story(begin).map((s, i) => JSON.stringify(stamp(s, i + 1, new Date(begin + s.t))));
  mkdirSync(WORK, { recursive: true });
  writeFileSync(`${WORK}demo-ledger.jsonl`, lines.join("\n") + "\n");
  console.log(`[replay-demo] wrote ${lines.length} events to ${WORK}demo-ledger.jsonl`);
  console.log(`  view: LEDGER_PATH="${WORK}demo-ledger.jsonl" npm start`);
}

const liveAt = process.argv.indexOf("--live");
if (liveAt === -1) write();
else await live(Number(process.argv[liveAt + 1]) || 6);
