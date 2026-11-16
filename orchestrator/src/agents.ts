// The three Cursor SDK agents. Model output lands only in TriageVerdict,
// ReviewVerdict and a summary string, and is validated before it leaves here.
import { execFile } from "node:child_process";
import { readdir, readFile, writeFile } from "node:fs/promises";
import { join, relative } from "node:path";
import { Agent, readOnlyFs, tempFs, unionFs } from "@cursor/sdk";
import type { FileSystem, ModelSelection, SDKCustomTool, SDKCustomToolResult, ToolName } from "@cursor/sdk";
import { z } from "zod";
import {
  vulnId,
  type AgentRole,
  type Ecosystem,
  type Finding,
  type PatchlineEvent,
  type Policy,
  type ReviewVerdict,
  type TriageVerdict,
} from "./domain.ts";

type Emit = (e: PatchlineEvent) => void;
export interface TestRun {
  ok: boolean;
  passed: number;
  failed: number;
  output: string;
}

const COMPOSER: ModelSelection = { id: "composer-2.5", params: [{ id: "fast", value: "false" }] };
const GROK: ModelSelection = {
  id: "grok-4.7",
  params: [
    { id: "context", value: "256k" },
    { id: "reasoning_effort", value: "medium" },
    { id: "fast", value: "false" },
  ],
};
/**
 * The reviewer is a different model family than the author, so the review is not the author grading
 * itself. Triage uses composer: on the same input it matched grok's verdicts in 23s vs 114s.
 */
export const MODELS: Record<AgentRole, ModelSelection> = { triage: COMPOSER, remediate: COMPOSER, review: GROK };
/** Past this the run is cancelled; triage and review then fall back to their fail-safe verdicts. */
const DEADLINE_MS: Record<AgentRole, number> = { triage: 90_000, remediate: 900_000, review: 150_000 };

// An allowlist, not disallowedTools: with only shell disallowed the agent ran shell through a `task`
// subagent. "mcp" is required for customTools; with no settingSources no other MCP servers load.
const READ_ONLY: ToolName[] = ["read", "grep", "glob", "ls", "mcp"];
const READ_WRITE: ToolName[] = [...READ_ONLY, "edit"]; // "edit" also grants Write (new files)

const SNAPSHOT_ROOT = "/repo";
const SKIP_DIRS = new Set([".git", "node_modules", "__pycache__", ".pytest_cache", ".venv", "venv", "dist", "build"]);

/**
 * In-memory read-only copy of the repo for the read-only agents. Host file tools read any path
 * (triage wandered into ~/.cache), and sandboxOptions only confines shell and writes; with
 * local.fs the agent sees nothing but this tree.
 */
async function repoSnapshot(dir: string): Promise<FileSystem> {
  const files: Record<string, string> = {};
  for (const e of await readdir(dir, { recursive: true, withFileTypes: true })) {
    const rel = relative(dir, join(e.parentPath, e.name));
    if (!e.isFile() || rel.split("/").some((part) => SKIP_DIRS.has(part))) continue;
    const buf = await readFile(join(dir, rel));
    if (buf.length <= 256 * 1024 && !buf.includes(0)) files[`/${rel}`] = buf.toString("utf8");
  }
  return unionFs({ [SNAPSHOT_ROOT]: readOnlyFs(tempFs(files)) });
}

// ---------- shared runner ----------

async function runAgent(o: {
  role: AgentRole;
  label?: string; // prefixes event text when several agents of one role run concurrently
  dir: string;
  fs?: FileSystem;
  prompt: string;
  tools: ToolName[];
  customTools: Record<string, SDKCustomTool>;
  emit: Emit;
  model?: ModelSelection;
}): Promise<string> {
  const apiKey = process.env.CURSOR_API_KEY;
  if (!apiKey) throw new Error("CURSOR_API_KEY is not set");
  const model = o.model ?? MODELS[o.role];
  const base = { role: o.role, model: model.id };
  const agent = await Agent.create({ apiKey, model, tools: o.tools, local: { cwd: o.dir, customTools: o.customTools, ...(o.fs && { fs: o.fs, reportedWorkspacePath: SNAPSHOT_ROOT }) } });
  const root = o.fs ? SNAPSHOT_ROOT : o.dir;
  const tag = o.label ? `[${o.label}] ` : "";
  let timer: NodeJS.Timeout | undefined;
  try {
    const run = await agent.send(o.prompt);
    timer = setTimeout(() => void run.cancel().catch(() => {}), DEADLINE_MS[o.role]);
    // Text and thinking arrive in fragments; flush one event per contiguous block.
    let buf: { kind: "text" | "thinking"; text: string } | null = null;
    const flush = () => {
      const text = buf && oneLine(buf.text, 600);
      if (buf && text) o.emit({ type: "agent", ...base, kind: buf.kind, text: tag + text });
      buf = null;
    };
    const append = (kind: "text" | "thinking", text: string) => {
      if (buf?.kind !== kind) flush();
      buf = { kind, text: (buf?.text ?? "") + text };
    };
    for await (const e of run.stream()) {
      if (e.type === "assistant") {
        for (const b of e.message.content) if (b.type === "text") append("text", b.text);
      } else if (e.type === "thinking") {
        append("thinking", e.text);
      } else if (e.type === "tool_call" && e.status !== "running") {
        flush();
        o.emit({ type: "agent", ...base, kind: "tool", text: tag + describeTool(root, e.name, e.status, e.args, e.result) });
      } else if (e.type === "status" && e.status === "ERROR" && e.message) {
        flush();
        o.emit({ type: "error", message: `${tag}${o.role} agent: ${e.message}` });
      }
    }
    flush();
    const r = await run.wait();
    const summary = r.result ?? "";
    o.emit({ type: "agent_done", ...base, status: r.status, durationMs: r.durationMs ?? 0, summary: tag + oneLine(summary, 2000) });
    if (r.status !== "finished") throw new Error(`${tag}${o.role} agent ${r.status}: ${r.error?.message ?? run.error?.message ?? "no detail"}`);
    return summary;
  } finally {
    clearTimeout(timer);
    agent.close();
  }
}

const oneLine = (s: string, max: number): string => {
  const t = s.replace(/\s+/g, " ").trim();
  return t.length > max ? `${t.slice(0, max - 1)}…` : t;
};

/** Tool args/results are an unstable internal shape: read them as unknown and narrow per field. */
const field = (v: unknown, k: string): unknown => (typeof v === "object" && v !== null ? Reflect.get(v, k) : undefined);
const str = (v: unknown): string | undefined => (typeof v === "string" && v ? v : undefined);

function describeTool(dir: string, name: string, status: string, args: unknown, result: unknown): string {
  const failed = status === "error" || field(result, "status") === "error" ? " (failed)" : "";
  if (name === "mcp") {
    const content = field(field(result, "value"), "content");
    const first: unknown = Array.isArray(content) ? content[0] : undefined;
    const text = str(field(field(first, "text"), "text")) ?? str(field(first, "text"));
    const out = text ? ` → ${oneLine(text.split("\n")[0] ?? "", 120)}` : "";
    return `${str(field(args, "toolName")) ?? "mcp"}${out}${failed}`;
  }
  const path = str(field(args, "path"));
  const target = str(field(args, "pattern")) ?? str(field(args, "globPattern")) ?? (path && (relative(dir, path) || "."));
  return `${name}${target ? ` ${oneLine(target, 120)}` : ""}${failed}`;
}

/** Numeric dotted-version compare; enough for picking the highest fixed version of one package. */
function compareVersions(a: string, b: string): number {
  const pa = a.split(/[.+-]/).map((x) => parseInt(x, 10) || 0);
  const pb = b.split(/[.+-]/).map((x) => parseInt(x, 10) || 0);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const d = (pa[i] ?? 0) - (pb[i] ?? 0);
    if (d) return d;
  }
  return 0;
}

// ---------- custom tools ----------

const err = (text: string): SDKCustomToolResult => ({ isError: true, content: [{ type: "text", text }] });
const zodWhy = (e: z.ZodError): string => e.issues.map((i) => `${i.path.join(".") || "(root)"}: ${i.message}`).join("; ");

function lookupAdvisory(findings: Finding[]): SDKCustomTool {
  return {
    description:
      "Return the scanner's advisory record (package, installed and fixed version, severity, title, url) for one vulnerability id. The only source of advisory data; unknown ids are an error.",
    inputSchema: { type: "object", properties: { id: { type: "string", description: "CVE-… or GHSA-… id" } }, required: ["id"] },
    execute: (args) => {
      const id = args.id;
      const hits = findings.filter((f) => f.id === id);
      if (hits.length === 0) return err(`unknown advisory id ${JSON.stringify(id)}. Known ids: ${[...new Set(findings.map((f) => f.id))].join(", ")}`);
      return JSON.stringify(hits.length === 1 ? hits[0] : hits, null, 2);
    },
  };
}

const VEX_STATUS = ["affected", "not_affected", "under_investigation"] as const;
const VEX_JUSTIFICATION = [
  "vulnerable_code_not_present",
  "vulnerable_code_not_in_execute_path",
  "vulnerable_code_cannot_be_controlled_by_adversary",
  "inline_mitigations_already_exist",
] as const;

const VerdictSchema = z
  .object({
    id: z.string(),
    status: z.enum(VEX_STATUS),
    justification: z.enum(VEX_JUSTIFICATION).nullish(),
    evidence: z.string().trim().min(1, "cite file:line evidence"),
  })
  .refine((v) => (v.status === "not_affected") === (v.justification != null), {
    message: "justification is required when status is not_affected and must be null otherwise",
    path: ["justification"],
  });

// ---------- triage ----------

/** One agent per package, concurrently; each covers only its package's advisories. */
export async function runTriage(dir: string, findings: Finding[], emit: Emit): Promise<TriageVerdict[]> {
  const fs = await repoSnapshot(dir);
  const pkgs = [...new Set(findings.map((f) => f.pkg))];
  const groups = await Promise.all(pkgs.map((pkg) => triagePackage(dir, fs, pkg, findings.filter((f) => f.pkg === pkg), emit)));
  return groups.flat();
}

async function triagePackage(dir: string, fs: FileSystem, pkg: string, findings: Finding[], emit: Emit): Promise<TriageVerdict[]> {
  const ids = [...new Set(findings.map((f) => f.id))];
  let recorded: TriageVerdict[] | null = null;

  const record_triage: SDKCustomTool = {
    description: "Record the final triage verdicts. Call exactly once, covering every advisory id exactly once.",
    inputSchema: {
      type: "object",
      required: ["verdicts"],
      properties: {
        verdicts: {
          type: "array",
          items: {
            type: "object",
            required: ["id", "status", "justification", "evidence"],
            properties: {
              id: { type: "string" },
              status: { type: "string", enum: [...VEX_STATUS] },
              justification: { type: ["string", "null"], enum: [...VEX_JUSTIFICATION, null], description: "Required iff status is not_affected" },
              evidence: { type: "string", description: "file:line references and one sentence of reasoning" },
            },
          },
        },
      },
    },
    execute: (args) => {
      const parsed = z.object({ verdicts: z.array(VerdictSchema) }).safeParse(args);
      if (!parsed.success) return err(`invalid verdicts: ${zodWhy(parsed.error)}`);
      const seen = parsed.data.verdicts.map((v) => v.id);
      const unknown = seen.filter((id) => !ids.some((k) => k === id));
      const missing = ids.filter((id) => !seen.includes(id));
      const dupes = seen.filter((id, i) => seen.indexOf(id) !== i);
      if (unknown.length || missing.length || dupes.length) {
        return err(`every advisory id must appear exactly once. unknown: [${unknown}] missing: [${missing}] duplicated: [${dupes}]`);
      }
      recorded = parsed.data.verdicts.map((v) => ({ id: vulnId(v.id), status: v.status, justification: v.justification ?? null, evidence: v.evidence }));
      return `recorded ${recorded.length} verdicts`;
    },
  };

  const prompt = `You are a security triage analyst. Decide, for each ${pkg} advisory below, whether the vulnerable code path in ${pkg} is reachable from THIS repository's code. Do not modify anything. Be quick: a handful of tool calls is enough.

Advisories for ${pkg} ${findings[0]?.installed ?? ""} (id: title):
${findings.map((f) => `- ${f.id}: ${f.title}`).join("\n")}

Deployment context: services run in Linux containers (python:3.12-slim / node:22-slim). An advisory that only applies on another OS (e.g. Windows device names or path separators) is not_affected with vulnerable_code_not_present or vulnerable_code_not_in_execute_path.

Method:
1. lookup_advisory returns the scanner's record for an id. It is the only source of advisory data: never invent ids, versions or scores.
2. The repository is mounted read-only at /repo and nothing else is there. Read only its application code, tests and manifests (grep for imports and calls of ${pkg}). Do not look for or read library sources, site-packages or caches; reason from the advisory text and your knowledge of ${pkg}'s public API plus how the repo uses it.
3. Choose an OpenVEX status:
   - affected: the vulnerable function or feature is used on a path reachable from the repo's entry points.
   - not_affected: you can show it is not; give a justification (${VEX_JUSTIFICATION.join(", ")}).
   - under_investigation: you cannot tell with confidence. Prefer this over guessing not_affected.
4. evidence: file:line references from this repo (e.g. app/profiles.py:38) plus one sentence of reasoning.
5. Call record_triage once with a verdict for every id (${ids.length} ids). If it returns an error, fix the input and call it again.`;

  try {
    await runAgent({ role: "triage", label: pkg, dir, fs, prompt,
      tools: READ_ONLY, customTools: { lookup_advisory: lookupAdvisory(findings), record_triage }, emit });
  } catch (e) {
    emit({ type: "error", message: e instanceof Error ? e.message : String(e) });
  }
  if (recorded) return recorded;
  emit({ type: "error", message: `${pkg} triage ended without a valid record_triage; marking its findings under_investigation` });
  return ids.map((id) => ({ id, status: "under_investigation", justification: null, evidence: "triage agent produced no valid verdict" }));
}

// ---------- dependency changes ----------

const LOCKFILE = "package-lock.json";
const NPM_NAME = /^(@[a-z0-9][\w.~-]*\/)?[a-z0-9][\w.~-]*$/i;
const VERSION = /^\d+(\.\d+)*([-+.][0-9a-z.-]+)?$/i;
const pipName = (s: string) => s.toLowerCase().replace(/[-_.]+/g, "-");

/**
 * The only way the remediation agent changes a version. npm locks are regenerated by npm in a
 * container, never written by the model (it invented integrity hashes when it could).
 */
function setDependency(dir: string, eco: Ecosystem, findings: Finding[], onLock: (lock: string) => void): SDKCustomTool {
  const run = async (name: string, version: string): Promise<string> => {
    if (eco === "pip") {
      const path = join(dir, findings[0]?.target ?? "requirements.txt");
      const lines = (await readFile(path, "utf8")).split("\n");
      const i = lines.findIndex((l) => pipName(l.split(/[=<>~!\[;\s]/)[0] ?? "") === pipName(name));
      const pin = `${name}==${version}`;
      if (i >= 0) lines[i] = pin;
      else lines.splice(lines.at(-1) === "" ? -1 : lines.length, 0, pin);
      await writeFile(path, lines.join("\n"));
      return `${relative(dir, path)}: ${pin}`;
    }
    // A transitive package gets an `overrides` pin; making it a direct dependency would not change the copy its parent uses.
    const pkgPath = join(dir, "package.json");
    const pkg: unknown = JSON.parse(await readFile(pkgPath, "utf8"));
    const direct = ["dependencies", "devDependencies", "optionalDependencies"].some((k) => field(field(pkg, k), name) !== undefined);
    let how = "direct dependency";
    if (!direct && typeof pkg === "object" && pkg !== null) {
      const overrides = field(pkg, "overrides");
      Reflect.set(pkg, "overrides", { ...(typeof overrides === "object" && overrides !== null ? overrides : {}), [name]: version });
      await writeFile(pkgPath, `${JSON.stringify(pkg, null, 2)}\n`);
      how = "override (transitive)";
    }
    const args = ["run", "--rm", "-v", `${dir}:/w:Z`, "-w", "/w", "-v", "patchline-npm-cache:/root/.npm:z", "docker.io/library/node:22-slim"];
    const npm = ["npm", "install", "--package-lock-only", "--no-audit", "--no-fund", ...(direct ? ["--save-exact", `${name}@${version}`] : [])];
    const out = await new Promise<string>((done, fail) =>
      execFile("podman", [...args, ...npm], { timeout: 300_000, maxBuffer: 16 << 20 }, (e, stdout, stderr) =>
        e ? fail(new Error(`${stderr || stdout || e.message}`.slice(-4000))) : done(stdout),
      ),
    );
    const lock = await readFile(join(dir, LOCKFILE), "utf8");
    onLock(lock);
    const packages = field(JSON.parse(lock), "packages");
    const entries = typeof packages === "object" && packages !== null ? Object.entries(packages) : [];
    const resolved = [...new Set(findings.map((f) => f.pkg))].map((p) => {
      const versions = entries.filter(([path]) => path === `node_modules/${p}` || path.endsWith(`/node_modules/${p}`)).map(([path, e]) => `${str(field(e, "version"))} (${path})`);
      return `${p}: ${versions.join(", ") || "absent"}`;
    });
    return `${name}@${version} set as ${how}. ${out.trim().slice(-500)}\nEvery resolved copy of the flagged packages:\n${resolved.join("\n")}`;
  };
  return {
    description:
      eco === "npm"
        ? "Pin a package to an exact version and regenerate package-lock.json with npm. A direct dependency is pinned in package.json; a transitive one gets a package.json `overrides` entry so every copy in the tree uses it. Returns every resolved copy of each flagged package."
        : "Pin a package to an exact version (name==version) in the requirements manifest, adding the line if absent.",
    inputSchema: { type: "object", required: ["name", "version"], properties: { name: { type: "string" }, version: { type: "string", description: "exact version, e.g. 4.17.21" } } },
    execute: async (args) => {
      const parsed = z.object({ name: z.string().regex(NPM_NAME), version: z.string().regex(VERSION) }).safeParse(args);
      if (!parsed.success) return err(`invalid input: ${zodWhy(parsed.error)}`);
      try {
        return await run(parsed.data.name, parsed.data.version);
      } catch (e) {
        return err(`set_dependency failed: ${e instanceof Error ? e.message : String(e)}`);
      }
    },
  };
}

const readOrNull = (path: string) => readFile(path, "utf8").catch(() => null);

// ---------- remediation ----------

export async function runRemediation(o: {
  dir: string;
  findings: Finding[];
  verdicts: TriageVerdict[];
  policy: Policy;
  eco: Ecosystem;
  emit: Emit;
  runTests: () => Promise<TestRun>;
  feedback?: string | undefined;
}): Promise<{ summary: string }> {
  // Any lockfile content other than what npm last produced via set_dependency is a model edit: revert it.
  const lockPath = join(o.dir, LOCKFILE);
  let lock = await readOrNull(lockPath);
  const revertLockEdits = async (): Promise<string> => {
    if (o.eco !== "npm" || lock === null || (await readOrNull(lockPath)) === lock) return "";
    await writeFile(lockPath, lock);
    o.emit({ type: "error", message: `remediate agent edited ${LOCKFILE} by hand; reverted` });
    return `NOTE: your manual edit to ${LOCKFILE} was reverted. Change versions only with set_dependency.\n`;
  };

  const run_tests: SDKCustomTool = {
    description: `Install the dependencies and run the test suite (\`${o.policy.test}\`) in the same container the merge gate uses. Takes no arguments. Returns pass/fail counts and the output tail.`,
    inputSchema: { type: "object", properties: {} },
    execute: async () => {
      const note = await revertLockEdits();
      const r = await o.runTests();
      return `${note}${r.ok ? "PASS" : "FAIL"}: ${r.passed} passed, ${r.failed} failed\n\n${r.output.slice(-12000)}`;
    },
  };

  const status = new Map(o.verdicts.map((v) => [v.id, v.status]));
  const minimum = new Map<string, string>();
  for (const f of o.findings) {
    const cur = minimum.get(f.pkg);
    if (f.fixed && (!cur || compareVersions(f.fixed, cur) > 0)) minimum.set(f.pkg, f.fixed);
  }
  const manifests = [...new Set(o.findings.map((f) => f.target))];
  const prompt = `You are remediating vulnerable ${o.eco} dependencies in the repository in the working directory. You have file tools and three custom tools: lookup_advisory (scanner advisory data), set_dependency (the only way to change a dependency version) and run_tests (the only way to install and test). There is no shell.

Findings (id, package installed → fixed, severity, triage status):
${o.findings.map((f) => `- ${f.id} ${f.pkg} ${f.installed} → ${f.fixed ?? "no fix published"} ${f.severity} [${status.get(f.id) ?? "under_investigation"}]`).join("\n")}
Manifests: ${manifests.join(", ")}
Minimum safe version per package (highest fixed version across its findings): ${[...minimum].map(([p, v]) => `${p}>=${v}`).join(", ") || "none"}

Rules:
1. Pin every package listed under "Minimum safe version" to at least that version (the latest patch release in that line is fine); a lower pin leaves a finding open. Change versions only with set_dependency, never by editing manifests or lockfiles yourself; never touch ${LOCKFILE}. For a transitive dependency, first upgrade the direct dependency that pulls it in (staying on its major version when a fix exists there); if a flagged package still resolves below its fix anywhere, call set_dependency on that package to add an override. Never add a transitive package as a new direct dependency. A fixed release in the same major line as the installed version is preferable to a major bump. If that version cannot be installed or is incompatible with the runtime, move to the lowest newer release that works, including a new major version. Keep other pinned packages compatible (e.g. a framework that requires a newer version of an upgraded library).
2. Adapt the application code to breaking API changes in the upgraded packages so behavior is preserved. Use what you know of the package's changelog; check that the code still does what the existing tests expect. Do not add new input limits, validation or other behavior changes when the upgrade itself fixes the issue.
3. For each finding triaged "affected", add a regression test when feasible without network access. It must fail on the vulnerable version: use an input the vulnerable code actually accepts (the advisory's known exploit pattern), not one the old version already rejected, and assert the fixed code rejects it.
4. Never delete, skip or weaken existing tests or assertions. Never edit .patchline/, CI configuration, Containerfile/Dockerfile, or files unrelated to the fix.
5. Call run_tests after your edits, fix what fails, and repeat until it reports PASS.
6. Finish with a short plain-text summary: each version change and why, each code change and why, and tests added. No markdown headings.${
    o.feedback ? `\n\nA previous attempt failed the deterministic verification checks below. Fix these:\n${o.feedback}` : ""
  }`;

  const summary = await runAgent({
    role: "remediate",
    dir: o.dir,
    prompt,
    tools: READ_WRITE,
    customTools: {
      lookup_advisory: lookupAdvisory(o.findings),
      set_dependency: setDependency(o.dir, o.eco, o.findings, (l) => (lock = l)),
      run_tests,
    },
    emit: o.emit,
  }).finally(revertLockEdits);
  return { summary };
}

// ---------- review ----------

export async function runReview(dir: string, diff: string, findings: Finding[], emit: Emit, measured = ""): Promise<ReviewVerdict> {
  const byPkg = new Map<string, Finding[]>();
  for (const f of findings) byPkg.set(f.pkg, [...(byPkg.get(f.pkg) ?? []), f]);
  const advisories = [...byPkg].map(([pkg, fs]) => {
    const fixed = fs.map((f) => f.fixed).filter((v): v is string => v !== null).sort(compareVersions).at(-1) ?? "none";
    return `- ${pkg} ${fs[0]?.installed} needs >= ${fixed}: ${fs.map((f) => `${f.id} (${f.title})`).join("; ")}`;
  });
  const prompt = `You are an adversarial security reviewer. Another model wrote this patch to remediate the advisories below. Find what is wrong with it. You have no file access: reason from the diff, the advisories and your knowledge of these libraries.

Advisories by package:
${advisories.join("\n")}

\`\`\`diff
${diff}
\`\`\`
${measured ? `\nMeasured by the pipeline (deterministic, already verified; the lockfile is regenerated by a tool and omitted from the diff):\n${measured}\n` : ""}
Version coverage is not your job: the measured facts above are authoritative, and a package the rescan reports cleared is fixed, including transitive packages you cannot see in the diff. Review only what measurement cannot see: (1) the vulnerable usage in application code is gone or no longer exploitable; (2) behavior does not change beyond the fix; (3) added tests would fail on the vulnerable version and no test was weakened. Then call record_review once: "approve" if all three hold, otherwise "concerns" naming the specific problem, with two to five sentences of notes.`;

  // Hedged review: the cross-family reviewer is preferred, the same-family one bounds latency.
  const attempt = (model: ModelSelection, label: string) => {
    let recorded: ReviewVerdict | null = null;
    const record_review: SDKCustomTool = {
      description: "Record the final review verdict. Call exactly once.",
      inputSchema: {
        type: "object",
        required: ["verdict", "notes"],
        properties: { verdict: { type: "string", enum: ["approve", "concerns"] }, notes: { type: "string" } },
      },
      execute: (args) => {
        const parsed = z.object({ verdict: z.enum(["approve", "concerns"]), notes: z.string().trim().min(1) }).safeParse(args);
        if (!parsed.success) return err(`invalid review: ${zodWhy(parsed.error)}`);
        recorded = { ...parsed.data, model: model.id };
        return "review recorded";
      },
    };
    return runAgent({ role: "review", label, model, dir, prompt, tools: ["mcp"], customTools: { record_review }, emit })
      .catch((e: unknown) => emit({ type: "error", message: e instanceof Error ? e.message : String(e) }))
      .then(() => recorded);
  };
  const [cross, same] = await Promise.all([attempt(MODELS.review, "cross-family"), attempt(COMPOSER, "same-family")]);
  if (cross) return cross;
  if (same) return { ...same, notes: `${same.notes} (Cross-family reviewer ${MODELS.review.id} gave no verdict in time; this verdict is from ${same.model}, the author's model family.)` };
  return { verdict: "concerns", notes: "no reviewer returned a valid verdict", model: MODELS.review.id };
}
