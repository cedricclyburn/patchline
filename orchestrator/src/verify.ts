import { execFile } from "node:child_process";
import { access, readFile } from "node:fs/promises";
import { basename, join, resolve } from "node:path";
import { promisify } from "node:util";
import { z } from "zod";
import type { DependencyChange, Ecosystem, Policy } from "./domain.ts";

const exec = promisify(execFile);
const exists = (p: string) => access(p).then(() => true, () => false);

// ---------- tests in a container ----------

const TEST_TIMEOUT_MS = 300_000;

async function containerCommand(
  dir: string,
  policy: Policy,
  eco: Ecosystem,
): Promise<{ image: string; cache: string; env: string[]; script: string }> {
  if (eco === "pip") {
    const reqs = (await exists(join(dir, "requirements-dev.txt"))) ? "requirements-dev.txt" : "requirements.txt";
    return {
      image: "docker.io/library/python:3.12-slim",
      // Shared (lowercase z) SELinux label so concurrent runs can share the cache volume.
      cache: "patchline-pip-cache:/root/.cache/pip:z",
      // The bare `pytest` entry point does not put the repo root on sys.path the way `python -m pytest` does.
      env: ["PYTHONPATH=/w", "PIP_ROOT_USER_ACTION=ignore"],
      script: `pip install -q --disable-pip-version-check -r ${reqs} && ${policy.test}`,
    };
  }
  return {
    image: "docker.io/library/node:22-slim",
    cache: "patchline-npm-cache:/root/.npm:z",
    env: [],
    script: `npm ci --no-audit --no-fund && ${policy.test}`,
  };
}

/** Last occurrence of a count in the output, so pip/npm noise earlier on cannot win. */
function lastCount(output: string, re: RegExp): number {
  const all = [...output.matchAll(re)];
  const last = all.at(-1)?.[1];
  return last === undefined ? 0 : Number(last);
}

export function parseTestCounts(output: string): { passed: number; failed: number } {
  // pytest: "== 1 failed, 4 passed in 0.12s ==". node --test: "# pass 5" (TAP) or "ℹ pass 5" (spec).
  const passed = lastCount(output, /(\d+) passed\b/g) || lastCount(output, /^(?:#|ℹ) pass (\d+)/gm);
  const failed = lastCount(output, /(\d+) failed\b/g) || lastCount(output, /^(?:#|ℹ) fail (\d+)/gm);
  return { passed, failed };
}

export async function runTests(
  dir: string,
  policy: Policy,
  eco: Ecosystem,
): Promise<{ ok: boolean; passed: number; failed: number; output: string }> {
  const { image, cache, env, script } = await containerCommand(dir, policy, eco);
  const args = ["run", "--rm", ...env.flatMap((e) => ["-e", e]), "-v", `${resolve(dir)}:/w:Z`, "-v", cache, "-w", "/w", image, "sh", "-c", `exec 2>&1; ${script}`];
  const { code, output } = await new Promise<{ code: number | null; output: string }>((done) => {
    execFile("podman", args, { timeout: TEST_TIMEOUT_MS, maxBuffer: 64 * 1024 * 1024 }, (err, stdout, stderr) => {
      const text = `${stdout}${stderr}`;
      if (!err) return done({ code: 0, output: text });
      const timedOut = "killed" in err && err.killed;
      const code = typeof err.code === "number" ? err.code : null;
      done({ code, output: timedOut ? `${text}\npatchline: test run timed out after ${TEST_TIMEOUT_MS / 1000}s` : `${text}\n${err.message}` });
    });
  });
  const { passed, failed } = parseTestCounts(output);
  return { ok: code === 0 && failed === 0, passed, failed, output: output.slice(-4000) };
}

// ---------- dependency changes ----------

const normalise = (name: string) => name.toLowerCase().replace(/[-_.]+/g, "-");

async function pipPins(dir: string): Promise<Map<string, { name: string; version: string }>> {
  const text = await readFile(join(dir, "requirements.txt"), "utf8");
  const pins = new Map<string, { name: string; version: string }>();
  for (const line of text.split("\n")) {
    const m = /^\s*([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*==\s*([^\s;#]+)/.exec(line);
    if (m?.[1] && m[2]) pins.set(normalise(m[1]), { name: m[1], version: m[2] });
  }
  return pins;
}

const PackageJson = z.object({
  dependencies: z.record(z.string(), z.string()).optional(),
  devDependencies: z.record(z.string(), z.string()).optional(),
});
const PackageLock = z.object({
  packages: z.record(z.string(), z.object({ version: z.string().optional() })),
});

async function npmVersions(dir: string): Promise<Map<string, { name: string; version: string }>> {
  const pkg = PackageJson.parse(JSON.parse(await readFile(join(dir, "package.json"), "utf8")));
  const lock = PackageLock.parse(JSON.parse(await readFile(join(dir, "package-lock.json"), "utf8")));
  const out = new Map<string, { name: string; version: string }>();
  for (const name of Object.keys({ ...pkg.dependencies, ...pkg.devDependencies })) {
    const version = lock.packages[`node_modules/${name}`]?.version;
    if (version) out.set(name, { name, version });
  }
  return out;
}

const majorOf = (v: string) => Number(/^\D*(\d+)/.exec(v)?.[1] ?? NaN);

export async function dependencyChanges(beforeDir: string, afterDir: string, eco: Ecosystem): Promise<DependencyChange[]> {
  const read = eco === "pip" ? pipPins : npmVersions;
  const [before, after] = await Promise.all([read(beforeDir), read(afterDir)]);
  const changes: DependencyChange[] = [];
  for (const [key, a] of after) {
    const b = before.get(key);
    if (!b || b.version === a.version) continue;
    changes.push({ pkg: a.name, from: b.version, to: a.version, major: majorOf(a.version) > majorOf(b.version) });
  }
  return changes;
}

// ---------- diff scope ----------

const DENY_PREFIXES = [".patchline/", ".gitea/", ".github/"];
const DENY_NAMES = new Set(["Containerfile", "Dockerfile"]);

const denied = (f: string) => DENY_PREFIXES.some((p) => f.startsWith(p)) || DENY_NAMES.has(basename(f));
const isTestFile = (f: string) =>
  /(^|\/)(tests?|__tests__)\//.test(f) || /^(test_.*\.py|.*_test\.py|.*\.(test|spec)\.[cm]?[jt]sx?)$/.test(basename(f));

async function git(dir: string, ...args: string[]): Promise<string[]> {
  const { stdout } = await exec("git", ["-C", dir, ...args], { maxBuffer: 64 * 1024 * 1024 });
  return stdout.split("\n").filter(Boolean);
}

export async function diffScope(dir: string, baseRef: string): Promise<{ ok: boolean; files: string[]; detail: string; stat: string }> {
  // --no-renames so a renamed-away test file still shows up as a deletion.
  const [changed, untracked, deleted, stat] = await Promise.all([
    git(dir, "diff", "--no-renames", "--name-only", baseRef),
    git(dir, "ls-files", "--others", "--exclude-standard"),
    git(dir, "diff", "--no-renames", "--diff-filter=D", "--name-only", baseRef),
    git(dir, "diff", "--no-renames", "--stat", baseRef),
  ]);
  const files = [...new Set([...changed, ...untracked])].sort();
  const problems: string[] = [];
  const outOfScope = files.filter(denied);
  if (outOfScope.length) problems.push(`protected files changed: ${outOfScope.join(", ")}`);
  const deletedTests = deleted.filter(isTestFile);
  if (deletedTests.length) problems.push(`test files deleted: ${deletedTests.join(", ")}`);
  return {
    ok: problems.length === 0,
    files,
    detail: problems.length ? problems.join("; ") : `${files.length} file(s) changed, all in scope`,
    stat: stat.join("\n"),
  };
}
