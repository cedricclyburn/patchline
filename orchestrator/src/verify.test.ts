import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { cp, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { loadPolicy } from "./policy.ts";
import { dependencyChanges, diffScope, parseTestCounts, runTests } from "./verify.ts";

const tmp = (p: string) => mkdtemp(join(tmpdir(), `patchline-${p}-`));

async function write(dir: string, files: Record<string, string>): Promise<void> {
  for (const [name, body] of Object.entries(files)) {
    await mkdir(dirname(join(dir, name)), { recursive: true });
    await writeFile(join(dir, name), body);
  }
}

test("pip: compares pins case-insensitively with -/_ normalised", async () => {
  const before = await tmp("before");
  const after = await tmp("after");
  await write(before, { "requirements.txt": "Flask==3.0.0\nPyYAML==5.3.1\ntyping_extensions==4.8.0\nrequests>=2\n# c\n" });
  await write(after, { "requirements.txt": "flask==3.1.3  # bumped\npyyaml==6.0.2\ntyping-extensions==4.8.0\nrequests>=2\n" });
  assert.deepEqual(await dependencyChanges(before, after, "pip"), [
    { pkg: "flask", from: "3.0.0", to: "3.1.3", major: false },
    { pkg: "pyyaml", from: "5.3.1", to: "6.0.2", major: true },
  ]);
});

test("npm: compares lockfile versions of top-level deps only", async () => {
  const pkg = JSON.stringify({ dependencies: { express: "^4.17.0" }, devDependencies: { mocha: "^10" } });
  const lock = (express: string, mocha: string, qs: string) =>
    JSON.stringify({
      packages: {
        "": {},
        "node_modules/express": { version: express },
        "node_modules/mocha": { version: mocha },
        "node_modules/qs": { version: qs },
      },
    });
  const before = await tmp("before");
  const after = await tmp("after");
  await write(before, { "package.json": pkg, "package-lock.json": lock("4.17.1", "10.0.0", "6.7.0") });
  await write(after, { "package.json": pkg, "package-lock.json": lock("5.0.0", "10.0.0", "6.11.0") });
  assert.deepEqual(await dependencyChanges(before, after, "npm"), [{ pkg: "express", from: "4.17.1", to: "5.0.0", major: true }]);
});

const git = (dir: string, ...args: string[]) => execFileSync("git", ["-C", dir, ...args], { encoding: "utf8" });

async function gitRepo(): Promise<string> {
  const dir = await tmp("git");
  git(dir, "init", "-q");
  git(dir, "config", "user.email", "t@example.invalid");
  git(dir, "config", "user.name", "t");
  await write(dir, {
    "requirements.txt": "Flask==3.0.0\n",
    "app/main.py": "x = 1\n",
    "tests/test_main.py": "def test_x(): pass\n",
    ".patchline/policy.json": "{}",
    ".gitignore": "node_modules/\n",
  });
  git(dir, "add", "-A");
  git(dir, "commit", "-qm", "base");
  return dir;
}

test("diffScope: in-scope edits plus untracked files pass", async () => {
  const dir = await gitRepo();
  await write(dir, { "requirements.txt": "Flask==3.1.3\n", "app/new.py": "", "node_modules/x/index.js": "" });
  const r = await diffScope(dir, "HEAD");
  assert.equal(r.ok, true, r.detail);
  assert.deepEqual(r.files, ["app/new.py", "requirements.txt"]);
  assert.match(r.stat, /requirements\.txt/);
});

test("diffScope: protected paths fail", async () => {
  for (const file of [".patchline/policy.json", ".github/workflows/ci.yml", ".gitea/x.yml", "Containerfile", "svc/Dockerfile"]) {
    const dir = await gitRepo();
    await write(dir, { [file]: "changed" });
    const r = await diffScope(dir, "HEAD");
    assert.equal(r.ok, false, file);
    assert.match(r.detail, /protected files changed/, file);
  }
});

test("diffScope: deleting or renaming away a test file fails", async () => {
  const dir = await gitRepo();
  await rm(join(dir, "tests/test_main.py"));
  const r = await diffScope(dir, "HEAD");
  assert.equal(r.ok, false);
  assert.match(r.detail, /test files deleted: tests\/test_main\.py/);

  const renamed = await gitRepo();
  git(renamed, "mv", "tests/test_main.py", "app/moved.py");
  assert.equal((await diffScope(renamed, "HEAD")).ok, false);
});

test("parseTestCounts reads pytest and node --test summaries", () => {
  assert.deepEqual(parseTestCounts("....\n1 failed, 4 passed in 0.31s\n"), { passed: 4, failed: 1 });
  assert.deepEqual(parseTestCounts("5 passed in 0.10s"), { passed: 5, failed: 0 });
  assert.deepEqual(parseTestCounts("ok 1 - a\n# tests 3\n# pass 2\n# fail 1\n"), { passed: 2, failed: 1 });
});

test("runTests runs telemetry-ingest in podman", { skip: !process.env.PODMAN_IT, timeout: 360_000 }, async () => {
  const src = fileURLToPath(new URL("../../demo/services/telemetry-ingest", import.meta.url));
  const dir = await tmp("it");
  await cp(src, dir, { recursive: true, filter: (p) => !/(__pycache__|\.pytest_cache)/.test(p) });
  const r = await runTests(dir, await loadPolicy(dir), "pip");
  assert.equal(r.ok, true, r.output);
  assert.equal(r.passed, 5);
  assert.equal(r.failed, 0);
});
