import assert from "node:assert/strict";
import { mkdir, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { loadPolicy } from "./policy.ts";

async function repo(files: Record<string, string>): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "patchline-policy-"));
  await mkdir(join(dir, ".patchline"));
  for (const [name, body] of Object.entries(files)) await writeFile(join(dir, name), body);
  return dir;
}

const valid = { owner: "team-a", riskClass: "LOW", rationale: "internal tool", approval: "auto_approve", test: "pytest -q tests" };

test("loads a valid policy", async () => {
  const dir = await repo({ ".patchline/policy.json": JSON.stringify(valid), "requirements.txt": "" });
  assert.deepEqual(await loadPolicy(dir), { ...valid, failedClosed: false });
});

test("valid policy without test falls back to the detected command", async () => {
  const { test: _, ...rest } = valid;
  const dir = await repo({ ".patchline/policy.json": JSON.stringify(rest), "package.json": "{}" });
  assert.equal((await loadPolicy(dir)).test, "npm test");
});

test("missing policy fails closed with a pip default test", async () => {
  const dir = await repo({ "requirements-dev.txt": "" });
  const p = await loadPolicy(dir);
  assert.equal(p.failedClosed, true);
  assert.equal(p.approval, "needs_approval");
  assert.equal(p.riskClass, "HIGH");
  assert.equal(p.owner, "unknown");
  assert.equal(p.test, "pytest -q");
  assert.match(p.rationale, /^policy missing or invalid: .*ENOENT/);
});

test("malformed JSON and schema violations fail closed", async () => {
  const broken = await repo({ ".patchline/policy.json": "{ not json", "package.json": "{}" });
  const b = await loadPolicy(broken);
  assert.equal(b.failedClosed, true);
  assert.equal(b.test, "npm test");

  const wrong = await repo({ ".patchline/policy.json": JSON.stringify({ ...valid, riskClass: "TRIVIAL" }) });
  const w = await loadPolicy(wrong);
  assert.equal(w.failedClosed, true);
  assert.equal(w.approval, "needs_approval");
  assert.match(w.rationale, /riskClass/);
});

test("the demo telemetry-ingest policy loads", async () => {
  const p = await loadPolicy(fileURLToPath(new URL("../../demo/services/telemetry-ingest", import.meta.url)));
  assert.equal(p.failedClosed, false);
  assert.equal(p.owner, "flight-software");
  assert.equal(p.test, "pytest -q");
});
