import assert from "node:assert/strict";
import { test } from "node:test";
import type { Check, CheckName, CheckState, Policy, ReviewVerdict } from "./domain.ts";
import { decide, type GateInput } from "./gate.ts";

const policy: Policy = { owner: "t", riskClass: "LOW", rationale: "r", approval: "auto_approve", test: "pytest -q", failedClosed: false };
const approve: ReviewVerdict = { verdict: "approve", notes: "lgtm", model: "grok-4.7" };
const check = (name: CheckName, state: CheckState = "pass"): Check => ({ name, state, detail: "" });
const green = [check("baseline_tests"), check("patched_tests"), check("diff_scope"), check("no_new_vulns", "skipped")];
const base: GateInput = { policy, checks: green, review: approve, changes: [{ pkg: "a", from: "1.0.0", to: "1.0.1", major: false }] };

test("auto-merges when everything is green and policy allows it", () => {
  assert.equal(decide(base).kind, "auto_merge");
});

test("a failed or pending check blocks regardless of policy, with all blocking reasons", () => {
  const d = decide({
    ...base,
    policy: { ...policy, approval: "needs_approval" },
    checks: [...green, check("patched_tests", "fail"), check("independent_review", "pending")],
  });
  assert.equal(d.kind, "blocked");
  assert.deepEqual(d.reasons, ["Failed: tests after patch", "Not yet measured: independent model review"]);
});

test("each approval condition alone routes to needs_approval", () => {
  const cases: [string, Partial<GateInput>][] = [
    ["failed closed", { policy: { ...policy, failedClosed: true } }],
    ["policy approval", { policy: { ...policy, approval: "needs_approval" } }],
    ["Risk class is HIGH", { policy: { ...policy, riskClass: "HIGH" } }],
    ["riskClass CRITICAL", { policy: { ...policy, riskClass: "CRITICAL" } }],
    ["major bump", { changes: [{ pkg: "pyyaml", from: "5.3.1", to: "6.0.2", major: true }] }],
    ["reviewer concerns", { review: { ...approve, verdict: "concerns", notes: "touches auth" } }],
    ["missing review", { review: null }],
  ];
  for (const [label, over] of cases) {
    const d = decide({ ...base, ...over });
    assert.equal(d.kind, "needs_approval", label);
    assert.equal(d.reasons.length, 1, label);
  }
});

test("collects every needs_approval reason", () => {
  const d = decide({
    ...base,
    policy: { ...policy, riskClass: "HIGH", approval: "needs_approval" },
    changes: [{ pkg: "pyyaml", from: "5.3.1", to: "6.0.2", major: true }],
    review: null,
  });
  assert.deepEqual(d, {
    kind: "needs_approval",
    reasons: ["The repository policy requires a human approver", "Risk class is HIGH", "Major version upgrade: pyyaml 5.3.1 to 6.0.2", "No independent review ran"],
  });
});

test("a warn check never blocks but forces needs_approval", () => {
  const warned = decide({ ...base, checks: [...green, check("test_count_not_reduced", "warn")] });
  assert.deepEqual(warned, { kind: "needs_approval", reasons: ["Test count not reduced flagged for a human"] });

  const failedToo = decide({ ...base, checks: [...green, check("no_new_vulns", "warn"), check("diff_scope", "fail")] });
  assert.deepEqual(failedToo, { kind: "blocked", reasons: ["Failed: diff touches only allowed files"] });
});
