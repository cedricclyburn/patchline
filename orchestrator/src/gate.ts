import type { Check, DependencyChange, GateDecision, Policy, ReviewVerdict } from "./domain.ts";
import { CHECK_LABELS } from "./report.ts";

export interface GateInput {
  policy: Policy;
  checks: Check[];
  review: ReviewVerdict | null;
  changes: DependencyChange[];
}

type Kind = GateDecision["kind"];

interface Rule {
  decision: Kind;
  /** Reasons this rule applies; empty when it does not. */
  when: (i: GateInput) => string[];
}

const names = (cs: Check[]) => cs.map((c) => CHECK_LABELS[c.name].toLowerCase()).join(", ");
const ifTrue = (cond: boolean, reason: string) => (cond ? [reason] : []);

// Mirrors the gate table in docs/DESIGN.md.
const RULES: readonly Rule[] = [
  {
    decision: "blocked",
    when: (i) => {
      const failed = i.checks.filter((c) => c.state === "fail");
      return ifTrue(failed.length > 0, `Failed: ${names(failed)}`);
    },
  },
  {
    decision: "blocked",
    when: (i) => {
      const pending = i.checks.filter((c) => c.state === "pending");
      return ifTrue(pending.length > 0, `Not yet measured: ${names(pending)}`);
    },
  },
  { decision: "needs_approval", when: (i) => ifTrue(i.policy.failedClosed, `Policy file missing or invalid, so a human must approve (${i.policy.rationale})`) },
  { decision: "needs_approval", when: (i) => ifTrue(i.policy.approval === "needs_approval", "The repository policy requires a human approver") },
  {
    decision: "needs_approval",
    when: (i) => ifTrue(i.policy.riskClass === "HIGH" || i.policy.riskClass === "CRITICAL", `Risk class is ${i.policy.riskClass}`),
  },
  {
    decision: "needs_approval",
    when: (i) => {
      const major = i.changes.filter((c) => c.major);
      return ifTrue(major.length > 0, `Major version upgrade: ${major.map((c) => `${c.pkg} ${c.from} to ${c.to}`).join(", ")}`);
    },
  },
  { decision: "needs_approval", when: (i) => i.checks.filter((c) => c.state === "warn" && c.name !== "independent_review").map((c) => `${CHECK_LABELS[c.name]} flagged for a human`) },
  { decision: "needs_approval", when: (i) => ifTrue(i.review === null, "No independent review ran") },
  {
    decision: "needs_approval",
    when: (i) => ifTrue(i.review?.verdict === "concerns", `Reviewer (${i.review?.model ?? "model"}) raised concerns: ${i.review?.notes ?? ""}`),
  },
];

const PRECEDENCE: readonly Kind[] = ["blocked", "needs_approval"];

export function decide(i: GateInput): GateDecision {
  const hits = RULES.flatMap((r) => r.when(i).map((reason) => ({ decision: r.decision, reason })));
  for (const kind of PRECEDENCE) {
    const reasons = hits.filter((h) => h.decision === kind).map((h) => h.reason);
    if (reasons.length) return { kind, reasons };
  }
  return { kind: "auto_merge", reasons: ["Every check passed, risk is low, the reviewer approved, and policy allows auto-merge"] };
}
