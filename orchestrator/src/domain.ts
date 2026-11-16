// Core data shapes. Everything security-relevant here comes from deterministic
// sources (scanner, policy file, test runs). Model output only ever lands in
// TriageVerdict, ReviewVerdict and AgentSummary, and never decides a merge.

export type Brand<T, B extends string> = T & { readonly __brand: B };
export type RepoName = Brand<string, "RepoName">;
export type RemediationId = Brand<string, "RemediationId">;
export type VulnId = Brand<string, "VulnId">; // CVE-… or GHSA-…

export const repoName = (s: string): RepoName => s as RepoName;
export const vulnId = (s: string): VulnId => s as VulnId;
export const remediationId = (s: string): RemediationId => s as RemediationId;

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "UNKNOWN";
export type Ecosystem = "pip" | "npm";

/** One scanner hit. Parsed once from Trivy JSON at the boundary. */
export interface Finding {
  id: VulnId;
  pkg: string;
  ecosystem: Ecosystem;
  installed: string;
  fixed: string | null; // null = no fix published
  severity: Severity;
  cvss: number | null;
  title: string;
  url: string | null;
  target: string; // manifest file, e.g. requirements.txt
}

/** .patchline/policy.json, reviewed like code. Missing or malformed fails closed. */
export interface Policy {
  owner: string;
  riskClass: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  rationale: string;
  approval: "auto_approve" | "needs_approval";
  test: string; // command run inside the verification container
  failedClosed: boolean; // true when the file was missing or invalid
}

/** Reachability call from the triage agent, expressed in OpenVEX vocabulary. */
export type VexStatus = "affected" | "not_affected" | "under_investigation";
export type VexJustification =
  | "vulnerable_code_not_present"
  | "vulnerable_code_not_in_execute_path"
  | "vulnerable_code_cannot_be_controlled_by_adversary"
  | "inline_mitigations_already_exist";

export interface TriageVerdict {
  id: VulnId;
  status: VexStatus;
  justification: VexJustification | null; // required when not_affected
  evidence: string; // file:line references the agent cited
}

/** Every row starts pending and only turns pass/fail when measured. `warn` never blocks; it routes to a human. */
export type CheckState = "pending" | "pass" | "fail" | "warn" | "skipped";
export type CheckName =
  | "policy"
  | "baseline_tests"
  | "patched_tests"
  | "targeted_vulns_cleared"
  | "no_new_vulns"
  | "test_count_not_reduced"
  | "diff_scope"
  | "independent_review";

export interface Check {
  name: CheckName;
  state: CheckState;
  detail: string;
}

export interface ReviewVerdict {
  verdict: "approve" | "concerns";
  notes: string;
  model: string;
}

export interface DependencyChange {
  pkg: string;
  from: string;
  to: string;
  major: boolean;
}

export type GateDecision =
  | { kind: "auto_merge"; reasons: string[] }
  | { kind: "needs_approval"; reasons: string[] }
  | { kind: "blocked"; reasons: string[] };

/** Remediation lifecycle. One per (repo, finding-set). */
export type Stage =
  | "queued"
  | "scanning"
  | "triaging"
  | "remediating"
  | "verifying"
  | "reviewing"
  | "gating"
  | "awaiting_approval"
  | "merged"
  | "deploying"
  | "deployed"
  | "rolled_back"
  | "nothing_to_do"
  | "escalated"
  | "failed";

export const TERMINAL: ReadonlySet<Stage> = new Set([
  "awaiting_approval",
  "deployed",
  "rolled_back",
  "nothing_to_do",
  "escalated",
  "failed",
]);

/** Append-only audit events. The dashboard and PR body are projections of these. */
export type PatchlineEvent =
  | { type: "stage"; stage: Stage; note?: string }
  | { type: "findings"; findings: Finding[] }
  | { type: "policy"; policy: Policy }
  | { type: "incident"; url: string; number: number }
  | { type: "triage"; verdicts: TriageVerdict[] }
  | { type: "agent"; role: AgentRole; model: string; kind: "tool" | "text" | "thinking"; text: string }
  | { type: "agent_done"; role: AgentRole; model: string; status: string; durationMs: number; summary: string }
  | { type: "check"; check: Check }
  | { type: "changes"; changes: DependencyChange[]; diffStat: string }
  | { type: "review"; review: ReviewVerdict }
  | { type: "gate"; decision: GateDecision }
  | { type: "pr"; url: string; number: number; branch: string }
  | { type: "deploy"; status: "started" | "healthy" | "rolled_back"; detail: string }
  | { type: "error"; message: string };

export type AgentRole = "triage" | "remediate" | "review";

export type StampedEvent = PatchlineEvent & {
  remediation: RemediationId;
  repo: RepoName;
  at: string; // ISO timestamp
  seq: number;
};
