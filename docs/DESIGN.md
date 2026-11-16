# Patchline design

## Problem

AI now finds vulnerabilities faster than teams can fix them. VulnCheck's November 2026 tracking of one AI discovery program counted 37,966 findings, 7,349 made public, and 217 marked fixed. Discovery scaled. Remediation did not. Meanwhile AI-assisted coding raises the volume of new code and new dependencies every sprint.

Dependency bots (Renovate, Dependabot) close the easy part: a patch bump that compiles. They stall on the part that eats engineer time: the upgrade that breaks an API, the finding nobody can say is reachable, and the review queue for forty bumps a week across sixty repos.

Patchline is an asynchronous remediation pipeline. A scanner finding goes in. A verified, reviewed pull request comes out, merged automatically or routed to a human per policy, then deployed with a health check and rollback.

## Principles

1. **The model never decides whether a change ships.** Three non-model sources decide: the scanner says what is affected, measured checks say whether the patch is safe, and the repo's policy file says whether a human must sign off.
2. **No invented security data.** CVE ids, versions, and severity come from Trivy output. Agents read them through a tool. If data is missing the PR says "not scored".
3. **Every check starts pending.** A row turns green only when measured. Any failed check blocks the merge whatever the policy says.
4. **Fail closed.** A missing or malformed `.patchline/policy.json` means `needs_approval`.
5. **Code stays on our side.** Agents run on the Cursor SDK local runtime against a local clone. Nothing is pushed to a third-party VM. That fits export-controlled (ITAR) code.

## Flow

```
Gitea push webhook / CLI / dashboard
        │
        ▼
 incident opened (Gitea issue) ──────────────────────────────┐
        │                                                    │
 scan (Trivy fs, JSON) ──► findings[]                         │
        │                                                    │
 triage agent (Cursor SDK, read-only tools) ──► VEX verdicts  │
        │                                                    │
 remediate agent (Cursor SDK, edit + run_tests tool)         │
        │        ▲                                            │
        ▼        │ one retry with failing check output        │
 verify (deterministic): baseline tests, patched tests,       │
   rescan, no new vulns, test count, diff scope               │
        │                                                    │
 review agent (different model, read-only) ──► approve|concerns
        │                                                    │
 gate (pure function of policy + checks + review + changes)   │
        ├── auto_merge ──► merge ──► Ansible deploy ──► health ─┤ close incident
        ├── needs_approval ──► PR waits for a human merge ─────┤ (merge webhook resumes)
        └── blocked ──► escalate on incident ──────────────────┘
```

## Data shape

`orchestrator/src/domain.ts` holds every type. Two structures carry the design:

- **`Stage`** is a state machine per remediation. Terminal states are explicit.
- **`PatchlineEvent`** is an append-only audit log (`ledger.ts`, JSONL). The dashboard, the PR body and the incident comments are projections of it, so "why did this merge?" is answered by replaying events.

## Alternatives considered

| Option | Pro | Con | Verdict |
|---|---|---|---|
| A. Cursor SDK local runtime, our own deterministic gate, self-hosted Gitea | Code never leaves the network. Works with any git host. Custom tools give structured output and a controlled test runner. | We own concurrency and the worktree lifecycle. | **Chosen** |
| B. Cursor SDK cloud agents with `autoCreatePR` | Least code. Durable VMs, scales wide. | Needs GitHub, GitLab, Bitbucket or Azure DevOps reachable from Cursor. Code is cloned into a hosted VM. The gate moves to the host's CI. | Good for open-source repos. Swap in by changing `runtime` in `agents.ts`. |
| C. Grok API with a hand-built tool loop | Full model control, 1M context, live search. | Weeks of plumbing (edit loop, sandbox, search) before remediation quality. | Grok is used instead as the independent reviewer model through the same Cursor SDK. |

## Agents (Cursor SDK)

| Role | Model | Tools | Output |
|---|---|---|---|
| triage (one agent per package, parallel) | `composer-2.5` | read, grep, glob, ls on a read-only in-memory snapshot, custom `lookup_advisory`, `record_triage` | `TriageVerdict[]` validated by zod |
| remediate | `composer-2.5` | read, edit, write, grep, glob, ls, custom `lookup_advisory`, `set_dependency`, `run_tests`. No shell (allowlist, since a denylist can be bypassed through a subagent). | edited worktree |
| review | `grok-4.7` | none: diff and advisories only, custom `record_review` | `ReviewVerdict` |

Measured on telemetry-ingest: Grok triage took 114s against 23s for Composer with identical verdicts, so triage moved to Composer. With repository read access, Grok review spent 200s or more in one reasoning call. Diff-only, it took 77s and caught that the agent's regression test passed even when the exploit ran. Hard deadlines (`run.cancel()`): triage 90s, remediation 900s, review 180s, each falling back to a fail-safe verdict.

Structured output goes through custom tools (`record_triage`, `record_review`) whose `execute` validates with zod and rejects bad input back to the agent. The remediation agent has no shell: it can only change files and ask for a test run in the same container the gate uses. The reviewer is a different model family than the author, so the review is not the author grading itself.

## Gate (pure function, `gate.ts`)

| Condition | Decision |
|---|---|
| any check `fail` | blocked |
| any check still `pending` | blocked |
| policy failed closed | needs_approval |
| policy `needs_approval` | needs_approval |
| riskClass HIGH or CRITICAL | needs_approval |
| any major-version bump | needs_approval |
| reviewer `concerns` | needs_approval |
| otherwise | auto_merge |

## Module contracts

```ts
// scan.ts
parseTrivy(json: unknown): Finding[]            // pure, zod at the boundary
scanRepo(dir: string): Promise<Finding[]>       // trivy fs --format json --scanners vuln

// policy.ts
loadPolicy(dir: string): Promise<Policy>        // fails closed

// gate.ts
decide(i: { policy: Policy; checks: Check[]; review: ReviewVerdict | null; changes: DependencyChange[] }): GateDecision

// verify.ts
runTests(dir: string, policy: Policy, eco: Ecosystem): Promise<{ ok: boolean; passed: number; failed: number; output: string }>
dependencyChanges(beforeDir: string, afterDir: string, eco: Ecosystem): Promise<DependencyChange[]>
diffScope(dir: string, baseRef: string): Promise<{ ok: boolean; files: string[]; detail: string; stat: string }>

// agents.ts
runTriage(dir, findings, emit): Promise<TriageVerdict[]>
runRemediation(dir, findings, verdicts, policy, eco, emit, feedback?: string): Promise<{ summary: string }>
runReview(dir, diff, findings, emit): Promise<ReviewVerdict>

// forge.ts (Gitea REST)
createIssue / commentIssue / closeIssue / pushBranch / openPullRequest / mergePullRequest / findOpenPullRequest

// pipeline.ts
remediate(repo: RepoName): Promise<Stage>       // idempotent per finding-set fingerprint
```

## What would change before a real team used it

- Durable job queue (the in-process queue loses work on crash; the ledger lets us resume, but nothing re-drives it).
- Run each agent in a disposable container or the SDK sandbox, not on the orchestrator host.
- Pull advisory data from an SBOM store (Dependency-Track, GUAC) instead of a scan per run.
- Org-wide rate limits and a cost budget per remediation (`agent.getUsage()`).
- Signed commits and provenance attestation on the built image.
