# Patchline

Patchline turns a vulnerability scanner finding into a verified, independently reviewed pull request, then merges and deploys it or routes it to a human, according to a policy file that lives in each repository.

It is built on the [Cursor TypeScript SDK](https://cursor.com/docs/sdk/typescript). Coding agents run on the SDK's local runtime against a local clone, so source code never leaves the network. Composer 2.5 writes patches. Grok 4.7 reviews them, so the reviewer is a different model family from the author.

## Why

AI has made vulnerability discovery cheap. VulnCheck's November 2026 tracking of one AI discovery program counted 37,966 findings, 7,349 made public and 217 marked fixed. Remediation is now the bottleneck.

Dependency bots solve the easy case: a patch bump that compiles. They stall on three harder ones:

- an upgrade that breaks an API
- a finding nobody can say is reachable
- a review queue of forty bumps a week across sixty repositories

Patchline handles those three with agents. Whether a change ships stays with deterministic sources.

## The rule

**The model proposes. It never decides.**

| Question | Answered by |
|---|---|
| What is vulnerable? | Trivy scan output (CVE, versions, CVSS), never model text |
| Is the patch safe? | Measured checks: baseline and patched tests in a container, rescan, test count, diff scope |
| Does a human sign off? | `.patchline/policy.json` in the repo, reviewed like code; missing or invalid fails closed |

Model output (reachability verdicts, the patch itself, review notes) can add caution. It can never remove it.

## Flow

```
trigger (Gitea push webhook, dashboard, or API)
  └─ open incident (Gitea issue) before any analysis
  └─ scan with Trivy ─► findings
  └─ triage agents, one per package, in parallel ─► OpenVEX verdicts   ┐ concurrent
  └─ baseline tests on the unpatched code                              ┘
  └─ remediation agent (Composer 2.5): edit files, call run_tests; no shell
  └─ verify (deterministic): patched tests, rescan, no new vulns, test count, diff scope
       └─ on failure: one retry with the failing check output, then escalate
  └─ review agent (Grok 4.7, read-only) ─► approve | concerns
  └─ gate (pure function) ─► auto_merge | needs_approval | blocked
  └─ PR with an evidence table; incident updated
  └─ on merge (auto or human, via webhook): Ansible build, swap, health check, rollback
  └─ close incident only when the deploy is healthy
```

## Where the Cursor SDK starts

`orchestrator/src/agents.ts`. Each role is one `Agent.create({ local: { cwd } })` with a restricted tool set:

| Role | Model | Built-in tools | Custom tools |
|---|---|---|---|
| Triage | see `MODELS` | read, grep, glob, ls | `lookup_advisory`, `record_triage` |
| Remediate | composer-2.5 | read, edit, write, grep, glob, ls | `lookup_advisory`, `run_tests`, `set_dependency` |
| Review | grok-4.7 | read, grep, glob, ls | `lookup_advisory`, `record_review` |

- **Structured output** goes through `record_*` tools. Their `execute` validates input with zod and returns the validation error to the agent so it can retry. If a run ends without a valid record, the result is the fail-safe default (`under_investigation`, `concerns`).
- **No shell for the author.** It can change files and ask for a test run. `run_tests` uses the same Podman image as the verification gate, so "green for the agent" and "green for the gate" mean the same thing.
- **No invented security data.** Agents read advisories only through `lookup_advisory`, which returns scanner output.

Trigger to output:

`server.ts` (webhook or `POST /api/remediate`) → `pipeline.ts remediate()` → `agents.ts` → `verify.ts` → `gate.ts decide()` → `forge.ts` (PR, merge) → `ansible/deploy.yml`

Every step appends to an audit ledger (`ledger.ts`, JSONL). The dashboard, the PR body and the incident comments are projections of that ledger.

## Run it locally

Requirements: macOS or Linux, Node 22.13+, Podman, Trivy, Ansible, a Cursor API key.

```bash
podman machine start
podman run -d --name forge -p 3000:3000 \
  -e GITEA__security__INSTALL_LOCK=true \
  -e GITEA__webhook__ALLOWED_HOST_LIST='*' \
  docker.io/gitea/gitea:1.24
```

Create an admin and a token in Gitea, then write `.env` at the repo root:

```
CURSOR_API_KEY=...
FORGE_URL=http://localhost:3000
FORGE_USER=...
FORGE_TOKEN=...
FORGE_ORG=mission-systems
```

```bash
cd orchestrator && npm install
(cd ../ansible && ansible-galaxy collection install -r requirements.yml -p collections)
npm run seed -- --reset      # creates the org, two demo services, labels and webhooks
npm start                    # dashboard on http://localhost:4100
```

Click **Run fleet**, or push a commit to either demo repository.

Offline fallback: `node scripts/replay-demo.ts --live 4` streams a recorded run into the dashboard with no agents.

## Demo services

| Service | Stack | Policy | What makes it interesting |
|---|---|---|---|
| `supplier-portal` | Node, Express 4.17.1, lodash 4.17.20 | LOW, auto_approve | Minor bumps; should auto-merge and deploy without a human. |
| `telemetry-ingest` | Python, Flask, PyYAML 5.3.1 | HIGH, needs_approval | CVE-2020-14343 (CVSS 9.8) is reachable from the upload endpoint. The fix needs PyYAML 6, which breaks `yaml.load`, and `safe_load` then breaks the custom `!vector` tag. The agent has to fix both. It passes every check and still waits for a human because of its policy. |

## Tests

```bash
cd orchestrator
npm run typecheck
npm test                      # unit tests: scan parsing, policy fail-closed, gate table, verify helpers
PODMAN_IT=1 npm test          # also runs the containerized test runner
```

## Design

See [docs/DESIGN.md](docs/DESIGN.md) for alternatives considered (Cursor cloud agents, raw Grok API), the gate table, and what would change before a real team used this.
