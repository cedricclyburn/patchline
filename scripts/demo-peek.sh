#!/usr/bin/env bash
# Patchline demo helper. Run read-only views of what the pipeline is doing.
# Usage: scripts/demo-peek.sh <command>
# It always resolves paths from the repo root, so it works from any folder.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"
LEDGER=".patchline-work/ledger.jsonl"
[ -f .env ] && set -a && . ./.env && set +a

die() { echo "$1" >&2; exit 1; }
need() { command -v "$1" >/dev/null || die "missing '$1' on PATH"; }

cmd="${1:-help}"
case "$cmd" in

  policy)   # the policy file that decides auto-merge vs human approval
    for f in demo/services/*/.patchline/policy.json; do
      echo "== $f =="; cat "$f"; echo
    done ;;

  scan)     # run Trivy against a service (default telemetry-ingest)
    need trivy
    svc="${2:-telemetry-ingest}"
    trivy fs --scanners vuln --quiet "demo/services/$svc" ;;

  scan-json) # the exact fields the pipeline parses: CVE, installed -> fixed
    need trivy; need jq
    svc="${2:-telemetry-ingest}"
    trivy fs --scanners vuln --quiet --format json "demo/services/$svc" \
      | jq -r '.Results[].Vulnerabilities[] | "\(.Severity)\t\(.VulnerabilityID)\t\(.PkgName) \(.InstalledVersion) -> \(.FixedVersion // "no fix")"' \
      | sort -u ;;

  health)   # the two running services
    for p in 8081 8082; do
      printf '%s  ' ":$p"; curl -s "localhost:$p/healthz" || echo "(down)"; echo
    done ;;

  containers) # what image each service is running (tag flips after a deploy)
    need podman
    podman ps --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}' ;;

  stages)   # live stage transitions from the audit ledger
    need jq; tail -n +1 -f "$LEDGER" \
      | jq -rc 'select(.type=="stage") | "\(.at[11:19])  \(.repo)\t\(.stage)\t\(.note // "")"' ;;

  checks)   # live readiness checks as they are measured
    need jq; tail -n +1 -f "$LEDGER" \
      | jq -rc 'select(.type=="check") | "\(.repo)\t[\(.check.state)]\t\(.check.name)\t\(.check.detail)"' ;;

  agents)   # which model did what, and how long it took
    need jq; tail -n +1 -f "$LEDGER" \
      | jq -rc 'select(.type=="agent_done") | "\(.repo)\t\(.role)\t\(.model)\t\(.status)\t\(.durationMs/1000)s"' ;;

  gate)     # gate decisions and their reasons
    need jq; tail -n +1 -f "$LEDGER" \
      | jq -rc 'select(.type=="gate") | "\(.repo)  ->  \(.decision.kind)\n  " + (.decision.reasons | join("\n  "))' ;;

  log)      # raw orchestrator log (agents, tool calls, everything)
    tail -f .patchline-work/server.log ;;

  prs)      # open pull requests Patchline has raised
    need jq
    for svc in telemetry-ingest supplier-portal; do
      curl -s -H "Authorization: token ${FORGE_TOKEN:?set .env}" \
        "${FORGE_URL}/api/v1/repos/${FORGE_ORG}/$svc/pulls?state=open" \
        | jq -r --arg s "$svc" '.[] | "[\($s)] #\(.number) \(.title)\n  \(.html_url)"'
    done ;;

  *)
    cat <<EOF
Patchline demo peek. Each command is read-only.

  scripts/demo-peek.sh policy        policy files (auto-merge vs human)
  scripts/demo-peek.sh scan [svc]    Trivy scan of a service
  scripts/demo-peek.sh scan-json [svc]  CVE + installed->fixed, one per line
  scripts/demo-peek.sh health        hit both services' /healthz
  scripts/demo-peek.sh containers    running images (tag flips on deploy)
  scripts/demo-peek.sh prs           open PRs Patchline opened

Live tails (leave running in a side pane; Ctrl-C to stop):
  scripts/demo-peek.sh stages        stage transitions
  scripts/demo-peek.sh checks        readiness checks as measured
  scripts/demo-peek.sh agents        model + duration per agent
  scripts/demo-peek.sh gate          gate decisions and reasons
  scripts/demo-peek.sh log           raw orchestrator log

Services: telemetry-ingest (default), supplier-portal
EOF
    ;;
esac
