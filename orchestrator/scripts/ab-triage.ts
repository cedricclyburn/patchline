// A/B the triage model on identical input: node --no-warnings --env-file=../.env scripts/ab-triage.ts [service]
import { MODELS, runTriage } from "../src/agents.ts";
import type { PatchlineEvent } from "../src/domain.ts";
import { prepareDemo } from "./demo-setup.ts";

const service = process.argv[2] ?? "telemetry-ingest";
const candidates = { grok: MODELS.review, composer: MODELS.remediate };
for (const [name, model] of Object.entries(candidates)) {
  const { dir, findings } = await prepareDemo(service);
  MODELS.triage = model;
  const perPkg: string[] = [];
  const emit = (e: PatchlineEvent) => {
    if (e.type === "agent_done") perPkg.push(`${e.summary.match(/^\[([^\]]+)\]/)?.[1] ?? "?"} ${(e.durationMs / 1000).toFixed(1)}s ${e.status}`);
    else if (e.type === "error") console.log(`  error: ${e.message}`);
  };
  const t = Date.now();
  const verdicts = await runTriage(dir, findings, emit);
  console.log(`\n=== ${name} (${model.id}) wall ${((Date.now() - t) / 1000).toFixed(1)}s | ${perPkg.join(" | ")}`);
  for (const v of verdicts) {
    const f = findings.find((x) => x.id === v.id);
    console.log(`${f?.pkg} ${v.id} ${v.status}${v.justification ? ` (${v.justification})` : ""}: ${v.evidence.slice(0, 160)}`);
  }
}
