// One reviewer candidate on a finished workdir (run one process per candidate):
//   node --no-warnings --env-file=../.env scripts/ab-review.ts <workdir> grok-4.7|grok-4.6|grok-4.5 [service]
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import type { ModelSelection } from "@cursor/sdk";
import { MODELS, runReview } from "../src/agents.ts";
import type { PatchlineEvent } from "../src/domain.ts";
import { prepareDemo } from "./demo-setup.ts";

const dir = process.argv[2];
if (!dir) throw new Error("usage: ab-review.ts <workdir> <model> [service]");
const name = process.argv[3] ?? "grok-4.7";
const { findings } = await prepareDemo(process.argv[4] ?? "telemetry-ingest");
const diff = (await promisify(execFile)("git", ["-C", dir, "diff", "--cached", "HEAD"])).stdout;
const candidates: Record<string, ModelSelection> = {
  "grok-4.7": MODELS.review,
  "grok-4.6": { id: "grok-4.6", params: [{ id: "effort", value: "medium" }, { id: "fast", value: "false" }] },
  "grok-4.5": { id: "grok-4.5", params: [{ id: "effort", value: "medium" }, { id: "fast", value: "false" }] },
};
const model = candidates[name];
if (!model) throw new Error(`unknown candidate ${name}`);
MODELS.review = model;
let ms = 0;
const t0 = Date.now();
const emit = (e: PatchlineEvent) => {
  if (e.type === "agent_done") ms = e.durationMs;
  else if (e.type === "agent") console.log(`[${((Date.now() - t0) / 1000).toFixed(0)}s ${e.kind}] ${e.text.slice(0, 200)}`);
};
const r = await runReview(dir, diff, findings, emit);
console.log(`=== ${name}: ${(ms / 1000).toFixed(1)}s ${r.verdict} (${r.model})\n${r.notes}`);
