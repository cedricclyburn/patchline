// Manual end-to-end run of the three agents against a copy of the demo service.
//   node --no-warnings --env-file=../.env scripts/try-agents.ts [telemetry-ingest|supplier-portal]
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { runRemediation, runReview, runTriage } from "../src/agents.ts";
import type { PatchlineEvent, Policy } from "../src/domain.ts";
import { containerTests, prepareDemo } from "./demo-setup.ts";

const { dir, eco, findings, git } = await prepareDemo(process.argv[2] ?? "telemetry-ingest");
console.log(`workdir ${dir} (${eco})`);
console.log(`${findings.length} findings: ${findings.map((f) => `${f.pkg}:${f.id}`).join(" ")}`);

const policy: Policy = { ...JSON.parse(await readFile(join(dir, ".patchline/policy.json"), "utf8")), failedClosed: false };
const timings: string[] = [];
const emit = (e: PatchlineEvent) => {
  if (e.type === "agent") console.log(`[${e.role}/${e.kind}] ${e.text}`);
  else if (e.type === "agent_done") {
    timings.push(`${e.role} (${e.model}): ${(e.durationMs / 1000).toFixed(1)}s ${e.status}`);
    console.log(`[${e.role}] done ${e.status} in ${e.durationMs}ms`);
  } else console.log(JSON.stringify(e));
};

const runTests = containerTests(dir, eco);

let t = Date.now();
const verdicts = await runTriage(dir, findings, emit);
console.log(`\n=== triage (${Date.now() - t}ms)`);
for (const v of verdicts) console.log(`${v.id} ${v.status}${v.justification ? ` (${v.justification})` : ""}: ${v.evidence}`);

t = Date.now();
const { summary } = await runRemediation({ dir, findings, verdicts, policy, eco, emit, runTests });
console.log(`\n=== remediation (${Date.now() - t}ms)\n${summary}`);

await git("add", "-A");
const diff = (await git("diff", "--cached", "HEAD")).stdout;
console.log(`\n=== diff\n${diff}`);
const final = await runTests();
console.log(`=== final tests: ok=${final.ok} ${final.passed} passed ${final.failed} failed`);

t = Date.now();
const review = await runReview(dir, diff, findings, emit);
console.log(`\n=== review (${Date.now() - t}ms)\n${review.verdict} (${review.model}): ${review.notes}`);
console.log(`\n=== timings\n${timings.join("\n")}`);
