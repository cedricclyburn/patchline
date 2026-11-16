import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import { z } from "zod";
import type { Policy } from "./domain.ts";

const PolicyFile = z.object({
  owner: z.string().min(1),
  riskClass: z.enum(["LOW", "MEDIUM", "HIGH", "CRITICAL"]),
  rationale: z.string(),
  approval: z.enum(["auto_approve", "needs_approval"]),
  test: z.string().min(1).optional(),
});

// A repo with no recognisable manifest gets a command that fails, so verification cannot pass vacuously.
const NO_TESTS = "echo 'patchline: no test command detected' >&2; exit 1";

export async function defaultTestCommand(dir: string): Promise<string> {
  const names: string[] = await readdir(dir).catch(() => []);
  if (names.some((n) => /^requirements.*\.txt$/.test(n))) return "pytest -q";
  if (names.includes("package.json")) return "npm test";
  return NO_TESTS;
}

export async function loadPolicy(dir: string): Promise<Policy> {
  const test = await defaultTestCommand(dir);
  let reason: string;
  try {
    const raw = await readFile(join(dir, ".patchline", "policy.json"), "utf8");
    const parsed = PolicyFile.safeParse(JSON.parse(raw));
    if (parsed.success) return { ...parsed.data, test: parsed.data.test ?? test, failedClosed: false };
    reason = parsed.error.issues.map((i) => `${i.path.join(".") || "(root)"}: ${i.message}`).join("; ");
  } catch (e) {
    reason = e instanceof Error ? e.message : String(e);
  }
  return {
    owner: "unknown",
    riskClass: "HIGH",
    rationale: `policy missing or invalid: ${reason}`,
    approval: "needs_approval",
    test,
    failedClosed: true,
  };
}
