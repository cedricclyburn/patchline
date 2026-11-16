import { execFile } from "node:child_process";
import { access } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { z } from "zod";
import { type Ecosystem, type Finding, vulnId } from "./domain.ts";

const Vuln = z.object({
  VulnerabilityID: z.string(),
  PkgName: z.string(),
  InstalledVersion: z.string(),
  FixedVersion: z.string().optional(),
  Severity: z.enum(["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]).catch("UNKNOWN"),
  Title: z.string().optional(),
  PrimaryURL: z.string().optional(),
  CVSS: z.record(z.string(), z.object({ V3Score: z.number().optional() })).optional(),
});

const Report = z.object({
  Results: z
    .array(
      z.object({
        Target: z.string(),
        Type: z.string().optional(),
        Vulnerabilities: z.array(Vuln).nullish(),
      }),
    )
    .nullish(),
});

const ECOSYSTEMS: Record<string, Ecosystem> = {
  pip: "pip",
  "python-pkg": "pip",
  npm: "npm",
  "node-pkg": "npm",
};

export function parseTrivy(json: unknown): Finding[] {
  const report = Report.parse(json);
  const out = new Map<string, Finding>();
  for (const result of report.Results ?? []) {
    const ecosystem = result.Type === undefined ? undefined : ECOSYSTEMS[result.Type];
    if (!ecosystem) continue;
    for (const v of result.Vulnerabilities ?? []) {
      const key = `${v.VulnerabilityID}\0${v.PkgName}`;
      if (out.has(key)) continue;
      const scores = Object.values(v.CVSS ?? {}).flatMap((c) => (c.V3Score === undefined ? [] : [c.V3Score]));
      out.set(key, {
        id: vulnId(v.VulnerabilityID),
        pkg: v.PkgName,
        ecosystem,
        installed: v.InstalledVersion,
        fixed: pickFix(v.InstalledVersion, v.FixedVersion),
        severity: v.Severity,
        cvss: scores.length ? Math.max(...scores) : null,
        title: v.Title ?? v.VulnerabilityID,
        url: v.PrimaryURL ?? null,
        target: result.Target,
      });
    }
  }
  return [...out.values()];
}

function trivyCacheDir(): string {
  if (process.env.TRIVY_CACHE_DIR) return process.env.TRIVY_CACHE_DIR;
  if (process.platform === "darwin") return join(homedir(), "Library", "Caches", "trivy");
  return join(process.env.XDG_CACHE_HOME ?? join(homedir(), ".cache"), "trivy");
}

const run = promisify(execFile);

export async function scanRepo(dir: string): Promise<Finding[]> {
  const args = ["fs", "--format", "json", "--scanners", "vuln", "--quiet"];
  // Skip the DB refresh when we have one: keeps rescans fast and comparable within a run.
  const hasDb = await access(join(trivyCacheDir(), "db", "trivy.db")).then(() => true, () => false);
  if (hasDb) args.push("--skip-db-update");
  const { stdout } = await run("trivy", [...args, dir], { maxBuffer: 64 * 1024 * 1024, timeout: 300_000 });
  return parseTrivy(JSON.parse(stdout));
}

const versionParts = (v: string) => v.split(/[.-]/).map((x) => parseInt(x, 10) || 0);
function compareVersions(a: string, b: string): number {
  const [pa, pb] = [versionParts(a), versionParts(b)];
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const d = (pa[i] ?? 0) - (pb[i] ?? 0);
    if (d !== 0) return d;
  }
  return 0;
}

/** Trivy lists one fixed version per release line. Prefer the line already installed so a fix never forces a needless major bump. */
export function pickFix(installed: string, fixed: string | undefined): string | null {
  const all = (fixed ?? "").split(",").map((s) => s.trim()).filter(Boolean).sort(compareVersions);
  const major = versionParts(installed)[0];
  return (
    all.find((v) => versionParts(v)[0] === major && compareVersions(v, installed) > 0) ??
    all.find((v) => compareVersions(v, installed) > 0) ??
    all[0] ??
    null
  );
}
