import { pickFix } from "../src/scan.ts";
// Shared by the manual agent scripts: a git-initialised temp copy of a demo service plus its Trivy findings.
import { execFile } from "node:child_process";
import { cp, mkdtemp } from "node:fs/promises";
import { existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import type { TestRun } from "../src/agents.ts";
import { vulnId, type Ecosystem, type Finding, type Severity } from "../src/domain.ts";

export const sh = promisify(execFile);

export async function prepareDemo(service: string): Promise<{ dir: string; eco: Ecosystem; findings: Finding[]; git: (...a: string[]) => Promise<{ stdout: string }> }> {
  const src = fileURLToPath(new URL(`../../demo/services/${service}`, import.meta.url));
  const dir = await mkdtemp(join(tmpdir(), `patchline-${service}-`));
  await cp(src, dir, { recursive: true, filter: (p) => !/(\.pytest_cache|__pycache__|node_modules)/.test(p) });
  const git = (...args: string[]) => sh("git", ["-C", dir, ...args], { maxBuffer: 16 << 20 });
  await git("init", "-q");
  await git("add", "-A");
  await git("-c", "user.name=patchline", "-c", "user.email=patchline@localhost", "commit", "-qm", "base");
  const eco: Ecosystem = existsSync(join(dir, "package.json")) ? "npm" : "pip";

  const { stdout } = await sh("trivy", ["fs", "--format", "json", "--scanners", "vuln", "--quiet", dir], { maxBuffer: 64 << 20 });
  interface TrivyVuln { VulnerabilityID: string; PkgName: string; InstalledVersion: string; FixedVersion?: string; Severity: Severity; Title?: string; PrimaryURL?: string; CVSS?: Record<string, { V3Score?: number }> }
  const report: { Results?: { Target: string; Vulnerabilities?: TrivyVuln[] }[] } = JSON.parse(stdout);
  const findings: Finding[] = (report.Results ?? []).flatMap((r) =>
    (r.Vulnerabilities ?? []).map((v) => ({
      id: vulnId(v.VulnerabilityID),
      pkg: v.PkgName,
      ecosystem: eco,
      installed: v.InstalledVersion,
      fixed: pickFix(v.InstalledVersion, v.FixedVersion),
      severity: v.Severity,
      cvss: v.CVSS?.nvd?.V3Score ?? null,
      title: v.Title ?? "",
      url: v.PrimaryURL ?? null,
      target: r.Target,
    })),
  );
  return { dir, eco, findings, git };
}

/** Same container shape the gate uses. `python -m pytest` so the repo root is importable. */
export function containerTests(dir: string, eco: Ecosystem): () => Promise<TestRun> {
  const [image, script] =
    eco === "pip"
      ? ["docker.io/library/python:3.12-slim", "pip install -q --disable-pip-version-check --root-user-action=ignore -r requirements-dev.txt && python -m pytest -q"]
      : ["docker.io/library/node:22-slim", "npm ci --no-audit --no-fund && npm test"];
  return async () => {
    const args = ["run", "--rm", "-v", `${dir}:/w:Z`, "-w", "/w", image, "sh", "-c", `exec 2>&1; ${script}`];
    const out = await sh("podman", args, { maxBuffer: 64 << 20 }).then(
      (r) => ({ ok: true, text: r.stdout }),
      (e: { stdout?: string; message: string }) => ({ ok: false, text: `${e.stdout ?? ""}\n${e.message}` }),
    );
    const count = (re: RegExp) => Number(out.text.match(re)?.[1] ?? 0);
    const passed = count(/(\d+) passed/) || count(/^# pass (\d+)/m);
    const failed = count(/(\d+) failed/) + count(/(\d+) errors?\b/) || count(/^# fail (\d+)/m);
    console.log(`  run_tests: ok=${out.ok} passed=${passed} failed=${failed}`);
    return { ok: out.ok, passed, failed, output: out.text };
  };
}

/** Trivy lists one fixed version per release line; prefer the lowest one on the installed major line. */
