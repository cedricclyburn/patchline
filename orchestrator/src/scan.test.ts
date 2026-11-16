import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";
import { parseTrivy, pickFix } from "./scan.ts";

const fixture: unknown = JSON.parse(await readFile(new URL("./__fixtures__/trivy-telemetry.json", import.meta.url), "utf8"));

test("parses the real telemetry-ingest scan", () => {
  const findings = parseTrivy(fixture);
  assert.equal(findings.length, 14);
  const pyyaml = findings.find((f) => f.id === "CVE-2020-14343");
  assert.deepEqual(pyyaml, {
    id: "CVE-2020-14343",
    pkg: "PyYAML",
    ecosystem: "pip",
    installed: "5.3.1",
    fixed: "5.4",
    severity: "CRITICAL",
    cvss: 9.8,
    title: "PyYAML: incomplete fix for CVE-2020-1747",
    url: "https://avd.aquasec.com/nvd/cve-2020-14343",
    target: "requirements.txt",
  });
  assert.ok(findings.every((f) => f.ecosystem === "pip" && f.target === "requirements.txt"));
});

const vuln = (over: Record<string, unknown> = {}) => ({
  VulnerabilityID: "CVE-1",
  PkgName: "lodash",
  InstalledVersion: "4.17.20",
  Severity: "HIGH",
  ...over,
});

test("maps npm types, takes max V3 score and first fixed version, dedupes by (id, pkg)", () => {
  const findings = parseTrivy({
    Results: [
      {
        Target: "package-lock.json",
        Type: "npm",
        Vulnerabilities: [
          vuln({ FixedVersion: "4.17.21, 5.0.1", CVSS: { nvd: { V3Score: 7.2 }, ghsa: { V3Score: 7.5 }, x: { V2Score: 9 } } }),
          vuln({ FixedVersion: "9.9.9" }),
          vuln({ PkgName: "minimist" }),
        ],
      },
      { Target: "node_modules/a/package.json", Type: "node-pkg", Vulnerabilities: [vuln({ VulnerabilityID: "CVE-2" })] },
    ],
  });
  assert.deepEqual(
    findings.map((f) => [f.id, f.pkg, f.ecosystem, f.fixed, f.cvss]),
    [
      ["CVE-1", "lodash", "npm", "4.17.21", 7.5],
      ["CVE-1", "minimist", "npm", null, null],
      ["CVE-2", "lodash", "npm", null, null],
    ],
  );
});

test("skips unsupported ecosystems and tolerates empty results", () => {
  assert.deepEqual(parseTrivy({ Results: [{ Target: "go.mod", Type: "gomod", Vulnerabilities: [vuln()] }] }), []);
  assert.deepEqual(parseTrivy({ Results: [{ Target: "requirements.txt", Type: "pip", Vulnerabilities: null }] }), []);
  assert.deepEqual(parseTrivy({ SchemaVersion: 2 }), []);
});

test("unknown severity becomes UNKNOWN; malformed input throws", () => {
  const [f] = parseTrivy({ Results: [{ Target: "r.txt", Type: "python-pkg", Vulnerabilities: [vuln({ Severity: "WEIRD" })] }] });
  assert.equal(f?.severity, "UNKNOWN");
  assert.equal(f?.ecosystem, "pip");
  assert.throws(() => parseTrivy({ Results: [{ Target: "r.txt", Type: "pip", Vulnerabilities: [{ PkgName: "x" }] }] }));
  assert.throws(() => parseTrivy("nope"));
});

test("pickFix stays on the installed release line when a fix exists there", () => {
  assert.equal(pickFix("0.1.7", "1.9.0, 0.1.12, 8.0.0"), "0.1.12");
  assert.equal(pickFix("1.19.0", "2.4.0, 1.20.9"), "1.20.9");
  assert.equal(pickFix("5.3.1", "5.4"), "5.4");
  assert.equal(pickFix("1.0.0", "2.0.0"), "2.0.0");
  assert.equal(pickFix("1.0.0", undefined), null);
});
