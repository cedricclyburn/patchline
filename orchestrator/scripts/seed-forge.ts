// Idempotent demo seeding: org, one repo per demo/services/* dir, labels, webhook. `--reset` recreates the repos.
import { cp, mkdtemp, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { z } from "zod";
import { repoName } from "../src/domain.ts";
import { ForgeError, api, cloneUrl, ensureLabels, forgeConfig, git, pushBranch } from "../src/forge.ts";

// host.containers.internal resolves inside the forge container (podman machine, libkrun) and reaches host loopback.
const WEBHOOK_URL = process.env.PATCHLINE_WEBHOOK_URL ?? "http://host.containers.internal:4100/webhooks/forge";
const LABELS = [
  { name: "patchline", color: "#5319e7" },
  { name: "security", color: "#d73a4a" },
  { name: "risk:low", color: "#0e8a16" },
  { name: "risk:high", color: "#b60205" },
  { name: "auto-merged", color: "#1d76db" },
  { name: "needs-approval", color: "#fbca04" },
];

const servicesDir = fileURLToPath(new URL("../../demo/services/", import.meta.url));
const reset = process.argv.includes("--reset");
const { org } = forgeConfig();

async function getOrNull(path: string): Promise<unknown> {
  try {
    return await api("GET", path);
  } catch (e) {
    if (e instanceof ForgeError && e.status === 404) return null;
    throw e;
  }
}

if ((await getOrNull(`/orgs/${org}`)) === null) {
  await api("POST", "/orgs", { username: org, visibility: "public" });
  console.log(`created org ${org}`);
}

const dirs = (await readdir(servicesDir, { withFileTypes: true })).filter((d) => d.isDirectory()).map((d) => d.name);
const Repo = z.object({ html_url: z.string(), empty: z.boolean() });

for (const name of dirs) {
  const repo = repoName(name);
  const path = `/repos/${org}/${name}`;
  if (reset && (await getOrNull(path)) !== null) {
    await api("DELETE", path);
    console.log(`${name}: deleted`);
  }

  let info = await getOrNull(path);
  if (info === null) {
    info = await api("POST", `/orgs/${org}/repos`, { name, default_branch: "main", private: false, auto_init: false });
    console.log(`${name}: created`);
  }
  const { html_url, empty } = Repo.parse(info);

  // Only an empty repo gets the import, so re-runs never clobber remediated history.
  if (empty) {
    const tmp = await mkdtemp(join(tmpdir(), `seed-${name}-`));
    try {
      await cp(join(servicesDir, name), tmp, { recursive: true });
      await rm(join(tmp, ".git"), { recursive: true, force: true });
      await git(tmp, ["init", "--quiet", "-b", "main"]);
      await git(tmp, ["add", "-A"]); // honours the service's own .gitignore
      await git(tmp, [
        "-c", "user.name=Flight Software", "-c", "user.email=flight-sw@localhost.test", "-c", "commit.gpgsign=false",
        "commit", "--quiet", "--no-verify", "-m", `Initial import of ${name}`,
      ]);
      await git(tmp, ["remote", "add", "origin", cloneUrl(repo)]);
      await pushBranch(tmp, "main");
      console.log(`${name}: pushed main`);
    } finally {
      await rm(tmp, { recursive: true, force: true });
    }
  }

  await ensureLabels(repo, LABELS);

  const hooks = z.array(z.object({ config: z.object({ url: z.string() }) })).parse(await api("GET", `${path}/hooks`));
  if (!hooks.some((h) => h.config.url === WEBHOOK_URL)) {
    await api("POST", `${path}/hooks`, {
      type: "gitea",
      active: true,
      events: ["push", "pull_request"],
      config: { url: WEBHOOK_URL, content_type: "json" },
    });
    console.log(`${name}: webhook → ${WEBHOOK_URL}`);
  }
  console.log(`${name}: ${html_url}`);
}
