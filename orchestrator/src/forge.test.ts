// Live integration test against the local Gitea. Run with FORGE_IT=1 and the ../.env loaded.
import assert from "node:assert/strict";
import { test } from "node:test";
import { repoName } from "./domain.ts";
import { api, closeIssue, commentIssue, createIssue, ensureLabels, forgeConfig } from "./forge.ts";

test("create, comment and close an issue on a throwaway repo", { skip: process.env.FORGE_IT !== "1" }, async (t) => {
  const { org } = forgeConfig();
  const name = `forge-it-${Date.now()}`;
  const repo = repoName(name);
  await api("POST", `/orgs/${org}/repos`, { name, auto_init: true, default_branch: "main" });
  t.after(() => api("DELETE", `/repos/${org}/${name}`));

  await ensureLabels(repo, [{ name: "patchline", color: "5319e7" }]);
  await ensureLabels(repo, [{ name: "patchline", color: "5319e7" }]); // idempotent

  const issue = await createIssue(repo, "IT issue", "body", ["patchline"]);
  assert.ok(issue.number > 0);
  assert.match(issue.url, new RegExp(`/${org}/${name}/issues/${issue.number}$`));

  await commentIssue(repo, issue.number, "a comment");
  await closeIssue(repo, issue.number);

  const after = await api("GET", `/repos/${org}/${name}/issues/${issue.number}`);
  assert.equal(typeof after === "object" && after !== null && "state" in after ? after.state : null, "closed");
});
