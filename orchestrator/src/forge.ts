// Minimal Gitea REST + git client. Config comes from env (FORGE_URL, FORGE_USER, FORGE_TOKEN, FORGE_ORG).
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { z } from "zod";
import { type RepoName, repoName } from "./domain.ts";

const exec = promisify(execFile);

const Env = z.object({
  FORGE_URL: z.url(),
  FORGE_USER: z.string().min(1),
  FORGE_TOKEN: z.string().min(1),
  FORGE_ORG: z.string().min(1),
});

export function forgeConfig() {
  const env = Env.parse(process.env);
  return { url: env.FORGE_URL.replace(/\/+$/, ""), user: env.FORGE_USER, token: env.FORGE_TOKEN, org: env.FORGE_ORG };
}

function redact(s: string): string {
  const { user, token } = forgeConfig();
  const basic = Buffer.from(`${user}:${token}`).toString("base64");
  return s.replaceAll(token, "***").replaceAll(basic, "***");
}

export class ForgeError extends Error {
  readonly status: number;
  constructor(message: string, status: number) {
    super(message);
    this.status = status;
  }
}

export async function api(method: string, path: string, body?: unknown): Promise<unknown> {
  const { url, token } = forgeConfig();
  const res = await fetch(`${url}/api/v1${path}`, {
    method,
    headers: { Authorization: `token ${token}`, "Content-Type": "application/json", Accept: "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await res.text();
  if (!res.ok) throw new ForgeError(redact(`${method} ${path} → ${res.status}: ${text.slice(0, 500)}`), res.status);
  return text ? JSON.parse(text) : null;
}

const repoPath = (repo: RepoName) => `/repos/${forgeConfig().org}/${repo}`;

/** Clone URL without credentials; auth goes in per-command env so the token never lands in .git/config or argv. */
export const cloneUrl = (repo: RepoName) => `${forgeConfig().url}/${forgeConfig().org}/${repo}.git`;

export async function git(dir: string, args: string[]): Promise<string> {
  const { user, token } = forgeConfig();
  const header = `Authorization: Basic ${Buffer.from(`${user}:${token}`).toString("base64")}`;
  try {
    const { stdout } = await exec("git", args, {
      cwd: dir,
      env: { ...process.env, GIT_TERMINAL_PROMPT: "0", GIT_CONFIG_COUNT: "1", GIT_CONFIG_KEY_0: "http.extraHeader", GIT_CONFIG_VALUE_0: header },
      maxBuffer: 64 * 1024 * 1024,
    });
    return stdout;
  } catch (e) {
    const err = z.object({ stderr: z.string().optional(), message: z.string() }).safeParse(e);
    throw new Error(redact(`git ${args.join(" ")} failed: ${err.success ? (err.data.stderr || err.data.message) : String(e)}`));
  }
}

export async function cloneRepo(repo: RepoName, dest: string): Promise<void> {
  await git(process.cwd(), ["clone", "--quiet", cloneUrl(repo), dest]);
}

export async function pushBranch(dir: string, branch: string): Promise<void> {
  await git(dir, ["push", "--quiet", "--force-with-lease", "origin", `HEAD:refs/heads/${branch}`]);
}

const Ref = z.object({ number: z.number(), html_url: z.string() });
const toRef = (r: z.infer<typeof Ref>) => ({ number: r.number, url: r.html_url });
const Label = z.object({ id: z.number(), name: z.string() });

async function repoLabels(repo: RepoName) {
  return z.array(Label).parse(await api("GET", `${repoPath(repo)}/labels?limit=100`));
}

async function labelIds(repo: RepoName, names: string[] = []): Promise<number[]> {
  if (names.length === 0) return [];
  const all = await repoLabels(repo);
  return names.map((n) => {
    const l = all.find((x) => x.name === n);
    if (!l) throw new Error(`label "${n}" missing on ${repo}; run ensureLabels first`);
    return l.id;
  });
}

export async function ensureLabels(repo: RepoName, labels: { name: string; color: string }[]): Promise<void> {
  const existing = new Set((await repoLabels(repo)).map((l) => l.name));
  for (const l of labels) {
    if (existing.has(l.name)) continue;
    await api("POST", `${repoPath(repo)}/labels`, { name: l.name, color: l.color.startsWith("#") ? l.color : `#${l.color}` });
  }
}

export async function createIssue(repo: RepoName, title: string, body: string, labels?: string[]) {
  const issue = { title, body, labels: await labelIds(repo, labels) };
  return toRef(Ref.parse(await api("POST", `${repoPath(repo)}/issues`, issue)));
}

export async function commentIssue(repo: RepoName, number: number, body: string): Promise<void> {
  await api("POST", `${repoPath(repo)}/issues/${number}/comments`, { body });
}

// Gitea PRs are issues, so PR comments use the issue comment endpoint.
export const commentPullRequest = commentIssue;

export async function closeIssue(repo: RepoName, number: number): Promise<void> {
  await api("PATCH", `${repoPath(repo)}/issues/${number}`, { state: "closed" });
}

export async function openPullRequest(
  repo: RepoName,
  pr: { head: string; base: string; title: string; body: string; labels?: string[] },
) {
  const req = { ...pr, labels: await labelIds(repo, pr.labels) };
  return toRef(Ref.parse(await api("POST", `${repoPath(repo)}/pulls`, req)));
}

const Pull = Ref.extend({ title: z.string(), merged: z.boolean(), head: z.object({ ref: z.string() }) });

export async function findOpenPullRequest(repo: RepoName, head: string) {
  for (let page = 1; ; page++) {
    const pulls = z.array(Pull).parse(await api("GET", `${repoPath(repo)}/pulls?state=open&limit=50&page=${page}`));
    const hit = pulls.find((p) => p.head.ref === head);
    if (hit) return toRef(hit);
    if (pulls.length < 50) return null;
  }
}

export async function getPullRequest(repo: RepoName, number: number) {
  const p = Pull.parse(await api("GET", `${repoPath(repo)}/pulls/${number}`));
  return { merged: p.merged, head: p.head.ref, url: p.html_url, title: p.title };
}

export async function mergePullRequest(repo: RepoName, number: number, opts: { style: "squash"; message: string }): Promise<void> {
  const [title = "", ...rest] = opts.message.split("\n");
  await api("POST", `${repoPath(repo)}/pulls/${number}/merge`, {
    Do: opts.style,
    MergeTitleField: title,
    MergeMessageField: rest.join("\n").trim(),
  }); // branch kept: once deleted, Gitea reports head.ref as refs/pull/N/head and webhooks can't be matched by branch
}

export async function listOrgRepos(): Promise<RepoName[]> {
  const names: RepoName[] = [];
  for (let page = 1; ; page++) {
    const repos = z.array(z.object({ name: z.string() })).parse(await api("GET", `/orgs/${forgeConfig().org}/repos?limit=50&page=${page}`));
    names.push(...repos.map((r) => repoName(r.name)));
    if (repos.length < 50) return names;
  }
}
