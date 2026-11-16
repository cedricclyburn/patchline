import { createHmac, timingSafeEqual } from "node:crypto";
import { readFile } from "node:fs/promises";
import { type IncomingMessage, type ServerResponse, createServer } from "node:http";
import { extname, join, normalize, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { z } from "zod";
import { type RepoName, type StampedEvent, repoName } from "./domain.ts";
import { ledger, onMerged, remediate, repos } from "./pipeline.ts";

const PORT = Number(process.env.PORT ?? 4100);
const UI_DIR = fileURLToPath(new URL("../ui/", import.meta.url));
const MAX_BODY = 5 * 1024 * 1024; // Gitea push payloads carry commit lists; 5 MB is ample.
const HEARTBEAT_MS = 15_000;

const MIME: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".ico": "image/x-icon",
};

const RemediateBody = z.object({ repo: z.string().min(1).optional() });

const Repository = z.object({ name: z.string().min(1), default_branch: z.string().optional() });
const PushPayload = z.object({
  ref: z.string(),
  repository: Repository,
  head_commit: z.object({ message: z.string() }).nullish(),
});
const PullRequestPayload = z.object({
  action: z.string(),
  number: z.number().int(),
  repository: Repository,
  pull_request: z.object({ merged: z.boolean(), head: z.object({ ref: z.string() }) }),
});

class HttpError extends Error {
  readonly status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

function readBody(req: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    req.on("data", (c: Buffer) => {
      size += c.length;
      if (size > MAX_BODY) {
        reject(new HttpError(413, "body too large"));
        req.destroy();
      } else chunks.push(c);
    });
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

function parseJson(raw: Buffer): unknown {
  if (raw.length === 0) return {};
  try {
    return JSON.parse(raw.toString("utf8"));
  } catch {
    throw new HttpError(400, "body is not valid JSON");
  }
}

function send(res: ServerResponse, status: number, body?: unknown): void {
  if (body === undefined) {
    res.writeHead(status).end();
    return;
  }
  res.writeHead(status, { "content-type": "application/json; charset=utf-8" }).end(JSON.stringify(body));
}

async function knownRepo(name: string): Promise<RepoName> {
  const repo = repoName(name);
  if (!(await repos()).includes(repo)) throw new HttpError(404, `unknown repository: ${name}`);
  return repo;
}

/** Long-running work is detached from the request; failures land in the log, never crash the process. */
function detach(label: string, work: Promise<unknown>): void {
  work.catch((err: unknown) => console.error(`[patchline] ${label} failed:`, err));
}

function verifySignature(req: IncomingMessage, raw: Buffer): void {
  const secret = process.env.FORGE_WEBHOOK_SECRET;
  if (!secret) return;
  const header = req.headers["x-gitea-signature"];
  const given = Buffer.from(typeof header === "string" ? header : "", "hex");
  const expected = createHmac("sha256", secret).update(raw).digest();
  if (given.length !== expected.length || !timingSafeEqual(given, expected)) throw new HttpError(401, "bad signature");
}

// Patchline's own merges land on main too; re-scanning them would loop.
const isPatchlineCommit = (message: string) => message.startsWith("fix(deps)") || message.includes("patchline/");

async function webhook(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const raw = await readBody(req);
  verifySignature(req, raw);
  const event = req.headers["x-gitea-event"];

  if (event === "push") {
    const p = PushPayload.safeParse(parseJson(raw));
    if (!p.success) throw new HttpError(400, `invalid push payload: ${z.prettifyError(p.error)}`);
    const { ref, repository, head_commit } = p.data;
    const onDefault = ref === `refs/heads/${repository.default_branch ?? "main"}`;
    if (!onDefault || !head_commit || isPatchlineCommit(head_commit.message)) return send(res, 204);
    const repo = await knownRepo(repository.name);
    detach(`remediate ${repo}`, remediate(repo));
    return send(res, 202, { accepted: "remediate", repo });
  }

  if (event === "pull_request") {
    const p = PullRequestPayload.safeParse(parseJson(raw));
    if (!p.success) throw new HttpError(400, `invalid pull_request payload: ${z.prettifyError(p.error)}`);
    const { action, number, repository, pull_request } = p.data;
    if (action !== "closed" || !pull_request.merged || !pull_request.head.ref.startsWith("patchline/")) return send(res, 204);
    const repo = await knownRepo(repository.name);
    detach(`onMerged ${repo}#${number}`, onMerged(repo, number));
    return send(res, 202, { accepted: "merged", repo, number });
  }

  send(res, 204);
}

async function startRemediation(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const body = RemediateBody.safeParse(parseJson(await readBody(req)));
  if (!body.success) throw new HttpError(400, z.prettifyError(body.error));
  const targets = body.data.repo ? [await knownRepo(body.data.repo)] : await repos();
  for (const repo of targets) detach(`remediate ${repo}`, remediate(repo));
  send(res, 202, { accepted: targets });
}

function events(req: IncomingMessage, res: ServerResponse): void {
  res.writeHead(200, {
    "content-type": "text/event-stream; charset=utf-8",
    "cache-control": "no-cache, no-transform",
    connection: "keep-alive",
    "x-accel-buffering": "no",
  });
  const write = (e: StampedEvent) => res.write(`id: ${e.seq}\ndata: ${JSON.stringify(e)}\n\n`);
  // On reconnect the browser sends the last seq it saw; replay only what it missed.
  // A seq beyond our ledger means the server restarted on a different ledger, so start the client over.
  const history = ledger.history();
  let after = Number(req.headers["last-event-id"] ?? 0) || 0;
  res.write("retry: 2000\n\n");
  if (after > (history.at(-1)?.seq ?? 0)) {
    res.write("event: reset\ndata: {}\n\n");
    after = 0;
  }
  for (const e of history) if (e.seq > after) write(e);
  res.write("event: replayed\ndata: {}\n\n");
  const unsubscribe = ledger.subscribe(write);
  const heartbeat = setInterval(() => res.write(": heartbeat\n\n"), HEARTBEAT_MS);
  req.on("close", () => {
    clearInterval(heartbeat);
    unsubscribe();
  });
}

async function serveStatic(res: ServerResponse, relative: string): Promise<void> {
  const path = normalize(join(UI_DIR, relative));
  if (!path.startsWith(UI_DIR) || path.endsWith(sep)) throw new HttpError(404, "not found");
  const body = await readFile(path).catch(() => {
    throw new HttpError(404, "not found");
  });
  res.writeHead(200, { "content-type": MIME[extname(path)] ?? "application/octet-stream", "cache-control": "no-cache" }).end(body);
}

async function route(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const { pathname } = new URL(req.url ?? "/", "http://localhost");
  const key = `${req.method} ${pathname}`;
  if (key === "GET /") return serveStatic(res, "index.html");
  if (req.method === "GET" && pathname.startsWith("/ui/")) return serveStatic(res, decodeURIComponent(pathname.slice(4)));
  if (key === "GET /api/events") return events(req, res);
  if (key === "GET /api/repos") return send(res, 200, await repos());
  if (key === "POST /api/remediate") return startRemediation(req, res);
  if (key === "POST /webhooks/forge") return webhook(req, res);
  throw new HttpError(404, "not found");
}

const server = createServer((req, res) => {
  route(req, res).catch((err: unknown) => {
    const status = err instanceof HttpError ? err.status : 500;
    if (status === 500) console.error("[patchline] request failed:", err);
    if (!res.headersSent) send(res, status, { error: err instanceof Error ? err.message : String(err) });
    else res.end();
  });
});

server.listen(PORT, "0.0.0.0", () => console.log(`[patchline] listening on http://0.0.0.0:${PORT}`));
