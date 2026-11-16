import { EventEmitter } from "node:events";
import { appendFileSync, existsSync, mkdirSync, readFileSync } from "node:fs";
import { dirname } from "node:path";
import type { PatchlineEvent, RemediationId, RepoName, StampedEvent } from "./domain.ts";

/** Append-only JSONL audit trail. The dashboard, PR body and incident are projections of it. */
export class Ledger {
  readonly #path: string;
  readonly #events: StampedEvent[] = [];
  readonly #bus = new EventEmitter();
  #seq = 0;

  constructor(path: string) {
    this.#path = path;
    mkdirSync(dirname(path), { recursive: true });
    if (existsSync(path)) {
      for (const line of readFileSync(path, "utf8").split("\n")) {
        if (!line) continue;
        const e: StampedEvent = JSON.parse(line);
        this.#events.push(e);
        this.#seq = Math.max(this.#seq, e.seq);
      }
    }
    this.#bus.setMaxListeners(100);
  }

  append(remediation: RemediationId, repo: RepoName, event: PatchlineEvent): StampedEvent {
    const stamped: StampedEvent = { ...event, remediation, repo, at: new Date().toISOString(), seq: ++this.#seq };
    this.#events.push(stamped);
    appendFileSync(this.#path, JSON.stringify(stamped) + "\n");
    this.#bus.emit("event", stamped);
    return stamped;
  }

  /** Bind a remediation so callers can just `emit(event)`. */
  emitterFor(remediation: RemediationId, repo: RepoName): (event: PatchlineEvent) => void {
    return (event) => void this.append(remediation, repo, event);
  }

  history(remediation?: RemediationId): StampedEvent[] {
    return remediation ? this.#events.filter((e) => e.remediation === remediation) : [...this.#events];
  }

  subscribe(fn: (e: StampedEvent) => void): () => void {
    this.#bus.on("event", fn);
    return () => this.#bus.off("event", fn);
  }
}
