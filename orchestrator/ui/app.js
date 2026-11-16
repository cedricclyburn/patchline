// Patchline readiness board. Folds the ledger's StampedEvents (domain.ts) into one view per remediation.

const TRACK = [
  { key: "scan", label: "Scan", model: false },
  { key: "triage", label: "Triage", model: true },
  { key: "remediate", label: "Patch", model: true },
  { key: "verify", label: "Verify", model: false },
  { key: "review", label: "Review", model: true },
  { key: "gate", label: "Gate", model: false },
  { key: "merge", label: "Merge", model: false },
  { key: "deploy", label: "Deploy", model: false },
];

// Stage -> position on the track. Terminal stages that are not a track position resolve against the last one reached.
const STAGE_POS = {
  queued: -1, scanning: 0, triaging: 1, remediating: 2, verifying: 3, reviewing: 4, gating: 5,
  awaiting_approval: 6, merged: 6, deploying: 7, deployed: 7, rolled_back: 7,
};

const STAGE_TEXT = {
  queued: "Queued", scanning: "Scanning", triaging: "Triaging findings", remediating: "Writing patch",
  verifying: "Verifying", reviewing: "Independent review", gating: "Gating", awaiting_approval: "Awaiting human approval",
  merged: "Merged", deploying: "Deploying", deployed: "Deployed and healthy", rolled_back: "Rolled back",
  nothing_to_do: "Nothing to do", escalated: "Escalated to owners", failed: "Failed",
};

const TERMINAL = new Set(["awaiting_approval", "deployed", "rolled_back", "nothing_to_do", "escalated", "failed"]);

const CHECKS = [
  ["policy", "Policy file loaded", false],
  ["baseline_tests", "Baseline tests on unpatched code", false],
  ["patched_tests", "Tests on patched code", false],
  ["targeted_vulns_cleared", "Targeted vulnerabilities cleared on rescan", false],
  ["no_new_vulns", "No new vulnerabilities introduced", false],
  ["test_count_not_reduced", "Test count not reduced", false],
  ["diff_scope", "Diff stays in scope", false],
  ["independent_review", "Independent review", true],
];
const PRE_PATCH_CHECKS = new Set(["policy", "baseline_tests"]);

const ROLES = [
  ["triage", "Triage"],
  ["remediate", "Patch"],
  ["review", "Review"],
];

const SEVERITY_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, UNKNOWN: 4 };
const VEX_TEXT = {
  affected: "Affected",
  not_affected: "Not affected",
  under_investigation: "Investigating",
};
const JUSTIFICATION_TEXT = {
  vulnerable_code_not_present: "code not present",
  vulnerable_code_not_in_execute_path: "not in execute path",
  vulnerable_code_cannot_be_controlled_by_adversary: "not adversary controlled",
  inline_mitigations_already_exist: "mitigated inline",
};
const MAX_LINES_PER_ROLE = 600;

// ---- state ---------------------------------------------------------------

/** @type {Map<string, ReturnType<typeof blank>>} */
const runs = new Map();
const ui = {
  selected: decodeURIComponent(location.hash.slice(1)) || null,
  pinned: Boolean(location.hash.slice(1)), // a click pins selection; otherwise follow the newest activity
  role: null, // transcript tab; null follows the most recent speaker
  live: false, // false while the server replays history
  lastSeq: 0,
  events: 0,
  lastAt: null,
  repos: [],
  reposError: null,
  requested: new Map(), // repo|"*" -> timestamp of a Run click
  flips: new Map(), // `${id}:${check}` -> time a live check changed state
};

function blank(e) {
  return {
    id: e.remediation, repo: e.repo, startedAt: e.at, updatedAt: e.at,
    stage: "queued", note: null, reached: -1, attempts: 0,
    findings: [], policy: null, incident: null, triage: new Map(),
    checks: new Map(), prior: new Map(), agents: new Map(), lastRole: null,
    changes: null, diffStat: "", review: null, gate: null, pr: null, deploys: [], errors: [],
  };
}

function agentFor(r, role, model) {
  let a = r.agents.get(role);
  if (!a) r.agents.set(role, (a = { model, runs: [] }));
  if (model) a.model = model;
  const last = a.runs.at(-1);
  if (!last || last.done) a.runs.push({ lines: [], done: null, startedAt: null });
  return a;
}

function reduce(e) {
  let r = runs.get(e.remediation);
  if (!r) runs.set(e.remediation, (r = blank(e)));
  r.updatedAt = e.at;
  switch (e.type) {
    case "stage": {
      if (e.stage === "remediating") {
        r.attempts += 1;
        // A retry re-measures everything after the patch, so those rows go back to pending.
        if (r.attempts > 1) {
          for (const [name, c] of r.checks) if (!PRE_PATCH_CHECKS.has(name)) { r.prior.set(name, c); r.checks.delete(name); }
        }
      }
      r.stage = e.stage;
      r.note = e.note ?? null;
      const pos = STAGE_POS[e.stage];
      if (pos !== undefined) r.reached = pos;
      break;
    }
    case "findings": r.findings = e.findings; break;
    case "policy": r.policy = e.policy; break;
    case "incident": r.incident = { url: e.url, number: e.number }; break;
    case "triage": for (const v of e.verdicts) r.triage.set(v.id, v); break;
    case "agent": {
      const run = agentFor(r, e.role, e.model).runs.at(-1);
      run.startedAt ??= e.at;
      run.lines.push({ at: e.at, kind: e.kind, text: e.text });
      if (run.lines.length > MAX_LINES_PER_ROLE) run.lines.splice(0, run.lines.length - MAX_LINES_PER_ROLE);
      r.lastRole = e.role;
      break;
    }
    case "agent_done": {
      const a = r.agents.get(e.role) ?? agentFor(r, e.role, e.model);
      const run = a.runs.at(-1);
      run.done = { status: e.status, durationMs: e.durationMs, summary: e.summary };
      r.lastRole = e.role;
      break;
    }
    case "check": {
      const prev = r.checks.get(e.check.name) ?? r.prior.get(e.check.name);
      if (ui.live && prev?.state !== e.check.state) ui.flips.set(`${r.id}:${e.check.name}`, performance.now());
      r.checks.set(e.check.name, e.check);
      break;
    }
    case "changes": r.changes = e.changes; r.diffStat = e.diffStat; break;
    case "review": r.review = e.review; break;
    case "gate": r.gate = e.decision; break;
    case "pr": r.pr = { url: e.url, number: e.number, branch: e.branch }; break;
    case "deploy": r.deploys.push({ status: e.status, detail: e.detail, at: e.at }); break;
    case "error": r.errors.push({ message: e.message, at: e.at }); break;
  }
}

// ---- helpers -------------------------------------------------------------

const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
const $ = (id) => document.getElementById(id);
const ms = (iso) => Date.parse(iso);

function duration(msTotal) {
  const s = Math.max(0, Math.round(msTotal / 1000));
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ${String(s % 60).padStart(2, "0")}s`;
  return `${Math.floor(m / 60)}h ${String(m % 60).padStart(2, "0")}m`;
}
const clock = (iso) => new Date(iso).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false });
const offset = (iso, from) => {
  const s = Math.max(0, Math.round((ms(iso) - ms(from)) / 1000));
  return `+${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`;
};
const elapsed = (r) => (TERMINAL.has(r.stage) ? ms(r.updatedAt) : Date.now()) - ms(r.startedAt);
const isActive = (r) => !TERMINAL.has(r.stage);

/** Cell state for each track position. */
function cells(r) {
  const at = r.reached;
  return TRACK.map((_, i) => {
    if (r.stage === "nothing_to_do") return i === 0 ? "done" : "skip";
    if (i < at) return "done";
    if (i > at) return "idle";
    switch (r.stage) {
      case "awaiting_approval": return "hold";
      case "merged": case "deployed": return "done";
      case "rolled_back": case "escalated": case "failed": return "fail";
      default: return "active";
    }
  });
}

function sortedRuns() {
  return [...runs.values()].sort((a, b) => (isActive(b) - isActive(a)) || ms(b.startedAt) - ms(a.startedAt));
}

function current() {
  if (ui.selected && runs.has(ui.selected)) return runs.get(ui.selected);
  const first = sortedRuns()[0];
  return first ?? null;
}

// ---- render --------------------------------------------------------------

const lastHtml = new Map();
/** Writes innerHTML only when it changed, so scroll and selection survive unrelated events. */
function put(el, html) {
  if (lastHtml.get(el) === html) return false;
  lastHtml.set(el, html);
  el.innerHTML = html;
  return true;
}

// Board vocabulary. Cell states from cells() map onto a launch poll's calls.
const CALL = {
  done: { cls: "go", word: "Go" },
  hold: { cls: "hold", word: "Hold" },
  fail: { cls: "nogo", word: "No go" },
  active: { cls: "active", word: "" },
  idle: { cls: "pending", word: "" },
  skip: { cls: "skipped", word: "" },
};
const CALL_ARIA = { done: "Go", hold: "Hold", fail: "No go", active: "in progress", idle: "not reached", skip: "skipped" };
const CHECK_CALL = { pass: "done", fail: "fail", warn: "hold", pending: "idle", skipped: "skip" };

const lower = (s) => String(s ?? "").toLowerCase();
const plural = (n, one, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

function renderStatus() {
  const meta = ui.events ? `${plural(ui.events, "event")}${ui.lastAt ? `, last ${duration(Date.now() - ms(ui.lastAt))} ago` : ""}` : "Ledger empty";
  $("stream-meta").textContent = meta;
}

/** Latest run per repository, plus every older run, in /api/repos order so rows never jump. */
function boardRows() {
  const byRepo = new Map();
  for (const r of runs.values()) {
    const list = byRepo.get(r.repo) ?? [];
    list.push(r);
    byRepo.set(r.repo, list);
  }
  const order = [...ui.repos, ...[...byRepo.keys()].filter((k) => !ui.repos.includes(k)).sort()];
  const latest = [];
  const earlier = [];
  for (const repo of order) {
    const list = (byRepo.get(repo) ?? []).sort((a, b) => ms(b.startedAt) - ms(a.startedAt));
    latest.push({ repo, run: list[0] ?? null });
    for (const r of list.slice(1)) earlier.push({ repo, run: r });
  }
  earlier.sort((a, b) => ms(b.run.startedAt) - ms(a.run.startedAt));
  return { latest, earlier };
}

function cellHtml(state, station, extra = "") {
  const c = CALL[state];
  return `<span class="call ${c.cls}" role="cell" aria-label="${esc(station)}: ${CALL_ARIA[state]}"><span class="call-word">${c.word}</span>${extra}</span>`;
}

function rowSub(r) {
  if (!r) return "Not polled yet";
  const bits = [];
  if (r.findings.length) bits.push(plural(r.findings.length, "finding"));
  else if (r.reached >= 1 || TERMINAL.has(r.stage)) bits.push("No findings");
  if (r.policy) bits.push(`${lower(r.policy.riskClass)} risk`);
  return `${bits.map(esc).join(", ")}${bits.length ? ", " : ""}<span data-elapsed="${esc(r.id)}"></span>`;
}

function pollRow({ repo, run: r }, sel, busy, earlier = false) {
  const cs = r ? cells(r) : TRACK.map(() => "idle");
  const selected = Boolean(r && sel && sel.id === r.id);
  const running = Boolean(r && isActive(r));
  const label = earlier ? `${esc(repo)}<span class="row-when">${clock(r.startedAt)}</span>` : esc(repo);
  const name = r
    ? `<button type="button" class="row-name" data-select="${esc(r.id)}" aria-pressed="${selected}">${label}</button>`
    : `<span class="row-name">${label}</span>`;
  const runBtn = earlier ? `<span role="cell"></span>` : `<span role="cell" class="row-action"><button class="btn btn-quiet" type="button" data-run="${esc(repo)}" ${busy(repo) || running ? "disabled" : ""}>${busy(repo) ? "Requested" : running ? "Running" : "Run"}</button></span>`;
  return `<div class="poll-row${selected ? " selected" : ""}${r ? " selectable" : ""}${earlier ? " earlier" : ""}" role="row"${r ? ` data-row="${esc(r.id)}"` : ""}>
    <span class="row-id" role="rowheader">${name}<span class="row-sub">${rowSub(r)}</span></span>
    <span class="row-calls">${TRACK.map((t, i) => {
      const retry = r && t.key === "remediate" && r.attempts > 1 ? `<b class="retry" title="${r.attempts} patch attempts">×${r.attempts}</b>` : "";
      return cellHtml(cs[i], t.label, retry);
    }).join("")}</span>
    ${runBtn}
  </div>`;
}

function renderBoard(sel) {
  const now = Date.now();
  const busy = (key) => (ui.requested.get(key) ?? 0) > now - 4000;
  const { latest, earlier } = boardRows();
  const head = `<div class="poll-row poll-head" role="row">
    <span class="row-id" role="columnheader"><span class="visually-hidden">Repository</span></span>
    <span class="row-calls">${TRACK.map((t) => `<span class="station${t.model ? " by-model" : ""}" role="columnheader">${t.model ? `<i class="model-mark" aria-hidden="true"></i>` : ""}${t.label}${t.model ? `<span class="visually-hidden">, model proposes</span>` : ""}</span>`).join("")}</span>
    <span role="columnheader"><span class="visually-hidden">Action</span></span>
  </div>`;
  const rows = latest.map((row) => pollRow(row, sel, busy)).join("");
  const older = earlier.length
    ? `<details class="earlier-runs"${ui.earlierOpen || earlier.some((e) => sel && e.run.id === sel.id) ? " open" : ""}>
        <summary>Earlier runs (${earlier.length})</summary>
        ${earlier.map((row) => pollRow(row, sel, busy, true)).join("")}
      </details>`
    : "";
  // Live events rebuild the board; keep keyboard focus on the same control across the rebuild.
  const focused = document.activeElement?.closest?.("#poll [data-select], #poll [data-run], #poll summary");
  const focusKey = focused && (focused.matches("summary") ? "summary" : focused.hasAttribute("data-select") ? `[data-select="${CSS.escape(focused.getAttribute("data-select"))}"]` : `[data-run="${CSS.escape(focused.getAttribute("data-run"))}"]`);
  if (put($("poll"), head + rows + older) && focusKey) $("poll").querySelector(focusKey)?.focus();

  const fleet = $("run-fleet");
  fleet.disabled = busy("*") || ui.repos.length === 0;
  fleet.textContent = busy("*") ? "Requested" : "Run fleet";

  const key = `<p class="foot-key"><i class="model-mark" aria-hidden="true"></i>A model proposes at these stations. Every call is made by a measured check or the repository's policy.</p>`;
  const foot = ui.reposError
    ? `<p class="foot-error">Could not load repositories: ${esc(ui.reposError)}. Check that the forge is reachable, then reload.</p>`
    : runs.size === 0
      ? `<p class="foot-empty">${ui.repos.length ? "Run fleet to poll every repository." : "No repositories found on the forge yet."}</p>${key}`
      : key;
  put($("board-foot"), foot);
}

// ---- detail --------------------------------------------------------------

function statusSentence(r) {
  const owner = r.policy?.owner;
  const pr = r.pr ? `PR #${r.pr.number}` : null;
  const lastErr = r.errors.at(-1)?.message;
  switch (r.stage) {
    case "queued": return "Queued. Polling starts when a worker is free.";
    case "scanning": return "Scanning dependencies for known vulnerabilities.";
    case "triaging": return "A model is checking whether each finding is reachable.";
    case "remediating": return r.attempts > 1
      ? `A model is rewriting the patch with verifier feedback, attempt ${r.attempts}.`
      : "A model is writing the patch.";
    case "verifying": return "Running the test suite and rescanning the patched code.";
    case "reviewing": return "A second model is reviewing the diff.";
    case "gating": return "Applying the repository policy to the measured results.";
    case "awaiting_approval": return `Waiting for ${owner ? `a ${owner} approver` : "a human approver"}${pr ? ` on ${pr}` : ""}.`;
    case "merged": return `${pr ? `Merged ${pr}` : "Merged"}. Deploy starts next.`;
    case "deploying": return `Deploying${pr ? ` ${pr}` : ""} and watching health checks.`;
    case "deployed": return "Deployed and healthy.";
    case "rolled_back": return "Deploy failed its health checks and was rolled back.";
    case "nothing_to_do": return "No fixable findings. Nothing to change.";
    case "escalated": return `Escalated to ${owner ?? "the owners"}: ${r.note ?? r.gate?.reasons[0] ?? "a check did not pass"}.`;
    case "failed": return `Failed at ${TRACK[r.reached]?.label ?? "start"}${lastErr ? `: ${lastErr}` : "."}`;
    default: return STAGE_TEXT[r.stage] ?? r.stage;
  }
}

function policySentence(p) {
  if (!p) return `<p class="policy none">Policy not loaded yet.</p>`;
  const approval = p.approval === "auto_approve" ? "merges automatically when every check passes" : "every merge needs a human approver";
  return `<p class="policy">
    ${p.failedClosed ? `<span class="policy-closed">Policy file missing or invalid, so the strictest rules apply.</span> ` : ""}
    Owned by <b>${esc(p.owner)}</b>. ${esc(cap(lower(p.riskClass)))} risk class; ${approval}.
    <span class="policy-why">${esc(p.rationale)}</span>
  </p>`;
}
const cap = (s) => s.charAt(0).toUpperCase() + s.slice(1);

function renderLinks(r) {
  const links = [];
  if (r.incident) links.push(`<a href="${esc(r.incident.url)}" target="_blank" rel="noreferrer">Incident #${r.incident.number}</a>`);
  if (r.pr) links.push(`<span class="link-pr"><a href="${esc(r.pr.url)}" target="_blank" rel="noreferrer">PR #${r.pr.number}</a><code>${esc(r.pr.branch)}</code></span>`);
  const dep = r.deploys.at(-1);
  if (dep) {
    const word = { started: "Deploy started", healthy: "Deploy healthy", rolled_back: "Deploy rolled back" }[dep.status] ?? dep.status;
    links.push(`<span class="deploy ${esc(dep.status)}">${word}: <code>${esc(dep.detail)}</code></span>`);
  }
  links.push(`<span class="when">Started ${clock(r.startedAt)}, ${isActive(r) ? "running" : "took"} <span data-elapsed="${esc(r.id)}"></span></span>`);
  return links.join("");
}

function callChip(state, extraCls = "") {
  const c = CALL[state];
  return `<span class="call chip ${c.cls} ${extraCls}" aria-hidden="true"><span class="call-word">${c.word}</span></span>`;
}

function renderChecks(r) {
  const now = performance.now();
  return `<ol class="checks">${CHECKS.map(([name, label, byModel]) => {
    const c = r.checks.get(name);
    const state = c?.state ?? "pending";
    const prior = r.prior.get(name);
    const flipped = now - (ui.flips.get(`${r.id}:${name}`) ?? -1e9) < 1400;
    const [head, ...rest] = (c?.detail ?? "").split("\n");
    const detail = c ? esc(head) : prior ? "Re-measuring on the new patch." : "Not measured yet.";
    return `<li class="check ${state}${flipped ? " flipped" : ""}">
      ${callChip(CHECK_CALL[state] ?? "idle")}
      <span class="check-body">
        <span class="check-name">${esc(label)}${byModel ? `<span class="model-input"><i class="model-mark" aria-hidden="true"></i>reviewer model input</span>` : ""}<span class="visually-hidden">: ${esc(state)}</span></span>
        <span class="check-detail">${detail}</span>
        ${rest.length ? `<pre class="check-output">${esc(rest.join("\n"))}</pre>` : ""}
        ${prior && prior.state !== c?.state ? `<span class="check-prior">Attempt ${r.attempts - 1}: ${esc(prior.state)}, ${esc(prior.detail.split("\n")[0])}</span>` : ""}
      </span>
    </li>`;
  }).join("")}</ol>`;
}

function renderGate(r) {
  if (!r.gate) {
    return `<div class="gate pending">${callChip("idle", "gate-chip")}<div class="gate-body"><p class="gate-kind">Gate decision</p><p class="none">Decided after review, from policy, checks and dependency changes.</p></div></div>`;
  }
  const g = r.gate;
  const [state, title] = {
    auto_merge: ["done", "Merge automatically"],
    needs_approval: ["hold", "Needs a human approver"],
    blocked: ["fail", "Blocked"],
  }[g.kind] ?? ["idle", g.kind];
  return `<div class="gate ${esc(g.kind)}">
    ${callChip(state, "gate-chip")}
    <div class="gate-body">
      <p class="gate-kind">${esc(title)}</p>
      <ul class="gate-reasons">${g.reasons.map((x) => `<li>${esc(x)}</li>`).join("")}</ul>
      <p class="gate-foot">Decided by a fixed rule table. Model output can add caution here, never remove it.</p>
    </div>
  </div>`;
}

function renderFindings(r) {
  if (!r.findings.length) {
    const msg = r.stage === "scanning" || r.stage === "queued" ? "Waiting for the scanner."
      : r.stage === "failed" ? "No scanner output was recorded before the run failed."
      : "The scanner reported no findings.";
    return `<p class="none">${msg}</p>`;
  }
  const rows = [...r.findings].sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] || a.pkg.localeCompare(b.pkg));
  return `<div class="table-wrap"><table class="grid findings">
    <colgroup><col class="c-adv"><col class="c-pkg"><col class="c-ver"><col class="c-sev"><col class="c-tri"></colgroup>
    <thead><tr><th>Advisory</th><th>Package</th><th>Version</th><th>Severity</th><th class="model-col"><i class="model-mark" aria-hidden="true"></i>Triage verdict</th></tr></thead>
    <tbody>${rows.map((f) => {
      const v = r.triage.get(f.id);
      const verdict = v
        ? `<span class="verdict ${esc(v.status)}">${VEX_TEXT[v.status] ?? esc(v.status)}${v.justification ? `, ${JUSTIFICATION_TEXT[v.justification] ?? esc(v.justification)}` : ""}</span>
           <code class="evidence" title="${esc(v.evidence)}">${esc(v.evidence)}</code>`
        : `<span class="none">${r.reached >= 1 ? "Awaiting the triage model." : ""}</span>`;
      const id = f.url ? `<a href="${esc(f.url)}" target="_blank" rel="noreferrer">${esc(f.id)}</a>` : esc(f.id);
      return `<tr>
        <td class="adv"><span class="vid">${id}</span><span class="ftitle" title="${esc(f.title)}">${esc(f.title)}</span></td>
        <td class="pkg">${esc(f.pkg)}</td>
        <td class="ver"><span>${esc(f.installed)} <span class="to">→</span></span> <span>${f.fixed ? esc(f.fixed) : `<span class="nofix">no fix</span>`}</span></td>
        <td class="sev sev-${esc(f.severity)}">${esc(cap(lower(f.severity)))}<span class="cvss">${f.cvss === null ? "" : f.cvss.toFixed(1)}</span></td>
        <td class="model-col">${verdict}</td>
      </tr>`;
    }).join("")}</tbody>
  </table></div>`;
}

function renderReview(r) {
  if (!r.review) return `<p class="none">${r.reached >= 4 ? "The reviewer model is reading the diff." : "Runs after verification passes."}</p>`;
  const v = r.review;
  return `<div class="review ${esc(v.verdict)}">
    <p class="review-verdict">${v.verdict === "approve" ? "Approves" : "Raises concerns"}<span class="review-model">${esc(v.model)}</span></p>
    <p class="review-notes">${esc(v.notes)}</p>
  </div>`;
}

function renderChanges(r) {
  if (!r.changes) return `<p class="none">${r.reached >= 3 ? "Measured from the lockfile once verification passes." : "No patch yet."}</p>`;
  return `<div class="table-wrap"><table class="grid changes">
    <thead><tr><th>Package</th><th>From</th><th>To</th><th>Bump</th></tr></thead>
    <tbody>${r.changes.map((c) => `<tr>
      <td class="pkg">${esc(c.pkg)}</td><td class="ver">${esc(c.from)}</td><td class="ver">${esc(c.to)}</td>
      <td>${c.major ? `<span class="major">Major</span>` : `<span class="minor">Minor or patch</span>`}</td>
    </tr>`).join("")}</tbody>
  </table></div>
  ${r.diffStat ? `<pre class="diffstat">${esc(r.diffStat.replace(/^\n+|\n+$/g, ""))}</pre>` : ""}`;
}

function pickRole(r) {
  if (ui.role && r.agents.has(ui.role)) return ui.role;
  return r.lastRole ?? "triage";
}

const defaultModel = (role) => (role === "remediate" ? "composer-2.5" : "grok-4.7");

function renderTabs(r, role) {
  return ROLES.map(([key, label]) => {
    const a = r.agents.get(key);
    const run = a?.runs.at(-1);
    const status = !a ? "idle" : run?.done ? "done" : "running";
    const meta = !a ? "Not started" : run?.done ? duration(run.done.durationMs) : "Running";
    return `<button type="button" role="tab" class="tab ${status}${key === role ? " on" : ""}" data-role="${key}" aria-selected="${key === role}">
      <span class="tab-role">${label}</span>
      <span class="tab-model">${esc(a?.model ?? defaultModel(key))}</span>
      <span class="tab-meta">${meta}</span>
    </button>`;
  }).join("");
}

const KIND_MARK = { tool: "tool", text: "says", thinking: "thinks" };

function renderTranscript(r, role) {
  const a = r.agents.get(role);
  if (!a) return `<p class="none log-none">This agent has not started.</p>`;
  return a.runs.map((run, i) => `
    ${a.runs.length > 1 ? `<div class="attempt">Attempt ${i + 1}</div>` : ""}
    ${run.lines.map((l) => `<div class="line ${esc(l.kind)}"><span class="t">${offset(l.at, r.startedAt)}</span><span class="k">${KIND_MARK[l.kind] ?? esc(l.kind)}</span><span class="x">${esc(l.text)}</span></div>`).join("")}
    ${run.done
      ? `<div class="line done"><span class="t"></span><span class="x">${esc(cap(String(run.done.status)))}: ${esc(run.done.summary)}, ${duration(run.done.durationMs)}</span></div>`
      : `<div class="line cursor"><span class="t"></span><span class="k"></span><span class="x">Working</span></div>`}
  `).join("");
}

function detailSkeleton() {
  $("detail").innerHTML = `
    <header class="detail-head" id="d-head"></header>
    <div class="errors" id="d-errors"></div>
    <div class="cols">
      <div class="col">
        <section class="panel" aria-labelledby="h-checks">
          <div class="panel-head"><h3 id="h-checks">Readiness checks</h3><p class="panel-src">Measured by tests, scanner and policy</p></div>
          <div id="d-checks"></div>
          <div id="d-gate"></div>
        </section>
        <section class="panel" aria-labelledby="h-findings">
          <div class="panel-head"><h3 id="h-findings">Findings</h3><p class="panel-src">From the scanner, with the triage model's reachability call</p></div>
          <div id="d-findings"></div>
        </section>
      </div>
      <div class="col">
        <section class="panel panel-model" aria-labelledby="h-log">
          <div class="panel-head"><h3 id="h-log"><i class="model-mark" aria-hidden="true"></i>Agent log</h3><p class="panel-src">Proposed by models</p></div>
          <div class="tabs" role="tablist" aria-label="Agent" id="d-tabs"></div>
          <div class="log" id="d-transcript" role="tabpanel" tabindex="0"></div>
        </section>
        <section class="panel panel-model" aria-labelledby="h-review">
          <div class="panel-head"><h3 id="h-review"><i class="model-mark" aria-hidden="true"></i>Reviewer verdict</h3><p class="panel-src">A different model reads the diff</p></div>
          <div id="d-review"></div>
        </section>
        <section class="panel" aria-labelledby="h-changes">
          <div class="panel-head"><h3 id="h-changes">Dependency changes</h3><p class="panel-src">Measured from the lockfile diff</p></div>
          <div id="d-changes"></div>
        </section>
      </div>
    </div>`;
  for (const id of ["d-head", "d-errors", "d-findings", "d-changes", "d-checks", "d-review", "d-gate", "d-tabs", "d-transcript"]) lastHtml.delete($(id));
}

function renderDetail(r) {
  if (!r) {
    $("detail").innerHTML = "";
    lastHtml.clear();
    return;
  }
  if (!$("d-head")) detailSkeleton();
  const tone = r.stage === "deployed" ? "go" : r.stage === "awaiting_approval" ? "hold" : ["rolled_back", "escalated", "failed"].includes(r.stage) ? "nogo" : "live";
  put($("d-head"), `
    <h2 class="repo">${esc(r.repo)}</h2>
    <p class="status ${tone}">${esc(statusSentence(r))}</p>
    <div class="links">${renderLinks(r)}</div>
    ${policySentence(r.policy)}`);
  // The status sentence already carries the fatal error, so only earlier ones are listed.
  const shown = r.stage === "failed" ? r.errors.slice(0, -1) : r.errors;
  put($("d-errors"), shown.map((e) => `<p class="error"><span class="error-at">${clock(e.at)}</span>${esc(e.message)}</p>`).join(""));
  put($("d-checks"), renderChecks(r));
  put($("d-gate"), renderGate(r));
  put($("d-findings"), renderFindings(r));
  put($("d-review"), renderReview(r));
  put($("d-changes"), renderChanges(r));
  const role = pickRole(r);
  put($("d-tabs"), renderTabs(r, role));
  const box = $("d-transcript");
  const stick = box.scrollHeight - box.scrollTop - box.clientHeight < 40;
  if (put(box, renderTranscript(r, role)) && stick) box.scrollTop = box.scrollHeight;
}

let queued = false;
function schedule() {
  if (queued) return;
  queued = true;
  requestAnimationFrame(() => {
    queued = false;
    const sel = current();
    renderStatus();
    renderBoard(sel);
    renderDetail(sel);
    tickClocks();
  });
}

// ---- wiring --------------------------------------------------------------

function connect() {
  const es = new EventSource("/api/events");
  const status = $("stream");
  es.onopen = () => { status.dataset.state = ui.live ? "live" : "replaying"; $("stream-label").textContent = ui.live ? "Live" : "Replaying ledger"; };
  es.onerror = () => { status.dataset.state = "down"; $("stream-label").textContent = "Reconnecting"; };
  es.addEventListener("reset", () => {
    runs.clear();
    ui.flips.clear();
    Object.assign(ui, { lastSeq: 0, events: 0, lastAt: null, live: false });
    schedule();
  });
  es.addEventListener("replayed", () => {
    ui.live = true;
    status.dataset.state = "live";
    $("stream-label").textContent = "Live";
    schedule();
  });
  es.onmessage = (m) => {
    const e = JSON.parse(m.data);
    if (e.seq <= ui.lastSeq) return;
    ui.lastSeq = e.seq;
    ui.events += 1;
    ui.lastAt = e.at;
    reduce(e);
    if (ui.live && !ui.pinned && e.type === "stage" && e.stage === "scanning") ui.selected = e.remediation;
    schedule();
  };
}

async function loadRepos() {
  try {
    const res = await fetch("/api/repos");
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    ui.repos = await res.json();
    ui.reposError = null;
  } catch (err) {
    ui.reposError = err instanceof Error ? err.message : String(err);
  }
  schedule();
}

async function run(repo) {
  ui.requested.set(repo ?? "*", Date.now());
  schedule();
  setTimeout(schedule, 4100);
  const res = await fetch("/api/remediate", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(repo ? { repo } : {}),
  }).catch(() => null);
  if (!res || res.status !== 202) {
    ui.requested.delete(repo ?? "*");
    ui.reposError = `run request failed${res ? ` (HTTP ${res.status})` : ""}`;
    schedule();
  }
}

document.addEventListener("click", (ev) => {
  const t = ev.target instanceof Element ? ev.target : null;
  const btn = t?.closest("[data-run]");
  if (btn) { run(btn.getAttribute("data-run")); return; }
  if (t?.closest("#run-fleet")) { run(null); return; }
  const tab = t?.closest("[data-role]");
  if (tab) { ui.role = tab.getAttribute("data-role"); schedule(); return; }
  if (t?.closest("a, summary")) return;
  // The repo name is the keyboard target; the rest of the row is a larger pointer target for the same action.
  const row = t?.closest("[data-select], [data-row]");
  if (row) {
    ui.selected = row.getAttribute("data-select") ?? row.getAttribute("data-row");
    ui.pinned = true;
    ui.role = null;
    history.replaceState(null, "", `#${encodeURIComponent(ui.selected)}`);
    schedule();
  }
});

// Re-renders rebuild the board, so the disclosure's state lives in ui.
document.addEventListener("toggle", (ev) => {
  if (ev.target instanceof HTMLDetailsElement && ev.target.classList.contains("earlier-runs")) ui.earlierOpen = ev.target.open;
}, true);

// Clocks live outside the rendered HTML so ticking them never forces a re-render.
function tickClocks() {
  for (const el of document.querySelectorAll("[data-elapsed]")) {
    const r = runs.get(el.getAttribute("data-elapsed"));
    if (r) el.textContent = duration(elapsed(r));
  }
}

setInterval(() => {
  tickClocks();
  renderStatus();
  const now = performance.now();
  for (const [k, t] of ui.flips) if (now - t > 1400) { ui.flips.delete(k); schedule(); }
}, 1000);

connect();
loadRepos();
schedule();
