// Mnemosyne app. Every value from the server is inserted as text (textContent), never as HTML.
"use strict";

const $ = (s) => document.querySelector(s);
let token = "";
let snaps = [];
let cwd = "";

function el(tag, attrs, ...kids) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null || v === false) continue;
    if (k === "class") n.className = v;
    else if (k.startsWith("on")) n.addEventListener(k.slice(2), v);
    else n.setAttribute(k, v === true ? "" : v);
  }
  for (const c of kids.flat()) if (c != null && c !== false) n.append(c instanceof Node ? c : String(c));
  return n;
}

async function api(path, body) {
  const opts = { headers: { "X-Mnemosyne-Token": token } };
  if (body !== undefined) {
    opts.method = "POST";
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body);
  }
  const r = await fetch(path, opts);
  if (r.status === 423) { await showLocked(); throw new Error("locked"); }
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.error || `HTTP ${r.status}`);
  return data;
}

function bytes(n) {
  if (n == null) return "–";
  const u = ["B", "KiB", "MiB", "GiB", "TiB"];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return i ? `${n.toFixed(1)} ${u[i]}` : `${n} B`;
}
const when = (iso) => (iso ? new Date(iso).toLocaleString([], { dateStyle: "medium", timeStyle: "short" }) : "never");
function ago(iso) {
  if (!iso) return "never";
  const s = (Date.now() - new Date(iso).getTime()) / 1000;
  if (s < 90) return "just now";
  if (s < 5400) return `${Math.round(s / 60)} min ago`;
  if (s < 172800) return `${Math.round(s / 3600)} h ago`;
  return `${Math.round(s / 86400)} days ago`;
}
const badge = (text, kind) => el("span", { class: `badge${kind ? " badge--" + kind : ""}` }, text);
function fail(err) {
  if (err.message === "locked") return;
  const e = $("#error");
  e.textContent = err.message;
  e.hidden = false;
  setTimeout(() => { e.hidden = true; }, 6000);
}

// --- locked view -------------------------------------------------------------------------------

let canUseFile = false;

async function showLocked() {
  const o = await fetch("/api/overview", { headers: { "X-Mnemosyne-Token": token } }).then((r) => r.json());
  canUseFile = o.password_file;
  $("#locked").hidden = false;
  $("#open").hidden = true;
  $("#lock").hidden = true;
  $("#repo-name").textContent = "";
  $("#lockstate").textContent = "locked";
  $("#lockstate").className = "badge";
  const cards = o.repos.map((r) => {
    const last = r.last_backup || {}, good = r.last_good_backup || {}, check = r.last_check || {};
    const state = !r.exists ? badge("not found", "bad") : last.time && !last.ok ? badge("last backup failed", "bad")
      : good.time ? badge("ok", "good") : badge("no backup yet", "warn");
    return el("article", { class: "repo" },
      el("div", { class: "actions" }, el("span", { class: "repo__path" }, r.path), state),
      el("dl", {},
        el("dt", {}, "last good backup"), el("dd", {}, `${ago(good.time)}${good.files ? ` · ${good.files.toLocaleString()} files, ${bytes(good.bytes)}` : ""}`),
        el("dt", {}, "verified"), el("dd", {}, `${ago(check.time)}${check.read_data ? ` (${check.read_data})` : ""}${check.time && !check.ok ? " · PROBLEMS" : ""}`),
        el("dt", {}, "stored"), el("dd", {}, `${r.snapshots} snapshots · ${bytes(r.repo_bytes)} on disk`)),
      el("div", { class: "actions" },
        el("button", { class: "btn btn--primary", type: "button", disabled: !r.exists, onclick: () => askPassword(r.path) }, "Open")));
  });
  if (!cards.length) cards.push(el("p", { class: "note" }, "No repositories known yet. Run a backup first (mnemosyne backup), or set MNEMOSYNE_REPO."));
  $("#repos").replaceChildren(...cards);
}

let pendingRepo = "";
function askPassword(path) {
  pendingRepo = path;
  $("#unlock-repo").textContent = path;
  $("#unlock-msg").textContent = "";
  $("#unlock-password").value = "";
  $("#unlock-file").hidden = !canUseFile;
  $("#unlock-dialog").showModal();
  $("#unlock-password").focus();
}

async function unlock(body) {
  try {
    await api("/api/unlock", { repo: pendingRepo, ...body });
    $("#unlock-dialog").close();
    await showOpen();
  } catch (err) {
    $("#unlock-msg").textContent = err.message;
  } finally {
    $("#unlock-password").value = "";
  }
}

// --- unlocked view -----------------------------------------------------------------------------

async function showOpen() {
  const data = await api("/api/snapshots");
  snaps = data.snapshots.filter((s) => !s.error);
  $("#locked").hidden = true;
  $("#open").hidden = false;
  $("#lock").hidden = false;
  $("#repo-name").textContent = data.repo;
  $("#lockstate").textContent = "open";
  $("#lockstate").className = "badge badge--good";
  renderStats(data);
  renderChart();
  renderSnapshots();
  const opts = () => [...snaps].reverse().map((s) => el("option", { value: s.name }, when(s.time)));
  $("#browse-snap").replaceChildren(...opts());
  $("#diff-a").replaceChildren(...opts());
  $("#diff-b").replaceChildren(...opts());
  if (snaps.length > 1) $("#diff-a").selectedIndex = 1;
  cwd = "";
  await browse("");
  if (snaps.length > 1) await showDiff();
  else $("#diff-summary").textContent = "Two snapshots are needed for a comparison.";
}

function stat(value, label, sub) {
  return el("div", { class: "stat" }, el("div", { class: "stat__value" }, value), el("div", { class: "stat__label" }, label),
    sub ? el("div", { class: "stat__sub" }, sub) : null);
}

function renderStats(data) {
  const last = snaps[snaps.length - 1];
  const protectedBytes = last ? last.summary.bytes : 0;
  // What keeping every snapshot as a full copy would take, against what it really takes.
  const fullCopies = snaps.reduce((a, s) => a + s.summary.bytes, 0);
  const ratio = data.disk_bytes ? fullCopies / data.disk_bytes : 0;
  const v = stat(ratio ? `${ratio.toFixed(1)}×` : "–", "less than full copies",
    `${snaps.length} full copies: ${bytes(fullCopies)}; stored: ${bytes(data.disk_bytes)}`);
  v.firstChild.classList.add("big");
  $("#stats").replaceChildren(
    stat(String(snaps.length), "snapshots", last ? `latest ${ago(last.time)}` : "none yet"),
    stat(bytes(protectedBytes), "protected", last ? `${last.summary.files.toLocaleString()} files in the latest` : ""),
    stat(bytes(data.disk_bytes), "on disk", "compressed, encrypted, deduplicated"),
    v,
  );
}

function renderChart() {
  const NS = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(NS, "svg");
  const W = 1000, H = 150, P = 6;
  svg.setAttribute("viewBox", `0 0 ${W} ${H}`);
  svg.setAttribute("preserveAspectRatio", "none");
  if (!snaps.length) { $("#chart").replaceChildren(svg); return; }
  const maxAdded = Math.max(1, ...snaps.map((s) => s.summary.added_bytes));
  const maxSize = Math.max(1, ...snaps.map((s) => s.summary.bytes));
  const step = W / snaps.length;
  snaps.forEach((s, i) => {
    const h = Math.max(1, (s.summary.added_bytes / maxAdded) * (H - 2 * P) * 0.85);
    const r = document.createElementNS(NS, "rect");
    Object.entries({ x: i * step + step * 0.15, y: H - P - h, width: Math.max(1, step * 0.7), height: h, class: "bar" })
      .forEach(([k, v]) => r.setAttribute(k, v));
    const t = document.createElementNS(NS, "title");
    t.textContent = `${when(s.time)}: ${bytes(s.summary.added_bytes)} added, ${bytes(s.summary.bytes)} in ${s.summary.files} files`;
    r.append(t);
    svg.append(r);
  });
  const pts = snaps.map((s, i) => `${(i + 0.5) * step},${H - P - (s.summary.bytes / maxSize) * (H - 2 * P)}`).join(" ");
  const line = document.createElementNS(NS, "polyline");
  line.setAttribute("points", pts);
  line.setAttribute("class", "line");
  svg.append(line);
  $("#chart").replaceChildren(svg);
}

function renderSnapshots() {
  $("#snapshots").replaceChildren(...[...snaps].reverse().map((s) => el("tr", { class: "pick", title: s.paths.join("\n"), onclick: () => openSnapshot(s.name) },
    el("td", {}, when(s.time), s.warnings ? el("span", { class: "note" }, ` · ${s.warnings} skipped`) : null),
    el("td", { class: "num" }, s.summary.files.toLocaleString()),
    el("td", { class: "num" }, bytes(s.summary.bytes)),
    el("td", { class: "num" }, bytes(s.summary.added_bytes)),
    el("td", { class: "num" }, s.summary.duration_ms < 1000 ? `${s.summary.duration_ms} ms` : `${(s.summary.duration_ms / 1000).toFixed(1)} s`),
    el("td", {}, el("button", { class: "btn btn--small btn--ghost", type: "button" }, "browse")))));
}

async function openSnapshot(name) {
  $("#browse-snap").value = name;
  $("#search").value = "";
  await browse("");
  $("#browse-snap").scrollIntoView({ behavior: "smooth", block: "center" });
}

function crumbs(dir, roots) {
  const parts = [el("button", { type: "button", onclick: () => browse("") }, "snapshot")];
  if (dir) {
    const root = roots.find((r) => dir === r || dir.startsWith(r + "/")) || "";
    const rest = dir.slice(root.length).split("/").filter(Boolean);
    let p = root;
    parts.push(el("span", {}, "›"), el("button", { type: "button", onclick: () => browse(root) }, root || "/"));
    for (const seg of rest) {
      p = `${p}/${seg}`;
      const target = p;
      parts.push(el("span", {}, "/"), el("button", { type: "button", onclick: () => browse(target) }, seg));
    }
  }
  $("#crumbs").replaceChildren(...parts);
}

function fileRow(e) {
  const isDir = e.kind === "dir";
  const icon = isDir ? "▸" : e.kind === "link" ? "↪" : "·";
  return el("tr", { class: isDir ? "pick" : "", onclick: isDir ? () => browse(e.path) : null },
    el("td", { class: "name", title: e.path }, el("span", { class: "icon" }, icon), cwd || $("#search").value ? e.name : e.path),
    el("td", { class: "num" }, isDir ? "" : bytes(e.size)),
    el("td", {}, new Date(e.mtime * 1000).toLocaleString([], { dateStyle: "short", timeStyle: "short" })),
    el("td", {}, e.kind === "file" ? el("button", { class: "btn btn--small", type: "button", onclick: (ev) => { ev.stopPropagation(); download(e); } }, "download") : null));
}

async function browse(dir) {
  cwd = dir;
  const snap = $("#browse-snap").value || "latest";
  let data = await api(`/api/tree?snap=${encodeURIComponent(snap)}&dir=${encodeURIComponent(dir)}`);
  if (!dir && data.entries.length === 1 && data.entries[0].kind === "dir") {
    // a single backed-up folder: open it right away
    cwd = data.entries[0].path;
    data = await api(`/api/tree?snap=${encodeURIComponent(snap)}&dir=${encodeURIComponent(cwd)}`);
    dir = cwd;
  }
  const s = snaps.find((x) => x.name === data.snapshot);
  crumbs(dir, s ? s.paths : []);
  const rows = data.entries.sort((a, b) => (a.kind === "dir") === (b.kind === "dir") ? a.name.localeCompare(b.name) : a.kind === "dir" ? -1 : 1);
  $("#files").replaceChildren(...(rows.length ? rows.map(fileRow) : [el("tr", {}, el("td", { colspan: 4, class: "note" }, "empty"))]));
}

let searchTimer = null;
function onSearch() {
  clearTimeout(searchTimer);
  searchTimer = setTimeout(async () => {
    const q = $("#search").value.trim();
    if (q.length < 2) { browse(cwd); return; }
    const snap = $("#browse-snap").value || "latest";
    try {
      const data = await api(`/api/search?snap=${encodeURIComponent(snap)}&q=${encodeURIComponent(q)}`);
      $("#crumbs").replaceChildren(el("span", {}, `${data.entries.length} match(es) for “${q}”`));
      $("#files").replaceChildren(...data.entries.map((e) => { const r = fileRow(e); r.firstChild.lastChild.textContent = e.path; return r; }));
    } catch (err) { fail(err); }
  }, 250);
}

async function download(e) {
  const snap = $("#browse-snap").value || "latest";
  try {
    const r = await fetch(`/api/download?snap=${encodeURIComponent(snap)}&path=${encodeURIComponent(e.path)}`, { headers: { "X-Mnemosyne-Token": token } });
    if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error || `HTTP ${r.status}`);
    const url = URL.createObjectURL(await r.blob());
    const a = el("a", { href: url, download: e.name });
    document.body.append(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 30000);
  } catch (err) { fail(err); }
}

async function showDiff() {
  const a = $("#diff-a").value, b = $("#diff-b").value;
  if (!a || !b) return;
  try {
    const d = await api(`/api/diff?a=${encodeURIComponent(a)}&b=${encodeURIComponent(b)}`);
    const s = d.summary;
    const sign = s.bytes_delta < 0 ? "−" : "+";
    $("#diff-summary").textContent = `${s.added} added, ${s.removed} removed, ${s.modified} modified, ${s.replaced} replaced · ${sign}${bytes(Math.abs(s.bytes_delta))}`
      + (d.total > d.changes.length ? ` · first ${d.changes.length} shown` : "");
    const sym = { added: "+", removed: "−", modified: "M", replaced: "T", metadata: "m" };
    $("#diff").replaceChildren(...(d.changes.length ? d.changes.map((c) => el("li", { class: c.kind },
      el("span", { class: "sym" }, sym[c.kind]), el("span", {}, c.path),
      c.entry === "file" ? el("span", { class: "muted" }, c.kind === "modified" ? `${bytes(c.old_size)} → ${bytes(c.new_size)}` : bytes(c.kind === "removed" ? c.old_size : c.new_size)) : null))
      : [el("li", { class: "muted" }, "No differences.")]));
  } catch (err) { fail(err); }
}

async function verify(pct) {
  const out = $("#verify-result");
  document.querySelectorAll("[data-pct]").forEach((b) => { b.disabled = true; });
  out.className = "verify";
  out.textContent = pct === 100 ? "Reading and checking every chunk…" : `Reading and checking ${pct} % of the chunks…`;
  try {
    const { ok, report } = await api("/api/verify", { percent: pct });
    out.className = `verify ${ok ? "ok" : "bad"}`;
    out.textContent = ok
      ? `✓ ${report.chunks_read.toLocaleString()} chunks (${bytes(report.bytes_read)}) decrypted and verified, no problems.`
      : `✗ ${report.errors.length} problem(s): ${report.errors[0]}`;
  } catch (err) { out.textContent = err.message; }
  document.querySelectorAll("[data-pct]").forEach((b) => { b.disabled = false; });
}

document.addEventListener("DOMContentLoaded", async () => {
  // The token comes in the URL fragment (never sent to a server); keep it for this tab only.
  const m = location.hash.match(/t=([0-9a-f]{64})/);
  if (m) {
    token = m[1];
    try { sessionStorage.setItem("mnemosyne-token", token); } catch { /* private mode */ }
    history.replaceState(null, "", location.pathname);
  } else {
    try { token = sessionStorage.getItem("mnemosyne-token") || ""; } catch { token = ""; }
  }
  $("#unlock-form").addEventListener("submit", (ev) => { ev.preventDefault(); unlock({ password: $("#unlock-password").value }); });
  $("#unlock-file").addEventListener("click", () => unlock({ use_file: true }));
  $("#unlock-cancel").addEventListener("click", () => $("#unlock-dialog").close());
  $("#lock").addEventListener("click", async () => { await api("/api/lock", {}); await showLocked(); });
  $("#browse-snap").addEventListener("change", () => { $("#search").value = ""; browse(""); });
  $("#search").addEventListener("input", onSearch);
  $("#diff-a").addEventListener("change", showDiff);
  $("#diff-b").addEventListener("change", showDiff);
  document.querySelectorAll("[data-pct]").forEach((b) => b.addEventListener("click", () => verify(Number(b.dataset.pct))));
  setInterval(() => fetch("/api/ping", { headers: { "X-Mnemosyne-Token": token } }).catch(() => {}), 10000);
  try {
    const o = await fetch("/api/overview", { headers: { "X-Mnemosyne-Token": token } });
    if (o.status === 401) throw new Error("This link is no longer valid: start Mnemosyne again.");
    if ((await o.json()).unlocked) await showOpen(); else await showLocked();
  } catch (err) { fail(err); }
});
