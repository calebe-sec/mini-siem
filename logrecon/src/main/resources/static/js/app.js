"use strict";

const REFRESH_MS = 30000;
const MAX_EVENTS_SHOWN = 50;
const TOP_N = 5;
const TIMELINE_BUCKETS = 24;
const HOUR_MS = 3600000;
const SEVERITIES = ["low", "medium", "high", "critical"];
const SVG_NS = "http://www.w3.org/2000/svg";

const state = { alerts: [], events: [], status: "ALL", severity: "ALL", query: "" };
const $ = (id) => document.getElementById(id);

// ---------------------------------------------------------------- helpers

function el(tag, className, content) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (content !== undefined) node.textContent = content;   // never innerHTML: log data is untrusted
  return node;
}

const text = (v) => (v === null || v === undefined || v === "" ? "-" : String(v));
const nameOf = (v) => (v && typeof v === "object" ? text(v.name ?? v.id) : text(v));
const upper = (v) => String(v ?? "").toUpperCase();

function fmtDate(v) {
  if (!v) return "-";
  const d = new Date(v);
  return Number.isNaN(d.getTime()) ? text(v) : d.toLocaleString();
}

function timeValue(v) {
  const t = new Date(v).getTime();
  return Number.isNaN(t) ? 0 : t;
}

function severityOf(item) {
  const raw = item.severity ?? (item.rule && item.rule.severity);
  const value = raw ? String(raw).toLowerCase() : "";
  return SEVERITIES.includes(value) ? value : "";
}

// Severity is shown as label + 4-step meter so it never relies on color alone.
function badge(label, kind) {
  const node = el("span", `sev sev-${kind}`);
  const pips = el("span", "pips");
  pips.setAttribute("aria-hidden", "true");
  for (let i = 0; i < 4; i++) pips.appendChild(el("i"));
  node.append(pips, label);
  return node;
}

function statusTag(status) {
  return el("span", `status${status === "OPEN" ? " status-open" : ""}`, status || "n/a");
}

function cell(content, className) {
  const td = el("td", className);
  if (content instanceof Node) td.appendChild(content);
  else td.textContent = content;
  return td;
}

function emptyRow(columns, message) {
  const tr = el("tr");
  const td = el("td", "empty", message);
  td.colSpan = columns;
  tr.appendChild(td);
  return tr;
}

function countBy(list, keyFn) {
  const map = new Map();
  list.forEach((item) => {
    const k = keyFn(item);
    if (k) map.set(k, (map.get(k) ?? 0) + 1);
  });
  return [...map.entries()].sort((a, b) => b[1] - a[1]);
}

// ------------------------------------------------------------------- data

async function getList(path) {
  const res = await fetch(path, { headers: { Accept: "application/json" }, credentials: "same-origin" });
  if (res.status === 401 || res.status === 403 || res.redirected) {
    window.location.href = "/login";          // session expired
    throw new Error("session expired");
  }
  if (!res.ok) throw new Error(`${path} -> HTTP ${res.status}`);
  const data = await res.json();
  return Array.isArray(data) ? data : (data.content ?? []);
}

function setFeed(ok, label, detail) {
  document.querySelector(".feed").className = "feed " + (ok ? "ok" : "fail");
  $("feed-state").textContent = label;
  $("last-updated").textContent = detail;
}

async function load() {
  const banner = $("error-banner");
  try {
    const [alerts, events] = await Promise.all([getList("/api/alerts"), getList("/api/events")]);
    state.alerts = alerts;
    state.events = events;
    banner.hidden = true;
    setFeed(true, "Feed connected", "Updated " + new Date().toLocaleTimeString());
    render();
  } catch (err) {
    if (err.message === "session expired") return;
    banner.textContent = "Could not load data: " + err.message;
    banner.hidden = false;
    setFeed(false, "Feed error", "Retrying every " + REFRESH_MS / 1000 + "s");
  }
}

// ----------------------------------------------------------------- render

function renderStats() {
  const sevCount = (s) => state.alerts.filter((a) => severityOf(a) === s).length;
  $("stat-alerts").textContent = state.alerts.length;
  $("stat-open").textContent = state.alerts.filter((a) => upper(a.status) === "OPEN").length;
  $("stat-critical").textContent = sevCount("critical");
  $("stat-high").textContent = sevCount("high");
  $("stat-events").textContent = state.events.length;
}

function renderSeverity() {
  const total = state.alerts.length;
  const bar = $("sev-bar");
  const legend = $("sev-legend");
  const rows = [...SEVERITIES].reverse().map((s) => [s, state.alerts.filter((a) => severityOf(a) === s).length]);
  const unrated = state.alerts.filter((a) => !severityOf(a)).length;
  if (unrated) rows.push(["none", unrated]);

  bar.replaceChildren(...rows.filter(([, n]) => n).map(([s, n]) => {
    const seg = el("span");
    seg.style.width = (100 * n) / total + "%";
    seg.style.background = s === "none" ? "var(--info)" : `var(--${s})`;
    return seg;
  }));
  legend.replaceChildren(...rows.map(([s, n]) => {
    const li = el("li");
    const sw = el("span", "swatch");
    sw.style.background = s === "none" ? "var(--info)" : `var(--${s})`;
    li.append(sw, el("span", "", s === "none" ? "Unrated" : s[0].toUpperCase() + s.slice(1)), el("span", "count", n));
    return li;
  }));
}

function renderRank(id, entries, emptyMsg) {
  const list = $(id);
  const top = entries.slice(0, TOP_N);
  if (!top.length) { list.replaceChildren(el("li", "none", emptyMsg)); return; }
  const max = top[0][1];
  list.replaceChildren(...top.map(([label, n]) => {
    const li = el("li");
    const meter = el("span", "meter");
    const fill = el("i");
    fill.style.width = (100 * n) / max + "%";
    meter.appendChild(fill);
    li.append(el("span", "label", label), el("span", "count", n), meter);
    li.title = `${label}: ${n}`;
    return li;
  }));
}

function renderTimeline() {
  const host = $("timeline");
  const stamps = state.events.map((e) => timeValue(e.timestamp)).filter(Boolean);
  if (!stamps.length) {
    host.replaceChildren(el("p", "muted", "No events to chart"));
    $("tl-range").textContent = "-";
    return;
  }
  // Window = the 24 hours ending at the latest recorded event.
  const end = Math.max(...stamps);
  const start = end - TIMELINE_BUCKETS * HOUR_MS;
  const buckets = new Array(TIMELINE_BUCKETS).fill(0);
  stamps.forEach((t) => {
    if (t < start) return;
    buckets[Math.min(TIMELINE_BUCKETS - 1, Math.floor((t - start) / HOUR_MS))]++;
  });
  const max = Math.max(1, ...buckets);

  const W = 480, H = 120, gap = 2, bw = W / TIMELINE_BUCKETS;
  const svg = document.createElementNS(SVG_NS, "svg");
  svg.setAttribute("viewBox", `0 0 ${W} ${H}`);
  svg.setAttribute("preserveAspectRatio", "none");
  svg.setAttribute("role", "img");
  svg.setAttribute("aria-label", `Events per hour, peak ${max}`);
  [0.5, 1].forEach((f) => {
    const line = document.createElementNS(SVG_NS, "line");
    line.setAttribute("class", "grid");
    line.setAttribute("x1", 0); line.setAttribute("x2", W);
    line.setAttribute("y1", H - f * (H - 4)); line.setAttribute("y2", H - f * (H - 4));
    svg.appendChild(line);
  });
  buckets.forEach((n, i) => {
    const h = n ? Math.max(2, (n / max) * (H - 4)) : 0;
    const rect = document.createElementNS(SVG_NS, "rect");
    rect.setAttribute("class", "bar");
    rect.setAttribute("x", i * bw + gap / 2);
    rect.setAttribute("width", bw - gap);
    rect.setAttribute("y", H - h);
    rect.setAttribute("height", h);
    const tip = document.createElementNS(SVG_NS, "title");
    tip.textContent = `${new Date(start + i * HOUR_MS).toLocaleString()} - ${n} event${n === 1 ? "" : "s"}`;
    rect.appendChild(tip);
    svg.appendChild(rect);
  });

  const axis = el("div", "timeline-axis");
  const t = (ms) => new Date(ms).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  axis.append(el("span", "", t(start)), el("span", "", `peak ${max}/h`), el("span", "", t(end)));
  host.replaceChildren(svg, axis);
  $("tl-range").textContent = "24 h ending at the latest event";
}

function renderStatusFilter() {
  const select = $("status-filter");
  const statuses = [...new Set(state.alerts.map((a) => upper(a.status)).filter(Boolean))];
  if (state.status !== "ALL" && !statuses.includes(state.status)) state.status = "ALL";
  const options = ["ALL", ...statuses].map((s) => {
    const o = el("option", "", s === "ALL" ? "All statuses" : s);
    o.value = s;
    return o;
  });
  select.replaceChildren(...options);
  select.value = state.status;
}

function renderAlerts() {
  const q = state.query.trim().toLowerCase();
  const filtered = state.alerts
    .filter((a) => state.status === "ALL" || upper(a.status) === state.status)
    .filter((a) => state.severity === "ALL" || severityOf(a) === state.severity)
    .filter((a) => !q || `${nameOf(a.rule)} ${a.description ?? ""}`.toLowerCase().includes(q))
    .sort((a, b) => timeValue(b.createdAt) - timeValue(a.createdAt) || (b.id ?? 0) - (a.id ?? 0));

  const rows = filtered.map((a) => {
    const sev = severityOf(a);
    const tr = el("tr", `clickable sev-row-${sev || "none"}`);
    tr.tabIndex = 0;
    tr.setAttribute("aria-label", `Inspect alert: ${nameOf(a.rule)}`);
    tr.appendChild(cell(fmtDate(a.createdAt), "time"));
    tr.appendChild(cell(badge(sev || "n/a", sev || "none")));
    tr.appendChild(cell(nameOf(a.rule)));
    tr.appendChild(cell(statusTag(upper(a.status))));
    tr.appendChild(cell(text(a.description)));
    tr.addEventListener("click", () => openDetail(a));
    tr.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") { e.preventDefault(); openDetail(a); }
    });
    return tr;
  });
  $("alerts-body").replaceChildren(...(rows.length ? rows : [emptyRow(5, "No alerts match the current filters")]));
  $("alerts-count").textContent = `${filtered.length} of ${state.alerts.length}`;
}

function renderEvents() {
  const sorted = [...state.events]
    .sort((a, b) => timeValue(b.timestamp) - timeValue(a.timestamp) || (b.id ?? 0) - (a.id ?? 0));
  const rows = sorted.slice(0, MAX_EVENTS_SHOWN).map((e) => {
    const tr = el("tr");
    const sev = severityOf(e);
    const message = text(e.rawMessage);
    const msgCell = cell(message, "msg");
    msgCell.title = message;                   // full text on hover (set as attribute, not HTML)
    tr.appendChild(cell(fmtDate(e.timestamp), "time"));
    tr.appendChild(cell(text(e.sourceIp), "mono nowrap"));
    tr.appendChild(cell(text(e.eventType), "nowrap"));
    tr.appendChild(cell(text(e.username), "nowrap"));
    tr.appendChild(cell(badge(sev || "n/a", sev || "none")));
    tr.appendChild(msgCell);
    return tr;
  });
  $("events-body").replaceChildren(...(rows.length ? rows : [emptyRow(6, "No events to show")]));
  $("events-count").textContent = `Latest ${Math.min(sorted.length, MAX_EVENTS_SHOWN)} of ${sorted.length}`;
}

function render() {
  renderStats();
  renderSeverity();
  renderTimeline();
  renderRank("top-ips", countBy(state.events, (e) => e.sourceIp), "No source IPs");
  renderRank("top-types", countBy(state.events, (e) => e.eventType), "No event types");
  renderStatusFilter();
  renderAlerts();
  renderEvents();
}

// ------------------------------------------------------------ alert detail

function openDetail(alert) {
  const body = $("detail-body");
  const fields = Object.entries({ ...alert, rule: nameOf(alert.rule) });
  body.replaceChildren(...fields.flatMap(([k, v]) => [
    el("dt", "", k),
    el("dd", "", v !== null && typeof v === "object" ? JSON.stringify(v, null, 2) : text(v)),
  ]));
  $("detail").showModal();
}

// ------------------------------------------------------------- navigation

function trackSection() {
  const links = [...document.querySelectorAll(".nav-link")];
  const obs = new IntersectionObserver((entries) => {
    entries.forEach((en) => {
      if (!en.isIntersecting) return;
      links.forEach((l) => l.classList.toggle("active", l.getAttribute("href") === "#" + en.target.id));
    });
  }, { rootMargin: "-20% 0px -70% 0px" });
  ["overview", "alerts", "events"].forEach((id) => obs.observe($(id)));
}

// ------------------------------------------------------------------- init

$("refresh").addEventListener("click", load);
$("search").addEventListener("input", (e) => { state.query = e.target.value; renderAlerts(); });
$("status-filter").addEventListener("change", (e) => { state.status = e.target.value; renderAlerts(); });
$("severity-filter").addEventListener("change", (e) => { state.severity = e.target.value; renderAlerts(); });
$("detail-close").addEventListener("click", () => $("detail").close());
$("detail").addEventListener("click", (e) => { if (e.target === e.currentTarget) e.currentTarget.close(); });

trackSection();
load();
setInterval(load, REFRESH_MS);