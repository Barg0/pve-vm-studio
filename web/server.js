/* PVE VM Studio - what the Hyper-V studio did not have: a server.
   studio.js holds the VM designer (blades, VM cards, validation, passwords...), ported from
   the Hyper-V VM Studio.
   This file signs in, loads and saves labs, and renders the blades that read the cluster:
   Dashboard, Windows media, Golds, Media, Deploy, Jobs and Studio settings. Every blade uses
   the studio's own building blocks - gsCard, toggle, iconSrc, esc, toast. */

"use strict";

const $id = id => document.getElementById(id);

/* ---------- API ---------- */

const session = { user: null, csrf: null };

async function api(method, path, body) {
  const headers = {};
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (method !== "GET" && session.csrf) headers["X-PVS-CSRF"] = session.csrf;
  const resp = await fetch("/api" + path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
  if (resp.status === 401 && path !== "/session") { showLogin(); throw new Error("signed out"); }
  if (resp.status === 204) return null;
  const data = await resp.json().catch(() => ({}));
  if (!resp.ok) { const e = new Error(data.error || `${resp.status} ${resp.statusText}`); e.status = resp.status; throw e; }
  return data;
}

/* ---------- small helpers on top of the studio's ---------- */

const gib = b => ((b || 0) / 1073741824).toFixed(1);
/* "410 / 1800 GiB" would not fit the meter's value column: one unit for both, TiB from
   1000 GiB on, decimals only below 100 - "0.4 / 1.8 TiB", "3.0 / 12.0 TiB", "61.5 / 512 GiB". */
function sizePair(used, total) {
  const tib = (total || 0) >= 1000 * 1073741824, d = tib ? 1099511627776 : 1073741824;
  const f = b => { const v = (b || 0) / d; return v < 100 ? v.toFixed(1) : v.toFixed(0); };
  return `${f(used)} / ${f(total)} ${tib ? "TiB" : "GiB"}`;
}
/* The studio's time format (Studio settings): "24h" or 12-hour. */
let clockFmt = "12h";
function when(iso) {
  if (!iso) return "";
  return new Date(iso).toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", hour12: clockFmt !== "24h" });
}
function took(a, b) {
  if (!a) return "";
  const s = Math.max(0, Math.round(((b ? new Date(b) : new Date()) - new Date(a)) / 1000));
  return s < 60 ? `${s}s` : s < 3600 ? `${Math.floor(s / 60)}m ${s % 60}s` : `${Math.floor(s / 3600)}h ${Math.floor(s % 3600 / 60)}m`;
}
function pillOn(text, on) { return `<span class="pill status ${on ? "on" : "off"}">${esc(cap(text))}</span>`; }
function stoggle(id, label, checked, sub) { return toggle(`id="${id}"`, esc(label), checked, false, sub ? esc(sub) : ""); }
function opts(list, selected, auto) {
  return (auto ? `<option value="">${esc(auto)}</option>` : "") +
    list.map(([v, l]) => `<option value="${esc(v)}" ${String(v) === String(selected) ? "selected" : ""}>${esc(l)}</option>`).join("");
}
function meter(used, max) {
  const pct = max ? Math.min(100, used / max * 100) : 0;
  const tone = pct >= 90 ? "danger" : pct >= 75 ? "warn" : "";
  return `<div class="meter"><div class="meter-track"><div class="meter-fill ${tone}" style="width:${pct.toFixed(1)}%"></div></div>
    <span class="meter-text">${gib(used)} / ${gib(max)} GiB</span></div>`;
}
function bladeHead(id, actions = "") {
  return `<div class="blade-toolbar">${bladeTitle(id)}<div class="row">${actions}</div></div>`;
}
const JOB_TONE = { running: "run", queued: "idle", succeeded: "ok", failed: "bad", interrupted: "warn" };
function jobPill(status) { return `<span class="pill status ${JOB_TONE[status] || "idle"}">${esc(cap(status))}</span>`; }

/* ---------- sign-in ---------- */

let loginShown = false;
async function showLogin() {
  const again = loginShown && !$id("login").hidden;
  session.user = session.csrf = null;
  stopLiveLog(); clearTimeout(dashPoll);
  loginShown = true;
  // Already on the sign-in form: a late 401 from a request in flight changes nothing.
  if (again) return;
  $id("layout").hidden = true; $id("login").hidden = false;
  document.querySelector(".topbar .actions").style.visibility = "hidden";
  applyTheme(state.themeId || DEFAULT_THEME_ID);
  $id("loginPass").value = "";
  try {
    const realms = await api("GET", "/realms");
    realms.sort((a, b) => (b.default || 0) - (a.default || 0) || a.realm.localeCompare(b.realm));
    $id("loginRealm").innerHTML = realms.map(r => `<option value="${esc(r.realm)}">${esc(r.comment || r.realm)} (${esc(r.realm)})</option>`).join("");
  } catch (e) {
    $id("loginRealm").innerHTML = '<option value="pam">Linux PAM (pam)</option><option value="pve">Proxmox VE (pve)</option>';
  }
  $id("loginUser").focus();
}

$id("loginForm").addEventListener("submit", async e => {
  e.preventDefault();
  const err = $id("loginError"); err.hidden = true;
  let user = $id("loginUser").value.trim();
  if (!user.includes("@")) user += "@" + $id("loginRealm").value;
  $id("loginBtn").disabled = true;
  try { signedIn(await api("POST", "/session", { username: user, password: $id("loginPass").value })); }
  catch (ex) { err.textContent = ex.message === "login failed" ? "Login failed. Check user name, password and realm." : ex.message; err.hidden = false; }
  finally { $id("loginBtn").disabled = false; }
});

$id("logoutBtn").addEventListener("click", async () => {
  await flushSave();
  try { await api("DELETE", "/session"); } catch { /* gone already */ }
  showLogin();
});

async function signedIn(s) {
  session.user = s.user; session.csrf = s.csrf;
  $id("login").hidden = true; $id("layout").hidden = false;
  document.querySelector(".topbar .actions").style.visibility = "";
  $id("userChip").textContent = s.user;
  try { clockFmt = (await api("GET", "/settings/server")).settings.clock || "12h"; } catch { /* keep 12h */ }
  // What this tab still holds from before (a session that ran out, an older studio) is not
  // the design: the server's copy is.
  lab.id = null; lab.saved = ""; clearTimeout(lab.timer);
  await openLab(null, true);
  render();
  startNavPoll();
  bellLoad();
}

/* The nav's badges (golds baking, jobs running) follow the server, not the last blade
   visited: the jobs every 5 s while the tab is visible, the golds again whenever a job
   started or ended - so "3 baking" turns into the ready count when the bakes finish. */
let navPoll = null;
function startNavPoll() {
  if (navPoll) return;
  let lastRun = "", tick = 0;
  navPoll = setInterval(async () => {
    if (document.hidden || !session.user) return;
    // The design is one for everyone: what another session saved shows up here within
    // 15 s - unless this tab has changes of its own waiting, which the save then reports.
    if (++tick % 3 === 0 && lab.id && !lab.saving && !lab.conflict && encodeState() === lab.saved) {
      try {
        const row = (await api("GET", "/labs")).find(l => l.id === lab.id);
        if (row && row.revision > lab.revision && encodeState() === lab.saved) {
          await openLab(lab.id, true); render();
          toast(`${row.updated_by} changed the design - showing it`);
        }
      } catch { /* the next tick tries again */ }
    }
    try {
      const jobs = await api("GET", "/jobs");
      cluster.jobs = jobs;
      const run = jobs.filter(j => j.status === "running" || j.status === "queued").map(j => j.id).sort().join(",");
      // A job that ended may have left a notification; the bell also looks every 15 s.
      if (run !== lastRun || tick % 3 === 0) bellLoad();
      if (run !== lastRun || cluster.golds.some(g => g.status === "baking")) {
        lastRun = run;
        cluster.golds = await api("GET", "/golds");
      }
      renderNav();
    } catch { /* signed out or offline - the next tick tries again */ }
  }, 5000);
}

/* ---------- labs: loaded, edited in the studio, saved as they change ---------- */

const lab = { id: null, name: "", revision: 0, saved: "", saving: false, conflict: false, timer: null, list: [] };

/* The design saves itself; the header says so only when it could not (a conflict, an
   error) - "saved", "saving..." and "unsaved" while the debounce runs stay out of sight. */
function setSaveState(text, tone) {
  const el = $id("saveState");
  el.textContent = text; el.className = "save-state " + (tone || "");
  el.hidden = tone !== "err";
}

/* The studio's own state payload - what its HVSS1. token carries, as JSON. */
function studioPayload() {
  const token = encodeState();
  return JSON.parse(decodeURIComponent(escape(atob(token.slice(STATE_PREFIX.length)))));
}
function loadPayload(payload) {
  const empty = !payload || !Object.keys(payload).length;
  if (!empty) decodeState(STATE_PREFIX + btoa(unescape(encodeURIComponent(JSON.stringify(payload)))));
}

/* fresh: load the server's copy without saving this tab's first - at sign-in and after a
   conflict, when what the tab holds is the stale one. */
async function openLab(id, fresh) {
  if (!fresh) await flushSave();
  lab.list = await api("GET", "/labs");
  // One design for the whole studio: the one saved last (the server lists it first). Saving
  // keeps it last, so every sign-in opens the same one.
  let wanted = id || (lab.list.length ? lab.list[0].id : null);
  let row;
  if (!wanted) {
    row = await api("POST", "/labs", { name: "Studio", state: studioPayload() });
    lab.list = await api("GET", "/labs");
  } else {
    row = await api("GET", "/labs/" + encodeURIComponent(wanted));
  }
  lab.id = row.id; lab.name = row.name; lab.revision = row.revision; lab.conflict = false;
  loadPayload(row.state);
  lab.saved = encodeState();
  setSaveState("saved", "ok");
  state.blade = bladeFromHash() || state.blade || "dashboard";
  applyTheme(state.themeId || DEFAULT_THEME_ID);
  refreshInventory();
}

/* Called by studio.js after every render: a changed state is saved a second later. */
function studioChanged() {
  // Every blade gets its own history entry, so Back goes to the blade before. An alias of
  // the same blade (#/passwords is Connect) and the first load replace instead.
  const cur = location.hash.replace(/^#\/?/, "").split("/")[0];
  if (cur !== state.blade) {
    if (!cur || resolveBladeId(cur) === state.blade) history.replaceState(null, "", "#/" + state.blade);
    else history.pushState(null, "", "#/" + state.blade);
  }
  if (!lab.id || lab.conflict) return;
  if (encodeState() === lab.saved) return;
  setSaveState("unsaved", "warn");
  clearTimeout(lab.timer);
  lab.timer = setTimeout(saveLab, 1000);
}

async function saveLab() {
  if (!lab.id || lab.saving || lab.conflict) return;
  const snapshot = encodeState();
  if (snapshot === lab.saved) { setSaveState("saved", "ok"); return; }
  lab.saving = true; setSaveState("saving…", "");
  try {
    const r = await api("PUT", "/labs/" + encodeURIComponent(lab.id), { name: lab.name, state: studioPayload(), revision: lab.revision });
    lab.revision = r.revision; lab.saved = snapshot;
    setSaveState(encodeState() === lab.saved ? "saved" : "unsaved", encodeState() === lab.saved ? "ok" : "warn");
  } catch (e) {
    if (e.status === 409) { lab.conflict = true; setSaveState("someone else saved - click to reload", "err"); toast(e.message, true); }
    else { setSaveState("not saved", "err"); toast("Saving the lab failed: " + e.message, true); }
  } finally { lab.saving = false; }
  if (!lab.conflict && encodeState() !== lab.saved) { clearTimeout(lab.timer); lab.timer = setTimeout(saveLab, 1000); }
}
async function flushSave() { clearTimeout(lab.timer); if (lab.id && !lab.conflict) await saveLab(); }
window.addEventListener("beforeunload", e => { if (lab.id && encodeState() !== lab.saved) { saveLab(); e.preventDefault(); } });

/* One studio, one design: the VMs, networks and identity catalogs in it. Saved as it changes;
   if someone else saved in between, the badge says so and a click reloads. */
$id("saveState").addEventListener("click", async () => {
  if (!lab.conflict) return;
  lab.conflict = false; lab.saved = "";
  await openLab(lab.id, true); render();
});
/* The bell: what happened lately - every event the studio can mail about, mail or not.
   Unread is per browser: the newest id seen when the panel was last opened. */
const bell = { items: [], open: false, seen: (() => { try { return Number(localStorage.getItem("pvs.bellSeen")) || 0; } catch { return 0; } })() };
const BELL_TONE = { success: "ok", danger: "bad", warn: "warn", accent: "run", neutral: "idle" };
function ago(iso) {
  const s = Math.max(0, Math.round((Date.now() - new Date(iso)) / 1000));
  return s < 60 ? "just now" : s < 3600 ? `${Math.floor(s / 60)} min ago` : s < 86400 ? `${Math.floor(s / 3600)} h ago` : s < 7 * 86400 ? `${Math.floor(s / 86400)} d ago`
    : new Date(iso).toLocaleDateString(undefined, { month: "short", day: "numeric" });
}
async function bellLoad() {
  try { bell.items = await api("GET", "/notifications?limit=25"); } catch { return; }
  const unread = bell.items.filter(n => n.id > bell.seen).length;
  const c = $id("bellCount");
  c.hidden = !unread; c.textContent = unread > 9 ? "9+" : String(unread);
  $id("bellBtn").title = unread ? `${unread} new notification${unread === 1 ? "" : "s"}` : "Notifications";
  if (bell.open) bellPaint();
}
/* A glyph's band, as its template names it - the tile under it takes that hue. */
function bellIcon(icon) { return icon === "mark-accent" ? "mark" : icon; }
function bellBand(icon) {
  const def = ICON_TEMPLATES[bellIcon(icon) + ".svg"];
  return (def && ["host", "work", "ident", "deploy", "linux", "studio"].includes(def[0])) ? def[0] : "ident";
}
function bellPaint() {
  const pop = $id("bellPop");
  const seenBefore = bell.paintedSeen ?? bell.seen;
  pop.innerHTML = `<div class="bell-h"><b>Notifications</b><button class="btn sm" type="button" data-goto-studio title="Which events notify - Studio settings"><img src="${iconSrc("certificate.svg")}" alt=""> Notifications</button></div>
    ${bell.items.length ? `<div class="bell-list">${bell.items.map(n => `<button class="bell-row${n.id > seenBefore ? " new" : ""}" type="button" data-bell-link="${esc(n.link)}" data-bell-job="${esc(n.job || "")}" title="${n.job ? "Open its log" : "Open"}">
      <span class="bell-ico" style="--tile:var(--band-${bellBand(n.icon)})"><img src="${iconSrc(bellIcon(n.icon) + ".svg")}" alt=""></span>
      <span class="bell-txt"><span class="bell-t">${esc(n.title)}</span>${n.subtitle ? `<span class="bell-s">${esc(n.subtitle)}</span>` : ""}</span>
      <span class="bell-r"><span class="pill status ${BELL_TONE[n.tone] || "idle"}">${esc(cap(String(n.status).toLowerCase()))}</span><span class="bell-at" title="${esc(new Date(n.at).toLocaleString())}">${esc(ago(n.at))}</span></span>
    </button>`).join("")}</div>`
    : `<div class="bell-empty">Nothing yet. Bakes, builds, updates and alerts show up here.</div>`}`;
}
function bellToggle(open) {
  bell.open = open ?? !bell.open;
  $id("bellPop").hidden = !bell.open;
  $id("bellBtn").setAttribute("aria-expanded", String(bell.open));
  if (!bell.open) { bell.paintedSeen = null; return; }
  // What was new when the panel opened stays marked while it is open; the count clears.
  bell.paintedSeen = bell.seen;
  bellPaint();
  const top = bell.items.reduce((m, n) => Math.max(m, n.id), bell.seen);
  bell.seen = top;
  try { localStorage.setItem("pvs.bellSeen", String(top)); } catch { /* this browser keeps nothing */ }
  $id("bellCount").hidden = true;
}
$id("bellBtn").addEventListener("click", e => { e.stopPropagation(); bellToggle(); });
$id("bellPop").addEventListener("click", e => {
  e.stopPropagation();
  if (e.target.closest("[data-goto-studio]")) { bellToggle(false); state.expanded["gs-notify"] = true; state.blade = "studio"; render(); return; }
  const row = e.target.closest("[data-bell-link]");
  if (!row) return;
  bellToggle(false);
  // An event of a job opens that job's log; the rest open where they point.
  if (row.dataset.bellJob) { openJob(row.dataset.bellJob); return; }
  const id = (row.dataset.bellLink || "").replace(/^#\/?/, "").split("/")[0];
  if (id) { state.blade = resolveBladeId(id); render(); }
});
document.addEventListener("click", e => { if (bell.open && !e.target.closest(".bell-anchor")) bellToggle(false); });
document.addEventListener("keydown", e => { if (e.key === "Escape" && bell.open) { bellToggle(false); $id("bellBtn").focus(); } });

function bladeFromHash() {
  const id = location.hash.replace(/^#\/?/, "").split("/")[0];
  return id ? resolveBladeId(id) : null;
}
window.addEventListener("hashchange", () => { const b = bladeFromHash(); if (b && b !== state.blade) { state.blade = b; render(); } });

/* ---------- the cluster, for the studio's pickers ---------- */

/* What the studio's own blades read from the server: the inventory, the golds, the VMs it
   built, and - kept fresh by the Dashboard and Jobs blades - the jobs and the WinPE state.
   `at` stays 0 until the first read, so nothing claims "no gold" before it knows. */
const cluster = { inventory: null, golds: [], vms: null, jobs: [], winpe: null, at: 0 };
async function refreshInventory(force) {
  if (!force && cluster.inventory && Date.now() - cluster.at < 15000) return cluster;
  const first = !cluster.at;
  try {
    const [inv, golds, vms, pools] = await Promise.all([api("GET", "/inventory"), api("GET", "/golds"), api("GET", "/vms"), api("GET", "/pools").catch(() => null)]);
    cluster.inventory = inv; cluster.golds = golds; cluster.vms = vms; cluster.at = Date.now();
    if (pools) cluster.pools = pools;
    // The studio's vSwitch list is the cluster's bridges and VNets now - read, never typed.
    const names = [...new Set(inv.nodes.flatMap(n => (n.bridges || []).map(b => b.iface)).concat(inv.vnets.map(v => v.vnet)))].sort();
    const switches = JSON.stringify(names) !== JSON.stringify(state.defaults.availableSwitches || []);
    if (switches) state.defaults.availableSwitches = names;
    /* The golds decide the VM cards' pickers and the preflight: the studio's own blades are
       drawn again once they are known. The server blades read their own data. */
    const bladeIsServer = (BLADES.find(b => b.id === state.blade) || {}).server;
    if (lab.id && (switches || (first && !bladeIsServer))) render();
    else { refreshValidation(); renderNav(); }
  } catch (e) { if (e.message !== "signed out") console.warn("inventory", e); }
  return cluster;
}

/* ---------- server blades ---------- */

let bladeSeq = 0;
function renderServerBlade(id, main) {
  /* Signed out, nothing is read: showLogin repaints the theme, and the theme renders -
     a server blade fetching then would answer 401 and call showLogin again, in a loop. */
  if (!session.user) return;
  const seq = ++bladeSeq;
  const stale = () => seq !== bladeSeq || state.blade !== id;
  if (!main.dataset.serverBlade || main.dataset.serverBlade !== id) {
    stopLiveLog();
    main.innerHTML = bladeHead(id) + `<p class="hint">Loading…</p>`;
  }
  main.dataset.serverBlade = id;
  const fn = { dashboard: bladeDashboard, winmedia: bladeWinMedia, golds: bladeGolds, media: bladeMedia, imagesettings: bladeImageSettings, studio: bladeStudio, deploy: bladeDeploy, jobs: bladeJobs }[id];
  Promise.resolve(fn(main, stale)).catch(e => {
    if (e.message !== "signed out" && !stale()) main.innerHTML = bladeHead(id) + warnBanner(esc(e.message));
  });
}
/* Blades rendered by studio.js leave the marker behind. */
const _renderBlade = renderBlade;
renderBlade = function () {
  const main = $id("main");
  const b = BLADES.find(x => x.id === state.blade);
  if (!b || !b.server) { delete main.dataset.serverBlade; stopLiveLog(); }
  _renderBlade();
};

/* -- Dashboard: what happens and what is designed on the left, the system on the right.
   Built from the studio's own parts - chips, collapsible cards, thin meters - and it took
   over the Cluster blade: the System card carries its nodes, storage and networks. -- */

let dashPoll = null, dashTls = null, dashTlsAsked = false, dashWin = null, dashFod = null, dashVer = null;
async function bladeDashboard(main, stale) {
  clearTimeout(dashPoll);
  const [, jobs, win, fod] = await Promise.all([refreshInventory(true), api("GET", "/jobs"), api("GET", "/settings/windows").catch(() => null),
    api("GET", "/settings/fod").catch(() => null)]);
  if (stale()) return;
  cluster.jobs = jobs; dashWin = win; dashFod = fod; cluster.winpe = !!(win && win.winpe && win.winpe.volid);
  if (!dashTlsAsked) {
    dashTlsAsked = true;
    api("GET", "/tls").then(t => { dashTls = t.certificate || null; if (!stale()) paintDashboard(main); }).catch(() => {});
    api("GET", "/studio/version").then(v => { dashVer = v; if (!stale()) paintDashboard(main); }).catch(() => {});
  }
  paintDashboard(main);
  renderNav();
  const busy = jobs.some(j => j.status === "running" || j.status === "queued");
  dashPoll = setTimeout(() => { if (!stale()) bladeDashboard(main, stale).catch(() => {}); }, busy ? 3000 : 15000);
}
document.addEventListener("click", async e => {
  const j = e.target.closest("#main [data-dash-job]");
  if (j) { openJob(j.dataset.dashJob); return; }
  if (e.target.closest("#main [data-cluster-check]")) {
    try { const { id } = await api("POST", "/jobs/cluster-check"); openJob(id); } catch (err) { toast(err.message, true); }
  }
});

/* A designed VM's state, from what the studio built and what PVE says about it now. */
function vmState(s, vms) {
  // The same match as the VM cards: by card, else by name (a card's id is not kept with it yet).
  const v = liveVm(s);
  if (!v && vmNameClash(s)) return { key: "warn", label: "name in use", v: null };
  if (!v || v.status === "removed") return { key: "design", label: "not built", v: null };
  if (v.status === "building") return { key: "run", label: "building", v };
  if (v.status === "failed") return { key: "bad", label: "build failed", v };
  if (v.power === "missing") return { key: "bad", label: "gone from PVE", v };
  if (v.power === "running") return { key: "ok", label: "running", v };
  return { key: "idle", label: v.power || "stopped", v };
}

function paintDashboard(main) {
  const inv = cluster.inventory, golds = cluster.golds || [], vms = cluster.vms || [], jobs = cluster.jobs || [];
  if (!inv || state.blade !== "dashboard") return;
  const online = inv.nodes.filter(n => n.status === "online");
  const states = state.servers.map(s => ({ s, st: vmState(s, vms) }));
  const count = k => states.filter(x => x.st.key === k).length;
  const running = jobs.filter(j => j.status === "running" || j.status === "queued");
  const ready = golds.filter(g => g.status === "ready");
  const nodesLine = inv.cluster ? `${online.length} of ${inv.nodes.length} nodes online` : `${esc(inv.nodes[0] ? inv.nodes[0].node : "node")} ${online.length ? "online" : "offline"}`;
  const nodesOk = online.length === inv.nodes.length && (!inv.cluster || inv.cluster.quorate);
  const html = bladeHead("dashboard", `<button class="btn" type="button" data-cluster-check><img src="${iconSrc("validate.svg")}" alt=""> Run cluster check</button>`) + `
    <div class="chips">
      <span class="pill status ${running.length ? "run" : "idle"}">${running.length} running</span>
      <span class="pill status ${nodesOk ? "ok" : "bad"}">${nodesLine}</span>
      <span class="pill">VMs: ${count("ok")} running of ${state.servers.length} designed</span>
      <span class="pill">Golds: ${ready.length} ready</span>
    </div>
    <div class="dash-split">
      <div class="dash-col">${dashRunning(jobs)}${dashActivity(jobs)}${dashVms(states)}</div>
      <div class="dash-col">${dashSystem(inv)}${dashWindows()}${dashGolds(golds)}</div>
    </div>
`;
  // Compared with what was drawn last, unless another blade has drawn in between.
  if (main._html !== html || !main.querySelector(".dash-split")) { main.innerHTML = html; main._html = html; }
}

const JOB_DOT = { running: "run", queued: "run", succeeded: "ok", failed: "bad", interrupted: "warn" };
function dashJobRow(j) {
  const p = j.progress, pct = p && typeof p.pct === "number" ? p.pct : null, live = j.status === "running" || j.status === "queued";
  const err = j.status === "failed" && j.error ? String(j.error).split("\n")[0] : "";
  // What it was (the subject's glyph: gold, Windows media, WinPE, VM...) with how it went
  // as a dot on its corner.
  const sub = jobSubject(j);
  return `<button type="button" class="dash-act" data-dash-job="${esc(j.id)}" title="${esc(sub.what)} - open the log">
    <span class="dash-act-ico"><img src="${sub.band ? iconSrcBand(sub.icon, sub.band) : iconSrc(sub.icon)}" alt=""><span class="dot ${JOB_DOT[j.status] || "idle"}"></span></span>
    <span class="dash-act-main"><span class="dash-act-title">${esc(j.title)}</span>
      ${live ? `<span class="dash-act-sub">${esc(p ? [p.label, p.detail].filter(Boolean).join(" · ") : "starting")}${pct != null ? ` · <b>${Math.floor(pct)}%</b>` : ""}</span>
        ${pct != null ? `<span class="dash-act-bar"><i style="width:${pct.toFixed(1)}%"></i></span>` : ""}`
      : `<span class="dash-act-sub">${esc(j.status)} · ${esc(when(j.ended_at || j.created_at))}${err ? ` · <span class="dash-act-err">${esc(err)}</span>` : ""}</span>`}</span>
    <span class="dash-act-took mono">${took(j.started_at, j.ended_at)}</span></button>`;
}

/* Running: what the studio works on right now, with its measured stage and percentage. It
   stays on top even when idle - one quiet line then, so "nothing runs" is visible too. */
function dashRunning(jobs) {
  const active = jobs.filter(j => j.status === "running" || j.status === "queued");
  const last = jobs.find(j => !active.includes(j));
  return gsCard("dash-running", "first-boot.svg", "Running", active.length ? `${active.length} job${active.length === 1 ? "" : "s"}` : "idle", active.length
    ? `<div class="dash-acts">${active.map(dashJobRow).join("")}</div>`
    : `<p class="dash-idle">Nothing runs right now.${last ? ` The last job ended ${esc(when(last.ended_at || last.created_at))}.` : ""}</p>`,
    "", true, active.length ? `<span class="pill status run">Live</span>` : "");
}

/* Activity: what ran, newest first - failures red with the first line of their reason. */
function dashActivity(jobs) {
  const done = jobs.filter(j => j.status !== "running" && j.status !== "queued");
  const day = Date.now() - 86400000;
  const recent = done.filter(j => new Date(j.ended_at || j.created_at) > day);
  const failed = recent.filter(j => j.status === "failed").length;
  const meta = recent.length ? `${recent.length} in the last day${failed ? `, ${failed} failed` : ""}` : "quiet for a day";
  return gsCard("dash-activity", "update.svg", "Activity", meta, done.length
    ? `<div class="dash-acts">${done.slice(0, 8).map(dashJobRow).join("")}</div>`
    : `<p class="dash-idle">No jobs yet - bakes, builds and checks show up here once they ran.</p>`, "", true, dashGoBtn("jobs", "Jobs"));
}

/* The designed VMs: one row each with its gold and address; what keeps one from deploying
   (no gold, a name in use, a failed build) is said on its own row. */
function dashVms(states) {
  const errors = reviewErrorCount();
  const toBuild = states.filter(x => x.st.key === "design" || x.st.label === "build failed").length;
  const meta = states.length ? [`${states.length} designed`, toBuild ? `${toBuild} to build` : "all built", errors ? `${errors} preflight error${errors === 1 ? "" : "s"}` : ""].filter(Boolean).join(" · ") : "nothing designed yet";
  return gsCard("dash-vms", "vm.svg", "Designed VMs", meta, states.length
    ? `<div class="dash-vms">${states.map(({ s, st }) => {
        const img = findImage(s.imageId), g = goldFor(s);
        const ip = (st.v && st.v.ip) || s.ipAddress || "DHCP";
        return `<button type="button" class="dash-vm" data-goto="${st.v ? "access" : "servers"}">
          <span class="dot ${st.key}"></span><span class="dash-vm-name">${esc(s.name || "(no name)")}</span>
          <span class="dash-vm-os"><img src="${imageIconSrc(img)}" alt="">${esc(img.label.replace(/^Windows Server /, "WS ").replace(/^Windows /, "W"))}
            ${g ? `<span class="mono muted">${esc(goldBuildLabel(g))}</span>` : `<span class="pill role danger">no gold</span>`}</span>
          <span class="dash-vm-ip mono">${esc(ip)}</span>
          <span class="pill status ${{ ok: "ok", run: "run", bad: "bad", warn: "warn" }[st.key] || "idle"}">${esc(cap(st.label))}</span></button>`;
      }).join("")}</div>`
    : `<div class="dp-empty"><span class="dp-empty-slot" aria-hidden="true"><img src="${iconSrc("vm.svg")}" alt=""></span>
        <div class="dp-empty-text"><b>Nothing designed yet</b><span>Each VM you design appears here with its gold, its address and its state.</span></div>
        <button class="btn" type="button" data-goto="servers"><img src="${iconSrc("vm.svg")}" alt=""> Design a VM</button></div>`, "", true);
}

/* The system in one card: short sections, each with the link to its full view. A section
   says when something is wrong (red or yellow dot and the reason) - there is no separate
   alert list. */
function dashSystem(inv) {
  const pct = (a, b) => b ? Math.min(100, a / b * 100) : 0;
  const tone = p => p >= 90 ? "danger" : p >= 75 ? "warn" : "";
  const bar = (p, text) => `<span class="meter-track"><span class="meter-fill ${tone(p)}" style="width:${p.toFixed(1)}%"></span></span><span class="meter-text">${text}</span>`;
  const sec = (title, link, label, body) => `<section class="dash-sec"><h5>${esc(title)}</h5>${body}</section>`;
  const line = (dot, text, right) => `<div class="dash-line"><span class="dot ${dot}"></span><span class="dash-line-text">${text}</span>${right ? `<span class="dash-line-right">${right}</span>` : ""}</div>`;
  const online = inv.nodes.filter(n => n.status === "online");

  const nodes = inv.nodes.slice(0, 8).map(n => {
    if (n.status !== "online") return line("bad", `<b>${esc(n.node)}</b> is ${esc(n.status || "unknown")}`);
    const cpu = (n.cpu || 0) * 100, mem = pct(n.mem, n.maxmem), disk = pct(n.disk, n.maxdisk);
    return `${line("ok", `<b>${esc(n.node)}</b>`, `<span class="mono muted">${esc(n.ip || "")}</span>`)}
      <div class="dash-mini"><em>CPU</em>${bar(cpu, `${cpu.toFixed(0)}%`)}</div>
      <div class="dash-mini"><em>RAM</em>${bar(mem, `${gib(n.mem)} / ${gib(n.maxmem)}`)}</div>
      <div class="dash-mini"><em>DISK</em>${bar(disk, `${gib(n.disk)} / ${gib(n.maxdisk)}`)}</div>`;
  }).join("") + (inv.nodes.length > 8 ? `<div class="hint">+${inv.nodes.length - 8} more nodes below</div>` : "");
  const quorum = inv.cluster ? line(inv.cluster.quorate ? "ok" : "bad", inv.cluster.quorate ? "Quorate" : "<b>No quorum</b>", `${online.length} / ${inv.nodes.length} online`) : "";

  // Storage that holds VM disks, once per shared storage; the free memory says how many more fit.
  const seen = new Set();
  const vmStor = inv.storages.filter(st => (st.content || "").split(",").includes("images") && st.maxdisk).filter(st => {
    const k = st.shared === 1 ? st.storage : st.storage + "@" + st.node; if (seen.has(k)) return false; seen.add(k); return true; });
  const storage = vmStor.map(st => {
    const p = pct(st.disk, st.maxdisk);
    return `${line(p >= 90 ? "bad" : p >= 75 ? "warn" : "ok", `<b>${esc(st.storage)}</b> <span class="muted">${esc(st.plugintype || "")}${st.shared === 1 ? ", shared" : inv.nodes.length > 1 ? " on " + esc(st.node) : ""}</span>`, p >= 90 ? `<span class="pill role danger">${Math.round(p)}% full</span>` : "")}
      <div class="dash-mini wide">${bar(p, sizePair(st.disk, st.maxdisk))}</div>`;
  }).join("");

  const bridges = [...new Set(inv.nodes.flatMap(n => (n.bridges || []).map(b => b.iface)))];
  const networks = line("", `<b>${bridges.length}</b> bridge${bridges.length === 1 ? "" : "s"}${bridges.length ? ` <span class="muted">(${esc(bridges.slice(0, 4).join(", "))}${bridges.length > 4 ? ", …" : ""})</span>` : ""} · <b>${inv.vnets.length}</b> SDN VNet${inv.vnets.length === 1 ? "" : "s"}`);

  const studio = dashTls ? line(dashTls.days_left < 7 ? "bad" : dashTls.days_left < 21 ? "warn" : "ok", `Certificate <span class="muted">${esc(dashTls.names[0] || "")}</span>`, `${dashTls.days_left} days`)
    : line("warn", "No certificate read yet");
  // This build against GitHub: the newest release decides; how far main is ahead is detail.
  const vr = dashVer;
  // The node the studio talks to PVE through - another one takes over when it is down.
  const via = /^https?:/.test(inv.api_via || "") ? (online.find(n => (inv.api_via || "").includes(n.ip)) || {}).node || inv.api_via.replace(/^https?:\/\/|:\d+\/?$/g, "") : inv.api_via;
  const apiLine = inv.api_via ? line("ok", `PVE API through <b>${esc(via)}</b>`, inv.api_ways > 1 ? `<span class="muted" title="If it cannot be reached, the studio continues through another node">${inv.api_ways - 1} more node${inv.api_ways === 2 ? "" : "s"} as fallback</span>` : `<span class="muted" title="A cluster's other nodes take over when this one is down - a single node has none">no fallback</span>`) : "";
  const build = vr ? `v${esc(vr.version)}${vr.commit ? ` <span class="muted mono">${esc(vr.commit)}</span>` : ""}` : "";
  const verLine = !vr ? "" : vr.state === "update"
    ? line("warn", `PVE VM Studio ${build}`, `<a class="pill status warn" href="${esc(vr.url)}" target="_blank" rel="noopener" title="Release notes on GitHub">v${esc(vr.latest)} available</a>`)
    : vr.state === "current"
    ? line("ok", `PVE VM Studio ${build}`, vr.main_ahead ? `up to date <span class="muted" title="Commits on main since this build - not released yet">· main +${vr.main_ahead}</span>` : "up to date")
    : line("", `PVE VM Studio ${build}`, `<span class="muted" title="GitHub has no published release to compare with yet">no release published yet</span>`);

  return gsCard("dash-system", "servers.svg", "System", `${inv.cluster ? esc(inv.cluster.name) : esc(online[0] ? online[0].node : "node")} · Proxmox VE ${esc(String(inv.version).split("-")[0])}`, `<div class="dash-sys">
    ${sec(inv.cluster ? "Cluster" : "Node", "", "", quorum + nodes)}
    ${sec("Storage for VMs", "", "", storage)}
    ${sec("Networks", "networks", "Networks", networks)}
    ${sec("Studio", "studio", "Settings", verLine + studio + apiLine)}
  </div>`, "", true);
}

const dashLine = (dot, text, right) => `<div class="dash-line"><span class="dot ${dot}"></span><span class="dash-line-text">${text}</span>${right ? `<span class="dash-line-right">${right}</span>` : ""}</div>`;
/* A way to the full view, as the studio's buttons look everywhere: small, with the blade's glyph. */
const DASH_GO_ICON = { jobs: "update.svg", networks: "vnet.svg", studio: "certificate.svg", golds: "gold-image.svg", media: "iso-media.svg" };
const dashGoBtn = (blade, label) => `<button type="button" class="btn sm" data-goto="${blade}"><img src="${iconSrc(DASH_GO_ICON[blade] || "overview.svg")}" alt=""> ${esc(label)}</button>`;

/* Windows: is the studio ready to bake and build Windows VMs? WinPE and virtio-win, one
   line each - the details are on Media. */
/* virtio-win releases as numbers, to tell which is newer: 0.1.302-1 -> [0, 1, 302, 1]. */
const vioNum = v => String(v || "").split(/[.-]/).map(x => parseInt(x, 10) || 0);
const vioNewer = (a, b) => { const x = vioNum(a), y = vioNum(b); for (let i = 0; i < Math.max(x.length, y.length); i++) { if ((x[i] || 0) !== (y[i] || 0)) return (x[i] || 0) > (y[i] || 0); } return false; };

/* Windows: what every Windows bake needs, one row each - green or red, the name, its build -
   and a newer virtio-win when there is one. */
/* WinPE against the newest Windows Server vNext build it is built from: what every bake, deploy
   and media build boots, so an old one is worth a look. */
function peHint(w) {
  const n = w.winpe_newest, st = w.winpe_state;
  const auto = "With Keep WinPE current on (Image settings → Windows updates), the studio rebuilds it in the next maintenance window.";
  const from = (PE_PRODUCTS.find(p => p[0] === (w.settings || {}).winpe_from) || PE_PRODUCTS[0])[1];
  if (st === "outdated" && n) return `<span class="pill status warn" title="${esc(from)} ${esc(n.build)} is out - WinPE is distilled from its WinRE. ${esc(auto)}">${esc(cap(n.build))} available</span>`;
  if (st === "virtio" && w.virtio_now) return `<span class="pill status warn" title="Its vioscsi driver is from virtio-win ${esc((w.winpe || {}).vioscsi || "none")}, the release in use is ${esc(w.virtio_now)}. ${esc(auto)}">virtio-win ${esc(w.virtio_now)} not in it</span>`;
  return "";
}
function dashWindows() {
  const w = dashWin || {}, pe = w.winpe || {}, set = (w.settings || {}).virtio || "stable";
  const vio = set === "stable" ? w.stable : set === "latest" ? w.latest : set;
  const newest = [w.stable, w.latest].filter(Boolean).reduce((m, v) => (!m || vioNewer(v, m) ? v : m), "");
  const update = vio && newest && vioNewer(newest, vio) ? newest : "";
  // The release in use is in PVE, or a bake fetches it (virtio::fetch) - not a blocker.
  const vioHere = !!vio && (w.present || []).includes(vio);
  // A WinPE without vioscsi cannot reach a virtio-scsi disk: not ready, whatever else is there.
  const peOk = !!pe.volid && !!pe.vioscsi;
  const ready = peOk && !!vio;
  const row = (ok, name, value, extra) => `<div class="dash-wrow"><span class="dot ${ok === "idle" ? "idle" : ok ? "ok" : "bad"}"></span><span class="dash-wrow-name">${name}</span>
    ${extra ? `<span class="dash-wrow-extra">${extra}</span>` : ""}<span class="dash-wrow-val mono">${value}</span></div>`;
  // Optional: the Features on Demand ISO of each release - without one, capabilities come
  // from Windows Update at a VM's first boot.
  const fs = (dashFod && dashFod.settings) || {}, fm = (dashFod && dashFod.media) || {};
  const fodRow = ([key, , label]) => {
    const v = fs[key], m = fm[key];
    const file = v ? v.replace(/^.*\//, "").replace(/\.iso$/, "") : "";
    const tone = !v ? "idle" : m && m.ok ? "ok" : "bad";
    return `<div class="dash-wrow"><span class="dot ${tone}"></span><span class="dash-wrow-name">FoD ${esc(label)}</span>
      <span class="dash-wrow-val mono${v ? "" : " muted"}" title="${v ? esc(v) + (m && m.missing ? " - not in PVE any more; VMs take their capabilities from Windows Update until it is built again" : "") : "Capabilities come from Windows Update"}">${!v ? "Windows Update" : m && m.missing ? "missing" : esc(file)}</span></div>`;
  };
  return gsCard("dash-windows", "windows-layers.svg", "Windows", ready ? "ready to provision Windows VMs" : "not ready yet",
    `<section class="dash-sec"><h5>Required</h5><div class="dash-wrows">${row(peOk, "WinPE", !pe.volid ? "missing" : pe.vioscsi ? esc(pe.build) : "no vioscsi - rebuild", peHint(w))}
      ${row(!vio ? false : vioHere ? true : "idle", "virtio-win", vio ? esc(vio) : "unknown",
        update ? `<span class="pill status warn" title="${set === "stable" || set === "latest" ? "Newer than the release in use" : "The pinned release is older - change it under Media"}">${esc(cap(update))} available</span>`
          : vio && !vioHere ? `<span class="hint" title="Not in PVE now - the first Windows bake downloads it">fetched by the first bake</span>` : "")}</div></section>
    <section class="dash-sec"><h5>Optional</h5><div class="dash-wrows">${FOD_SLOTS.map(fodRow).join("")}</div></section>`,
    "", true, `<span class="pill status ${ready ? "ok" : "bad"}">${ready ? "Ready" : "Not ready"}</span>${dashGoBtn("media", "Media")}`);
}
function dashGolds(golds) {
  const inv = goldInventory(golds), shelf = inv.filter(e => e.kind === "newest").map(e => e.g);
  const baking = golds.filter(g => g.status === "baking").length, spare = inv.filter(e => e.suggested).length;
  const goldRow = g => {
    const img = findImage(g.image_id), m = goldManifest(g);
    const name = img.id === g.image_id ? img.label : (m.displayName || g.image_id);
    return `<div class="dash-gold"><img src="${imageIconSrc(img)}" alt=""><span class="dash-gold-name">${esc(name)}</span><span class="mono muted">${esc(goldBuildLabel(g))}</span></div>`;
  };
  // Windows and Linux apart, each its own section.
  const part = (title, list) => list.length ? `<section class="dash-sec"><h5>${title}</h5>${list.slice(0, 6).map(goldRow).join("")}
    ${list.length > 6 ? `<div class="hint">+${list.length - 6} more</div>` : ""}</section>` : "";
  const rows = shelf.length ? part("Windows", shelf.filter(g => g.os === "windows")) + part("Linux", shelf.filter(g => g.os !== "windows"))
    : dashLine("", `No gold yet. Linux bakes right away${cluster.winpe ? ", Windows too" : "; Windows needs WinPE first"}.`);
  return gsCard("dash-golds", "gold-image.svg", "Golds", `${shelf.length} ready${baking ? ` · ${baking} baking` : ""}`, rows
    + (spare ? (shelf.length ? '<section class="dash-sec">' : "") + dashLine("warn", `${spare} older gold${spare === 1 ? "" : "s"} can be cleaned up`, `<button class="btn sm" type="button" data-goto="golds">Clean up</button>`) + (shelf.length ? "</section>" : "") : "")
    , "", true, (baking ? `<span class="pill status run">Baking</span>` : "") + dashGoBtn("golds", "Golds"));
}

/* -- Windows media: install ISOs built from Microsoft's own update files (src/media.rs).
   Products on the left, the chosen product's builds - newest on top, every one buildable -
   in the middle, and what the chosen build becomes, and costs, on the right. -- */

/* A language tag as people write it: en-US, sr-Latn-RS (the catalog has en-us). */
function langTag(t) {
  return String(t || "").split("-").map((p, i) => i === 0 ? p.toLowerCase() : p.length === 4 ? p[0].toUpperCase() + p.slice(1).toLowerCase() : p.toUpperCase()).join("-");
}
const wmUi = { product: "ws2025", uuid: "", lang: "", editions: null, kind: "", search: "", products: null, builds: {}, wu: {}, wuTimer: null, eds: {}, size: {}, isos: [], err: "" };
const WM_SIZE_KEY = () => `${wmUi.uuid}|${wmUi.lang}|${wmBaseEditions().sort().join(",")}`;
const gb = b => (b / 1e9).toFixed(b >= 1e10 ? 0 : 1) + " GB";
function wmDate(sec) { return sec ? new Date(sec * 1000).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" }) : ""; }
function wmBuild(b) {
  const i = String(b).lastIndexOf(".");
  return i > 0 ? `<span class="wm-build"><span class="base">${esc(b.slice(0, i + 1))}</span>${esc(b.slice(i + 1))}</span>` : `<span class="wm-build">${esc(b)}</span>`;
}

async function bladeWinMedia(main, stale) {
  wmUi.main = main; wmUi.stale = stale;
  // The language starts at the studio's region preselection (Studio settings).
  if (!wmUi.lang) {
    try { catalogCache = catalogCache || await api("GET", "/catalog"); wmUi.lang = String(catalogCache.region.language || "en-US").toLowerCase(); } catch { /* the catalog picks en-us */ }
  }
  if (!wmUi.products) {
    try { const r = await api("GET", "/media/products"); wmUi.products = r.products; wmUi.checked = Date.now() - (r.checked || 0) * 1000; }
    catch (e) { if (stale()) return; wmUi.err = e.message; }
  }
  try { wmUi.isos = await api("GET", "/media/isos"); } catch { /* the list stays as it was */ }
  if (stale()) return;
  paintWinMedia();
  wmLoadBuilds();
}
async function wmLoadBuilds(fresh) {
  const id = wmUi.product;
  if (!wmUi.builds[id] || fresh) {
    try { const r = await api("GET", `/media/builds?product=${encodeURIComponent(id)}${fresh ? "&fresh=1" : ""}`); wmUi.builds[id] = r.builds; wmUi.wu[id] = r.wu; }
    catch (e) { wmUi.err = e.message; }
  }
  // Until Microsoft Update has answered, the labels are estimates: asked again shortly.
  clearTimeout(wmUi.wuTimer);
  if (wmUi.wu[id] && !wmUi.wu[id].checked) wmUi.wuTimer = setTimeout(() => { if (wmUi.product === id && location.hash === "#/winmedia") wmLoadBuilds(true); }, 10000);
  const list = wmUi.builds[id] || [];
  // The newest stable (Patch Tuesday) build - what the default filter shows first.
  if (!list.some(b => b.uuid === wmUi.uuid)) { const first = list.find(b => / (B|OOB)$/.test(b.kind)) || list[0]; wmUi.uuid = first ? first.uuid : ""; wmUi.editions = null; }
  paintWinMedia();
  wmLoadEditions();
}
async function wmLoadEditions() {
  const id = wmUi.uuid; if (!id) return;
  const key = id + "|" + (wmUi.lang || "");
  if (!wmUi.eds[key]) {
    try { const r = await api("GET", `/media/editions?id=${encodeURIComponent(id)}&lang=${encodeURIComponent(wmUi.lang || "")}`); wmUi.eds[key] = r; wmUi.eds[id + "|" + r.lang] = r; wmUi.lang = r.lang; }
    catch (e) { wmUi.eds[key] = { error: e.message }; }
  }
  const r = wmUi.eds[id + "|" + wmUi.lang] || wmUi.eds[key];
  if (r && r.editions && (!wmUi.editions || ![...wmUi.editions].every(e => r.editions.some(x => x.code === e)))) {
    // Server: Datacenter, Core and Desktop Experience; Windows 11: Pro.
    const has = c => r.editions.some(e => e.code === c);
    const server = ["SERVERDATACENTERCORE", "SERVERDATACENTER"].filter(has);
    const pick = server.length ? server : has("PROFESSIONAL") ? ["PROFESSIONAL"] : [(r.editions[0] || {}).code].filter(Boolean);
    wmUi.editions = new Set(pick);
  }
  paintWinMedia();
  wmLoadSize();
}
let wmSizeTimer = null;
function wmLoadSize() {
  clearTimeout(wmSizeTimer);
  const key = WM_SIZE_KEY();
  if (!wmUi.uuid || !wmBaseEditions().length || wmUi.size[key]) { paintWinMedia(); return; }
  wmSizeTimer = setTimeout(async () => {
    try { wmUi.size[key] = await api("GET", `/media/size?product=${wmUi.product}&id=${wmUi.uuid}&lang=${wmUi.lang}&editions=${wmBaseEditions().join(",")}`); }
    catch (e) { wmUi.size[key] = { error: e.message }; }
    paintWinMedia();
  }, 400);
}

/* Editions as the studio shows choices everywhere: toggles, grouped the way the editions
   are sold - Standard and Datacenter with Core and Desktop Experience under each; Home and
   Pro. Only what Microsoft ships: Enterprise and the other editions made from Pro are a
   choice of the bake (edition upgrade), not of the media. */
const WM_FAMILY = [
  [/^SERVERSTANDARD/, "Standard"], [/^SERVERDATACENTER/, "Datacenter"],
  [/^CORE/, "Home"], [/^PROFESSIONAL/, "Pro"],
];
function wmEditionRows(ed) {
  const groups = new Map();
  for (const e of ed.editions) {
    const fam = (WM_FAMILY.find(([re]) => re.test(e.code)) || [null, "Other"])[1];
    const server = /^SERVER/.test(e.code);
    const label = server ? (/CORE$/.test(e.code) ? "Core" : "Desktop Experience") : e.name.replace(/^Windows /, "");
    if (!groups.has(fam)) groups.set(fam, []);
    groups.get(fam).push({ code: e.code, label, tip: server && label === "Core"
      ? "No desktop: Server Core is run from the command line, PowerShell and remote tools such as Windows Admin Center and RSAT. Smaller, and fewer updates to install."
      : !server && /N$/.test(e.code) ? "N editions come without the media apps (Media Player, Camera and similar) - made for markets that require it. Microsoft's Media Feature Pack adds them back." : "" });
  }
  // The same order in every group: Core, then Desktop Experience.
  for (const list of groups.values()) list.sort((a, b) => (a.label === "Core" ? 0 : 1) - (b.label === "Core" ? 0 : 1));
  return [...groups.entries()].map(([fam, list]) => `<div class="wm-ed-group"><div class="wm-ed-head">${esc(fam)}</div>
    ${list.map(x => toggle(`data-wm-ed="${esc(x.code)}"`, esc(x.label) + (x.tip ? " " + infoTip(x.label, x.tip) : ""), !!wmUi.editions && wmUi.editions.has(x.code))).join("")}</div>`).join("");
}
function wmBaseEditions() { return [...(wmUi.editions || [])]; }

function paintWinMedia() {
  const main = wmUi.main;
  if (!main || state.blade !== "winmedia" || (wmUi.stale && wmUi.stale())) return;
  const prods = wmUi.products || [];
  const prod = prods.find(p => p.id === wmUi.product) || {};
  const all = wmUi.builds[wmUi.product];
  const q = wmUi.search.trim().toLowerCase();
  // Stable (Patch Tuesday releases) by default; an Insider product has none, so All.
  const kind = wmUi.kind || (prod.insider ? "all" : "b");
  const builds = all && all.filter(x => (kind === "all" || (kind === "b" ? / (B|OOB)$/.test(x.kind) : !/ (B|OOB)$/.test(x.kind)))
    && (!q || x.build.includes(q) || x.kind.toLowerCase().includes(q) || wmDate(x.created).toLowerCase().includes(q)));
  const b = (all || []).find(x => x.uuid === wmUi.uuid);
  const groups = [...new Set(prods.map(p => p.group))];

  const filter = `<div class="card wm-filter">
      <div class="wm-filter-row">
        ${field(fieldLabel("windows-layers.svg", "Product"), `<select id="wmProduct">${groups.map(g => `<optgroup label="${esc(g)}">${prods.filter(p => p.group === g).map(p =>
          `<option value="${esc(p.id)}" ${p.id === wmUi.product ? "selected" : ""}>${esc(p.name)}${p.newest ? ` - ${esc(p.newest.build)}` : ""}</option>`).join("")}</optgroup>`).join("")}</select>`)}
        <div class="field-like">${fieldLabel("update.svg", "Releases")}
          <div class="ov-seg" role="group" aria-label="Releases">${[["b", "Stable"], ["other", prod.insider ? "Insider" : "Preview"], ["all", "All"]].map(([k, l]) =>
            `<button type="button" class="btn${kind === k ? " on" : ""}" data-wm-kind="${k}" aria-pressed="${kind === k}">${l}</button>`).join("")}</div></div>
        ${field(fieldLabel("validate.svg", "Search"), `<input id="wmSearch" type="search" placeholder="Build, month or date - 33438, 2026-08, Jul" value="${esc(wmUi.search)}">`)}
      </div>
      <div class="wm-filter-meta">${prod.insider ? `<span class="pill status warn">Insider Preview</span>` : `<span class="pill">Supported</span>`}
        <span class="hint">${esc(prod.support || "")}${all ? ` · ${all.length} build${all.length === 1 ? "" : "s"} in the catalog${builds.length !== all.length ? `, ${builds.length} shown` : ""}` : ""}${wmUi.wu[wmUi.product] && !wmUi.wu[wmUi.product].checked ? ` · <span class="wm-wu">Checking Microsoft Update…</span>${infoTip("Microsoft Update", "Which builds are Patch Tuesday (B) and out-of-band security releases comes from Microsoft Update. Until it has answered - about a minute and a half on a fresh install - the labels are estimates from the date (B?), and Stable shows none.")}` : ""}</span></div>
    </div>`;

  const rows = !all ? `<tr><td colspan="5" class="muted">Asking the catalog…</td></tr>`
    : !builds.length ? `<tr><td colspan="5" class="muted">${kind === "b" && !q && wmUi.wu[wmUi.product] && !wmUi.wu[wmUi.product].checked ? "Checking Microsoft Update for the security releases…" : "No build matches - clear the search or pick All."}</td></tr>`
    : builds.map(x => `<tr class="${x.uuid === wmUi.uuid ? "sel" : ""}" data-wm-build="${esc(x.uuid)}">
      <td>${wmBuild(x.build)}${x.uuid === all[0].uuid ? ' <span class="pill status ok wm-newest">Newest</span>' : ""}</td>
      <td>${x.kind === "Insider" ? `<span class="pill status warn">Insider</span>` : `<span class="pill">${esc(x.kind)}</span>`}</td>
      <td class="muted">${esc(wmDate(x.created))}</td>
      <td>${(x.isos || []).length ? `<span class="pill status ok">Built</span>` : ""}</td>
      <td class="row-actions"><button class="btn sm${x.uuid === wmUi.uuid ? " primary" : ""}" type="button" data-wm-build="${esc(x.uuid)}">${x.uuid === wmUi.uuid ? "Selected" : "Select"}</button></td></tr>`).join("");

  const ed = b && wmUi.eds[b.uuid + "|" + wmUi.lang];
  const sz = wmUi.size[WM_SIZE_KEY()];
  const n = wmUi.editions ? wmUi.editions.size : 0;
  const needWorker = sz && !sz.error && sz.worker;
  const workerMin = needWorker ? 20 * n : 0;
  const mins = sz && !sz.error ? Math.round(sz.total / 20e6 / 60 + workerMin + 3) : 0;
  const tight = sz && sz.free != null && sz.total * 3 > sz.free;
  const panel = !b ? `<p class="hint">Pick a build.</p>` : `
      ${prod.insider ? `<div class="warn-banner"><div class="warn-banner-text">Insider Preview: for trying things, not for production. It expires, and Microsoft supports it only through the Feedback Hub.</div></div>` : ""}
      <div class="field-like">${fieldLabel("windows-layers.svg", "Editions - one image each, all in one ISO")}
        ${!ed ? `<p class="hint">Asking the catalog…</p>` : ed.error ? `<p class="hint err">${esc(ed.error)}</p>` : `<div class="wm-eds">${wmEditionRows(ed)}</div>`}</div>
      <div class="field-like">${fieldLabel("language.svg", "Language")}
        <select id="wmLang" ${ed && ed.langs ? "" : "disabled"}>${ed && ed.langs ? opts(ed.langs.slice().sort().map(l => [l, langTag(l)]), wmUi.lang) : "<option>…</option>"}</select></div>
      <div class="wm-pre">
        <div class="wm-pre-head">Before it starts</div>
        ${!n ? `<p class="hint" style="padding:10px 12px">Pick at least one edition.</p>` : !sz ? `<p class="hint" style="padding:10px 12px">Adding it up…</p>` : sz.error ? `<p class="hint err" style="padding:10px 12px">${esc(sz.error)}</p>` : `
        <div class="wm-pre-grid">
          <div>Download<b>${gb(sz.total)}</b>${sz.files} file(s) from Microsoft</div>
          <div>Takes about<b>${mins} min</b>${needWorker ? `then the worker, ~${workerMin} min` : "no worker needed"}</div>
          <div>Cumulative update<b>${sz.updates ? gb(sz.updates) : "none"}</b>${sz.worker ? "the worker applies it" : "the build is complete as it is"}</div>
          <div>Room while it runs<b>${gb(sz.total * 3)}</b>${sz.free != null ? `${gb(sz.free)} free in the studio` : ""}${tight ? ' - <span class="dash-bad">too little</span>' : ""}</div>
        </div>`}
      </div>
      ${(b.isos || []).length ? `<p class="hint">Built already: ${b.isos.map(i => `<span class="mono">${esc(i.volid.split("/").pop())}</span>`).join(", ")} - building again replaces it.</p>` : ""}
      <div class="row gs-actions"><button class="btn primary" type="button" id="wmGo" ${n && sz && !sz.error && !tight ? "" : "disabled"}><img src="${iconSrcOnAccent("download.svg")}" alt=""> Build ISO</button></div>`;

  const html = bladeHead("winmedia", `<button class="btn" type="button" id="wmRefresh"><img src="${iconSrc("update.svg")}" alt=""> Refresh the catalog</button>`) + `
    ${wmUi.err ? warnBanner(esc(wmUi.err)) : ""}
    ${filter}
    <div class="wm-layout">
      <section class="card wm-builds">
        <div class="wm-scroll"><table class="data"><thead><tr><th>Build</th><th>Release</th><th>Date</th><th>Here</th><th></th></tr></thead><tbody>${rows}</tbody></table></div>
      </section>
      <aside class="card wm-panel">
        <div class="wm-panel-head">${b ? `${wmBuild(b.build)}<span class="muted">${esc(b.kind)} · ${esc(wmDate(b.created))}</span>` : `<span class="muted">No build selected</span>`}</div>
        <div class="wm-panel-body">${panel}</div>
      </aside>
    </div>`;
  if (main._html !== html || !main.querySelector(".wm-layout")) {
    // Typing in the search box repaints; keep the caret where it was.
    const f = document.activeElement && document.activeElement.id === "wmSearch" ? document.activeElement.selectionStart : null;
    const top = main.querySelector(".wm-scroll") ? main.querySelector(".wm-scroll").scrollTop : 0;
    main.innerHTML = html; main._html = html;
    if (main.querySelector(".wm-scroll")) main.querySelector(".wm-scroll").scrollTop = top;
    if (f != null && $id("wmSearch")) { $id("wmSearch").focus(); $id("wmSearch").setSelectionRange(f, f); }
  }
}

document.addEventListener("click", async e => {
  if (state.blade !== "winmedia") return;
  const t = e.target;
  const k = t.closest("[data-wm-kind]");
  if (k) { wmUi.kind = k.dataset.wmKind; paintWinMedia(); return; }
  const bt = t.closest("[data-wm-build]");
  if (bt && !t.closest(".toggle")) { if (bt.dataset.wmBuild !== wmUi.uuid) { wmUi.uuid = bt.dataset.wmBuild; paintWinMedia(); wmLoadEditions(); } return; }
  if (t.closest("#wmRefresh")) { wmUi.products = null; wmUi.builds = {}; wmUi.err = ""; bladeWinMedia(wmUi.main, wmUi.stale); return; }
  const cp = t.closest("#main .wm-isos-copy, #main [data-copy]");
  if (cp && cp.closest(".card")) { try { await navigator.clipboard.writeText(cp.dataset.copy); toast("Copied"); } catch (err) { toast("Copy failed: " + err.message, true); } return; }
  const ib = t.closest("[data-iso-bake]");
  if (ib) { winForm.iso = ib.dataset.isoBake; winForm.index = null; winForm.edition = ""; openBake("windows"); return; }
  if (t.closest("#wmGo")) {
    const b = (wmUi.builds[wmUi.product] || []).find(x => x.uuid === wmUi.uuid); if (!b) return;
    try { const { id } = await api("POST", "/media/build", { product: wmUi.product, uuid: b.uuid, build: b.build, lang: wmUi.lang, editions: [...(wmUi.editions || [])] }); openJob(id); }
    catch (err) { toast(err.message, true); }
  }
});
document.addEventListener("change", e => {
  if (state.blade !== "winmedia") return;
  const t = e.target;
  if (t.id === "wmLang") { wmUi.lang = t.value; wmUi.editions = null; paintWinMedia(); wmLoadEditions(); }
  else if (t.id === "wmProduct") { wmUi.product = t.value; wmUi.uuid = ""; wmUi.editions = null; wmUi.err = ""; wmUi.kind = ""; wmUi.search = ""; paintWinMedia(); wmLoadBuilds(); }
  else if (t.dataset.wmEd) {
    const set = wmUi.editions = new Set(wmUi.editions || []);
    t.checked ? set.add(t.dataset.wmEd) : set.delete(t.dataset.wmEd);
    paintWinMedia(); wmLoadSize();
  }
});
document.addEventListener("input", e => {
  if (state.blade !== "winmedia" || e.target.id !== "wmSearch") return;
  wmUi.search = e.target.value; paintWinMedia();
});

/* -- Golds: the library, and the bake panel above it -- */

const bakeForm = { image: "", mirror: null, node: "", bridge: "", vlan: null, addresses: "", gateway: "", dns: "", disk: null, storage: "", updates: true, features: ["aliases", "prompt", "fastfetch", "quietmotd"], region: true, language: "", format: "", keyboard: "", timezone: "", cis: 0 };
const winForm = { iso: "", index: null, edition: "", disk: 64, storage: "", locale: "", keyboard: "", timezone: "", features: ["rdp", "ping", "svrmgr", "noencrypt", "power"] };
const goldsUi = { bake: false, os: "linux", cleanup: false, cleanupPick: null, labelEdit: null, au: null, placeOpen: false };
let catalogCache = null;

function openBake(os) { goldsUi.bake = true; goldsUi.os = os; state.blade = "golds"; $id("main").scrollTop = 0; render(); }

/* One tile per kind - image, language and disk size, Build-Vms' "of their kind": two golds
   that differ in any of those are both wanted. The newest ready gold heads the tile (highest
   build, then latest bake), what is baking or failed after it shows below, older ones fold. */
function goldKind(g) { return g.image_id + "|" + goldLang(g) + "|" + (goldManifest(g).diskSizeGB || ""); }
function goldTiles(golds, catalog) {
  const groups = new Map();
  golds.forEach(g => { const k = goldKind(g); if (!groups.has(k)) groups.set(k, []); groups.get(k).push(g); });
  return [...groups.entries()].map(([key, list]) => {
    list.sort((a, b) => (a.status === "ready") === (b.status === "ready") ? compareGolds(a, b) : a.status === "ready" ? -1 : 1);
    const current = list.find(g => g.status === "ready") || null;
    const head = current || list.slice().sort((a, b) => String(b.created_at).localeCompare(String(a.created_at)))[0];
    const m = goldManifest(head);
    const img = findImage(head.image_id);
    const name = head.os === "windows" && img.id === head.image_id ? img.label
      : m.displayName || (head.os === "windows" ? (m.name || img.label) : (catalog.linux.find(i => i.id === head.image_id)?.name || m.name || head.image_id));
    return { key, list, current, head, name, os: head.os,
      newer: current ? list.filter(g => g.status !== "ready" && g.created_at > current.created_at) : [],
      older: current ? list.filter(g => g !== current && !(g.status !== "ready" && g.created_at > current.created_at)) : list.filter(g => g !== head) };
  }).sort((a, b) => a.name.localeCompare(b.name));
}

/* Remove a gold: the red trash can everywhere. A gold with linked clones cannot go - PVE keeps
   a template while a clone uses its disk (a differencing disk's parent on Hyper-V) - so the
   can is greyed and says why. */
function goldRemoveBtn(x) {
  if (x.status === "baking") return "";
  return x.used_by
    ? `<button class="btn icon sm" type="button" disabled title="${x.used_by} VM(s) are linked clones of this gold - PVE keeps a template while a clone uses its disk. Remove those VMs first." aria-label="Remove - blocked by linked clones">${trashIcon()}</button>`
    : `<button class="btn icon sm danger-text" type="button" data-gold-remove="${esc(x.id)}" title="Remove this gold" aria-label="Remove this gold">${trashIcon()}</button>`;
}
/* The build as it reads best: Windows splits off the cumulative update's revision - the
   number that changes every month - and sets it bold; anything else shows as it is. */
function goldBuildHtml(g, build) {
  const i = build.lastIndexOf(".");
  return g.os === "windows" && i > 0
    ? `<span class="gold-build"><span class="base">${esc(build.slice(0, i + 1))}</span>${esc(build.slice(i + 1))}</span>`
    : `<span class="gold-build">${esc(build)}</span>`;
}
const ACTIVATION = { "kms-client": "KMS client key (GVLK)", retail: "Retail key", mak: "MAK", none: "None" };
const BAKE_OPTION = { rdp: "Remote Desktop", ping: "Answers ping", suppressServerManagerAtLogon: "No Server Manager at sign-in",
  blockSignInInputMethods: "STIG sign-in keyboard", suppressWelcomeExperience: "No welcome experience", suppressFirstSignInAnimation: "No first sign-in animation",
  edgeBaseline: "Edge baseline", preferIPv4: "Prefer IPv4", preventDeviceEncryption: "No auto device encryption", vmPowerPlan: "VM power plan" };
const shortHash = h => h ? `${h.slice(0, 8)}…${h.slice(-4)}` : "";
function goldKv(rows) {
  return `<dl class="gold-kv">${rows.filter(r => r && r[1] !== undefined && r[1] !== "").map(([k, v, raw]) =>
    `<dt>${esc(k)}</dt><dd>${raw ? v : esc(v)}</dd>`).join("")}</dl>`;
}
function goldHash(h) { return h ? `<span class="mono">${esc(shortHash(h))}</span> <button class="gold-copy" type="button" data-copy="${esc(h)}">Copy</button>` : ""; }
/* The sidecar in words, three columns: what is inside, region and options, provenance.
   The JSON itself stays one click further down. */
function goldDetailHtml(g) {
  const m = goldManifest(g), win = g.os === "windows";
  const utc = iso => iso ? String(iso).replace("T", " ").slice(0, 16) + " UTC" : "";
  const baked = m.createdUtc && g.created_at ? Math.max(0, Math.round((new Date(m.createdUtc) - new Date(g.created_at)) / 1000)) : null;
  const inside = win ? [
    ["Edition", m.editionId], ["Experience", m.installationType === "Server Core" ? "Server Core" : m.installationType === "Server" ? "Desktop Experience" : m.installationType],
    ["Build", m.build], ["Language", m.language || m.imageLanguage], ["Activation", ACTIVATION[m.activation] || m.activation || (m.key === "gvlk" ? ACTIVATION["kms-client"] : "")],
    ["Evaluation", m.evaluation === undefined ? "" : m.evaluation ? "Yes - 180 days" : "No"], ["Generalized", m.generalized === undefined ? "" : m.generalized ? "Yes" : "No - VMs share its SID"],
    ["Firmware", "OVMF (UEFI) · q35"], ["Secure Boot", "On · Microsoft keys enrolled"],
    ["vTPM", m.requiresTpm === undefined ? "" : m.requiresTpm ? "Required" : "Not required"], ["System disk", m.diskSizeGB ? `${m.diskSizeGB} GB` : ""], ["virtio-win", m.virtio],
  ] : [
    ["Distribution", m.name], ["Version", m.distroVersion], ["Kernel", m.kernel], ["Updates", (m.updatesApplied ?? m.updates) ? "Applied at bake" : "Not applied"],
    ["Packages", m.missingPackages ? (m.missingPackages.length ? "Missing: " + m.missingPackages.join(", ") : "All installed") : ""],
    ["Secure Boot", m.secureBoot === undefined ? "" : m.secureBoot ? "On" : "Off"],
  ];
  const rg = m.region || {};
  const region = win
    ? [["Format", m.locale], ["Keyboard", m.keyboardLayout ? m.keyboardLayout + (m.inputLocale ? ` (${m.inputLocale})` : "") : ""], ["Time zone", m.timeZone]]
    : [["Language", rg.language], ["Format", rg.format], ["Keyboard", rg.keyboard], ["Time zone", rg.timezone],
      ["Package mirror", m.aptMirror ? m.aptMirror.split("/")[2] : ""]];
  const options = win
    ? (m.bakeOptions ? Object.entries(m.bakeOptions).map(([k, v]) => [BAKE_OPTION[k] || k, v]) : (m.policies || []).map(p => [p, true]))
    : (m.features || []).map(f => [f, true]);
  const src = m.sourceMedia || m.sourceIso || m.sourceUrl || "";
  const prov = [
    ["Source", win ? `${src.replace(/^[^:]+:iso\//, "")}${m.imageIndex ? `, image ${m.imageIndex}` : ""}` : src.split("/").slice(2, 3).concat(src.split("/").slice(-1)).join(" · ")],
    ["Source SHA-256", goldHash(m.sourceMediaSha256 || m.sourceChecksum), true], ["Bake script", goldHash(m.scriptSha256), true],
    ["Baked on", [m.bakeHost || g.node, utc(m.createdUtc || g.created_at)].filter(Boolean).join(", ")],
    ["Bake took", baked != null ? fmtSecs(baked) : ""],
  ];
  return `<div class="gold-detail">
    <section class="gold-col"><h4>What's inside</h4>${goldKv(inside)}</section>
    <section class="gold-col"><h4>Region and options</h4>${goldKv(region)}
      ${options.length ? `<div class="gold-tags ov-ticks">${options.map(([k, v]) => `<span class="${v ? "on" : ""}" title="${v ? "Baked in" : "Not baked in"}">${esc(k)}</span>`).join("")}</div>` : ""}</section>
    <section class="gold-col"><h4>Provenance</h4>${goldKv(prov)}</section>
    <details class="gold-raw"><summary>Raw sidecar (JSON)</summary><pre class="gold-sidecar code-block">${highlightJson(JSON.stringify(m, null, 2))}</pre>
      <button class="btn sm" type="button" data-copy="${esc(JSON.stringify(m, null, 2))}"><img src="${iconSrc("code.svg")}" alt=""> Copy JSON</button></details>
  </div>`;
}

/* One card per kind of gold, collapsible like every other card: who it is, its build, the
   facts that tell it apart, what it is used by, and its actions; the sidecar opens under it. */
/* Where this bake runs: node and network as chips at the foot of the bake form. A click opens a
   small picker in place; what is picked holds for this bake only - Image settings' "Build environment"
   keeps the defaults (the chip shows them until something else is picked). */
function bakePlaceChips(r, s) {
  const node = bakeForm.node || r.node || "";
  const bridge = bakeForm.bridge || r.bridge || "";
  const vlan = bakeForm.bridge ? bakeForm.vlan : (s && s.vlan);
  const inv = cluster.inventory || { nodes: [], vnets: [] };
  const nodes = inv.nodes.filter(n => n.status === "online").map(n => [n.node, n.node]);
  const bridges = (inv.nodes.find(n => n.node === node)?.bridges || []).map(b => [b.iface, b.iface]).concat((inv.vnets || []).map(v => [v.vnet, v.vnet + " (SDN)"]));
  const addr = bakeForm.addresses || (s && s.linux_address) || "";
  const gw = bakeForm.addresses ? bakeForm.gateway : (s && s.linux_gateway) || "";
  const dns = bakeForm.addresses ? bakeForm.dns : ((s && s.linux_dns) || []).join(", ");
  const changed = !!(bakeForm.node || bakeForm.bridge || bakeForm.addresses);
  const chip = (k, icon, label, value) => `<button type="button" class="chip-btn${goldsUi.placeOpen ? " on" : ""}" data-bake-place="${k}" aria-expanded="${goldsUi.placeOpen}">
    <img src="${iconSrc(icon)}" alt=""><span class="k">${label}</span><b>${esc(value || "?")}</b></button>`;
  return `<div class="bake-place">
    ${chip("node", "servers.svg", "Node", node)}${chip("net", "vnet.svg", "Network", bridge + (vlan ? " · VLAN " + vlan : ""))}${chip("addr", "static-ip.svg", "Address", addr && addr.toLowerCase() !== "dhcp" ? addr : "DHCP")}
    ${changed ? `<span class="pill" title="Media's defaults: ${esc(r.node)} · ${esc(r.bridge)}">this bake only</span>` : ""}
    ${goldsUi.placeOpen ? `<div class="bake-place-pop" role="dialog" aria-label="Where this bake runs">
      ${field(fieldLabel("servers.svg", "Node"), `<select id="bpNode">${opts(nodes, node)}</select>`)}
      ${field(fieldLabel("vnet.svg", "Network"), `<select id="bpBridge">${opts(bridges, bridge)}</select>`)}
      ${field(fieldLabel("vlan.svg", "VLAN"), `<input id="bpVlan" type="number" min="1" max="4094" placeholder="none" value="${vlan ?? ""}">`)}
      ${field(`<span class="field-label"><img src="${iconSrc("static-ip.svg")}" alt="">Linux addresses${infoTip("Linux addresses", "For this bake: DHCP (type dhcp), one address (10.10.0.60/24) or a range (10.10.0.60-69/24) - the bake takes the first one no running bake holds. Empty keeps Media's.")}</span>`,
        `<input id="bpAddr" placeholder="${esc((s && s.linux_address) || "DHCP")}" value="${esc(bakeForm.addresses || "")}">`)}
      ${field(fieldLabel("vnet.svg", "Gateway"), `<input id="bpGw" placeholder="${esc((s && s.linux_gateway) || "10.10.0.1")}" value="${esc(bakeForm.addresses ? bakeForm.gateway : "")}">`)}
      ${field(fieldLabel("dns.svg", "DNS"), `<input id="bpDns" placeholder="${esc(((s && s.linux_dns) || []).join(", ") || "10.10.0.1")}" value="${esc(bakeForm.addresses ? bakeForm.dns : "")}">`)}
      <div class="bake-place-acts">${changed ? `<button class="btn sm" type="button" id="bpReset">Media's defaults</button>` : ""}<button class="btn sm primary" type="button" id="bpDone">Done</button></div>
    </div>` : ""}</div>`;
}

function wireBakePlace(main) {
  const again = () => renderServerBlade("golds", main);
  main.querySelectorAll("[data-bake-place]").forEach(b => b.addEventListener("click", () => { goldsUi.placeOpen = !goldsUi.placeOpen; again(); }));
  const n = $id("bpNode"), br = $id("bpBridge"), v = $id("bpVlan");
  // Another node: its bridges and storages are other ones - the bridge goes back to the default.
  if (n) n.addEventListener("change", () => { bakeForm.node = n.value; bakeForm.bridge = ""; bakeForm.vlan = null; bakeForm.storage = ""; again(); });
  if (br) br.addEventListener("change", () => { bakeForm.bridge = br.value; again(); });
  if (v) v.addEventListener("change", () => { const x = parseInt(v.value, 10); bakeForm.vlan = Number.isFinite(x) ? x : null; if (!bakeForm.bridge && br) bakeForm.bridge = br.value; });
  // Addresses, gateway and DNS go together: typed in here, they are this bake's.
  const ad = $id("bpAddr"), g = $id("bpGw"), d = $id("bpDns");
  const net = () => { bakeForm.addresses = ad.value.trim(); bakeForm.gateway = g.value.trim(); bakeForm.dns = d.value.trim(); };
  [ad, g, d].forEach(el => { if (el) el.addEventListener("change", net); });
  const reset = $id("bpReset"); if (reset) reset.addEventListener("click", () => { Object.assign(bakeForm, { node: "", bridge: "", vlan: null, storage: "", addresses: "", gateway: "", dns: "" }); again(); });
  const done = $id("bpDone"); if (done) done.addEventListener("click", () => { if (ad) net(); goldsUi.placeOpen = false; again(); });
}

/* Keep current on a Windows gold's card: it follows its ISO's product (Image settings → Windows updates). */
function keepCurrentToggle(g) {
  const k = goldsUi.au && goldsUi.au.golds && goldsUi.au.golds[g.id];
  if (!k || g.os !== "windows" || g.status !== "ready") return "";
  const tip = k.can ? `Follows ${k.product}, on ${k.build} now: every newer Patch Tuesday build gives a new ISO and a new gold, baked with this gold's settings in a maintenance window.` : k.why;
  return toggle(`data-keep-current="${esc(g.id)}"`, `Keep current${infoTip("Keep current", tip)}`, !!k.on, !k.can && !k.on, "", "gold-keep");
}

function goldRowHtml(t) {
  const g = t.head, m = goldManifest(g), img = findImage(g.image_id);
  const tone = { ready: "ok", baking: "run", failed: "bad" }[g.status] || "idle";
  const picked = g.picked_by || [];
  const after = t.newer.filter(x => x.status === "baking" || x.status === "failed")[0];
  const oldOpen = isNestedOpen("gold-old-" + t.key, false);
  const known = img && img.id === g.image_id;
  // The studio's own name, "Windows Server 2025 Datacenter Core" - not DISM's "ServerDatacenterCore".
  const full = known ? img.label : m.editionUpgrade ? (m.displayName || t.name) : t.name;
  const win = g.os === "windows";
  const exp = win ? (m.installationType === "Server Core" ? "Server Core" : m.installationType === "Server" ? "Desktop Experience" : "") : (m.name || "").replace(/^[^(]*\(?|\)$/g, "");
  // "Windows 11 Enterprise 26H2": the release beside the name, the build big on the right.
  const rel = goldRelease(g);
  const title = full + (rel && !full.includes(rel) ? " " + rel : "");
  const sub = [m.editionUpgrade ? "virtual edition from " + (m.sourceEdition || "") : /\s(Desktop|Core)(:|$)/.test(full) ? "" : exp].filter(Boolean).join(" · ");
  const build = goldBuildNumber(g);
  const facts = win
    ? [["Language", goldLang(g) || m.imageLanguage], ["Disk", m.diskSizeGB ? m.diskSizeGB + " GB" : ""]]
    : [["Language", (m.region || {}).language], ["Kernel", m.kernel ? m.kernel.replace(/-generic$/, "") : ""], ["Updates", (m.updatesApplied ?? m.updates) ? "applied" : ""]];
  const flags = [m.evaluation ? `<span class="gold-flag warn" title="180 days, no KMS activation">evaluation</span>` : "",
    m.generalized === false ? `<span class="gold-flag warn" title="VMs from it share its SID">not generalized</span>` : "",
    m.requiresTpm ? `<span class="gold-flag" title="VMs from it get a vTPM">TPM</span>` : "",
    m.cis ? `<button type="button" class="gold-flag ${m.cis.fail || m.cis.error ? "warn" : "ok"}" data-cis-report="${esc(g.id)}" title="${esc(m.cis.benchmark + " v" + m.cis.version)} - self-assessed. Open the report">CIS L${m.cis.level} · ${m.cis.score}%</button>` : "",
    g.old_secure_boot_certs ? `<span class="gold-flag warn" title="Its EFI disk holds only Microsoft's 2011 Secure Boot certificates, which expired in June 2026 - rebake it (new EFI disks carry the 2023 set)">2011 certs</span>` : ""].join("");
  const key = "gold-" + g.id, open = gs(key, false);
  const rebake = after ? `<button type="button" class="gold-flag ${after.status === "failed" ? "bad" : "run"}" ${after.job_id ? `data-job-open="${esc(after.job_id)}"` : ""}
    title="${esc(when(after.created_at))} - open its log">${after.status === "baking" ? "rebake running" : "rebake failed"}</button>` : "";
  return `<div class="card collapsible gold-card ${open ? "" : "collapsed"}">
    <div class="card-head" data-toggle="${esc(key)}">
      <div class="card-lead">
        <span class="card-chevron">${chevron()}</span>
        <div class="card-icon"><img src="${imageIconSrc(img)}" alt=""></div>
        <div class="gold-id">
          <div class="card-title">${esc(title)}${titleBadges(`<span class="pill status ${tone}">${esc(cap(g.status))}</span>`)}</div>
          <div class="gold-sub">${esc(sub)}${sub ? '<span class="gold-sep">·</span>' : ""}${goldsUi.labelEdit === g.id
            ? `<input class="gold-label-input" id="goldLabelInput" maxlength="80" value="${esc(m.label || "")}" placeholder="What this gold is for"><button class="btn icon sm" type="button" data-label-save="${esc(g.id)}" title="Save the label" aria-label="Save the label">${checkIcon()}</button>`
            : `<button type="button" class="gold-label ${m.label ? "" : "empty"}" data-label-edit="${esc(g.id)}" title="Set the label">${esc(m.label || "Add a label")}${pencilIcon()}</button>`}</div>
        </div>
      </div>
      <div class="gold-buildcol">${build ? goldBuildHtml(g, build) : ""}
        <div class="gold-when">baked ${esc(goldAge(g.created_at))} · <span class="mono" title="Gold id - template ${esc(g.name)}${g.vmid != null ? " (" + esc(g.vmid) + ")" : ""} on ${esc(g.node)} · ${esc(g.storage)}">${esc(goldShortId(g))}</span></div></div>
      <div class="gold-facts">
        <div>${facts.filter(f => f[1]).map(([k, v]) => `<span>${esc(k)} <b>${esc(v)}</b></span>`).join("")}${flags}${rebake}</div>
        <div class="gold-usage" title="${picked.length ? esc(picked.join(", ")) : "No designed VM builds from it"}"><b>${goldBuilt(g)}</b> built · <b>${picked.length}</b> picked</div>
      </div>
      <div class="card-actions gold-acts">
        ${keepCurrentToggle(g)}
        ${g.job_id ? `<button class="btn sm" type="button" data-job-open="${esc(g.job_id)}" title="Bake log"><img src="${iconSrc("log.svg")}" alt=""> Log</button>` : ""}
        ${g.status !== "baking" ? `<button class="btn sm" type="button" data-rebake="${esc(g.id)}"><img src="${iconSrc("update.svg")}" alt=""> Rebake</button>` : ""}
        ${goldRemoveBtn(g)}
      </div>
    </div>
    <div class="card-body">
      ${after ? `<div class="gold-after ${after.status}">${after.status === "baking" ? "A rebake is running" : "The last rebake failed"} · ${esc(when(after.created_at))}
        ${after.job_id ? `<button class="btn sm" type="button" data-job-open="${esc(after.job_id)}"><img src="${iconSrc("log.svg")}" alt=""> Log</button>` : ""}${after.status === "failed" ? goldRemoveBtn(after) : ""}</div>` : ""}
      ${open ? goldDetailHtml(g) : ""}
      ${t.older.length ? `<div class="section collapsible ${oldOpen ? "" : "collapsed"} gold-older">
        <div class="section-head" data-nested="gold-old-${esc(t.key)}"><span class="section-chevron">${chevron()}</span>${t.older.length} older<span class="section-meta">${t.older.filter(x => !x.used_by).length} not a parent</span></div>
        <div class="section-body"><table class="data"><tbody>${t.older.map(x => `<tr><td class="mono">${esc(goldShortId(x))}</td><td class="mono">${esc(goldBuildLabel(x))}</td><td class="muted">${esc(goldAge(x.created_at))}</td>
          <td>${jobPill(x.status === "ready" ? "succeeded" : x.status)}</td><td class="muted">${x.used_by ? x.used_by + " linked clone" + (x.used_by === 1 ? "" : "s") : ""}</td>
          <td class="row-actions">${x.job_id ? `<button class="btn sm" type="button" data-job-open="${esc(x.job_id)}"><img src="${iconSrc("log.svg")}" alt=""> Log</button>` : ""}${goldRemoveBtn(x)}</td></tr>`).join("")}</tbody></table></div>
      </div>` : ""}
    </div>
  </div>`;
}

/* New-Vhdx's -VhdType (Fixed / Dynamic). On PVE thin or thick is the storage's property,
   never the disk's, so the switch picks a storage of that kind on the bake node - and says
   so when the node has none. */
function diskField(prefix, value, min, storages, chosen) {
  const kinds = { thin: storages.filter(x => x.provisioning === "thin"), thick: storages.filter(x => x.provisioning === "thick") };
  const current = storages.find(x => x.storage === chosen) || storages[0];
  const kind = current ? current.provisioning : "thin";
  const label = st => `${st.storage} (${st.type}${st.shared ? ", shared" : ""}) · ${gib(st.free)} GiB free`;
  const seg = ["thin", "thick"].map(k => `<button type="button" class="btn${kind === k ? " on" : ""}" data-prov="${k}" data-prov-form="${prefix}"
      ${kinds[k].length ? "" : `disabled title="No ${k} storage holds VM disks on this node"`}>${k === "thin" ? "Thin" : "Thick"}</button>`).join("");
  const why = !kinds.thick.length
    ? "No thick storage on this node - an LVM storage, or a directory storage with preallocation full, with the Disk image content (Datacenter → Storage) adds one."
    : !kinds.thin.length ? "No thin storage on this node." : "";
  return `
    ${field(fieldLabel("disk.svg", "System disk (GiB)"), `<input id="${prefix}Disk" type="number" min="${min}" max="2048" step="1" value="${esc(value)}">
      <span class="hint">VMs can grow it, never shrink it.</span>`)}
    <div class="field-like">${fieldLabel("storage.svg", "Provisioning")}
      <div class="prov-row"><div class="ov-seg" role="group" aria-label="Provisioning">${seg}</div>
        ${kinds[kind].length > 1 ? `<select id="${prefix}Storage">${opts(kinds[kind].map(st => [st.storage, label(st)]), current && current.storage)}</select>`
          : `<span class="prov-store">${current ? esc(label(current)) : "no storage"}</span><input type="hidden" id="${prefix}Storage" value="${esc(current ? current.storage : "")}">`}</div>
      <span class="hint">${esc(why || (kind === "thin" ? "Allocated as it is written - New-Vhdx's Dynamic." : "Allocated in full up front - New-Vhdx's Fixed."))}</span>
    </div>`;
}
function wireProvisioning(root, form, storages, rerender) {
  root.querySelectorAll(`[data-prov-form]`).forEach(b => b.addEventListener("click", () => {
    const st = storages.find(x => x.provisioning === b.dataset.prov);
    if (st) { form.storage = st.storage; rerender(); }
  }));
}

/* Features on Demand media (Build-Vms' FoD ISO): a Languages and Optional Features ISO per
   release. The WinPE deploy pass installs RSAT and the Server Core App Compatibility pack
   from it straight into a new VM's disk - no Windows Update, no internet. Each slot can be
   built from Microsoft's own update packages (every FoD but the language ones). */
const ISO_KIND_TAG = { winpe: "WinPE", fod: "Features on Demand" };
const FOD_SLOTS = [
  ["server", "ws2025-datacenter-desktop", "Windows Server 2025", "Build 26100."],
  ["server2022", "ws2022-datacenter-desktop", "Windows Server 2022", "Build 20348."],
  ["client", "w11-pro", "Windows 11", "Build 26100 - one set serves 24H2, 25H2 and 26H2."]
];
function fodCard(fod, isos, lang) {
  const s = fod.settings || {}, media = fod.media || {};
  const list = (isos.isos || []).filter(i => i.readable && i.kind !== "winpe");
  const state = key => {
    const m = media[key];
    if (!s[key]) return `<span class="pill status idle">Windows Update</span>`;
    if (!m || !m.ok) return `<span class="pill status bad" title="${esc((m && m.error) || "The studio cannot read this ISO")}">Unreadable</span>`;
    return `<span class="pill status ok">${m.media.fod_packages} packages</span>`;
  };
  const set = FOD_SLOTS.filter(([k]) => s[k]).length;
  return gsCard("md-fod", "fod.svg", "Features on Demand", `${set} of ${FOD_SLOTS.length} set`, `
    <div class="grid-3" style="align-items:start">${FOD_SLOTS.map(([key, imageId, label, tip]) => `<div class="field-like fod-slot">
      <span class="field-label"><img src="${imageIconSrc(findImage(imageId))}" alt="">${esc(label)}${infoTip(label,
        `${tip} Build from Microsoft puts every Feature on Demand of the newest build on one ISO - App Compatibility, RSAT, OpenSSH, .NET 3.5 and the rest - with their ${lang} parts, without language features. None installs from Windows Update at first boot.`)}</span>
      <select data-fod-slot="${key}">${opts(list.map(i => [i.volid, i.file]), s[key], "None")}</select>
      <div class="fod-slot-foot">${state(key)}<button class="btn sm" type="button" data-fod-build="${key}"><img src="${iconSrc("download.svg")}" alt=""> Build from Microsoft</button></div>
    </div>`).join("")}</div>
    ${actions(act("fodSave", "save.svg", "Save", true))}`, "", true);
}

/* Clean up golds (Build-Vms): every gold judged - the newest of its kind stays, an older
   one of the same kind is suggested, a failed bake's leftover row is suggested, a gold
   any VM was cloned from is locked. Nothing goes before Remove is pressed. */
function goldInventory(golds) {
  const newest = new Map();
  golds.filter(g => g.status === "ready").forEach(g => { const k = goldKind(g); if (!newest.has(k) || compareGolds(g, newest.get(k)) < 0) newest.set(k, g); });
  return golds.filter(g => g.status !== "baking").map(g => {
    const kind = g.status !== "ready" ? "leftover" : newest.get(goldKind(g)) === g ? "newest" : "older";
    const locked = g.used_by ? `${g.used_by} linked clone${g.used_by === 1 ? "" : "s"}` : "";
    return { g, kind, locked, suggested: (kind === "older" || kind === "leftover") && !locked };
  }).sort((a, b) => ({ newest: 0, older: 1, leftover: 2 }[a.kind] - { newest: 0, older: 1, leftover: 2 }[b.kind]) || a.g.image_id.localeCompare(b.g.image_id) || compareGolds(a.g, b.g));
}

function cleanupPanel(golds) {
  const inv = goldInventory(golds);
  if (!goldsUi.cleanupPick) goldsUi.cleanupPick = new Set(inv.filter(e => e.suggested).map(e => e.g.id));
  const pick = goldsUi.cleanupPick;
  const picked = inv.filter(e => pick.has(e.g.id) && !e.locked);
  return `<div class="card bake-panel">
    <div class="bake-head"><div class="card-title"><img src="${iconSrcDanger("trash.svg")}" alt=""> Clean up golds</div>
      <button class="btn icon close-x" type="button" id="cleanupClose" title="Close" aria-label="Close">${chipRemoveIcon()}</button></div>
    <p class="hint bake-lead">Pre-ticked: older golds of the same kind (image, language, disk size) and the rows failed bakes left. Golds with linked clones are locked - a linked clone needs its gold; full copies do not.</p>
    <div class="table-wrap"><table class="data"><thead><tr><th></th><th>Gold</th><th>Image</th><th>Language · build · disk · age</th><th>Kind</th><th>Picked by</th><th></th></tr></thead><tbody>
    ${inv.map(e => `<tr class="${e.locked ? "muted-row" : ""}"><td>${toggle(`data-cleanup="${esc(e.g.id)}" aria-label="Remove ${esc(goldShortId(e.g))}"`, "", pick.has(e.g.id) && !e.locked, !!e.locked, "", "bare")}</td>
      <td class="mono">${esc(goldShortId(e.g))}</td><td>${esc(findImage(e.g.image_id).label)}</td><td class="muted">${esc(goldMetaLine(e.g))}</td>
      <td>${e.kind === "newest" ? '<span class="pill status ok">Newest</span>' : e.kind === "older" ? '<span class="pill">older</span>' : `<span class="pill status bad">${esc(cap(e.g.status))}</span>`}</td>
      <td class="muted">${esc((e.g.picked_by || []).join(", "))}</td><td class="muted">${esc(e.locked)}</td></tr>`).join("")}
    </tbody></table></div>
    ${actions(`<span class="hint gs-actions-note">${picked.length} of ${inv.length} ticked</span>`,
      `<button class="btn" type="button" id="cleanupGo" ${picked.length ? "" : "disabled"}><img src="${iconSrcDanger("trash.svg")}" alt=""> Remove ${picked.length} gold${picked.length === 1 ? "" : "s"}</button>`)}
  </div>`;
}

/* VMs the studio built from a gold that are on the cluster now - full copies and linked
   clones alike (used_by counts linked clones only: those are what lock a gold). */
function goldBuilt(g) { return ((cluster.vms || []).filter(v => v.gold === g.id && v.status === "ready")).length; }
async function bladeGolds(main, stale) {
  const [catalog, golds, bake, au] = await Promise.all([catalogCache || api("GET", "/catalog"), api("GET", "/golds"),
    api("GET", "/settings/bake" + (bakeForm.node ? "?node=" + encodeURIComponent(bakeForm.node) : "")), api("GET", "/auto-update").catch(() => null),
    cluster.inventory ? null : refreshInventory()]);
  if (stale()) return;
  goldsUi.au = au;
  catalogCache = catalog; cluster.golds = golds;
  if (!bakeForm.language) {
    bakeForm.language = catalog.region.language || "en-US"; bakeForm.format = catalog.region.locale || bakeForm.language;
    bakeForm.keyboard = catalog.region.keyboard || bakeForm.language; bakeForm.timezone = catalog.region.timeZone || Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC";
  }
  const img = catalog.linux.find(i => i.id === bakeForm.image) || catalog.linux[0];
  const feats = catalog.features.filter(f => !f.images.length || f.images.includes(img.id));
  // CIS: only where the studio has the image's benchmark.
  const cisBench = (catalog.cis || {})[img.id] || null;
  const cisLevel = cisBench ? bakeForm.cis : 0;
  const locales = Object.entries(catalog.locales).sort((a, b) => a[1].localeCompare(b[1]));
  // Ubuntu and Debian: the country package mirror (New-Vhdx's mirror menu). It opens on the
  // country of the studio's region preselection when that country has one.
  const aptDistro = img.family === "debian" ? img.distro : "";
  const mirrors = aptDistro ? (catalog.mirrors || []).filter(m => m[aptDistro]) : [];
  if (bakeForm.mirror == null) {
    const cc = String(catalog.region.locale || catalog.region.language || "").split("-").pop().toLowerCase();
    bakeForm.mirror = (catalog.mirrors || []).some(m => m.code === (cc === "uk" ? "gb" : cc)) ? (cc === "uk" ? "gb" : cc) : "";
  }
  const mirrorPick = mirrors.some(m => m.code === bakeForm.mirror) ? bakeForm.mirror : "";
  const r = bake.resolved || {};
  const ready = golds.filter(g => g.status === "ready");
  const tiles = goldTiles(golds, catalog);
  const section = (os, label) => {
    const list = tiles.filter(t => t.os === os);
    return list.length ? `<div class="field-group">${label} <span class="hint">${list.length}</span></div>${list.map(goldRowHtml).join("")}` : "";
  };

  const linuxForm = `
      <div class="grid-2">
        ${field(fieldLabel("iso-media.svg", "Image"), `<select id="bkImage">${opts(catalog.linux.map(i => [i.id, i.name]), img.id)}</select>
          <span class="hint">${esc(img.url.split("/").pop())} · Secure Boot ${img.secure_boot ? "on" : "off"}</span>`)}
        ${aptDistro ? field(`<span class="field-label"><img src="${iconSrc("download.svg")}" alt="">Package mirror${infoTip("Package mirror", "Where apt takes packages from - in the bake and on every VM from this gold. The image's own default is archive.ubuntu.com or deb.debian.org; a country mirror is usually faster. Security updates keep coming from the distribution's own security host. Only countries with a mirror for this distribution are listed.")}</span>`,
          cisLevel ? `<select id="bkMirror" disabled title="Country mirrors serve http only; CIS needs https sources">${opts([["", "Default (https) - CIS needs https sources"]], "")}</select>`
          : `<select id="bkMirror">${opts([["", "Default (the image's own)"]].concat(mirrors.map(m => [m.code, `${m.name} - ${m[aptDistro]}`])), mirrorPick)}</select>`) : ""}
      </div>
      <div class="grid-2 disk-row">${diskField("bk", Math.max(bakeForm.disk || img.disk_gb, img.disk_gb, cisLevel === 2 ? 40 : 0), Math.max(img.disk_gb, cisLevel === 2 ? 40 : 0), bake.disk_storages || [], bakeForm.storage || r.disk_storage)}</div>
      <div class="field-group">Baked in</div>
      <div class="toggle-grid">${toggle('id="bkUpdates"', `Install updates${infoTip("Install updates", "Every package upgraded to the newest version during the bake, so the gold - and every VM cloned from it - starts current.")}`, bakeForm.updates)}
        ${feats.map(f => toggle(`id="bkF_${esc(f.id)}"`, `${esc(f.label)}${f.tip ? infoTip(f.label, f.tip) : ""}`, bakeForm.features.includes(f.id))).join("")}</div>
      ${cisBench ? `<div class="field-group">Hardening</div>
      <div class="field-like">${`<span class="field-label"><img src="${iconSrc("security.svg")}" alt="">CIS benchmark${infoTip(cisBench.name + " v" + cisBench.version,
        "Level 1 and Level 2 Server, applied in the bake and checked after a reboot - the score and every rule's evidence stay with the gold. Level 2 adds the audit rules, an outbound firewall (DNS, NTP, HTTP/S, DHCP only), its own volumes for /home, /var, /var/tmp, /var/log and /var/log/audit (40 GB disk at least), and turns off squashfs and overlay: no snaps, no containers. Self-assessed - not a CIS certification.")}</span>`}
        <div class="cis-level-row"><div class="ov-seg" role="group" aria-label="CIS level">${[[0, "Off"], [1, "Level 1 Server"], [2, "Level 2 Server"]].map(([n, l]) =>
          `<button type="button" class="btn${cisLevel === n ? " on" : ""}" data-cis="${n}">${l}</button>`).join("")}</div>
          <button type="button" class="btn cis-rules-btn" data-cis-rules="${esc(img.id)}" data-cis-level="${cisLevel || 2}" title="The rules of ${esc(cisBench.name + " v" + cisBench.version)}" aria-label="Policy Catalog"><img src="${iconSrc("cis-rules.svg")}" alt=""> Policy Catalog</button></div></div>` : ""}
      <div class="field-group">Region</div>
      <div class="toggle-grid">${stoggle("bkRegion", "Set the region", bakeForm.region)}</div>
      <div class="grid-2" id="bkRegionFields" style="margin-top:12px" ${bakeForm.region ? "" : "hidden"}>
        ${field(fieldLabel("language.svg", "Language"), `<select id="bkLang">${opts(locales, bakeForm.language)}</select>`)}
        ${field(fieldLabel("language.svg", "Formats"), `<select id="bkFormat">${opts(locales, bakeForm.format)}</select>`)}
        ${field(fieldLabel("language.svg", "Keyboard"), `<select id="bkKeyboard">${opts(locales, bakeForm.keyboard)}</select>`)}
        ${field(fieldLabel("language.svg", "Time zone"), `<select id="bkTz">${opts(catalog.timezones.map(z => [z.id, z.id]), bakeForm.timezone)}</select>`)}
      </div>
      <p class="hint" id="bkRegionOff" ${bakeForm.region ? "hidden" : ""}>Off: the image keeps its own - usually en_US, UTC and a US keyboard.</p>
      ${actions(bake.problem ? `<span class="hint err gs-actions-note">${esc(bake.problem)}</span>` : bakePlaceChips(r, bake.settings),
        act("bkStart", "gold-image.svg", "Bake", true))}`;

  const bakePanel = !goldsUi.bake ? "" : `<div class="card bake-panel">
      <div class="bake-head">
        <div class="card-title"><img src="${iconSrc("gold-image.svg")}" alt=""> Bake a gold</div>
        <div class="ov-seg" role="group" aria-label="Operating system">
          <button class="btn${goldsUi.os === "linux" ? " on" : ""}" type="button" data-bake-os="linux">Linux</button><button class="btn${goldsUi.os === "windows" ? " on" : ""}" type="button" data-bake-os="windows">Windows</button>
        </div>
        <button class="btn icon close-x" type="button" id="bakeClose" title="Close" aria-label="Close">${chipRemoveIcon()}</button>
      </div>
      <p class="hint bake-lead">${goldsUi.os === "linux"
        ? "Proxmox VE downloads the cloud image and checks its checksum; the studio bakes updates, packages, region and features into it and seals it."
        : "New-Vhdx's pipeline: WinPE applies the image, audit mode installs virtio and the guest agent, sysprep generalizes, WinPE sets region, policies and the key."}</p>
      ${goldsUi.os === "linux" ? linuxForm : `<div id="winBakeBody"><p class="hint">Reading the ISOs…</p></div>`}
    </div>`;

  main.innerHTML = bladeHead("golds", `${goldsUi.cleanup || !golds.length ? "" : `<button class="btn" type="button" id="cleanupOpen"><img src="${iconSrcDanger("trash.svg")}" alt=""> Clean up</button>`}
    ${goldsUi.bake ? "" : `<button class="btn primary" type="button" id="bakeOpen"><img src="${iconSrcOnAccent("gold-image.svg")}" alt=""> Bake a gold</button>`}`) + `
    <div class="chips"><span class="pill">Ready: ${ready.length}</span><span class="pill">Windows: ${ready.filter(g => g.os === "windows").length}</span>
      <span class="pill">Linux: ${ready.filter(g => g.os === "linux").length}</span>
      <span class="pill status ${golds.some(g => g.status === "baking") ? "run" : "idle"}">Baking: ${golds.filter(g => g.status === "baking").length}</span>
      <span class="pill">VMs built from golds: ${golds.reduce((n, g) => n + goldBuilt(g), 0)}</span></div>
    ${goldsUi.cleanup ? cleanupPanel(golds) : ""}
    ${bakePanel}
    ${tiles.length ? section("windows", "Windows") + section("linux", "Linux")
      : `<div class="empty-state"><div class="ue-icon"><img src="${iconSrc("gold-image.svg")}" alt=""></div><h3>No golds yet</h3>
        <p>A gold is baked once per image and every VM starts from it. Linux can bake right away; Windows needs WinPE (Media) first.</p>
        <div class="ue-actions"><button class="btn primary" type="button" data-bake-open="linux">Bake a Linux gold</button><button class="btn" type="button" data-bake-open="windows">Bake a Windows gold</button></div></div>`}
`;

  const on = (id, ev, fn) => { const el = $id(id); if (el) el.addEventListener(ev, fn); };
  on("bakeOpen", "click", () => openBake(goldsUi.os));
  on("bakeClose", "click", () => { goldsUi.bake = false; render(); });
  main.querySelectorAll("[data-bake-os]").forEach(b => b.addEventListener("click", () => openBake(b.dataset.bakeOs)));
  main.querySelectorAll("[data-bake-open]").forEach(b => b.addEventListener("click", () => openBake(b.dataset.bakeOpen)));
  const rerender = () => renderServerBlade("golds", main);
  main.querySelectorAll("[data-keep-current]").forEach(c => c.addEventListener("change", async () => {
    try { await api("POST", `/golds/${encodeURIComponent(c.dataset.keepCurrent)}/keep-current`, { on: c.checked }); toast(c.checked ? "Keeps current - follows newer builds in a maintenance window" : "Stays on its build"); rerender(); }
    catch (e) { c.checked = !c.checked; toast(e.message, true); }
  }));
  on("cleanupOpen", "click", () => { goldsUi.cleanup = true; goldsUi.cleanupPick = null; rerender(); });
  on("cleanupClose", "click", () => { goldsUi.cleanup = false; rerender(); });
  main.querySelectorAll("[data-cleanup]").forEach(c => c.addEventListener("change", () => {
    if (c.checked) goldsUi.cleanupPick.add(c.dataset.cleanup); else goldsUi.cleanupPick.delete(c.dataset.cleanup);
    rerender();
  }));
  on("cleanupGo", "click", async () => {
    const ids = goldInventory(golds).filter(e => goldsUi.cleanupPick.has(e.g.id) && !e.locked).map(e => e.g.id);
    const sel = golds.filter(g => ids.includes(g.id));
    const copies = (cluster.vms || []).filter(v => ids.includes(v.gold) && !["removed", "cleared"].includes(v.status)).length;
    const moved = sel.reduce((n, g) => n + (g.picked_by || []).length, 0);
    if (!ids.length || !await confirmDelete("gold", `Remove ${ids.length} gold${ids.length === 1 ? "" : "s"}?`, [
      ["del", "Templates deleted in PVE", ids.length],
      ["keep", "VMs built as full copies keep running", copies],
      ["move", "Designed VMs move to the next gold", moved],
    ], "Remove")) return;
    let started = 0;
    for (const id of ids) { try { await api("DELETE", "/golds/" + encodeURIComponent(id)); started++; } catch (e) { toast(e.message, true); } }
    goldsUi.cleanup = false;
    toast(`${started} removal job(s) started`);
    state.blade = "jobs"; render();
  });
  main.querySelectorAll("[data-label-edit]").forEach(b => b.addEventListener("click", () => { goldsUi.labelEdit = b.dataset.labelEdit; rerender(); }));
  main.querySelectorAll(".gold-card [data-copy]").forEach(b => b.addEventListener("click", async () => {
    try { await navigator.clipboard.writeText(b.dataset.copy); toast("Copied"); } catch (e) { toast("Copy failed: " + e.message, true); }
  }));
  const saveLabel = async id => {
    try { await api("PATCH", "/golds/" + encodeURIComponent(id), { label: $id("goldLabelInput").value }); goldsUi.labelEdit = null; rerender(); }
    catch (e) { toast(e.message, true); }
  };
  main.querySelectorAll("[data-label-save]").forEach(b => b.addEventListener("click", () => saveLabel(b.dataset.labelSave)));
  on("goldLabelInput", "keydown", e => { if (e.key === "Enter") saveLabel(goldsUi.labelEdit); if (e.key === "Escape") { goldsUi.labelEdit = null; rerender(); } });
  if ($id("goldLabelInput")) $id("goldLabelInput").focus();
  main.querySelectorAll("[data-rebake]").forEach(b => b.addEventListener("click", () => {
    const g = golds.find(x => x.id === b.dataset.rebake); if (!g) return;
    const m = goldManifest(g);
    if (g.os === "windows") {
      const bo = m.bakeOptions;
      const policies = bo ? [["rdp", "rdp"], ["ping", "ping"], ["blockSignInInputMethods", "signinkeyboard"], ["suppressServerManagerAtLogon", "svrmgr"],
        ["suppressWelcomeExperience", "welcome"], ["suppressFirstSignInAnimation", "firstlogon"], ["edgeBaseline", "edge"], ["preferIPv4", "preferipv4"],
        // A gold from before these two were toggles had both, always.
        ["preventDeviceEncryption", "noencrypt", true], ["vmPowerPlan", "power", true]].filter(([k, , was]) => bo[k] ?? was).map(([, f]) => f) : m.policies;
      const editionKey = { EnterpriseMultiSession: "MultiSession", DatacenterAzureEdition: "AzureEdition", Enterprise: "Enterprise", Education: "Education",
        ProfessionalWorkstation: "ProWorkstation", ProfessionalEducation: "ProEducation", EnterpriseN: "EnterpriseN", EducationN: "EducationN",
        ProfessionalWorkstationN: "ProWorkstationN", ProfessionalEducationN: "ProEducationN" }[m.editionUpgrade] || "";
      Object.assign(winForm, { iso: m.sourceMedia || m.sourceIso || winForm.iso, index: m.imageIndex ?? null, edition: editionKey, disk: m.diskSizeGB || 64, locale: m.locale || winForm.locale,
        keyboard: m.keyboardLayout || winForm.keyboard, timezone: m.timeZone || winForm.timezone, features: policies || winForm.features });
    } else {
      bakeForm.image = g.image_id; bakeForm.disk = m.diskSizeGB || null; bakeForm.updates = !!(m.updatesApplied ?? m.updates); if (m.features) bakeForm.features = m.features;
      bakeForm.cis = (m.cis && m.cis.level) || 0;
      const host = m.aptMirror ? m.aptMirror.split("/")[2] : "";
      bakeForm.mirror = host ? ((catalog.mirrors || []).find(x => x.ubuntu === host || x.debian === host) || {}).code || "" : "";
      const region = m.schema ? (m.language ? { language: m.language, format: m.locale, keyboard: m.keyboardLayout, timezone: m.timeZone } : null) : m.region;
      bakeForm.region = !!region;
      if (region) Object.assign(bakeForm, { language: region.language, format: region.format || region.language, keyboard: region.keyboard || region.language, timezone: region.timezone || bakeForm.timezone });
    }
    openBake(g.os);
  }));
  wireRowActions(main, () => renderServerBlade("golds", main));
  if (!goldsUi.bake) return;
  if (goldsUi.os === "windows") { fillWinBake(catalog, stale); return; }

  const keep = () => {
    const newImage = $id("bkImage").value !== bakeForm.image;
    bakeForm.image = $id("bkImage").value; bakeForm.updates = $id("bkUpdates").checked;
    bakeForm.disk = newImage ? null : (parseInt($id("bkDisk").value, 10) || null);
    bakeForm.storage = ($id("bkStorage") || {}).value || bakeForm.storage;
    bakeForm.features = catalog.features.filter(f => $id("bkF_" + f.id)?.checked).map(f => f.id).concat(bakeForm.features.filter(f => !$id("bkF_" + f)));
    if ($id("bkMirror") && !$id("bkMirror").disabled) bakeForm.mirror = $id("bkMirror").value;
    bakeForm.region = $id("bkRegion").checked;
    bakeForm.language = $id("bkLang").value; bakeForm.format = $id("bkFormat").value; bakeForm.keyboard = $id("bkKeyboard").value; bakeForm.timezone = $id("bkTz").value;
  };
  $id("bkImage").addEventListener("change", () => { keep(); renderServerBlade("golds", main); });
  main.querySelectorAll("[data-cis]").forEach(b => b.addEventListener("click", () => { keep(); bakeForm.cis = Number(b.dataset.cis); renderServerBlade("golds", main); }));
  $id("bkRegion").addEventListener("change", () => {
    $id("bkRegionFields").hidden = !$id("bkRegion").checked; $id("bkRegionOff").hidden = $id("bkRegion").checked;
  });
  wireProvisioning(main, bakeForm, bake.disk_storages || [], () => { keep(); renderServerBlade("golds", main); });
  if ($id("bkStorage") && $id("bkStorage").tagName === "SELECT") $id("bkStorage").addEventListener("change", () => { keep(); });
  wireBakePlace(main);
  $id("bkStart").addEventListener("click", async () => {
    keep();
    try {
      const { id } = await api("POST", "/golds", { image: bakeForm.image, updates: bakeForm.updates, disk_gb: bakeForm.disk || img.disk_gb, disk_storage: bakeForm.storage || null,
        features: bakeForm.features.filter(f => feats.some(x => x.id === f)),
        region: bakeForm.region ? { language: bakeForm.language, format: bakeForm.format, keyboard: bakeForm.keyboard, timezone: bakeForm.timezone } : null,
        cis: cisLevel ? { level: cisLevel, exceptions: [] } : null, mirror: aptDistro && !cisLevel ? ($id("bkMirror") || {}).value || "" : "",
        node: bakeForm.node || null, bridge: bakeForm.bridge || null, vlan: bakeForm.bridge ? bakeForm.vlan : null,
        addresses: bakeForm.addresses || null, gateway: bakeForm.addresses ? bakeForm.gateway || null : null,
        dns: bakeForm.addresses && bakeForm.dns ? bakeForm.dns.split(/[,;\s]+/).filter(Boolean) : null });
      goldsUi.bake = false;
      openJob(id);
    } catch (e) { toast(e.message, true); }
  });
}

/* The policies the selected index can take: Server Manager is a server's, the welcome
   experience and the first sign-in animation a client's. */
/* The policies that reach the picked image: client or server ones, and Edge not on Server Core. */
function winPolicies(info) {
  const img = info.images.find(i => i.index === winForm.index) || info.images[0] || {};
  const kind = img.installation_type === "Client" ? "client" : "server";
  return info.features.filter(f => !f.scope || f.scope === kind || (f.scope === "desktop" && img.installation_type !== "Server Core"));
}

/* An ISO index (or a virtual edition) by the studio's name - "Windows Server 2025 Datacenter
   Core" - not DISM's "Windows Server 2025 ServerDatacenterCore". */
function wiEditionName(imageId, fallback) {
  const img = findImage(imageId);
  return img && img.id === imageId ? img.label : fallback;
}

let winDiskStorage = "", winDiskStorages = [];
async function fillWinBake(catalog, stale) {
  const body = $id("winBakeBody");
  if (!body) return;
  let isos, win, bakeSet;
  try { [isos, win, bakeSet] = await Promise.all([api("GET", "/windows/isos"), api("GET", "/settings/windows"), api("GET", "/settings/bake")]); }
  catch (e) { if (!stale() && $id("winBakeBody")) $id("winBakeBody").innerHTML = warnBanner(esc(e.message)); return; }
  if (stale() || !$id("winBakeBody")) return;
  // Only Windows install media - not the WinPE or Features on Demand ISOs.
  isos.isos = isos.isos.filter(i => i.kind === "windows");
  const readable = isos.isos.filter(i => i.readable);
  if (!win.winpe || !win.winpe.volid) {
    $id("winBakeBody").innerHTML = `<div class="warn-banner"><div class="warn-banner-text">Windows bakes boot a WinPE - build it first under <b>Media</b>, straight from Microsoft or from a Windows ISO.</div></div><div class="row"><button class="btn" type="button" data-goto="media"><img src="${iconSrc("iso-media.svg")}" alt=""> Open Media</button></div>`;
    return;
  }
  if (!isos.isos.length) {
    $id("winBakeBody").innerHTML = `<p class="hint">No Windows ISO on ${esc(isos.node)} yet. Upload one in PVE (a storage's <b>ISO Images → Upload</b> or <b>Download from URL</b>).</p>`;
    return;
  }
  if (!winForm.iso || !readable.some(i => i.volid === winForm.iso)) winForm.iso = (readable[0] || isos.isos[0]).volid;
  const locales = Object.entries(catalog.locales).sort((a, b) => a[1].localeCompare(b[1]));
  winDiskStorage = (bakeSet.resolved || {}).disk_storage || "";
  winDiskStorages = bakeSet.disk_storages || [];
  $id("winBakeBody").innerHTML = `<div class="grid-2">
      ${field(fieldLabel("iso-media.svg", "Windows ISO"), `<select id="wiIso">${opts(isos.isos.map(i => [i.volid, `${i.file} · ${gib(i.size)} GiB${i.readable ? "" : " · not readable by the studio"}`]), winForm.iso)}</select>`)}
      <div class="bake-parts">
        ${fieldLabel("integration.svg", "Baked with")}
        <div class="bake-part-row">
          <button type="button" class="bake-part" data-goto="media" title="${esc(win.winpe.volid)} - built from ${esc(win.winpe.source_iso || "")}">
            <img src="${iconSrc("os-window.svg")}" alt=""><span class="bp-k">WinPE</span><span class="bp-v">${esc(String(win.winpe.volid).split("/").pop().replace(/^(pvs-)?winpe-|\.iso$/g, ""))}</span></button>
          <button type="button" class="bake-part" data-goto="media" title="virtio-win drivers and the QEMU guest agent">
            <img src="${iconSrc("integration.svg")}" alt=""><span class="bp-k">virtio-win</span><span class="bp-v">${esc(win.settings.virtio === "stable" && win.stable ? win.stable : win.settings.virtio)}</span>${win.settings.virtio === "stable" ? `<span class="bp-tag">stable</span>` : ""}</button>
        </div>
      </div>
    </div><div id="wiImages" style="margin-top:12px"><p class="hint">Reading the ISO…</p></div>`;
  $id("wiIso").addEventListener("change", () => { winForm.iso = $id("wiIso").value; winForm.index = null; winForm.edition = ""; fillWinBake(catalog, stale); });
  let info;
  try { info = await api("GET", "/windows/images?volid=" + encodeURIComponent(winForm.iso)); }
  catch (e) { if ($id("wiImages")) $id("wiImages").innerHTML = warnBanner(esc(e.message)); return; }
  if (!$id("wiImages")) return;
  if (winForm.index == null) winForm.index = (info.images.find(i => i.installation_type === "Server Core" && /Datacenter/.test(i.edition_id)) || info.images[0]).index;
  const lang = (info.images[0] || {}).language || "en-US";
  if (!winForm.locale) winForm.locale = catalog.region.locale || lang;
  if (!winForm.keyboard) winForm.keyboard = catalog.region.keyboard || lang;
  if (!winForm.timezone) winForm.timezone = catalog.region.windowsTimeZone || (info.default_timezone !== "UTC" ? info.default_timezone : "UTC");
  $id("wiImages").innerHTML = `<div class="table-wrap"><table class="data">
      <thead><tr><th></th><th>Edition</th><th>Type</th><th>Build</th><th>Language</th><th>Size</th><th>Gold id</th></tr></thead>
      <tbody>${info.images.map(i => `<tr class="clickable ${i.index === winForm.index && !winForm.edition ? "selected" : ""}" data-wi="${i.index}" data-wi-edition="">
        <td class="mono">${i.index}</td><td>${esc(wiEditionName(i.image_id, i.name))}</td>
        <td><span class="pill role ${i.installation_type === "Server Core" ? "core" : i.installation_type === "Client" ? "client" : "desktop"}">${esc(i.installation_type === "Server Core" ? "Core" : i.installation_type === "Client" ? "Client" : "Desktop")}</span></td>
        <td class="mono">${esc(String(i.version || i.build).replace(/^10\.0\./, ""))}</td><td class="mono">${esc(i.language)}</td><td class="mono">${i.size_gb} GiB</td><td class="mono">${esc(i.image_id)}</td></tr>${(i.virtual || []).map(v => `
        <tr class="clickable wi-virtual ${i.index === winForm.index && winForm.edition === v.key ? "selected" : ""}" data-wi="${i.index}" data-wi-edition="${esc(v.key)}"
          title="Applied from index ${i.index}, changed to the virtual edition after sysprep (DISM /Set-Edition)">
          <td></td><td><span class="wi-arrow">↳</span> ${esc(wiEditionName(v.image_id, v.label))}</td>
          <td><span class="wi-types"><span class="pill role ${i.installation_type === "Server Core" ? "core" : i.installation_type === "Client" ? "client" : "desktop"}">${esc(i.installation_type === "Server Core" ? "Core" : i.installation_type === "Client" ? "Client" : "Desktop")}</span><span class="pill role virtual">Virtual</span></span></td><td class="mono">${esc(String(i.version || i.build).replace(/^10\.0\./, ""))}</td><td class="mono">${esc(i.language)}</td><td class="mono">${i.size_gb} GiB</td>
          <td class="mono">${esc(v.image_id)}</td></tr>`).join("")}`).join("")}</tbody></table></div>
    <div class="field-group">Disk</div>
    <div class="grid-2 disk-row">${diskField("wi", winForm.disk, 32, winDiskStorages, winForm.storage || winDiskStorage)}</div>
    <div class="field-group">Region</div>
    <div class="grid-3">
      ${field(fieldLabel("language.svg", "Formats and system locale"), `<select id="wiLocale">${opts(locales, winForm.locale)}</select>`)}
      ${field(fieldLabel("language.svg", "Keyboard"), `<select id="wiKeyboard">${opts(locales, winForm.keyboard)}</select>`)}
      ${field(fieldLabel("language.svg", "Time zone"), `<select id="wiTz">${opts(info.timezones.map(z => [z.id, `${z.id} · ${z.iana}`]), winForm.timezone)}</select>`)}
    </div>
    <div class="field-group">Policies baked in</div>
    <div class="toggle-grid">${winPolicies(info).map(f => toggle(`id="wiF_${esc(f.id)}"`, `${esc(f.label)}${f.tip ? infoTip(f.label, f.tip) : ""}`, winForm.features.includes(f.id))).join("")}</div>
    ${actions(`<span class="hint gs-actions-note">WinPE pass 1 (apply${winForm.edition ? ", check the edition target" : ""}) · audit mode (virtio, agent, sysprep) · WinPE pass 2 (verify${winForm.edition ? ", change the edition" : ""}, region, policies, key)</span>`,
      act("wiStart", "gold-image.svg", "Bake", true))}`;
  const keepWin = () => {
    winForm.locale = $id("wiLocale").value; winForm.keyboard = $id("wiKeyboard").value; winForm.timezone = $id("wiTz").value;
    winForm.disk = Math.min(2048, Math.max(32, parseInt($id("wiDisk").value, 10) || 64));
    winForm.storage = ($id("wiStorage") || {}).value || winForm.storage;
    // Policies the selected image does not offer keep their setting for when it comes back.
    const shown = winPolicies(info).map(f => f.id);
    winForm.features = winForm.features.filter(f => !shown.includes(f)).concat(shown.filter(id => $id("wiF_" + id)?.checked));
  };
  wireProvisioning($id("wiImages"), winForm, winDiskStorages, () => { keepWin(); fillWinBake(catalog, stale); });
  $id("wiImages").querySelectorAll("[data-wi]").forEach(tr => tr.addEventListener("click", () => {
    keepWin(); winForm.index = parseInt(tr.dataset.wi, 10); winForm.edition = tr.dataset.wiEdition || ""; fillWinBake(catalog, stale);
  }));
  $id("wiStart").addEventListener("click", async () => {
    keepWin();
    try {
      const { id } = await api("POST", "/golds/windows", { iso: winForm.iso, index: winForm.index,
        region: { locale: winForm.locale, keyboard: winForm.keyboard, timezone: winForm.timezone },
        features: winForm.features.filter(f => winPolicies(info).some(p => p.id === f)), policies: 1,
        edition_upgrade: winForm.edition || "", disk_gb: winForm.disk, disk_storage: winForm.storage || null });
      goldsUi.bake = false;
      openJob(id);
    } catch (e) { toast(e.message, true); }
  });
}

/* Log / Remove buttons in the server blades' tables. Removing is irreversible: the first
   click arms the button, the second does it. */
function wireRowActions(root, rerender) {
  root.querySelectorAll("[data-job-open]").forEach(b => b.addEventListener("click", () => openJob(b.dataset.jobOpen)));
  root.querySelectorAll("[data-gold-remove]").forEach(b => b.addEventListener("click", async () => {
    const g = (cluster.golds || []).find(x => x.id === b.dataset.goldRemove);
    const name = g ? `${goldShortId(g)}${goldBuildLabel(g) ? " · " + goldBuildLabel(g) : ""}` : b.dataset.goldRemove;
    if (!await confirmDelete("golds", `Remove gold ${name}?`,
      "Its template is deleted from PVE. VMs built from it as full copies keep running; designed VMs that pick this gold move to the next one of their image.", "Remove gold")) return;
    try { const { id } = await api("DELETE", "/golds/" + encodeURIComponent(b.dataset.goldRemove)); openJob(id); } catch (e) { toast(e.message, true); }
  }));
}

/* -- Deploy: the design against what exists -- */

/* A PVE tag's colour, as Proxmox VE's own UI picks it: the datacenter's tag-style colour map
   when it names the tag, else Proxmox.Utils.stringToRGB (proxmox-widget-toolkit) - the same
   hash, the same 0.7 blend with white. */
let tagColours = null;
function pveTagRgb(t) {
  const own = tagColours && tagColours[t];
  if (own && /^[0-9a-f]{6}$/i.test(own)) return "#" + own;
  let hash = 0;
  const str = t + "prox";
  for (let i = 0; i < str.length; i++) { hash = str.charCodeAt(i) + ((hash << 5) - hash); hash = hash & hash; }
  const ch = v => Math.round(v * 0.7 + 255 * 0.3);
  return `rgb(${ch(hash & 255)}, ${ch((hash >> 8) & 255)}, ${ch((hash >> 16) & 255)})`;
}
/* A tag as PVE writes it: lower case, letters, digits and - _ + . */
function cleanTag(t) { return String(t || "").trim().toLowerCase().replace(/[^a-z0-9_+.-]/g, "-").replace(/^-+|-+$/g, ""); }
function tagsOf(s) { return (Array.isArray(s.pveTags) ? s.pveTags : String(s.pveTags || "").split(/[,; ]+/)).map(cleanTag).filter(Boolean); }
function tagBadge(t, removable) {
  return `<span class="tagc" style="--c:${pveTagRgb(t)}">${esc(t)}${removable ? `<button type="button" data-tag-x="${esc(t)}" aria-label="Remove tag ${esc(t)}">×</button>` : ""}</span>`;
}
/* Saves the design without redrawing the blade - the plan repaints only its own rows. */
function saveSoon() {
  if (!lab.id || lab.conflict || encodeState() === lab.saved) return;
  setSaveState("unsaved", "warn");
  clearTimeout(lab.timer);
  lab.timer = setTimeout(saveLab, 1000);
}

/* -- Deploy: the design against what exists -- */

/* The plan's floating destination editor: pool and tags of one VM still to build (or, ticked,
   of all of them). A layer on the page - never inside the table's scroll box - placed under
   its row, or above it when the window has no room below. */
const dpEd = { id: null, all: false, newPool: false, q: "", hi: 0, tagOpen: false, layer: null, plan: null };

async function bladeDeploy(main, stale) {
  const [vms, golds, tc] = await Promise.all([api("GET", "/vms"), api("GET", "/golds"), tagColours ? null : api("GET", "/tags").catch(() => null)]);
  if (stale()) return;
  cluster.golds = golds; cluster.vms = vms;
  if (tc) tagColours = tc.colours || {};
  refreshValidation();
  const errors = reviewErrorCount();
  const byName = new Map(vms.map(v => [v.name, v]));
  const planned = state.servers.map(s => {
    const name = (s.name || "").toLowerCase();
    const built = byName.get(name);
    const gold = goldFor(s);
    return { s, name, built, gold };
  });
  const toBuild = planned.filter(p => !p.built || p.built.status === "failed");
  const preflight = reviewPreflightCard();
  dpEd.plan = { planned, toBuild, errors };
  const goAll = `<button class="btn" type="button" id="dpGo" ${toBuild.length && !errors ? "" : "disabled"} title="${errors ? "Fix the preflight errors first" : toBuild.length ? `Builds the ${toBuild.length} VM(s) not on the cluster yet` : state.servers.length ? "Every designed VM exists" : "Design a VM first"}"><img src="${iconSrc("deploy.svg")}" alt=""> Deploy all${toBuild.length ? ` · ${toBuild.length}` : ""}</button>`;
  main.innerHTML = bladeHead("deploy") + `
    <div class="chips"><span class="pill">Designed <b>${state.servers.length}</b></span><span class="pill">Built <b>${planned.filter(p => p.built && p.built.status === "ready").length}</b></span>
      <span class="pill">To build <b>${toBuild.length}</b></span>${errors ? `<span class="pill status off">${errors} preflight error(s)</span>` : `<span class="pill status on">Preflight OK</span>`}</div>
    ${preflight}
    ${gsCard("dp-plan", "vm.svg", "Deployment plan", state.servers.length ? `${state.servers.length} designed · ${toBuild.length} to build` : "nothing designed yet", state.servers.length ? `<div class="table-wrap"><table class="data dp-plan">
      <thead><tr><th>VM</th><th>Gold</th><th>Pool · Tags</th><th>State</th><th>Address</th><th></th></tr></thead>
      <tbody id="dpRows">${dpRows()}</tbody></table></div>` : `<div class="dp-empty">
        <span class="dp-empty-slot" aria-hidden="true"><img src="${iconSrc("vm.svg")}" alt=""></span>
        <div class="dp-empty-text"><b>Nothing to deploy yet</b><span>Each VM you design under Virtual machines appears here with its gold, its address and where it lands - then Deploy builds it.</span></div>
        <button class="btn" type="button" data-goto="servers"><img src="${iconSrc("vm.svg")}" alt=""> Design a VM</button></div>`, "", true, state.servers.length ? goAll : "")}
    ${vms.filter(v => !state.servers.some(s => (s.name || "").toLowerCase() === v.name)).length ? gsCard("dp-other", "servers.svg", "Built by the studio, not in the design",
      "VMs the studio built whose card is gone - clearing them only takes them out of this list", `<div class="table-wrap"><table class="data"><tbody>${vms.filter(v => !state.servers.some(s => (s.name || "").toLowerCase() === v.name)).map(v => `<tr>
        <td><b>${esc(v.name)}</b></td><td>${pillOn(cap(v.power), v.power === "running")}</td><td class="mono">${esc(v.ip || "")}</td><td class="mono">${esc(v.node + " · " + (v.vmid ?? "—"))}</td>
        <td class="row-actions"><button class="btn sm" type="button"${v.job_id ? ` data-job-open="${esc(v.job_id)}"` : ' disabled title="No build log"'}><img src="${iconSrc("log.svg")}" alt=""> Log</button><button class="btn icon sm danger-text" type="button" data-clear-record="${esc(v.id)}" title="Clear from view - takes it out of the studio's view; the VM in Proxmox VE is not touched" aria-label="Clear from view">${trashIcon()}</button></td></tr>`).join("")}</tbody></table></div>`, "", false) : ""}
    <div class="field-group">The design at a glance</div>
    ${reviewSummaryCards()}`;
  wireRowActions(main, () => renderServerBlade("deploy", main));
  dpWireRows();
  const deploy = async names => {
    dpClose();
    await flushSave();
    if (reviewErrorCount()) { toast("Review and validate reports errors - fix them first", true); return; }
    try {
      const r = await api("POST", `/labs/${encodeURIComponent(lab.id)}/deploy`, { names });
      toast(`${r.jobs.length} build job(s) started`);
      state.blade = "jobs"; render();
    } catch (e) { toast(e.message, true); }
  };
  dpEd.deploy = deploy;
  const go = $id("dpGo");
  if (go) go.addEventListener("click", () => deploy(toBuild.map(p => p.name)));
}

/* One row per designed VM, every row the same columns and the same three buttons; a button
   that does not apply is there, greyed out, and says why. */
function dpRows() {
  const { planned, toBuild, errors } = dpEd.plan;
  return planned.map(p => {
    const open = toBuild.includes(p);
    const b = p.built;
    const job = b && b.job_id && (cluster.jobs || []).find(j => j.id === b.job_id);
    const pct = job && job.progress && typeof job.progress.pct === "number" ? ` · ${Math.round(job.progress.pct)} %` : "";
    const st = !b ? `<span class="pill status none idle">Not built</span>`
      : b.status === "building" ? `<span class="pill status run">Building${pct}</span>`
      : b.status === "failed" ? `<span class="pill status bad">Failed</span>`
      : `<span class="pill status ${b.power === "running" ? "ok" : "idle"}">${esc(cap(b.power || "unknown"))}</span>`;
    const pool = p.s.pvePool;
    const tags = tagsOf(p.s);
    const dest = `${pool ? `<span class="dp-pool-name"><img src="${iconSrcBand("pool.svg", "ident")}" alt="">${esc(pool)}</span>` : `<span class="dp-pool-name none" title="No pool">—</span>`}${tags.map(t => tagBadge(t)).join("")}`;
    const node = b && b.status !== "failed" ? b.node : (p.s.pveNode || state.defaults.pveNode || "auto");
    const why = errors ? "Fix the preflight errors first" : !p.gold ? "No gold to build it from" : !p.name ? "The VM has no name" : "";
    return `<tr>
      <td><div class="dp-cell"><img src="${iconSrcBand("vm.svg", serverGlyphBand(p.s))}" alt=""><div class="dp-two"><b>${esc(p.name || "(no name)")}</b><span>${esc(findImage(p.s.imageId).label)}</span></div></div></td>
      <td>${p.gold ? `<div class="dp-cell"><img src="${iconSrcBand("gold-image.svg", serverGlyphBand(p.gold.image_id ? { imageId: p.gold.image_id } : p.s))}" alt=""><div class="dp-two"><span class="mono">${esc(p.gold.name)}</span><span>${esc(goldMetaLine(p.gold))}</span></div></div>`
        : `<button class="btn sm danger-text" type="button" data-goto="servers">no gold - pick one</button>`}</td>
      <td>${open ? `<button class="dp-dest" type="button" data-dest="${esc(p.s._id)}" aria-haspopup="dialog" aria-expanded="${dpEd.id === p.s._id}" title="Pool and tags">${dest}</button>`
        : `<div class="dp-dest ro">${dest}</div>`}</td>
      <td>${st}</td>
      <td><div class="dp-two"><span class="mono${b && b.status !== "failed" ? "" : " muted"}">${esc((b && b.ip) || p.s.ipAddress || "DHCP")}</span><span class="mono">${esc(node)} · ${b && b.status !== "failed" && b.vmid != null ? esc(b.vmid) : "—"}</span></div></td>
      <td class="row-actions">
        <button class="btn sm" type="button"${b && b.job_id ? ` data-job-open="${esc(b.job_id)}"` : ' disabled title="Not built yet - no log"'}><img src="${iconSrc("log.svg")}" alt=""> Log</button>
        <button class="btn sm" type="button"${open && !why ? ` data-deploy-one="${esc(p.name)}"` : ` disabled title="${esc(open ? why : "Already on the cluster")}"`}><img src="${iconSrc("deploy.svg")}" alt=""> Deploy</button>
        <button class="btn icon sm danger-text" type="button"${b && b.status !== "building" ? ` data-clear-vm="${esc(p.s._id)}" title="Clear from view - takes it out of the studio's view; the VM in Proxmox VE is not touched"` : ` disabled title="${b ? "Building - wait for it to finish" : "Not built - nothing to clear"}"`} aria-label="Clear from view">${trashIcon()}</button></td>
    </tr>`;
  }).join("");
}
function dpWireRows(repaint) {
  const body = $id("dpRows"); if (!body) return;
  body.querySelectorAll("[data-dest]").forEach(b => b.addEventListener("click", e => { e.stopPropagation(); dpEd.id === b.dataset.dest ? dpClose() : dpOpen(b.dataset.dest); }));
  body.querySelectorAll("[data-deploy-one]").forEach(b => b.addEventListener("click", () => dpEd.deploy && dpEd.deploy([b.dataset.deployOne])));
  // The blade's wireRowActions covers the first paint; a repaint brings new buttons.
  if (repaint) body.querySelectorAll("[data-job-open]").forEach(b => b.addEventListener("click", () => openJob(b.dataset.jobOpen)));
}
function dpRepaint() { const body = $id("dpRows"); if (body && dpEd.plan) { body.innerHTML = dpRows(); dpWireRows(true); } }

/* The VMs a change applies to: the one being edited, or every VM still to build. */
function dpTargets(s) { return dpEd.all ? dpEd.plan.toBuild.map(p => p.s) : [s]; }
/* Tags on the cluster's guests and in the design, with how many carry each - the suggestions. */
function dpKnownTags() {
  const n = new Map();
  // Templates (the golds) carry the studio's own tags - not ones a VM would want.
  for (const g of ((cluster.inventory && cluster.inventory.guests) || []).filter(g => !g.template)) for (const t of String(g.tags || "").split(/[;, ]+/).map(cleanTag).filter(Boolean)) n.set(t, (n.get(t) || 0) + 1);
  for (const s of state.servers) for (const t of tagsOf(s)) if (!n.has(t)) n.set(t, 0);
  return n;
}
function dpOpen(id) {
  Object.assign(dpEd, { id, newPool: false, q: "", hi: 0, tagOpen: false });
  if (!dpEd.layer) {
    dpEd.layer = document.createElement("div");
    dpEd.layer.className = "dp-layer"; dpEd.layer.setAttribute("role", "dialog");
    document.body.appendChild(dpEd.layer);
    document.addEventListener("mousedown", e => { if (dpEd.id && !dpEd.layer.contains(e.target) && !e.target.closest("[data-dest]")) dpClose(); });
    document.addEventListener("keydown", e => { if (e.key === "Escape" && dpEd.id) dpClose(); });
    window.addEventListener("scroll", dpPlace, true); window.addEventListener("resize", dpPlace);
  }
  dpEd.layer.hidden = false;
  dpRepaint(); dpPaint(); dpPlace();
  const cur = dpEd.layer.querySelector('[aria-selected="true"]'); if (cur) cur.focus();
}
function dpClose() {
  if (!dpEd.id) return;
  const was = dpEd.id; dpEd.id = null;
  if (dpEd.layer) dpEd.layer.hidden = true;
  dpRepaint();
  const b = document.querySelector(`[data-dest="${CSS.escape(was)}"]`); if (b) b.focus();
}
function dpPlace() {
  if (!dpEd.id || !dpEd.layer || dpEd.layer.hidden) return;
  const b = document.querySelector(`[data-dest="${CSS.escape(dpEd.id)}"]`);
  if (!b) { dpClose(); return; }
  const r = b.getBoundingClientRect(), h = dpEd.layer.offsetHeight, w = dpEd.layer.offsetWidth;
  const below = window.innerHeight - r.bottom - 8 >= h || r.top < h + 8;
  dpEd.layer.style.top = `${below ? r.bottom + 6 : r.top - h - 6}px`;
  dpEd.layer.style.left = `${Math.max(16, Math.min(r.left, window.innerWidth - w - 16))}px`;
}
function dpChanged(focusSel) { saveSoon(); dpRepaint(); dpPaint(focusSel); dpPlace(); }
function dpPaint(focusSel) {
  const s = state.servers.find(x => x._id === dpEd.id); if (!s) { dpClose(); return; }
  const L = dpEd.layer;
  const tags = tagsOf(s), known = dpKnownTags();
  const q = cleanTag(dpEd.q);
  const sugg = [...known.keys()].filter(t => !tags.includes(t) && (!q || t.includes(q))).sort((a, b) => known.get(b) - known.get(a) || a.localeCompare(b)).slice(0, 6);
  const list = (q && !known.has(q) && !tags.includes(q) ? [q] : []).concat(sugg);
  const inPool = id => state.servers.filter(x => x.pvePool === id).length;
  const others = dpEd.plan.toBuild.length;
  L.setAttribute("aria-label", `Pool and tags of ${s.name || "the VM"}`);
  L.innerHTML = `
    <div class="dp-l-h"><img src="${iconSrcBand("vm.svg", serverGlyphBand(s))}" alt=""><b>${esc(s.name || "(no name)")}</b><span>pool and tags</span></div>
    <div class="dp-l-sec"><div class="dp-l-k">Pool</div>
      <div class="dp-plist" role="listbox" aria-label="Pool">${[{ id: "", comment: "" }, ...(cluster.pools || [])].map(p => `
        <button class="dp-popt${p.id ? "" : " none"}" type="button" role="option" aria-selected="${(s.pvePool || "") === p.id}" data-pool="${esc(p.id)}">
          ${p.id ? `<img src="${iconSrcBand("pool.svg", "ident")}" alt="">` : "<span></span>"}<span class="nm">${esc(p.id || "None")}</span><span class="z">${esc(p.comment || "")}</span><span class="cnt">${p.id && inPool(p.id) ? inPool(p.id) : ""}</span><span class="tick">✓</span></button>`).join("")}
        ${dpEd.newPool ? `<div class="dp-newpool"><input id="dpNewPool" placeholder="pool-name" aria-label="New pool name" spellcheck="false" autocomplete="off"><input id="dpNewPoolC" placeholder="Comment (optional)" aria-label="Comment" autocomplete="off"><button class="btn sm primary" type="button" data-mkpool>Create</button></div>`
          : `<button class="dp-popt new" type="button" data-newpool><span>+</span><span class="nm">New pool</span><span></span><span></span><span></span></button>`}
      </div></div>
    <div class="dp-l-sec"><div class="dp-l-k">Tags</div>
      <div class="dp-tagfield"><div class="dp-tagbox">${tags.map(t => tagBadge(t, true)).join("")}<input id="dpTag" value="${esc(dpEd.q)}" placeholder="${tags.length ? "" : "Add a tag"}" aria-label="Add a tag" autocomplete="off" spellcheck="false"></div>
        ${dpEd.tagOpen && list.length ? `<div class="dp-tsugg" role="listbox">${list.map((t, i) => `<button type="button" role="option" class="${i === dpEd.hi ? "on" : ""}" data-add="${esc(t)}"><span class="sq" style="background:${pveTagRgb(t)}"></span>${esc(t)}<span class="z">${!known.has(t) ? "new tag" : known.get(t) ? `${known.get(t)} on the cluster` : "in the design"}</span></button>`).join("")}</div>` : ""}
      </div></div>
    <div class="dp-l-foot"><label class="dp-all"><input type="checkbox" id="dpAll"${dpEd.all ? " checked" : ""}${others > 1 ? "" : " disabled"}> Same for all ${others} to build</label><button class="btn sm primary" type="button" data-done>Done</button></div>`;
  L.querySelectorAll("[data-pool]").forEach(b => b.onclick = () => { dpTargets(s).forEach(x => { x.pvePool = b.dataset.pool; x._poolNew = false; }); dpChanged(); });
  const np = L.querySelector("[data-newpool]"); if (np) np.onclick = () => { dpEd.newPool = true; dpPaint("#dpNewPool"); dpPlace(); };
  const mk = async () => {
    const name = L.querySelector("#dpNewPool").value.trim(), comment = L.querySelector("#dpNewPoolC").value.trim();
    if (!name) return;
    try {
      const r = await api("POST", "/pools", { name, comment });
      cluster.pools = (cluster.pools || []).filter(p => p.id !== r.id).concat({ id: r.id, comment }).sort((a, b) => a.id.localeCompare(b.id));
      dpTargets(s).forEach(x => { x.pvePool = r.id; });
      dpEd.newPool = false; toast(`Pool ${r.id} created`); dpChanged();
    } catch (e) { toast(e.message, true); }
  };
  const mkb = L.querySelector("[data-mkpool]"); if (mkb) mkb.onclick = mk;
  L.querySelectorAll("#dpNewPool, #dpNewPoolC").forEach(i => i.onkeydown = e => { if (e.key === "Enter") mk(); if (e.key === "Escape") { e.stopPropagation(); dpEd.newPool = false; dpPaint(); } });
  const setTags = (fn) => dpTargets(s).forEach(x => { x.pveTags = fn(tagsOf(x)); });
  const add = t => { t = cleanTag(t); if (t) setTags(cur => cur.includes(t) ? cur : cur.concat(t)); dpEd.q = ""; dpEd.hi = 0; dpChanged("#dpTag"); };
  L.querySelectorAll("[data-tag-x]").forEach(b => b.onclick = () => { setTags(cur => cur.filter(t => t !== b.dataset.tagX)); dpChanged(); });
  L.querySelectorAll("[data-add]").forEach(b => b.onmousedown = e => { e.preventDefault(); add(b.dataset.add); });
  const ti = L.querySelector("#dpTag");
  ti.oninput = () => { dpEd.q = ti.value; dpEd.hi = 0; dpEd.tagOpen = true; dpPaint("#dpTag"); };
  ti.onfocus = () => { if (!dpEd.tagOpen) { dpEd.tagOpen = true; dpPaint("#dpTag"); } };
  ti.onblur = () => setTimeout(() => { if (dpEd.id && dpEd.tagOpen && document.activeElement?.id !== "dpTag") { dpEd.tagOpen = false; L.querySelector(".dp-tsugg")?.remove(); } }, 0);
  ti.onkeydown = e => {
    const items = [...L.querySelectorAll(".dp-tsugg [data-add]")];
    if (e.key === "ArrowDown" && items.length) { e.preventDefault(); dpEd.hi = (dpEd.hi + 1) % items.length; dpPaint("#dpTag"); }
    else if (e.key === "ArrowUp" && items.length) { e.preventDefault(); dpEd.hi = (dpEd.hi - 1 + items.length) % items.length; dpPaint("#dpTag"); }
    else if ((e.key === "Enter" || e.key === ",") && (items[dpEd.hi] || ti.value.trim())) { e.preventDefault(); add(items[dpEd.hi] ? items[dpEd.hi].dataset.add : ti.value); }
    else if (e.key === "Backspace" && !ti.value && tags.length) { const last = tags[tags.length - 1]; setTags(cur => cur.filter(t => t !== last)); dpChanged("#dpTag"); }
  };
  L.querySelector("#dpAll").onchange = e => {
    dpEd.all = e.target.checked;
    if (dpEd.all) dpEd.plan.toBuild.forEach(p => { p.s.pvePool = s.pvePool || ""; p.s.pveTags = tagsOf(s); });
    dpChanged();
  };
  L.querySelector("[data-done]").onclick = dpClose;
  if (focusSel) { const f = L.querySelector(focusSel); if (f) { f.focus(); if (f.setSelectionRange) f.setSelectionRange(f.value.length, f.value.length); } }
}

/* -- Jobs -- */

let jobSelected = null;
function openJob(id) { jobSelected = id; state.blade = "jobs"; render(); }

/* The blade is built once and then updated in place: the list every few seconds, the log
   line by line. Rebuilding it on every render threw the log away and replayed it - the
   flicker - and cost a round trip before anything showed. */
let jobsPoll = null, jobFilter = "all", jobsCache = [];
const JOB_KIND = { "auto-update": "Windows update", bake: "Linux gold", "windows-bake": "Windows gold", media: "Windows media", fod: "Features on Demand", winpe: "WinPE", virtio: "virtio-win", deploy: "Deploy", "cluster-check": "Cluster check", acme: "Certificate" };
const JOB_FILTERS = [["all", "All"], ["running", "Running"], ["failed", "Failed"], ["succeeded", "Succeeded"]];
function clock(iso) { return iso ? new Date(iso).toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit", hour12: clockFmt !== "24h" }) : ""; }
function dayOf(iso) {
  const d = new Date(iso), today = new Date(); today.setHours(0, 0, 0, 0);
  const diff = Math.round((today - new Date(d.getFullYear(), d.getMonth(), d.getDate())) / 86400000);
  return diff <= 0 ? "Today" : diff === 1 ? "Yesterday" : d.toLocaleDateString(undefined, { weekday: "long", month: "short", day: "numeric" });
}
/* What a job worked on - the VM, the gold, WinPE - so retries read as one history, not rows. */
function jobSubject(j) {
  let p = {}; try { p = JSON.parse(j.params || "{}"); } catch { /* none */ }
  // A VM's and a gold's cube takes the colour of what the machine is: Windows Server green,
  // Windows client blue, Linux yellow, Azure Local purple (serverGlyphBand).
  if (j.kind === "deploy") {
    const n = p.name || j.title.replace(/^Build /, "");
    const srv = (state.servers || []).find(s => (s.name || "").toLowerCase() === n.toLowerCase());
    // The gold it is built from says what it is; the design only when the gold is gone.
    const vm = p.vm && (cluster.vms || []).find(v => v.id === p.vm);
    const goldId = p.gold || (vm && vm.gold);
    const g = goldId && (cluster.golds || []).find(x => x.id === goldId);
    const band = g && g.image_id ? serverGlyphBand({ imageId: g.image_id }) : srv ? serverGlyphBand(srv) : g && g.os === "linux" ? "linux" : "work";
    return { key: "vm:" + n, name: n, icon: "vm.svg", band, what: "VM" };
  }
  if (j.kind === "media" && p.media) return { key: "media:" + p.media + ":" + p.build, name: j.title.replace(/^Build /, "").replace(/ media \(.*\)$/, ""), icon: "download.svg", what: "Windows media" };
  if (p.gold) {
    const g = (cluster.golds || []).find(x => x.id === p.gold);
    // A removed gold's newest job (its removal) names no image: its bake does.
    const bakeImage = () => { for (const o of cluster.jobs || []) { try { const q = JSON.parse(o.params || "{}"); if (q.gold === p.gold && q.image) return q.image; } catch { /* none */ } } return ""; };
    const image = (g && g.image_id) || p.image || bakeImage();
    return { key: "gold:" + p.gold, name: "Gold " + String(p.gold).replace(/^(pve-|bake-)/, ""), icon: "gold-image.svg",
      band: image ? serverGlyphBand({ imageId: image }) : (j.kind === "bake" ? "linux" : "work"), what: "Gold" };
  }
  if (j.kind === "fod" && p.fod) return { key: "fod:" + p.fod, name: j.title.replace(/^Build /, ""), icon: "fod.svg", what: "Features on Demand" };
  const k = { winpe: ["WinPE", "os-window.svg"], virtio: ["virtio-win", "disk.svg"], "cluster-check": ["Cluster", "servers.svg"], certificate: ["Certificate", "certificate.svg"] }[j.kind];
  return k ? { key: j.kind, name: k[0], icon: k[1], what: k[0] } : { key: "job:" + j.id, name: j.title, icon: "update.svg", what: JOB_KIND[j.kind] || j.kind };
}
function jobGroups(jobs) {
  const groups = new Map();
  for (const j of jobs) { const sub = jobSubject(j); if (!groups.has(sub.key)) groups.set(sub.key, { sub, runs: [] }); groups.get(sub.key).runs.push(j); }
  return [...groups.values()];
}
function jobItems(jobs) {
  const sel = jobs.find(j => j.id === jobSelected), selKey = sel && jobSubject(sel).key;
  const shown = jobGroups(jobs).filter(g => jobFilter === "all" || g.runs[0].status === jobFilter);
  if (!shown.length) return `<p class="hint job-none">No ${esc(jobFilter)} jobs.</p>`;
  let day = "", out = "";
  for (const { sub, runs } of shown) {
    const last = runs[0], d = dayOf(last.started_at || last.created_at);
    if (d !== day) { day = d; out += `<div class="job-day">${esc(d)}</div>`; }
    // The strip reads left to right, oldest to newest - the last run sits next to the name's end.
    const strip = runs.slice(0, 10).reverse().map(r => `<i class="s-${esc(r.status)}" title="${esc(r.title)} · ${esc(r.status)} · ${esc(clock(r.started_at || r.created_at))}"></i>`).join("");
    out += `<button type="button" class="job-item s-${esc(last.status)} ${sub.key === selKey ? "selected" : ""}" data-job="${esc(sub.key === selKey ? jobSelected : last.id)}">
      <img class="job-ico" src="${sub.band ? iconSrcBand(sub.icon, sub.band) : iconSrc(sub.icon)}" alt="">
      <span class="job-main"><span class="job-name">${esc(sub.name)}</span>
        <span class="job-sub">${runs.length > 1 ? `${runs.length} runs · ` : ""}${esc(last.status === "running" ? "running now" : (last.status === "failed" ? "failed " : "") + clock(last.started_at || last.created_at))}</span></span>
      <span class="job-hist">${strip}</span></button>`;
  }
  return out;
}
/* The selected subject's runs, newest first - GitHub's attempts, Buildkite's retries. */
function jobAttempts(jobs, job) {
  const key = jobSubject(job).key, runs = jobs.filter(j => jobSubject(j).key === key);
  if (runs.length < 2) return "";
  return runs.map((r, i) => `<button type="button" class="job-att s-${esc(r.status)} ${r.id === job.id ? "on" : ""}" data-job="${esc(r.id)}" title="${esc(r.title)}">
    <span class="job-dot"></span>#${runs.length - i}<small>${esc(clock(r.started_at || r.created_at))} · ${took(r.started_at, r.ended_at)}</small></button>`).join("");
}
function jobMeta(j) {
  return `<span>${esc(JOB_KIND[j.kind] || j.kind)}</span><span>started ${esc(when(j.started_at || j.created_at))}</span>` +
    `<span>${j.ended_at ? "took" : "running for"} ${took(j.started_at, j.ended_at)}</span><span>by ${esc(j.created_by)}</span>`;
}

async function bladeJobs(main, stale) {
  clearTimeout(jobsPoll);
  const jobs = await api("GET", "/jobs");
  if (stale()) return;
  jobsCache = jobs; cluster.jobs = jobs; renderNav();
  if (!jobSelected && jobs.length) jobSelected = jobs[0].id;
  const job = jobs.find(j => j.id === jobSelected);
  if (!jobs.length) {
    main.innerHTML = bladeHead("jobs") + `<div class="empty-state"><div class="ue-icon"><img src="${iconSrc("update.svg")}" alt=""></div><h3>No jobs yet</h3><p>Bakes, builds and checks show up here with their logs.</p></div>`;
  } else {
    if (!$id("jobList")) {
      main.innerHTML = bladeHead("jobs") + `
        <div class="jobs-split">
          <aside class="card job-rail">
            <div class="job-filters" id="jobFilters"></div>
            <div class="job-list" id="jobList"></div>
          </aside>
          <section class="card job-detail">
            <header class="job-head">
              <div class="job-title"><div class="job-title-row"><span id="jobStatus"></span><h3 id="jobTitle"></h3></div><div class="job-meta" id="jobMeta"></div></div>
              <button class="btn sm primary" type="button" id="jobContinue" hidden><img src="${iconSrc("update.svg")}" alt=""> Continue</button>
              <button class="btn sm" type="button" id="jobRetry" hidden><img src="${iconSrc("update.svg")}" alt=""> Retry</button>
              <button class="btn sm" type="button" id="jobAbort" hidden title="Stop this job - it ends at its next safe point and cleans up its VMs"><img src="${iconSrcDanger("stop.svg")}" alt=""> Cancel</button>
              <button class="btn icon sm ghost" type="button" id="jobDelete" title="Delete from the history" aria-label="Delete from the history">${trashIcon()}</button>
            </header>
            <div id="jobError"></div>
            <div class="job-atts" id="jobAttempts"></div>
            <div class="job-bar" id="jobBar"></div>
            <div class="log-bar">
              <span class="hint" id="jobStepsN"></span>
              <span class="log-bar-fill"></span>
              <div class="log-view">
                <button class="btn sm" type="button" id="logViewBtn" aria-haspopup="true" aria-expanded="false"><img src="${iconSrc("settings.svg")}" alt=""> View ${chevron()}</button>
                <div class="log-view-menu" id="logViewMenu" hidden>
                  ${toggle('id="logDebug"', 'Debug lines <span class="hint" id="logDebugN"></span>', false)}
                  ${toggle('id="logFollow"', "Follow the log", true)}
                </div>
              </div>
              <button class="btn sm" type="button" id="logExpand">Expand all</button>
              <button class="btn sm" type="button" id="logCopy">Copy log</button>
            </div>
            <div class="job-steps" id="jobLog"></div>
          </section>
        </div>`;
      const pick = e => {
        const b = e.target.closest("[data-job]");
        if (!b || b.dataset.job === jobSelected) return;
        jobSelected = b.dataset.job;
        renderServerBlade("jobs", main);
      };
      $id("jobRetry").addEventListener("click", async () => {
        const j = jobsCache.find(x => x.id === jobSelected); if (!j) return;
        let p = {}; try { p = JSON.parse(j.params || "{}"); } catch { /* none */ }
        // Bakes and VM builds go back to their form; the rest starts again as it ran.
        if (j.kind === "bake" || j.kind === "windows-bake") {
          if (p.iso) { Object.assign(winForm, { iso: p.iso, index: p.index ?? null, edition: "" }); openBake("windows"); }
          else { const g = (cluster.golds || []).find(x => x.id === p.gold); if (g) bakeForm.image = g.image_id; openBake("linux"); }
          return;
        }
        if (j.kind === "deploy") { state.blade = "deploy"; render(); return; }
        if (j.kind === "certificate") { state.blade = "studio"; render(); return; }
        try { const { id } = await api("POST", `/jobs/${encodeURIComponent(j.id)}/retry`); jobSelected = id; renderServerBlade("jobs", main); toast("Started again"); }
        catch (e) { toast(e.message, true); }
      });
      $id("jobContinue").addEventListener("click", async () => {
        const j = jobsCache.find(x => x.id === jobSelected); if (!j) return;
        try { const { id } = await api("POST", `/jobs/${encodeURIComponent(j.id)}/continue`); jobSelected = id; renderServerBlade("jobs", main); toast("Continuing"); }
        catch (e) { toast(e.message, true); }
      });
      $id("jobAbort").addEventListener("click", async () => {
        const j = jobsCache.find(x => x.id === jobSelected); if (!j || j.status !== "running") return;
        if (!await confirmDelete("abort", `Cancel ${j.title}?`,
          "It stops at its next safe point - a download chunk, a status check - and then cleans up as a failed job does: its bake or worker VM is removed. Retry starts it again.", "Cancel the job", undefined, "Keep running")) return;
        try { await api("POST", `/jobs/${encodeURIComponent(j.id)}/abort`); toast("Cancel requested"); renderServerBlade("jobs", main); }
        catch (e) { toast(e.message, true); }
      });
      $id("jobDelete").addEventListener("click", async () => {
        const sel = jobsCache.find(j => j.id === jobSelected); if (!sel) return;
        const sub = jobSubject(sel), runs = jobsCache.filter(j => jobSubject(j).key === sub.key);
        const n = `${runs.length} run${runs.length === 1 ? "" : "s"}`;
        // Several runs: the selected one alone, or all of them.
        const choice = await confirmDelete("jobs", `Delete ${sub.name} from the history?`,
          runs.length > 1
            ? `The selected run (${when(sel.started_at || sel.created_at)}), or all ${n} - their logs go for good. A running job, and a log a gold or VM still links to, stay.`
            : `Its run and its log go for good. A running job, and a log a gold or VM still links to, stay.`,
          `Delete ${n}`, runs.length > 1 ? "Delete this run" : undefined);
        if (!choice) return;
        const ids = choice === "alt" ? [sel.id] : runs.map(j => j.id);
        try {
          const r = await api("DELETE", "/jobs", { ids });
          const why = [...new Set(r.kept.map(k => k.why))].join("; ");
          toast(r.kept.length ? `Deleted ${r.deleted} of ${ids.length} - ${r.kept.length} kept: ${why}` : `Deleted ${r.deleted} run${r.deleted === 1 ? "" : "s"}`, !r.deleted);
          if (r.deleted) jobSelected = null;
        } catch (e) { toast(e.message, true); }
        renderServerBlade("jobs", main);
      });
      $id("jobList").addEventListener("click", pick);
      $id("jobAttempts").addEventListener("click", pick);
      $id("jobBar").addEventListener("click", e => {
        const seg = e.target.closest("[data-step]"); if (!seg) return;
        const st = logSteps[+seg.dataset.step]; if (!st) return;
        st.el.open = true; st.el._user = true; $id("logFollow").checked = false;
        st.el.scrollIntoView({ block: "start", behavior: "smooth" });
      });
      $id("logExpand").addEventListener("click", e => {
        const open = e.target.textContent === "Expand all";
        logSteps.forEach(st => { st.el.open = open; st.el._user = true; });
        e.target.textContent = open ? "Collapse all" : "Expand all";
      });
      // A step the user opened or closed stays that way; the live view leaves it alone.
      $id("jobLog").addEventListener("click", e => { const sm = e.target.closest("summary"); if (sm) sm.parentElement._user = true; });
      $id("jobFilters").addEventListener("click", e => {
        const b = e.target.closest("[data-filter]"); if (!b) return;
        jobFilter = b.dataset.filter;
        setHtml($id("jobFilters"), jobFilterHtml(jobsCache));
        setHtml($id("jobList"), jobItems(jobsCache));
      });
      // The View menu: opens on its button, closes on a click elsewhere or Escape.
      const viewMenu = $id("logViewMenu"), viewBtn = $id("logViewBtn");
      const setView = open => { viewMenu.hidden = !open; viewBtn.setAttribute("aria-expanded", open); viewBtn.classList.toggle("on", open); };
      viewBtn.addEventListener("click", e => { e.stopPropagation(); setView(viewMenu.hidden); });
      document.addEventListener("click", e => { if (!viewMenu.hidden && !e.target.closest(".log-view")) setView(false); });
      document.addEventListener("keydown", e => { if (e.key === "Escape" && !viewMenu.hidden) setView(false); });
      let debug = false; try { debug = localStorage.getItem("pvs.logDebug") === "1"; } catch { /* default */ }
      $id("logDebug").checked = debug; $id("jobLog").classList.toggle("hide-debug", !debug);
      $id("logDebug").addEventListener("change", e => {
        $id("jobLog").classList.toggle("hide-debug", !e.target.checked);
        try { localStorage.setItem("pvs.logDebug", e.target.checked ? "1" : "0"); } catch { /* fine */ }
      });
      $id("logFollow").addEventListener("change", e => { if (e.target.checked) { const p = $id("jobLog"); p.scrollTop = p.scrollHeight; } });
      $id("logCopy").addEventListener("click", async () => {
        try { await navigator.clipboard.writeText([...$id("jobLog").querySelectorAll(".ln")].map(d => d.dataset.raw || d.textContent).join("\n")); toast("Log copied"); }
        catch (e) { toast("Copy failed: " + e.message, true); }
      });
    }
    setHtml($id("jobFilters"), jobFilterHtml(jobs));
    setHtml($id("jobList"), jobItems(jobs));
    if (job) {
      followLog(job);
      setHtml($id("jobMeta"), jobMeta(job));
      setHtml($id("jobStatus"), jobPill(job.status));
      setHtml($id("jobAttempts"), jobAttempts(jobs, job));
      setHtml($id("jobError"), job.error ? warnBanner(esc(job.error)) : "");
      paintJobDelete(jobs.filter(j => jobSubject(j).key === jobSubject(job).key));
      // Retry: a failed or interrupted job that is the newest of its subject (an older one
      // was retried already).
      const newest = jobs.find(j => jobSubject(j).key === jobSubject(job).key);
      const r = $id("jobRetry");
      if (r) {
        r.hidden = !["failed", "interrupted"].includes(job.status) || !newest || newest.id !== job.id || job.kind === "remove-gold";
        const a = $id("jobAbort");
        if (a) a.hidden = job.status !== "running";
        r.title = { bake: "Open the bake form with this bake's ISO and image", "windows-bake": "Open the bake form with this bake's ISO and image", deploy: "Open Deploy", certificate: "Open Studio settings" }[job.kind] || "Start this job again with the same settings";
        // Continue: a media build that left something behind - a finished stage or downloads.
        const c = $id("jobContinue");
        if (c) {
          const show = k => {
            c.hidden = !k;
            if (k) { c.title = `Pick up where it stopped: ${k.label}`; r.title = "Start over - the downloads in the cache are still used"; }
          };
          const key = `${job.id}:${job.status}`;
          if (r.hidden || job.kind !== "media") show(null);
          else if (jobResume.key === key) show(jobResume.k);
          else {
            show(null);
            api("GET", `/jobs/${encodeURIComponent(job.id)}/continue`).then(k => {
              jobResume = { key, k };
              if (jobSelected === job.id) show(k);
            }).catch(() => {});
          }
        }
      }
    }
  }
  jobsPoll = setTimeout(() => { if (!stale()) bladeJobs(main, stale).catch(() => {}); }, jobs.some(j => j.status === "running") ? 2000 : 15000);
}
/* The selected job's Continue answer, asked once per job and status. */
let jobResume = { key: "", k: null };
function jobFilterHtml(jobs) {
  return JOB_FILTERS.map(([k, label]) => {
    const n = k === "all" ? jobs.length : jobs.filter(j => j.status === k).length;
    return `<button type="button" class="job-filter f-${k} ${jobFilter === k ? "on" : ""} ${n ? "" : "zero"}" data-filter="${k}" aria-pressed="${jobFilter === k}">
      <span class="n">${n}</span><span class="l">${label}</span></button>`;
  }).join("");
}
function paintJobDelete(runs) {
  const b = $id("jobDelete"); if (!b) return;
  const busy = runs.some(j => j.status === "running" || j.status === "queued");
  b.disabled = busy;
  b.title = busy ? "Running - delete it once it ends" : "Delete from the history";
}

/* Asking before a delete: an overlay with the consequence, and "Don't ask again" for this
   kind of delete - remembered in this browser, switched back on under Studio settings. */
const CONFIRM_KINDS = { jobs: "Deleting job history", golds: "Removing golds", clear: "Clearing VMs from view", abort: "Cancelling a running job", isos: "Deleting ISOs" };
const skipConfirm = kind => { try { return localStorage.getItem("pvs.skipConfirm." + kind) === "1"; } catch { return false; } };
function setSkipConfirm(kind, skip) { try { skip ? localStorage.setItem("pvs.skipConfirm." + kind, "1") : localStorage.removeItem("pvs.skipConfirm." + kind); } catch { /* this browser keeps nothing */ } }
/* Resolves false (cancel), true (the main action) or "alt" (the second, smaller choice - e.g.
   only the selected run instead of all of them). Skipped ("Don't ask again"), a call that
   offers an alternative takes it: the narrower delete. */
/* The confirm overlay (design B): the question, then what happens - outcome rows when the
   caller knows them (deleted / kept / moved, with counts), else one sentence. Red is the icon
   and the action's text only; "Don't ask again" is a plain switch, its meaning in the (i). */
const CF_ROW_ICON = {
  del: () => `<img src="${iconSrcDanger("trash.svg")}" alt="">`,
  keep: () => `<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"><path d="M3 8.4l3 3 7-7"/></svg>`,
  move: () => `<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"><path d="M2.5 8h10M9 4.5L12.5 8 9 11.5"/></svg>`,
};
function confirmDelete(kind, title, body, label, altLabel, noLabel = "Cancel") {
  if (skipConfirm(kind)) return Promise.resolve(altLabel ? "alt" : true);
  return new Promise(resolve => {
    const ov = document.createElement("div");
    ov.className = "overlay open confirm-overlay";
    const what = Array.isArray(body)
      ? `<div class="cf-rows" id="cfBody">${body.map(([k, text, n]) => `<div class="cf-row ${esc(k)}"><span class="cf-ic">${(CF_ROW_ICON[k] || CF_ROW_ICON.del)()}</span><span>${esc(text)}</span><span class="cf-n">${n ?? ""}</span></div>`).join("")}</div>`
      : `<p class="confirm-body" id="cfBody">${esc(body)}</p>`;
    ov.innerHTML = `<div class="modal confirm-modal" role="alertdialog" aria-modal="true" aria-labelledby="cfTitle" aria-describedby="cfBody">
      <h2 class="cf-title" id="cfTitle"><img src="${iconSrcDanger("trash.svg")}" alt="">${esc(title)}</h2>
      ${what}
      <div class="cf-foot"><div class="cf-skip">${toggle('id="cfSkip"', `Don't ask again${infoTip("Don't ask again", "This kind of delete goes through without asking from now on, in this browser. Switch it back on under Studio settings.")}`, false)}</div>
        <div class="cf-actions"><button class="btn" type="button" data-cf="no">${esc(noLabel)}</button>${altLabel ? `<button class="btn cf-go" type="button" data-cf="alt"><img src="${iconSrcDanger("trash.svg")}" alt="">${esc(altLabel)}</button>` : ""}<button class="btn cf-go" type="button" data-cf="yes"><img src="${iconSrcDanger("trash.svg")}" alt="">${esc(label)}</button></div></div>
    </div>`;
    const done = v => {
      if (v && ov.querySelector("#cfSkip").checked) setSkipConfirm(kind, true);
      document.removeEventListener("keydown", key, true); ov.remove(); resolve(v);
    };
    const key = e => { if (e.key === "Escape") { e.stopPropagation(); done(false); } };
    ov.addEventListener("click", e => { const b = e.target.closest("[data-cf]"); if (b) done(b.dataset.cf === "yes" ? true : b.dataset.cf === "alt" ? "alt" : false); else if (e.target === ov) done(false); });
    document.addEventListener("keydown", key, true);
    document.body.appendChild(ov);
    ov.querySelector('[data-cf="no"]').focus();
  });
}

/* A gold's CIS report: every rule with its status and evidence, filtered by status; the HTML
   and JSON for an auditor; the GRUB password for admins. Self-assessed wording only. */
const CIS_TABS = [["all", "All"], ["fail", "Failed"], ["exception", "Exceptions"], ["review", "Review"], ["pass", "Passed"], ["na", "N/A"]];
async function openCisReport(goldId) {
  let rep;
  try { rep = await api("GET", "/golds/" + encodeURIComponent(goldId) + "/cis"); } catch (e) { toast(e.message, true); return; }
  const results = rep.results || [], c = rep.counts || {};
  const judged = (c.pass || 0) + (c.fail || 0) + (c.error || 0);
  const score = judged ? Math.round((c.pass || 0) * 1000 / judged) / 10 : 0;
  let tab = (c.fail || c.error) ? "fail" : "all", q = "";
  const ov = document.createElement("div");
  ov.className = "overlay open cis-overlay";
  const count = k => k === "all" ? results.length : k === "fail" ? (c.fail || 0) + (c.error || 0) : (c[k] || 0);
  const rows = () => results.filter(r => (tab === "all" || r.status === tab || (tab === "fail" && r.status === "error"))
      && (!q || (r.id + " " + r.title + " " + r.evidence).toLowerCase().includes(q)))
    .map(r => `<details class="cis-row ${esc(r.status)}"><summary><span class="cis-id mono">${esc(r.id)}</span><span class="cis-lvl">L${esc(r.level)}</span>
      <span class="cis-title">${esc(r.title)}${r.kind === "manual" ? ' <span class="cis-manual">manual</span>' : ""}</span><span class="cis-st">${esc(r.status === "na" ? "n/a" : r.status)}</span></summary>
      ${r.reason ? `<div class="cis-why">Exception: ${esc(r.reason)}</div>` : ""}<pre class="cis-ev">${esc(r.evidence || "(no evidence)")}</pre></details>`).join("") || `<p class="hint cis-empty">Nothing here.</p>`;
  const paint = () => {
    ov.querySelector(".cis-tabs").innerHTML = CIS_TABS.map(([k, l]) => `<button type="button" class="btn sm${tab === k ? " on" : ""}" data-cis-tab="${k}">${l} <span class="cis-n">${count(k)}</span></button>`).join("");
    ov.querySelector(".cis-list").innerHTML = rows();
  };
  ov.innerHTML = `<div class="modal cis-modal" role="dialog" aria-modal="true" aria-labelledby="cisTitle">
    <div class="cis-head"><span class="card-icon"><img src="${iconSrc("security.svg")}" alt=""></span>
      <div><h2 id="cisTitle">${esc(rep.benchmark)} v${esc(rep.version)} · Level ${esc(rep.level)} Server</h2>
      <div class="hint">Checked ${esc(when(rep.checked))} · self-assessed by the studio - not a CIS certification</div></div>
      <div class="cis-score"><b>${score}%</b><span>of the applicable automated rules pass</span></div></div>
    <div class="cis-bar"><div class="ov-seg cis-tabs" role="group" aria-label="Filter"></div><input type="search" class="cis-search" placeholder="Search rules and evidence" aria-label="Search"></div>
    <div class="cis-list"></div>
    <div class="actions"><span class="cis-grub"></span>
      <a class="btn" href="/api/golds/${encodeURIComponent(goldId)}/cis.html" download><img src="${iconSrc("download.svg")}" alt=""> HTML</a>
      <a class="btn" href="/api/golds/${encodeURIComponent(goldId)}/cis?download=1" download><img src="${iconSrc("download.svg")}" alt=""> JSON</a>
      <button class="btn primary" type="button" data-cis-close>Close</button></div>
  </div>`;
  const close = () => { document.removeEventListener("keydown", key, true); ov.remove(); };
  const key = e => { if (e.key === "Escape") { e.stopPropagation(); close(); } };
  ov.addEventListener("click", async e => {
    const t = e.target.closest("[data-cis-tab]");
    if (t) { tab = t.dataset.cisTab; paint(); return; }
    if (e.target.closest("[data-cis-close]") || e.target === ov) { close(); return; }
    if (e.target.closest("[data-cis-grub]")) {
      try {
        const g = await api("GET", "/golds/" + encodeURIComponent(goldId) + "/cis/grub");
        ov.querySelector(".cis-grub").innerHTML = `GRUB <span class="mono">${esc(g.user)}</span> / <span class="mono cis-pw">${esc(g.password)}</span>`;
      } catch (err) { toast(err.message, true); }
    }
  });
  ov.querySelector(".cis-search").addEventListener("input", e => { q = e.target.value.trim().toLowerCase(); paint(); });
  ov.querySelector(".cis-grub").innerHTML = `<button class="btn" type="button" data-cis-grub title="The password that protects editing the boot menu - admins only"><img src="${iconSrc("secret.svg")}" alt=""> Show GRUB password</button>`;
  document.addEventListener("keydown", key, true);
  document.body.appendChild(ov);
  paint();
}
/* A benchmark's rules before a bake (the bake form's rules button): what the studio applies,
   only checks, or leaves to a person - by chapter, for Level 1 or Level 2. Our own titles. */
const CIS_CHAPTERS = { 1: "Setup and boot", 2: "Services", 3: "Network", 4: "Firewall", 5: "Access and authentication", 6: "Logging and audit", 7: "Maintenance" };
const CIS_DOES = [["all", "All"], ["fix", "Fixes"], ["chk", "Checks"], ["rev", "Review"]];
async function openCisRules(image, level) {
  let rep;
  try { rep = await api("GET", "/cis/rules/" + encodeURIComponent(image)); } catch (e) { toast(e.message, true); return; }
  const all = rep.rules || [];
  const does = r => r.decision || r.manual ? "rev" : r.fix ? "fix" : "chk";
  let lv = level === 1 ? 1 : 2, f = "all", q = "";
  const inLv = r => r.level <= lv;
  const match = r => inLv(r) && (f === "all" || does(r) === f) && (!q || (r.id + " " + r.title + " " + r.decision).toLowerCase().includes(q));
  const count = k => all.filter(r => inLv(r) && (k === "all" || does(r) === k)).length;
  const row = r => {
    const d = does(r);
    return `<details class="cis-row rule-${d}"><summary><span class="cis-id mono">${esc(r.id)}</span><span class="cis-lvl${r.level === 2 ? " l2" : ""}">L${r.level}</span>
      <span class="cis-title">${esc(r.title)}${r.manual ? ' <span class="cis-manual">manual</span>' : ""}</span><span class="cis-does ${d}">${d === "fix" ? "Fixes" : d === "chk" ? "Checks" : "Review"}</span></summary>
      <div class="cis-why-rule">${d === "fix" ? "Applied in the bake; the check after the reboot proves it." : d === "chk" ? "Checked after the reboot - nothing to apply." : "Reported for a person to review, not scored."}${r.decision ? `<br><b>Studio decision:</b> ${esc(r.decision)}` : ""}</div></details>`;
  };
  const ov = document.createElement("div");
  ov.className = "overlay open cis-overlay";
  ov.innerHTML = `<div class="modal cis-modal" role="dialog" aria-modal="true" aria-labelledby="cisRulesTitle">
    <div class="cis-head"><span class="card-icon"><img src="${iconSrc("security.svg")}" alt=""></span>
      <div><h2 id="cisRulesTitle">${esc(rep.benchmark)} v${esc(rep.version)}</h2></div></div>
    <div class="cis-bar"><div class="ov-seg cis-lv" role="group" aria-label="Level"></div><div class="ov-seg cis-tabs" role="group" aria-label="Filter"></div>
      <input type="search" class="cis-search" placeholder="Search number, title, decision" aria-label="Search"></div>
    <div class="cis-list cis-rules-list"></div>
    <div class="actions"><button class="btn primary" type="button" data-cis-close>Close</button></div>
  </div>`;
  const paint = () => {
    ov.querySelector(".cis-lv").innerHTML = [1, 2].map(n => `<button type="button" class="btn sm${lv === n ? " on" : ""}" data-cis-lv="${n}">Level ${n}</button>`).join("");
    ov.querySelector(".cis-tabs").innerHTML = CIS_DOES.map(([k, l]) => `<button type="button" class="btn sm${f === k ? " on" : ""}" data-cis-tab="${k}">${l} <span class="cis-n">${count(k)}</span></button>`).join("");
    let html = "";
    for (const c of Object.keys(CIS_CHAPTERS)) {
      const rs = all.filter(r => r.id.split(".")[0] === c && match(r));
      if (rs.length) html += `<div class="cis-chapter"><b class="mono">${c}</b>${CIS_CHAPTERS[c]}<span>${rs.length}</span></div>` + rs.map(row).join("");
    }
    ov.querySelector(".cis-list").innerHTML = html || `<p class="hint cis-empty">No rule matches.</p>`;
  };
  const close = () => { document.removeEventListener("keydown", key, true); ov.remove(); };
  const key = e => { if (e.key === "Escape") { e.stopPropagation(); close(); } };
  ov.addEventListener("click", e => {
    const l = e.target.closest("[data-cis-lv]"); if (l) { lv = Number(l.dataset.cisLv); paint(); return; }
    const t = e.target.closest("[data-cis-tab]"); if (t) { f = t.dataset.cisTab; paint(); return; }
    if (e.target.closest("[data-cis-close]") || e.target === ov) close();
  });
  ov.querySelector(".cis-search").addEventListener("input", e => { q = e.target.value.trim().toLowerCase(); paint(); });
  document.addEventListener("keydown", key, true);
  document.body.appendChild(ov);
  paint();
  ov.querySelector(".cis-search").focus();
}
document.addEventListener("click", e => {
  const b = e.target.closest("[data-cis-rules]");
  if (b) { e.preventDefault(); e.stopPropagation(); openCisRules(b.dataset.cisRules, Number(b.dataset.cisLevel)); }
}, true);
document.addEventListener("click", e => {
  const b = e.target.closest("[data-cis-report]");
  if (b) { e.preventDefault(); e.stopPropagation(); openCisReport(b.dataset.cisReport); }
}, true);

/* innerHTML only when it differs - an identical rewrite still re-lays out and loses hover. */
function setHtml(el, html) { if (el && el._html !== html) { el.innerHTML = html; el._html = html; } }

let liveLog = null, liveJob = null, logQueue = [], logFrame = 0, debugLines = 0, logSteps = [], logEnded = "";
function stopLiveLog() {
  if (liveLog) { liveLog.close(); liveLog = null; }
  liveJob = null; logQueue = []; cancelAnimationFrame(logFrame); logFrame = 0;
  clearTimeout(jobsPoll); clearTimeout(dashPoll); jobProg = null;
}

function followLog(job) {
  if (liveJob === job.id) return;
  stopLiveLog();
  liveJob = job.id;
  $id("jobTitle").textContent = job.title;
  $id("jobLog").textContent = ""; debugLines = 0; $id("logDebugN").textContent = "";
  logSteps = []; logEnded = ""; setHtml($id("jobBar"), ""); $id("jobStepsN").textContent = ""; $id("logExpand").textContent = "Expand all";
  const es = new EventSource(`/api/jobs/${encodeURIComponent(job.id)}/events`);
  liveLog = es;
  // Lines come in bursts (a replay, DISM on the serial console): queued and written once
  // per frame, so a thousand lines are one layout, not a thousand.
  es.addEventListener("line", e => {
    logQueue.push(JSON.parse(e.data).text);
    if (!logFrame) logFrame = requestAnimationFrame(flushLog);
  });
  es.addEventListener("progress", e => { const p = JSON.parse(e.data); showProgress(p.done ? null : p); });
  es.addEventListener("status", e => {
    const { status } = JSON.parse(e.data);
    showProgress(null);
    setHtml($id("jobStatus"), jobPill(status));
    es.close(); if (liveLog === es) liveLog = null;
    flushLog(); endSteps(status);
  });
}
/* The log as steps: every "[ run ]" line opens one and it lasts until the next - GitHub's
   and Buildkite's step list. Lines before the first step are "Prepare". */
const secsOf = clk => { const [h, m, x] = clk.split(":").map(Number); return h * 3600 + m * 60 + x; };
function stepName(msg) {
  const m = /^(WinPE deploy pass|WinPE pass \d|Audit mode|First boot)\b/.exec(msg);
  return m ? m[1] : msg;
}
function newStep(name, full, at) {
  const el = document.createElement("details");
  el.className = "job-step s-ok";
  el.innerHTML = `<summary><span class="job-dot"></span><span class="step-name"></span><span class="step-n"></span><span class="step-took"></span></summary><div class="job-log"></div>`;
  el.querySelector(".step-name").textContent = name; el.querySelector(".step-name").title = full || name;
  const st = { el, body: el.lastElementChild, name, start: at, last: at, status: "ok", n: 0 };
  // The step before closes as this one opens, unless it went wrong or the user touched it.
  const prev = logSteps[logSteps.length - 1];
  if (prev && !prev.el._user && prev.status === "ok") prev.el.open = false;
  if (!logEnded) el.open = true;
  logSteps.push(st);
  return st;
}
function flushLog() {
  logFrame = 0;
  const p = $id("jobLog"); if (!p) { logQueue = []; return; }
  for (const t of logQueue) {
    const d = logLine(t), clk = (/(\d\d:\d\d:\d\d) \[/.exec(t) || [])[1];
    const at = clk ? secsOf(clk) : null;
    const tag = d.dataset.tag || "", msg = d.dataset.msg || "";
    let st = logSteps[logSteps.length - 1];
    if (tag === "run" && !/^PVS-/.test(msg)) { st = newStep(stepName(msg), msg, at); p.appendChild(st.el); }
    else if (!st) { st = newStep("Prepare", "", at); p.appendChild(st.el); }
    if (at != null) { if (st.start == null) st.start = at; st.last = at; }
    if (d.classList.contains("t-debug")) debugLines++; else st.n++;
    if (tag === "error") st.status = "bad"; else if (tag === "warn" && st.status === "ok") st.status = "warn";
    st.body.appendChild(d);
  }
  logQueue = [];
  paintSteps();
  if (debugLines) $id("logDebugN").textContent = `(${debugLines})`;
  if ($id("logFollow")?.checked) p.scrollTop = p.scrollHeight;
}
function paintSteps() {
  const t0 = logSteps.length ? logSteps[0].start : null;
  logSteps.forEach((st, i) => {
    const next = logSteps[i + 1];
    let end = next && next.start != null ? next.start : st.last;
    if (end != null && st.start != null && end < st.start) end += 86400; // past midnight
    st.dur = st.start != null && end != null ? Math.max(0, end - st.start) : 0;
    const running = !logEnded && !next;
    const sp = running && jobProg ? progPct(jobProg) : null;
    st.el.className = `job-step s-${running ? "running" : st.status}${sp != null ? " prog" : ""}`;
    if (sp != null) st.el.style.setProperty("--pct", sp.toFixed(1) + "%");
    st.el.querySelector(".step-n").textContent = running && jobProg ? progText(jobProg) : `${st.n} line${st.n === 1 ? "" : "s"}`;
    st.el.querySelector(".step-took").textContent = fmtSecs(st.dur);
  });
  $id("jobStepsN").textContent = logSteps.length ? `${logSteps.length} step${logSteps.length === 1 ? "" : "s"}` : "";
  // Where the time went: one segment per step, as wide as it took.
  setHtml($id("jobBar"), t0 == null ? "" : logSteps.map((st, i) => `<button type="button" class="seg ${st.el.className.replace("job-step ", "").replace(" prog", "")}" data-step="${i}"
    style="flex:${Math.max(1, st.dur)}" title="${esc(st.name)} · ${fmtSecs(st.dur)}"></button>`).join(""));
}
function fmtSecs(x) { return x < 60 ? `${x}s` : x < 3600 ? `${Math.floor(x / 60)}m ${String(x % 60).padStart(2, "0")}s` : `${Math.floor(x / 3600)}h ${String(Math.floor(x % 3600 / 60)).padStart(2, "0")}m`; }
/* The job ended: a failed one opens on the step that failed, scrolled to its first error. */
function endSteps(status) {
  logEnded = status;
  const last = logSteps[logSteps.length - 1];
  if (status === "failed" && last) {
    if (last.status === "ok") last.status = "bad";
    const bad = logSteps.find(st => st.status === "bad") || last;
    logSteps.forEach(st => { if (!st.el._user) st.el.open = st === bad || st.status === "bad"; });
    paintSteps();
    const err = bad.body.querySelector(".t-error") || bad.el;
    if ($id("logFollow")?.checked) requestAnimationFrame(() => err.scrollIntoView({ block: "center" }));
    return;
  }
  paintSteps();
}

/* "2026-09-30 17:45:09 [ o.k.  ] message" - Write-Log's layout. On screen the date goes
   and the clock and brackets are furniture in muted; the tag takes New-Vhdx's colours. */
const TAG_CLASS = { start: "t-start", get: "t-get", run: "t-run", info: "t-info", warn: "t-warn", "o.k.": "t-ok", error: "t-error", debug: "t-debug", end: "t-end" };
function logLine(text) {
  const div = document.createElement("div");
  div.dataset.raw = text;
  const m = /^(\d{4}-\d\d-\d\d )?(\d\d:\d\d:\d\d) \[ (.{1,5}?)\s* \] (.*)$/.exec(text);
  if (!m) { div.className = "ln"; div.innerHTML = `<span class="ln-msg">${esc(text)}</span>`; return div; }
  const [, , clk, tag, msg] = m;
  div.dataset.tag = tag; div.dataset.msg = msg;
  // Serial console lines arrive as "| text" - the bar is the log's way of saying "echoed".
  const echoed = msg.startsWith("| ");
  div.className = "ln " + (TAG_CLASS[tag] || "t-error") + (echoed ? " echoed" : "") + "";
  div.innerHTML = `<span class="ln-f">${esc(clk)}</span><span class="ln-f">[</span><span class="ln-tag">${esc(tag)}</span><span class="ln-f">]</span><span class="ln-msg">${esc(echoed ? msg.slice(2) : msg)}</span>`;
  return div;
}

/* Measured progress (download bytes, DISM's percentage) goes on the running step's row:
   the stage and the job's percentage, next to where its time is counted. */
let jobProg = null;
/* The percentage first - a long stage name must not push it out of sight - then the detail
   (file, bytes, speed). The job's own label is the step's name already. */
function progPct(p) { const v = typeof p.step === "number" ? p.step : p.pct; return typeof v === "number" ? Math.min(100, Math.max(0, v)) : null; }
function progText(p) {
  const v = progPct(p);
  return [v != null ? Math.floor(v) + "%" : "", p.detail || p.label].filter(Boolean).join(" · ");
}
function showProgress(p) { jobProg = p; if ($id("jobLog")) paintSteps(); }

/* -- Media: what Windows golds are baked from, and where every bake runs -- */

/* lego's provider help in the code palette: section heads as keywords, the variables to
   set as parameters, quoted values and links as strings. */
function highlightHelp(text) {
  return esc(text).split("\n").map(l => /^\S.*:\s*$/.test(l) || /^(Configuration for|Code:|Since:)/.test(l)
      ? `<span class="jbool">${l}</span>`
      : l.replace(/(&quot;[A-Z0-9_]+&quot;)/g, '<span class="jkey">$1</span>').replace(/('[^']*'|https?:\/\/\S+)/g, '<span class="jstr">$1</span>')).join("\n");
}

const acmeForm = { email: "", challenge: "dns-01", dns_provider: "", staging: false, extra_names: [] };

/* The names the certificate is for: the studio's own DNS name first (fixed - it is set
   above), then any added with +. Painted in place, so a typed credential stays. */
function leNamesHtml(fqdn) {
  const extra = acmeForm.extra_names || [];
  return `<span class="le-name fixed" title="The studio's DNS name - change it above">${esc(fqdn || "no DNS name set")}</span>`
    + extra.map((n, i) => `<span class="le-name">${esc(n)}<button type="button" data-le-name-del="${i}" aria-label="Remove ${esc(n)}">×</button></span>`).join("")
    + `<span class="le-name-add"><input id="leNameNew" placeholder="${acmeForm.challenge === "dns-01" ? "studio.example.com or *.example.com" : "studio.example.com"}" spellcheck="false" autocomplete="off">
       <button class="btn sm" type="button" id="leNameAdd" aria-label="Add the name">+</button></span>`;
}

/* A card's actions: a row of their own under the fields, right-aligned, each with its
   glyph - the primary one on the accent, as the studio's own blades do. */
function act(id, icon, label, primary) {
  return `<button class="btn${primary ? " primary" : ""}" type="button" id="${id}"><img src="${primary ? iconSrcOnAccent(icon) : iconSrc(icon)}" alt=""> ${esc(label)}</button>`;
}
function actions(...buttons) { return `<div class="row gs-actions">${buttons.join("")}</div>`; }

/* WinPE from Microsoft: the UUP dump catalog's builds and languages, asked once per page
   visit and kept - the catalog is slow, and its answer changes once a month. */
/* WinPE comes from the newest Windows Server vNext or Windows Server 2025 build (picked in
   WindowsSettings.winpe_from), en-US, always: it only boots the bakes. */
const PE_PRODUCTS = [["ws-insider", "Windows Server vNext"], ["ws2025", "Windows Server 2025"]];
const mediaUi = { peFrom: null, product: "", build: "" };
const uupCache = { builds: {}, langs: {} };
function peSourceLabel(src) {
  const m = /^uup:(\S+) (\S+) (\S+)$/.exec(src || "");
  return m ? `Microsoft (UUP) · ${m[2]}` : src || "";
}
async function fillUupPickers(stale) {
  const sel = $id("peBuildSel"); if (!sel) return;
  try {
    const list = uupCache.builds[mediaUi.product] || (uupCache.builds[mediaUi.product] = (await api("GET", "/uup/builds?product=" + encodeURIComponent(mediaUi.product))).builds);
    if (stale() || !$id("peBuildSel")) return;
    if (!list.length) { mediaUi.build = ""; sel.textContent = "The catalog lists no build"; return; }
    // Server 2025: the newest Patch Tuesday build - not an optional preview. vNext: the newest.
    const b = list.find(x => (x.release || "").endsWith(" B")) || list[0];
    const name = (PE_PRODUCTS.find(p => p[0] === mediaUi.product) || [, mediaUi.product])[1];
    mediaUi.build = b.uuid;
    sel.innerHTML = `<b class="mono">${esc(b.build)}</b> <span class="hint">${esc(name)} · en-US · ${b.release && b.release !== "Insider" ? esc(b.release) + " · " : ""}${esc(new Date(b.created * 1000).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" }))}</span>`;
  } catch (e) { if (!stale() && $id("peUupHint")) { $id("peUupHint").hidden = false; $id("peUupHint").textContent = "The UUP dump catalog did not answer: " + e.message; } }
}
/* -- Media: Windows updates - golds with Keep current follow their ISO's product -- */

const AU_STEP = { pending: "waits for a window", iso: "building the ISO", bake: "baking golds", cleanup: "cleaning up", done: "done", failed: "failed", stopped: "new base build - stays put" };
const AU_DOT = { pending: "idle", iso: "run", bake: "run", cleanup: "run", done: "ok", failed: "bad", stopped: "warn" };

function autoUpdateCard(au) {
  const s = au.settings, runs = au.runs || [];
  const following = Object.entries(au.golds || {}).filter(([, g]) => g.on);
  const active = runs.filter(r => !["done", "failed", "stopped"].includes(r.step));
  const failed = runs.find(r => r.step === "failed");
  const meta = active.length ? `${esc(active[0].product)} ${esc(active[0].to)} - ${AU_STEP[active[0].step]}`
    : !following.length ? "no gold keeps current" : `${following.length} gold${following.length === 1 ? "" : "s"} keep current · ${au.next_window ? "next window " + esc(fmtWhen(au.next_window)) : "no maintenance window"}`;
  const badge = active.some(r => r.job) ? `<span class="pill status run">Running</span>` : failed ? `<span class="pill status warn">Failed</span>` : "";
  const stepText = r => {
    if (r.step === "bake") { const g = r.golds || []; return `baking golds (${g.filter(x => x.to && !x.job).length} of ${g.length})`; }
    if (r.step === "failed") return `failed while ${{ pending: "starting", iso: "building the ISO", bake: "baking", cleanup: "cleaning up" }[r.failed_step] || "running"}`;
    if (r.step === "pending" && r.force) return "starts when nothing else runs";
    return AU_STEP[r.step] || r.step;
  };
  const rows = runs.map(r => `<tr>
    <td><b>${esc(r.product)}</b><div class="hint mono">${esc((r.source_iso || "").split("/").pop())}</div></td>
    <td class="mono">${esc(r.from)} → ${esc(r.to)}</td>
    <td class="muted">${esc(r.release)}</td>
    <td><span class="au-step"><span class="dot ${AU_DOT[r.step] || "idle"}"></span>${esc(stepText(r))}</span>${r.error ? `<div class="hint ${r.step === "failed" ? "err" : ""}">${esc(r.error)}</div>` : ""}</td>
    <td class="muted">${(r.golds || []).length}</td>
    <td class="row-actions">${r.job ? `<button class="btn sm" type="button" data-job-open="${esc(r.job)}"><img src="${iconSrc("log.svg")}" alt=""> Log</button>` : ""}
      ${["pending", "bake", "cleanup"].includes(r.step) && !r.job && !r.force ? `<button class="btn sm" type="button" data-au-start="${esc(r.id)}"><img src="${iconSrc("update.svg")}" alt=""> Start now</button>` : ""}
      ${r.step === "failed" ? `<button class="btn sm" type="button" data-au-retry="${esc(r.id)}"><img src="${iconSrc("update.svg")}" alt=""> Retry</button>` : ""}
      ${["done", "failed", "stopped"].includes(r.step) ? `<button class="btn icon sm" type="button" data-au-dismiss="${esc(r.id)}" title="Remove from the list" aria-label="Remove from the list">${chipRemoveIcon()}</button>` : ""}</td></tr>`).join("");
  const gold = id => (cluster.golds || []).find(g => g.id === id);
  const followRows = following.map(([id, g]) => { const x = gold(id); return `<tr><td class="mono">${esc(id)}</td><td>${esc(x ? x.image_id : "")}</td><td>${esc(g.product || "")}</td><td class="mono">${esc(g.build || "")}</td></tr>`; }).join("");
  return gsCard("md-au", "update.svg", `Windows updates ${infoTip("Windows updates", "Golds with Keep current on (on their card under Golds) follow the product their ISO was built from. A newer Patch Tuesday build of the same product and base build gives one new ISO with the same editions and language; each following gold is baked again from it with its own settings, then the old ISO goes and older golds beyond the kept number are removed - not ones with linked clones or pinned by a design. The check runs every six hours; the work runs in a maintenance window (Studio settings).")}`, meta, `
    <div class="grid-3">
      ${field(`<span class="field-label"><img src="${iconSrc("gold-image.svg")}" alt="">Golds kept per kind${infoTip("Golds kept", "After an update: the newest golds of each kind (image, language, disk size) that stay. 2 keeps the one before as a way back.")}</span>`,
        `<input id="auKeep" type="number" min="1" max="10" value="${s.keep_golds}">`)}
    </div>
    <div class="toggle-grid" style="grid-template-columns:1fr;margin-top:12px">${toggle('id="auVirtio"', `Keep virtio-win current${infoTip("Keep virtio-win current", "With virtio-win on stable (or latest) under Media: in a maintenance window, a newer release of that channel is downloaded into PVE - and WinPE built again, so its storage driver is the new one. New Windows golds take it; golds baked before keep theirs.")}`, s.keep_virtio_current !== false)}</div>
    <div class="toggle-grid" style="grid-template-columns:1fr;margin-top:12px">${toggle('id="auWinpe"', `Keep WinPE current${infoTip("Keep WinPE current", "WinPE is what every Windows bake, deploy and media build boots. In a maintenance window, when the product WinPE is built from has a newer build than the WinPE - or virtio-win a newer release than its driver - the studio builds WinPE again - before the golds' updates run.")}`, s.keep_winpe_current !== false)}</div>
    <div class="toggle-grid" style="grid-template-columns:1fr;margin-top:12px">${toggle('id="auPreviews"', `Include preview releases${infoTip("Preview releases", "Off: only the Patch Tuesday release of each month (B). On: also the optional non-security release later in the month. Insider builds are never followed.")}`, !!s.include_previews)}</div>
    ${following.length ? `<div class="field-group">Keep current</div><div class="table-wrap"><table class="data"><thead><tr><th>Gold</th><th>Image</th><th>Product</th><th>Build</th></tr></thead><tbody>${followRows}</tbody></table></div>` : ""}
    ${runs.length ? `<div class="field-group">Runs</div><div class="table-wrap"><table class="data"><thead><tr><th>Product</th><th>Build</th><th>Release</th><th>Step</th><th>Golds</th><th></th></tr></thead><tbody>${rows}</tbody></table></div>` : ""}
    ${actions(`<button class="btn" type="button" id="auCheck"><img src="${iconSrc("update.svg")}" alt=""> Check now</button>`, act("auSave", "save.svg", "Save", true))}`, "", active.length > 0 || !!failed, badge);
}

function wireAutoUpdate(main) {
  const again = () => renderServerBlade("imagesettings", main);
  const on = (id, fn) => { const el = $id(id); if (el) el.addEventListener("click", fn); };
  on("auSave", async () => {
    try { await api("PUT", "/auto-update", { keep_golds: parseInt($id("auKeep").value, 10) || 2, include_previews: $id("auPreviews").checked, keep_winpe_current: $id("auWinpe").checked, keep_virtio_current: $id("auVirtio").checked }); toast("Saved"); again(); }
    catch (e) { toast(e.message, true); }
  });
  on("auCheck", async e => {
    const b = e.currentTarget; b.disabled = true;
    try { const r = await api("POST", "/auto-update/check"); toast(r.found ? `${r.found} newer build(s) found` : "No newer build for the golds that keep current"); again(); }
    catch (err) { toast(err.message, true); b.disabled = false; }
  });
  const each = (attr, fn) => main.querySelectorAll(`[${attr}]`).forEach(b => b.addEventListener("click", async () => {
    try { await fn(b.getAttribute(attr)); again(); } catch (e) { toast(e.message, true); }
  }));
  each("data-au-start", async id => { await api("POST", `/auto-update/runs/${encodeURIComponent(id)}/start`); toast("Starts as soon as nothing else runs"); });
  each("data-au-retry", async id => { await api("POST", `/auto-update/runs/${encodeURIComponent(id)}/retry`); toast("Retries as soon as nothing else runs"); });
  each("data-au-dismiss", async id => { await api("DELETE", `/auto-update/runs/${encodeURIComponent(id)}`); });
}

async function bladeMedia(main, stale) {
  const [win, isos, bake, c, fod, region, au, golds] = await Promise.all([api("GET", "/settings/windows"), api("GET", "/windows/isos").catch(e => ({ error: e.message, isos: [] })),
    api("GET", "/settings/bake"), refreshInventory(), api("GET", "/settings/fod").catch(() => null), api("GET", "/settings/region").catch(() => ({})),
    api("GET", "/auto-update").catch(() => null), api("GET", "/golds").catch(() => null)]);
  // The ISOs' Golds column needs them - Media can be the first blade opened.
  if (golds) cluster.golds = golds;
  // FoD satellites in the studio's preselected language (Studio settings), en-US without one.
  const fodLang = region.language || "en-US";
  if (stale()) return;
  const inv = c.inventory;
  const pe = win.winpe || {};
  cluster.winpe = !!pe.volid;
  // The card opens on where the current WinPE came from; Microsoft when there is none.
  if (!mediaUi.peFrom) mediaUi.peFrom = pe.volid && pe.source_iso && !pe.source_iso.startsWith("uup:") ? "iso" : "uup";
  /* Proxmox's list of virtio-win releases broken for Windows guests - the server refuses them too. */
  const vioBad = r => { const n = parseInt(String(r || "").replace(/^0\.1\./, ""), 10); return (n >= 215 && n <= 262) || n === 285; };
  /* The release in use and where it stands: in PVE, being fetched, an older copy only, or
     fetched by the next bake. */
  // virtio-win's state for the card head's badge; the meta line keeps the channel and release.
  const vioMeta = () => {
    const set = win.settings.virtio, vio = set === "stable" ? win.stable : set === "latest" ? win.latest : set;
    return esc(set) + (vio && vio !== set ? ` · ${esc(vio)}` : "");
  };
  const vioBadge = () => {
    const set = win.settings.virtio, vio = set === "stable" ? win.stable : set === "latest" ? win.latest : set;
    const job = (cluster.jobs || []).find(j => j.kind === "virtio" && (j.status === "running" || j.status === "queued"));
    const pct = job && job.progress && typeof job.progress.pct === "number" ? ` · ${Math.round(job.progress.pct)} %` : "";
    const here = (win.present || []).slice().sort((a, b) => vioNewer(a, b) ? -1 : 1);
    const where = win.settings.iso_storage || (bake.resolved || {}).iso_storage || "PVE";
    return job ? `<span class="pill status run">Fetching${pct}</span>`
      : vio && here.includes(vio) ? `<span class="pill status ok" title="virtio-win ${esc(vio)} is on ${esc(where)}">In ${esc(where)}</span>`
      : here.length ? `<span class="pill status warn" title="The copy on ${esc(where)} is ${esc(here[0])} - fetched again at the next bake">${esc(vio || set)} available</span>`
      : `<span class="pill status none idle" title="Fetched into PVE at the next Windows bake">Not fetched</span>`;
  };
  // WinPE's: built, building, or behind the newest build / the virtio-win in use.
  const peBadge = () => {
    const job = (cluster.jobs || []).find(j => j.kind === "winpe" && (j.status === "running" || j.status === "queued"));
    const pct = job && job.progress && typeof job.progress.pct === "number" ? ` · ${Math.round(job.progress.pct)} %` : "";
    if (job) return `<span class="pill status run">Building${pct}</span>`;
    if (!pe.volid) return `<span class="pill status none idle" title="Windows golds need it">Not built</span>`;
    return peHint(win) || `<span class="pill status ok">Ready</span>`;
  };
  const vioChoices = [["stable", `stable${win.stable ? " (" + win.stable + ")" : ""}${vioBad(win.stable) ? " · broken per Proxmox" : ""}`],
    ["latest", `latest${win.latest ? " (" + win.latest + ")" : ""}${vioBad(win.latest) ? " · broken per Proxmox" : ""}`]]
    .concat(win.releases.map(r => [r, r + (vioBad(r) ? " · broken per Proxmox" : win.present.includes(r) ? " · in PVE" : "")]));
  const s = bake.settings, r = bake.resolved || {};
  const node = s.node || r.node;
  const stor = content => inv.storages.filter(x => x.node === node && (x.content || "").split(",").includes(content))
    .map(x => [x.storage, `${x.storage} (${x.plugintype}${x.shared === 1 ? ", shared" : ""})`]);
  const bridges = (inv.nodes.find(n => n.node === node)?.bridges || []).map(b => [b.iface, b.iface]).concat(inv.vnets.map(v => [v.vnet, v.vnet + " (SDN)"]));
  const auto = v => v ? `Auto (${v})` : "Auto";
  const readable = isos.isos.filter(i => i.readable);
  // A Windows gold records its ISO as sourceMedia (sourceIso before that).
  const usedBy = volid => readyGolds().filter(g => (goldManifest(g).sourceMedia || goldManifest(g).sourceIso) === volid)
    .map(g => `<span class="pill" title="${esc(goldBuildLabel(g) || g.name)}">${esc(goldShortId(g))}</span>`).join(" ");
  mediaUi.product = win.settings.winpe_from || "ws-insider";

  main.innerHTML = bladeHead("media") + `
    <div class="chips">
      <span class="pill status ${pe.volid ? "on" : "off"}">WinPE ${pe.volid ? "built" : "not built"}</span>
      <span class="pill">Windows ISOs: ${isos.isos.length}${isos.isos.length !== readable.length ? ` (${readable.length} readable)` : ""}</span>
      <span class="pill">virtio-win: ${esc(win.settings.virtio)}${win.settings.virtio === "stable" && win.stable ? " (" + esc(win.stable) + ")" : ""}</span>
      <span class="pill">Bakes run on ${esc(r.node || "?")}</span>
    </div>
    ${gsCard("md-isos", "iso-media.svg", "Windows ISOs", isos.error ? "could not be read" : `${isos.isos.length} on ${esc(isos.node || "")}`, isos.error ? warnBanner(esc(isos.error)) : isos.isos.length ? `
      <div class="table-wrap"><table class="data"><thead><tr><th>ISO</th><th>Storage</th><th>Size</th><th>Studio can read it</th><th>Golds</th><th></th></tr></thead><tbody>
      ${isos.isos.map(i => `<tr><td><div class="name-cell"><img src="${iconSrc("iso-media.svg")}" alt=""><b>${esc(i.file)}</b>${pe.source_iso === i.volid ? ' <span class="pill">WinPE source</span>' : ""}${ISO_KIND_TAG[i.kind] ? ` <span class="pill">${ISO_KIND_TAG[i.kind]}</span>` : ""}</div></td>
        <td class="mono">${esc(i.storage)}</td><td class="mono">${gib(i.size)} GiB</td><td>${pillOn(i.readable ? "yes" : "no", i.readable)}</td>
        <td>${usedBy(i.volid)}</td>
        <td class="row-actions">${i.readable && i.kind === "windows" ? `<button class="btn sm" type="button" data-iso-bake="${esc(i.volid)}"><img src="${iconSrc("gold-image.svg")}" alt=""> Bake a gold</button>` : ""}${pe.volid === i.volid
          ? `<button class="btn icon sm" type="button" disabled title="The WinPE every Windows bake boots - build another WinPE first" aria-label="Delete - the WinPE in use">${trashIcon()}</button>`
          : `<button class="btn icon sm danger-text" type="button" data-iso-delete="${esc(i.volid)}" title="Delete this ISO" aria-label="Delete ${esc(i.file)}">${trashIcon()}</button>`}</td></tr>`).join("")}
      </tbody></table></div>
      <div class="tip-box"><img src="${iconSrc("help.svg")}" alt=""><div>ISOs come from the bake node's ISO storages - upload one in Proxmox VE (a storage's <b>ISO Images → Upload</b> or <b>Download from URL</b>).
        The studio reads them through a read-only mount to list their editions.</div></div>`
      : `<p class="hint">No Windows ISO on ${esc(isos.node || "the bake node")} yet. Upload one in Proxmox VE (a storage's <b>ISO Images → Upload</b> or <b>Download from URL</b>).</p>`, "", true)}
    ${fod ? fodCard(fod, isos, fodLang) : ""}
    ${gsCard("gs-winpe", "os-server-desktop.svg", "Windows: WinPE", pe.volid ? `${esc(pe.volid)} · build ${esc(pe.build)}` : "Windows golds need it", `
      <p class="hint" style="margin-bottom:10px">The Setup environment (boot.wim <b>index 2</b>, the one that can service an offline image) with our startnet.cmd and the
      no-prompt EFI boot image. Every Windows bake boots it twice - to apply the image, and to customize it after sysprep. Build it from Microsoft's own files, or from a Windows ISO you uploaded.</p>
      ${pe.volid ? `<div class="kv-grid" style="margin-bottom:12px"><div>WinPE</div><div class="kv-val">${esc(pe.volid)}</div><div>Built from</div><div class="kv-val">${esc(peSourceLabel(pe.source_iso))}</div>
        <div>Build</div><div class="kv-val">${esc(pe.build)} ${peHint(win)}</div>
        <div>vioscsi</div><div class="kv-val">${pe.vioscsi ? "virtio-win " + esc(pe.vioscsi) + " built in - VM builds need no virtio ISO" : "not built in - rebuild to carry it"}</div><div>Built</div><div class="kv-val">${esc(when(pe.built))} on ${esc(pe.node)}</div></div>` : ""}
      <div class="field-like" style="margin-bottom:12px">${fieldLabel("download.svg", "Build from")}
        <div class="ov-seg" role="group" aria-label="Build WinPE from">
          <button type="button" class="btn${mediaUi.peFrom === "uup" ? " on" : ""}" data-pe-from="uup">Microsoft</button><button type="button" class="btn${mediaUi.peFrom === "iso" ? " on" : ""}" data-pe-from="iso">A Windows ISO</button>
        </div></div>
      ${mediaUi.peFrom === "uup" ? `
      <div class="grid-2">
        ${field(`<span class="field-label"><img src="${iconSrc("os-server-core.svg")}" alt="">Product${infoTip("Why Windows Server vNext", "Insider builds ship their edition image at the full build, so the WinPE distilled from its WinRE always has the newest DISM - and DISM may be newer than the images it services, never older. Windows Server 2025's edition image is the release build (26100.1) in every set, so its WinPE stays at the September 2024 DISM. WinPE only boots the bakes and the media worker; the images it services are unaffected by the Insider label.")}</span>`, `<div class="pe-product"><select id="peProduct">${opts(PE_PRODUCTS, mediaUi.product)}</select>${mediaUi.product === "ws-insider" ? `<span class="pill status on">Recommended</span>` : ""}</div>`)}
        ${field(`<span class="field-label"><img src="${iconSrc("update.svg")}" alt="">Build${infoTip("WinPE from Microsoft", "Always en-US and the newest build the UUP dump catalog lists (for Windows Server 2025, the newest Patch Tuesday build) - WinPE only boots the bakes, whatever their language. The studio downloads a Core edition's ESD straight from Microsoft and checks its SHA-1 - no Windows ISO needed.")}</span>`,
          `<div class="pe-newest" id="peBuildSel" aria-live="polite">Asking the catalog…</div>`)}
      </div>
      <p class="hint err" id="peUupHint" hidden></p>
      ${actions(act("peBuildUup", "download.svg", pe.volid ? "Rebuild WinPE" : "Build WinPE", !pe.volid))}`
      : `<div class="grid-2">${field(fieldLabel("iso-media.svg", "Distil from"), `<select id="peIso">${readable.length ? opts(readable.map(i => [i.volid, i.file]), pe.source_iso || readable[0].volid) : '<option value="">No readable Windows ISO in PVE yet</option>'}</select>`)}</div>
      ${actions(act("peBuild", "os-window.svg", pe.volid ? "Rebuild WinPE" : "Build WinPE", !pe.volid))}`}`, "", !pe.volid, peBadge())}
    ${gsCard("gs-virtio", "integration.svg", "Windows: virtio-win", vioMeta(), `
      <div class="grid-2">${field(fieldLabel("update.svg", "Release baked into Windows golds"), `<select id="vioSel">${opts(vioChoices, win.settings.virtio)}</select>
        <span class="hint">Drivers and QEMU guest agent. "stable" follows the virtio-win project's stable channel; a pinned release stays put.</span>`)}</div>
      ${actions(act("vioFetch", "download.svg", "Fetch into PVE now"), act("vioSave", "save.svg", "Save", true))}`, "", false, vioBadge())}
`;

  const on = (id, ev, fn) => { const el = $id(id); if (el) el.addEventListener(ev, fn); };
  on("fodSave", "click", async () => {
    try {
      const body = {};
      main.querySelectorAll("[data-fod-slot]").forEach(el => { body[el.dataset.fodSlot] = el.value; });
      await api("PUT", "/settings/fod", body);
      toast("Saved"); renderServerBlade("media", main);
    } catch (e) { toast(e.message, true); }
  });
  main.querySelectorAll("[data-fod-build]").forEach(b => b.addEventListener("click", async () => {
    try { const { id } = await api("POST", "/fod/build", { slot: b.dataset.fodBuild, lang: fodLang }); openJob(id); }
    catch (e) { toast(e.message, true); }
  }));
  main.querySelectorAll("[data-iso-delete]").forEach(b => b.addEventListener("click", async () => {
    const iso = isos.isos.find(i => i.volid === b.dataset.isoDelete); if (!iso) return;
    const golds = usedBy(iso.volid);
    if (!await confirmDelete("isos", `Delete ${iso.file}?`, [["del", `${iso.file} on ${iso.storage}`, gib(iso.size) + " GiB"]].concat(golds ? [["keep", "Golds baked from it", golds]] : []), "Delete ISO")) return;
    try { await api("DELETE", "/windows/isos?volid=" + encodeURIComponent(iso.volid)); toast(`Deleted ${iso.file}`); renderServerBlade("media", main); }
    catch (e) { toast(e.message, true); }
  }));
  main.querySelectorAll("[data-iso-bake]").forEach(b => b.addEventListener("click", () => {
    winForm.iso = b.dataset.isoBake; winForm.index = null; winForm.edition = ""; openBake("windows");
  }));
  main.querySelectorAll("[data-pe-from]").forEach(b => b.addEventListener("click", () => { mediaUi.peFrom = b.dataset.peFrom; renderServerBlade("media", main); }));
  if (mediaUi.peFrom === "uup") fillUupPickers(stale);
  on("peBuildUup", "click", async () => {
    const uuid = mediaUi.build;
    if (!uuid) return toast("Wait for the catalog's newest build", true);
    const build = (uupCache.builds[mediaUi.product] || []).find(b => b.uuid === uuid);
    try { const { id } = await api("POST", "/winpe/build-uup", { uuid, lang: "en-us", build: build ? build.build : "" }); openJob(id); }
    catch (e) { toast(e.message, true); }
  });
  on("peProduct", "change", async () => {
    try { await api("PUT", "/settings/windows", { ...win.settings, winpe_from: $id("peProduct").value }); renderServerBlade("media", main); }
    catch (e) { toast(e.message, true); }
  });
  on("peBuild", "click", async () => {
    if (!$id("peIso").value) return toast("Pick a Windows ISO first", true);
    try { const { id } = await api("POST", "/winpe/build", { volid: $id("peIso").value }); openJob(id); } catch (e) { toast(e.message, true); }
  });
  on("vioSave", "click", async () => { try { await api("PUT", "/settings/windows", { ...win.settings, virtio: $id("vioSel").value }); toast("Saved"); } catch (e) { toast(e.message, true); } });
  on("vioFetch", "click", async () => {
    try { await api("PUT", "/settings/windows", { ...win.settings, virtio: $id("vioSel").value }); const { id } = await api("POST", "/virtio/fetch"); openJob(id); }
    catch (e) { toast(e.message, true); }
  });
}

/* -- Image settings: how and where images are built, and how Windows golds stay current -- */
async function bladeImageSettings(main, stale) {
  const [bake, c, au] = await Promise.all([api("GET", "/settings/bake"), refreshInventory(), api("GET", "/auto-update").catch(() => null)]);
  if (stale()) return;
  const inv = c.inventory;
  const s = bake.settings, r = bake.resolved || {};
  const node = s.node || r.node;
  const stor = content => inv.storages.filter(x => x.node === node && (x.content || "").split(",").includes(content))
    .map(x => [x.storage, `${x.storage} (${x.plugintype}${x.shared === 1 ? ", shared" : ""})`]);
  const bridges = (inv.nodes.find(n => n.node === node)?.bridges || []).map(b => [b.iface, b.iface]).concat(inv.vnets.map(v => [v.vnet, v.vnet + " (SDN)"]));
  const auto = v => v ? `Auto (${v})` : "Auto";
  main.innerHTML = bladeHead("imagesettings") + `
    ${gsCard("gd-where", "settings.svg", "Build environment", `${esc(r.node || "")} · ${esc(r.disk_storage || "")} · ${esc(r.bridge || "")}`, `
      <div class="grid-3">
        ${field(fieldLabel("servers.svg", "Node"), `<select id="bsNode">${opts(inv.nodes.filter(n => n.status === "online").map(n => [n.node, n.node]), s.node, auto(r.node))}</select>`)}
        ${field(fieldLabel("disk.svg", "Gold disks (images)"), `<select id="bsDisk">${opts(stor("images"), s.disk_storage, auto(r.disk_storage))}</select>`)}
        ${field(fieldLabel("storage.svg", "Cloud image cache (import)"), `<select id="bsImport">${opts(stor("import"), s.import_storage, auto(r.import_storage))}</select>`)}
        ${field(fieldLabel("iso-media.svg", "ISOs: WinPE, virtio-win, media (iso)"), `<select id="bsIso">${opts(stor("iso"), s.iso_storage, auto(r.iso_storage))}</select>`)}
        ${field(fieldLabel("ram.svg", "Memory (MiB)"), `<input id="bsMem" type="number" min="1024" step="512" value="${s.memory_mb}">`)}
        ${field(fieldLabel("cpu.svg", "Cores"), `<input id="bsCores" type="number" min="1" value="${s.cores}">`)}
      </div>
      <div class="toggle-grid" style="grid-template-columns:1fr">${toggle('id="bsHost"', `Bake and worker VMs on the node's own CPU${infoTip("CPU type host", "Bake, WinPE and media worker VMs never migrate, so they get the node's CPU as it is (host) - every instruction it has. Windows ones without nested virtualization (-nested-virt): Setup decides nothing about VBS from a CPU the clones may not have. On a node that is itself a VM, and on PVE before 9.1, they get x86-64-v3.")}`, s.bake_host !== false)}</div>
      <div class="field-group">Network</div>
      <div class="grid-3">
        ${field(fieldLabel("vnet.svg", "Network"), `<select id="bsBridge">${opts(bridges, s.bridge, auto(r.bridge))}</select>`)}
        ${field(fieldLabel("vlan.svg", "VLAN tag"), `<input id="bsVlan" type="number" min="1" max="4094" placeholder="none" value="${s.vlan ?? ""}">`)}
        ${field(`<span class="field-label"><img src="${iconSrc("static-ip.svg")}" alt="">Linux addresses${infoTip("Linux bake addresses", "For a bake network without DHCP: one address (10.10.0.60/24) or a range (10.10.0.60-69/24). Each Linux bake takes the first address no running bake holds, so a range of 4 lets 4 bakes run side by side. Reserve them for the bakes. Empty: DHCP. Windows bakes stay offline and need none.")}</span>`,
          `<input id="bsLinAddr" placeholder="DHCP - or 10.10.0.60-69/24" value="${esc(s.linux_address || "")}">`)}
        ${field(fieldLabel("vnet.svg", "Gateway"), `<input id="bsLinGw" placeholder="10.10.0.1" value="${esc(s.linux_gateway || "")}">`)}
        ${field(fieldLabel("dns.svg", "DNS"), `<input id="bsLinDns" placeholder="10.10.0.1" value="${esc((s.linux_dns || []).join(", "))}">`)}
      </div>
      <div class="tip-box"><img src="${iconSrc("help.svg")}" alt=""><div>The Linux bake VM needs internet access on its network - by DHCP, or by the addresses above. "Auto" prefers shared storage, so one gold serves every node.</div></div>
      ${actions(bake.problem ? `<span class="hint err gs-actions-note">${esc(bake.problem)}</span>` : "", act("bsSave", "save.svg", "Save", true))}`, "", false)}
    ${au ? autoUpdateCard(au) : ""}`;
  const on = (id, ev, fn) => { const el = $id(id); if (el) el.addEventListener(ev, fn); };
  on("bsSave", "click", async () => {
    const vlan = parseInt($id("bsVlan").value, 10);
    try {
      await api("PUT", "/settings/bake", { node: $id("bsNode").value, disk_storage: $id("bsDisk").value, import_storage: $id("bsImport").value,
        iso_storage: $id("bsIso").value, bridge: $id("bsBridge").value, vlan: Number.isFinite(vlan) ? vlan : null,
        cpu: s.cpu, cpu_windows: s.cpu_windows, bake_host: $id("bsHost").checked, memory_mb: parseInt($id("bsMem").value, 10) || 4096,
        cores: parseInt($id("bsCores").value, 10) || 2, timeout_min: s.timeout_min,
        linux_address: $id("bsLinAddr").value.trim(), linux_gateway: $id("bsLinGw").value.trim(),
        linux_dns: $id("bsLinDns").value.split(/[,;\s]+/).map(x => x.trim()).filter(Boolean) });
      toast("Saved"); renderServerBlade("imagesettings", main);
    } catch (e) { toast(e.message, true); }
  });
  wireAutoUpdate(main);
}

/* -- Studio settings: the studio's own name and certificate -- */

const regionLocales = cat => Object.entries(cat.locales).sort((a, b) => a[1].localeCompare(b[1]));

/* Studio settings' last card (design B): this build against the newest release, then the
   releases as a timeline with their notes; the update itself is a job (waits for the others,
   checks the SHA-256, a root helper swaps the binary and restarts the studio). */
function versionCard(v) {
  if (!v) return "";
  if (v.channel === "development") return versionCardDev(v);
  const rels = v.releases || [];
  const cur = v.version, latest = rels[0];
  const when = iso => iso ? new Date(iso).toLocaleDateString(undefined, { month: "short", day: "numeric", year: "numeric" }) : "";
  const mb = b => b ? (b / 1e6).toFixed(1) + " MB" : "";
  const kind = { new: "New", fix: "Fixed", chg: "Changed" };
  const notes = r => (r.notes || []).length ? `<ul class="ver-notes">${r.notes.slice(0, 8).map(([k, t]) => `<li>${k ? `<span class="ver-k ${esc(k)}">${kind[k]}</span>` : ""}${esc(t)}</li>`).join("")}</ul>` : "";
  const state = v.state === "update" ? `<span class="pill status warn">Update</span>` : v.state === "current" ? `<span class="pill status ok">Up to date</span>` : "";
  const meta = v.state === "update" ? `${esc(latest.version)} available` : v.state === "current" ? "up to date" : v.state === "none" ? "no release published yet" : "GitHub not reachable";
  const newest = v.state === "update" || v.state === "current";
  const box = (label, ver, sub, on) => `<div class="ver-box${on ? " on" : ""}"><div class="ver-l">${label}</div><div class="ver-v mono">${esc(ver)}</div><div class="hint">${sub}</div></div>`;
  const body = `
    <div class="ver-cmp">
      ${box("Installed", cur, `${v.commit ? `<span class="mono">${esc(v.commit)}</span>` : ""}`, false)}
      <span class="ver-arrow">${v.state === "update" ? "→" : "="}</span>
      ${newest ? box(v.state === "update" ? "Available" : "Newest", latest.version, [when(latest.published), mb(latest.asset_size), v.main_ahead ? `main +${v.main_ahead} not released` : ""].filter(Boolean).join(" · "), v.state === "update")
        : box("Newest", "-", v.state === "none" ? "no release on GitHub yet" : "GitHub not reachable", false)}
    </div>
    ${rels.length ? `<ul class="ver-tl">${rels.slice(0, 6).map(r => {
      const mine = r.version === cur, ahead = !mine && rels.indexOf(r) < rels.findIndex(x => x.version === cur) || (!rels.some(x => x.version === cur) && v.state === "update" && r === latest);
      return `<li class="${mine ? "cur" : ahead ? "nxt" : ""}"><div class="ver-h"><b class="mono">${esc(r.version)}</b><span>${esc(when(r.published))}${mine ? " · installed" : ""}</span></div>${notes(r)}</li>`;
    }).join("")}</ul>` : ""}
    ${verChannel(v)}
    <div class="toggle-grid" style="grid-template-columns:1fr;margin-top:12px">${toggle('id="upAuto"', `Install updates automatically${infoTip("Automatic updates", "In a maintenance window (Maintenance windows), when a newer release is out and no job runs, the studio installs it the same way as the button: it checks the release's SHA-256, a root helper in the container checks it again against GitHub, swaps the binary (the old one stays as pve-vm-studio.prev) and restarts the studio. Sessions survive the restart.")}`, !!v.auto)}</div>
    ${actions(`<span class="hint gs-actions-note">checked ${esc(when(v.checked))}</span>`,
      `${latest && latest.url ? `<a class="btn" href="${esc(latest.url)}" target="_blank" rel="noopener"><img src="${iconSrc("log.svg")}" alt=""> Release notes on GitHub</a>` : ""}
       <button class="btn" type="button" id="verCheck"><img src="${iconSrc("update.svg")}" alt=""> Check now</button>
       ${v.state === "update" ? `<button class="btn primary" type="button" id="verUpdate" data-tag="${esc(latest.tag)}"><img src="${iconSrcOnAccent("download.svg")}" alt=""> Update to ${esc(latest.version)}</button>` : ""}`)}`;
  return gsCard("gs-version", "update.svg", "Version", meta, body, "", true, state);
}

/* Troubleshooting tools - only with debug_tools = true in the studio's config.toml, so an
   install never shows them and nobody switches them on from the browser. */
function debugCard(worker) {
  const on = [worker.keep_downloads && "downloads kept"].filter(Boolean);
  return gsCard("gs-debug", "search.svg", `Debug tools ${infoTip("Debug tools", "For troubleshooting, shown because config.toml has debug_tools = true. Remove that line and restart the studio: the card goes and every tool switches off.")}`, on.length ? on.join(" · ") : "all off", `
    <div class="toggle-grid" style="grid-template-columns:1fr">${toggle('id="dbgKeep"', `Keep downloads${infoTip("Keep downloads", "Every file a Windows media, WinPE or Features on Demand build downloads stays in the work volume (work/uup-files), and the next build of the same files downloads nothing. Off: a build uses them up and the rest goes after six idle hours.")}`, !!worker.keep_downloads)}</div>
    ${actions(`<button class="btn" type="button" id="dbgClear"${worker.downloads_bytes ? "" : " disabled"} title="Deletes work/uup-files now - the next build downloads again"><img src="${iconSrcDanger("trash.svg")}" alt=""> Clear downloads${worker.downloads_bytes ? ` · ${(worker.downloads_bytes / 1e9).toFixed(1)} GB` : ""}</button>`,
      `<button class="btn" type="button" data-dbg-rebuild="winpe"><img src="${iconSrc("update.svg")}" alt=""> Rebuild last WinPE</button>`,
      `<button class="btn" type="button" data-dbg-rebuild="media"><img src="${iconSrc("update.svg")}" alt=""> Rebuild last Windows media</button>`,
      act("dbgSave", "save.svg", "Save", true))}`, "", false);
}

/* Stable (releases) or Development (CI's build of every commit on main - untested). */
function verChannel(v) {
  return `<div class="field-like" style="margin-top:14px"><span class="field-label"><img src="${iconSrc("update.svg")}" alt="">Channel${infoTip("Update channel", "Stable: the studio's releases, tested. Development: the newest commit on main, built automatically by GitHub Actions and not tested - for trying fixes before they are released. Switching back to Stable offers the newest release again.")}</span>
    <div class="ov-seg" role="group" aria-label="Update channel">${[["stable", "Stable"], ["development", "Development"]].map(([k, l]) =>
      `<button type="button" class="btn${v.channel === k ? " on" : ""}" data-ver-channel="${k}">${l}</button>`).join("")}</div></div>`;
}

/* The Version card on the development channel: this build against CI's build of main, the
   commits in between as the changelog. */
function versionCardDev(v) {
  const d = v.development || null;
  const when = iso => iso ? new Date(iso).toLocaleDateString(undefined, { month: "short", day: "numeric", year: "numeric" }) : "";
  const state = v.state === "update" ? `<span class="pill status warn">Update</span>` : v.state === "current" ? `<span class="pill status ok">Up to date</span>` : "";
  const meta = !d ? "no development build published yet" : v.state === "update" ? `development build ${esc(d.commit)} available` : "up to date with main";
  const box = (label, ver, sub, on) => `<div class="ver-box${on ? " on" : ""}"><div class="ver-l">${label}</div><div class="ver-v mono">${esc(ver)}</div><div class="hint">${sub}</div></div>`;
  const body = `
    <div class="ver-cmp">
      ${box("Installed", (v.commit || "-").replace(/-dirty$/, ""), `v${esc(v.version)}${/-dirty$/.test(v.commit || "") ? " · local changes" : ""}`, false)}
      <span class="ver-arrow">${v.state === "update" ? "→" : "="}</span>
      ${d ? box("Development build", d.commit, [when(d.release.published), d.ahead ? `${d.ahead} commit${d.ahead === 1 ? "" : "s"} newer` : ""].filter(Boolean).join(" · "), v.state === "update")
        : box("Development build", "-", "none published yet", false)}
    </div>
    ${d && (d.commits || []).length ? `<ul class="ver-tl">${d.commits.map((c, i) => `<li class="${i === 0 ? "nxt" : ""}"><div class="ver-h"><b class="mono">${esc(c.sha)}</b><span>${esc(when(c.date))}</span></div><ul class="ver-notes"><li>${esc(c.message)}</li></ul></li>`).join("")}
      <li class="cur"><div class="ver-h"><b class="mono">${esc((v.commit || "").replace(/-dirty$/, ""))}</b><span>installed</span></div></li></ul>` : ""}
    ${verChannel(v)}
    <div class="toggle-grid" style="grid-template-columns:1fr;margin-top:12px">${toggle('id="upAuto"', `Install updates automatically${infoTip("Automatic updates", "In a maintenance window, when a newer build is out on this channel and no job runs, the studio installs it the same way as the button. On Development that is every new commit on main.")}`, !!v.auto)}</div>
    ${actions(`<span class="hint gs-actions-note">checked ${esc(when(v.checked))}</span>`,
      `${d && d.release.url ? `<a class="btn" href="${esc(d.release.url)}" target="_blank" rel="noopener"><img src="${iconSrc("log.svg")}" alt=""> Build on GitHub</a>` : ""}
       <button class="btn" type="button" id="verCheck"><img src="${iconSrc("update.svg")}" alt=""> Check now</button>
       ${v.state === "update" ? `<button class="btn primary" type="button" id="verUpdate" data-tag="development"><img src="${iconSrcOnAccent("download.svg")}" alt=""> Update to ${esc(d.commit)}</button>` : ""}`)}`;
  return gsCard("gs-version", "update.svg", "Version", meta, body, "", true, state);
}

/* -- Studio settings: maintenance windows, mail, notifications -- */

const MW_DAYS = [["mon", "Mon"], ["tue", "Tue"], ["wed", "Wed"], ["thu", "Thu"], ["fri", "Fri"], ["sat", "Sat"], ["sun", "Sun"]];
/* The rows being edited: kept across repaints until saved. */
const maintUi = { rows: null };

function fmtWhen(iso) {
  if (!iso) return "";
  const d = new Date(iso);
  return d.toLocaleString(undefined, { weekday: "short", month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", hour12: clockFmt !== "24h" });
}

function maintRowsHtml() {
  const rows = maintUi.rows || [];
  if (!rows.length) return `<p class="hint mw-empty">No window - the studio never updates itself or Windows golds on its own.</p>`;
  return rows.map((w, i) => `<div class="mw-row">
    <div class="ov-seg mw-days" role="group" aria-label="Days">${MW_DAYS.map(([k, l]) => `<button type="button" class="btn${w.days.includes(k) ? " on" : ""}" data-mw-day="${i}" data-day="${k}" aria-pressed="${w.days.includes(k)}">${l}</button>`).join("")}</div>
    <div class="mw-times"><input type="time" data-mw-start="${i}" value="${esc(w.start)}" aria-label="Start"><span class="mw-dash">to</span><input type="time" data-mw-end="${i}" value="${esc(w.end)}" aria-label="End"></div>
    ${toggle(`data-mw-patch="${i}"`, `Patch week only${infoTip("Patch week only", "The window opens only from Patch Tuesday (the second Tuesday of the month) to the Monday after it.")}`, !!w.patch_week_only, false, "", "mw-patch")}
    <button class="btn icon sm danger-text" type="button" data-mw-del="${i}" title="Remove this window" aria-label="Remove this window">${trashIcon()}</button>
  </div>`).join("");
}

function maintCard(m) {
  const meta = m.open ? `open now, until ${esc(m.open)}` : m.next ? `next ${esc(fmtWhen(m.next))}` : "none - nothing runs on its own";
  const badge = m.open ? `<span class="pill status on">Open</span>` : "";
  return gsCard("gs-maint", "clock.svg", `Maintenance windows ${infoTip("Maintenance windows", "When the studio may do work nobody started: its own update (when Install updates automatically is on), then the Windows golds that keep current. Work starts only inside a window; at its end no new step starts, and one already running finishes. An end before the start runs past midnight. Times are the studio's" + (m.zone ? " (" + m.zone + ")" : "") + ".")}`, meta, `
    <div id="mwRows" class="mw-rows">${maintRowsHtml()}</div>
    ${actions(`<button class="btn" type="button" id="mwAdd"><img src="${iconSrc("clock.svg")}" alt=""> Add a window</button>`, act("mwSave", "save.svg", "Save", true))}`, "", false, badge);
}

function wireMaint(main) {
  const box = $id("mwRows");
  if (!box) return;
  const repaint = () => { box.innerHTML = maintRowsHtml(); };
  box.addEventListener("click", e => {
    const d = e.target.closest("[data-mw-day]");
    if (d) {
      const w = maintUi.rows[+d.dataset.mwDay], k = d.dataset.day;
      w.days = w.days.includes(k) ? w.days.filter(x => x !== k) : MW_DAYS.map(x => x[0]).filter(x => x === k || w.days.includes(x));
      d.classList.toggle("on", w.days.includes(k)); d.setAttribute("aria-pressed", w.days.includes(k));
      return;
    }
    const del = e.target.closest("[data-mw-del]");
    if (del) { maintUi.rows.splice(+del.dataset.mwDel, 1); repaint(); }
  });
  box.addEventListener("change", e => {
    const t = e.target;
    if (t.dataset.mwStart != null) maintUi.rows[+t.dataset.mwStart].start = t.value;
    else if (t.dataset.mwEnd != null) maintUi.rows[+t.dataset.mwEnd].end = t.value;
    else if (t.dataset.mwPatch != null) maintUi.rows[+t.dataset.mwPatch].patch_week_only = t.checked;
  });
  const on = (id, fn) => { const el = $id(id); if (el) el.addEventListener("click", fn); };
  on("mwAdd", () => { maintUi.rows.push({ days: MW_DAYS.map(x => x[0]), start: "01:00", end: "06:00", patch_week_only: false }); repaint(); });
  on("mwSave", async () => {
    try { await api("PUT", "/settings/maintenance", { windows: maintUi.rows }); maintUi.rows = null; toast("Saved"); renderServerBlade("studio", main); }
    catch (err) { toast(err.message, true); }
  });
}

function mailCard(m, notif) {
  const s = m.settings, st = m.status || {};
  const failed = s.enabled && st.last_error && (!st.last_ok || st.last_error_at > st.last_ok);
  const on = !!s.enabled;
  const meta = !on ? "off" : s.host ? `${esc(s.host)}:${s.port} · to ${esc(s.to.join(", ") || "nobody")}` : "on, not filled in";
  const badge = failed ? `<span class="pill status warn" title="${esc(st.last_error)}">Send failed</span>` : on && mailReady(s) ? `<span class="pill status on">On</span>` : "";
  const dis = on ? "" : " disabled";
  return gsCard("gs-mail", "users.svg", `Mail ${infoTip("Mail", "Notifications go to a smart host - Proxmox Mail Gateway, an Exchange relay, a Postfix - without signing in: the smart host has to accept mail from the studio's address. Switched on, every field is required.")}`, meta, `
    <div class="toggle-grid" style="grid-template-columns:1fr">${toggle('id="mlEnabled"', "Send mail", on)}</div>
    ${failed ? `<p class="hint err" style="margin-top:10px">Last send failed ${esc(when(st.last_error_at))}: ${esc(st.last_error)}</p>` : ""}
    <div class="grid-3" id="mlFields" style="margin-top:12px">
      ${field(fieldLabel("servers.svg", "Smart host"), `<input id="mlHost" placeholder="pmg.example.com" value="${esc(s.host)}"${dis}>`)}
      ${field(fieldLabel("vnet.svg", "Port"), `<input id="mlPort" type="number" min="1" max="65535" value="${s.port || 25}"${dis}>`)}
      ${field(`<span class="field-label"><img src="${iconSrc("security.svg")}" alt="">Security${infoTip("Security", "None: plain SMTP, usual for a relay inside the network (port 25). STARTTLS: upgrades the connection and refuses to send without it (port 25 or 587). TLS: encrypted from the start (port 465).")}</span>`,
        `<select id="mlSec"${dis}>${opts([["none", "None"], ["starttls", "STARTTLS"], ["tls", "TLS"]], s.security || "none")}</select>`)}
      ${field(fieldLabel("users.svg", "Display name"), `<input id="mlFromName" placeholder="PVE VM Studio" value="${esc(s.from_name ?? "PVE VM Studio")}" maxlength="80"${dis}>`)}
      ${field(fieldLabel("users.svg", "From"), `<input id="mlFrom" placeholder="pve-vm-studio@example.com" value="${esc(s.from)}"${dis}>`)}
      ${field(fieldLabel("users.svg", "To"), `<div class="ml-to" id="mlToBox">${(mlTo = [...(s.to || [])]).map((t, i) => mlToChip(t, i)).join("")}<input id="mlTo" placeholder="${(s.to || []).length ? "" : "admins@example.com"}" aria-label="Add a recipient" autocomplete="off" spellcheck="false"${dis}></div>`)}
      ${field(fieldLabel("monitor.svg", "Theme"), `<div class="ml-theme"><select id="mlTheme">${opts((m.themes || []).map(t => [t.id, t.name]), s.theme || "proxmox_dark")}</select>
        <button class="btn" type="button" id="mlPreview"><img src="${iconSrc("search.svg")}" alt=""> Preview</button></div>`)}
    </div>
    <div class="toggle-grid" style="grid-template-columns:1fr;margin-top:12px">${toggle('id="mlVerify"', `Check the smart host's certificate${infoTip("Certificate check", "Off for a smart host whose certificate the studio cannot verify - one it made itself, or from an internal CA. Only matters with STARTTLS or TLS.")}`, s.verify_cert !== false, !on)}</div>
    ${mailLog(m.log || [], notif)}
    ${actions(`<button class="btn" type="button" id="mlTest"${dis}><img src="${iconSrc("users.svg")}" alt=""> Send test mail</button>`, act("mlSave", "save.svg", "Save", true))}`, "", !on || !mailReady(s), badge);
}

/* What went to the smart host and what it answered - one row per mail, newest first, each
   opening to its envelope and the SMTP reply in the job log's own lines. Only what the
   studio saw: the envelope it sent, the final reply (or why there was none), the time. */
function mailLog(rows, notif) {
  const label = Object.fromEntries(((notif && notif.events) || []).map(e => [e.key, e.label]));
  label.test = "Test mail";
  const failed = rows.filter(r => !r.ok).length;
  const meta = rows.length ? `${rows.length} newest${failed ? ` · ${failed} not sent` : ""}` : "";
  const t = iso => new Date(iso).toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false });
  const ln = (at, tag, cls, msg) => `<div class="ln t-${cls}"><span class="ln-f">${t(at)}</span><span class="ln-f">[</span><span class="ln-tag">${tag}</span><span class="ln-f">]</span><span class="ln-msg">${esc(msg)}</span></div>`;
  const code = r => r.code == null ? "—" : String(r.code);
  const tone = r => r.ok ? "ok" : r.code != null && r.code < 500 ? "warn" : "bad";
  const body = rows.length ? `<div class="ml-log">${rows.map(r => `
    <details class="job-step ml-row s-${tone(r)}">
      <summary><span class="job-dot"></span>
        <span class="ml-main"><span class="step-name">${esc(r.subject)}</span><span class="step-n">${esc(label[r.event] || r.event)} · to ${esc(r.recipients.join(", "))}</span></span>
        <span class="ml-code c-${tone(r)}">${code(r)}</span>
        <span class="step-took">${esc(when(r.at))}</span></summary>
      <div class="job-log">
        ${ln(r.at, "mail ", "get", `${r.sender} → ${r.recipients.join(", ")}`)}
        ${ln(r.at, "smtp ", "run", `${r.host} · ${r.security === "none" ? "plain SMTP" : r.security.toUpperCase()} · ${r.took_ms} ms`)}
        ${r.ok ? (r.reply || "").split("\n").map(l => ln(r.at, "o.k. ", "ok", `${r.code} ${l}`)).join("")
          : `${r.reply ? r.reply.split("\n").map(l => ln(r.at, "smtp ", "warn", `${r.code} ${l}`)).join("") : ""}${ln(r.at, "error", "error", r.error)}`}
      </div>
    </details>`).join("")}</div>` : `<p class="hint">Nothing sent yet.</p>`;
  return `<div class="section collapsible ${isNestedOpen("gs-mail-log", false) ? "" : "collapsed"}" style="margin-top:12px"><div class="section-head" data-nested="gs-mail-log"><span class="section-chevron">${chevron()}</span>
    <img src="${iconSrc("log.svg")}" alt=""> Sent mail<span class="section-meta">${meta}</span></div><div class="section-body">${body}</div></div>`;
}

/* A sample mail in each of the studio's themes: the theme picker inside switches the
   frame, "Use this theme" puts it into the card (Save keeps it). */
function openMailPreview(themes, current, use) {
  let theme = current || "proxmox_dark";
  const ov = document.createElement("div");
  ov.className = "overlay open";
  ov.innerHTML = `<div class="modal ml-preview" role="dialog" aria-modal="true" aria-labelledby="mlPvTitle">
    <div class="ml-pv-head"><span class="card-icon"><img src="${iconSrc("users.svg")}" alt=""></span><h2 id="mlPvTitle">Mail preview</h2>
      <select id="mlPvTheme" aria-label="Theme">${opts(themes.map(t => [t.id, t.name]), theme)}</select></div>
    <iframe class="ml-pv-frame" title="Sample mail" sandbox></iframe>
    <div class="actions"><button class="btn" type="button" data-pv-close>Close</button>
      <button class="btn primary" type="button" data-pv-use><img src="${iconSrcOnAccent("save.svg")}" alt=""> Use this theme</button></div>
  </div>`;
  const frame = ov.querySelector("iframe");
  const load = async () => {
    try {
      const r = await fetch("/api/mail/preview?theme=" + encodeURIComponent(theme), { credentials: "same-origin" });
      frame.srcdoc = await r.text();
    } catch (e) { toast(e.message, true); }
  };
  const close = () => { document.removeEventListener("keydown", key, true); ov.remove(); };
  const key = e => { if (e.key === "Escape") { e.stopPropagation(); close(); } };
  ov.querySelector("#mlPvTheme").addEventListener("change", e => { theme = e.target.value; load(); });
  ov.addEventListener("click", e => {
    if (e.target.closest("[data-pv-close]") || e.target === ov) return close();
    if (e.target.closest("[data-pv-use]")) { use(theme); toast("Theme picked - Save keeps it"); close(); }
  });
  document.addEventListener("keydown", key, true);
  document.body.appendChild(ov);
  load();
}

/* The recipients: one chip each; Enter, comma or space adds what is typed, Backspace in an
   empty box takes the last one back. */
let mlTo = [];
function mlToChip(t, i) {
  return `<span class="chip">${esc(t)}<button class="chip-x" type="button" data-mlto-x="${i}" title="Remove ${esc(t)}" aria-label="Remove ${esc(t)}">${chipRemoveIcon()}</button></span>`;
}
function mlToPaint() {
  const box = $id("mlToBox"); if (!box) return;
  box.querySelectorAll(".chip").forEach(c => c.remove());
  $id("mlTo").insertAdjacentHTML("beforebegin", mlTo.map((t, i) => mlToChip(t, i)).join(""));
  $id("mlTo").placeholder = mlTo.length ? "" : "admins@example.com";
}
function mlToTake() {
  const inp = $id("mlTo"); if (!inp) return;
  const typed = inp.value.split(/[,;\s]+/).map(x => x.trim()).filter(Boolean);
  if (!typed.length) return;
  typed.forEach(t => { if (!mlTo.includes(t)) mlTo.push(t); });
  inp.value = ""; mlToPaint();
}

/* Mail can go out: switched on and every field there. */
function mailReady(s) { return !!(s && s.enabled && s.host && s.port && s.from && (s.to || []).length); }

function mailForm(m) {
  return {
    enabled: $id("mlEnabled").checked,
    host: $id("mlHost").value.trim(), port: parseInt($id("mlPort").value, 10) || 0, security: $id("mlSec").value,
    verify_cert: $id("mlVerify").checked, from: $id("mlFrom").value.trim(), from_name: $id("mlFromName").value.trim(),
    to: [...mlTo, ...$id("mlTo").value.split(/[,;\s]+/).map(x => x.trim()).filter(Boolean)], timeout_sec: (m && m.settings.timeout_sec) || 30,
    theme: $id("mlTheme") ? $id("mlTheme").value : "proxmox_dark",
  };
}

/* Switched on, every field is required: the empty or wrong ones get the red border and the
   save does not go out. Returns whether all is filled in. */
function mailMarkInvalid(f) {
  const mail = v => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v);
  const bad = {
    mlHost: f.enabled && !f.host,
    mlPort: f.enabled && !(f.port >= 1 && f.port <= 65535),
    mlFrom: f.enabled && !mail(f.from),
    mlTo: f.enabled && (!f.to.length || !f.to.every(mail)),
  };
  Object.entries(bad).forEach(([id, b]) => { const el = $id(id); if (el) { el.classList.toggle("is-invalid", b); el.setAttribute("aria-invalid", b ? "true" : "false"); } });
  return !Object.values(bad).some(Boolean);
}

function wireMail(main, m) {
  const on = (id, fn) => { const el = $id(id); if (el) el.addEventListener("click", fn); };
  const to = $id("mlTo"), toBox = $id("mlToBox");
  if (to && toBox) {
    to.addEventListener("keydown", e => {
      if ((e.key === "Enter" || e.key === "," || e.key === " ") && to.value.trim()) { e.preventDefault(); mlToTake(); }
      else if (e.key === "Backspace" && !to.value && mlTo.length) { mlTo.pop(); mlToPaint(); }
    });
    to.addEventListener("blur", mlToTake);
    toBox.addEventListener("click", e => {
      const x = e.target.closest("[data-mlto-x]");
      if (x) { if (!to.disabled) { mlTo.splice(Number(x.dataset.mltoX), 1); mlToPaint(); } return; }
      to.focus();
    });
  }
  let tried = false;
  const enable = () => {
    const en = $id("mlEnabled").checked;
    ["mlHost", "mlPort", "mlSec", "mlFromName", "mlFrom", "mlTo", "mlVerify", "mlTest"].forEach(id => {
      const el = $id(id); if (!el) return;
      el.disabled = !en;
      const t = el.closest(".toggle"); if (t) t.classList.toggle("disabled", !en);
    });
    if (!en) mailMarkInvalid({ ...mailForm(m), enabled: false });
    else if (tried) mailMarkInvalid(mailForm(m));
  };
  const t = $id("mlEnabled"); if (t) t.addEventListener("change", enable);
  const box = $id("mlFields"); if (box) box.addEventListener("input", () => { if (tried) mailMarkInvalid(mailForm(m)); });
  on("mlSave", async () => {
    const f = mailForm(m);
    tried = true;
    if (!mailMarkInvalid(f)) return toast("Fill in the marked fields - mail is switched on", true);
    try { await api("PUT", "/settings/mail", f); toast(f.enabled ? "Saved - mail is on" : "Saved - mail is off"); renderServerBlade("studio", main); } catch (e) { toast(e.message, true); }
  });
  on("mlPreview", () => openMailPreview(m.themes || [], $id("mlTheme").value, id => { $id("mlTheme").value = id; }));
  on("mlTest", async e => {
    const f = mailForm(m);
    tried = true;
    if (!mailMarkInvalid({ ...f, enabled: true })) return toast("Fill in the marked fields first", true);
    const b = e.currentTarget; b.disabled = true;
    try { const r = await api("POST", "/mail/test", f); toast("Sent - the smart host said: " + (r.reply || "OK")); }
    catch (err) { toast(err.message, true); }
    finally { b.disabled = false; }
    // The log has the new row - with the answer, or why there was none.
    state.nestedOpen["gs-mail-log"] = true;
    renderServerBlade("studio", main);
  });
}

function notifyCard(n, mail) {
  const ev = n.events || [];
  const groups = [...new Set(ev.map(e => e.group))];
  const onCount = ev.filter(e => e.on).length;
  const ready = mailReady(mail);
  return gsCard("gs-notify", "update.svg", `Notifications ${infoTip("Notifications", "Which events send a mail. On by default: what happens while nobody watches - automatic work - and every failure.")}`,
    ready ? `${onCount} of ${ev.length} on` : "needs mail", `
    ${ready ? "" : `<div class="notify-off-banner">${warnBanner("Notifications go out by mail - switch Mail on and fill it in first.")}</div>`}
    <div class="notify-groups${ready ? "" : " is-off"}" ${ready ? "" : 'aria-disabled="true"'}>${groups.map(g => `<div class="field-group">${esc(g)}</div>
      <div class="toggle-grid">${ev.filter(e => e.group === g).map(e => toggle(`data-notify="${esc(e.key)}"`, esc(e.label), e.on, !ready)).join("")}</div>`).join("")}</div>`, "", false);
}

function wireNotify(main, n) {
  if (!n) return;
  main.querySelectorAll("[data-notify]").forEach(c => c.addEventListener("change", async () => {
    const events = {};
    main.querySelectorAll("[data-notify]").forEach(x => { events[x.dataset.notify] = x.checked; });
    try { await api("PUT", "/settings/notify", { events }); toast(c.checked ? "Mails for it" : "No mail for it"); } catch (e) { toast(e.message, true); }
  }));
}

async function bladeStudio(main, stale) {
  const [server, t, region, cat, worker, ver, maint, mail, notif] = await Promise.all([api("GET", "/settings/server"), api("GET", "/tls"), api("GET", "/settings/region"), catalogCache || api("GET", "/catalog"),
    api("GET", "/settings/worker").catch(() => ({ memory_mb: 4096, cores: 4 })), api("GET", "/studio/version").catch(() => null),
    api("GET", "/settings/maintenance").catch(() => null), api("GET", "/settings/mail").catch(() => null), api("GET", "/settings/notify").catch(() => null)]);
  if (maint && !maintUi.rows) maintUi.rows = maint.settings.windows.map(w => ({ ...w, days: [...w.days] }));
  catalogCache = cat;
  if (stale()) return;
  const c = t.certificate, st = t.settings;
  if (!acmeForm.email && st.acme.email) Object.assign(acmeForm, st.acme);
  // No provider chosen yet: the first one lego lists, not a favourite of ours.
  if (!acmeForm.dns_provider || !t.providers.some(p => p.id === acmeForm.dns_provider)) acmeForm.dns_provider = (t.providers[0] || {}).id || "";
  const mode = { acme: "Let's Encrypt", imported: "Imported", "self-signed": "Self-signed" }[st.mode] || "Self-signed";
  main.innerHTML = bladeHead("studio") + `
    <div class="chips">
      <span class="pill">DNS name: ${esc(server.settings.fqdn || "not set")}</span>
      ${c ? `<span class="pill status ${c.days_left < 21 ? "warn" : "on"}">${esc(cap(mode))} · ${c.days_left} days left</span>` : `<span class="pill status off">No certificate</span>`}
    </div>
    ${gsCard("gs-dns", "dns.svg", "DNS name", server.settings.fqdn || "not set", `
      <div class="grid-2">${field(fieldLabel("dns.svg", "Fully qualified name"), `<input id="stFqdn" placeholder="pve-vm-studio.example.com" value="${esc(server.settings.fqdn)}">
        <span class="hint">What people type to reach the studio; the certificate is issued for it. It needs an A record for ${esc(server.suggested.filter(n => /^\d/.test(n)).join(", "))}.</span>`)}</div>
      ${actions(act("stFqdnSave", "save.svg", "Save", true))}`, "", !server.settings.fqdn)}
    ${gsCard("gs-cert", "certificate.svg", "Certificate", c ? `${mode} · ${c.days_left} days left` : "none", `
      ${c ? `<div class="kv-grid"><div>In use</div><div class="kv-val">${esc(mode)}</div><div>Names</div><div class="kv-val">${esc(c.names.join(", "))}</div>
        <div>Issuer</div><div class="kv-val">${esc(c.issuer)}</div><div>Valid until</div><div class="kv-val">${esc(when(c.not_after))} (${c.days_left} days)</div>
        ${st.mode === "acme" ? `<div>Renewal</div><div class="kv-val">automatic, checked twice a day${st.last_check ? " · last " + esc(when(st.last_check)) : ""}</div>` : ""}</div>` : ""}
      ${st.last_error ? `<p class="hint err" style="margin-top:8px">Last attempt failed: ${esc(st.last_error)}</p>` : ""}
      <div class="section collapsible ${isNestedOpen("gs-cert-le", st.mode !== "acme") ? "" : "collapsed"}" style="margin-top:14px"><div class="section-head" data-nested="gs-cert-le"><span class="section-chevron">${chevron()}</span>
        <img src="${iconSrc("certificate.svg")}" alt=""> Let's Encrypt<span class="section-meta">HTTP-01 or DNS-01 through 100+ DNS providers (lego)</span></div><div class="section-body">
        <div class="grid-3">${field(fieldLabel("users.svg", "Contact e-mail"), `<input id="leMail" type="email" value="${esc(acmeForm.email)}" placeholder="admin@example.com">`)}
          ${field(fieldLabel("validate.svg", "Challenge"), `<select id="leChallenge">${opts([["http-01", "HTTP-01 - port 80 reachable from the internet"], ["dns-01", "DNS-01 - a TXT record through your DNS provider"]], acmeForm.challenge)}</select>`)}
          <div class="field-like">${fieldLabel("validate.svg", "Certificate authority")}
            <div class="ov-seg le-ca" role="group" aria-label="Certificate authority">
              <button type="button" class="btn${acmeForm.staging ? "" : " on"}" data-le-staging="0" aria-pressed="${!acmeForm.staging}">Production</button><button type="button" class="btn${acmeForm.staging ? " on" : ""}" data-le-staging="1" aria-pressed="${acmeForm.staging}">Staging</button>
            </div>
            <span class="hint" id="leCaHint">${acmeForm.staging ? "Staging tests the setup - its certificates are not trusted by browsers." : "A real certificate, trusted by browsers."}</span></div></div>
        <div class="field-like" style="margin-top:12px">${fieldLabel("dns.svg", "DNS names")}<div class="le-names" id="leNames">${leNamesHtml(server.settings.fqdn)}</div></div>
        <div id="leDns" ${acmeForm.challenge === "dns-01" ? "" : "hidden"} style="margin-top:12px">
          <div class="grid-2">${field(fieldLabel("dns.svg", "DNS provider"), `<select id="leProvider">${opts(t.providers.map(p => [p.id, p.id + (p.saved ? " · credentials saved" : "")]), acmeForm.dns_provider)}</select>`)}</div>
          <pre class="provider-help code-block" id="leHelp">…</pre>
          ${field(fieldLabel("secret.svg", "Credentials, one KEY=value per line"), `<textarea id="leCreds" style="min-height:90px" placeholder="NAME_OF_THE_VARIABLE=value - the help above lists them"></textarea>
            <span class="hint">Stored in the container, readable only by the studio, never shown again.</span>`)}</div>
        ${actions(act("leGo", "certificate.svg", "Get certificate", true))}</div></div>
      <div class="section collapsible ${isNestedOpen("gs-cert-import", false) ? "" : "collapsed"}"><div class="section-head" data-nested="gs-cert-import"><span class="section-chevron">${chevron()}</span>
        <img src="${iconSrc("certificate.svg")}" alt=""> Import a certificate<span class="section-meta">your own certificate and key, PEM</span></div><div class="section-body">
        <div class="grid-2">${field(fieldLabel("certificate.svg", "Certificate (PEM, with its chain)"), `<textarea id="imCert" placeholder="-----BEGIN CERTIFICATE-----"></textarea><input type="file" id="imCertFile" accept=".pem,.crt,.cer">`)}
          ${field(fieldLabel("key.svg", "Private key (PEM)"), `<textarea id="imKey" placeholder="-----BEGIN PRIVATE KEY-----"></textarea><input type="file" id="imKeyFile" accept=".pem,.key">`)}</div>
        ${actions(act("ssGo", "update.svg", "New self-signed certificate"), act("imGo", "certificate.svg", "Import", true))}</div></div>`, "", false)}
    ${gsCard("gs-clock", "clock.svg", "Time format", clockFmt === "24h" ? "24-hour" : "12-hour", `
      <div class="grid-2">${field(fieldLabel("clock.svg", "Times show as"), `<select id="stClock">${opts([["12h", "12-hour - 3:45 PM"], ["24h", "24-hour - 15:45"]], clockFmt)}</select>
        <span class="hint">For everyone using the studio: jobs, the dashboard, certificates. Job logs always use 24-hour.</span>`)}</div>
      ${actions(act("stClockSave", "save.svg", "Save", true))}`, "", false)}
    ${gsCard("gs-worker", "ram.svg", "Media worker", `${worker.cores} cores · ${worker.memory_mb / 1024} GB`, `
      <div class="grid-2">
        ${field(`<span class="field-label"><img src="${iconSrc("cpu.svg")}" alt="">Cores${infoTip("Media worker", "The WinPE VM that applies the cumulative update to a Windows media build with DISM. It lives only while the build runs.")}</span>`,
          `<input id="wkCores" type="number" min="1" max="64" value="${worker.cores}">`)}
        ${field(fieldLabel("ram.svg", "Memory (MiB)"), `<input id="wkMem" type="number" min="2048" max="262144" step="1024" value="${worker.memory_mb}">`)}
      </div>
      ${actions(act("wkSave", "save.svg", "Save", true))}`, "", false)}
    ${gsCard("gs-confirm", "trash.svg", `Confirmations ${infoTip("Confirmations", "All on by default. \"Don't ask again\" in a delete dialog switches its question off here - remembered per browser, not for everyone.")}`, Object.keys(CONFIRM_KINDS).some(skipConfirm) ? "some skipped in this browser" : "asks before every delete", `
      <div class="toggle-grid">${Object.entries(CONFIRM_KINDS).map(([k, l]) => toggle(`id="cf_${k}"`, `Ask before ${esc(l.toLowerCase())}`, !skipConfirm(k))).join("")}</div>`, "", false)}
    ${gsCard("gs-region", "language.svg", "Region preselection", region.language ? `${esc(region.language)} · formats ${esc(region.locale || region.language)} · ${esc(region.timezone || "time zone of the browser")}` : "not set - English (United States)", `
      <div class="grid-2">
        ${field(fieldLabel("language.svg", "Language"), `<select id="rgLang">${opts(regionLocales(cat), region.language || "en-US")}</select>`)}
        ${field(fieldLabel("language.svg", "Formats"), `<select id="rgFormat">${opts(regionLocales(cat), region.locale || region.language || "en-US")}</select>`)}
        ${field(fieldLabel("language.svg", "Keyboard"), `<select id="rgKeyboard">${opts(regionLocales(cat), region.keyboard || region.language || "en-US")}</select>`)}
        ${field(fieldLabel("clock.svg", "Time zone"), `<select id="rgTz">${opts(cat.timezones.map(z => [z.id, z.id]), region.timezone || Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC")}</select>`)}
      </div>
      <p class="hint" style="margin-top:8px">Preselected - not enforced: new Linux and Windows bakes and Windows media downloads start with these, and each can still pick something else.</p>
      ${actions(act("rgSave", "save.svg", "Save", true))}`, "", false)}
    ${maint ? maintCard(maint) : ""}
    ${mail ? mailCard(mail, notif) : ""}
    ${notif ? notifyCard(notif, mail && mail.settings) : ""}
    ${versionCard(ver)}
    ${worker.debug_tools ? debugCard(worker) : ""}`;
  wireMaint(main); wireMail(main, mail); wireNotify(main, notif);
  if (acmeForm.challenge === "dns-01" && acmeForm.dns_provider && $id("leHelp")) {
    api("GET", "/tls/providers/" + encodeURIComponent(acmeForm.dns_provider)).then(r => { if ($id("leHelp")) $id("leHelp").innerHTML = highlightHelp(r.help); })
      .catch(e => { if ($id("leHelp")) $id("leHelp").textContent = e.message; });
  }
  const on = (id, ev, fn) => { const el = $id(id); if (el) el.addEventListener(ev, fn); };
  on("verCheck", "click", async () => { try { await api("GET", "/studio/version?fresh=1"); renderServerBlade("studio", main); } catch (e) { toast(e.message, true); } });
  on("verUpdate", "click", async e => {
    const tag = e.currentTarget.dataset.tag;
    try { const { id } = await api("POST", "/studio/update", { tag }); openJob(id); } catch (err) { toast(err.message, true); }
  });
  main.querySelectorAll("[data-ver-channel]").forEach(b => b.addEventListener("click", async () => {
    try {
      await api("PUT", "/settings/update", { auto: !!(ver && ver.auto), channel: b.dataset.verChannel });
      await api("GET", "/studio/version?fresh=1"); renderServerBlade("studio", main);
    } catch (err) { toast(err.message, true); }
  }));
  on("upAuto", "change", async e => { try { await api("PUT", "/settings/update", { auto: e.target.checked, channel: (ver && ver.channel) || "stable" }); toast(e.target.checked ? "Updates install in a maintenance window" : "Updates wait for you"); } catch (err) { toast(err.message, true); } });
  on("stFqdnSave", "click", async () => { try { await api("PUT", "/settings/server", { ...server.settings, fqdn: $id("stFqdn").value }); toast("Saved"); render(); } catch (e) { toast(e.message, true); } });
  Object.keys(CONFIRM_KINDS).forEach(k => on("cf_" + k, "change", e => { setSkipConfirm(k, !e.target.checked); toast(e.target.checked ? "Asks again" : "Won't ask"); }));
  on("rgSave", "click", async () => {
    try {
      await api("PUT", "/settings/region", { language: $id("rgLang").value, locale: $id("rgFormat").value, keyboard: $id("rgKeyboard").value, timezone: $id("rgTz").value });
      catalogCache = null; bakeForm.language = ""; winForm.locale = ""; winForm.keyboard = ""; winForm.timezone = ""; wmUi.lang = "";
      toast("Saved - new bakes and downloads start with it"); render();
    } catch (e) { toast(e.message, true); }
  });
  on("wkSave", "click", async () => {
    try {
      await api("PUT", "/settings/worker", { memory_mb: parseInt($id("wkMem").value, 10) || 4096, cores: parseInt($id("wkCores").value, 10) || 2, keep_downloads: !!worker.keep_downloads });
      toast("Saved"); render();
    } catch (e) { toast(e.message, true); }
  });
  on("dbgSave", "click", async () => {
    try {
      await api("PUT", "/settings/worker", { memory_mb: worker.memory_mb, cores: worker.cores, keep_downloads: $id("dbgKeep").checked });
      toast("Saved"); render();
    } catch (e) { toast(e.message, true); }
  });
  on("dbgClear", "click", async () => {
    if (!await confirmDelete("downloads", `Clear ${(worker.downloads_bytes / 1e9).toFixed(1)} GB of downloads?`,
      "Everything Windows media, WinPE and Features on Demand builds downloaded is deleted from the work volume. The next build downloads its files again.", "Clear downloads")) return;
    try { const r = await api("DELETE", "/settings/worker/downloads"); toast(`${(r.freed / 1e9).toFixed(1)} GB cleared`); render(); } catch (e) { toast(e.message, true); }
  });
  // The last build of a kind again, with its own parameters - from the kept downloads.
  main.querySelectorAll("[data-dbg-rebuild]").forEach(b => b.addEventListener("click", async () => {
    const kind = b.dataset.dbgRebuild;
    try {
      const jobs = await api("GET", "/jobs");
      const last = (jobs || []).filter(j => j.kind === kind).sort((a, c) => (c.created_at || "").localeCompare(a.created_at || ""))[0];
      if (!last) return toast(`No ${kind === "media" ? "Windows media" : "WinPE"} build to repeat yet`, true);
      const r = await api("POST", `/jobs/${encodeURIComponent(last.id)}/retry`);
      openJob(r.id);
    } catch (e) { toast(e.message, true); }
  }));
  on("stClockSave", "click", async () => {
    try { const clock = $id("stClock").value; await api("PUT", "/settings/server", { ...server.settings, clock }); clockFmt = clock; toast("Saved"); render(); } catch (e) { toast(e.message, true); }
  });
  const keepAcme = () => { acmeForm.email = $id("leMail").value.trim(); acmeForm.challenge = $id("leChallenge").value; acmeForm.dns_provider = $id("leProvider").value; };
  leFqdn = server.settings.fqdn || "";
  // In place: a re-render would empty the credentials box.
  main.querySelectorAll("[data-le-staging]").forEach(b => b.addEventListener("click", () => {
    acmeForm.staging = b.dataset.leStaging === "1";
    main.querySelectorAll("[data-le-staging]").forEach(x => { const on = (x.dataset.leStaging === "1") === acmeForm.staging; x.classList.toggle("on", on); x.setAttribute("aria-pressed", on); });
    $id("leCaHint").textContent = acmeForm.staging ? "Staging tests the setup - its certificates are not trusted by browsers." : "A real certificate, trusted by browsers.";
  }));
  on("leChallenge", "change", () => { keepAcme(); render(); });
  on("leProvider", "change", () => { keepAcme(); render(); });
  on("leGo", "click", async () => {
    keepAcme();
    try { const { id } = await api("POST", "/tls/acme", { ...acmeForm, credentials: $id("leCreds").value || null }); openJob(id); } catch (e) { toast(e.message, true); }
  });
  const fileInto = (input, area) => on(input, "change", async e => { const f = e.target.files[0]; if (f) $id(area).value = await f.text(); });
  fileInto("imCertFile", "imCert"); fileInto("imKeyFile", "imKey");
  on("imGo", "click", async () => {
    try { const info = await api("POST", "/tls/import", { cert: $id("imCert").value, key: $id("imKey").value }); toast(`Imported - ${info.names.join(", ")}`); render(); }
    catch (e) { toast(e.message, true); }
  });
  on("ssGo", "click", async () => { try { await api("POST", "/tls/self-signed"); toast("New self-signed certificate in place"); render(); } catch (e) { toast(e.message, true); } });
}

/* ---------- start ---------- */

api("GET", "/session").then(signedIn).catch(showLogin);

/* "Clear from view": the studio forgets a VM - its record, and its card if it has one. The VM
   in Proxmox VE is never touched; deleting it stays a deliberate act there. Asks first, like
   every delete (the confirm overlay, its "Don't ask again" revocable in Studio settings). */
document.addEventListener("click", async e => {
  const b = e.target.closest("[data-clear-vm], [data-clear-record]");
  if (!b) return;
  e.preventDefault(); e.stopPropagation();
  let recordId = b.dataset.clearRecord, name = "";
  const srv = b.dataset.clearVm ? state.servers.find(x => x._id === b.dataset.clearVm) : null;
  if (srv) name = srv.name;
  else { const v = (cluster.vms || []).find(x => x.id === recordId); name = v ? v.name : ""; }
  if (!await confirmDelete("clear", `Clear ${name || "this VM"} from view?`,
    `The studio forgets it${srv ? " - its record and its card" : ""}. The VM itself stays in Proxmox VE, untouched; delete it there if it should go.`, "Clear from view")) return;
  if (srv) {
    const rec = liveVm(srv);
    recordId = rec && rec.id;
    state.servers = state.servers.filter(x => x._id !== b.dataset.clearVm);
  }
  try {
    if (recordId) await api("DELETE", "/vms/" + encodeURIComponent(recordId));
    if (cluster.vms) cluster.vms = cluster.vms.filter(v => v.id !== recordId);
    toast(`${name || "VM"} cleared from the studio - it is untouched in Proxmox VE`);
  } catch (err) { toast(err.message, true); }
  render();
});

/* The VM card's Pool picker (studio.js renderServerCard): None, PVE's pools, or a new one -
   created in PVE right away, then picked. */
document.addEventListener("change", e => {
  const sel = e.target.closest("select[data-pool-for]"); if (!sel) return;
  const s = state.servers.find(x => x._id === sel.dataset.poolFor); if (!s) return;
  if (sel.value === "__new__") { s._poolNew = true; render(); const n = document.querySelector(`[data-pool-name="${s._id}"]`); if (n) n.focus(); return; }
  s._poolNew = false; s.pvePool = sel.value; render();
});
document.addEventListener("click", async e => {
  const cancel = e.target.closest("[data-pool-cancel]");
  if (cancel) { const s = state.servers.find(x => x._id === cancel.dataset.poolCancel); if (s) { s._poolNew = false; render(); } return; }
  const go = e.target.closest("[data-pool-create]"); if (!go) return;
  const s = state.servers.find(x => x._id === go.dataset.poolCreate); if (!s) return;
  const name = (document.querySelector(`[data-pool-name="${s._id}"]`) || {}).value || "";
  const comment = (document.querySelector(`[data-pool-comment="${s._id}"]`) || {}).value || "";
  try {
    const r = await api("POST", "/pools", { name, comment });
    cluster.pools = (cluster.pools || []).filter(p => p.id !== r.id).concat({ id: r.id, comment }).sort((a, b) => a.id.localeCompare(b.id));
    s.pvePool = r.id; s._poolNew = false; toast(`Pool ${r.id} created`); render();
  } catch (err) { toast(err.message, true); }
});

/* The DNS names row of the Let's Encrypt card - wired once for the page, not per redraw. */
let leFqdn = "";
function leAddName() {
  const input = $id("leNameNew"); if (!input) return;
  const n = (input.value || "").trim().toLowerCase().replace(/\.$/, "");
  if (!n) return;
  if (!/^(\*\.)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$/.test(n)) { toast(`'${n}' is not a DNS name`, true); return; }
  if (n.startsWith("*.") && ($id("leChallenge") || {}).value !== "dns-01") { toast("A wildcard needs the DNS-01 challenge", true); return; }
  if (n === leFqdn.toLowerCase() || (acmeForm.extra_names || []).includes(n)) { toast(`${n} is in the list already`, true); return; }
  acmeForm.extra_names = (acmeForm.extra_names || []).concat(n);
  $id("leNames").innerHTML = leNamesHtml(leFqdn); $id("leNameNew").focus();
}
document.addEventListener("click", e => {
  if (state.blade !== "studio") return;
  if (e.target.closest("#leNameAdd")) { leAddName(); return; }
  const del = e.target.closest("[data-le-name-del]");
  if (del && $id("leNames")) { acmeForm.extra_names.splice(Number(del.dataset.leNameDel), 1); $id("leNames").innerHTML = leNamesHtml(leFqdn); }
});
document.addEventListener("keydown", e => { if (state.blade === "studio" && e.target.id === "leNameNew" && e.key === "Enter") { e.preventDefault(); leAddName(); } });
