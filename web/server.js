/* PVE VM Studio - what the Hyper-V studio did not have: a server.
   studio.js is the Hyper-V VM Studio itself (blades, VM cards, validation, passwords...).
   This file signs in, loads and saves labs, and renders the blades that read the cluster:
   Cluster, Golds, Deploy, Jobs, and the server half of General Settings. Every blade uses
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
function when(iso) {
  if (!iso) return "";
  return new Date(iso).toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}
function took(a, b) {
  if (!a) return "";
  const s = Math.max(0, Math.round(((b ? new Date(b) : new Date()) - new Date(a)) / 1000));
  return s < 60 ? `${s}s` : s < 3600 ? `${Math.floor(s / 60)}m ${s % 60}s` : `${Math.floor(s / 3600)}h ${Math.floor(s % 3600 / 60)}m`;
}
function pillOn(text, on) { return `<span class="pill status ${on ? "on" : "off"}">${esc(text)}</span>`; }
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
  const b = BLADES.find(x => x.id === id);
  return `<div class="blade-toolbar"><div class="page-title"><img src="${iconSrc(b.icon)}" alt=""> ${esc(b.label)}</div>
    <div class="row">${actions}</div></div>`;
}
const JOB_TONE = { running: "run", queued: "idle", succeeded: "ok", failed: "bad", interrupted: "warn" };
function jobPill(status) { return `<span class="pill status ${JOB_TONE[status] || "idle"}">${esc(status)}</span>`; }

/* ---------- sign-in ---------- */

async function showLogin() {
  session.user = session.csrf = null;
  stopLiveLog();
  $id("layout").hidden = true; $id("login").hidden = false;
  document.querySelector(".topbar .actions").style.visibility = "hidden";
  $id("labBtn").style.visibility = "hidden";
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
  $id("labBtn").style.visibility = "";
  $id("userChip").textContent = s.user;
  await openLab(null);
  render();
}

/* ---------- labs: loaded, edited in the studio, saved as they change ---------- */

const LAST_LAB = "pvs.lab";
const lab = { id: null, name: "", revision: 0, saved: "", saving: false, conflict: false, timer: null, list: [] };

function setSaveState(text, tone) {
  const el = $id("saveState");
  el.textContent = text; el.className = "save-state " + (tone || "");
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

async function openLab(id) {
  await flushSave();
  lab.list = await api("GET", "/labs");
  let wanted = id || (() => { try { return localStorage.getItem(LAST_LAB); } catch { return null; } })();
  if (!lab.list.some(l => l.id === wanted)) wanted = lab.list.length ? lab.list[0].id : null;
  let row;
  if (!wanted) {
    row = await api("POST", "/labs", { name: "Lab", state: studioPayload() });
    lab.list = await api("GET", "/labs");
  } else {
    row = await api("GET", "/labs/" + encodeURIComponent(wanted));
  }
  lab.id = row.id; lab.name = row.name; lab.revision = row.revision; lab.conflict = false;
  try { localStorage.setItem(LAST_LAB, row.id); } catch { /* fine */ }
  loadPayload(row.state);
  lab.saved = encodeState();
  $id("labName").textContent = lab.name;
  setSaveState("saved", "ok");
  state.blade = bladeFromHash() || state.blade || "overview";
  applyTheme(state.themeId || DEFAULT_THEME_ID);
  refreshInventory();
}

/* Called by studio.js after every render: a changed state is saved a second later. */
function studioChanged() {
  if (location.hash !== "#/" + state.blade) history.replaceState(null, "", "#/" + state.blade);
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
    if (e.status === 409) { lab.conflict = true; setSaveState("conflict", "err"); toast(e.message, true); }
    else { setSaveState("not saved", "err"); toast("Saving the lab failed: " + e.message, true); }
  } finally { lab.saving = false; }
  if (!lab.conflict && encodeState() !== lab.saved) { clearTimeout(lab.timer); lab.timer = setTimeout(saveLab, 1000); }
}
async function flushSave() { clearTimeout(lab.timer); if (lab.id && !lab.conflict) await saveLab(); }
window.addEventListener("beforeunload", e => { if (lab.id && encodeState() !== lab.saved) { saveLab(); e.preventDefault(); } });

function renderLabList() {
  $id("labList").innerHTML = lab.list.map(l => `<button type="button" class="btn row ${l.id === lab.id ? "selected" : ""}" data-lab="${esc(l.id)}">
      <span class="radio"></span><span class="tname">${esc(l.name)}</span><span class="hint">${esc(when(l.updated_at))}</span></button>`).join("") +
    (lab.conflict ? `<div class="hint err" style="padding:6px 10px">Someone else saved this lab - <a href="#" id="labReload">reload it</a> (your changes since the last save are lost).</div>` : "");
}
$id("labBtn").addEventListener("click", async e => {
  e.stopPropagation();
  const pop = $id("labPopover");
  if (!pop.classList.contains("open")) { try { lab.list = await api("GET", "/labs"); } catch { /* keep */ } renderLabList(); }
  pop.classList.toggle("open");
});
$id("labPopover").addEventListener("click", async e => {
  e.stopPropagation();
  const row = e.target.closest("[data-lab]");
  if (row) { $id("labPopover").classList.remove("open"); await openLab(row.dataset.lab); render(); return; }
  if (e.target.id === "labReload") { e.preventDefault(); lab.conflict = false; lab.saved = ""; $id("labPopover").classList.remove("open"); await openLab(lab.id); render(); }
});
$id("labNewBtn").addEventListener("click", async () => {
  const name = $id("labNewName").value.trim();
  if (!name) return toast("Name the lab first", true);
  await flushSave();
  const row = await api("POST", "/labs", { name, state: {} });
  $id("labNewName").value = ""; $id("labPopover").classList.remove("open");
  // A new lab starts from the studio's defaults.
  state.servers = []; state.networks = []; state.domainJoinAccounts = []; state.azureArcPrincipals = []; state.vhdSets = [];
  await openLab(row.id); render();
});
document.addEventListener("click", () => $id("labPopover").classList.remove("open"));
$id("deployBtn").addEventListener("click", () => { state.blade = "deploy"; render(); });

function bladeFromHash() {
  const id = location.hash.replace(/^#\/?/, "").split("/")[0];
  return BLADES.some(b => b.id === id) ? id : null;
}
window.addEventListener("hashchange", () => { const b = bladeFromHash(); if (b && b !== state.blade) { state.blade = b; render(); } });

/* ---------- the cluster, for the studio's pickers ---------- */

const cluster = { inventory: null, golds: [], at: 0 };
async function refreshInventory(force) {
  if (!force && cluster.inventory && Date.now() - cluster.at < 15000) return cluster;
  try {
    const [inv, golds] = await Promise.all([api("GET", "/inventory"), api("GET", "/golds")]);
    cluster.inventory = inv; cluster.golds = golds; cluster.at = Date.now();
    // The studio's vSwitch list is the cluster's bridges and VNets now - read, never typed.
    const names = [...new Set(inv.nodes.flatMap(n => (n.bridges || []).map(b => b.iface)).concat(inv.vnets.map(v => v.vnet)))].sort();
    if (JSON.stringify(names) !== JSON.stringify(state.defaults.availableSwitches || [])) {
      state.defaults.availableSwitches = names;
      if (lab.id) render();
    }
  } catch (e) { if (e.message !== "signed out") console.warn("inventory", e); }
  return cluster;
}

/* ---------- server blades ---------- */

let bladeSeq = 0;
function renderServerBlade(id, main) {
  const seq = ++bladeSeq;
  const stale = () => seq !== bladeSeq || state.blade !== id;
  if (!main.dataset.serverBlade || main.dataset.serverBlade !== id) {
    stopLiveLog();
    main.innerHTML = bladeHead(id) + `<p class="hint">Loading…</p>`;
  }
  main.dataset.serverBlade = id;
  const fn = { cluster: bladeCluster, golds: bladeGolds, deploy: bladeDeploy, jobs: bladeJobs }[id];
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
  if (state.blade === "general") fillServerGeneral();
};

/* -- Cluster -- */

async function bladeCluster(main, stale) {
  const c = await refreshInventory(true);
  if (stale()) return;
  const inv = c.inventory;
  const online = inv.nodes.filter(n => n.status === "online");
  const vms = inv.guests.filter(g => g.type === "qemu" && g.template !== 1);
  const templates = inv.guests.filter(g => g.type === "qemu" && g.template === 1);
  const mem = online.reduce((s, n) => s + (n.mem || 0), 0), maxmem = online.reduce((s, n) => s + (n.maxmem || 0), 0);
  main.innerHTML = bladeHead("cluster", `<button class="btn" type="button" id="clCheck"><img src="${iconSrc("validate.svg")}" alt=""> Run cluster check</button>`) + `
    <div class="hero"><div class="hero-icon"><img src="${iconSrc("servers.svg")}" alt=""></div>
      <div class="hero-body"><h2>${inv.cluster ? "Cluster " + esc(inv.cluster.name) : "Single node"} · Proxmox VE ${esc(inv.version)}</h2>
        <p>What the studio deploys onto - read through the API with its own token. ${inv.cluster ? (inv.cluster.quorate ? "The cluster is quorate." : "<b>The cluster has no quorum.</b>") : ""}</p></div></div>
    <div class="chips">
      <span class="pill">Nodes: ${online.length} / ${inv.nodes.length} online</span>
      <span class="pill">CPUs: ${online.reduce((s, n) => s + (n.maxcpu || 0), 0)}</span>
      <span class="pill">Memory: ${gib(mem)} of ${gib(maxmem)} GiB used</span>
      <span class="pill">VMs: ${vms.length} (${vms.filter(v => v.status === "running").length} running)</span>
      <span class="pill">Templates: ${templates.length}</span>
      <span class="pill">Storages: ${inv.storages.length}</span>
    </div>
    ${gsCard("cl-nodes", "servers.svg", "Nodes", `${inv.nodes.length} node(s), ${online.length} online`, `
      <div class="table-wrap"><table class="data"><thead><tr><th>Node</th><th>Status</th><th>Address</th><th>CPU</th><th>Memory</th><th>Root disk</th><th>Up</th></tr></thead>
      <tbody>${inv.nodes.map(n => `<tr><td><b>${esc(n.node)}</b></td><td>${pillOn(n.status || "unknown", n.status === "online")}</td>
        <td class="mono">${esc(n.ip || "")}</td><td class="mono">${n.maxcpu ? `${((n.cpu || 0) * 100).toFixed(0)}% of ${n.maxcpu}` : ""}</td>
        <td>${n.maxmem ? meter(n.mem, n.maxmem) : ""}</td><td>${n.maxdisk ? meter(n.disk, n.maxdisk) : ""}</td>
        <td class="muted">${n.uptime ? took(new Date(Date.now() - n.uptime * 1000).toISOString()) : ""}</td></tr>`).join("")}</tbody></table></div>`, "", true)}
    ${gsCard("cl-storage", "storage.svg", "Storage", `${inv.storages.length} storage(s), ${inv.storages.filter(s => s.shared === 1).length} shared`, `
      <div class="table-wrap"><table class="data"><thead><tr><th>Storage</th><th>Node</th><th>Type</th><th>Content</th><th>Shared</th><th>Usage</th></tr></thead>
      <tbody>${inv.storages.map(s => `<tr><td><b>${esc(s.storage)}</b></td><td>${esc(s.node || "")}</td><td class="mono">${esc(s.plugintype || "")}</td>
        <td class="muted">${esc((s.content || "").split(",").join(", "))}</td><td>${pillOn(s.shared === 1 ? "shared" : "local", s.shared === 1)}</td>
        <td>${s.maxdisk ? meter(s.disk, s.maxdisk) : ""}</td></tr>`).join("")}</tbody></table></div>
      <div class="tip-box"><img src="${iconSrc("help.svg")}" alt=""><div>Linked clones need the gold on the same storage as the VM - on shared storage one gold serves every node.</div></div>`, "", true)}
    ${gsCard("cl-bridges", "vnet.svg", "Bridges and VNets", "Where VM network adapters connect - the Hyper-V studio's vSwitches", `
      <div class="table-wrap"><table class="data"><thead><tr><th>Bridge</th><th>Node</th><th>Address</th><th>VLAN aware</th><th>Comment</th></tr></thead>
      <tbody>${inv.nodes.flatMap(n => (n.bridges || []).map(b => `<tr><td><b>${esc(b.iface)}</b></td><td>${esc(n.node)}</td><td class="mono">${esc(b.cidr || "")}</td>
        <td>${pillOn(b.bridge_vlan_aware === 1 ? "yes" : "no", b.bridge_vlan_aware === 1)}</td><td class="muted">${esc(b.comments || "")}</td></tr>`)).join("")}
        ${inv.vnets.map(v => `<tr><td><b>${esc(v.vnet)}</b></td><td class="muted">SDN zone ${esc(v.zone || "")}</td><td></td><td>${v.tag ? "tag " + esc(v.tag) : ""}</td><td class="muted">${esc(v.alias || "")}</td></tr>`).join("")}
      </tbody></table></div>`, "", false)}`;
  $id("clCheck").addEventListener("click", async () => {
    try { const { id } = await api("POST", "/jobs/cluster-check"); openJob(id); } catch (e) { toast(e.message, true); }
  });
}

/* -- Golds -- */

const bakeForm = { image: "debian13", updates: true, features: ["aliases", "prompt", "fastfetch"], region: false, language: "", format: "", keyboard: "", timezone: "" };
const winForm = { iso: "", index: null, locale: "", keyboard: "", timezone: "", features: ["rdp", "ping", "svrmgr"] };
let catalogCache = null;

async function bladeGolds(main, stale) {
  const [catalog, golds, bake] = await Promise.all([catalogCache || api("GET", "/catalog"), api("GET", "/golds"), api("GET", "/settings/bake")]);
  if (stale()) return;
  catalogCache = catalog; cluster.golds = golds;
  const inv = (await refreshInventory()).inventory;
  if (stale()) return;
  if (!bakeForm.language) {
    bakeForm.language = catalog.region.language || "en-US"; bakeForm.format = catalog.region.locale || bakeForm.language;
    bakeForm.keyboard = catalog.region.keyboard || bakeForm.language; bakeForm.timezone = Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC";
  }
  const img = catalog.linux.find(i => i.id === bakeForm.image) || catalog.linux[0];
  const feats = catalog.features.filter(f => !f.images.length || f.images.includes(img.id));
  const locales = Object.entries(catalog.locales).sort((a, b) => a[1].localeCompare(b[1]));
  const s = bake.settings, r = bake.resolved || {};
  const node = s.node || r.node;
  const stor = content => inv.storages.filter(x => x.node === node && (x.content || "").split(",").includes(content))
    .map(x => [x.storage, `${x.storage} (${x.plugintype}${x.shared === 1 ? ", shared" : ""})`]);
  const bridges = (inv.nodes.find(n => n.node === node)?.bridges || []).map(b => [b.iface, b.iface]).concat(inv.vnets.map(v => [v.vnet, v.vnet + " (SDN)"]));
  const auto = v => v ? `Auto (${v})` : "Auto";
  const ready = golds.filter(g => g.status === "ready");

  const goldRows = golds.map(g => {
    const m = (() => { try { return JSON.parse(g.manifest); } catch { return {}; } })();
    const name = catalog.linux.find(i => i.id === g.image_id)?.name || m.name || g.image_id;
    const tone = { ready: "ok", baking: "run", failed: "bad" }[g.status] || "idle";
    return `<tr><td><div class="name-cell"><img src="${iconSrc(g.os === "windows" ? "os-server-core.svg" : "gold-image.svg")}" alt=""><div><b>${esc(name)}</b><div class="hint mono">${esc(g.name)}</div></div></div></td>
      <td><span class="pill status ${tone}">${esc(g.status)}</span></td><td class="mono">${g.vmid ?? ""}</td><td>${esc(g.node)}</td><td class="mono">${esc(g.storage)}</td>
      <td class="mono">${esc(m.kernel || (m.build ? "build " + m.build : ""))}</td><td class="muted">${esc(when(g.created_at))}</td>
      <td class="row-actions">${g.job_id ? `<button class="btn sm ghost" type="button" data-job-open="${esc(g.job_id)}">Log</button>` : ""}
        ${g.status !== "baking" ? `<button class="btn sm danger-text" type="button" data-gold-remove="${esc(g.id)}">Remove</button>` : ""}</td></tr>`;
  }).join("");

  main.innerHTML = bladeHead("golds") + `
    <div class="hero"><div class="hero-icon"><img src="${iconSrc("gold-image.svg")}" alt=""></div>
      <div class="hero-body"><h2>Bake gold images</h2><p>A gold is baked once per image and every VM starts from it - New-Vhdx.ps1's job, done by the server.
      Golds are PVE templates in the pool <code>vm-studio</code>, IDs from 9000; a rebake makes a new one and never touches the old.</p></div></div>
    <div class="chips"><span class="pill">Ready: ${ready.length}</span><span class="pill">Linux: ${ready.filter(g => g.os === "linux").length}</span>
      <span class="pill">Windows: ${ready.filter(g => g.os === "windows").length}</span>
      <span class="pill status ${golds.some(g => g.status === "baking") ? "run" : "idle"}">Baking: ${golds.filter(g => g.status === "baking").length}</span></div>
    ${gsCard("gd-list", "gold-image.svg", "Golds", `${ready.length} ready`, golds.length ? `<div class="table-wrap"><table class="data">
      <thead><tr><th>Image</th><th>Status</th><th>Template</th><th>Node</th><th>Storage</th><th>Kernel / build</th><th>Baked</th><th></th></tr></thead>
      <tbody>${goldRows}</tbody></table></div>` : `<div class="empty-state"><div class="ue-icon"><img src="${iconSrc("gold-image.svg")}" alt=""></div><h3>No golds yet</h3><p>Bake one below.</p></div>`, "", true)}
    ${gsCard("gd-linux", "gold-image.svg", "Bake a Linux gold", `${catalog.linux.length} images - PVE downloads the cloud image, the studio bakes it`, `
      <div class="grid-2">
        ${field(fieldLabel("iso-media.svg", "Image"), `<select id="bkImage">${opts(catalog.linux.map(i => [i.id, i.name]), img.id)}</select>
          <span class="hint">${esc(img.url.split("/").pop())} · ${img.disk_gb} GiB disk · Secure Boot ${img.secure_boot ? "on" : "off"}</span>`)}
      </div>
      <div class="field-group">Baked in</div>
      <div class="toggle-grid">${stoggle("bkUpdates", "Install updates", bakeForm.updates, "package upgrade during the bake")}
        ${feats.map(f => stoggle("bkF_" + f.id, f.label, bakeForm.features.includes(f.id))).join("")}</div>
      <div class="field-group">Region</div>
      <div class="toggle-grid">${stoggle("bkRegion", "Language, formats, keyboard and time zone", bakeForm.region, "otherwise the image keeps its own (usually en_US, UTC, us)")}</div>
      <div class="grid-2" id="bkRegionFields" style="margin-top:12px" ${bakeForm.region ? "" : "hidden"}>
        ${field(fieldLabel("language.svg", "Language"), `<select id="bkLang">${opts(locales, bakeForm.language)}</select>`)}
        ${field(fieldLabel("language.svg", "Formats"), `<select id="bkFormat">${opts(locales, bakeForm.format)}</select>`)}
        ${field(fieldLabel("language.svg", "Keyboard"), `<select id="bkKeyboard">${opts(locales, bakeForm.keyboard)}</select>`)}
        ${field(fieldLabel("language.svg", "Time zone"), `<select id="bkTz">${opts(catalog.timezones.map(z => [z.id, z.id]), bakeForm.timezone)}</select>`)}
      </div>
      ${actions(bake.problem ? `<span class="hint err gs-actions-note">${esc(bake.problem)}</span>` : `<span class="hint gs-actions-note">on ${esc(r.node)} · disk ${esc(r.disk_storage)} · network ${esc(r.bridge)}</span>`,
        act("bkStart", "gold-image.svg", "Bake", true))}`, "", true)}
    ${gsCard("gd-windows", "os-server-desktop.svg", "Bake a Windows gold", "New-Vhdx's pipeline: WinPE apply, audit, sysprep, WinPE customize", `<div id="winBakeBody"><p class="hint">Reading the ISOs…</p></div>`, "", true)}
    ${gsCard("gd-where", "settings.svg", "Where bakes run", `${esc(r.node || "")} · ${esc(r.disk_storage || "")} · ${esc(r.bridge || "")}`, `
      <div class="grid-3">
        ${field(fieldLabel("servers.svg", "Node"), `<select id="bsNode">${opts(inv.nodes.filter(n => n.status === "online").map(n => [n.node, n.node]), s.node, auto(r.node))}</select>`)}
        ${field(fieldLabel("disk.svg", "Gold disks (images)"), `<select id="bsDisk">${opts(stor("images"), s.disk_storage, auto(r.disk_storage))}</select>`)}
        ${field(fieldLabel("storage.svg", "Cloud image cache (import)"), `<select id="bsImport">${opts(stor("import"), s.import_storage, auto(r.import_storage))}</select>`)}
        ${field(fieldLabel("iso-media.svg", "Seed ISOs (iso)"), `<select id="bsIso">${opts(stor("iso"), s.iso_storage, auto(r.iso_storage))}</select>`)}
        ${field(fieldLabel("vnet.svg", "Bake network"), `<select id="bsBridge">${opts(bridges, s.bridge, auto(r.bridge))}</select>`)}
        ${field(fieldLabel("vlan.svg", "VLAN tag"), `<input id="bsVlan" type="number" min="1" max="4094" placeholder="none" value="${s.vlan ?? ""}">`)}
        ${field(fieldLabel("cpu.svg", "CPU type (Linux)"), `<input id="bsCpu" value="${esc(s.cpu)}">`)}
        ${field(fieldLabel("cpu.svg", "CPU type (Windows)"), `<input id="bsCpuWin" value="${esc(s.cpu_windows)}">`)}
        ${field(fieldLabel("ram.svg", "Memory (MiB)"), `<input id="bsMem" type="number" min="1024" step="512" value="${s.memory_mb}">`)}
        ${field(fieldLabel("cpu.svg", "Cores"), `<input id="bsCores" type="number" min="1" value="${s.cores}">`)}
      </div>
      <div class="tip-box"><img src="${iconSrc("help.svg")}" alt=""><div>The bake VM needs DHCP and internet access on its network (Linux). "Auto" prefers shared storage, so one gold serves every node.</div></div>
      ${actions(act("bsSave", "save.svg", "Save", true))}`, "", false)}`;

  const keep = () => {
    bakeForm.image = $id("bkImage").value; bakeForm.updates = $id("bkUpdates").checked;
    bakeForm.features = catalog.features.filter(f => $id("bkF_" + f.id)?.checked).map(f => f.id).concat(bakeForm.features.filter(f => !$id("bkF_" + f)));
    bakeForm.region = $id("bkRegion").checked;
    bakeForm.language = $id("bkLang").value; bakeForm.format = $id("bkFormat").value; bakeForm.keyboard = $id("bkKeyboard").value; bakeForm.timezone = $id("bkTz").value;
  };
  $id("bkImage").addEventListener("change", () => { keep(); renderServerBlade("golds", main); });
  $id("bkRegion").addEventListener("change", () => { $id("bkRegionFields").hidden = !$id("bkRegion").checked; });
  $id("bkStart").addEventListener("click", async () => {
    keep();
    try {
      const { id } = await api("POST", "/golds", { image: bakeForm.image, updates: bakeForm.updates,
        features: bakeForm.features.filter(f => feats.some(x => x.id === f)),
        region: bakeForm.region ? { language: bakeForm.language, format: bakeForm.format, keyboard: bakeForm.keyboard, timezone: bakeForm.timezone } : null });
      openJob(id);
    } catch (e) { toast(e.message, true); }
  });
  $id("bsSave").addEventListener("click", async () => {
    const vlan = parseInt($id("bsVlan").value, 10);
    try {
      await api("PUT", "/settings/bake", { node: $id("bsNode").value, disk_storage: $id("bsDisk").value, import_storage: $id("bsImport").value,
        iso_storage: $id("bsIso").value, bridge: $id("bsBridge").value, vlan: Number.isFinite(vlan) ? vlan : null,
        cpu: $id("bsCpu").value.trim(), cpu_windows: $id("bsCpuWin").value.trim(), memory_mb: parseInt($id("bsMem").value, 10) || 2048,
        cores: parseInt($id("bsCores").value, 10) || 2, timeout_min: s.timeout_min });
      toast("Saved"); renderServerBlade("golds", main);
    } catch (e) { toast(e.message, true); }
  });
  wireRowActions(main, () => renderServerBlade("golds", main));
  fillWinBake(catalog, stale);
}

async function fillWinBake(catalog, stale) {
  const body = $id("winBakeBody");
  if (!body) return;
  let isos, win;
  try { [isos, win] = await Promise.all([api("GET", "/windows/isos"), api("GET", "/settings/windows")]); }
  catch (e) { if (!stale() && $id("winBakeBody")) $id("winBakeBody").innerHTML = warnBanner(esc(e.message)); return; }
  if (stale() || !$id("winBakeBody")) return;
  const readable = isos.isos.filter(i => i.readable);
  if (!win.winpe || !win.winpe.volid) {
    $id("winBakeBody").innerHTML = `<div class="warn-banner"><div class="warn-banner-text">Windows bakes boot a WinPE distilled from a Windows ISO - build it first under
      <b>General Settings → Windows</b>.</div></div><div class="row"><button class="btn" type="button" data-goto="general">Open General Settings</button></div>`;
    return;
  }
  if (!isos.isos.length) {
    $id("winBakeBody").innerHTML = `<p class="hint">No Windows ISO on ${esc(isos.node)} yet. Upload one in PVE (a storage's <b>ISO Images → Upload</b> or <b>Download from URL</b>).</p>`;
    return;
  }
  if (!winForm.iso || !readable.some(i => i.volid === winForm.iso)) winForm.iso = (readable[0] || isos.isos[0]).volid;
  const locales = Object.entries(catalog.locales).sort((a, b) => a[1].localeCompare(b[1]));
  $id("winBakeBody").innerHTML = `<div class="grid-2">
      ${field(fieldLabel("iso-media.svg", "Windows ISO"), `<select id="wiIso">${opts(isos.isos.map(i => [i.volid, `${i.file} · ${gib(i.size)} GiB${i.readable ? "" : " · not readable by the studio"}`]), winForm.iso)}</select>`)}
      <div class="kv-grid"><div>WinPE</div><div class="kv-val">${esc(win.winpe.volid)}</div><div>virtio-win</div><div class="kv-val">${esc(win.settings.virtio)}${win.stable && win.settings.virtio === "stable" ? " (" + esc(win.stable) + ")" : ""}</div></div>
    </div><div id="wiImages" style="margin-top:12px"><p class="hint">Reading the ISO…</p></div>`;
  $id("wiIso").addEventListener("change", () => { winForm.iso = $id("wiIso").value; winForm.index = null; fillWinBake(catalog, stale); });
  let info;
  try { info = await api("GET", "/windows/images?volid=" + encodeURIComponent(winForm.iso)); }
  catch (e) { if ($id("wiImages")) $id("wiImages").innerHTML = warnBanner(esc(e.message)); return; }
  if (!$id("wiImages")) return;
  if (winForm.index == null) winForm.index = (info.images.find(i => i.installation_type === "Server Core" && /Datacenter/.test(i.edition_id)) || info.images[0]).index;
  const lang = (info.images[0] || {}).language || "en-US";
  if (!winForm.locale) winForm.locale = catalog.region.locale || lang;
  if (!winForm.keyboard) winForm.keyboard = catalog.region.keyboard || lang;
  if (!winForm.timezone) winForm.timezone = info.default_timezone !== "UTC" ? info.default_timezone : "W. Europe Standard Time";
  $id("wiImages").innerHTML = `<div class="table-wrap"><table class="data">
      <thead><tr><th></th><th>Edition</th><th>Type</th><th>Build</th><th>Language</th><th>Size</th><th>Gold id</th><th>Key</th></tr></thead>
      <tbody>${info.images.map(i => `<tr class="clickable ${i.index === winForm.index ? "selected" : ""}" data-wi="${i.index}">
        <td class="mono">${i.index}</td><td>${esc(i.name)}</td>
        <td><span class="pill role ${i.installation_type === "Server Core" ? "core" : i.installation_type === "Client" ? "client" : "desktop"}">${esc(i.installation_type === "Server Core" ? "Core" : i.installation_type === "Client" ? "Client" : "Desktop")}</span></td>
        <td class="mono">${esc(i.build)}</td><td class="mono">${esc(i.language)}</td><td class="mono">${i.size_gb} GiB</td><td class="mono">${esc(i.image_id)}</td>
        <td>${pillOn(i.key ? "KMS client" : "none", i.key)}</td></tr>`).join("")}</tbody></table></div>
    <div class="field-group">Region</div>
    <div class="grid-3">
      ${field(fieldLabel("language.svg", "Formats and system locale"), `<select id="wiLocale">${opts(locales, winForm.locale)}</select>`)}
      ${field(fieldLabel("language.svg", "Keyboard"), `<select id="wiKeyboard">${opts(locales, winForm.keyboard)}</select>`)}
      ${field(fieldLabel("language.svg", "Time zone"), `<select id="wiTz">${opts(info.timezones.map(z => [z.id, `${z.id} · ${z.iana}`]), winForm.timezone)}</select>`)}
    </div>
    <div class="field-group">Policies baked in</div>
    <div class="toggle-grid">${info.features.map(f => stoggle("wiF_" + f.id, f.label, winForm.features.includes(f.id))).join("")}</div>
    ${actions(`<span class="hint gs-actions-note">WinPE pass 1 (apply) · audit mode (virtio, agent, sysprep) · WinPE pass 2 (verify, region, policies, key)</span>`,
      act("wiStart", "gold-image.svg", "Bake", true))}`;
  const keepWin = () => {
    winForm.locale = $id("wiLocale").value; winForm.keyboard = $id("wiKeyboard").value; winForm.timezone = $id("wiTz").value;
    winForm.features = info.features.filter(f => $id("wiF_" + f.id)?.checked).map(f => f.id);
  };
  $id("wiImages").querySelectorAll("[data-wi]").forEach(tr => tr.addEventListener("click", () => { keepWin(); winForm.index = parseInt(tr.dataset.wi, 10); fillWinBake(catalog, stale); }));
  $id("wiStart").addEventListener("click", async () => {
    keepWin();
    try {
      const { id } = await api("POST", "/golds/windows", { iso: winForm.iso, index: winForm.index,
        region: { locale: winForm.locale, keyboard: winForm.keyboard, timezone: winForm.timezone }, features: winForm.features });
      openJob(id);
    } catch (e) { toast(e.message, true); }
  });
}

/* Log / Remove buttons in the server blades' tables. Removing is irreversible: the first
   click arms the button, the second does it. */
function wireRowActions(root, rerender) {
  root.querySelectorAll("[data-job-open]").forEach(b => b.addEventListener("click", () => openJob(b.dataset.jobOpen)));
  root.querySelectorAll("[data-gold-remove], [data-vm-remove]").forEach(b => b.addEventListener("click", async () => {
    if (!b.dataset.armed) {
      b.dataset.armed = "1"; const t = b.textContent; b.textContent = "Click again to remove";
      setTimeout(() => { delete b.dataset.armed; b.textContent = t; }, 4000);
      return;
    }
    const path = b.dataset.goldRemove ? "/golds/" + encodeURIComponent(b.dataset.goldRemove) : "/vms/" + encodeURIComponent(b.dataset.vmRemove);
    try { const { id } = await api("DELETE", path); openJob(id); } catch (e) { toast(e.message, true); }
  }));
  root.querySelectorAll("[data-power]").forEach(b => b.addEventListener("click", async () => {
    try { await api("POST", `/vms/${encodeURIComponent(b.dataset.vm)}/${b.dataset.power}`); toast(`${b.textContent.trim()}: sent`); setTimeout(rerender, 2500); }
    catch (e) { toast(e.message, true); }
  }));
}

/* -- Deploy: the lab against what exists -- */

async function bladeDeploy(main, stale) {
  const [vms, golds] = await Promise.all([api("GET", "/vms"), api("GET", "/golds")]);
  if (stale()) return;
  cluster.golds = golds;
  const errors = reviewErrorCount();
  const byName = new Map(vms.map(v => [v.name, v]));
  const planned = state.servers.map(s => {
    const name = (s.name || "").toLowerCase();
    const built = byName.get(name);
    const gold = goldFor(s);
    return { s, name, built, gold };
  });
  const toBuild = planned.filter(p => !p.built || p.built.status === "failed");
  main.innerHTML = bladeHead("deploy", `<button class="btn primary" type="button" id="dpGo" ${toBuild.length ? "" : "disabled"}><img src="${iconSrcOnAccent("first-boot.svg")}" alt=""> Deploy ${toBuild.length} VM(s)</button>`) + `
    <div class="hero"><div class="hero-icon"><img src="${iconSrc("first-boot.svg")}" alt=""></div>
      <div class="hero-body"><h2>Build the lab on Proxmox VE</h2><p>What Build-Vms.ps1 did from config.json: every VM of lab <b>${esc(lab.name)}</b> that does not exist yet is cloned from its gold,
      gets its seed for the first boot, and is started - each as a job with its own log. VMs that exist are left alone.</p></div></div>
    <div class="chips"><span class="pill">In the lab: ${state.servers.length}</span><span class="pill">Built: ${planned.filter(p => p.built && p.built.status === "ready").length}</span>
      <span class="pill">To build: ${toBuild.length}</span>${errors ? `<span class="pill status off">${errors} error(s) in Review</span>` : `<span class="pill status on">No errors</span>`}</div>
    ${errors ? `<div class="warn-banner"><div class="warn-banner-text"><b>Review and validate</b> reports ${errors} error(s) - fix them before deploying.</div></div>` : ""}
    ${gsCard("dp-plan", "vm.svg", "The lab's VMs", `${state.servers.length} designed`, state.servers.length ? `<div class="table-wrap"><table class="data">
      <thead><tr><th>VM</th><th>Image</th><th>Gold</th><th>Built</th><th>Power</th><th>Address</th><th>Node / VMID</th><th></th></tr></thead>
      <tbody>${planned.map(p => `<tr>
        <td><b>${esc(p.name || "(no name)")}</b></td>
        <td>${esc(findImage(p.s.imageId).label)}</td>
        <td>${p.gold ? `<span class="mono">${esc(p.gold.name)}</span>` : `<span class="pill status off">no gold</span>`}</td>
        <td>${p.built ? `<span class="pill status ${{ ready: "ok", building: "run", failed: "bad" }[p.built.status] || "idle"}">${esc(p.built.status)}</span>` : '<span class="pill">not built</span>'}</td>
        <td>${p.built ? pillOn(p.built.power, p.built.power === "running") : ""}</td>
        <td class="mono">${esc((p.built && p.built.ip) || p.s.ipAddress || "")}</td>
        <td class="mono">${p.built ? esc(p.built.node + " / " + (p.built.vmid ?? "")) : ""}</td>
        <td class="row-actions">${p.built && p.built.job_id ? `<button class="btn sm ghost" type="button" data-job-open="${esc(p.built.job_id)}">Log</button>` : ""}
          ${p.built && p.built.status === "ready" && p.built.power === "stopped" ? `<button class="btn sm ghost" type="button" data-power="start" data-vm="${esc(p.built.id)}">Start</button>` : ""}
          ${p.built && p.built.status === "ready" && p.built.power === "running" ? `<button class="btn sm ghost" type="button" data-power="shutdown" data-vm="${esc(p.built.id)}">Shut down</button>` : ""}
          ${p.built && p.built.status !== "building" ? `<button class="btn sm danger-text" type="button" data-vm-remove="${esc(p.built.id)}">Remove</button>` : ""}</td>
      </tr>`).join("")}</tbody></table></div>` : `<div class="empty-state"><div class="ue-icon"><img src="${iconSrc("vm.svg")}" alt=""></div><h3>No VMs in this lab</h3>
        <p>Design them under Virtual machines.</p><div class="ue-actions"><button class="btn primary" type="button" data-goto="servers">Open Virtual machines</button></div></div>`, "", true)}
    ${vms.filter(v => !state.servers.some(s => (s.name || "").toLowerCase() === v.name)).length ? gsCard("dp-other", "servers.svg", "Built by the studio, not in this lab",
      "Other labs' VMs, or VMs removed from this lab's design", `<div class="table-wrap"><table class="data"><tbody>${vms.filter(v => !state.servers.some(s => (s.name || "").toLowerCase() === v.name)).map(v => `<tr>
        <td><b>${esc(v.name)}</b></td><td>${pillOn(v.power, v.power === "running")}</td><td class="mono">${esc(v.ip || "")}</td><td class="mono">${esc(v.node + " / " + (v.vmid ?? ""))}</td>
        <td class="row-actions">${v.job_id ? `<button class="btn sm ghost" type="button" data-job-open="${esc(v.job_id)}">Log</button>` : ""}<button class="btn sm danger-text" type="button" data-vm-remove="${esc(v.id)}">Remove</button></td></tr>`).join("")}</tbody></table></div>`, "", false) : ""}`;
  wireRowActions(main, () => renderServerBlade("deploy", main));
  const go = $id("dpGo");
  if (go) go.addEventListener("click", async () => {
    await flushSave();
    if (reviewErrorCount()) { toast("Review and validate reports errors - fix them first", true); return; }
    try {
      const r = await api("POST", `/labs/${encodeURIComponent(lab.id)}/deploy`, { names: toBuild.map(p => p.name) });
      toast(`${r.jobs.length} build job(s) started`);
      state.blade = "jobs"; render();
    } catch (e) { toast(e.message, true); }
  });
}

/* The gold a designed VM builds from: the newest ready one for its image. */
function goldFor(s) {
  return cluster.golds.filter(g => g.status === "ready" && g.image_id === s.imageId)
    .sort((a, b) => String(b.created_at).localeCompare(String(a.created_at)))[0] || null;
}

/* -- Jobs -- */

let jobSelected = null;
function openJob(id) { jobSelected = id; state.blade = "jobs"; render(); }

/* The blade is built once and then updated in place: the list every few seconds, the log
   line by line. Rebuilding it on every render threw the log away and replayed it - the
   flicker - and cost a round trip before anything showed. */
let jobsPoll = null, jobFilter = "all", jobsCache = [];
const JOB_KIND = { bake: "Linux gold", "windows-bake": "Windows gold", winpe: "WinPE", virtio: "virtio-win", deploy: "Deploy", "cluster-check": "Cluster check", acme: "Certificate" };
const JOB_FILTERS = [["all", "All"], ["running", "Running"], ["failed", "Failed"], ["succeeded", "Succeeded"]];
function clock(iso) { return iso ? new Date(iso).toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" }) : ""; }
function dayOf(iso) {
  const d = new Date(iso), today = new Date(); today.setHours(0, 0, 0, 0);
  const diff = Math.round((today - new Date(d.getFullYear(), d.getMonth(), d.getDate())) / 86400000);
  return diff <= 0 ? "Today" : diff === 1 ? "Yesterday" : d.toLocaleDateString(undefined, { weekday: "long", month: "short", day: "numeric" });
}
function jobItems(jobs) {
  const shown = jobs.filter(j => jobFilter === "all" || j.status === jobFilter);
  if (!shown.length) return `<p class="hint job-none">No ${esc(jobFilter)} jobs.</p>`;
  let day = "", out = "";
  for (const j of shown) {
    const d = dayOf(j.started_at || j.created_at);
    if (d !== day) { day = d; out += `<div class="job-day">${esc(d)}</div>`; }
    out += `<button type="button" class="job-item s-${esc(j.status)} ${j.id === jobSelected ? "selected" : ""}" data-job="${esc(j.id)}">
      <span class="job-dot"></span>
      <span class="job-main"><span class="job-name">${esc(j.title)}</span>
        <span class="job-sub">${esc(JOB_KIND[j.kind] || j.kind)} · ${esc(j.created_by)} · ${esc(clock(j.started_at || j.created_at))}</span></span>
      <span class="job-took">${took(j.started_at, j.ended_at)}</span></button>`;
  }
  return out;
}
function jobMeta(j) {
  return `<span>${esc(JOB_KIND[j.kind] || j.kind)}</span><span>started ${esc(when(j.started_at || j.created_at))}</span>` +
    `<span>${j.ended_at ? "took" : "running for"} ${took(j.started_at, j.ended_at)}</span><span>by ${esc(j.created_by)}</span>`;
}

async function bladeJobs(main, stale) {
  clearTimeout(jobsPoll);
  const jobs = await api("GET", "/jobs");
  if (stale()) return;
  jobsCache = jobs;
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
              <div class="job-title"><h3 id="jobTitle"></h3><div class="job-meta" id="jobMeta"></div></div>
              <span id="jobStatus"></span>
            </header>
            <div id="jobError"></div>
            <div class="chomp" id="jobProgress" hidden>
              <div class="chomp-head"><span class="chomp-label"></span><span class="chomp-detail"></span><span class="chomp-pct"></span></div>
              <div class="chomp-line"><span class="chomp-br">[</span><span class="chomp-bar"></span><span class="chomp-br">]</span></div>
            </div>
            <div class="log-bar">
              <label class="log-opt"><input type="checkbox" id="logDebug"> Debug lines <span class="hint" id="logDebugN"></span></label>
              <label class="log-opt"><input type="checkbox" id="logFollow" checked> Follow</label>
              <span class="log-bar-fill"></span>
              <button class="btn" type="button" id="logCopy">Copy log</button>
            </div>
            <pre class="job-log" id="jobLog"></pre>
          </section>
        </div>`;
      $id("jobList").addEventListener("click", e => {
        const b = e.target.closest("[data-job]");
        if (!b || b.dataset.job === jobSelected) return;
        jobSelected = b.dataset.job;
        renderServerBlade("jobs", main);
      });
      $id("jobFilters").addEventListener("click", e => {
        const b = e.target.closest("[data-filter]"); if (!b) return;
        jobFilter = b.dataset.filter;
        setHtml($id("jobFilters"), jobFilterHtml(jobsCache));
        setHtml($id("jobList"), jobItems(jobsCache));
      });
      let debug = false; try { debug = localStorage.getItem("pvs.logDebug") === "1"; } catch { /* default */ }
      $id("logDebug").checked = debug; $id("jobLog").classList.toggle("hide-debug", !debug);
      $id("logDebug").addEventListener("change", e => {
        $id("jobLog").classList.toggle("hide-debug", !e.target.checked);
        try { localStorage.setItem("pvs.logDebug", e.target.checked ? "1" : "0"); } catch { /* fine */ }
      });
      $id("logFollow").addEventListener("change", e => { if (e.target.checked) { const p = $id("jobLog"); p.scrollTop = p.scrollHeight; } });
      $id("logCopy").addEventListener("click", async () => {
        try { await navigator.clipboard.writeText([...$id("jobLog").children].map(d => d.dataset.raw || d.textContent).join("\n")); toast("Log copied"); }
        catch (e) { toast("Copy failed: " + e.message, true); }
      });
    }
    setHtml($id("jobFilters"), jobFilterHtml(jobs));
    setHtml($id("jobList"), jobItems(jobs));
    if (job) {
      followLog(job);
      setHtml($id("jobMeta"), jobMeta(job));
      setHtml($id("jobStatus"), jobPill(job.status));
      setHtml($id("jobError"), job.error ? warnBanner(esc(job.error)) : "");
    }
  }
  jobsPoll = setTimeout(() => { if (!stale()) bladeJobs(main, stale).catch(() => {}); }, jobs.some(j => j.status === "running") ? 2000 : 15000);
}
function jobFilterHtml(jobs) {
  return JOB_FILTERS.map(([k, label]) => {
    const n = k === "all" ? jobs.length : jobs.filter(j => j.status === k).length;
    return `<button type="button" class="job-filter f-${k} ${jobFilter === k ? "on" : ""}" data-filter="${k}">${label}<span class="n">${n}</span></button>`;
  }).join("");
}

/* innerHTML only when it differs - an identical rewrite still re-lays out and loses hover. */
function setHtml(el, html) { if (el && el._html !== html) { el.innerHTML = html; el._html = html; } }

let liveLog = null, liveJob = null, logQueue = [], logFrame = 0, debugLines = 0;
function stopLiveLog() {
  if (liveLog) { liveLog.close(); liveLog = null; }
  liveJob = null; logQueue = []; cancelAnimationFrame(logFrame); logFrame = 0;
  clearTimeout(jobsPoll); clearInterval(chompTimer); chompTimer = null; chompState = null;
}

function followLog(job) {
  if (liveJob === job.id) return;
  stopLiveLog();
  liveJob = job.id;
  $id("jobTitle").textContent = job.title;
  $id("jobLog").textContent = ""; debugLines = 0; $id("logDebugN").textContent = "";
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
  });
}
function flushLog() {
  logFrame = 0;
  const p = $id("jobLog"); if (!p) { logQueue = []; return; }
  const frag = document.createDocumentFragment();
  for (const t of logQueue) { const d = logLine(t); if (d.classList.contains("t-debug")) debugLines++; frag.appendChild(d); }
  logQueue = [];
  p.appendChild(frag);
  if (debugLines) $id("logDebugN").textContent = `(${debugLines})`;
  if ($id("logFollow")?.checked) p.scrollTop = p.scrollHeight;
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
  // Serial console lines arrive as "| text" - the bar is the log's way of saying "echoed".
  const echoed = msg.startsWith("| ");
  div.className = "ln " + (TAG_CLASS[tag] || "t-error") + (echoed ? " echoed" : "") + (/^PVS-/.test(msg) ? " marker" : "");
  div.innerHTML = `<span class="ln-f">${esc(clk)}</span><span class="ln-f">[</span><span class="ln-tag">${esc(tag)}</span><span class="ln-f">]</span><span class="ln-msg">${esc(echoed ? msg.slice(2) : msg)}</span>`;
  return div;
}

/* The chomp bar - Write-ChompBar from New-Vhdx: chewed track in fg, the mouth in the log's
   yellow, the dots ahead (every third cell, fixed) in the accent. The bar shows measured
   progress only; the mouth alone moves, so a bar standing on one percentage still lives. */
const CHOMP_WIDTH = 42;
/* The bar fills its card: as many cells as the line holds (New-Vhdx sizes it to the console). */
function chompCells(el) {
  const line = el.querySelector(".chomp-line");
  if (!line._cw) { const s = document.createElement("span"); s.textContent = "0".repeat(20); line.appendChild(s); line._cw = s.getBoundingClientRect().width / 20; s.remove(); }
  return Math.max(20, Math.floor(line.clientWidth / (line._cw || 8)) - 3);
}
let chompFrame = 0, chompState = null, chompTimer = null;
function chompHtml(pct, frame, cells) {
  const w = cells || CHOMP_WIDTH;
  const filled = Math.round(Math.min(100, Math.max(0, pct || 0)) / 100 * w);
  if (filled >= w) return `<span class="c-track">${"-".repeat(w)}</span>`;
  const at = Math.max(0, filled - 1);
  let dots = "";
  for (let c = at + 1; c < w; c++) dots += c % 3 === 0 ? "o" : " ";
  return `<span class="c-track">${"-".repeat(at)}</span><span class="c-mouth">${frame % 4 < 2 ? "C" : "c"}</span><span class="c-dots">${dots}</span>`;
}
function paintChomp() {
  const el = $id("jobProgress"); if (!el || !chompState) return;
  el.querySelector(".chomp-bar").innerHTML = chompHtml(chompState.pct, chompFrame, chompCells(el));
  el.querySelector(".chomp-pct").textContent = `${Math.floor(chompState.pct || 0)}%`;
}
function showProgress(p) {
  const el = $id("jobProgress"); chompState = p;
  if (!el) return;
  if (!p) { el.hidden = true; clearInterval(chompTimer); chompTimer = null; return; }
  el.hidden = false;
  el.querySelector(".chomp-label").textContent = p.label;
  el.querySelector(".chomp-detail").textContent = p.detail || "";
  paintChomp();
  if (!chompTimer) chompTimer = setInterval(() => { chompFrame++; paintChomp(); }, 160);
}

/* -- General Settings: the server's half, below the studio's own cards -- */

const acmeForm = { email: "", challenge: "dns-01", dns_provider: "ionos", staging: false };

/* A card's actions: a row of their own under the fields, right-aligned, each with its
   glyph - the primary one on the accent, as the studio's own blades do. */
function act(id, icon, label, primary) {
  return `<button class="btn${primary ? " primary" : ""}" type="button" id="${id}"><img src="${primary ? iconSrcOnAccent(icon) : iconSrc(icon)}" alt=""> ${esc(label)}</button>`;
}
function actions(...buttons) { return `<div class="row gs-actions">${buttons.join("")}</div>`; }

async function fillServerGeneral() {
  const main = $id("main");
  let host = $id("serverGeneral");
  if (!host) { host = document.createElement("div"); host.id = "serverGeneral"; main.appendChild(host); }
  const seq = ++bladeSeq;
  const stale = () => seq !== bladeSeq || state.blade !== "general";
  let win, server, t;
  try { [win, server, t] = await Promise.all([api("GET", "/settings/windows"), api("GET", "/settings/server"), api("GET", "/tls")]); }
  catch (e) { if (!stale()) host.innerHTML = warnBanner(esc(e.message)); return; }
  if (stale() || !$id("serverGeneral")) return;
  const pe = win.winpe || {};
  const c = t.certificate, st = t.settings;
  if (!acmeForm.email && st.acme.email) Object.assign(acmeForm, st.acme);
  const mode = { acme: "Let's Encrypt", imported: "Imported", "self-signed": "Self-signed" }[st.mode] || "Self-signed";
  const vioChoices = [["stable", `stable${win.stable ? " (" + win.stable + ")" : ""}`], ["latest", `latest${win.latest ? " (" + win.latest + ")" : ""}`]]
    .concat(win.releases.map(r => [r, r + (win.present.includes(r) ? " · in PVE" : "")]));
  host.innerHTML = `
    ${gsCard("gs-winpe", "os-server-desktop.svg", "Windows: WinPE", pe.volid ? `${pe.volid} · build ${pe.build}` : "not built yet - Windows golds need it", `
      <p class="hint" style="margin-bottom:10px">Distilled from a Windows ISO: its boot files, boot.wim <b>index 2</b> (the Setup environment - the one that can service an offline image),
      our startnet.cmd, and the no-prompt EFI boot image. Every Windows bake boots it twice - to apply the image, and to customize it after sysprep.</p>
      ${pe.volid ? `<div class="kv-grid" style="margin-bottom:12px"><div>WinPE</div><div class="kv-val">${esc(pe.volid)}</div><div>Distilled from</div><div class="kv-val">${esc(pe.source_iso)}</div>
        <div>Build</div><div class="kv-val">${esc(pe.build)}</div><div>Built</div><div class="kv-val">${esc(when(pe.built))} on ${esc(pe.node)}</div></div>` : ""}
      <div class="grid-2">${field(fieldLabel("iso-media.svg", "Distil from"), `<select id="peIso"><option value="">Reading the ISOs…</option></select>`)}</div>
      ${actions(act("peBuild", "os-window.svg", pe.volid ? "Rebuild WinPE" : "Build WinPE", !pe.volid))}`, "", !pe.volid)}
    ${gsCard("gs-virtio", "integration.svg", "Windows: virtio-win", `${win.settings.virtio}${win.settings.virtio === "stable" && win.stable ? " (" + win.stable + ")" : ""}`, `
      <div class="grid-2">${field(fieldLabel("update.svg", "Release baked into Windows golds"), `<select id="vioSel">${opts(vioChoices, win.settings.virtio)}</select>
        <span class="hint">Drivers and QEMU guest agent. "stable" follows the virtio-win project's stable channel; a pinned release stays put.</span>`)}</div>
      ${actions(act("vioFetch", "download.svg", "Fetch into PVE now"), act("vioSave", "save.svg", "Save", true))}`, "", false)}
    ${gsCard("gs-dns", "dns.svg", "Studio: DNS name", server.settings.fqdn || "not set", `
      <div class="grid-2">${field(fieldLabel("dns.svg", "Fully qualified name"), `<input id="stFqdn" placeholder="pve-vm-studio.example.com" value="${esc(server.settings.fqdn)}">
        <span class="hint">What people type to reach the studio; the certificate is issued for it. It needs an A record for ${esc(server.suggested.filter(n => /^\d/.test(n)).join(", "))}.</span>`)}</div>
      ${actions(act("stFqdnSave", "save.svg", "Save", true))}`, "", false)}
    ${gsCard("gs-cert", "certificate.svg", "Studio: certificate", c ? `${mode} · ${c.days_left} days left` : "none", `
      ${c ? `<div class="kv-grid"><div>In use</div><div class="kv-val">${esc(mode)}</div><div>Names</div><div class="kv-val">${esc(c.names.join(", "))}</div>
        <div>Issuer</div><div class="kv-val">${esc(c.issuer)}</div><div>Valid until</div><div class="kv-val">${esc(when(c.not_after))} (${c.days_left} days)</div>
        ${st.mode === "acme" ? `<div>Renewal</div><div class="kv-val">automatic, checked twice a day${st.last_check ? " · last " + esc(when(st.last_check)) : ""}</div>` : ""}</div>` : ""}
      ${st.last_error ? `<p class="hint err" style="margin-top:8px">Last attempt failed: ${esc(st.last_error)}</p>` : ""}
      <div class="section collapsible ${isNestedOpen("gs-cert-le", st.mode !== "acme") ? "" : "collapsed"}" style="margin-top:14px"><div class="section-head" data-nested="gs-cert-le"><span class="section-chevron">${chevron()}</span>
        <img src="${iconSrc("certificate.svg")}" alt=""> Let's Encrypt<span class="section-meta">HTTP-01 or DNS-01 through 100+ DNS providers (lego)</span></div><div class="section-body">
        <div class="grid-3">${field(fieldLabel("users.svg", "Contact e-mail"), `<input id="leMail" type="email" value="${esc(acmeForm.email)}" placeholder="admin@example.com">`)}
          ${field(fieldLabel("validate.svg", "Challenge"), `<select id="leChallenge">${opts([["http-01", "HTTP-01 - port 80 reachable from the internet"], ["dns-01", "DNS-01 - a TXT record through your DNS provider"]], acmeForm.challenge)}</select>`)}
          <div class="toggle-grid" style="grid-template-columns:1fr">${stoggle("leStaging", "Staging", acmeForm.staging, "test the setup - not trusted by browsers")}</div></div>
        <div id="leDns" ${acmeForm.challenge === "dns-01" ? "" : "hidden"} style="margin-top:12px">
          <div class="grid-2">${field(fieldLabel("dns.svg", "DNS provider"), `<select id="leProvider">${opts(t.providers.map(p => [p.id, p.id + (p.saved ? " · credentials saved" : "")]), acmeForm.dns_provider)}</select>`)}</div>
          <pre class="provider-help" id="leHelp">…</pre>
          ${field(fieldLabel("secret.svg", "Credentials, one KEY=value per line"), `<textarea id="leCreds" style="min-height:90px" placeholder="IONOS_API_KEY=prefix.secret"></textarea>
            <span class="hint">Stored in the container, readable only by the studio, never shown again.</span>`)}</div>
        ${actions(act("leGo", "certificate.svg", "Get certificate", true))}</div></div>
      <div class="section collapsible ${isNestedOpen("gs-cert-import", false) ? "" : "collapsed"}"><div class="section-head" data-nested="gs-cert-import"><span class="section-chevron">${chevron()}</span>
        <img src="${iconSrc("certificate.svg")}" alt=""> Import a certificate<span class="section-meta">your own certificate and key, PEM</span></div><div class="section-body">
        <div class="grid-2">${field(fieldLabel("certificate.svg", "Certificate (PEM, with its chain)"), `<textarea id="imCert" placeholder="-----BEGIN CERTIFICATE-----"></textarea><input type="file" id="imCertFile" accept=".pem,.crt,.cer">`)}
          ${field(fieldLabel("key.svg", "Private key (PEM)"), `<textarea id="imKey" placeholder="-----BEGIN PRIVATE KEY-----"></textarea><input type="file" id="imKeyFile" accept=".pem,.key">`)}</div>
        ${actions(act("ssGo", "update.svg", "New self-signed certificate"), act("imGo", "certificate.svg", "Import", true))}</div></div>`, "", false)}`;

  api("GET", "/windows/isos").then(r => {
    const list = r.isos.filter(i => i.readable);
    if ($id("peIso")) $id("peIso").innerHTML = list.length ? opts(list.map(i => [i.volid, i.file]), pe.source_iso || list[0].volid) : '<option value="">No readable Windows ISO in PVE yet</option>';
  }).catch(e => { if ($id("peIso")) $id("peIso").innerHTML = `<option value="">${esc(e.message)}</option>`; });
  if (acmeForm.challenge === "dns-01" && acmeForm.dns_provider && $id("leHelp")) {
    api("GET", "/tls/providers/" + encodeURIComponent(acmeForm.dns_provider)).then(r => { if ($id("leHelp")) $id("leHelp").textContent = r.help; })
      .catch(e => { if ($id("leHelp")) $id("leHelp").textContent = e.message; });
  }
  const on = (id, ev, fn) => { const el = $id(id); if (el) el.addEventListener(ev, fn); };
  on("peBuild", "click", async () => {
    if (!$id("peIso").value) return toast("Pick a Windows ISO first", true);
    try { const { id } = await api("POST", "/winpe/build", { volid: $id("peIso").value }); openJob(id); } catch (e) { toast(e.message, true); }
  });
  on("vioSave", "click", async () => { try { await api("PUT", "/settings/windows", { ...win.settings, virtio: $id("vioSel").value }); toast("Saved"); } catch (e) { toast(e.message, true); } });
  on("vioFetch", "click", async () => {
    try { await api("PUT", "/settings/windows", { ...win.settings, virtio: $id("vioSel").value }); const { id } = await api("POST", "/virtio/fetch"); openJob(id); }
    catch (e) { toast(e.message, true); }
  });
  on("stFqdnSave", "click", async () => { try { await api("PUT", "/settings/server", { fqdn: $id("stFqdn").value }); toast("Saved"); render(); } catch (e) { toast(e.message, true); } });
  const keepAcme = () => { acmeForm.email = $id("leMail").value.trim(); acmeForm.challenge = $id("leChallenge").value; acmeForm.dns_provider = $id("leProvider").value; acmeForm.staging = $id("leStaging").checked; };
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
