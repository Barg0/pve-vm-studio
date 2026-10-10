/* The maintenance console's page. Plain DOM and fetch: it has to work when everything else
   does not. Each section is one render function; the hash names the section. */
"use strict";

const SECTIONS = [
  ["pve", "PVE connection"],
  ["network", "Network"],
  ["certificate", "DNS name & certificate"],
  ["cas", "Trusted CAs"],
  ["time", "Time"],
  ["version", "Version"],
  ["debug", "Debug tools"],
  ["service", "Service"],
  ["shell", "Shell"],
  ["password", "Console password"],
];

const ui = { session: null, status: null, page: "pve", msg: null, term: null, logTimer: null, statusTimer: null };

const $ = id => document.getElementById(id);
const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const gb = b => (b / 1e9).toFixed(1) + " GB";
/* 47:51:D5:5F:…:44:97:1B:53 - the whole one on hover, for comparing with PVE's page. */
const fp = f => { const p = String(f || "").split(":"); return p.length > 10 ? `<span title="${esc(f)}">${esc(p.slice(0, 4).join(":"))}:…:${esc(p.slice(-4).join(":"))}</span>` : esc(f); };
const day = iso => iso ? String(iso).replace("T", " ").replace(/:\d\d(\.\d+)?(Z|[+-]\d\d:\d\d)$/, "") : "";

async function api(method, path, body) {
  const opt = { method, headers: {} };
  if (method !== "GET") opt.headers["X-Console"] = "1";
  if (body !== undefined) { opt.headers["Content-Type"] = "application/json"; opt.body = JSON.stringify(body); }
  const r = await fetch("/api" + path, opt);
  if (r.status === 401 && path !== "/session") { ui.session = null; boot(); throw new Error("not signed in"); }
  const text = await r.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch { data = { error: text }; }
  if (!r.ok) throw new Error((data && data.error) || `${r.status} ${r.statusText}`);
  return data;
}

function say(text, ok) { ui.msg = text ? { text, ok } : null; const m = $("msg"); if (m) paintMsg(m); }
function paintMsg(m) {
  m.hidden = !ui.msg;
  if (ui.msg) { m.className = "msg " + (ui.msg.ok ? "ok" : "err"); m.textContent = ui.msg.text; }
}

/* A button that does something hard to undo asks by itself: the first click arms it for
   four seconds, the second does it. No dialogs. */
function armed(btn, label) {
  if (btn.dataset.armed === "1") { btn.dataset.armed = ""; btn.classList.remove("armed"); btn.textContent = btn.dataset.label; return true; }
  btn.dataset.label = btn.textContent;
  btn.dataset.armed = "1";
  btn.classList.add("armed");
  btn.textContent = label || "Click again to confirm";
  setTimeout(() => { if (btn.dataset.armed === "1") { btn.dataset.armed = ""; btn.classList.remove("armed"); btn.textContent = btn.dataset.label; } }, 4000);
  return false;
}

async function busy(btn, fn) {
  const was = btn.disabled;
  btn.disabled = true;
  try { await fn(); } catch (e) { say(e.message, false); } finally { btn.disabled = was; }
}

function theme() { return document.documentElement.dataset.theme === "light" ? "light" : "dark"; }
function toggleTheme() {
  const t = theme() === "light" ? "dark" : "light";
  document.documentElement.dataset.theme = t;
  try { localStorage.setItem("pvs-console-theme", t); } catch (e) {}
  paintBar();
  if (ui.term) ui.term.options.theme = termTheme();
}

// ---- frame ----

function paintBar() {
  const s = ui.session || {};
  $("barHost").textContent = ["PVE VM Studio", s.host, `${location.hostname}:${s.port || location.port}`].filter(Boolean).join(" · ");
  const studio = s.fqdn ? `https://${s.fqdn}${s.studio_port && s.studio_port !== 443 ? ":" + s.studio_port : ""}` : `${location.protocol}//${location.hostname}${s.studio_port && s.studio_port !== 443 ? ":" + s.studio_port : ""}`;
  $("barRight").innerHTML = (s.signed_in ? `<span>${esc(s.user)}</span> · ` : "")
    + `<button type="button" class="link" id="themeBtn">${theme() === "light" ? "Dark" : "Light"}</button>`
    + (s.signed_in ? ` · <button type="button" class="link" id="signOut">Sign out</button>` : "")
    + ` · <a href="${esc(studio)}" style="font-weight:700">Open the studio</a>`;
  $("themeBtn").onclick = toggleTheme;
  if ($("signOut")) $("signOut").onclick = async () => { try { await api("DELETE", "/session"); } catch (e) {} ui.session = null; boot(); };
}

function paintNav() {
  const nav = $("nav");
  if (!nav) return;
  const st = ui.status || {};
  const dot = st.pve_trusted === false ? ` <span class="dot" title="PVE's certificate is not trusted">●</span>` : "";
  const studio = st.studio ? (st.studio.active === "active" ? "running" : st.studio.active) : "…";
  const up = st.uptime ? `${Math.floor(st.uptime / 86400)}d ${Math.floor(st.uptime % 86400 / 3600)}h` : "";
  nav.innerHTML = SECTIONS.map(([id, label]) => `<a href="#${id}" class="${ui.page === id ? "on" : ""}">${esc(label)}${id === "pve" ? dot : ""}</a>`).join("")
    + `<div class="stat"><span>studio: <span class="${studio === "running" ? "" : "bad"}">${esc(studio)}</span></span><span>jobs: ${st.jobs ?? "…"} running</span>${up ? `<span>up ${up}</span>` : ""}<span>${esc(st.version || "")}</span></div>`;
}

async function refreshStatus() {
  try { ui.status = await api("GET", "/status"); paintNav(); } catch (e) {}
}

async function boot() {
  clearInterval(ui.statusTimer);
  stopLog();
  closeTerm();
  try { ui.session = await api("GET", "/session"); } catch (e) { ui.session = {}; }
  paintBar();
  const wrap = $("wrap");
  if (ui.session.off) {
    wrap.innerHTML = `<div class="signin"><form><h1>Switched off</h1><div>The maintenance console is switched off in the studio (Studio settings → Maintenance console).</div><div class="muted">On the node:<br><span class="mono" style="color:var(--fg)">pct exec &lt;ct&gt; -- pve-vm-studio console-enable</span></div></form></div>`;
    return;
  }
  if (!ui.session.signed_in) return signInPage();
  wrap.innerHTML = `<nav class="nav" id="nav" aria-label="Sections"></nav><main class="main" id="main"></main>`;
  route();
  refreshStatus();
  ui.statusTimer = setInterval(refreshStatus, 15000);
}

function signInPage() {
  const s = ui.session;
  $("wrap").innerHTML = `<div class="signin"><form id="signin">
    <h1>Sign in</h1>
    <div class="field"><label for="u">User</label><input id="u" value="${esc(s.user || "maint")}" autocomplete="username" readonly></div>
    <div class="field"><label for="p">Password</label><input id="p" type="password" autocomplete="current-password" autofocus></div>
    <div class="bad" id="signinErr" hidden></div>
    <button type="submit" class="btn pri">Sign in</button>
    <div class="muted" style="border-top:1px solid var(--line);padding-top:10px">${s.password_set === false ? "No password is set yet." : "Lost the password?"} On the node:<br><span class="mono" style="color:var(--fg)">pct exec &lt;ct&gt; -- pve-vm-studio console-password --reset</span></div>
  </form></div>`;
  $("signin").onsubmit = async e => {
    e.preventDefault();
    const btn = e.submitter || $("signin").querySelector("button");
    btn.disabled = true;
    try {
      await api("POST", "/session", { password: $("p").value });
      boot();
    } catch (err) {
      $("signinErr").hidden = false; $("signinErr").textContent = err.message; $("p").select();
    } finally { btn.disabled = false; }
  };
}

function route() {
  const id = (location.hash || "#pve").slice(1);
  const page = SECTIONS.some(s => s[0] === id) ? id : "pve";
  if (page !== ui.page) ui.msg = null;
  ui.page = page;
  stopLog();
  if (page !== "shell") closeTerm();
  paintNav();
  const main = $("main");
  if (!main) return;
  main.className = "main" + (page === "shell" || page === "service" ? " wide" : "");
  const label = SECTIONS.find(s => s[0] === page)[1];
  main.innerHTML = `<h1>${esc(label)}</h1><div id="msg" hidden></div><div id="body" class="muted">Loading…</div>`;
  paintMsg($("msg"));
  PAGES[page]().catch(e => { $("body").innerHTML = ""; say(e.message, false); });
}
window.addEventListener("hashchange", () => { if (ui.session && ui.session.signed_in) route(); });

function body(html) { const b = $("body"); b.className = ""; b.style.display = "flex"; b.style.flexDirection = "column"; b.style.gap = "14px"; b.innerHTML = html; return b; }
const kv = rows => `<table class="kv"><tbody>${rows.filter(Boolean).map(([k, v]) => `<tr><th scope="row">${esc(k)}</th><td>${v}</td></tr>`).join("")}</tbody></table>`;
const on = (id, ev, fn) => { const el = $(id); if (el) el.addEventListener(ev, fn); };

function readFile(input) {
  return new Promise((res, rej) => {
    const f = input.files && input.files[0];
    if (!f) return rej(new Error("pick a file first"));
    const r = new FileReader();
    r.onload = () => res(String(r.result).split(",")[1] || "");
    r.onerror = () => rej(new Error("the file could not be read"));
    r.readAsDataURL(f);
  });
}
function readText(input) {
  return new Promise((res, rej) => {
    const f = input.files && input.files[0];
    if (!f) return res("");
    const r = new FileReader();
    r.onload = () => res(String(r.result));
    r.onerror = () => rej(new Error("the file could not be read"));
    r.readAsText(f);
  });
}

// ---- pages ----

const PAGES = {};

PAGES.pve = async () => {
  const d = await api("GET", "/pve");
  const first = d.nodes[0] || {};
  let note = "";
  if (first.unreachable) note = `<div class="note">The studio cannot reach PVE at ${esc(first.url)}: ${esc(first.unreachable)}</div>`;
  else if (!first.trusted) {
    const issuer = first.chain[0] ? first.chain[0].issuer : "an unknown CA";
    note = `<div class="note">The studio cannot check ${esc(first.node)}'s certificate: it was issued by ${esc(issuer)}, which the studio does not trust. Sign-in to the studio fails until it does.</div>`;
  } else if (!first.api_ok) note = `<div class="note warn">The certificate is trusted, but PVE did not accept the studio's token: ${esc(first.api_error || "")}</div>`;
  const status = first.unreachable ? `<span class="bad">not reached</span>` : !first.trusted ? `<span class="bad">Certificate not trusted${first.trust_error ? ` (${esc(first.trust_error)})` : ""}</span>`
    : first.api_ok ? `<span class="ok">trusted${first.trusted_by === "pin" ? " (this certificate only)" : ""} · token accepted · PVE ${esc(first.pve_version || "")}</span>` : `<span class="warn">trusted · token not accepted</span>`;
  const chainTable = n => {
    if (!n.chain.length) return "";
    const rows = n.chain.map((c, i) => {
      const lead = i === 0 ? "" : (i === n.chain.length - 1 ? "└─ " : "├─ ");
      const state = i === 0 ? (n.trusted ? `<span class="ok">trusted${n.trusted_by === "pin" ? " (pinned)" : ""}</span>` : `<span class="bad">unknown issuer</span>`) : (n.trusted ? "sent" : "sent, not trusted");
      const names = c.names.length ? `<br><span class="muted">${esc(c.names.join(", "))}</span>` : "";
      const btn = !n.trusted && c.is_ca ? `<br><button type="button" class="btn sm" data-trust="ca" data-url="${esc(n.url)}" data-fp="${esc(c.fingerprint)}">Trust this CA</button>` : "";
      return `<tr><td>${lead}${esc(c.subject)}${names}${btn}</td><td class="nw">${esc(c.not_before)} → ${esc(c.not_after)}</td><td class="mono">${fp(c.fingerprint)}</td><td>${state}</td></tr>`;
    });
    const top = n.chain[n.chain.length - 1];
    if (top && !top.self_signed) {
      const aia = top.aia.length ? `AIA ${top.aia.map(a => esc(a.split("?")[0].slice(0, 60))).join(", ")}` : "no AIA";
      rows.push(`<tr><td>└─ ${esc(top.issuer)}</td><td>—</td><td>—</td><td class="muted">not sent · ${aia}</td></tr>`);
    }
    return `<div class="box"><table class="grid mono"><thead><tr><th>Subject</th><th>Valid</th><th>SHA-256</th><th>State</th></tr></thead><tbody>${rows.join("")}</tbody></table></div>`;
  };
  const issuerCa = first.chain.slice(1).find(c => c.is_ca);
  const actions = first.chain.length && !first.trusted ? `<div class="btns">
      ${issuerCa ? `<button type="button" class="btn pri" data-trust="ca" data-url="${esc(first.url)}" data-fp="${esc(issuerCa.fingerprint)}">Trust issuer: ${esc((issuerCa.subject.match(/CN=([^,]+)/) || [, issuerCa.subject])[1])}</button>` : ""}
      <a class="btn" href="#cas" style="text-decoration:none;display:inline-flex;align-items:center">Upload CA…</a>
      <button type="button" class="btn" data-trust="pin" data-url="${esc(first.url)}" data-fp="${esc(first.chain[0].fingerprint)}">Trust this certificate only</button>
      <button type="button" class="btn" id="pveTest">Test connection</button>
    </div>` : `<div class="btns"><button type="button" class="btn" id="pveTest">Test connection</button></div>`;
  const others = d.nodes.slice(1);
  const nodeRow = n => `<tr><td>${esc(n.node)}</td><td class="mono">${esc(n.url.replace("https://", ""))}${n.tls_name ? `<br><span class="muted">as ${esc(n.tls_name)}</span>` : ""}</td>
    <td>${n.unreachable ? `<span class="bad">not reached</span>` : n.trusted ? `<span class="ok">${n.trusted_by === "pin" ? "pinned" : "CA"}</span>` : `<span class="bad">not trusted</span>`}</td><td>${esc(n.chain[0] ? n.chain[0].not_after : "")}</td></tr>`;
  const b = body(`${note}
    ${kv([["API", `<span class="mono">${esc(d.config.url)}</span>`], d.config.tls_name ? ["Name on certificate", `<span class="mono">${esc(d.config.tls_name)}</span>`] : first.chain[0] && first.chain[0].names.length ? ["Names on certificate", `<span class="mono">${esc(first.chain[0].names.join(", "))}</span>`] : null,
      ["API token", `<span class="mono">${esc(d.config.token_id)}</span>`], ["Status", status], d.config.insecure ? ["Checks", `<span class="warn">insecure = true - certificates are not checked</span>`] : null])}
    <h2>Certificate chain ${esc(first.node || "")} sends</h2>
    <div class="muted">Compare with PVE → ${esc(first.node || "node")} → System → Certificates.</div>
    ${chainTable(first) || `<div class="muted">Nothing received.</div>`}
    ${actions}
    <h2>Cluster nodes</h2>
    <div class="box"><table class="grid"><thead><tr><th>Node</th><th>Address</th><th>Trusted by</th><th>Certificate until</th></tr></thead><tbody>
      ${nodeRow(first)}${others.map(nodeRow).join("")}
      ${d.learned ? "" : `<tr><td colspan="4" class="muted">The other nodes show up once the studio reaches PVE.</td></tr>`}
    </tbody></table></div>
    ${others.filter(n => !n.trusted && n.chain.length).map(n => `<h2>${esc(n.node)}</h2>${chainTable(n)}<div class="btns"><button type="button" class="btn" data-trust="pin" data-url="${esc(n.url)}" data-fp="${esc(n.chain[0].fingerprint)}">Trust this certificate only</button></div>`).join("")}
    <h2>Connection settings</h2>
    <form class="form wide" id="connForm">
      <label for="cUrl">API address</label><input id="cUrl" class="mono" value="${esc(d.config.url)}">
      <label for="cName">Name on certificate</label><input id="cName" class="mono" value="${esc(d.config.tls_name || "")}" placeholder="only when it is not the address">
      <label for="cTok">Token id</label><input id="cTok" class="mono" value="${esc(d.config.token_id)}">
      <label for="cSec">Token secret</label><input id="cSec" class="mono" type="password" placeholder="unchanged" autocomplete="off">
    </form>
    <div class="btns"><button type="button" class="btn" id="connSave">Save and restart the studio</button></div>`);
  b.querySelectorAll("[data-trust]").forEach(btn => btn.addEventListener("click", () => busy(btn, async () => {
    if (btn.dataset.trust === "pin" && !armed(btn, "Click again: trusted until it is renewed")) return;
    await api("POST", "/pve/trust", { url: btn.dataset.url, fingerprint: btn.dataset.fp, how: btn.dataset.trust });
    say(btn.dataset.trust === "pin" ? "This certificate is trusted - the studio takes it within seconds." : "CA trusted - the studio takes it within seconds.", true);
    await PAGES.pve(); refreshStatus();
  })));
  on("pveTest", "click", e => busy(e.target, async () => { await PAGES.pve(); refreshStatus(); say("Checked " + new Date().toLocaleTimeString(), true); }));
  on("connSave", "click", e => busy(e.target, async () => {
    if (!armed(e.target, "Click again: write config.toml and restart")) return;
    const r = await api("PUT", "/pve/connection", { url: $("cUrl").value, tls_name: $("cName").value, token_id: $("cTok").value, token_secret: $("cSec").value });
    say(r.restarted ? "Saved - the studio restarts with it." : "Saved - jobs are running, so it takes effect at the studio's next restart (Service).", true);
  }));
};

PAGES.network = async () => {
  const d = await api("GET", "/network");
  const n = d.now;
  const now = `<pre class="pre">${esc(n.addr)}
route  ${esc(n.route || "none")}
dns    ${esc(n.dns.join("  "))}${n.search ? "   search " + esc(n.search) : ""}
reach  PVE ${esc(n.pve)} <span class="${n.pve_reach === "open" ? "ok" : "bad"}">${esc(n.pve_reach)}</span>${n.fqdn ? ` · ${esc(n.fqdn)} → <span class="${(n.fqdn_resolves || []).length ? "ok" : "bad"}">${(n.fqdn_resolves || []).length ? esc(n.fqdn_resolves.join(", ")) : "does not resolve"}</span>` : ""}</pre>`;
  if (d.error) {
    body(`<div class="note warn">The container's network belongs to PVE (its CT → net0), so it is changed through the PVE API - not reachable now: ${esc(d.error)}</div><h2>Now</h2>${now}`);
    return;
  }
  const o = d.own;
  const b = body(`<form class="form">
      <span>Interface</span><span class="mono">${esc(o.iface)} · ${esc(o.bridge)}${o.vlan ? " · VLAN " + esc(o.vlan) : ""} · CT ${esc(o.vmid)} on ${esc(o.node)}</span>
      <span>Address</span><div class="radio"><label><input type="radio" name="nm" value="static" ${o.mode === "static" ? "checked" : ""}> Static</label><label><input type="radio" name="nm" value="dhcp" ${o.mode === "dhcp" ? "checked" : ""}> DHCP</label></div>
      <label for="nIp">IPv4 / prefix</label><input id="nIp" class="mono" value="${esc(o.ip || o.current_ip)}">
      <label for="nGw">Gateway</label><input id="nGw" class="mono" value="${esc(o.gw || o.current_gw)}">
      <label for="nDns">DNS servers</label><input id="nDns" class="mono" value="${esc((o.dns || []).join(", "))}">
      <span>Search domain</span><span class="mono">${esc(o.searchdomain || "—")}</span>
    </form>
    <div class="btns"><button type="button" class="btn pri" id="nApply">Apply and restart the container</button></div>
    <h2>Now</h2>${now}`);
  const sync = () => { const st = b.querySelector("input[name=nm]:checked").value === "static"; $("nIp").disabled = $("nGw").disabled = !st; };
  b.querySelectorAll("input[name=nm]").forEach(r => r.addEventListener("change", sync)); sync();
  on("nApply", "click", e => busy(e.target, async () => {
    if (!armed(e.target, "Click again: the container restarts")) return;
    const mode = b.querySelector("input[name=nm]:checked").value;
    const r = await api("PUT", "/network", { mode, ip: $("nIp").value.trim(), gw: $("nGw").value.trim(), dns: $("nDns").value.split(/[\s,]+/).filter(Boolean) });
    say(`Set - the container restarts now. Reconnect at ${mode === "dhcp" ? "its new address" : r.ip.split("/")[0]}:${ui.session.port}.`, true);
  }));
};

PAGES.certificate = async () => {
  const d = await api("GET", "/certificate");
  const c = d.certificate;
  const modes = { acme: "Let's Encrypt", imported: "uploaded", "self-signed": "self-signed", "": "self-signed (made at install)" };
  const b = body(`<form class="form"><label for="fq">DNS name</label><input id="fq" class="mono" value="${esc(d.fqdn)}"></form>
    <div class="btns"><button type="button" class="btn" id="fqSave">Save name</button></div>
    <h2>Certificate in use</h2>
    ${c ? kv([["Subject", `<span class="mono">${esc(c.subject)}</span>`], ["Names", `<span class="mono">${esc(c.names.join(", "))}</span>`], ["Issuer", `<span class="mono">${esc(c.issuer)}</span>`],
      ["Valid", `${esc(day(c.not_before))} → ${esc(day(c.not_after))} · <span class="${c.days_left < 14 ? "bad" : c.days_left < 30 ? "warn" : "ok"}">${c.days_left} days left</span>`],
      ["SHA-256", `<span class="mono">${esc(d.fingerprint || "")}</span>`], ["From", esc(modes[d.settings.mode || ""] || d.settings.mode)],
      d.settings.last_error ? ["Last renewal", `<span class="bad">${esc(d.settings.last_error)}</span>`] : null]) : `<div class="muted">${d.plain_http ? "plain_http is set - no certificate." : "None yet."}</div>`}
    ${d.plain_http ? "" : `<h2>Replace it</h2>
    <div class="tabs" role="tablist"><button type="button" role="tab" class="tab on" data-tab="pfx">Upload .pfx (AD CS, Windows)</button><button type="button" role="tab" class="tab" data-tab="pem">Upload PEM</button><button type="button" role="tab" class="tab" data-tab="self">Self-signed</button></div>
    <div data-pane="pfx"><form class="form"><label for="pfx">Certificate (.pfx / .p12)</label><input id="pfx" type="file" accept=".pfx,.p12"><label for="pfxPw">Password</label><input id="pfxPw" type="password" autocomplete="off"></form>
      <div class="btns" style="margin-top:10px"><button type="button" class="btn pri" id="pfxGo">Check and use</button></div></div>
    <div data-pane="pem" hidden><form class="form"><label for="pemCert">Certificate (.pem / .crt, chain included)</label><input id="pemCert" type="file" accept=".pem,.crt,.cer"><label for="pemKey">Private key (.pem / .key)</label><input id="pemKey" type="file" accept=".pem,.key"></form>
      <div class="btns" style="margin-top:10px"><button type="button" class="btn pri" id="pemGo">Check and use</button></div></div>
    <div data-pane="self" hidden><div class="muted">A new self-signed certificate for ${esc(d.fqdn || "the studio")} and its addresses, valid ten years.</div>
      <div class="btns" style="margin-top:10px"><button type="button" class="btn" id="selfGo">Make and use</button></div></div>
    <div class="muted">Let's Encrypt is ordered in the studio (Studio settings → Certificate). The studio and this console switch to a new certificate within seconds; running jobs keep running.</div>`}`);
  b.querySelectorAll("[data-tab]").forEach(t => t.addEventListener("click", () => {
    b.querySelectorAll("[data-tab]").forEach(x => x.classList.toggle("on", x === t));
    b.querySelectorAll("[data-pane]").forEach(p => p.hidden = p.dataset.pane !== t.dataset.tab);
  }));
  on("fqSave", "click", e => busy(e.target, async () => { await api("PUT", "/certificate/fqdn", { fqdn: $("fq").value }); say("Name saved. A certificate for it: below, or Let's Encrypt in the studio.", true); }));
  on("pfxGo", "click", e => busy(e.target, async () => {
    const pfx = await readFile($("pfx"));
    const r = await api("POST", "/certificate/import", { pfx, password: $("pfxPw").value });
    say(`In use: ${r.subject}, until ${day(r.not_after)}.`, true); await PAGES.certificate();
  }));
  on("pemGo", "click", e => busy(e.target, async () => {
    const cert = await readText($("pemCert")), key = await readText($("pemKey"));
    if (!cert || !key) throw new Error("pick the certificate and its key");
    const r = await api("POST", "/certificate/import", { cert, key });
    say(`In use: ${r.subject}, until ${day(r.not_after)}.`, true); await PAGES.certificate();
  }));
  on("selfGo", "click", e => busy(e.target, async () => {
    if (!armed(e.target, "Click again: browsers will warn")) return;
    await api("POST", "/certificate/self-signed"); say("Self-signed certificate in use.", true); await PAGES.certificate();
  }));
};

PAGES.cas = async () => {
  const d = await api("GET", "/cas");
  const caRow = (c, fromInstaller) => `<tr><td class="mono">${esc(c.name)}<br><span class="muted">${esc(c.kind)}</span></td><td>${esc(day(c.not_after))}</td><td class="mono">${fp(c.fingerprint)}</td>
    <td>${fromInstaller ? `<span class="muted">installer</span>` : `<button type="button" class="btn sm dan" data-rm-ca="${esc(c.fingerprint)}">Remove</button>`}</td></tr>`;
  const b = body(`<div class="muted">For PVE's certificates, beside the system's own roots. The same list as the studio's Studio settings → Trusted CAs.</div>
    <div class="box"><table class="grid"><thead><tr><th>CA</th><th>Valid until</th><th>SHA-256</th><th></th></tr></thead><tbody>
      ${d.cluster.map(c => caRow(c, true)).join("")}${d.added.map(c => caRow(c, false)).join("")}
      ${d.cluster.length + d.added.length ? "" : `<tr><td colspan="4" class="muted">None.</td></tr>`}
    </tbody></table></div>
    <form class="form"><label for="caFile">Add a CA</label><input id="caFile" type="file" accept=".cer,.crt,.pem,.der,.p7b"></form>
    <div class="btns"><button type="button" class="btn pri" id="caAdd">Add</button><span class="muted">.cer / .crt / .pem / .p7b - certlm → Export → Base-64 X.509 or DER</span></div>
    <h2>Pinned certificates</h2>
    <div class="muted">Node certificates trusted as they are, without a CA. A pin stops working when the node's certificate is renewed.</div>
    <div class="box"><table class="grid"><thead><tr><th>Node</th><th>Subject</th><th>SHA-256</th><th>Expires</th><th></th></tr></thead><tbody>
      ${d.pins.map(p => `<tr><td>${esc(p.node)}</td><td class="mono">${esc(p.subject)}<br><span class="muted">${esc(p.added_by)} · ${esc(day(p.added_at))}</span></td><td class="mono">${fp(p.fingerprint)}</td><td>${esc(p.not_after)}</td><td><button type="button" class="btn sm dan" data-rm-pin="${esc(p.fingerprint)}">Remove</button></td></tr>`).join("") || `<tr><td colspan="5" class="muted">None.</td></tr>`}
    </tbody></table></div>`);
  on("caAdd", "click", e => busy(e.target, async () => {
    const data = await readFile($("caFile"));
    const peek = await api("POST", "/cas", { data });
    if (!peek.cas.length) throw new Error("the file holds no CA certificate" + (peek.skipped.length ? ` (only ${peek.skipped.join(", ")})` : ""));
    await api("POST", "/cas", { data, commit: true });
    say(`Trusted: ${peek.cas.map(c => c.name).join(", ")} - the studio takes it within seconds.`, true); await PAGES.cas(); refreshStatus();
  }));
  b.querySelectorAll("[data-rm-ca]").forEach(btn => btn.addEventListener("click", () => busy(btn, async () => {
    if (!armed(btn, "Remove?")) return;
    await api("DELETE", "/cas/" + encodeURIComponent(btn.dataset.rmCa)); say("Removed.", true); await PAGES.cas();
  })));
  b.querySelectorAll("[data-rm-pin]").forEach(btn => btn.addEventListener("click", () => busy(btn, async () => {
    if (!armed(btn, "Remove?")) return;
    await api("DELETE", "/pins/" + encodeURIComponent(btn.dataset.rmPin)); say("Removed.", true); await PAGES.cas();
  })));
};

PAGES.time = async () => {
  const d = await api("GET", "/time");
  const drift = Math.round((Date.now() - d.epoch_ms) / 1000);
  const z = d.zone || {};
  const b = body(`${kv([["Now", `<span class="mono">${esc(d.local)} · ${esc(d.utc)}</span>`],
      ["Clock", `from the host${d.synced === true ? ` · <span class="ok">NTP in sync</span>` : d.synced === false ? ` · <span class="bad">not in sync</span>` : ""}`],
      ["Your browser", `<span class="mono">${new Date().toLocaleTimeString()} · ${Math.abs(drift) <= 2 ? "in step" : `${Math.abs(drift)} s apart`}</span>`]])}
    <div class="muted">A container shares the host's clock; NTP is set on the node, not here.</div>
    <h2>Time zone</h2>
    ${z.error ? `<div class="note warn">The time zone is the container's setting in PVE - not reachable now: ${esc(z.error)}</div>` : ""}
    <form class="form">
      <label for="tz">Time zone</label><input id="tz" class="mono" list="tzList" value="${esc(z.config || "")}" ${z.error ? "disabled" : ""}>
      <label for="clk">Clock in the studio</label><select id="clk"><option value="24h" ${d.clock === "24h" ? "selected" : ""}>24 h</option><option value="12h" ${d.clock === "12h" ? "selected" : ""}>12 h</option></select>
    </form>
    <datalist id="tzList"><option value="host">${(d.zones || []).map(x => `<option value="${esc(x)}">`).join("")}</datalist>
    <div class="btns"><button type="button" class="btn pri" id="tzSave">Save</button><span class="muted">A new time zone restarts the container.</span></div>`);
  on("tzSave", "click", e => busy(e.target, async () => {
    const tz = $("tz").value.trim();
    if (z.config && tz !== z.config && !armed(e.target, "Click again: the container restarts")) return;
    const r = await api("PUT", "/time", { timezone: z.error ? "" : tz, clock: $("clk").value });
    say(r.rebooting ? "Saved - the container restarts now." : "Saved.", true);
  }));
  void b;
};

PAGES.version = async (fresh) => {
  const d = await api("GET", "/version" + (fresh ? "?fresh=true" : ""));
  const s = d.status || {}, set = d.settings;
  const dev = set.channel === "development";
  const newestStable = (s.releases || [])[0];
  const devb = s.development || null;
  const target = dev ? (devb && s.state === "update" ? { tag: "development", label: devb.commit } : null) : (s.state === "update" && newestStable ? { tag: newestStable.tag, label: newestStable.version } : null);
  const b = body(`<div class="btns"><span class="muted" style="width:180px">Channel</span>
      <div class="seg" role="radiogroup" aria-label="Update channel"><button type="button" role="radio" aria-checked="${!dev}" class="${dev ? "" : "on"}" data-ch="stable">Stable</button><button type="button" role="radio" aria-checked="${dev}" class="${dev ? "on" : ""}" data-ch="development">Development</button></div>
      <span class="muted">Development: every commit on main, built by CI, untested.</span></div>
    ${kv([["Installed", `<span class="mono">${esc(s.version || "")} · ${esc(s.commit || "")}</span>`],
      ["Newest on Stable", newestStable ? `<span class="mono">${esc(newestStable.version)} · ${esc(day(newestStable.published))}</span>${!dev && s.state === "update" ? ` <span class="warn">— update available</span>` : ""}` : `<span class="muted">—</span>`],
      ["Newest on Development", devb ? `<span class="mono">${esc(devb.commit)}${devb.ahead ? ` · ${devb.ahead} commit(s) newer` : ""}</span>${dev && s.state === "update" ? ` <span class="warn">— update available</span>` : ""}` : `<span class="muted">${dev ? "none published yet" : "—"}</span>`],
      ["Last check", esc(day(s.checked) || "—")], s.error ? ["Check", `<span class="bad">${esc(s.error)}</span>`] : null,
      ["Container OS", `<span class="mono">${esc(d.os)}${d.lego ? " · lego " + esc(d.lego) : ""}</span>`]])}
    <label class="chk"><input type="checkbox" id="vAuto" ${set.auto ? "checked" : ""}> Install updates automatically in a maintenance window</label>
    <div class="btns">
      ${target ? `<button type="button" class="btn pri" id="vUpdate" data-tag="${esc(target.tag)}" ${d.jobs ? "disabled" : ""}>Update to ${esc(target.label)}</button>` : `<span class="ok">Up to date</span>`}
      <button type="button" class="btn" id="vCheck">Check now</button>
      ${d.jobs ? `<span class="muted">${d.jobs} job(s) running - updating restarts the studio; wait for them.</span>` : `<span class="muted">Updating restarts the studio and this console.</span>`}
    </div>
    <h2>History</h2>
    <div class="box"><table class="grid"><thead><tr><th>When</th><th>Update</th><th>By</th><th>Result</th></tr></thead><tbody>
      ${d.history.map(h => `<tr><td>${esc(day(h.at))}</td><td>${esc(h.title)}</td><td>${esc(h.by)}</td><td class="${h.status === "succeeded" ? "ok" : h.status === "failed" ? "bad" : ""}">${esc(h.status)}</td></tr>`).join("") || `<tr><td colspan="4" class="muted">No updates from the studio yet.</td></tr>`}
    </tbody></table></div>`);
  const save = async (channel, auto) => { await api("PUT", "/version", { channel, auto }); };
  b.querySelectorAll("[data-ch]").forEach(btn => btn.addEventListener("click", () => busy(btn, async () => { await save(btn.dataset.ch, $("vAuto").checked); await PAGES.version(true); })));
  on("vAuto", "change", e => busy(e.target, async () => { await save(set.channel, e.target.checked); say("Saved.", true); }));
  on("vCheck", "click", e => busy(e.target, async () => { await PAGES.version(true); say("Checked.", true); }));
  on("vUpdate", "click", e => busy(e.target, async () => {
    if (!armed(e.target, "Click again: download and restart")) return;
    e.target.textContent = "Downloading…";
    const r = await api("POST", "/version/update", { tag: e.target.dataset.tag });
    say(`Installing ${r.target} - the studio and this console restart. Reload this page in a minute.`, true);
  }));
};

PAGES.debug = async () => {
  const d = await api("GET", "/debug");
  const last = (l, kind) => l ? `${esc(l.title)} · ${esc(l.status)} ${esc(day(l.at))}${l.from_iso ? " · from an ISO: repeat it in the studio" : " · runs as a new job"}` : `no ${kind} build yet`;
  const b = body(`<form class="form wide">
      <span>Debug tools</span><label class="chk"><input type="checkbox" id="dTools" ${d.debug_tools ? "checked" : ""}> On — <span class="mono">debug_tools = true</span> in config.toml, also shown in the studio's Studio settings</label>
      <span>Downloads</span><label class="chk"><input type="checkbox" id="dKeep" ${d.keep_downloads ? "checked" : ""} ${d.debug_tools ? "" : "disabled"}> Keep downloads — every file a Windows media, WinPE or FoD build fetches stays in work/uup-files</label>
      <label for="dLevel">Log level</label><select id="dLevel">${d.levels.map(l => `<option value="${l}" ${l === d.log_level ? "selected" : ""}>${l}${l === d.recommended ? " (recommended)" : ""}</option>`).join("")}</select>
    </form>
    <div class="btns"><button type="button" class="btn pri" id="dSave">Save</button><span class="muted">Turning debug tools on or off restarts the studio.</span></div>
    <h2>Actions</h2>
    <div class="box"><table class="grid" style="min-width:600px"><tbody>
      <tr><td style="width:260px"><button type="button" class="btn dan" id="dClear" style="width:100%" ${d.downloads_bytes ? "" : "disabled"}>Clear downloads · ${gb(d.downloads_bytes)}</button></td><td class="muted">Deletes work/uup-files now. The next build downloads again.</td></tr>
      <tr><td><button type="button" class="btn" data-rebuild="winpe" style="width:100%" ${d.last_winpe && !d.last_winpe.from_iso ? "" : "disabled"}>Rebuild last WinPE</button></td><td class="muted">${last(d.last_winpe, "WinPE")}</td></tr>
      <tr><td><button type="button" class="btn" data-rebuild="media" style="width:100%" ${d.last_media ? "" : "disabled"}>Rebuild last Windows media</button></td><td class="muted">${last(d.last_media, "Windows media")}</td></tr>
    </tbody></table></div>
    <h2>Support bundle</h2>
    <div class="muted">config.toml with the token secret removed · the last 5,000 lines of the studio's and the console's log · job logs of the last 7 days · versions · network · every PVE node's certificate chain</div>
    <div class="btns"><a class="btn" href="/api/debug/bundle" download style="text-decoration:none;display:inline-flex;align-items:center">Download support bundle</a></div>`);
  on("dTools", "change", () => { $("dKeep").disabled = !$("dTools").checked; if (!$("dTools").checked) $("dKeep").checked = false; });
  on("dSave", "click", e => busy(e.target, async () => {
    const r = await api("PUT", "/debug", { debug_tools: $("dTools").checked, keep_downloads: $("dKeep").checked, log_level: $("dLevel").value });
    say(r.restarted ? "Saved - the studio restarts." : "Saved.", true); await PAGES.debug();
  }));
  on("dClear", "click", e => busy(e.target, async () => {
    if (!armed(e.target, "Click again: delete them")) return;
    const r = await api("DELETE", "/debug/downloads"); say(`${gb(r.freed)} cleared.`, true); await PAGES.debug();
  }));
  b.querySelectorAll("[data-rebuild]").forEach(btn => btn.addEventListener("click", () => busy(btn, async () => {
    const r = await api("POST", "/debug/rebuild", { kind: btn.dataset.rebuild });
    say(`Started as job ${r.job} - follow it in the studio's Jobs.`, true);
  })));
};

function stopLog() { clearTimeout(ui.logTimer); ui.logTimer = null; }

PAGES.service = async () => {
  const d = await api("GET", "/service");
  const unit = u => u.active === "unknown" ? `<span class="muted">not known (no systemd here)</span>`
    : `<span class="${u.active === "active" ? "ok" : "bad"}">${esc(u.active)}</span>${u.sub ? ` (${esc(u.sub)})` : ""}${u.since ? ` since ${esc(u.since)}` : ""}${u.pid && u.pid !== "0" ? ` · PID ${esc(u.pid)}` : ""}${u.memory ? ` · ${Math.round(u.memory / 1048576)} MB` : ""}`;
  const b = body(`${kv([["pve-vm-studio", unit(d.studio)], ["Console", unit(d.console)],
      ["Listening", `<span class="mono">${esc(d.listen.studio)} studio${d.listen.http ? ` · ${esc(d.listen.http)} redirect` : ""} · ${esc(d.listen.console)} console</span>`],
      ["Jobs", d.jobs.length ? `${d.jobs.length} running or queued: ${d.jobs.map(j => esc(j.title)).join(", ")}` : "none running"],
      d.disk ? ["Disk", `<span class="mono">${esc(d.disk.path)} · ${gb(d.disk.total - d.disk.free)} of ${gb(d.disk.total)} used</span>`] : null])}
    <div class="btns">
      <button type="button" class="btn dan" id="sRestart">Restart the studio</button>
      ${d.jobs.length ? `<button type="button" class="btn dan" id="sForce">Restart anyway (cuts the jobs off)</button>` : ""}
    </div>
    <h2>Log</h2>
    <div class="btns">
      <select id="lUnit" style="width:auto"><option value="studio">studio</option><option value="console">console</option></select>
      <select id="lLevel" style="width:auto"><option value="warn">warn and up</option><option value="info" selected>info and up</option><option value="">everything</option></select>
      <input id="lGrep" placeholder="Filter" style="width:220px">
      <label class="chk"><input type="checkbox" id="lFollow" checked> Follow</label>
    </div>
    <pre class="pre log" id="log">Loading…</pre>`);
  on("sRestart", "click", e => busy(e.target, async () => {
    if (!armed(e.target)) return;
    await api("POST", "/service/restart", { force: false }); say("Restarting the studio.", true); setTimeout(PAGES.service, 3000);
  }));
  on("sForce", "click", e => busy(e.target, async () => {
    if (!armed(e.target, "Click again: the running jobs fail")) return;
    await api("POST", "/service/restart", { force: true }); say("Restarting the studio - the running jobs were cut off.", true); setTimeout(PAGES.service, 3000);
  }));
  let cursor = "";
  const logEl = $("log");
  const load = async (append) => {
    stopLog();
    if (!$("log")) return;
    const q = new URLSearchParams({ unit: $("lUnit").value, level: $("lLevel").value, grep: $("lGrep").value });
    if (append && cursor) q.set("cursor", cursor);
    try {
      const r = await api("GET", "/service/log?" + q);
      if (r.error) { logEl.textContent = r.error; return; }
      const atEnd = logEl.scrollTop + logEl.clientHeight >= logEl.scrollHeight - 8;
      const text = r.lines.map(colour).join("\n");
      if (append) { if (text) logEl.innerHTML += (logEl.innerHTML ? "\n" : "") + text; } else logEl.innerHTML = text || `<span class="muted">No lines.</span>`;
      cursor = r.cursor || cursor;
      if (atEnd || !append) logEl.scrollTop = logEl.scrollHeight;
    } catch (e) { logEl.textContent = e.message; }
    if ($("lFollow") && $("lFollow").checked) ui.logTimer = setTimeout(() => load(true), 2000);
  };
  ["lUnit", "lLevel"].forEach(id => on(id, "change", () => { cursor = ""; load(false); }));
  let t; on("lGrep", "input", () => { clearTimeout(t); t = setTimeout(() => { cursor = ""; load(false); }, 400); });
  on("lFollow", "change", e => { if (e.target.checked) load(true); else stopLog(); });
  load(false);
  void b;
};

function colour(line) {
  const l = esc(line);
  return l.replace(/\b(ERROR)\b/, `<span class="bad">$1</span>`).replace(/\b(WARN)\b/, `<span class="warn">$1</span>`);
}

// ---- shell ----

function termTheme() {
  return theme() === "light" ? { background: "#1c1f23", foreground: "#d6dadf", cursor: "#d6dadf" } : { background: "#0b0c0e", foreground: "#d6dadf", cursor: "#d6dadf" };
}

function loadScript(src) {
  return new Promise((res, rej) => {
    if (document.querySelector(`script[src="${src}"]`)) return res();
    const s = document.createElement("script"); s.src = src; s.onload = res; s.onerror = () => rej(new Error("could not load " + src)); document.head.appendChild(s);
  });
}
function loadCss(href) {
  if (document.querySelector(`link[href="${href}"]`)) return;
  const l = document.createElement("link"); l.rel = "stylesheet"; l.href = href; document.head.appendChild(l);
}

function closeTerm() {
  if (ui.term) { try { ui.term.ws && ui.term.ws.close(); } catch (e) {} try { ui.term.dispose(); } catch (e) {} ui.term = null; }
  window.removeEventListener("resize", fitTerm);
}
function fitTerm() { if (ui.term && ui.term.fit) { try { ui.term.fit.fit(); } catch (e) {} } }

PAGES.shell = async () => {
  // xterm.js only for this page - the rest of the console loads nothing extra.
  loadCss("vendor/xterm.css");
  await loadScript("vendor/xterm.js");
  await loadScript("vendor/addon-fit.js");
  const b = body(`<div class="btns">
      <span class="mono muted" id="tInfo">root shell in the studio's container</span>
      <span class="mono" id="tState">connecting…</span>
      <span class="muted">Every session is recorded.</span>
      <span style="margin-left:auto;display:flex;gap:8px">
        <button type="button" class="btn sm" id="tCopy">Copy</button>
        <button type="button" class="btn sm" id="tSmaller" aria-label="Smaller text">A−</button>
        <button type="button" class="btn sm" id="tBigger" aria-label="Larger text">A+</button>
        <button type="button" class="btn sm" id="tReconnect">Reconnect</button>
      </span></div>
    <div class="term-wrap" id="term"></div>`);
  void b;
  connectTerm();
  on("tCopy", "click", async () => { if (!ui.term) return; const s = ui.term.getSelection(); try { await navigator.clipboard.writeText(s); say(s ? "Copied." : "Select text in the shell first.", !!s); } catch (e) { say("The browser did not allow copying - use Ctrl+Shift+C.", false); } });
  on("tSmaller", "click", () => { if (ui.term) { ui.term.options.fontSize = Math.max(9, ui.term.options.fontSize - 1); fitTerm(); } });
  on("tBigger", "click", () => { if (ui.term) { ui.term.options.fontSize = Math.min(24, ui.term.options.fontSize + 1); fitTerm(); } });
  on("tReconnect", "click", () => { closeTerm(); connectTerm(); });
};

function connectTerm() {
  const el = $("term");
  if (!el) return;
  el.innerHTML = "";
  const term = new window.Terminal({ fontFamily: 'ui-monospace, Consolas, "DejaVu Sans Mono", monospace', fontSize: 13, cursorBlink: true, scrollback: 5000, theme: termTheme() });
  const fit = new window.FitAddon.FitAddon();
  term.loadAddon(fit);
  term.open(el);
  term.fit = fit;
  ui.term = term;
  fitTerm();
  const proto = location.protocol === "https:" ? "wss:" : "ws:";
  const ws = new WebSocket(`${proto}//${location.host}/api/shell?cols=${term.cols}&rows=${term.rows}`);
  ws.binaryType = "arraybuffer";
  term.ws = ws;
  const state = (t, cls) => { const s = $("tState"); if (s) { s.textContent = t; s.className = "mono " + (cls || ""); } };
  const started = Date.now();
  let tick;
  ws.onopen = () => {
    state("● connected", "ok");
    tick = setInterval(() => { if (ws.readyState === 1) state(`● connected ${Math.floor((Date.now() - started) / 60000)} min`, "ok"); }, 30000);
    term.focus();
  };
  ws.onmessage = ev => term.write(typeof ev.data === "string" ? ev.data : new Uint8Array(ev.data));
  ws.onclose = () => { clearInterval(tick); state("○ disconnected", "bad"); };
  term.onData(d => { if (ws.readyState === 1) ws.send("i" + d); });
  term.onResize(({ cols, rows }) => { if (ws.readyState === 1) ws.send(`r${cols}x${rows}`); });
  window.addEventListener("resize", fitTerm);
}

PAGES.password = async () => {
  const d = await api("GET", "/password");
  const b = body(`<div class="muted">User <span class="mono" style="color:var(--fg)">${esc(d.user)}</span>${d.set_at ? ` · set ${esc(day(d.set_at))}${d.set_by ? " by " + esc(d.set_by) : ""}` : ""}</div>
    <form class="form" id="pwForm">
      <label for="pCur">Current password</label><input id="pCur" type="password" autocomplete="current-password">
      <label for="pNew">New password</label><input id="pNew" type="password" autocomplete="new-password">
      <label for="pRep">Repeat</label><input id="pRep" type="password" autocomplete="new-password">
    </form>
    <div class="btns"><button type="button" class="btn pri" id="pSave">Change password</button><button type="button" class="btn" id="pGen">Generate 32 characters</button></div>
    <div class="mono" id="pShown" hidden></div>
    <div class="muted">At least ${d.min} characters. Changing it signs out every other console session.</div>
    <h2>Sign-ins</h2>
    <div class="box"><table class="grid"><thead><tr><th>When</th><th>From</th><th>Result</th></tr></thead><tbody>
      ${d.signins.map(s => `<tr><td>${esc(day(s.at))}</td><td class="mono">${esc(s.from)}</td><td class="${s.ok ? "ok" : "bad"}">${esc(s.what)}</td></tr>`).join("") || `<tr><td colspan="3" class="muted">None yet.</td></tr>`}
    </tbody></table></div>
    <div class="muted">5 wrong passwords lock the console for 5 minutes. Lost it: <span class="mono" style="color:var(--fg)">pct exec &lt;ct&gt; -- pve-vm-studio console-password --reset</span> on the node. The console is switched off in the studio's Studio settings.</div>`);
  void b;
  on("pGen", "click", () => {
    const A = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
    let pw = "";
    while (pw.length < 32) { const r = crypto.getRandomValues(new Uint8Array(64)); for (const x of r) if (x < 256 - 256 % A.length && pw.length < 32) pw += A[x % A.length]; }
    const shown = pw.match(/.{1,4}/g).join("-");
    $("pNew").value = $("pRep").value = shown;
    $("pShown").hidden = false; $("pShown").innerHTML = `New password: <b>${esc(shown)}</b> - write it down before you save.`;
  });
  on("pSave", "click", e => busy(e.target, async () => {
    if ($("pNew").value !== $("pRep").value) throw new Error("the two new passwords differ");
    await api("PUT", "/password", { current: $("pCur").value, new: $("pNew").value });
    ["pCur", "pNew", "pRep"].forEach(id => $(id).value = ""); $("pShown").hidden = true;
    say("Password changed.", true); await PAGES.password();
  }));
};

boot();
