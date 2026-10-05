// Records the README's videos: short clips of single studio elements, with a pointer that
// moves like a hand and typing at human speed, as animated WebP in .github/assets/video/.
//
//   tools/demo/run.sh                      (another terminal: mock PVE + the studio)
//   python3 tools/demo/seed.py             (sample data, once)
//   cd tools/demo && npm i && node record.mjs [scene ...]
//
// Each scene: open the studio in Chromium (Proxmox Dark), set the stage, mark the element to
// keep, act. The video is cut to the acting part, cropped to the element and encoded with
// ffmpeg (libwebp_anim) at 860 px wide.
import { chromium } from "playwright";
import { execFileSync } from "node:child_process";
import { mkdirSync, rmSync, readdirSync } from "node:fs";
import { join, resolve } from "node:path";

const BASE = "http://127.0.0.1:8443";
const OUT = resolve(import.meta.dirname, "../../.github/assets/video");
const TMP = "/tmp/pvs-demo-video";
const W = 1440, H = 900;

// ---- the pointer: drawn into the page, it follows the real mouse events ----
const CURSOR = `
(() => {
  const add = () => {
    if (document.getElementById("__cur")) return;
    const c = document.createElement("div");
    c.id = "__cur";
    c.innerHTML = '<svg width="22" height="22" viewBox="0 0 22 22"><path d="M3 2 L3 18 L7.5 13.8 L10.6 20.4 L13.4 19.2 L10.4 12.8 L16.6 12.6 Z" fill="#fff" stroke="#111" stroke-width="1.3" stroke-linejoin="round"/></svg>';
    Object.assign(c.style, { position: "fixed", left: "0", top: "0", zIndex: 2147483647, pointerEvents: "none", transform: "translate(-100px,-100px)", filter: "drop-shadow(0 1px 2px rgba(0,0,0,.45))" });
    const r = document.createElement("div");
    r.id = "__ripple";
    Object.assign(r.style, { position: "fixed", left: "0", top: "0", width: "26px", height: "26px", marginLeft: "-13px", marginTop: "-13px", borderRadius: "50%",
      border: "2px solid rgba(229,112,0,.9)", zIndex: 2147483646, pointerEvents: "none", opacity: "0" });
    document.body.append(r, c);
    document.addEventListener("mousemove", e => { c.style.transform = "translate(" + e.clientX + "px," + e.clientY + "px)"; }, true);
    document.addEventListener("mousedown", e => {
      r.style.transition = "none"; r.style.left = e.clientX + "px"; r.style.top = e.clientY + "px"; r.style.opacity = "1"; r.style.transform = "scale(.4)";
      requestAnimationFrame(() => { r.style.transition = "transform .45s ease-out, opacity .45s ease-out"; r.style.transform = "scale(1.6)"; r.style.opacity = "0"; });
    }, true);
  };
  if (document.body) add(); else document.addEventListener("DOMContentLoaded", add);
})();`;

const sleep = ms => new Promise(r => setTimeout(r, ms));
const ease = t => (t < 0.5 ? 4 * t * t * t : 1 - Math.pow(-2 * t + 2, 3) / 2);

function helpers(page) {
  let pos = { x: W / 2, y: H / 2 };
  const h = {
    // An eased path with a slight curve, ~60 fps, slower over longer distances.
    async move(x, y) {
      const from = { ...pos }, dist = Math.hypot(x - from.x, y - from.y);
      const steps = Math.max(12, Math.min(60, Math.round(dist / 12)));
      const bend = (Math.random() - 0.5) * Math.min(80, dist * 0.18);
      for (let i = 1; i <= steps; i++) {
        const t = ease(i / steps), s = Math.sin(Math.PI * i / steps) * bend;
        const nx = from.x + (x - from.x) * t - (y - from.y) / (dist || 1) * s;
        const ny = from.y + (y - from.y) * t + (x - from.x) / (dist || 1) * s;
        await page.mouse.move(nx, ny);
        await sleep(14);
      }
      pos = { x, y };
    },
    async to(sel, { dx = 0, dy = 0 } = {}) {
      const el = page.locator(sel).first();
      await el.scrollIntoViewIfNeeded();
      const b = await el.boundingBox();
      if (!b) throw new Error(`not on screen: ${sel}`);
      const jx = (Math.random() - 0.5) * Math.min(10, b.width / 4), jy = (Math.random() - 0.5) * Math.min(4, b.height / 4);
      await h.move(b.x + b.width / 2 + jx + dx, b.y + b.height / 2 + jy + dy);
      return b;
    },
    async click(sel, opt = {}) {
      await h.to(sel, opt);
      await sleep(180 + Math.random() * 120);
      await page.mouse.down(); await sleep(70); await page.mouse.up();
      await sleep(350);
    },
    async type(sel, text) {
      await h.click(sel);
      await page.locator(sel).first().fill("");
      for (const ch of text) { await page.keyboard.type(ch); await sleep(55 + Math.random() * 70); }
      await sleep(300);
    },
    async select(sel, value) {
      await h.click(sel);
      await sleep(250);
      await page.locator(sel).first().selectOption(value);
      await page.locator(sel).first().dispatchEvent("change");
      await sleep(500);
    },
    pause: sleep,
    eval: (fn, arg) => page.evaluate(fn, arg),
  };
  return h;
}

async function login(page) {
  const r = await page.request.post(`${BASE}/api/session`, { data: { username: "root@pam", password: "demo" } });
  if (!r.ok()) throw new Error(`sign-in failed: ${r.status()}`);
}

/* What a clip keeps: a selector, several (their union), or { sel, up, down } - the element
   grown by that many pixels above and below (room for a popover). Scrolled into view first,
   unless stay is set (the page stays where the stage left it). */
async function region(page, spec, pad) {
  const o = typeof spec === "string" || Array.isArray(spec) ? { sel: spec } : spec;
  const sels = Array.isArray(o.sel) ? o.sel : [o.sel];
  if (!o.stay) await page.locator(sels[0]).first().scrollIntoViewIfNeeded();
  if (o.scrollBy) await page.mouse.wheel(0, o.scrollBy);
  await sleep(400);
  let x0 = Infinity, y0 = Infinity, x1 = -Infinity, y1 = -Infinity;
  for (const sel of sels) {
    const b = await page.locator(sel).first().boundingBox();
    if (!b) throw new Error(`not on screen: ${sel}`);
    x0 = Math.min(x0, b.x); y0 = Math.min(y0, b.y); x1 = Math.max(x1, b.x + b.width); y1 = Math.max(y1, b.y + b.height);
  }
  y0 -= o.up || 0; y1 += o.down || 0;
  const crop = { x: Math.max(0, Math.floor(x0 - pad)), y: Math.max(0, Math.floor(y0 - pad)) };
  crop.w = Math.min(W - crop.x, Math.ceil(x1 - x0 + 2 * pad)) & ~1;
  crop.h = Math.min(H - crop.y, Math.ceil(y1 - y0 + 2 * pad + Math.min(0, y0 - pad))) & ~1;
  return crop;
}

/* One clip. stage(page, h) sets the scene and returns what to keep (see region); act(page, h)
   is what the video shows. */
async function record(name, { blade, stage, act, pad = 12 }) {
  rmSync(TMP, { recursive: true, force: true });
  mkdirSync(TMP, { recursive: true });
  const browser = await chromium.launch();
  const ctx = await browser.newContext({ viewport: { width: W, height: H }, deviceScaleFactor: 1, colorScheme: "dark",
    recordVideo: { dir: TMP, size: { width: W, height: H } } });
  await ctx.addInitScript(CURSOR);
  const page = await ctx.newPage();
  const t0 = Date.now();
  await login(page);
  await page.goto(`${BASE}/#/${blade}`);
  await page.waitForFunction("typeof session !== \"undefined\" && !!session.user && typeof cluster !== \"undefined\" && !!cluster.inventory", null, { timeout: 20000 });
  await page.evaluate(() => { applyTheme("proxmox_dark"); render(); });
  await sleep(1500);
  const h = helpers(page);
  const spec = await stage(page, h);
  await sleep(600);
  const crop = await region(page, spec, pad);
  await page.mouse.move(crop.x + crop.w * 0.85, crop.y + crop.h * 0.9);
  await sleep(500);
  const start = (Date.now() - t0) / 1000;
  await act(page, h);
  await sleep(900);
  const end = (Date.now() - t0) / 1000;
  await ctx.close();
  await browser.close();
  const webm = join(TMP, readdirSync(TMP).find(f => f.endsWith(".webm")));
  mkdirSync(OUT, { recursive: true });
  const out = join(OUT, `${name}.webp`);
  const scale = crop.w > 860 ? "860:-2" : `${crop.w}:-2`;
  execFileSync("ffmpeg", ["-y", "-loglevel", "error", "-ss", start.toFixed(2), "-to", end.toFixed(2), "-i", webm,
    "-vf", `crop=${crop.w}:${crop.h}:${crop.x}:${crop.y},fps=20,scale=${scale}:flags=lanczos`,
    "-c:v", "libwebp_anim", "-lossless", "0", "-q:v", "78", "-compression_level", "5", "-loop", "0", out]);
  console.log(`${name}: ${(end - start).toFixed(1)} s, ${crop.w}x${crop.h} -> ${out}`);
}

// ---- the stage: the demo design, made once through the studio's own functions ----

async function setup() {
  const browser = await chromium.launch();
  const page = await (await browser.newContext({ viewport: { width: W, height: H } })).newPage();
  await login(page);
  await page.goto(`${BASE}/#/servers`);
  await page.waitForFunction("typeof session !== \"undefined\" && !!session.user && typeof cluster !== \"undefined\" && !!cluster.inventory", null, { timeout: 20000 });
  const n = await page.evaluate(async () => {
    applyTheme("proxmox_dark");
    // A card a scene added (vm-card) does not stay in the design.
    if (state.servers.some(s => s.name === "sql-01")) {
      state.servers = state.servers.filter(s => s.name !== "sql-01");
      render(); await new Promise(r => setTimeout(r, 800)); await flushSave();
    }
    if (state.servers.length) return state.servers.length;
    const vm = (name, imageId, ip, mem, cpu, user) => {
      const s = createServer();
      Object.assign(s, { name, imageId, ipAddress: ip, prefixLength: 24, defaultGateway: "10.10.0.1", dnsServers: ["10.10.0.10", "10.10.0.11"],
        switchName: "vmbr0", memoryGB: mem, cpuCount: cpu, localUserName: user });
      s.localUserPassword = generateLocalPassword(32);
      state.servers.push(s);
    };
    vm("dc-01", "ws2025-datacenter-core", "10.10.0.10", 4, 2, "lab-admin");
    vm("dc-02", "ws2025-datacenter-core", "10.10.0.11", 4, 2, "lab-admin");
    vm("web-01", "ubuntu2604", "10.10.0.20", 4, 2, "ops");
    vm("files-01", "ws2025-datacenter-desktop", "10.10.0.30", 8, 4, "lab-admin");
    vm("app-01", "debian13", "10.10.0.40", 4, 2, "ops");
    render();
    await new Promise(r => setTimeout(r, 1500));
    await flushSave();
    return state.servers.length;
  });
  console.log(`design: ${n} VMs`);
  await browser.close();
}

// ---- the scenes ----

const to = (page, blade) => page.evaluate(b => { state.blade = b; render(); }, blade);
const openCard = (page, key) => page.evaluate(k => {
  const h = document.querySelector(`[data-toggle="${k}"]`);
  if (h && h.closest(".card").classList.contains("collapsed")) h.click();
}, key);
const linuxBake = async (page, h, image) => {
  await h.eval(img => { Object.assign(bakeForm, { image: img, cis: 0, node: "", bridge: "", vlan: null, addresses: "", gateway: "", dns: "", mirror: null });
    goldsUi.placeOpen = false; openBake("linux"); }, image);
  await page.waitForSelector("#bkImage");
};

/* A deploy of app-01 that runs while the clip records: fresh sample data, a mock PVE that
   forgets earlier deploys, then Deploy as the button does it. The mock's first boot takes two
   minutes, so `after` seconds in, the job is where the clip wants it. Returns the job's id. */
async function liveDeploy(page, after) {
  execFileSync("curl", ["-sk", "-X", "POST", "https://127.0.0.1:8006/api2/json/demo/reset"]);
  execFileSync("python3", [resolve(import.meta.dirname, "seed.py")]);
  const id = await page.evaluate(async () => {
    const r = await api("POST", `/labs/${encodeURIComponent(lab.id)}/deploy`, { names: ["app-01"] });
    const j = r.jobs[0];
    return typeof j === "string" ? j : j.id;
  });
  await page.waitForTimeout(after * 1000);
  return id;
}

const SCENES = {
  // Dashboard: a deploy runs, the rest of the cluster around it.
  "dashboard": {
    blade: "dashboard",
    async stage(page) {
      await liveDeploy(page, 30);
      await to(page, "dashboard"); await page.waitForTimeout(2500);
      await page.evaluate(() => window.scrollTo(0, 0));
      return { sel: ".dash-split", up: 92, stay: true };
    },
    async act(page, h) {
      await h.to(".dash-act .dash-act-bar"); await h.pause(2500);
      await h.to(".dash-col:last-child .card"); await h.pause(800);
      for (let i = 0; i < 4; i++) { await page.mouse.wheel(0, 180); await h.pause(700); }
      await h.to(".dash-vm:nth-child(3)"); await h.pause(1200);
      for (let i = 0; i < 4; i++) { await page.mouse.wheel(0, -180); await h.pause(500); }
      await h.to(".dash-act"); await h.pause(1500);
    },
  },
  // Jobs: the same kind of deploy, live, with the guest's own output.
  "job-running": {
    blade: "jobs",
    async stage(page) {
      const id = await liveDeploy(page, 4);
      await page.evaluate(j => openJob(j), id); await page.waitForTimeout(1500);
      return { sel: [".job-rail .job-filters", ".job-head"], down: 540 };
    },
    async act(page, h) {
      await h.pause(1500);
      await h.click("#logViewBtn"); await h.pause(500);
      await h.click("label.toggle:has(#logDebug) .toggle-track"); await h.pause(400);
      await h.click("#logViewBtn");
      await h.to("#jobBar"); await h.pause(9000);
      await h.to("#jobLog"); await h.pause(9000);
    },
  },

  // Golds: the Linux bake form - image, mirror, what goes in.
  "bake-linux": {
    blade: "golds",
    async stage(page, h) { await linuxBake(page, h, "ubuntu2604"); return [".bake-panel .bake-head", ".bake-panel .toggle-grid"]; },
    async act(page, h) {
      await h.select("#bkImage", "debian13");
      await h.select("#bkMirror", "de");
      await h.click("label.toggle:has(#bkF_pskeys)");
      await h.to("#bkDisk"); await h.pause(400);
      await h.type("#bkDisk", "40");
    },
  },
  // Golds: where this one bake runs, without leaving the form.
  "bake-network": {
    blade: "golds",
    async stage(page, h) { await linuxBake(page, h, "ubuntu2604"); return { sel: ".bake-panel .gs-actions", up: 250 }; },
    async act(page, h) {
      await h.click('[data-bake-place="net"]');
      await h.pause(500);
      await h.select("#bpBridge", "vmbr1");
      await h.type("#bpAddr", "10.20.0.60-63/24");
      await h.type("#bpGw", "10.20.0.1");
      await h.type("#bpDns", "10.20.0.1");
      await h.click("#bpDone");
      await h.pause(900);
      await h.to("#bkStart");
    },
  },
  // Golds: CIS Level 2 for a Linux gold.
  "bake-cis": {
    blade: "golds", pad: 8,
    async stage(page, h) { await linuxBake(page, h, "ubuntu2604"); return { sel: ".cis-level-row", up: 40 }; },
    async act(page, h) {
      await h.click('[data-cis="1"]');
      await h.pause(500);
      await h.click('[data-cis="2"]');
      await h.pause(700);
      await h.to("[data-cis-rules]");
      await h.pause(600);
    },
  },
  // Golds: a Windows gold that keeps itself current.
  "keep-current": {
    blade: "golds",
    async stage(page) { await page.evaluate(() => { goldsUi.bake = false; }); await to(page, "golds"); await page.waitForSelector('[data-keep-current="7d2c4b19"]', { state: "attached" });
      return { sel: '.gold-card:has([data-keep-current="7d2c4b19"]) .card-head', down: 100 }; },
    async act(page, h) {
      await h.to('.gold-card:has([data-keep-current="7d2c4b19"]) .gold-keep .tip-info');
      await h.pause(1800);
      await h.click('label.gold-keep:has([data-keep-current="7d2c4b19"]) .toggle-track');
      await h.pause(1200);
      await h.click('label.gold-keep:has([data-keep-current="7d2c4b19"]) .toggle-track');
      await h.pause(800);
    },
  },
  // Golds: the CIS report of a hardened gold.
  "cis-report": {
    blade: "golds",
    async stage(page, h) { await page.evaluate(() => { goldsUi.bake = false; }); await to(page, "golds"); await h.click('[data-cis-report="b6b6510a"]'); await page.waitForTimeout(1200);
      return ".cis-modal"; },
    async act(page, h) {
      await h.to(".cis-list"); await h.pause(400);
      for (let i = 0; i < 3; i++) { await page.mouse.wheel(0, 240); await h.pause(500); }
      await h.type(".cis-search", "sshd");
      await h.pause(1500);
    },
  },
  // Media: Windows updates - what follows what, checked against Microsoft's catalog.
  "windows-updates": {
    blade: "media",
    async stage(page) { await to(page, "media"); await page.waitForTimeout(2500); await openCard(page, "md-au"); await page.waitForTimeout(600);
      return { sel: '.card:has([data-toggle="md-au"])', down: 90 }; },
    async act(page, h) {
      await h.to("#auKeep"); await h.pause(500);
      await h.click("#auCheck");
      await h.pause(5000);
      await h.to('.card:has([data-toggle="md-au"]) table'); await h.pause(1200);
    },
  },
  // Windows media: a patched Windows ISO straight from Microsoft's servers.
  "windows-media": {
    blade: "winmedia",
    async stage(page) { await to(page, "winmedia"); await page.waitForSelector("[data-wm-build]", { timeout: 60000 }); await page.waitForTimeout(1500); return ".wm-layout"; },
    async act(page, h) {
      await h.click("[data-wm-build]:nth-child(1) button, tr[data-wm-build]:nth-of-type(2)");
      await h.pause(2500);
      await h.click("[data-wm-ed]");
      await h.pause(1500);
      await h.to("#wmGo"); await h.pause(800);
    },
  },
  // Virtual machines: a new card.
  "vm-card": {
    blade: "servers",
    async stage(page, h) {
      await page.evaluate(() => { state.servers = state.servers.filter(s => s.name !== "sql-01" && s.name); render(); });
      await to(page, "servers");
      await h.click("#addServer");
      await page.waitForTimeout(800);
      await page.evaluate(() => [...document.querySelectorAll(".card.collapsible")].pop().scrollIntoView({ block: "start" }));
      await page.waitForTimeout(400);
      return { sel: '.card.collapsible:last-of-type .card-head', down: 400 };
    },
    async act(page, h) {
      const id = await page.evaluate(() => state.servers[state.servers.length - 1]._id);
      await h.type(`input[data-s="${id}"][data-k="name"]`, "sql-01");
      await h.click(`[data-image-picker-toggle="${id}"]`);
      await h.pause(700);
      await h.click(`[data-image-pick="${id}"][data-image-id="ws2025-datacenter-core"]`);
      await h.pause(1500);
    },
  },
  // Deploy: preflight, then the plan.
  "deploy": {
    blade: "deploy",
    async stage(page) { await page.evaluate(() => { state.servers = state.servers.filter(s => s.name !== "sql-01"); render(); }); await to(page, "deploy"); await page.waitForTimeout(1200);
      await openCard(page, "dp-plan"); await page.waitForTimeout(500);
      return ['[data-toggle="rev-issues"]', '.card:has([data-toggle="dp-plan"])', "#dpGo"]; },
    async act(page, h) {
      await h.to('[data-toggle="rev-issues"]'); await h.pause(700);
      await h.to('.card:has([data-toggle="dp-plan"]) tr:nth-child(5)'); await h.pause(900);
      await h.to("#dpGo"); await h.pause(1200);
    },
  },
  // Connect: every VM's address, user and password - and the CSV.
  "passwords": {
    blade: "access",
    async stage(page) { await page.evaluate(() => { state.blade = "access"; state.accessTab = "passwords"; render(); }); await page.waitForTimeout(1000);
      return [".blade-toolbar", ".pw-list"]; },
    async act(page, h) {
      await h.click("#pwToggleAll"); await h.pause(1400);
      await h.to(".pw-list .pw-row:nth-child(3) [data-pw-copy]"); await h.pause(700);
      await h.click("#pwExport"); await h.pause(1200);
    },
  },
  // Jobs: a bake's log, step by step.
  "job-log": {
    blade: "jobs",
    async stage(page, h) { await to(page, "jobs"); await page.waitForTimeout(800); await h.click('[data-job="fcc26ac0-f968-4ea0-89d8-d5c56eb30611"]'); await page.waitForTimeout(1500);
      await page.evaluate(() => { document.getElementById("jobLog").scrollTop = 0; });
      return ["#jobTitle", "#jobLog"]; },
    async act(page, h) {
      await h.to("#jobLog"); await h.pause(500);
      for (let i = 0; i < 5; i++) { await page.mouse.wheel(0, 220); await h.pause(600); }
      await h.pause(500);
    },
  },
  // Studio settings: mail - switched on, every field is required.
  "mail": {
    blade: "studio",
    async stage(page) {
      await page.request.put("http://127.0.0.1:8443/api/settings/mail", { data: { enabled: false, host: "", port: 25, security: "none", verify_cert: true, from: "", to: [], timeout_sec: 30 },
        headers: { "x-pvs-csrf": await page.evaluate(() => session.csrf) } });
      await to(page, "studio"); await page.waitForTimeout(1500); await openCard(page, "gs-mail"); await page.waitForTimeout(500);
      return '.card:has([data-toggle="gs-mail"])'; },
    async act(page, h) {
      await h.click("label.toggle:has(#mlEnabled) .toggle-track");
      await h.click("#mlSave"); await h.pause(1200);
      await h.type("#mlHost", "pmg.lab.example");
      await h.type("#mlFrom", "studio@lab.example");
      await h.type("#mlTo", "admins@lab.example");
      await h.to("#mlSave"); await h.pause(1200);
    },
  },
  // Studio settings: maintenance windows.
  "maintenance": {
    blade: "studio",
    async stage(page) { await to(page, "studio"); await page.waitForTimeout(1500); await openCard(page, "gs-maint"); await page.waitForTimeout(500);
      return { sel: '.card:has([data-toggle="gs-maint"])', down: 52 }; },
    async act(page, h) {
      await h.click('[data-mw-day="0"][data-day="sat"]');
      await h.click('[data-mw-day="0"][data-day="sun"]');
      await h.click("#mwAdd"); await h.pause(700);
      await h.click('[data-mw-day="1"][data-day="mon"]');
      await h.click('[data-mw-day="1"][data-day="tue"]');
      await h.click('[data-mw-day="1"][data-day="wed"]');
      await h.click('[data-mw-day="1"][data-day="thu"]');
      await h.click('[data-mw-day="1"][data-day="fri"]');
      await h.click('label.toggle:has([data-mw-patch="1"]) .toggle-track');
      await h.click("#mwSave"); await h.pause(1200);
    },
  },
};

await setup();
const want = process.argv.slice(2);
for (const [name, s] of Object.entries(SCENES)) {
  if (want.length && !want.includes(name)) continue;
  await record(name, s);
}
