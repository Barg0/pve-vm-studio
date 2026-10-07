//! Notifications: which events send a mail, and the mails themselves.
//!
//! The rule for the defaults: mail what happens while nobody is watching - the automatic
//! work - and every failure. A manual job someone watched in the browser needs no mail.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{
    AppState,
    jobs::JobRow,
    mail::{self, Fact, Report, Row, Section, Step, StepState, Tone, button, fact, mono, tile},
    settings,
};

/// (key, group, label, on by default)
pub static EVENTS: &[(&str, &str, &str, bool)] = &[
    ("update_found", "Windows updates", "New build found", true),
    ("update_done", "Windows updates", "Update done", true),
    ("update_failed", "Windows updates", "Update failed", true),
    ("update_stopped", "Windows updates", "Base build changed", true),
    ("bake_failed", "Golds", "Bake failed", true),
    ("bake_done", "Golds", "Bake done", false),
    ("vm_provisioned", "VMs", "VM provisioned", true),
    ("deploy_failed", "VMs", "Deploy failed", true),
    ("media_built", "Media", "Windows media ISO built", true),
    ("winpe_built", "Media", "WinPE built", true),
    ("virtio_updated", "Media", "virtio-win downloaded", true),
    ("fod_built", "Media", "Features on Demand ISO built", true),
    ("iso_newer", "Media", "Newer build for a built ISO", true),
    ("media_failed", "Media", "Media, WinPE, FoD or virtio-win failed", true),
    ("virtio_newer", "Media", "Newer virtio-win", false),
    ("cert_renewed", "Certificate", "Renewed", true),
    ("cert_failed", "Certificate", "Renewal failed", true),
    ("cert_expiring", "Certificate", "Expires in under 14 days", true),
    ("studio_updated", "Studio", "Studio update installed or failed", true),
    ("jobs_interrupted", "Studio", "Restart interrupted jobs", true),
    ("node_offline", "Cluster", "Node offline", true),
    ("storage_high", "Cluster", "Gold or ISO storage over 85 %", true),
];

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct NotifySettings {
    /// Only what differs from the defaults is stored, so a new event gets its default.
    pub events: BTreeMap<String, bool>,
}

impl NotifySettings {
    pub fn on(&self, key: &str) -> bool {
        self.events.get(key).copied().unwrap_or_else(|| EVENTS.iter().find(|e| e.0 == key).is_some_and(|e| e.3))
    }

    /// Every event with its state, for the page.
    pub fn all(&self) -> Vec<serde_json::Value> {
        EVENTS.iter().map(|(k, g, l, d)| json!({ "key": k, "group": g, "label": l, "default": d, "on": self.on(k) })).collect()
    }
}

/// What a watch loop already told, so a node that stays offline mails once, not every round.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
struct Told {
    nodes_offline: Vec<String>,
    storage_high: Vec<String>,
    cert_expiring: String,
    virtio_newer: String,
    /// A built ISO's volid -> the newer build already mailed for it.
    iso_newer: BTreeMap<String, String>,
    /// When UUP dump was last asked about the built ISOs (every 6 hours, not every round).
    iso_checked: String,
}

/// The last send that failed, for the dashboard.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct MailStatus {
    pub last_ok: Option<String>,
    pub last_error: Option<String>,
    pub last_error_at: Option<String>,
}

/// The studio's address as people reach it: https://<fqdn>[:port].
pub async fn studio_url(app: &AppState) -> String {
    let server: crate::tls::ServerSettings = settings::load(&app.db, "server").await.unwrap_or_default();
    let host = if server.fqdn.is_empty() { app.config.fqdn.clone().unwrap_or_default() } else { server.fqdn };
    if host.is_empty() {
        return String::new();
    }
    let port = app.config.listen.port();
    let scheme = if app.config.plain_http { "http" } else { "https" };
    let default = if app.config.plain_http { 80 } else { 443 };
    if port == default { format!("{scheme}://{host}") } else { format!("{scheme}://{host}:{port}") }
}

/// The name in the mail's top right corner: the studio's DNS name, else the host's name.
async fn host_name(app: &AppState) -> String {
    let server: crate::tls::ServerSettings = settings::load(&app.db, "server").await.unwrap_or_default();
    let fqdn = if server.fqdn.is_empty() { app.config.fqdn.clone().unwrap_or_default() } else { server.fqdn };
    if !fqdn.is_empty() {
        return fqdn;
    }
    std::fs::read_to_string("/etc/hostname").map(|s| s.trim().to_owned()).unwrap_or_default()
}

/// Sends the mail for `key` when that event is on and mail is set up. Never fails its
/// caller: a mail that does not go out is logged and shown on the dashboard.
pub async fn send(app: &AppState, key: &str, mut r: Report) {
    if let Err(e) = record(app, key, &r).await {
        tracing::warn!("notification '{}' not recorded: {e:#}", r.subject);
    }
    let n: NotifySettings = settings::load(&app.db, "notify").await.unwrap_or_default();
    if !n.on(key) {
        return;
    }
    let m: mail::MailSettings = settings::load(&app.db, "mail").await.unwrap_or_default();
    if !m.ready() {
        return;
    }
    let url = studio_url(app).await;
    if let Some(l) = r.link.as_mut()
        && l.starts_with('#')
    {
        *l = if url.is_empty() { String::new() } else { format!("{url}/{l}") };
    }
    r.link = r.link.filter(|l| !l.is_empty());
    // Buttons point into the studio the same way; without its address they cannot.
    for b in r.buttons.iter_mut() {
        if b.link.starts_with('#') {
            b.link = if url.is_empty() { String::new() } else { format!("{url}/{}", b.link) };
        }
    }
    let mut st: MailStatus = settings::load(&app.db, "mail_status").await.unwrap_or_default();
    match mail::send(&app.db, key, &m, &r, &url, &host_name(app).await).await {
        Ok(_) => {
            tracing::info!("mail sent: {}", r.subject);
            st.last_ok = Some(chrono::Utc::now().to_rfc3339());
        }
        Err(e) => {
            tracing::warn!("mail '{}' not sent: {e:#}", r.subject);
            st.last_error = Some(format!("{e:#}"));
            st.last_error_at = Some(chrono::Utc::now().to_rfc3339());
        }
    }
    let _ = settings::save(&app.db, "mail_status", &st).await;
}

/// The bell keeps this many.
const KEEP: i64 = 200;

/// Every event goes into the bell's list - mail or not, switched on or not.
async fn record(app: &AppState, key: &str, r: &Report) -> anyhow::Result<()> {
    sqlx::query("INSERT INTO notifications (at, event, icon, title, subtitle, status, tone, link, job) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)")
        .bind(chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
        .bind(key)
        .bind(r.icon)
        .bind(&r.title)
        .bind(&r.subtitle)
        .bind(&r.status)
        .bind(r.tone.key())
        .bind(r.link.as_deref().unwrap_or(""))
        .bind(r.job.as_deref().unwrap_or(""))
        .execute(&app.db)
        .await?;
    sqlx::query("DELETE FROM notifications WHERE id NOT IN (SELECT id FROM notifications ORDER BY id DESC LIMIT ?)").bind(KEEP).execute(&app.db).await?;
    Ok(())
}

#[derive(Debug, serde::Serialize, sqlx::FromRow)]
pub struct Notification {
    pub id: i64,
    pub at: String,
    pub event: String,
    pub icon: String,
    pub title: String,
    pub subtitle: String,
    pub status: String,
    pub tone: String,
    pub link: String,
    pub job: String,
}

/// The newest first.
pub async fn list(app: &AppState, limit: i64) -> anyhow::Result<Vec<Notification>> {
    Ok(sqlx::query_as("SELECT id, at, event, icon, title, subtitle, status, tone, link, job FROM notifications ORDER BY id DESC LIMIT ?")
        .bind(limit.clamp(1, KEEP))
        .fetch_all(&app.db)
        .await?)
}

/// A test mail through the saved settings, with the SMTP answer.
pub async fn test(app: &AppState, m: &mail::MailSettings, by: &str) -> anyhow::Result<String> {
    // A test is asked for: the toggle does not stand in its way, the fields do.
    let m = &mail::MailSettings { enabled: true, ..m.clone() };
    m.check()?;
    let url = studio_url(app).await;
    let mut r = Report::new("PVE VM Studio: test mail", "mark-accent", "Test mail", "OK", Tone::Success);
    r.subtitle = format!("Sent from Studio settings by {by}");
    r.facts = vec![mono("Smart host", format!("{}:{}", m.host, m.port)), fact("Security", m.security.clone()), fact("Recipients", m.to.join(", "))];
    r.notice = Some((Tone::Accent, "When this arrives, the studio's notifications reach you the same way.".into()));
    if !url.is_empty() {
        r.link = Some(url.clone());
    }
    mail::send(&app.db, "test", m, &r, &url, &host_name(app).await).await
}

fn duration(row: &JobRow) -> String {
    let p = |s: &str| chrono::DateTime::parse_from_rfc3339(s).ok();
    match (row.started_at.as_deref().and_then(p), row.ended_at.as_deref().and_then(p)) {
        (Some(a), Some(b)) => {
            let s = (b - a).num_seconds().max(0);
            if s >= 3600 { format!("{}h {:02}m", s / 3600, s % 3600 / 60) } else { format!("{}m {:02}s", s / 60, s % 60) }
        }
        _ => String::new(),
    }
}

fn job_facts(row: &JobRow) -> Vec<Fact> {
    let mut f = vec![fact("Job", row.title.clone()), fact("Started by", row.created_by.clone())];
    let d = duration(row);
    if !d.is_empty() {
        f.push(fact("Time", d));
    }
    f
}

/// A job's stages with their times, from <id>.steps: each lasts until the next began, the
/// last until the job ended - and failed, when the job did.
async fn job_steps(app: &AppState, row: &JobRow, ok: bool) -> Vec<Step> {
    let marks = app.jobs.steps(&row.id).await;
    let end = row.ended_at.as_deref().and_then(|e| chrono::DateTime::parse_from_rfc3339(e).ok());
    let mut out = Vec::new();
    for (i, (at, name)) in marks.iter().enumerate() {
        let until = marks.get(i + 1).map(|(t, _)| *t).or(end);
        let secs = until.map(|u| (u - *at).num_seconds().max(0)).unwrap_or(0);
        // A stage entered twice in a row (a retry) is one step.
        if let Some(last) = out.last_mut().filter(|l: &&mut Step| l.name == *name) {
            last.secs += secs;
            continue;
        }
        out.push(Step { name: name.clone(), secs, state: StepState::Done });
    }
    if !ok && let Some(last) = out.last_mut() {
        last.state = StepState::Failed;
    }
    out
}

fn steps_section(steps: Vec<Step>) -> Option<Section> {
    (!steps.is_empty()).then(|| Section { title: "Steps".into(), icon: "clock", steps, ..Default::default() })
}

/// The Time tile: how long, and from when to when (the studio's time zone).
fn took_tile(row: &JobRow) -> mail::Tile {
    let t = |s: Option<&str>| s.and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok()).map(|d| d.with_timezone(&chrono::Local).format("%H:%M").to_string()).unwrap_or_default();
    tile("clock", "Time", duration(row), format!("{} - {}", t(row.started_at.as_deref()), t(row.ended_at.as_deref())), false)
}

/// The designed VMs that build from a gold, with their address and state.
async fn designs_using(app: &AppState, gold: &crate::golds::GoldRow) -> Vec<Row> {
    let golds = crate::golds::list(&app.db).await.unwrap_or_default();
    let built = crate::vms::list(&app.db).await.unwrap_or_default();
    let (_, vm_glyph) = machine_glyphs(&serde_json::from_str(&gold.manifest).unwrap_or_default());
    let mut out = Vec::new();
    for l in crate::labs::list(&app.db).await.unwrap_or_default() {
        let Ok(Some(full)) = crate::labs::get(&app.db, &l.id).await else { continue };
        let state: serde_json::Value = serde_json::from_str(&full.state).unwrap_or_default();
        for s in state["servers"].as_array().into_iter().flatten() {
            let str_of = |k: &str| s[k].as_str().unwrap_or("");
            if crate::golds::resolve(&golds, str_of("imageId"), str_of("goldLanguage"), str_of("goldId")).is_none_or(|g| g.id != gold.id) {
                continue;
            }
            let name = str_of("name").to_lowercase();
            let rec = built.iter().find(|v| v.name == name);
            let state = match rec.map(|v| v.status.as_str()) {
                Some("ready") => (Tone::Success, "Built".to_owned()),
                Some("building") => (Tone::Accent, "Building".to_owned()),
                Some("failed") => (Tone::Danger, "Failed".to_owned()),
                _ => (Tone::Neutral, "Not built".to_owned()),
            };
            let ip = rec.and_then(|v| v.ip.clone()).filter(|i| !i.is_empty()).unwrap_or_else(|| str_of("ipAddress").to_owned());
            out.push(Row { icon: vm_glyph, name, right: ip, state: Some(state), ..Default::default() });
        }
    }
    out
}

/// en-us -> en-US, as the media cards write a language.
fn uup_lang(l: &str) -> String {
    crate::uup::lang_tag(l)
}

/// Bake options as the gold card names them - the chips of a gold's mail.
fn bake_option_label(k: &str) -> &str {
    match k {
        "rdp" => "Remote Desktop",
        "ping" => "Answer ping",
        "suppressServerManagerAtLogon" => "No Server Manager at logon",
        "blockSignInInputMethods" => "Sign-in keyboard (STIG)",
        "suppressWelcomeExperience" => "No welcome experience",
        "suppressFirstSignInAnimation" => "No first sign-in animation",
        "edgeBaseline" => "Edge baseline",
        "preferIPv4" => "Prefer IPv4",
        "preventDeviceEncryption" => "No auto device encryption",
        "vmPowerPlan" => "VM power plan",
        other => other,
    }
}

/// A gold's glyph and a VM's cube in the studio's machine colours (serverGlyphBand): Linux
/// yellow, a Windows client blue, a Windows Server green - from the gold's manifest.
fn machine_glyphs(m: &serde_json::Value) -> (&'static str, &'static str) {
    if m["osFamily"].as_str() == Some("linux") {
        ("gold-image-linux", "vm-linux")
    } else if m["installationType"].as_str().is_some_and(|t| t.starts_with("Server")) || m["imageId"].as_str().is_some_and(|i| i.starts_with("ws")) {
        ("gold-image-work", "vm-work")
    } else {
        ("gold-image-host", "vm-host")
    }
}

/// Called by the job runner when a job ends.
pub async fn job_ended(app: AppState, id: String) {
    let Ok(Some(row)) = app.jobs.get(&id).await else { return };
    let ok = row.status == "succeeded";
    let params: serde_json::Value = serde_json::from_str(&row.params).unwrap_or_default();
    // The auto-update chain's own steps report through the chain, once, as a whole.
    if params["auto_update"].as_str().is_some_and(|s| !s.is_empty()) {
        return;
    }
    match row.kind.as_str() {
        "bake" | "windows-bake" => {
            let gold = params["gold"].as_str().unwrap_or_default();
            let g = crate::golds::get(&app.db, gold).await.ok().flatten();
            let m: serde_json::Value = g.as_ref().map(|g| serde_json::from_str(&g.manifest).unwrap_or_default()).unwrap_or_default();
            let display = m["displayName"].as_str().or_else(|| m["name"].as_str()).unwrap_or(&row.title).to_owned();
            let (gold_glyph, vm_glyph) = machine_glyphs(&m);
            let mut r = Report::new(
                format!("{}: {display}", if ok { "Gold baked" } else { "Bake failed" }),
                gold_glyph,
                if ok { "Gold baked" } else { "Bake failed" },
                if ok { "READY" } else { "FAILED" },
                if ok { Tone::Success } else { Tone::Danger },
            );
            r.subtitle = display;
            r.pills = vec![("Started by".into(), row.created_by.clone())];
            if let Some(g) = &g {
                let opts: serde_json::Value = serde_json::from_str(&g.options).unwrap_or_default();
                if opts["keep_current"].as_bool() == Some(true) {
                    r.pills.push(("Keep current".into(), "on".into()));
                }
                let build = m["build"].as_str().or_else(|| m["distroVersion"].as_str()).unwrap_or("").trim_start_matches("10.0.").to_owned();
                r.tiles = vec![
                    tile(gold_glyph, "Gold", m["id"].as_str().unwrap_or(&g.name), g.vmid.map(|v| format!("template {v}")).unwrap_or_default(), true),
                    tile("update", "Build", build, m["language"].as_str().unwrap_or(""), true),
                    tile("disk", "Disk", m["diskSizeGB"].as_u64().map(|d| format!("{d} GB")).unwrap_or_default(), g.storage.clone(), false),
                    took_tile(&row),
                ];
            }
            r.sections.extend(steps_section(job_steps(&app, &row, ok).await));
            if ok && let Some(g) = &g {
                let mut baked = Section { title: "Baked in".into(), icon: "first-boot", ..Default::default() };
                if g.os == "windows" {
                    let region = [m["locale"].as_str(), m["keyboardLayout"].as_str().map(|k| k.split(' ').next().unwrap_or(k)), m["timeZone"].as_str()].into_iter().flatten().collect::<Vec<_>>().join(" · ");
                    baked.facts.push(fact("Region", region).icon("dns"));
                    let src = m["sourceMedia"].as_str().or_else(|| m["sourceIso"].as_str()).unwrap_or("").rsplit('/').next().unwrap_or("").to_owned();
                    baked.facts.push(mono("Source", format!("{src}{}", m["imageIndex"].as_u64().map(|i| format!(" · image {i}")).unwrap_or_default())).icon("iso-media"));
                    if let Some(v) = m["virtio"].as_str() {
                        baked.facts.push(fact("virtio-win", v).icon("integration"));
                    }
                    if let Some(o) = m["bakeOptions"].as_object() {
                        baked.chips = o.iter().map(|(k, v)| (bake_option_label(k).to_owned(), v.as_bool().unwrap_or(false))).collect();
                    }
                } else if let Some(f) = m["features"].as_array() {
                    baked.chips = f.iter().filter_map(|x| x.as_str()).map(|x| (x.to_owned(), true)).collect();
                }
                r.sections.push(baked);
                let used = designs_using(&app, g).await;
                if !used.is_empty() {
                    r.sections.push(Section { title: "Used by".into(), icon: vm_glyph, rows: used, ..Default::default() });
                }
            }
            if !ok {
                r.error = Some(row.error.clone().unwrap_or_default());
                r.log_tail = app.jobs.log_tail(&row.id, 4).await;
            }
            r.buttons = if ok {
                vec![button("Open the gold", "#/golds", gold_glyph, true), button("Log", "#/jobs", "log", false)]
            } else {
                vec![button("Open the log", "#/jobs", "log", true), button("Golds", "#/golds", "gold-image", false)]
            };
            r.link = Some("#/golds".into());
            r.job = Some(row.id.clone());
            send(&app, if ok { "bake_done" } else { "bake_failed" }, r).await;
        }
        "deploy" => {
            let vm = params["vm"].as_str().unwrap_or_default();
            let v = crate::vms::get(&app.db, vm).await.ok().flatten();
            let name = v.as_ref().map(|v| v.name.clone()).or_else(|| params["name"].as_str().map(str::to_owned)).unwrap_or_default();
            let spec: crate::vms::VmSpec = v.as_ref().and_then(|v| serde_json::from_str(&v.spec).ok()).unwrap_or_default();
            let g = crate::golds::get(&app.db, &spec.gold).await.ok().flatten();
            let gm: serde_json::Value = g.as_ref().map(|g| serde_json::from_str(&g.manifest).unwrap_or_default()).unwrap_or_default();
            let gold_name = gm["id"].as_str().map(str::to_owned).or_else(|| g.as_ref().map(|g| g.name.clone())).unwrap_or_default();
            let (gold_glyph, vm_glyph) = machine_glyphs(&gm);
            let steps = job_steps(&app, &row, ok).await;
            let failed_at = steps.iter().find(|s| s.state == StepState::Failed).map(|s| s.name.clone());
            let mut r = Report::new(
                format!("{}: {name}", if ok { "VM provisioned" } else { "Deploy failed" }),
                vm_glyph,
                if ok { format!("{name} is ready") } else { format!("{name} was not built") },
                &if ok { "PROVISIONED".to_owned() } else { failed_at.map_or("FAILED".to_owned(), |f| format!("Failed at {f}")) },
                if ok { Tone::Success } else { Tone::Danger },
            );
            let image = gm["displayName"].as_str().or_else(|| gm["name"].as_str()).unwrap_or("").to_owned();
            r.subtitle = [image, if gold_name.is_empty() { String::new() } else { format!("from gold {gold_name}") }].into_iter().filter(|s| !s.is_empty()).collect::<Vec<_>>().join(" · ");
            r.pills = vec![("Started by".into(), row.created_by.clone())];
            if let Some(v) = &v {
                let nic = if spec.nic_name.is_empty() { "net0".to_owned() } else { spec.nic_name.clone() };
                let ip = v.ip.clone().filter(|i| !i.is_empty()).unwrap_or_else(|| spec.ip.clone());
                r.tiles = vec![
                    tile("static-ip", "Address", if ip.is_empty() { "DHCP".to_owned() } else { ip }, format!("{}{nic} · {}", if spec.prefix > 0 { format!("/{} · ", spec.prefix) } else { String::new() }, spec.bridge), true),
                    tile("servers", "Node", v.node.clone(), v.vmid.map(|i| format!("VMID {i}")).unwrap_or_default(), true),
                    tile(gold_glyph, "Gold", gold_name.clone(), gm["build"].as_str().unwrap_or("").trim_start_matches("10.0.").to_owned(), true),
                    took_tile(&row),
                ];
            }
            r.sections.extend(steps_section(steps));
            if ok {
                let mut cfg = Section { title: "Configuration".into(), icon: "cpu", ..Default::default() };
                cfg.facts.push(fact("Domain", spec.domain_join.as_ref().map_or("Workgroup".to_owned(), |d| d.domain.clone())).icon("users"));
                let vlan = spec.vlan.map_or("untagged".to_owned(), |v| format!("VLAN {v}"));
                let dns = if spec.dns.is_empty() { String::new() } else { format!(" · DNS {}", spec.dns.join(", ")) };
                cfg.facts.push(
                    fact("Network", format!("{} · {} · {vlan}{}", if spec.nic_name.is_empty() { "net0" } else { &spec.nic_name }, spec.bridge, if spec.extra_nics.is_empty() { String::new() } else { format!(" · +{} adapter(s)", spec.extra_nics.len()) }))
                        .icon("vnet")
                        .why(if spec.gateway.is_empty() { dns.trim_start_matches(" · ").to_owned() } else { format!("gateway {}{dns}", spec.gateway) }),
                );
                let gb = f64::from(spec.memory_mb) / 1024.0;
                cfg.facts.push(fact("Compute", format!("{} vCPU · {} GB{}{}", spec.cores, if gb.fract() == 0.0 { format!("{gb:.0}") } else { format!("{gb:.1}") }, if spec.vtpm { " · vTPM" } else { "" }, if spec.nested { " · nested" } else { "" })).icon("cpu"));
                let storage = if spec.storage.is_empty() { g.as_ref().map(|g| g.storage.clone()).unwrap_or_default() } else { spec.storage.clone() };
                cfg.facts.push(
                    fact("Disks", format!("scsi0 · {} on {storage} · {}{}", gm["diskSizeGB"].as_u64().map(|d| format!("{d} GB")).unwrap_or_default(), if spec.linked { "linked clone" } else { "full copy" }, if spec.data_disks.is_empty() { String::new() } else { format!(" · +{} data disk(s)", spec.data_disks.len()) }))
                        .icon("disk"),
                );
                // Applications from WinGet, as GuestProvision reported them.
                let raw: serde_json::Value = v.as_ref().and_then(|v| serde_json::from_str(&v.spec).ok()).unwrap_or_default();
                if let Some(apps) = raw["winget_result"].as_array().filter(|a| !a.is_empty()) {
                    let ok = apps.iter().filter(|a| a["success"].as_bool() == Some(true)).count();
                    let failed: Vec<&str> = apps.iter().filter(|a| a["success"].as_bool() != Some(true)).filter_map(|a| a["id"].as_str()).collect();
                    cfg.facts.push(
                        fact("Applications", format!("{ok} of {} from WinGet", apps.len()))
                            .icon("log")
                            .why(if failed.is_empty() { String::new() } else { format!("not installed: {}", failed.join(", ")) }),
                    );
                }
                if !spec.pool.is_empty() || !spec.tags.is_empty() {
                    cfg.facts.push(fact("Pool · tags", [spec.pool.clone(), spec.tags.join(", ")].into_iter().filter(|s| !s.is_empty()).collect::<Vec<_>>().join(" · ")).icon("servers"));
                }
                r.sections.push(cfg);
            } else {
                r.error = Some(row.error.clone().unwrap_or_default());
                r.log_tail = app.jobs.log_tail(&row.id, 4).await;
            }
            r.buttons = if ok {
                vec![button("Open the VM", "#/access", vm_glyph, true), button("Log", "#/jobs", "log", false)]
            } else {
                vec![button("Open the log", "#/jobs", "log", true), button("Deploy", "#/deploy", vm_glyph, false)]
            };
            r.link = Some("#/vms".into());
            r.job = Some(row.id.clone());
            send(&app, if ok { "vm_provisioned" } else { "deploy_failed" }, r).await;
        }
        "media" if ok => {
            // The ISO this job made: the newest record of its build and language.
            let isos: Vec<crate::media::MediaIso> = settings::load(&app.db, "media_isos").await.unwrap_or_default();
            let (build, lang) = (params["build"].as_str().unwrap_or_default(), params["lang"].as_str().unwrap_or_default());
            let iso = isos.iter().filter(|i| i.build == build && i.lang.eq_ignore_ascii_case(lang)).max_by(|a, b| a.built.cmp(&b.built));
            let mut r = Report::new(format!("Windows media built: {}", row.title), "iso-media", "New Windows ISO", "BUILT", Tone::Success);
            r.subtitle = row.title.clone();
            r.pills = vec![("Started by".into(), row.created_by.clone())];
            if let Some(i) = iso {
                r.tiles = vec![
                    tile("iso-media", "Size", format!("{:.1} GB", i.size as f64 / 1e9), i.volid.split(':').next().unwrap_or("").to_owned(), false),
                    tile("update", "Build", i.build.clone(), uup_lang(&i.lang), true),
                    tile("first-boot", "Editions", i.editions.len().to_string(), if i.updates.is_empty() { "no update applied".to_owned() } else { format!("{} update(s) in", i.updates.len()) }, false),
                    took_tile(&row),
                ];
                let mut d = Section { title: "Details".into(), icon: "iso-media", ..Default::default() };
                d.facts.push(mono("ISO", i.volid.clone()).icon("iso-media"));
                d.facts.push(fact("Editions", i.editions.join(", ")).icon("first-boot"));
                if !i.updates.is_empty() {
                    d.facts.push(fact("Updates", i.updates.join(", ")).icon("update"));
                }
                if !i.sha256.is_empty() {
                    d.facts.push(mono("SHA-256", i.sha256.clone()).icon("security"));
                }
                r.sections.extend(steps_section(job_steps(&app, &row, true).await));
                r.sections.push(d);
            }
            r.notice = Some((Tone::Accent, "Bake a gold from it under Golds, or let the golds that keep current pick it up.".into()));
            r.buttons = vec![button("Bake a gold", "#/golds", "gold-image", true), button("Windows media", "#/winmedia", "iso-media", false), button("Log", "#/jobs", "log", false)];
            r.link = Some("#/winmedia".into());
            r.job = Some(row.id.clone());
            send(&app, "media_built", r).await;
        }
        "winpe" if ok => {
            let pe: crate::winpe::WinPe = settings::load(&app.db, "winpe").await.unwrap_or_default();
            let mut r = Report::new("WinPE built", "iso-media", "WinPE built", "BUILT", Tone::Success);
            r.subtitle = row.title.clone();
            r.pills = vec![("Started by".into(), row.created_by.clone())];
            r.tiles = vec![
                tile("iso-media", "ISO", pe.volid.rsplit('/').next().unwrap_or("").to_owned(), pe.volid.split(':').next().unwrap_or("").to_owned(), true),
                tile("update", "Build", pe.build.clone(), String::new(), true),
                tile("servers", "Node", pe.node.clone(), String::new(), true),
                took_tile(&row),
            ];
            r.sections.extend(steps_section(job_steps(&app, &row, true).await));
            r.buttons = vec![button("Open Media", "#/media", "iso-media", true), button("Log", "#/jobs", "log", false)];
            r.link = Some("#/media".into());
            r.job = Some(row.id.clone());
            send(&app, "winpe_built", r).await;
        }
        "fod" if ok => {
            let f: crate::fod::FodSettings = settings::load(&app.db, "fod").await.unwrap_or_default();
            let volid = match params["fod"].as_str().unwrap_or_default() {
                "server2022" => f.server2022.clone(),
                "client" => f.client.clone(),
                _ => f.server.clone(),
            };
            let mut r = Report::new(format!("Features on Demand ISO built: {}", row.title), "iso-media", "Features on Demand ISO built", "BUILT", Tone::Success);
            r.subtitle = row.title.clone();
            r.pills = vec![("Started by".into(), row.created_by.clone())];
            r.tiles = vec![tile("iso-media", "ISO", volid.rsplit('/').next().unwrap_or("").to_owned(), volid.split(':').next().unwrap_or("").to_owned(), true), took_tile(&row)];
            r.sections.extend(steps_section(job_steps(&app, &row, true).await));
            r.buttons = vec![button("Open Media", "#/media", "iso-media", true), button("Log", "#/jobs", "log", false)];
            r.link = Some("#/media".into());
            r.job = Some(row.id.clone());
            send(&app, "fod_built", r).await;
        }
        "virtio" if ok => {
            let release = params["release"].as_str().unwrap_or_default().to_owned();
            let mut r = Report::new(format!("virtio-win {release} downloaded"), "integration", format!("virtio-win {release} is in PVE"), "DOWNLOADED", Tone::Success);
            r.subtitle = row.title.clone();
            r.tiles = vec![
                tile("integration", "Release", release, String::new(), true),
                tile("update", "Channel", params["virtio"].as_str().unwrap_or_default().to_owned(), String::new(), false),
                took_tile(&row),
            ];
            r.buttons = vec![button("Open Media", "#/media", "iso-media", true)];
            r.notice = Some((Tone::Accent, "New Windows golds and WinPE take it; golds baked before keep the release they were baked with.".into()));
            r.link = Some("#/media".into());
            r.job = Some(row.id.clone());
            send(&app, "virtio_updated", r).await;
        }
        "media" | "winpe" | "fod" | "virtio" if !ok => {
            let what = match row.kind.as_str() {
                "media" => "Windows media",
                "winpe" => "WinPE",
                "fod" => "Features on Demand",
                _ => "virtio-win",
            };
            let mut r = Report::new(format!("{what} failed: {}", row.title), "iso-media", format!("{what} failed"), "FAILED", Tone::Danger);
            r.subtitle = row.title.clone();
            r.pills = vec![("Started by".into(), row.created_by.clone())];
            r.tiles = vec![took_tile(&row)];
            r.sections.extend(steps_section(job_steps(&app, &row, false).await));
            r.error = Some(row.error.clone().unwrap_or_default());
            r.log_tail = app.jobs.log_tail(&row.id, 4).await;
            r.buttons = vec![button("Open the log", "#/jobs", "log", true), button("Media", "#/media", "iso-media", false)];
            r.link = Some("#/media".into());
            r.job = Some(row.id.clone());
            send(&app, "media_failed", r).await;
        }
        "certificate" => {
            let mut r = Report::new(
                if ok { "Certificate issued".to_owned() } else { "Certificate request failed".to_owned() },
                "certificate",
                if ok { "Certificate issued" } else { "Certificate request failed" },
                if ok { "ISSUED" } else { "FAILED" },
                if ok { Tone::Success } else { Tone::Danger },
            );
            r.subtitle = row.title.clone();
            r.facts = job_facts(&row);
            r.error = row.error.clone();
            r.link = Some("#/studio".into());
            r.job = Some(row.id.clone());
            send(&app, if ok { "cert_renewed" } else { "cert_failed" }, r).await;
        }
        _ => {}
    }
}

/// The automatic certificate renewal's outcome (tls::renew_loop).
pub async fn cert_renewal(app: AppState, result: Result<crate::tls::CertInfo, String>) {
    match result {
        Ok(info) => {
            let mut r = Report::new("Certificate renewed", "certificate", "Certificate renewed", "RENEWED", Tone::Success);
            r.subtitle = "The automatic renewal installed a new certificate".into();
            r.tiles = vec![
                tile("certificate", "Days left", info.days_left.to_string(), format!("until {}", info.not_after), false),
                tile("dns", "Names", info.names.first().cloned().unwrap_or_default(), if info.names.len() > 1 { format!("+{} more", info.names.len() - 1) } else { String::new() }, true),
            ];
            r.facts = vec![fact("Issuer", info.issuer).icon("security")];
            r.link = Some("#/studio".into());
            send(&app, "cert_renewed", r).await;
        }
        Err(e) => {
            let mut r = Report::new("Certificate renewal failed", "certificate", "Certificate renewal failed", "FAILED", Tone::Danger);
            r.subtitle = "The automatic renewal tries again in 12 hours".into();
            r.error = Some(e);
            r.link = Some("#/studio".into());
            send(&app, "cert_failed", r).await;
        }
    }
}

/// After a restart: the self-update's own outcome, and the jobs the restart cut off.
pub async fn after_restart(app: AppState, update: Option<(String, bool, String)>, interrupted: Vec<(String, String)>) {
    if let Some((_, ok, msg)) = update {
        let mut r = Report::new(
            if ok { "Studio updated" } else { "Studio update failed" },
            "update",
            if ok { "Studio updated" } else { "Studio update failed" },
            if ok { "UPDATED" } else { "FAILED" },
            if ok { Tone::Success } else { Tone::Danger },
        );
        r.subtitle = format!("Now running {}", crate::update::current_label());
        if ok {
            r.facts = vec![fact("Result", msg)];
        } else {
            r.error = Some(msg);
        }
        r.link = Some("#/studio".into());
        send(&app, "studio_updated", r).await;
    }
    // A restart for an update ends that job here too; it is not "interrupted".
    let interrupted: Vec<_> = interrupted.into_iter().filter(|(_, t)| !t.starts_with("Update the studio")).collect();
    if !interrupted.is_empty() {
        let mut r = Report::new(
            format!("Restart interrupted {} job(s)", interrupted.len()),
            "security",
            "Jobs interrupted",
            "INTERRUPTED",
            Tone::Warn,
        );
        r.subtitle = "The studio stopped while these ran; they are marked interrupted and can be retried".into();
        r.facts = interrupted.iter().map(|(_, t)| fact("Job", t.clone())).collect();
        r.link = Some("#/jobs".into());
        send(&app, "jobs_interrupted", r).await;
    }
}

/// Every 10 minutes: nodes, storage, an expiring certificate, a newer virtio-win - each
/// mailed when it changes, not every round.
pub async fn watch_loop(app: AppState) {
    tokio::time::sleep(std::time::Duration::from_secs(120)).await;
    loop {
        watch_once(&app).await;
        tokio::time::sleep(std::time::Duration::from_secs(600)).await;
    }
}

async fn watch_once(app: &AppState) {
    let mut told: Told = settings::load(&app.db, "notify_told").await.unwrap_or_default();
    let before = serde_json::to_string(&told).unwrap_or_default();
    if let Ok(res) = app.pve.resources().await {
        // Nodes.
        let offline: Vec<String> = res.iter().filter(|r| r.kind == "node" && r.status.as_deref() != Some("online")).filter_map(|r| r.node.clone()).collect();
        for n in offline.iter().filter(|n| !told.nodes_offline.contains(n)) {
            let mut r = Report::new(format!("Node {n} is offline"), "servers", format!("{n} is offline"), "OFFLINE", Tone::Danger);
            r.subtitle = "The cluster reports this node as not online".into();
            r.tiles = vec![tile("servers", "Node", n.clone(), "not online", true)];
            r.notice = Some((Tone::Warn, "Builds and bakes placed on it wait until it is back; the studio reaches PVE through the other nodes.".into()));
            r.buttons = vec![button("Open the dashboard", "#/dashboard", "servers", true)];
            send(app, "node_offline", r).await;
        }
        told.nodes_offline = offline;

        // The storages golds and ISOs live on.
        let bake: crate::settings::BakeSettings = settings::load(&app.db, "bake").await.unwrap_or_default();
        if let Ok(p) = bake.resolve(&app.pve).await {
            let mut high = Vec::new();
            for name in [p.disk_storage.clone(), p.iso_storage.clone()] {
                let Some(s) = res.iter().find(|r| r.kind == "storage" && r.node.as_deref() == Some(&p.node) && r.storage.as_deref() == Some(&name)) else { continue };
                let (used, max) = (s.disk.unwrap_or(0), s.maxdisk.unwrap_or(0));
                if max == 0 || used * 100 / max < 85 || high.contains(&name) {
                    continue;
                }
                high.push(name.clone());
                if !told.storage_high.contains(&name) {
                    let gb = |b: u64| format!("{:.0} GB", b as f64 / 1e9);
                    let mut r = Report::new(format!("Storage {name} is {}% full", used * 100 / max), "storage", format!("{name} is {}% full", used * 100 / max), "OVER 85 %", Tone::Warn);
                    r.subtitle = format!("On {} - golds, ISOs and the Windows auto-update need room here", p.node);
                    r.meter = Some(mail::Meter { pct: (used * 100 / max) as u32, threshold: 85, left: format!("{} / {}", gb(used), gb(max)), right: "alert at 85 %".into() });
                    r.tiles = vec![
                        tile("storage", "Used", gb(used), name.clone(), false),
                        tile("storage", "Free", gb(max - used), String::new(), false),
                        tile("servers", "Node", p.node.clone(), String::new(), true),
                    ];
                    r.buttons = vec![button("Clean up golds", "#/golds", "gold-image", true), button("Open the dashboard", "#/dashboard", "servers", false)];
                    send(app, "storage_high", r).await;
                }
            }
            told.storage_high = high;
        }
    }

    // An imported or self-made certificate does not renew itself.
    let tls: crate::tls::TlsSettings = settings::load(&app.db, "tls").await.unwrap_or_default();
    let paths = crate::tls::Paths::new(&app.config.data_dir);
    if tls.mode != "acme"
        && let Ok(pem) = tokio::fs::read(&paths.cert).await
        && let Ok(info) = crate::tls::cert_info(&pem)
        && info.days_left < 14
        && told.cert_expiring != info.not_after
    {
        let mut r = Report::new(format!("Certificate expires in {} day(s)", info.days_left), "certificate", "Certificate expires soon", "EXPIRING", Tone::Warn);
        r.subtitle = "It does not renew itself - import a new one, or switch to Let's Encrypt".into();
        r.tiles = vec![
            tile("certificate", "Days left", info.days_left.to_string(), format!("until {}", info.not_after), false),
            tile("dns", "Names", info.names.first().cloned().unwrap_or_default(), if info.names.len() > 1 { format!("+{} more", info.names.len() - 1) } else { String::new() }, true),
        ];
        r.buttons = vec![button("Studio settings", "#/studio", "certificate", true)];
        r.link = Some("#/studio".into());
        send(app, "cert_expiring", r).await;
        told.cert_expiring = info.not_after;
    }

    // A virtio-win newer than the one golds are baked with.
    let win: crate::virtio::WindowsSettings = settings::load(&app.db, "windows").await.unwrap_or_default();
    let up = crate::virtio::upstream(&app.web).await;
    let used = match win.virtio.as_str() {
        "stable" => up.stable.clone(),
        "latest" => up.latest.clone(),
        v => Some(v.to_owned()),
    };
    if let (Some(used), Some(stable)) = (used, up.stable.clone())
        && newer(&stable, &used)
        && told.virtio_newer != stable
    {
        let mut r = Report::new(format!("virtio-win {stable} is out"), "integration", format!("virtio-win {stable} is out"), "NEWER", Tone::Accent);
        r.subtitle = "Windows golds are baked with an older release".into();
        r.facts = vec![fact("In use", used), fact("Stable", stable.clone())];
        r.link = Some("#/media".into());
        send(app, "virtio_newer", r).await;
        told.virtio_newer = stable;
    }

    // A newer Patch Tuesday build for an ISO the studio built and no gold follows - every 6
    // hours, one mail per ISO and build.
    let due = chrono::DateTime::parse_from_rfc3339(&told.iso_checked).map_or(true, |t| chrono::Utc::now().signed_duration_since(t) > chrono::Duration::hours(6));
    if due {
        match crate::autoupdate::newer_for_untracked(app).await {
            Ok(found) => {
                told.iso_checked = chrono::Utc::now().to_rfc3339();
                for (iso, p, b) in found {
                    if told.iso_newer.get(&iso.volid) == Some(&b.build) {
                        continue;
                    }
                    let release = crate::uup::release_kind(p, &b.build, b.created);
                    let mut r = Report::new(format!("{} {} is out", p.name, b.build), "iso-media", format!("{} {} is out", p.name, b.build), "NEWER", Tone::Accent);
                    r.subtitle = format!("Newer than the ISO built from {}", iso.build);
                    r.facts = vec![mono("ISO", iso.volid.clone()), mono("Its build", iso.build.clone()), mono("Newer build", b.build.clone()), fact("Release", release)];
                    r.notice = Some((Tone::Accent, "Build it under Windows media - or switch Keep current on for the golds baked from this ISO.".into()));
                    r.link = Some("#/winmedia".into());
                    send(app, "iso_newer", r).await;
                    told.iso_newer.insert(iso.volid.clone(), b.build.clone());
                }
            }
            Err(e) => tracing::warn!("newer ISO check: {e:#}"),
        }
    }

    if serde_json::to_string(&told).unwrap_or_default() != before {
        let _ = settings::save(&app.db, "notify_told", &told).await;
    }
}

fn newer(a: &str, b: &str) -> bool {
    let n = |s: &str| s.split(['.', '-']).map(|p| p.parse::<u64>().unwrap_or(0)).collect::<Vec<_>>();
    n(a) > n(b)
}

/// The auto-update chain's mails.
pub fn section(title: &str, icon: &'static str, facts: Vec<Fact>) -> Section {
    Section { title: title.into(), icon, facts, ..Default::default() }
}
