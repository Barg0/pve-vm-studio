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
    mail::{self, Fact, Report, Section, Tone, fact, mono},
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

fn host_name() -> String {
    std::fs::read_to_string("/etc/hostname").map(|s| s.trim().to_owned()).unwrap_or_default()
}

/// Sends the mail for `key` when that event is on and mail is set up. Never fails its
/// caller: a mail that does not go out is logged and shown on the dashboard.
pub async fn send(app: &AppState, key: &str, mut r: Report) {
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
    let mut st: MailStatus = settings::load(&app.db, "mail_status").await.unwrap_or_default();
    match mail::send(&app.db, key, &m, &r, &url, &host_name()).await {
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
    mail::send(&app.db, "test", m, &r, &url, &host_name()).await
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
        f.push(fact("Took", d));
    }
    f
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
        "bake" => {
            let gold = params["gold"].as_str().unwrap_or_default();
            let g = crate::golds::get(&app.db, gold).await.ok().flatten();
            let mut r = Report::new(
                format!("{}: {}", if ok { "Gold baked" } else { "Bake failed" }, row.title),
                "os-window",
                if ok { "Gold baked" } else { "Bake failed" },
                if ok { "DONE" } else { "FAILED" },
                if ok { Tone::Success } else { Tone::Danger },
            );
            r.subtitle = row.title.clone();
            r.facts = job_facts(&row);
            if let Some(g) = g {
                r.facts.push(mono("Gold", g.id.clone()));
                r.facts.push(fact("Image", g.image_id.clone()));
                if !g.node.is_empty() {
                    r.facts.push(fact("Node", g.node.clone()));
                }
            }
            r.error = row.error.clone();
            r.link = Some("#/golds".into());
            send(&app, if ok { "bake_done" } else { "bake_failed" }, r).await;
        }
        "deploy" => {
            let vm = params["vm"].as_str().unwrap_or_default();
            let v = crate::vms::get(&app.db, vm).await.ok().flatten();
            let name = v.as_ref().map(|v| v.name.clone()).or_else(|| params["name"].as_str().map(str::to_owned)).unwrap_or_default();
            let mut r = Report::new(
                format!("{}: {name}", if ok { "VM provisioned" } else { "Deploy failed" }),
                "vm",
                if ok { format!("{name} is ready") } else { format!("{name} was not built") },
                if ok { "PROVISIONED" } else { "FAILED" },
                if ok { Tone::Success } else { Tone::Danger },
            );
            r.subtitle = row.title.clone();
            if let Some(v) = &v {
                r.facts.push(fact("VM", v.name.clone()));
                r.facts.push(mono("Address", v.ip.clone().unwrap_or_default()));
                r.facts.push(fact("Node", v.node.clone()));
                if let Some(id) = v.vmid {
                    r.pills.push(("VMID".into(), id.to_string()));
                }
                r.facts.push(mono("Gold", v.gold_id.clone()));
            }
            r.facts.extend(job_facts(&row));
            r.error = row.error.clone();
            r.link = Some("#/vms".into());
            send(&app, if ok { "vm_provisioned" } else { "deploy_failed" }, r).await;
        }
        "media" if ok => {
            // The ISO this job made: the newest record of its build and language.
            let isos: Vec<crate::media::MediaIso> = settings::load(&app.db, "media_isos").await.unwrap_or_default();
            let (build, lang) = (params["build"].as_str().unwrap_or_default(), params["lang"].as_str().unwrap_or_default());
            let iso = isos.iter().filter(|i| i.build == build && i.lang.eq_ignore_ascii_case(lang)).max_by(|a, b| a.built.cmp(&b.built));
            let mut r = Report::new(format!("Windows media built: {}", row.title), "iso-media", "New Windows ISO", "BUILT", Tone::Success);
            r.subtitle = row.title.clone();
            if let Some(i) = iso {
                r.facts.push(mono("ISO", i.volid.clone()));
                r.facts.push(mono("Build", i.build.clone()));
                r.facts.push(fact("Editions", i.editions.join(", ")));
                r.facts.push(fact("Size", format!("{:.2} GB", i.size as f64 / 1e9)));
                if !i.updates.is_empty() {
                    r.facts.push(fact("Updates", i.updates.join(", ")));
                }
                if !i.sha256.is_empty() {
                    r.facts.push(mono("SHA-256", i.sha256.clone()));
                }
            }
            r.facts.extend(job_facts(&row));
            r.notice = Some((Tone::Accent, "Bake a gold from it under Golds, or let the golds that keep current pick it up.".into()));
            r.link = Some("#/winmedia".into());
            send(&app, "media_built", r).await;
        }
        "winpe" if ok => {
            let pe: crate::winpe::WinPe = settings::load(&app.db, "winpe").await.unwrap_or_default();
            let mut r = Report::new("WinPE built", "iso-media", "WinPE built", "BUILT", Tone::Success);
            r.subtitle = row.title.clone();
            r.facts = vec![mono("ISO", pe.volid.clone()), mono("Build", pe.build.clone()), fact("Node", pe.node.clone())];
            r.facts.extend(job_facts(&row));
            r.link = Some("#/media".into());
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
            if !volid.is_empty() {
                r.facts.push(mono("ISO", volid));
            }
            r.facts.extend(job_facts(&row));
            r.link = Some("#/media".into());
            send(&app, "fod_built", r).await;
        }
        "virtio" if ok => {
            let release = params["release"].as_str().unwrap_or_default().to_owned();
            let mut r = Report::new(format!("virtio-win {release} downloaded"), "integration", format!("virtio-win {release} is in PVE"), "DOWNLOADED", Tone::Success);
            r.subtitle = row.title.clone();
            r.facts = vec![fact("Release", release), fact("Channel", params["virtio"].as_str().unwrap_or_default().to_owned())];
            r.facts.extend(job_facts(&row));
            r.notice = Some((Tone::Accent, "New Windows golds and WinPE take it; golds baked before keep the release they were baked with.".into()));
            r.link = Some("#/media".into());
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
            r.facts = job_facts(&row);
            r.error = row.error.clone();
            r.link = Some("#/media".into());
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
            r.facts = vec![fact("Names", info.names.join(", ")), fact("Issuer", info.issuer), fact("Valid until", info.not_after)];
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
            r.facts = vec![fact("Node", n.clone())];
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
                    r.facts = vec![fact("Storage", name.clone()), fact("Used", gb(used)), fact("Free", gb(max - used)), fact("Size", gb(max))];
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
        r.facts = vec![fact("Names", info.names.join(", ")), fact("Valid until", info.not_after.clone()), fact("Days left", info.days_left.to_string())];
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
                    let release = crate::uup::release_kind(p, b.created);
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
    Section { title: title.into(), icon, facts }
}
