//! virtio-win: the Windows drivers and guest agent every Windows gold is baked with.
//! Which release is used is a setting ("stable", "latest", or a pinned version); the ISO
//! is fetched by PVE itself (download-url) into an ISO storage, named by its version, so
//! several releases can sit side by side and a gold records the one it was baked with.

use anyhow::{anyhow, bail, Result};
use serde::{Deserialize, Serialize};

use crate::{
    form,
    jobs::JobLog,
    pve::{enc, Pve},
};

const BASE: &str = "https://fedorapeople.org/groups/virt/virtio-win/direct-downloads";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct WindowsSettings {
    /// "stable", "latest", or a release such as "0.1.302-1".
    pub virtio: String,
    /// Where the virtio ISO (and later the Windows ISOs) go; empty = the bake ISO storage.
    pub iso_storage: String,
    /// The UUP product WinPE is built from: "ws-insider" (Windows Server vNext) or "ws2025".
    pub winpe_from: String,
}

impl Default for WindowsSettings {
    fn default() -> Self {
        Self { virtio: "stable".into(), iso_storage: String::new(), winpe_from: "ws-insider".into() }
    }
}

/// Every release in the archive, newest first.
pub async fn releases(web: &reqwest::Client) -> Result<Vec<String>> {
    let index = web.get(format!("{BASE}/archive-virtio/")).send().await?.error_for_status()?.text().await?;
    let mut out: Vec<String> = Vec::new();
    for part in index.split("virtio-win-").skip(1) {
        let v: String = part.chars().take_while(|c| c.is_ascii_digit() || *c == '.' || *c == '-').collect();
        let v = v.trim_end_matches(['-', '.']).to_owned();
        if v.starts_with("0.1.") && v.contains('-') && !out.contains(&v) {
            out.push(v);
        }
    }
    out.sort_by_key(|v| std::cmp::Reverse(version_key(v)));
    Ok(out)
}

/// What the settings page shows about upstream - the release list and where "stable" and
/// "latest" point - fetched together and kept for an hour: three round trips to
/// fedorapeople on every page view made General Settings take over a second.
#[derive(Clone, Default)]
pub struct Upstream {
    pub releases: Vec<String>,
    pub stable: Option<String>,
    pub latest: Option<String>,
}

pub async fn upstream(web: &reqwest::Client) -> Upstream {
    static CACHE: tokio::sync::Mutex<Option<(std::time::Instant, Upstream)>> = tokio::sync::Mutex::const_new(None);
    let mut c = CACHE.lock().await;
    if let Some((at, u)) = c.as_ref() {
        if at.elapsed() < std::time::Duration::from_secs(3600) && !u.releases.is_empty() {
            return u.clone();
        }
    }
    let (releases, stable, latest) = tokio::join!(releases(web), resolve("stable"), resolve("latest"));
    let u = Upstream { releases: releases.unwrap_or_default(), stable: stable.ok(), latest: latest.ok() };
    *c = Some((std::time::Instant::now(), u.clone()));
    u
}

fn version_key(v: &str) -> Vec<u32> {
    v.split(['.', '-']).filter_map(|p| p.parse().ok()).collect()
}

/// Releases Proxmox lists as broken for Windows guests (pve.proxmox.com/wiki/Windows_VirtIO_Drivers):
/// 0.1.215-0.1.262, and 0.1.285 (read errors on vioscsi/viostor under heavy IO on Server
/// 2025). None is baked into a gold - a driver problem in a gold is in every VM cloned from it.
pub fn known_bad(release: &str) -> Option<&'static str> {
    let n: Option<u32> = release.strip_prefix("0.1.").and_then(|r| r.split('-').next()).and_then(|r| r.parse().ok());
    match n {
        Some(215..=262) => Some("Proxmox lists 0.1.215 to 0.1.262 as broken for Windows guests"),
        Some(285) => Some("Proxmox lists 0.1.285 as broken: storage read errors under heavy IO on Windows Server 2025"),
        _ => None,
    }
}

/// "stable" and "latest" are redirects to a release; this follows them. A release Proxmox
/// lists as broken is refused, the channels' too.
pub async fn resolve(wanted: &str) -> Result<String> {
    let r = resolve_any(wanted).await?;
    if let Some(why) = known_bad(&r) {
        bail!("virtio-win {r}{} - {why}; pin another release under Media", if r == wanted { String::new() } else { format!(" (what '{wanted}' points at)") });
    }
    Ok(r)
}

async fn resolve_any(wanted: &str) -> Result<String> {
    if wanted != "stable" && wanted != "latest" {
        if !wanted.starts_with("0.1.") {
            bail!("'{wanted}' is not a virtio-win release");
        }
        return Ok(wanted.to_owned());
    }
    let url = format!("{BASE}/{wanted}-virtio/virtio-win.iso");
    let no_redirect = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).build()?;
    let resp = no_redirect.head(&url).send().await?;
    let loc = resp
        .headers()
        .get(reqwest::header::LOCATION)
        .and_then(|l| l.to_str().ok())
        .ok_or_else(|| anyhow!("{url} did not point at a release"))?;
    loc.split("virtio-win-")
        .nth(1)
        .and_then(|s| s.split('/').next())
        .map(str::to_owned)
        .ok_or_else(|| anyhow!("cannot read the release from {loc}"))
}

pub fn iso_name(release: &str) -> String {
    format!("virtio-win-{release}.iso")
}

/// Makes sure the release's ISO is in the storage; returns its volid.
pub async fn fetch(pve: &Pve, log: &JobLog, node: &str, storage: &str, release: &str) -> Result<String> {
    let name = iso_name(release);
    let volid = format!("{storage}:iso/{name}");
    if pve.storage_content(node, storage, "iso").await?.iter().any(|v| v.volid == volid) {
        log.ok(format!("{name} is in {storage} already")).await;
        return Ok(volid);
    }
    let url = format!("{BASE}/archive-virtio/virtio-win-{release}/virtio-win.iso");
    log.get(format!("PVE downloads {url}")).await;
    log.warn("The virtio-win project publishes no checksum for the ISO itself - PVE checks the TLS connection only").await;
    let upid: String = pve
        .post(
            &format!("/nodes/{}/storage/{}/download-url", enc(node), enc(storage)),
            form![("content", "iso"), ("filename", &name), ("url", &url)],
        )
        .await?;
    let label = format!("Downloading {name}");
    log.progress(&label, Some(0.0), "");
    let r = pve
        .wait_task(&upid, |l| {
            let words: Vec<&str> = l.split_whitespace().collect();
            if let Some(i) = words.iter().position(|w| w.ends_with('%') && w.trim_end_matches('%').parse::<f64>().is_ok()) {
                let pct = words[i].trim_end_matches('%').parse::<f64>().unwrap_or(0.0);
                log.progress(&label, Some(pct), words[i + 1..].join(" ").replace('=', " in "));
            }
        })
        .await;
    log.progress_done();
    r?;
    log.ok(format!("{name} in {storage}")).await;
    Ok(volid)
}
