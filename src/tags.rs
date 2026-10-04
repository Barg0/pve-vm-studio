//! The PVE tags the studio puts on what it makes, and their colours.
//!
//! A gold carries `gold`, its OS with the build it was baked from (ws2025-datacenter-core-26100.4061,
//! ubuntu-26.04) and its CIS level (cis-l2). A VM carries its OS alone, without a build - it
//! updates, so a build would soon be wrong. Bake VMs carry `bake`, media workers `media-worker`.
//! Nothing else: the studio knows its golds and VMs by record, name and VMID, not by tag.
//!
//! The colours are the studio's (Kaido palette), set through the datacenter's tag-style
//! colour map - the documented PVE mechanism. That map is cluster wide and exact per tag, so
//! the studio adds its own entries and leaves every other one as it is. It needs Sys.Modify
//! on /; without it the tags stay PVE's default colour.

use crate::{catalog, form, pve::Pve};
use serde_json::Value;

pub const GOLD: &str = "gold";
pub const BAKE: &str = "bake";
pub const WORKER: &str = "media-worker";

/// Text on every studio tag: the palette's dark background.
const TEXT: &str = "16171e";

/// A tag in PVE's alphabet: lowercase letters, digits and - _ + . (anything else becomes -).
pub fn clean(t: &str) -> String {
    t.trim().to_lowercase().chars().map(|c| if c.is_ascii_alphanumeric() || "-_+.".contains(c) { c } else { '-' }).collect()
}

/// A Linux image's OS tag: ubuntu-26.04, debian-13, opensuse-16.0, arch.
fn linux_os(image_id: &str) -> String {
    match catalog::linux(image_id) {
        Some(i) if i.version == "rolling" => clean(i.distro),
        Some(i) => clean(&format!("{}-{}", i.distro, i.version)),
        None => clean(image_id),
    }
}

/// A gold's or VM's OS tag. Windows image ids are tags already (ws2025-datacenter-core,
/// w11-enterprise); `build` (10.0.26100.4061 or 26100) adds the build for a gold.
pub fn os(os: &str, image_id: &str, build: Option<&str>) -> String {
    if os != "windows" {
        return linux_os(image_id);
    }
    match build.map(|b| b.trim().trim_start_matches("10.0.")).filter(|b| !b.is_empty()) {
        Some(b) => clean(&format!("{image_id}-{b}")),
        None => clean(image_id),
    }
}

/// A gold's tags, from its record: gold, OS with build, CIS level when it has one.
pub fn gold(os_name: &str, image_id: &str, manifest: &Value) -> Vec<String> {
    let mut t = vec![GOLD.to_owned(), os(os_name, image_id, manifest["build"].as_str())];
    if let Some(l) = manifest["cis"]["level"].as_u64().filter(|l| *l > 0) {
        t.push(format!("cis-l{l}"));
    }
    t
}

/// The studio colour of one of its tags (background, text), hex without #.
fn colour(tag: &str) -> &'static str {
    let server = tag.strip_prefix("ws").is_some_and(|r| r.starts_with(|c: char| c.is_ascii_digit()));
    let client = tag.starts_with("w1") && tag[2..].starts_with(|c: char| c.is_ascii_digit());
    match tag {
        GOLD => "e0af68",
        BAKE => "7aa2f7",
        WORKER => "8b93ad",
        t if t.starts_with("cis-") => "bb9af7",
        _ if server => "9ece6a",
        _ if client => "7dcfff",
        _ => "e6de78",
    }
}

static PAINT: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Gives the studio's tags their colours in the datacenter's tag-style map, keeping every
/// other entry and setting. Best effort: a missing Sys.Modify only leaves the default colour.
pub async fn paint(pve: &Pve, tags: &[String]) {
    let _one = PAINT.lock().await;
    if let Err(e) = paint_now(pve, tags).await {
        tracing::debug!("tag colours not set: {e:#}");
    }
}

async fn paint_now(pve: &Pve, tags: &[String]) -> anyhow::Result<()> {
    let opts: Value = pve.get("/cluster/options").await?;
    // PVE answers the tag-style property parsed (an object) or as its string.
    let mut parts: Vec<(String, String)> = match &opts["tag-style"] {
        Value::Object(m) => m.iter().map(|(k, v)| (k.clone(), v.as_str().map(str::to_owned).unwrap_or_else(|| v.to_string()))).collect(),
        Value::String(s) => s.split(',').filter_map(|p| p.split_once('=')).map(|(k, v)| (k.to_owned(), v.to_owned())).collect(),
        _ => vec![],
    };
    let map = parts.iter().find(|(k, _)| k == "color-map").map(|(_, v)| v.clone()).unwrap_or_default();
    let mut entries: Vec<(String, String)> = map
        .split(';')
        .filter_map(|e| e.split_once(':'))
        .map(|(t, c)| (t.to_owned(), c.to_owned()))
        .collect();
    let mut changed = false;
    for t in tags {
        let want = format!("{}:{TEXT}", colour(t));
        match entries.iter_mut().find(|(k, _)| k == t) {
            Some((_, c)) if *c == want => {}
            Some((_, c)) => {
                *c = want;
                changed = true;
            }
            None => {
                entries.push((t.clone(), want));
                changed = true;
            }
        }
    }
    if !changed {
        return Ok(());
    }
    let map = entries.iter().map(|(t, c)| format!("{t}:{c}")).collect::<Vec<_>>().join(";");
    parts.retain(|(k, _)| k != "color-map");
    parts.insert(0, ("color-map".into(), map));
    let style = parts.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join(",");
    let _: Value = pve.put("/cluster/options", form![("tag-style", style)]).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn os_tags() {
        assert_eq!(os("windows", "ws2025-datacenter-desktop", Some("10.0.26100.4061")), "ws2025-datacenter-desktop-26100.4061");
        assert_eq!(os("windows", "w11-enterprise", None), "w11-enterprise");
        assert_eq!(os("linux", "ubuntu2604", Some("x")), "ubuntu-26.04");
        assert_eq!(os("linux", "arch", None), "arch");
        assert_eq!(os("linux", "leap16", None), "opensuse-16.0");
    }

    #[test]
    fn gold_tags() {
        let m = serde_json::json!({ "cis": { "level": 2 } });
        assert_eq!(gold("linux", "rocky9", &m), ["gold", "rocky-9", "cis-l2"]);
        assert_eq!(gold("windows", "w11-pro", &serde_json::json!({ "build": "26100" })), ["gold", "w11-pro-26100"]);
    }

    #[test]
    fn colours() {
        assert_eq!(colour("ws2022-standard-core"), "9ece6a");
        assert_eq!(colour("w11-pro"), "7dcfff");
        assert_eq!(colour("debian-13"), "e6de78");
        assert_eq!(colour("cis-l1"), "bb9af7");
    }
}
