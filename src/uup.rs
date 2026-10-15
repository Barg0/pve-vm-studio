//! Windows media straight from Microsoft's update servers. The UUP dump catalog
//! (api.uupdump.net) lists every build Windows Update offers, and for a build, language and
//! edition the files it is made of - each with Microsoft's CDN link and its SHA-1. The
//! studio takes only the list from UUP dump; the files come from Microsoft and are checked
//! against those hashes. Nothing here runs UUP dump's own converter.
//!
//! An edition's ESD carries three images: 1 is the Setup media (bootmgr, boot/, efi/,
//! sources/), 2 is WinRE - the base of WinPE - and 3 is the install image. WinPE needs only
//! that one file.

use std::path::Path;

use anyhow::{bail, Context, Result};
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt;

use crate::{jobs::JobLog, progress::Progress};

const API: &str = "https://api.uupdump.net";

/// One build in the catalog.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Build {
    pub uuid: String,
    pub title: String,
    pub build: String,
    pub arch: String,
    pub created: i64,
}

/// One file of a build, as the catalog lists it.
#[derive(Debug, Clone)]
pub struct File {
    pub name: String,
    pub url: String,
    pub sha1: String,
    pub size: u64,
}

/// When the last file list (get.php) was asked for. The catalog lets the other questions
/// through at any pace, but a file list makes it ask Microsoft, and it answers a second one
/// within about ten seconds with "too many requests" (measured: 1.2, 3 and 8 s apart are
/// refused, 12 s apart never). File lists are asked one at a time and that far apart; the
/// rest go straight, so the editions of a build never wait behind a file list.
static PACE: tokio::sync::Mutex<Option<std::time::Instant>> = tokio::sync::Mutex::const_new(None);
const GAP: std::time::Duration = std::time::Duration::from_secs(12);

/// One question to the catalog. It answers quick repeats with HTTP 429 or USER_RATE_LIMITED:
/// the studio waits (3, 9, 27 s) and asks again before it gives up.
async fn get(web: &reqwest::Client, path: &str, query: &[(&str, &str)]) -> Result<serde_json::Value> {
    let mut last = if path == "get.php" { Some(PACE.lock().await) } else { None };
    let mut wait = 3;
    for attempt in 0..4 {
        if let Some(Some(at)) = last.as_deref() {
            tokio::time::sleep(GAP.saturating_sub(at.elapsed())).await;
        }
        let resp = web.get(format!("{API}/{path}")).query(query).send().await;
        if let Some(l) = last.as_deref_mut() {
            *l = Some(std::time::Instant::now());
        }
        let resp = resp.with_context(|| format!("asking the UUP dump catalog ({path})"))?;
        // Too many questions too fast: it says so as HTTP 429 as well as in its JSON.
        if resp.status() == reqwest::StatusCode::TOO_MANY_REQUESTS && attempt < 3 {
            tokio::time::sleep(std::time::Duration::from_secs(wait)).await;
            wait *= 3;
            continue;
        }
        let v: serde_json::Value = resp
            .error_for_status()
            .with_context(|| format!("the UUP dump catalog refused {path}"))?
            .json()
            .await
            .with_context(|| format!("reading the UUP dump catalog's answer to {path}"))?;
        match v["response"]["error"].as_str() {
            Some("USER_RATE_LIMITED") if attempt < 3 => {
                tokio::time::sleep(std::time::Duration::from_secs(wait)).await;
                wait *= 3;
            }
            Some(e) => bail!("the UUP dump catalog says {e}"),
            None => return Ok(v["response"].clone()),
        }
    }
    bail!("the UUP dump catalog keeps saying \"too many requests\" - try again in a minute")
}

// ---- products ----

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    /// One ESD per edition holds the whole install image (Windows Server).
    Server,
    /// A small metadata ESD per edition plus shared package ESDs and CABs (Windows 11).
    Client,
}

/// A product the studio builds media for: how the catalog titles its full builds, and
/// whether Microsoft still supports it. Server 2019 and 2016 are not here - Windows Update
/// lists only their cumulative updates, never install media.
pub struct Product {
    pub id: &'static str,
    pub name: &'static str,
    pub group: &'static str,
    pub kind: Kind,
    pub insider: bool,
    /// The Windows Insider channel it follows, as UUP dump's fetchupd asks Windows Update
    /// for it (ring): its builds are the build line Microsoft offers there right now.
    pub ring: Option<&'static str>,
    /// Shown in the catalog and followed by Keep current. A hidden product only resolves
    /// the ISOs and golds made under it.
    pub listed: bool,
    pub support: &'static str,
    /// The short name in ISO file names: ws2025, w11-25h2.
    pub short: &'static str,
    matches: fn(&str) -> bool,
}

pub static PRODUCTS: &[Product] = &[
    Product { id: "ws2025", name: "Windows Server 2025", group: "Windows Server", kind: Kind::Server, insider: false, ring: None, listed: true, short: "ws2025",
        support: "mainstream until 2029-11, extended until 2034-11", matches: |t| t.starts_with("Windows Server 2025 (") },
    Product { id: "ws2022", name: "Windows Server 2022", group: "Windows Server", kind: Kind::Server, insider: false, ring: None, listed: true, short: "ws2022",
        support: "extended support until 2031-10", matches: |t| t.starts_with("Feature update to Microsoft server operating system, version 21H2 (") },
    Product { id: "w11-26h2", name: "Windows 11, version 26H2", group: "Windows 11", kind: Kind::Client, insider: false, ring: None, listed: true, short: "w11-26h2",
        support: "current release", matches: |t| t.starts_with("Windows 11, version 26H2 (") },
    Product { id: "w11-26h1", name: "Windows 11, version 26H1", group: "Windows 11", kind: Kind::Client, insider: false, ring: None, listed: true, short: "w11-26h1",
        support: "for new devices only", matches: |t| t.starts_with("Windows 11, version 26H1 (") },
    Product { id: "w11-25h2", name: "Windows 11, version 25H2", group: "Windows 11", kind: Kind::Client, insider: false, ring: None, listed: true, short: "w11-25h2",
        support: "Pro until 2027-10, Enterprise until 2028-10", matches: |t| t.starts_with("Windows 11, version 25H2 (") },
    Product { id: "w11-24h2", name: "Windows 11, version 24H2", group: "Windows 11", kind: Kind::Client, insider: false, ring: None, listed: true, short: "w11-24h2",
        support: "Enterprise until 2027-10", matches: |t| t.starts_with("Windows 11, version 24H2 (") },
    Product { id: "w11-23h2", name: "Windows 11, version 23H2", group: "Windows 11", kind: Kind::Client, insider: false, ring: None, listed: true, short: "w11-23h2",
        support: "Enterprise until 2026-11", matches: |t| t.starts_with("Windows 11, version 23H2 (") },
    Product { id: "ws-insider", name: "Windows Server vNext", group: "Insider and vNext", kind: Kind::Server, insider: true, ring: None, listed: true, short: "ws-vnext",
        support: "Insider Preview - not for production", matches: |t| t.starts_with("Windows Server Insider Preview ") },
    // Windows 11 Insider by channel (Microsoft's names since 04/2026), each asked live.
    Product { id: "w11-beta", name: "Windows 11 Insider, Beta", group: "Insider and vNext", kind: Kind::Client, insider: true, ring: Some("Beta"), listed: true, short: "w11-beta",
        support: "Insider Preview - not for production", matches: insider_title },
    Product { id: "w11-experimental", name: "Windows 11 Insider, Experimental", group: "Insider and vNext", kind: Kind::Client, insider: true, ring: Some("Dev:2"), listed: true, short: "w11-experimental",
        support: "Insider Preview - not for production", matches: insider_title },
    Product { id: "w11-future", name: "Windows 11 Insider, Future Platforms", group: "Insider and vNext", kind: Kind::Client, insider: true, ring: Some("Dev"), listed: true, short: "w11-future",
        support: "Insider Preview - not for production", matches: insider_title },
    // Before the channels: Dev and Beta mixed several build lines - it follows none.
    Product { id: "w11-dev", name: "Windows 11 Insider, Dev and Beta", group: "Insider and vNext", kind: Kind::Client, insider: true, ring: None, listed: false, short: "w11-dev",
        support: "Insider Preview - not for production", matches: |t| t.starts_with("Windows 11 Insider Preview Feature Update (") },
];

impl Product {
    /// An Insider product's channel in a word or two - Beta, Experimental, Future Platforms,
    /// vNext - for a gold's line; "" for a release.
    pub fn channel(&self) -> &'static str {
        if !self.insider {
            return "";
        }
        if self.kind == Kind::Server {
            return "vNext";
        }
        self.name.strip_prefix("Windows 11 Insider, ").unwrap_or(self.name)
    }
}

/// A product by id. "w11-canary" is Future Platforms: Microsoft renamed Canary in 04/2026,
/// and ISOs and golds made under the old id still resolve.
pub fn product(id: &str) -> Option<&'static Product> {
    let id = if id == "w11-canary" { "w11-future" } else { id };
    PRODUCTS.iter().find(|p| p.id == id)
}

/// The Insider product an ISO the studio built belongs to, by its file name
/// (enus-w11-future-pro-29683.1000.iso, enus-ws-vnext-29683.1000.iso) - a canary ISO is
/// Future Platforms.
pub fn insider_of_iso(volid: &str) -> Option<&'static Product> {
    let file = volid.rsplit('/').next()?;
    if file.contains("-w11-canary-") {
        return product("w11-future");
    }
    PRODUCTS.iter().filter(|p| p.insider).find(|p| file.contains(&format!("-{}-", p.short)))
}

/// A Windows 11 Insider flight as the catalog titles it: "Windows 11 Insider Preview Feature
/// Update (26220.9606)" or "Windows 11 Insider Preview 29683.1000 (rs_prerelease)" - not a
/// Quality Update, which is no install set.
fn insider_title(t: &str) -> bool {
    t.starts_with("Windows 11 Insider Preview Feature Update (")
        || (t.starts_with("Windows 11 Insider Preview ") && t.contains("(rs_prerelease)") && t[27..].starts_with(|c: char| c.is_ascii_digit()))
}

/// The Windows 11 releases a channel is asked from, newest first. Not 26H1: Microsoft offers
/// it on new devices only. Beta is offered from 25H2 but not from 26H2 (2026-10-14), so a
/// channel without an answer is asked from the next one.
const CHANNEL_BASES: [&str; 3] = ["w11-26h2", "w11-25h2", "w11-24h2"];

/// What each Insider channel offers: the flight Windows Update gives a Windows 11 client in
/// that ring (UUP dump's fetchupd), by product id. Asked in the background (refresh_offers)
/// and kept in the database, so the page never waits for Microsoft - a live question takes up
/// to 15 s, may fail, and the catalog allows about one in ten seconds - and a restart has
/// the last answers at once.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Offers {
    pub builds: std::collections::HashMap<String, Build>,
    /// Why a channel has no answer yet, by product id.
    pub errors: std::collections::HashMap<String, String>,
    /// When the channels were asked last (Unix seconds).
    pub asked: i64,
}

static OFFERS: std::sync::Mutex<Option<Offers>> = std::sync::Mutex::new(None);
/// One refresh at a time: the background's, a window's, a Refresh press.
static REFRESHING: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// The last answers from the database - once, at start.
pub async fn load_offers(db: &sqlx::SqlitePool) {
    let o: Offers = crate::settings::load(db, "channel_offers").await.unwrap_or_default();
    *OFFERS.lock().unwrap() = Some(o);
}

/// What the channel offers, as last asked - None while it has never answered.
pub fn offer(p: &Product) -> Option<Build> {
    OFFERS.lock().unwrap().as_ref().and_then(|o| o.builds.get(p.id).cloned())
}

/// Why a channel has no answer (None: none asked yet, or it answered).
pub fn offer_error(p: &Product) -> Option<String> {
    OFFERS.lock().unwrap().as_ref().and_then(|o| o.errors.get(p.id).cloned())
}

/// Seconds since the channels were asked last; None: never.
pub fn offers_age() -> Option<i64> {
    OFFERS.lock().unwrap().as_ref().filter(|o| o.asked > 0).map(|o| chrono::Utc::now().timestamp() - o.asked)
}

/// Asks every channel once, one question at a time and twelve seconds apart, from the newest
/// Windows 11 release that answers - a failed question tries the next release. A channel
/// that answers nothing keeps its last answer and says why. `wait`: queue behind a refresh
/// already running (a window wants fresh answers); else return at once.
pub async fn refresh_offers(web: &reqwest::Client, db: &sqlx::SqlitePool, wait: bool) -> Result<()> {
    let _one = if wait {
        REFRESHING.lock().await
    } else {
        match REFRESHING.try_lock() {
            Ok(g) => g,
            Err(_) => return Ok(()),
        }
    };
    let all = catalog(web, false).await?;
    let mut last_ask: Option<std::time::Instant> = None;
    for p in PRODUCTS.iter().filter(|p| p.listed) {
        let Some(ring) = p.ring else { continue };
        let mut found = None;
        let mut why = String::new();
        for base in CHANNEL_BASES.iter().filter_map(|id| product(id)) {
            // Its newest build, read off the catalog.
            let Some(from) = all.iter().filter(|b| b.arch == "amd64" && (base.matches)(&b.title)).max_by_key(|b| build_num(&b.build)) else { continue };
            if let Some(at) = last_ask {
                tokio::time::sleep(GAP.saturating_sub(at.elapsed())).await;
            }
            last_ask = Some(std::time::Instant::now());
            match get(web, "fetchupd.php", &[("arch", "amd64"), ("ring", ring), ("build", &from.build), ("sku", "48")]).await {
                Ok(r) => {
                    if let Some(mut b) = offered(p, &r) {
                        b.created = all.iter().filter(|c| c.uuid == b.uuid).map(|c| c.created).min().unwrap_or_else(|| chrono::Utc::now().timestamp());
                        found = Some(b);
                        break;
                    }
                }
                Err(e) => why = format!("asked from {}: {e:#}", base.name),
            }
        }
        let snapshot = {
            let mut g = OFFERS.lock().unwrap();
            let o = g.get_or_insert_with(Default::default);
            match found {
                Some(b) => {
                    o.builds.insert(p.id.to_owned(), b);
                    o.errors.remove(p.id);
                }
                None => {
                    let msg = if why.is_empty() {
                        format!("Microsoft offers nothing in {} from any Windows 11 release - the channel query ({ring}) may have changed", p.name)
                    } else {
                        format!("Microsoft did not answer for {} ({why}) - asked again in 15 minutes", p.name)
                    };
                    tracing::warn!("{msg}");
                    o.errors.insert(p.id.to_owned(), msg);
                }
            }
            o.asked = chrono::Utc::now().timestamp();
            o.clone()
        };
        crate::settings::save(db, "channel_offers", &snapshot).await?;
    }
    Ok(())
}

/// The background: the channels at start, then every six hours - a quarter of an hour after
/// one did not answer.
pub async fn offers_loop(web: reqwest::Client, db: sqlx::SqlitePool) {
    loop {
        // Asked within the last six hours (before a restart): not again yet.
        let fresh = offers_age().is_some_and(|a| a < 6 * 3600) && OFFERS.lock().unwrap().as_ref().is_some_and(|o| o.errors.is_empty());
        if !fresh && let Err(e) = refresh_offers(&web, &db, false).await {
            tracing::warn!("Insider channels not asked: {e:#}");
        }
        let failed = OFFERS.lock().unwrap().as_ref().is_none_or(|o| !o.errors.is_empty());
        tokio::time::sleep(std::time::Duration::from_secs(if failed { 900 } else { 6 * 3600 })).await;
    }
}

/// The newest flight of the product's kind in a fetchupd answer - beside it Windows Update
/// lists what else that client would get (OOBE updates, .NET, the release itself).
fn offered(p: &Product, r: &serde_json::Value) -> Option<Build> {
    r["updateArray"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|u| {
            let title = u["updateTitle"].as_str()?;
            if !(p.matches)(title) {
                return None;
            }
            Some(Build {
                uuid: u["updateId"].as_str()?.to_owned(),
                title: title.to_owned(),
                build: u["foundBuild"].as_str()?.to_owned(),
                arch: "amd64".into(),
                // Its first appearance in the catalog, else now - fetchupd just found it.
                created: 0,
            })
        })
        .max_by_key(|b| build_num(&b.build))
}

fn build_num(b: &str) -> Vec<u64> {
    b.split('.').map(|x| x.parse::<u64>().unwrap_or(0)).collect()
}

/// The whole catalog, asked once and kept for a quarter of an hour: one answer serves every
/// product, and the catalog rate-limits quick repeats.
static CATALOG: tokio::sync::Mutex<Option<(std::time::Instant, std::sync::Arc<Vec<Build>>)>> = tokio::sync::Mutex::const_new(None);

pub async fn catalog(web: &reqwest::Client, fresh: bool) -> Result<std::sync::Arc<Vec<Build>>> {
    let mut c = CATALOG.lock().await;
    if let Some((at, list)) = c.as_ref()
        && !fresh
        && at.elapsed() < std::time::Duration::from_secs(900)
    {
        return Ok(list.clone());
    }
    let r = get(web, "listid.php", &[("sortByDate", "1")]).await?;
    let list: Vec<Build> = match &r["builds"] {
        serde_json::Value::Object(m) => m.values().filter_map(|b| serde_json::from_value(b.clone()).ok()).collect(),
        serde_json::Value::Array(a) => a.iter().filter_map(|b| serde_json::from_value(b.clone()).ok()).collect(),
        _ => vec![],
    };
    if list.is_empty() {
        bail!("the UUP dump catalog listed no builds");
    }
    let list = std::sync::Arc::new(list);
    *c = Some((std::time::Instant::now(), list.clone()));
    Ok(list)
}

/// When the catalog was read last (for the page: "checked 10:20").
pub async fn catalog_age() -> Option<u64> {
    CATALOG.lock().await.as_ref().map(|(at, _)| at.elapsed().as_secs())
}

/// A product's full builds, highest build first, one entry per build number - its first
/// appearance in the catalog: the catalog lists an old build again when it fetches it once
/// more (26200.7985 of March, again on 2026-10-02), and that date is not its release.
///
/// A channel's builds are its current build line - the base build (26220, 29683) of what
/// Microsoft offers there now - so a jump to a new base (29xxx to 30xxx) moves the list with it.
pub async fn product_builds(web: &reqwest::Client, p: &Product, fresh: bool) -> Result<Vec<Build>> {
    let all = catalog(web, fresh).await?;
    // A channel's line is what it offered when last asked - never a live question here.
    let offer = match p.ring {
        Some(_) => match offer(p) {
            Some(o) => Some(o),
            None => return Ok(Vec::new()),
        },
        None => None,
    };
    let line = offer.as_ref().map(|o| o.build.split('.').next().unwrap_or("").to_owned());
    let mut out: Vec<Build> = all
        .iter()
        .filter(|b| b.arch == "amd64" && (p.matches)(&b.title) && line.as_deref().is_none_or(|l| b.build.split('.').next() == Some(l)))
        .cloned()
        .collect();
    if let Some(o) = offer
        && !out.iter().any(|b| b.build == o.build)
    {
        out.push(o);
    }
    out.sort_by_key(|a| a.created);
    let mut seen = std::collections::HashSet::new();
    out.retain(|b| seen.insert(b.build.clone()));
    let num = |b: &Build| b.build.split('.').map(|x| x.parse::<u64>().unwrap_or(0)).collect::<Vec<_>>();
    out.sort_by_key(|b| std::cmp::Reverse(num(b)));
    Ok(out)
}

/// The second Tuesday of a date's month (Patch Tuesday) and whether the date is it or the
/// day after.
fn on_patch_tuesday(d: chrono::NaiveDate) -> bool {
    use chrono::{Datelike, Weekday};
    let first = chrono::NaiveDate::from_ymd_opt(d.year(), d.month(), 1).unwrap();
    let to_tue = (7 + Weekday::Tue.num_days_from_monday() as i64 - first.weekday().num_days_from_monday() as i64) % 7;
    let pt = first + chrono::Duration::days(to_tue + 7);
    d >= pt && d <= pt + chrono::Duration::days(1)
}

/// What kind of release a build is, as Microsoft Update says (wu.rs): "2026-09 B" - the
/// month's Patch Tuesday security update; "2026-09 OOB" - a security update out of band;
/// "2026-09 preview" - not a security release (the D preview, a Release Preview build, a
/// non-security out-of-band fix); "Insider". Until Microsoft Update has been asked, the
/// catalog's date gives an estimate that never reads as a release: "2026-09 B?".
pub fn release_kind(p: &Product, build: &str, created: i64) -> String {
    use chrono::{Datelike, TimeZone};
    if p.insider {
        return "Insider".into();
    }
    let Some(d) = chrono::Utc.timestamp_opt(created, 0).single() else { return String::new() };
    let month = format!("{}-{:02}", d.year(), d.month());
    if let Some(answer) = crate::wu::category(p.id).and_then(|c| crate::wu::lookup(c, build)) {
        return match answer {
            Some(u) => {
                // Its month as Microsoft titles it ("2026-09 Cumulative Update ..."), else its date.
                let pub_day = chrono::DateTime::parse_from_rfc3339(&u.created).map(|t| t.date_naive()).unwrap_or(d.date_naive());
                let m = u.title.get(..7).filter(|t| t.as_bytes().get(4) == Some(&b'-') && t.chars().filter(|c| c.is_ascii_digit()).count() == 6).map(str::to_owned).unwrap_or_else(|| format!("{}-{:02}", pub_day.year(), pub_day.month()));
                format!("{m} {}", if on_patch_tuesday(pub_day) { "B" } else { "OOB" })
            }
            None => format!("{month} preview"),
        };
    }
    if on_patch_tuesday(d.date_naive()) { format!("{month} B?") } else { format!("{month} preview") }
}

/// A release "Keep current" and the Stable filter take: Microsoft's security updates,
/// Patch Tuesday and out of band.
pub fn is_release(kind: &str) -> bool {
    kind.ends_with(" B") || kind.ends_with(" OOB")
}

/// The editions of a build in a language, with the names Microsoft gives them.
pub async fn editions_named(web: &reqwest::Client, uuid: &str, lang: &str) -> Result<Vec<(String, String)>> {
    let r = get(web, "listeditions.php", &[("id", uuid), ("lang", lang)]).await?;
    let names = r["editionFancyNames"].clone();
    Ok(r["editionList"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|e| e.as_str())
        .map(|e| (e.to_owned(), names[e].as_str().unwrap_or(e).to_owned()))
        .collect())
}

/// The languages a build is offered in (lower case, "en-us").
pub async fn languages(web: &reqwest::Client, uuid: &str) -> Result<Vec<String>> {
    let r = get(web, "listlangs.php", &[("id", uuid)]).await?;
    Ok(r["langList"].as_array().into_iter().flatten().filter_map(|l| l.as_str()).filter(|l| *l != "neutral").map(str::to_owned).collect())
}

/// The editions of a build in a language (upper case, "SERVERDATACENTERCORE").
pub async fn editions(web: &reqwest::Client, uuid: &str, lang: &str) -> Result<Vec<String>> {
    let r = get(web, "listeditions.php", &[("id", uuid), ("lang", lang)]).await?;
    Ok(r["editionList"].as_array().into_iter().flatten().filter_map(|e| e.as_str()).map(str::to_owned).collect())
}

/// A language tag as people write it: en-US, sr-Latn-RS, zh-CN (the catalog has en-us).
pub fn lang_tag(t: &str) -> String {
    t.split('-')
        .enumerate()
        .map(|(i, p)| match (i, p.len()) {
            (0, _) => p.to_lowercase(),
            (_, 4) => p[..1].to_uppercase() + &p[1..].to_lowercase(),
            _ => p.to_uppercase(),
        })
        .collect::<Vec<_>>()
        .join("-")
}

/// The files of a build, language and edition.
pub async fn files(web: &reqwest::Client, uuid: &str, lang: &str, edition: &str) -> Result<Vec<File>> {
    let ed = edition.to_lowercase();
    let r = get(web, "get.php", &[("id", uuid), ("lang", lang), ("edition", &ed)]).await?;
    let Some(map) = r["files"].as_object() else { bail!("the UUP dump catalog lists no files for {uuid} {lang} {edition}") };
    Ok(map
        .iter()
        .map(|(name, f)| File {
            name: name.clone(),
            url: f["url"].as_str().unwrap_or_default().to_owned(),
            sha1: f["sha1"].as_str().unwrap_or_default().to_lowercase(),
            size: f["size"].as_str().and_then(|s| s.parse().ok()).or_else(|| f["size"].as_u64()).unwrap_or(0),
        })
        .collect())
}

/// Every file of a build - all languages, all editions, the Features on Demand.
pub async fn files_all(web: &reqwest::Client, uuid: &str) -> Result<Vec<File>> {
    let r = get(web, "get.php", &[("id", uuid)]).await?;
    let Some(map) = r["files"].as_object() else { bail!("the UUP dump catalog lists no files for {uuid}") };
    Ok(map
        .iter()
        .map(|(name, f)| File {
            name: name.clone(),
            url: f["url"].as_str().unwrap_or_default().to_owned(),
            sha1: f["sha1"].as_str().unwrap_or_default().to_lowercase(),
            size: f["size"].as_str().and_then(|s| s.parse().ok()).or_else(|| f["size"].as_u64()).unwrap_or(0),
        })
        .collect())
}

/// The edition whose ESD is the smallest way to WinPE: every edition carries the same
/// Setup media and WinRE, so a Core edition (no desktop in its install image) will do.
pub fn winpe_edition(editions: &[String]) -> Option<String> {
    const PREFER: [&str; 5] = ["SERVERDATACENTERCORE", "SERVERSTANDARDCORE", "CORE", "PROFESSIONAL", "SERVERSTANDARD"];
    PREFER.iter().find_map(|p| editions.iter().find(|e| e.eq_ignore_ascii_case(p)).cloned()).or_else(|| editions.first().cloned())
}

/// An edition's own ESD among a build's files: <Edition>_<lang>.esd, or an Insider set's
/// MetadataESD_<Edition>_<lang>.esd.
pub fn edition_esd(files: &[File], edition: &str, lang: &str) -> Option<File> {
    let want = format!("{edition}_{lang}.esd").to_lowercase();
    files.iter().find(|f| f.name.to_lowercase() == want || f.name.to_lowercase() == format!("metadataesd_{want}")).cloned()
}

/// When a CDN link stops being handed out (its P1 parameter, epoch seconds). Microsoft's
/// links live about a quarter of an hour; a download already running finishes past it.
pub fn link_expires(url: &str) -> Option<i64> {
    url.split(['?', '&']).find_map(|kv| kv.strip_prefix("P1=")).and_then(|v| v.parse().ok())
}

fn forbidden(e: &anyhow::Error) -> bool {
    e.chain().any(|c| c.downcast_ref::<reqwest::Error>().and_then(|r| r.status()) == Some(reqwest::StatusCode::FORBIDDEN))
}

/// A body that ended before the catalog's size.
#[derive(Debug)]
struct Short;

impl std::fmt::Display for Short {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the connection ended early")
    }
}

impl std::error::Error for Short {}

/// A cut connection, a stall or a server hiccup: the next try continues the part where
/// this one stopped.
fn cut(e: &anyhow::Error) -> bool {
    e.chain().any(|c| {
        c.downcast_ref::<Short>().is_some()
            || c.downcast_ref::<reqwest::Error>().is_some_and(|r| {
                r.is_body() || r.is_decode() || r.is_timeout() || r.is_connect() || r.is_request() || r.status().is_some_and(|s| s.is_server_error())
            })
    })
}

/// Whether `dest` is this file already - same size, same SHA-1 (a retry after a failed
/// build skips what it has).
async fn have(file: &File, dest: &Path) -> bool {
    if tokio::fs::metadata(dest).await.map(|m| m.len()).ok() != Some(file.size) {
        return false;
    }
    let Ok(sum) = tokio::process::Command::new("sha1sum").arg(dest).output().await else { return false };
    String::from_utf8_lossy(&sum.stdout).split_whitespace().next().is_some_and(|h| h.eq_ignore_ascii_case(&file.sha1))
}

/// Downloads many files one after the other, the bar measured over all of their bytes.
/// Files already in `dir` (right size and SHA-1) are kept. Links about to expire, or
/// refused with 403, are asked again: `refresh` returns the catalog's fresh file list.
pub async fn download_all<F, Fut>(web: &reqwest::Client, log: &JobLog, pr: &mut Progress, files: &mut [File], dir: &Path, mut refresh: F) -> Result<()>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<Vec<File>>>,
{
    let total: u64 = files.iter().map(|f| f.size).sum::<u64>().max(1);
    let mut before = 0u64;
    let (mut kept, mut fetched) = (0, 0);
    // One step for all of them; each file is a line inside it.
    log.run(format!("Downloading {} file(s), {:.2} GB, from Microsoft", files.len(), total as f64 / 1e9)).await;
    let count = files.len();
    for i in 0..count {
        let dest = dir.join(&files[i].name);
        if have(&files[i], &dest).await {
            before += files[i].size;
            kept += 1;
            pr.within(before as f64 / total as f64, format!("file {} of {count} · already here", i + 1));
            continue;
        }
        let (mut attempt, mut cuts) = (0, 0);
        loop {
            // A link that runs out within two minutes is asked again first.
            if link_expires(&files[i].url).is_some_and(|t| t < chrono::Utc::now().timestamp() + 120) || attempt > 0 {
                let fresh = refresh().await.context("asking the catalog for fresh download links")?;
                for f in files.iter_mut() {
                    if let Some(n) = fresh.iter().find(|n| n.name == f.name) {
                        f.url = n.url.clone();
                    }
                }
                log.debug("Fresh download links from the catalog").await;
            }
            let (n, big) = (i + 1, files[i].size > 100_000_000);
            let r = download_with(web, log, &files[i], &dest, big, |got, rate| {
                let all = before + got;
                pr.within(all as f64 / total as f64, format!("file {n} of {count} · {:.2} of {:.2} GB · {rate:.0} MB/s", all as f64 / 1e9, total as f64 / 1e9));
            })
            .await;
            match r {
                Ok(()) => break,
                Err(e) if forbidden(&e) && attempt < 2 => {
                    attempt += 1;
                    log.warn(format!("{}: the link expired - asking the catalog for a fresh one", files[i].name)).await;
                }
                Err(e) if cut(&e) && cuts < 5 => {
                    cuts += 1;
                    log.debug(format!("{e:#}")).await;
                    log.warn(format!("{}: the connection broke - continuing where it stopped (try {} of 6)", files[i].name, cuts + 1)).await;
                    tokio::time::sleep(std::time::Duration::from_secs(5 * cuts)).await;
                    log.check_abort()?;
                }
                Err(e) => return Err(e),
            }
        }
        before += files[i].size;
        fetched += 1;
    }
    log.ok(format!("{count} file(s) here, each matching the catalog's SHA-1{}", if kept > 0 { format!(" - {kept} kept from an earlier try, {fetched} downloaded") } else { String::new() })).await;
    Ok(())
}

async fn download_with(web: &reqwest::Client, log: &JobLog, file: &File, dest: &Path, loud: bool, mut tick: impl FnMut(u64, f64)) -> Result<()> {
    if file.url.is_empty() || file.sha1.len() != 40 {
        bail!("the catalog gives {} no link or no SHA-1", file.name);
    }
    let host = file.url.split('/').nth(2).unwrap_or("Microsoft's CDN");
    if loud {
        // A step of its own in the log - the longest one.
        log.line(format!("{} ({:.1} GB) from {host}", file.name, file.size as f64 / 1e9)).await;
    } else {
        log.debug(format!("Downloading {} ({:.1} MB)", file.name, file.size as f64 / 1e6)).await;
    }
    // Its own client: the studio's shared one gives a whole request 60 s, and 2 GB take
    // longer than that. Here only a stall counts - no byte for a minute.
    let _ = web;
    let dl = reqwest::Client::builder()
        .user_agent(concat!("pve-vm-studio/", env!("CARGO_PKG_VERSION")))
        .connect_timeout(std::time::Duration::from_secs(30))
        .read_timeout(std::time::Duration::from_secs(60))
        .build()?;
    // The bytes go to <name>.part and continue where a cut-off try stopped (an HTTP range):
    // a restart of the studio in the middle of a 4.6 GB update costs only what was missing.
    // A file left whole-named but short by a studio before 2026-10-07 is such a part too.
    let part = dest.with_file_name(format!("{}.part", file.name));
    if !tokio::fs::try_exists(&part).await.unwrap_or(false)
        && tokio::fs::metadata(dest).await.is_ok_and(|m| m.len() < file.size)
    {
        let _ = tokio::fs::rename(dest, &part).await;
    }
    let mut from = tokio::fs::metadata(&part).await.map(|m| m.len()).unwrap_or(0);
    if from >= file.size {
        from = 0;
    }
    let mut req = dl.get(&file.url);
    if from > 0 {
        req = req.header(reqwest::header::RANGE, format!("bytes={from}-"));
    }
    let resp = req.send().await.with_context(|| format!("downloading {}", file.name))?.error_for_status()?;
    // 206: the rest follows. 200: the server sends it all again - start over.
    if resp.status() != reqwest::StatusCode::PARTIAL_CONTENT {
        from = 0;
    } else {
        log.debug(format!("{}: continuing at {:.2} of {:.2} GB", file.name, from as f64 / 1e9, file.size as f64 / 1e9)).await;
    }
    let total = from + resp.content_length().unwrap_or(file.size - from);
    let total = total.max(1);
    let mut out = if from > 0 {
        tokio::fs::OpenOptions::new().append(true).open(&part).await.with_context(|| format!("opening {}", part.display()))?
    } else {
        tokio::fs::File::create(&part).await.with_context(|| format!("creating {}", part.display()))?
    };
    let mut stream = resp.bytes_stream();
    let (mut got, mut shown) = (from, from);
    let started = std::time::Instant::now();
    while let Some(chunk) = stream.next().await {
        log.check_abort()?;
        let chunk = chunk.with_context(|| format!("downloading {}", file.name))?;
        out.write_all(&chunk).await?;
        got += chunk.len() as u64;
        // Every half percent: often enough to move, rarely enough not to flood the log.
        if got - shown >= total / 200 || got == total {
            shown = got;
            let rate = (got - from) as f64 / started.elapsed().as_secs_f64().max(0.1) / 1e6;
            tick(got, rate);
        }
    }
    out.flush().await?;
    drop(out);
    if file.size != 0 && got != file.size {
        // More than the catalog's size: the part is not this file's - the next try starts over.
        if got > file.size {
            let _ = tokio::fs::remove_file(&part).await;
            bail!("{}: got {got} bytes, the catalog says {}", file.name, file.size);
        }
        return Err(anyhow::Error::new(Short).context(format!("{}: got {got} of {} bytes", file.name, file.size)));
    }
    if loud {
        log.debug(format!("Checking {} against the catalog's SHA-1", file.name)).await;
    }
    let sum = tokio::process::Command::new("sha1sum").arg(&part).output().await.context("running sha1sum")?;
    let hash = String::from_utf8_lossy(&sum.stdout).split_whitespace().next().unwrap_or_default().to_lowercase();
    if hash != file.sha1 {
        // Damaged (or a continued part that was not this file's): never continued again.
        let _ = tokio::fs::remove_file(&part).await;
        bail!("{}: SHA-1 {hash}, the catalog says {} - the download is damaged", file.name, file.sha1);
    }
    tokio::fs::rename(&part, dest).await.with_context(|| format!("naming {}", dest.display()))?;
    if loud {
        log.ok(format!("{}: SHA-1 matches ({})", file.name, file.sha1)).await;
    } else {
        log.debug(format!("{}: SHA-1 matches", file.name)).await;
    }
    Ok(())
}

/// The names and sizes of an edition's files, for the size shown before a build - not for
/// the build itself (Microsoft's links expire). A build's files never change, so they are
/// asked for once and kept on disk: one file list costs the catalog's ten-second budget.
static SIZES: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

pub async fn files_cached(web: &reqwest::Client, cache: &std::path::Path, uuid: &str, lang: &str, edition: &str) -> Result<Vec<File>> {
    // One at a time: a second ask for the same list waits and then finds it on disk.
    let _one = SIZES.lock().await;
    let key = format!("{uuid}/{lang}/{}", edition.to_lowercase());
    let mut all: std::collections::BTreeMap<String, Vec<(String, u64)>> =
        tokio::fs::read(cache).await.ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default();
    if let Some(list) = all.get(&key) {
        return Ok(list.iter().map(|(name, size)| File { name: name.clone(), url: String::new(), sha1: String::new(), size: *size }).collect());
    }
    let f = files(web, uuid, lang, edition).await?;
    all.insert(key, f.iter().map(|x| (x.name.clone(), x.size)).collect());
    if let Ok(b) = serde_json::to_vec(&all) {
        let tmp = cache.with_extension("tmp");
        if tokio::fs::write(&tmp, b).await.is_ok() {
            let _ = tokio::fs::rename(&tmp, cache).await;
        }
    }
    Ok(f)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// fetchupd's answers of 2026-10-15, asked from 26300.9711 (26H2) - trimmed to updateArray.
    fn answer(entries: &[(&str, &str, &str)]) -> serde_json::Value {
        serde_json::json!({ "updateArray": entries.iter().map(|(b, id, t)| serde_json::json!({ "foundBuild": b, "updateId": id, "updateTitle": t })).collect::<Vec<_>>() })
    }

    #[test]
    fn a_channel_takes_its_flight_from_the_answer() {
        let oobe = ("26100.9544", "4080ccdd-2ca4-4159-9d58-580338279bdf", "Critical OOBE Update for Windows 11 - KB5128942 (26100.9544) (3)");
        let net = ("26300.10008", "16df4c62-9d99-47e5-ac31-a5ae03d7e113", ".NET Framework Security Update for Windows 11 - KB5127694 (26300.10008)");
        let dev = answer(&[oobe, ("29683.1000", "2fab9ee5-66d1-4532-8592-f48a223edf69", "Windows 11 Insider Preview 29683.1000 (rs_prerelease)"), net]);
        let b = offered(product("w11-future").unwrap(), &dev).unwrap();
        assert_eq!((b.build.as_str(), b.uuid.as_str()), ("29683.1000", "2fab9ee5-66d1-4532-8592-f48a223edf69"));
        let dev2 = answer(&[oobe, ("26340.9616", "398e3bc2-9c3f-4d87-b40b-e54a46826056", "Windows 11 Insider Preview Feature Update (26340.9616)"), net]);
        assert_eq!(offered(product("w11-experimental").unwrap(), &dev2).unwrap().build, "26340.9616");
        // Beta from 26H2: only the release and other updates - nothing, so the next base is asked.
        let beta = answer(&[("26300.9711", "2b22470a-8b6f-498f-9c88-66f7b9fb56b1", "Windows 11, version 26H2 (26300.9711)"), oobe, net]);
        assert!(offered(product("w11-beta").unwrap(), &beta).is_none());
        assert!(offered(product("w11-beta").unwrap(), &serde_json::json!({})).is_none());
    }

    /// Live: asks UUP dump for every channel the way the background does, into a database,
    /// and reads them back the way the page does. `cargo test -- --ignored channels_live`.
    #[tokio::test]
    #[ignore]
    async fn channels_live() {
        let db = sqlx::sqlite::SqlitePoolOptions::new().max_connections(1).connect("sqlite::memory:").await.unwrap();
        sqlx::migrate!().run(&db).await.unwrap();
        let web = reqwest::Client::builder().user_agent("pve-vm-studio/test").build().unwrap();
        let t = std::time::Instant::now();
        refresh_offers(&web, &db, true).await.unwrap();
        eprintln!("asked in {:.0} s", t.elapsed().as_secs_f64());
        // A restart: the answers come back from the database.
        *OFFERS.lock().unwrap() = None;
        load_offers(&db).await;
        let t = std::time::Instant::now();
        for id in ["w11-beta", "w11-experimental", "w11-future"] {
            let p = product(id).unwrap();
            let list = product_builds(&web, p, false).await.unwrap();
            eprintln!("{id}: offer {:?}, error {:?}, {} builds, newest {:?}", offer(p).map(|b| b.build), offer_error(p), list.len(), list.first().map(|b| &b.build));
        }
        eprintln!("listed in {:.2} s", t.elapsed().as_secs_f64());
        assert!(["w11-beta", "w11-experimental", "w11-future"].iter().any(|id| offer(product(id).unwrap()).is_some()));
    }

    #[test]
    fn insider_titles_and_names() {
        assert!(insider_title("Windows 11 Insider Preview Feature Update (26220.9606)"));
        assert!(insider_title("Windows 11 Insider Preview 29683.1000 (rs_prerelease)"));
        assert!(!insider_title("Windows 11 Insider Preview Quality Update (26340.9233)"), "no install set");
        assert!(!insider_title("Windows Server Insider Preview 29683.1000 (rs_flight)"));
        // Canary is Future Platforms since 04/2026: the old id resolves, and is not listed.
        assert_eq!(product("w11-canary").unwrap().id, "w11-future");
        assert!(PRODUCTS.iter().all(|p| p.id != "w11-canary"));
        assert!(!product("w11-dev").unwrap().listed);
        let listed: Vec<&str> = PRODUCTS.iter().filter(|p| p.insider && p.listed).map(|p| p.id).collect();
        assert_eq!(listed, ["ws-insider", "w11-beta", "w11-experimental", "w11-future"]);
        // The channel by the ISO's name - it outlives the ISO.
        assert_eq!(insider_of_iso("local:iso/enus-w11-canary-pro-29671.1000.iso").unwrap().id, "w11-future");
        assert_eq!(insider_of_iso("local:iso/enus-w11-beta-pro-26220.9606.iso").unwrap().id, "w11-beta");
        assert_eq!(insider_of_iso("local:iso/enus-w11-experimental-26340.9616.iso").unwrap().id, "w11-experimental");
        assert_eq!(insider_of_iso("local:iso/enus-ws-vnext-dc-core-29683.1000.iso").unwrap().id, "ws-insider");
        assert!(insider_of_iso("local:iso/enus-w11-pro-26300.9711.iso").is_none());
        assert!(insider_of_iso("local:iso/enus-ws2025-dc-core-26100.33650.iso").is_none());
        let ch = |id: &str| product(id).unwrap().channel();
        assert_eq!([ch("w11-beta"), ch("w11-experimental"), ch("w11-canary"), ch("ws-insider"), ch("w11-dev"), ch("w11-26h2")],
            ["Beta", "Experimental", "Future Platforms", "vNext", "Dev and Beta", ""]);
    }

    #[test]
    fn release_preview_is_no_patch_tuesday() {
        let p = super::product("w11-25h2").unwrap();
        // 26200.9445 (2026-09-08), 26200.9539 Release Preview (2026-09-10), 26200.9550 (2026-09-22).
        // Before Microsoft Update has answered: an estimate, never a release.
        assert_eq!(super::release_kind(p, "26200.9445", 1788868800), "2026-09 B?");
        assert_eq!(super::release_kind(p, "26200.9539", 1789059644), "2026-09 preview");
        assert_eq!(super::release_kind(p, "26200.9550", 1790096424), "2026-09 preview");
        assert!(!super::is_release("2026-09 B?") && super::is_release("2026-09 B") && super::is_release("2026-09 OOB"));
    }

    #[test]
    fn tags() {
        assert_eq!(super::lang_tag("en-us"), "en-US");
        assert_eq!(super::lang_tag("sr-latn-rs"), "sr-Latn-RS");
        assert_eq!(super::lang_tag("de-DE"), "de-DE");
    }
}
