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
    pub support: &'static str,
    /// The short name in ISO file names: ws2025, w11-25h2.
    pub short: &'static str,
    matches: fn(&str) -> bool,
}

pub static PRODUCTS: &[Product] = &[
    Product { id: "ws2025", name: "Windows Server 2025", group: "Windows Server", kind: Kind::Server, insider: false, short: "ws2025",
        support: "mainstream until 2029-11, extended until 2034-11", matches: |t| t.starts_with("Windows Server 2025 (") },
    Product { id: "ws2022", name: "Windows Server 2022", group: "Windows Server", kind: Kind::Server, insider: false, short: "ws2022",
        support: "extended support until 2031-10", matches: |t| t.starts_with("Feature update to Microsoft server operating system, version 21H2 (") },
    Product { id: "w11-26h2", name: "Windows 11, version 26H2", group: "Windows 11", kind: Kind::Client, insider: false, short: "w11-26h2",
        support: "current release", matches: |t| t.starts_with("Windows 11, version 26H2 (") },
    Product { id: "w11-26h1", name: "Windows 11, version 26H1", group: "Windows 11", kind: Kind::Client, insider: false, short: "w11-26h1",
        support: "for new devices only", matches: |t| t.starts_with("Windows 11, version 26H1 (") },
    Product { id: "w11-25h2", name: "Windows 11, version 25H2", group: "Windows 11", kind: Kind::Client, insider: false, short: "w11-25h2",
        support: "Pro until 2027-10, Enterprise until 2028-10", matches: |t| t.starts_with("Windows 11, version 25H2 (") },
    Product { id: "w11-24h2", name: "Windows 11, version 24H2", group: "Windows 11", kind: Kind::Client, insider: false, short: "w11-24h2",
        support: "Enterprise until 2027-10", matches: |t| t.starts_with("Windows 11, version 24H2 (") },
    Product { id: "w11-23h2", name: "Windows 11, version 23H2", group: "Windows 11", kind: Kind::Client, insider: false, short: "w11-23h2",
        support: "Enterprise until 2026-11", matches: |t| t.starts_with("Windows 11, version 23H2 (") },
    Product { id: "ws-insider", name: "Windows Server vNext", group: "Insider and vNext", kind: Kind::Server, insider: true, short: "ws-vnext",
        support: "Insider Preview - not for production", matches: |t| t.starts_with("Windows Server Insider Preview ") },
    Product { id: "w11-canary", name: "Windows 11 Insider, Canary", group: "Insider and vNext", kind: Kind::Client, insider: true, short: "w11-canary",
        support: "Insider Preview - not for production",
        matches: |t| t.starts_with("Windows 11 Insider Preview ") && t.contains("(rs_prerelease)") && t[27..].starts_with(|c: char| c.is_ascii_digit()) },
    Product { id: "w11-dev", name: "Windows 11 Insider, Dev and Beta", group: "Insider and vNext", kind: Kind::Client, insider: true, short: "w11-dev",
        support: "Insider Preview - not for production", matches: |t| t.starts_with("Windows 11 Insider Preview Feature Update (") },
];

pub fn product(id: &str) -> Option<&'static Product> {
    PRODUCTS.iter().find(|p| p.id == id)
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
pub async fn product_builds(web: &reqwest::Client, p: &Product, fresh: bool) -> Result<Vec<Build>> {
    let all = catalog(web, fresh).await?;
    let mut out: Vec<Build> = all.iter().filter(|b| b.arch == "amd64" && (p.matches)(&b.title)).cloned().collect();
    out.sort_by(|a, b| a.created.cmp(&b.created));
    let mut seen = std::collections::HashSet::new();
    out.retain(|b| seen.insert(b.build.clone()));
    let num = |b: &Build| b.build.split('.').map(|x| x.parse::<u64>().unwrap_or(0)).collect::<Vec<_>>();
    out.sort_by(|a, b| num(b).cmp(&num(a)));
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
        let mut attempt = 0;
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
    let resp = dl.get(&file.url).send().await.with_context(|| format!("downloading {}", file.name))?.error_for_status()?;
    let total = resp.content_length().unwrap_or(file.size).max(1);
    let mut out = tokio::fs::File::create(dest).await.with_context(|| format!("creating {}", dest.display()))?;
    let mut stream = resp.bytes_stream();
    let (mut got, mut shown) = (0u64, 0u64);
    let started = std::time::Instant::now();
    while let Some(chunk) = stream.next().await {
        log.check_abort()?;
        let chunk = chunk.with_context(|| format!("downloading {}", file.name))?;
        out.write_all(&chunk).await?;
        got += chunk.len() as u64;
        // Every half percent: often enough to move, rarely enough not to flood the log.
        if got - shown >= total / 200 || got == total {
            shown = got;
            let rate = got as f64 / started.elapsed().as_secs_f64().max(0.1) / 1e6;
            tick(got, rate);
        }
    }
    out.flush().await?;
    drop(out);
    if file.size != 0 && got != file.size {
        bail!("{}: got {got} bytes, the catalog says {}", file.name, file.size);
    }
    if loud {
        log.debug(format!("Checking {} against the catalog's SHA-1", file.name)).await;
    }
    let sum = tokio::process::Command::new("sha1sum").arg(dest).output().await.context("running sha1sum")?;
    let hash = String::from_utf8_lossy(&sum.stdout).split_whitespace().next().unwrap_or_default().to_lowercase();
    if hash != file.sha1 {
        bail!("{}: SHA-1 {hash}, the catalog says {} - the download is damaged", file.name, file.sha1);
    }
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
