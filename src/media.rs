//! Windows install media built from Microsoft's own update files - the "Windows media" blade.
//! The way Microsoft refreshes its media every month, done here:
//!
//!   1. the UUP dump catalog names the files of a build, language and edition;
//!   2. they come from Microsoft's CDN, each checked against its SHA-1;
//!   3. on Linux (wimlib): the Setup media from the first edition's ESD, boot.wim (WinPE and
//!      the Setup environment), and install.wim - one image per edition, WinRE inside;
//!   4. when the build is newer than its base (a cumulative update on top), a temporary
//!      WinPE worker VM applies the updates with DISM - Linux cannot install CBS packages.
//!      It fetches its input from the studio over HTTPS and sends the serviced image back
//!      the same way - curl.exe out of the very image it services, on its seed disk, the
//!      studio's certificate pinned, one random token per run (no file share in the
//!      container); it reports on its serial console and powers off when done;
//!   5. a UDF ISO (install.wim passes 4 GiB), uploaded into PVE's ISO storage.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

use crate::{
    form,
    golds::{self, GOLD_IDS, GOLD_POOL},
    jobs::JobLog,
    progress::Progress,
    pve::{enc, Pve},
    seed::{self, SeedDisk},
    settings::{self, Placement},
    uup::{self, Kind, Product},
    windows,
    winpe::{self, run},
};

/// How the worker reaches the studio: its HTTPS address and the SHA-256 pin of its
/// certificate's public key ("" when the studio serves plain HTTP).
pub struct Link {
    pub base: String,
    pub pin: String,
}

/// The runs the worker endpoints serve: run id -> (token, folder). A run is there only
/// while its worker is.
type Runs = std::sync::Mutex<std::collections::HashMap<String, (String, PathBuf)>>;
static RUNS: std::sync::LazyLock<Runs> = std::sync::LazyLock::new(Default::default);

/// The worker's side door, outside /api: GET a file of its run, PUT the serviced image back.
/// Only a running run's random token opens it; no body size limit (images pass 4 GiB).
pub fn worker_router<S: Clone + Send + Sync + 'static>() -> axum::Router<S> {
    use axum::routing::get;
    axum::Router::new()
        .route("/worker/{run}/{token}/{*path}", get(worker_get).put(worker_put))
        .layer(axum::extract::DefaultBodyLimit::disable())
}

fn worker_file(run: &str, token: &str, path: &str) -> Option<PathBuf> {
    let runs = RUNS.lock().unwrap();
    let (t, dir) = runs.get(run)?;
    if t.len() != token.len() || !t.bytes().zip(token.bytes()).fold(true, |ok, (a, b)| ok & (a == b)) {
        return None;
    }
    // Plain names below the run's folder only: install.wim, upd/01-x.cab, upd/lcu/x.msu.
    let parts: Vec<&str> = path.split('/').collect();
    if parts.is_empty() || parts.len() > 3 || parts.iter().any(|p| p.is_empty() || p.starts_with('.') || p.contains('\\')) {
        return None;
    }
    Some(parts.iter().fold(dir.clone(), |d, p| d.join(p)))
}

async fn worker_get(axum::extract::Path((run, token, path)): axum::extract::Path<(String, String, String)>) -> axum::response::Response {
    use axum::response::IntoResponse;
    if path == "ping" {
        return match worker_file(&run, &token, "ping") {
            Some(_) => "ok".into_response(),
            None => axum::http::StatusCode::NOT_FOUND.into_response(),
        };
    }
    let Some(file) = worker_file(&run, &token, &path) else { return axum::http::StatusCode::NOT_FOUND.into_response() };
    match tokio::fs::File::open(&file).await {
        Ok(f) => {
            let len = f.metadata().await.map(|m| m.len()).unwrap_or(0);
            let body = axum::body::Body::from_stream(tokio_util::io::ReaderStream::with_capacity(f, 1 << 20));
            ([(axum::http::header::CONTENT_LENGTH, len.to_string())], body).into_response()
        }
        Err(_) => axum::http::StatusCode::NOT_FOUND.into_response(),
    }
}

async fn worker_put(axum::extract::Path((run, token, path)): axum::extract::Path<(String, String, String)>, body: axum::body::Body) -> axum::http::StatusCode {
    use futures::StreamExt;
    use tokio::io::AsyncWriteExt;
    // What the worker sends back: the images, its package lists, DISM's log.
    let list = path.strip_prefix("packages-").and_then(|r| r.strip_suffix(".txt")).is_some_and(|n| !n.is_empty() && n.chars().all(|c| c.is_ascii_digit()))
        // health-<index>[-before|-updated|-cleaned].txt: a scan after each stage, the last as it ships.
        || path.strip_prefix("health-").and_then(|r| r.strip_suffix(".txt")).map(|n| ["-before", "-updated", "-cleaned"].iter().find_map(|s| n.strip_suffix(s)).unwrap_or(n)).is_some_and(|n| !n.is_empty() && n.chars().all(|c| c.is_ascii_digit()));
    let step_log = path.strip_prefix("logs/").and_then(|r| r.strip_suffix(".log")).is_some_and(|n| !n.is_empty() && n.chars().all(|c| c.is_ascii_alphanumeric() || "-_.%".contains(c)) && !n.contains(".."));
    if !matches!(path.as_str(), "serviced.wim" | "winre-serviced.wim" | "boot-serviced.wim" | "dism.log") && !list && !step_log {
        return axum::http::StatusCode::FORBIDDEN;
    }
    let Some(file) = worker_file(&run, &token, &path) else { return axum::http::StatusCode::NOT_FOUND };
    let Ok(mut out) = tokio::fs::File::create(&file).await else { return axum::http::StatusCode::INTERNAL_SERVER_ERROR };
    let mut stream = body.into_data_stream();
    while let Some(chunk) = stream.next().await {
        let Ok(chunk) = chunk else { return axum::http::StatusCode::BAD_REQUEST };
        if out.write_all(&chunk).await.is_err() {
            return axum::http::StatusCode::INTERNAL_SERVER_ERROR;
        }
    }
    if out.flush().await.is_err() {
        return axum::http::StatusCode::INTERNAL_SERVER_ERROR;
    }
    axum::http::StatusCode::CREATED
}

/// The SHA-256 of the certificate's public key, base64 - what curl --pinnedpubkey takes.
pub fn cert_pin(cert_pem: &[u8]) -> Option<String> {
    use base64::Engine;
    let (_, pem) = x509_parser::pem::parse_x509_pem(cert_pem).ok()?;
    let cert = pem.parse_x509().ok()?;
    let spki = cert.tbs_certificate.subject_pki.raw;
    let out = std::process::Command::new("sha256sum")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .ok()
        .and_then(|mut c| {
            use std::io::Write;
            c.stdin.take()?.write_all(spki).ok()?;
            c.wait_with_output().ok()
        })?;
    let hex = String::from_utf8_lossy(&out.stdout).split_whitespace().next()?.to_owned();
    let bytes: Vec<u8> = (0..hex.len()).step_by(2).filter_map(|i| u8::from_str_radix(hex.get(i..i + 2)?, 16).ok()).collect();
    (bytes.len() == 32).then(|| base64::engine::general_purpose::STANDARD.encode(bytes))
}

/// An ISO the studio built, as the blade lists it.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct MediaIso {
    pub volid: String,
    pub product: String,
    pub build: String,
    pub uuid: String,
    pub lang: String,
    pub editions: Vec<String>,
    pub built: String,
    pub size: u64,
    pub sha256: String,
    /// The updates the worker applied ("" when the build needed none).
    pub updates: Vec<String>,
}

/// The media worker VM's size (Studio settings). 4 GB by default; more makes DISM page less
/// on a big install image.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct WorkerSettings {
    pub memory_mb: u32,
    pub cores: u32,
    /// Debug tool (config.toml debug_tools): keep every downloaded file (work/uup-files)
    /// after a build, so the next build of the same files downloads nothing. Off: a build
    /// uses them up and the rest goes after six idle hours.
    pub keep_downloads: bool,
}

impl Default for WorkerSettings {
    fn default() -> Self {
        Self { memory_mb: 4096, cores: 2, keep_downloads: false }
    }
}

pub struct Request {
    pub product: &'static Product,
    pub uuid: String,
    pub build: String,
    pub lang: String,
    pub editions: Vec<String>,
    /// The run's id: its work folder media-<run>. A continued build has the interrupted one's.
    pub run: String,
}

/// <lang>-<os>[-<editions>]-<build>.iso - enus-ws2025-dc-core-26100.33438.iso. Windows 11's
/// releases share "w11" (the build number tells them apart); Insider channels keep theirs.
pub fn iso_name(p: &Product, build: &str, editions: &[String], lang: &str) -> String {
    let os = if p.kind == Kind::Client && !p.insider { "w11" } else { p.short };
    let ed = editions_part(editions);
    let ed = if ed.is_empty() { String::new() } else { format!("-{ed}") };
    format!("{}-{os}{ed}-{build}.iso", lang.to_lowercase().replace('-', ""))
}

/// The editions in a name, as short as they still say it: Server dc / std, narrowed by core or
/// desktop when only one of the two is on the ISO (dc-core, dc, core); Standard and
/// Datacenter mixed say nothing. One client edition by its name (pro, home, pro-n), several
/// say nothing.
fn editions_part(editions: &[String]) -> String {
    let up: Vec<String> = editions.iter().map(|e| e.to_uppercase()).collect();
    if up.is_empty() {
        return String::new();
    }
    if up.iter().all(|e| e.starts_with("SERVER")) {
        let family = |e: &str| if e.starts_with("SERVERDATACENTER") { "dc" } else if e.starts_with("SERVERSTANDARD") { "std" } else { "" };
        let fams: std::collections::BTreeSet<&str> = up.iter().map(|e| family(e)).collect();
        let cores = up.iter().filter(|e| e.ends_with("CORE")).count();
        let shape = if cores == up.len() { "core" } else if cores == 0 { "desktop" } else { "" };
        return match (fams.len(), fams.iter().next().copied().unwrap_or("")) {
            (1, f) if !f.is_empty() => [f, shape].iter().filter(|x| !x.is_empty()).copied().collect::<Vec<_>>().join("-"),
            _ => if shape == "core" { "core".into() } else { String::new() },
        };
    }
    if up.len() > 1 {
        return String::new();
    }
    match up[0].as_str() {
        "PROFESSIONAL" => "pro".into(),
        "PROFESSIONALN" => "pro-n".into(),
        "CORE" => "home".into(),
        "COREN" => "home-n".into(),
        "CORESINGLELANGUAGE" => "home-sl".into(),
        "EDUCATION" => "edu".into(),
        "EDUCATIONN" => "edu-n".into(),
        "ENTERPRISE" => "ent".into(),
        "ENTERPRISEN" => "ent-n".into(),
        e => e.to_lowercase(),
    }
}

pub fn is_update(name: &str) -> bool {
    let n = name.to_lowercase();
    // -baseless.cab/.psf are the express form of the same update - the full one is beside it.
    if n.contains("-baseless") {
        return false;
    }
    (n.starts_with("windows1") && n.contains("-kb") && (n.ends_with(".msu") || n.ends_with(".cab"))) || (n.starts_with("ssu-") && n.ends_with(".cab"))
}

pub(crate) fn is_aggregated(name: &str) -> bool {
    name.to_lowercase().ends_with(".aggregatedmetadata.cab")
}

/// KB5125758 out of Windows11.0-KB5125758-x64.cab.
pub(crate) fn kb_of(name: &str) -> Option<String> {
    let up = name.to_uppercase();
    let at = up.find("-KB")? + 1;
    let digits: String = up[at + 2..].chars().take_while(|c| c.is_ascii_digit()).collect();
    (!digits.is_empty()).then(|| format!("KB{digits}"))
}

/// Where an update goes, as Microsoft's media servicing steps put it: the install image,
/// WinRE (the Safe OS dynamic update), or the media's sources\ folder (the Setup dynamic
/// update - a CAB of files, not a package).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Target {
    Image,
    WinRe,
    Setup,
}

/// What the build's AggregatedMetadata.cab says about its updates: each one's target
/// (SafeOSDUCompDB_KB…, SetupDUCompDB_KB…; the rest go into the image), and which are the
/// cumulative update chain (outer.AggregatedMetadata_KB… - a checkpoint and the target).
#[derive(Default)]
pub(crate) struct UpdateInfo {
    targets: HashMap<String, Target>,
    pub(crate) cumulative: Vec<String>,
}

pub(crate) async fn update_targets(agg: &Path) -> UpdateInfo {
    let mut out = UpdateInfo::default();
    let Ok(o) = tokio::process::Command::new("cabextract").arg("-l").arg(agg).output().await else { return out };
    for line in String::from_utf8_lossy(&o.stdout).lines() {
        let name = line.rsplit('|').next().unwrap_or("").trim();
        if let Some(rest) = name.strip_prefix("outer.AggregatedMetadata_") {
            out.cumulative.push(rest.trim_end_matches(".cab").to_owned());
            continue;
        }
        let target = if name.starts_with("SafeOSDUCompDB_") {
            Target::WinRe
        } else if name.starts_with("SetupDUCompDB_") {
            Target::Setup
        } else {
            continue;
        };
        if let Some(kb) = name.split(['_', '-', '.']).find(|p| p.starts_with("KB")) {
            out.targets.insert(kb.to_owned(), target);
        }
    }
    out
}

/// The updates to apply, one per KB: the .msu where there is one, the .cab for the dynamic
/// updates and where no .msu exists. Order as Microsoft's servicing steps: the cumulative
/// update chain first, oldest first (the checkpoint, then the update built on it), then the
/// rest in KB order.
pub(crate) fn pick_updates(files: &[uup::File], info: &UpdateInfo) -> Vec<(uup::File, Target)> {
    let targets = &info.targets;
    let mut by_kb: Vec<(String, uup::File, Target)> = Vec::new();
    for f in files.iter().filter(|f| is_update(&f.name)) {
        let kb = kb_of(&f.name).unwrap_or_else(|| f.name.clone());
        let target = targets.get(&kb).copied().unwrap_or(Target::Image);
        let msu = f.name.to_lowercase().ends_with(".msu");
        match by_kb.iter_mut().find(|(k, _, _)| *k == kb) {
            Some(slot) => {
                let better = if target == Target::Image { msu } else { !msu };
                if better {
                    slot.1 = f.clone();
                }
            }
            None => by_kb.push((kb, f.clone(), target)),
        }
    }
    by_kb.sort_by(|a, b| {
        let n = |k: &str| k.trim_start_matches("KB").parse::<u64>().unwrap_or(u64::MAX);
        let later = |k: &str| !info.cumulative.iter().any(|c| c == k);
        later(&a.0).cmp(&later(&b.0)).then(n(&a.0).cmp(&n(&b.0)))
    });
    by_kb.into_iter().map(|(_, f, t)| (f, t)).collect()
}

/// Package CABs held back until an export asks for them. Off: the 26H2 run of 2026-10-04
/// showed the client export refers to them (Features on Demand preinstalled in the image), so
/// holding them back only cost a second round of downloads. The fallback in build() stays.
pub fn deferrable(kind: Kind, name: &str) -> bool {
    const HOLD_BACK: bool = false;
    let n = name.to_lowercase();
    HOLD_BACK && kind == Kind::Client && n.ends_with(".cab") && !is_update(name) && !is_aggregated(name)
}

/// Copies `src` into `dest`, matching existing names without case (the Setup dynamic
/// update writes setup.exe where the media has Setup.exe - an ISO must not carry both).
fn merge_ci(src: &Path, dest: &Path) -> Result<usize> {
    let mut n = 0;
    std::fs::create_dir_all(dest)?;
    for e in std::fs::read_dir(src)? {
        let e = e?;
        let name = e.file_name().to_string_lossy().into_owned();
        let existing = std::fs::read_dir(dest)?
            .filter_map(|x| x.ok())
            .find(|x| x.file_name().to_string_lossy().eq_ignore_ascii_case(&name))
            .map(|x| x.path());
        let to = existing.unwrap_or_else(|| dest.join(&name));
        if e.file_type()?.is_dir() {
            n += merge_ci(&e.path(), &to)?;
        } else {
            std::fs::copy(e.path(), &to)?;
            n += 1;
        }
    }
    Ok(n)
}

/// The edition's own ESD: <edition>_<lang>.esd, or MetadataESD_<edition>_<lang>.esd in the
/// split sets of Windows 11 and the Insider builds.
fn is_metadata(name: &str, edition: &str, lang: &str) -> bool {
    let n = name.to_lowercase();
    let want = format!("{}_{}.esd", edition.to_lowercase(), lang.to_lowercase());
    n == want || n == format!("metadataesd_{want}")
}

/// What to download for a build: each edition's ESD, the updates, and - for a split client
/// set - the package ESDs and CABs its install image is put together from. Apps, Edge and
/// the deployment helpers stay where they are.
pub fn wanted(kind: Kind, f: &uup::File, editions: &[String], lang: &str) -> bool {
    let n = f.name.to_lowercase();
    if editions.iter().any(|e| is_metadata(&f.name, e, lang)) || is_update(&f.name) || is_aggregated(&f.name) {
        return true;
    }
    if kind == Kind::Server {
        return false;
    }
    if n.contains("desktopdeployment") || n.starts_with("metadataesd_") || n.contains("-baseless") || n.ends_with(".psf") {
        return false;
    }
    // Another edition's metadata ESD (professional_en-us.esd while building Home) is not a package.
    let other_meta = n.ends_with(&format!("_{}.esd", lang.to_lowercase())) && !n.starts_with("microsoft-");
    // Edge.wim: Microsoft Edge, which a client's edition ESD no longer carries (/Add-Edge).
    (n.ends_with(".esd") && !other_meta) || n.ends_with(".cab") || n == "edge.wim"
}

fn kv(info: &str, key: &str) -> String {
    info.lines().find_map(|l| l.strip_prefix(key).map(|v| v.trim().to_owned())).unwrap_or_default()
}

/// The address the worker reaches the studio on: its first IPv4 address.
pub fn studio_ip() -> Result<String> {
    let out = std::process::Command::new("hostname").arg("-I").output().context("running hostname -I")?;
    String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .find(|ip| ip.parse::<std::net::Ipv4Addr>().is_ok_and(|a| !a.is_loopback()))
        .map(str::to_owned)
        .ok_or_else(|| anyhow::anyhow!("the studio has no IPv4 address for the worker to reach it on"))
}

/// The worker's script: take curl.exe off the seed, reach the studio, put the image and
/// the updates on the SATA scratch disk, apply the updates to every index (the .msu files
/// together - DISM orders a checkpoint update itself - then each .cab on its own, smallest
/// first, a cab that is not for this image skipped), clean up, export, send it back.
/// Everything it says goes to COM1, where the job reads it.
/// One DISM step with a verdict on the serial console: PVS-UPD-OK / PVS-UPD-FAIL <code>
/// (3010, "restart required", counts as done).
/// Each step logs to a file of its own (DISM's dism.log rotates and loses the early steps),
/// sent back to the studio whatever the verdict: an error line DISM logs in a step that
/// succeeded is reported with that step, not counted from a log that lost half the run.
/// Errors and warnings only (/LogLevel:2): at the default level a cumulative update's log
/// is 500-800 MB of info lines per image. dism.log keeps the full detail of the last steps.
fn dism_step(s: &mut String, what: &str, log: &str, dism: &str) {
    s.push_str(&format!("echo PVS-UPD {what} > COM1\r\n{dism} /LogPath:W:\\logs\\{log}.log /LogLevel:2 > COM1 2>&1\r\nset RC=!errorlevel!\r\nif \"!RC!\"==\"3010\" set RC=0\r\n"));
    s.push_str(&format!(
        "if \"!RC!\"==\"0\" (echo PVS-UPD-OK {what} > COM1) else (echo PVS-UPD-FAIL {what} !RC! > COM1 & set ERR=1)\r\n%C% -T W:\\logs\\{log}.log %U%/logs/{log}.log > nul 2>&1\r\n"
    ));
}

/// What the worker's DISM logs say: dism.log kept whole for reading (it rotates and holds
/// only the last steps), and each step's error lines in the job, named by its step - the
/// step's verdict follows from its markers. Files go to dism-logs/<kind>-<run>[-<step>].log.
pub(crate) async fn report_dism_logs(log: &JobLog, work: &Path, share: &Path, kind: &str, run_id: &str) -> Result<()> {
    let short = run_id.trim_start_matches("run-").chars().take(8).collect::<String>();
    let keep_dir = work.parent().unwrap_or(work).join("dism-logs");
    tokio::fs::create_dir_all(&keep_dir).await?;
    prune_dism_logs(&keep_dir, 5).await;
    let dism_log = share.join("dism.log");
    if dism_log.exists() {
        tokio::fs::copy(&dism_log, keep_dir.join(format!("{kind}-{short}.log"))).await?;
    }
    if let Ok(mut rd) = tokio::fs::read_dir(share.join("logs")).await {
        let mut names = Vec::new();
        while let Ok(Some(e)) = rd.next_entry().await {
            names.push(e.file_name().to_string_lossy().into_owned());
        }
        names.sort();
        for name in names {
            let path = share.join("logs").join(&name);
            let keep = keep_dir.join(format!("{kind}-{short}-{name}"));
            tokio::fs::copy(&path, &keep).await?;
            let text = String::from_utf8_lossy(&tokio::fs::read(&path).await?).into_owned();
            let errors: Vec<&str> = text.lines().filter(|l| l.contains(", Error ")).collect();
            if errors.is_empty() {
                continue;
            }
            let step = name.trim_end_matches(".log");
            // DISM logs error lines in steps that succeed (reverse deltas of superseded files, host
            // components WinPE lacks) - the verdicts and the health scan below decide.
            log.debug(format!("DISM logged {} error line(s) in {step}; the log is {}", errors.len(), keep.display())).await;
            for l in errors.iter().take(10) {
                log.debug(format!("{step} | {}", l.trim())).await;
            }
        }
    }
    Ok(())
}

/// Keeps the DISM logs of the newest `keep` builds (one build: <kind>-<run>.log and its
/// <kind>-<run>-<step>.log files), so the studio's disk does not fill up build by build.
async fn prune_dism_logs(dir: &Path, keep: usize) {
    let Ok(mut rd) = tokio::fs::read_dir(dir).await else { return };
    let mut runs: std::collections::HashMap<String, (std::time::SystemTime, Vec<PathBuf>)> = Default::default();
    while let Ok(Some(e)) = rd.next_entry().await {
        let name = e.file_name().to_string_lossy().into_owned();
        // <kind>-<run>[-<step>].log: every kind's runs together (winpe- ones from before too).
        let mut parts = name.splitn(3, ['-', '.']);
        let (Some(kind), Some(run)) = (parts.next(), parts.next()) else { continue };
        let run = format!("{kind}-{run}");
        let at = e.metadata().await.and_then(|m| m.modified()).unwrap_or(std::time::UNIX_EPOCH);
        let ent = runs.entry(run).or_insert((at, Vec::new()));
        ent.0 = ent.0.max(at);
        ent.1.push(e.path());
    }
    let mut by_age: Vec<_> = runs.into_values().collect();
    by_age.sort_by(|a, b| b.0.cmp(&a.0));
    for (_, files) in by_age.into_iter().skip(keep) {
        for f in files {
            let _ = tokio::fs::remove_file(f).await;
        }
    }
}

/// DISM /ScanHealth on the mounted image, its answer sent back as health-<at>.txt for the
/// studio to read (health_verdict) - the build takes no image Windows itself calls damaged.
/// Its own log (logs/health-<at>.log) names each corrupt file - what tells Microsoft's
/// reverse-delta scan error from real damage (reverse_delta_only).
fn health_check(at: &str) -> String {
    format!(
        "echo PVS-HEALTH {at} > COM1\r\ndism /English /Image:W:\\mount /Cleanup-Image /ScanHealth /ScratchDir:W:\\scratch /LogPath:W:\\logs\\health-{at}.log > W:\\health-{at}.txt 2>&1\r\n%C% -T W:\\health-{at}.txt %U%/health-{at}.txt > nul 2>&1\r\n%C% -T W:\\logs\\health-{at}.log %U%/logs/health-{at}.log > nul 2>&1\r\n"
    )
}

/// Since the 2026 cumulative updates of 26100/26200, /ScanHealth calls the store repairable
/// for reverse-delta payloads (WinSxS\<component>\r\<file>) alone - byte-identical to copies
/// it does not flag, RestoreHealth cannot clear them, live systems show the same (Microsoft
/// Tech Community, Sysnative, 2026-09). Some(count) when the scan's log has nothing
/// else: every corruption a CSI payload, every payload under \r\.
pub(crate) fn reverse_delta_only(cbs: &str) -> Option<usize> {
    let count = |key: &str| {
        cbs.lines().rev().find_map(|l| l.split_once(key).map(|(_, v)| v.trim().parse::<usize>().unwrap_or(usize::MAX)))
    };
    let total = count("Total Detected Corruption:")?;
    let payload = count("CSI Payload Corruption:")?;
    let corrupt: Vec<&str> = cbs.lines().filter(|l| l.contains("CSI Payload Corrupt\t") || l.contains("CSI Payload Corrupt ")).collect();
    (total > 0 && total == payload && corrupt.len() == total && corrupt.iter().all(|l| l.contains("\\r\\"))).then_some(total)
}

/// " - only reverse-delta files (n)" for a scan's log that reverse_delta_only accepts.
fn reverse_note(cbs: &str) -> String {
    reverse_delta_only(cbs).map(|n| format!(" - only {n} reverse-delta file(s), the known scan error")).unwrap_or_default()
}

/// What /ScanHealth said: Ok with its sentence, or Err with why the image is not healthy.
pub(crate) fn health_verdict(text: &str) -> std::result::Result<String, String> {
    let t = text.to_lowercase();
    if t.contains("no component store corruption detected") {
        Ok("no component store corruption detected".into())
    } else if t.contains("not repairable") {
        Err("the component store is damaged and not repairable".into())
    } else if t.contains("is repairable") {
        Err("the component store is damaged (repairable)".into())
    } else {
        // DISM's own words: its "Error: <n>" line and the sentence after it, else the last line.
        let lines: Vec<&str> = text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with("The DISM log file")).collect();
        let why = match lines.iter().position(|l| l.starts_with("Error:")) {
            Some(i) => lines[i..].iter().take(2).copied().collect::<Vec<_>>().join(" "),
            None => lines.last().copied().unwrap_or("no answer").to_owned(),
        };
        Err(format!("the scan gave no verdict: {why}"))
    }
}

/// boot.wim from a WinRE image: 1 is WinPE, 2 the Setup environment (Setup and its own DISM
/// in X:\sources, from the media in `tree`). Returns how many Setup files went in.
async fn build_boot_wim(log: &JobLog, tree: &Path, winre: &Path) -> Result<usize> {
    let winre_s = winre.display().to_string();
    let boot = tree.join("sources/boot.wim");
    let boot_s = boot.display().to_string();
    let _ = tokio::fs::remove_file(&boot).await;
    run(log, "wimlib-imagex", &["export", &winre_s, "1", &boot_s, "Microsoft Windows PE", "Microsoft Windows PE", "--compress=maximum"]).await?;
    run(log, "wimlib-imagex", &["info", &boot_s, "1", "--image-property", "FLAGS=9"]).await?;
    winpe::wim_update(&boot, "delete --force /Windows/System32/winpeshl.ini\n").await?;
    run(log, "wimlib-imagex", &["export", &winre_s, "1", &boot_s, "Microsoft Windows Setup", "Microsoft Windows Setup", "--boot"]).await?;
    run(log, "wimlib-imagex", &["info", &boot_s, "2", "--image-property", "FLAGS=2"]).await?;
    let (mut setup, n) = winpe::setup_source_cmds(tree).await?;
    setup.insert_str(0, "delete --force /Windows/System32/winpeshl.ini\n");
    winpe_update_index(&boot, 2, &setup).await?;
    Ok(n)
}

/// Microsoft's step 28: the boot manager of the (serviced) boot.wim onto the media - every
/// bootmgfw.efi / bootx64.efi / bootmgr.efi, and efi\microsoft\boot\boot.stl. Returns
/// what it replaced.
async fn boot_files_from(log: &JobLog, dir: &Path, tree: &Path) -> Result<Vec<String>> {
    let x = dir.join("bootfiles");
    let _ = tokio::fs::remove_dir_all(&x).await;
    tokio::fs::create_dir_all(&x).await?;
    let boot_s = tree.join("sources/boot.wim").display().to_string();
    let dest = format!("--dest-dir={}", x.display());
    // One by one: a path the image does not have fails the whole extract.
    for f in ["/Windows/Boot/EFI/bootmgfw.efi", "/Windows/Boot/EFI/bootmgr.efi", "/Windows/Boot/EFI/boot.stl"] {
        let _ = run(log, "wimlib-imagex", &["extract", &boot_s, "2", f, &dest, "--no-acls"]).await;
    }
    let mut replaced = Vec::new();
    let mut stack = vec![tree.to_path_buf()];
    while let Some(d) = stack.pop() {
        let mut rd = tokio::fs::read_dir(&d).await?;
        while let Some(e) = rd.next_entry().await? {
            let path = e.path();
            if e.file_type().await?.is_dir() {
                stack.push(path);
                continue;
            }
            let name = e.file_name().to_string_lossy().to_lowercase();
            let from = match name.as_str() {
                "bootmgfw.efi" | "bootx64.efi" => x.join("bootmgfw.efi"),
                "bootmgr.efi" => x.join("bootmgr.efi"),
                _ => continue,
            };
            if from.exists() {
                tokio::fs::copy(&from, &path).await?;
                replaced.push(path.strip_prefix(tree).unwrap_or(&path).display().to_string());
            }
        }
    }
    if x.join("boot.stl").exists() {
        tokio::fs::create_dir_all(tree.join("efi/microsoft/boot")).await?;
        tokio::fs::copy(x.join("boot.stl"), tree.join("efi/microsoft/boot/boot.stl")).await?;
        replaced.push("efi/microsoft/boot/boot.stl".into());
    }
    let _ = tokio::fs::remove_dir_all(&x).await;
    Ok(replaced)
}

/// The servicing stack out of a cumulative update's .msu (since 24H2 a WIM - MSWIM header -
/// which wimlib opens and WinPE's expand.exe cannot) into `dest`. Returns its file name.
pub(crate) async fn extract_ssu(log: &JobLog, msu: &Path, dest: &Path) -> Result<Option<String>> {
    let listing = run(log, "wimlib-imagex", &["dir", &msu.display().to_string(), "1"]).await.unwrap_or_default();
    let Some(path) = listing.lines().map(str::trim).find(|l| l.trim_start_matches('/').to_uppercase().starts_with("SSU-") && l.to_lowercase().ends_with(".cab")) else {
        return Ok(None);
    };
    run(log, "wimlib-imagex", &["extract", &msu.display().to_string(), "1", path, &format!("--dest-dir={}", dest.display()), "--no-acls"]).await?;
    Ok(Some(path.trim_start_matches('/').to_owned()))
}

/// A step's log file name: the update's file name without its extension, per image.
fn log_name(at: &str, file: &str) -> String {
    let stem = file.rsplit_once('.').map_or(file, |(s, _)| s);
    format!("{}-{stem}", if at == "winre" || at.starts_with("boot") { at.to_owned() } else { format!("image{at}") })
}

/// The worker's script: the install image's updates one at a time (each with its verdict),
/// the package list of every image for the studio to check, the Safe OS update into WinRE,
/// and DISM's own log back to the studio whatever happened.
fn worker_cmd(url: &str, pin: &str, indexes: usize, chain: &[String], image: &[String], winre: &[String], ssu: Option<&str>, extra: &Extras) -> String {
    let mut s = worker_head("media worker: install.wim + updates -> serviced install.wim", url, pin);
    s += &worker_cmd_body(indexes, chain, image, winre, ssu, extra);
    s
}

/// What the worker does beyond the updates: Microsoft Edge and the inbox apps into each
/// install image (a Windows 11 set carries both outside its edition ESD), and boot.wim
/// brought to the cumulative update.
#[derive(Default, Clone, Serialize, Deserialize)]
pub(crate) struct Extras {
    /// Edge.wim, sent to the worker: /Add-Edge into each image.
    pub edge: bool,
    /// The frameworks (relative to apps\), provisioned first.
    pub frameworks: Vec<String>,
    /// Per image: its apps. Empty: no apps.wim.
    pub apps: Vec<Vec<crate::apps::App>>,
    /// The cumulative update chain for boot.wim (as `image` names them), empty: boot.wim
    /// is not serviced.
    pub boot: Vec<String>,
}

/// A provisioning step (Edge, a framework, an app): its own markers - one line per app is
/// detail, summed up per image by the build - and its own DISM log.
fn prov_step(s: &mut String, at: &str, name: &str, log: &str, dism: &str) {
    s.push_str(&format!("{dism} /LogPath:W:\\logs\\{log}.log /LogLevel:2 > nul 2>&1\r\nset RC=!errorlevel!\r\nif \"!RC!\"==\"3010\" set RC=0\r\n"));
    s.push_str(&format!(
        "if \"!RC!\"==\"0\" (echo PVS-PROV-OK {at} {name} > COM1) else (echo PVS-PROV-FAIL {at} {name} !RC! > COM1)\r\n%C% -T W:\\logs\\{log}.log %U%/logs/{log}.log > nul 2>&1\r\n"
    ));
}

/// Every worker script starts alike: COM1, the network, curl off the seed, the studio
/// reached, the scratch disk W: with its folders.
fn worker_head(what: &str, url: &str, pin: &str) -> String {
    let mut s = String::new();
    s += &format!("@echo off\r\nrem PVE VM Studio {what}.\r\n");
    s += "setlocal enabledelayedexpansion\r\nset ERR=0\r\necho PVS-WORKER-START > COM1\r\n";
    // NetKVM first, when WinPE carries it (the worker's NIC is virtio then).
    s += "for %%v in (2k25 w11) do if exist X:\\pvs\\drivers\\netkvm\\%%v\\amd64\\netkvm.inf (drvload X:\\pvs\\drivers\\netkvm\\%%v\\amd64\\netkvm.inf > nul 2>&1 & goto :nic)\r\n:nic\r\nwpeutil InitializeNetwork > nul 2>&1\r\n";
    s += "copy /y %1\\pvs\\curl.exe X:\\curl.exe > nul || (echo PVS-NO-CURL > COM1 & goto :fail)\r\n";
    // -k because the certificate names the studio's DNS name, not its address - the pin is
    // what is checked: a server without the studio's key gets no byte.
    let pin = if pin.is_empty() { String::new() } else { format!(" -k --pinnedpubkey sha256//{pin}") };
    s += &format!("set C=X:\\curl.exe -sS -f --retry 5 --retry-delay 3 --retry-all-errors{pin}\r\nset U={url}\r\nset /a n=0\r\n");
    s += ":net\r\n%C% -o X:\\ping.txt %U%/ping > nul 2>&1 && goto :online\r\nset /a n+=1\r\nif !n! lss 40 (ping -n 4 127.0.0.1 > nul & goto :net)\r\n";
    s += "echo PVS-NO-STUDIO > COM1\r\n%C% -o X:\\ping.txt %U%/ping > COM1 2>&1\r\ngoto :fail\r\n:online\r\necho PVS-ONLINE > COM1\r\n";
    // The scratch disk: the SATA disk without a volume (the seed disk is SATA too, with FAT).
    s += "set OSDISK=\r\nfor /l %%n in (0,1,7) do (\r\n  (echo select disk %%n& echo detail disk) > X:\\dd.txt\r\n  diskpart /s X:\\dd.txt > X:\\dd%%n.txt 2>&1\r\n";
    s += "  for /f \"usebackq tokens=1,2 delims=: \" %%a in (\"X:\\dd%%n.txt\") do (\r\n    if /i \"%%a\"==\"Type\" set T%%n=%%b\r\n    if /i \"%%a\"==\"Volume\" if not \"%%b\"==\"###\" set V%%n=1\r\n  )\r\n)\r\n";
    s += "for /l %%n in (0,1,7) do if not defined OSDISK if /i \"!T%%n!\"==\"SATA\" if not defined V%%n set OSDISK=%%n\r\n";
    s += "if not defined OSDISK (echo PVS-NO-SCRATCH-DISK > COM1 & goto :fail)\r\n";
    s += "(\r\necho select disk %OSDISK%\r\necho online disk noerr\r\necho attributes disk clear readonly noerr\r\necho clean\r\necho convert gpt\r\necho create partition primary\r\necho format quick fs=ntfs label=Scratch\r\necho assign letter=W\r\n) > X:\\dp.txt\r\n";
    s += "diskpart /s X:\\dp.txt > nul 2>&1\r\nif not exist W:\\ (echo PVS-SCRATCH-FAILED > COM1 & goto :fail)\r\nmkdir W:\\mount W:\\scratch W:\\upd W:\\logs\r\n";
    s
}

/// The end of every worker script: DISM's own log back to the studio, and the failure exit.
fn worker_tail() -> String {
    // DISM's own log - the why behind any error code - goes back in every case.
    let mut s = String::from(":log\r\n%C% -T X:\\Windows\\Logs\\DISM\\dism.log %U%/dism.log > nul 2>&1\r\nexit /b 0\r\n");
    s += ":fail\r\ncall :log\r\necho PVS-WORKER-FAILED > COM1\r\n";
    s
}

/// The worker's operations in the order its script runs them (worker_cmd_body), each keyed
/// by the marker that starts it (windows::unit_key) and weighted in seconds as the workers
/// of 2026-10-05..07 took them on a 2-core worker: a cumulative update 6-17 min, a scan
/// 1-2, the cleanup 1-1.5, saving an image 2-5, an inbox app seconds.
fn worker_units(indexes: usize, image: &[String], winre: &[String], ssu: Option<&str>, extra: &Extras) -> Vec<(String, f64)> {
    let weight = |file: &str| {
        let f = file.to_lowercase();
        if f.ends_with(".msu") { 500.0 } else if f.contains("-ndp") { 20.0 } else { 10.0 }
    };
    let is_net = |u: &&String| u.to_lowercase().contains("-ndp");
    let file = |u: &String| u.rsplit('/').next().unwrap_or(u).to_owned();
    let mut v: Vec<(String, f64)> = vec![("COPY-IN".into(), 60.0)];
    for i in 1..=indexes {
        v.push((format!("INDEX {i}"), 25.0));
        v.push((format!("HEALTH {i}-before"), 100.0));
        for u in image.iter().filter(|u| !is_net(u)) {
            v.push((format!("UPD {i} {}", file(u)), weight(&file(u))));
        }
        v.push((format!("HEALTH {i}-updated"), 120.0));
        v.push((format!("UPD {i} cleanup"), 75.0));
        let net: Vec<&String> = image.iter().filter(is_net).collect();
        if !net.is_empty() {
            v.push((format!("HEALTH {i}-cleaned"), 120.0));
        }
        for u in net {
            v.push((format!("UPD {i} {}", file(u)), weight(&file(u))));
        }
        if extra.edge {
            v.push((format!("EDGE {i}"), 10.0));
        }
        // An app's verdict starts the next one; the first starts with APPS.
        let apps = extra.apps.get(i - 1).filter(|a| !a.is_empty());
        if let Some(apps) = apps {
            let items: Vec<String> = extra.frameworks.iter().map(|f| format!("fw:{}", f.rsplit('\\').next().unwrap_or(f))).chain(apps.iter().map(|a| a.id.clone())).collect();
            v.push((format!("APPS {i} {}", apps.len()), 6.0));
            for it in items.iter().take(items.len().saturating_sub(1)) {
                v.push((format!("PROV {i} {it}"), 6.0));
            }
        }
        v.push((format!("HEALTH {i}"), 120.0));
        // Saving: 2-5 min, about 11 with the inbox apps in (26H2 26300.9457, 2026-10-07).
        v.push((format!("COMMIT {i}"), if apps.is_some() { 650.0 } else { 240.0 }));
    }
    if !winre.is_empty() {
        v.push(("WINRE".into(), 20.0));
        if let Some(f) = ssu {
            v.push((format!("UPD winre {f}"), 10.0));
        }
        for u in winre {
            v.push((format!("UPD winre {u}"), 20.0));
        }
        // The cleanup, then saving and exporting WinRE: no marker of their own.
        v.push(("UPD winre cleanup".into(), 60.0));
    }
    if !extra.boot.is_empty() {
        for b in 1..=2 {
            v.push((format!("BOOT {b}"), 300.0));
        }
    }
    v.push(("EXPORT".into(), 30.0 * indexes as f64));
    v.push(("COPY-OUT".into(), 70.0));
    v
}

fn worker_cmd_body(indexes: usize, chain: &[String], image: &[String], winre: &[String], ssu: Option<&str>, extra: &Extras) -> String {
    let mut s = String::new();
    s += "echo PVS-COPY-IN > COM1\r\n%C% -o W:\\install.wim %U%/install.wim > COM1 2>&1 || goto :fail\r\n";
    if !winre.is_empty() {
        s += "%C% -o W:\\winre.wim %U%/winre.wim > COM1 2>&1 || goto :fail\r\n";
    }
    if !extra.boot.is_empty() {
        s += "%C% -o W:\\boot.wim %U%/boot.wim > COM1 2>&1 || goto :fail\r\n";
    }
    if extra.edge {
        s += "mkdir W:\\edge\r\n%C% -o W:\\edge\\Edge.wim %U%/Edge.wim > COM1 2>&1 || goto :fail\r\n";
    }
    // The apps as one WIM (a bundle's packages, stubs and licence laid out as DISM wants
    // them - 2,800 files would be 2,800 requests), applied to W:\apps.
    if extra.apps.iter().any(|a| !a.is_empty()) {
        s += "%C% -o W:\\apps.wim %U%/apps.wim > COM1 2>&1 || goto :fail\r\nmkdir W:\\apps\r\n";
        s += "dism /English /Apply-Image /ImageFile:W:\\apps.wim /Index:1 /ApplyDir:W:\\apps /ScratchDir:W:\\scratch > COM1 2>&1 || goto :fail\r\ndel W:\\apps.wim\r\n";
    }
    let files: Vec<String> = chain.iter().map(|c| format!("lcu/{c}")).chain(image.iter().filter(|u| !u.starts_with("lcu/")).cloned()).chain(winre.iter().cloned()).chain(ssu.filter(|_| !winre.is_empty()).map(str::to_owned)).collect();
    // Every folder an update sits in (lcu/ for the one-call chain, lcu1/, lcu2/ ... for a chain
    // applied one update at a time) exists before curl writes into it.
    let mut dirs: Vec<&str> = files.iter().filter_map(|u| u.rsplit_once('/').map(|(d, _)| d)).collect();
    dirs.dedup();
    for d in dirs {
        s += &format!("mkdir W:\\upd\\{}\r\n", d.replace('/', "\\"));
    }
    for u in &files {
        let local = u.replace('/', "\\");
        s += &format!("%C% -o W:\\upd\\{local} %U%/upd/{u} > COM1 2>&1 || goto :fail\r\n");
    }
    s += &format!("for /l %%i in (1,1,{indexes}) do call :service %%i || goto :fail\r\n");
    if !winre.is_empty() {
        s += "call :winre || goto :fail\r\n";
    }
    // boot.wim is not worth the install images: a failure there leaves the studio's own
    // boot.wim (from the serviced WinRE) in place, the rest goes on.
    if !extra.boot.is_empty() {
        s += "call :boot\r\n";
    }
    s += "echo PVS-EXPORT > COM1\r\n";
    s += &format!(
        "for /l %%i in (1,1,{indexes}) do dism /English /Export-Image /SourceImageFile:W:\\install.wim /SourceIndex:%%i /DestinationImageFile:W:\\serviced.wim /Compress:max /ScratchDir:W:\\scratch > COM1 2>&1 || goto :fail\r\n"
    );
    s += "echo PVS-COPY-OUT > COM1\r\n%C% -T W:\\serviced.wim %U%/serviced.wim > COM1 2>&1 || goto :fail\r\n";
    s += "call :log\r\necho PVS-WORKER-OK > COM1\r\ngoto :eof\r\n";

    // One image: its updates in order, the component store cleaned, its package list.
    s += ":service\r\necho PVS-INDEX %1 > COM1\r\n";
    s += "dism /English /Mount-Image /ImageFile:W:\\install.wim /Index:%1 /MountDir:W:\\mount /ScratchDir:W:\\scratch > COM1 2>&1 || exit /b 1\r\n";
    // The image as it came, before any update: a store damaged here was put together wrong;
    // one that is only damaged after was damaged by an update. Reported, never fatal.
    s += &health_check("%1-before");
    // .NET after the cleanup (Microsoft's media steps: a .NET update leaves operations
    // pending that the cleanup would fail on); the rest - the enablement package first, then
    // the cumulative chain, as the build ordered them - before it.
    let is_net = |u: &&String| u.to_lowercase().contains("-ndp");
    for u in image.iter().filter(|u| !is_net(u)) {
        // lcu/<target>: the cumulative update chain sits in its own folder, the target named
        // alone - DISM takes the checkpoints in that folder first (Microsoft's checkpoint
        // procedure; naming the checkpoint itself fails with 0x80070228).
        let (file, local) = (u.rsplit('/').next().unwrap_or(u), u.replace('/', "\\"));
        dism_step(&mut s, &format!("%1 {file}"), &log_name("%1", file), &format!("dism /English /Image:W:\\mount /Add-Package /PackagePath:W:\\upd\\{local} /ScratchDir:W:\\scratch"));
    }
    // Microsoft's procedure cleans the install image without /ResetBase (the updates stay
    // removable), and only a pending operation (0x800F0806) is a warning, not a failure.
    // Scanned after each stage (a minute or two each), so a damaged store names the stage
    // that damaged it: the updates, the cleanup, or .NET.
    s += &health_check("%1-updated");
    dism_step(&mut s, "%1 cleanup", "image%1-cleanup", "dism /English /Image:W:\\mount /Cleanup-Image /StartComponentCleanup /ScratchDir:W:\\scratch");
    let net: Vec<&String> = image.iter().filter(is_net).collect();
    if !net.is_empty() {
        s += &health_check("%1-cleaned");
    }
    for u in net {
        let (file, local) = (u.rsplit('/').next().unwrap_or(u), u.replace('/', "\\"));
        dism_step(&mut s, &format!("%1 {file}"), &log_name("%1", file), &format!("dism /English /Image:W:\\mount /Add-Package /PackagePath:W:\\upd\\{local} /ScratchDir:W:\\scratch"));
    }
    // Edge and the inbox apps after the updates (Microsoft's OEM order: "add major updates
    // before apps... if you add an update later, you'll need to re-add the apps").
    if extra.edge {
        s += "echo PVS-EDGE %1 > COM1\r\n";
        prov_step(&mut s, "%1", "edge", "image%1-edge", "dism /English /Image:W:\\mount /Add-Edge /SupportPath:W:\\edge /ScratchDir:W:\\scratch");
    }
    if extra.apps.iter().any(|a| !a.is_empty()) {
        s += "call :apps%1\r\n";
    }
    // Windows' own verdict on the image as it ships. Not WinRE: DISM refuses /ScanHealth on
    // a Windows PE image (error 50).
    s += &health_check("%1");
    s += "dism /English /Image:W:\\mount /Get-Packages /Format:Table > W:\\packages-%1.txt 2>&1\r\n%C% -T W:\\packages-%1.txt %U%/packages-%1.txt > nul 2>&1\r\n";
    s += "echo PVS-COMMIT %1 > COM1\r\ndism /English /Unmount-Image /MountDir:W:\\mount /Commit /ScratchDir:W:\\scratch > COM1 2>&1 || exit /b 1\r\nexit /b 0\r\n";

    // WinRE: the Safe OS dynamic update, then back to the studio as winre-serviced.wim.
    if !winre.is_empty() {
        s += ":winre\r\necho PVS-WINRE > COM1\r\n";
        s += "dism /English /Mount-Image /ImageFile:W:\\winre.wim /Index:1 /MountDir:W:\\mount /ScratchDir:W:\\scratch > COM1 2>&1 || exit /b 1\r\n";
        // WinRE takes the servicing stack first (Microsoft: SSU, then the Safe OS update). Since
        // 24H2 it ships inside the cumulative update's .msu - a WIM, which the studio opened.
        if let Some(f) = ssu {
            dism_step(&mut s, &format!("winre {f}"), "winre-ssu", &format!("dism /English /Image:W:\\mount /Add-Package /PackagePath:W:\\upd\\{f} /ScratchDir:W:\\scratch"));
        }
        for u in winre {
            dism_step(&mut s, &format!("winre {u}"), &log_name("winre", u), &format!("dism /English /Image:W:\\mount /Add-Package /PackagePath:W:\\upd\\{u} /ScratchDir:W:\\scratch"));
        }
        // Microsoft: /ResetBase /Defer for WinRE - the long null-delta compression of the
        // boot-recovery components is left to the recovery image's own maintenance.
        dism_step(&mut s, "winre cleanup", "winre-cleanup", "dism /English /Image:W:\\mount /Cleanup-Image /StartComponentCleanup /ResetBase /Defer /ScratchDir:W:\\scratch");
        s += "dism /English /Unmount-Image /MountDir:W:\\mount /Commit /ScratchDir:W:\\scratch > COM1 2>&1 || exit /b 1\r\n";
        s += "dism /English /Export-Image /SourceImageFile:W:\\winre.wim /SourceIndex:1 /DestinationImageFile:W:\\winre-serviced.wim /Compress:max /Bootable /ScratchDir:W:\\scratch > COM1 2>&1 || exit /b 1\r\n";
        s += "%C% -T W:\\winre-serviced.wim %U%/winre-serviced.wim > COM1 2>&1 || exit /b 1\r\nexit /b 0\r\n";
    }

    // Each image's apps (an N edition ships fewer): the frameworks without a licence, then
    // every app with its own, for every region, a stubbed app in full (as uup-converter).
    for (i, apps) in extra.apps.iter().enumerate() {
        let n = i + 1;
        s += &format!(":apps{n}\r\necho PVS-APPS {n} {} > COM1\r\n", apps.len());
        if !apps.is_empty() {
            for f in &extra.frameworks {
                let name = f.rsplit('\\').next().unwrap_or(f);
                prov_step(&mut s, &n.to_string(), &format!("fw:{name}"), &format!("image{n}-fw-{name}"), &format!("dism /English /Image:W:\\mount /Add-ProvisionedAppxPackage /PackagePath:\"W:\\apps\\{f}\" /SkipLicense /ScratchDir:W:\\scratch"));
            }
        }
        for a in apps {
            let stub = if a.stub { " /StubPackageOption:InstallFull" } else { "" };
            prov_step(
                &mut s,
                &n.to_string(),
                &a.id,
                &format!("image{n}-app-{}", a.id),
                &format!("dism /English /Image:W:\\mount /Add-ProvisionedAppxPackage /PackagePath:\"W:\\apps\\{}\\{}\" /LicensePath:\"W:\\apps\\{}\\License.xml\" /Region:all{stub} /ScratchDir:W:\\scratch", a.id, a.main, a.id),
            );
        }
        s += "exit /b 0\r\n";
    }

    // boot.wim (WinPE and the Setup environment) to the cumulative update, as Microsoft's
    // media steps 17-25: the update chain into each index, then the cleanup with /ResetBase.
    // On 26052 and newer WinPE-Rejuv-Package goes first (uup-converter: the update does not
    // take it), then back as boot-serviced.wim.
    if !extra.boot.is_empty() {
        s += ":boot\r\nfor %%b in (1 2) do call :bootidx %%b || exit /b 1\r\n";
        s += "for %%b in (1 2) do dism /English /Export-Image /SourceImageFile:W:\\boot.wim /SourceIndex:%%b /DestinationImageFile:W:\\boot-serviced.wim /Compress:max /ScratchDir:W:\\scratch > COM1 2>&1 || exit /b 1\r\n";
        s += "%C% -T W:\\boot-serviced.wim %U%/boot-serviced.wim > COM1 2>&1 || exit /b 1\r\nexit /b 0\r\n";
        s += ":bootidx\r\necho PVS-BOOT %1 > COM1\r\n";
        s += "dism /English /Mount-Image /ImageFile:W:\\boot.wim /Index:%1 /MountDir:W:\\mount /ScratchDir:W:\\scratch > COM1 2>&1 || (echo PVS-UPD-FAIL boot%1 mount 1 > COM1 & dism /English /Unmount-Image /MountDir:W:\\mount /Discard > nul 2>&1 & exit /b 1)\r\n";
        s += "for /f \"tokens=4\" %%p in ('dism /English /Image:W:\\mount /Get-Packages ^| findstr /i \"WinPE-Rejuv-Package\"') do dism /English /Image:W:\\mount /Remove-Package /PackageName:%%p /ScratchDir:W:\\scratch > COM1 2>&1\r\n";
        for u in &extra.boot {
            let (file, local) = (u.rsplit('/').next().unwrap_or(u), u.replace('/', "\\"));
            dism_step(&mut s, &format!("boot%1 {file}"), &log_name("boot%1", file), &format!("dism /English /Image:W:\\mount /Add-Package /PackagePath:W:\\upd\\{local} /ScratchDir:W:\\scratch"));
        }
        dism_step(&mut s, "boot%1 cleanup", "boot%1-cleanup", "dism /English /Image:W:\\mount /Cleanup-Image /StartComponentCleanup /ResetBase /ScratchDir:W:\\scratch");
        s += "dism /English /Unmount-Image /MountDir:W:\\mount /Commit /ScratchDir:W:\\scratch > COM1 2>&1 || exit /b 1\r\nexit /b 0\r\n";
    }
    s += &worker_tail();
    s
}



/// A worker VM's run: what it boots, what it is served, how long it may take.
pub(crate) struct WorkerSpec<'a> {
    /// Its id; the worker's side door serves `share` under it while it runs.
    pub run_id: &'a str,
    pub share: &'a Path,
    /// The WinPE it boots.
    pub pe: &'a winpe::WinPe,
    /// curl.exe for its seed disk (from a Windows image of the same family).
    pub curl: &'a [u8],
    pub scratch_gb: u64,
    pub minutes: u64,
    /// For the VM's description: "media worker for Windows Server 2025 26100.33438".
    pub what: String,
    /// Its operations in order, weighted (windows::run_pass); empty: no step percentage.
    pub units: Vec<(String, f64)>,
}

/// Runs one worker VM: boots the WinPE with a seed disk carrying `script(url, pin)` and
/// curl, serves `share` to it over the studio's own HTTPS port until it is done, and
/// removes the VM whatever happened. Returns the markers it wrote to COM1.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_worker(
    pve: &Pve,
    db: &SqlitePool,
    log: &JobLog,
    pr: &mut Progress,
    work: &Path,
    p: &Placement,
    link: &Link,
    w: WorkerSpec<'_>,
    script: impl FnOnce(&str, &str) -> String,
) -> Result<Vec<String>> {
    let ip = studio_ip()?;
    let short = w.run_id.trim_start_matches("run-").chars().take(8).collect::<String>();
    let seed_name = format!("pvs-seed-worker-{short}");
    let token: String = uuid::Uuid::new_v4().simple().to_string() + &uuid::Uuid::new_v4().simple().to_string();
    let url = format!("{}/worker/{}/{token}", link.base.replace("{ip}", &ip), w.run_id);
    tokio::fs::write(w.share.join("ping"), "ok").await?;
    RUNS.lock().unwrap().insert(w.run_id.to_owned(), (token.clone(), w.share.to_path_buf()));
    let mut vm: Option<u32> = None;
    let result = async {
        let cmd = script(&url, &link.pin);
        let seed_disk = SeedDisk::build_bytes(work, &seed_name, "PVSSEED", &[("pvs/pe.cmd", cmd.as_bytes()), ("pvs/curl.exe", w.curl)]).await?;
        log.ok(format!("Worker fetches from the studio at {} over {}", link.base.replace("{ip}", &ip), if link.pin.is_empty() { "HTTP" } else { "HTTPS, the studio's key pinned" })).await;
        let size: WorkerSettings = settings::load(db, "worker").await?;
        golds::check_node_memory(pve, log, &p.node, size.memory_mb).await?;
        pve.ensure_pool(GOLD_POOL, "PVE VM Studio: golds (templates) and the bakes that make them").await?;
        let guard = pve.vmid_guard().await;
        let vmid = pve.free_vmid_in(GOLD_IDS).await?;
        // virtio with the NetKVM driver WinPE carries; e1000 for a WinPE without it.
        let mut net0 = format!("{},bridge={}", if w.pe.netkvm.is_empty() { "e1000" } else { "virtio" }, p.bridge);
        if let Some(v) = p.vlan {
            net0 += &format!(",tag={v}");
        }
        let vm_name = format!("worker-{short}");
        log.line(format!(
            "Creating worker VM {vmid} ({vm_name}): WinPE {}, {} GB memory, {} cores, {} GB scratch disk on {}",
            w.pe.build,
            size.memory_mb / 1024,
            size.cores,
            w.scratch_gb,
            p.disk_storage
        ))
        .await;
        let create = form![
            ("vmid", vmid),
            ("name", &vm_name),
            ("pool", GOLD_POOL),
            ("ostype", "win11"),
            ("machine", "q35"),
            ("bios", "ovmf"),
            ("cpu", &p.cpu_windows),
            ("cores", size.cores),
            ("memory", size.memory_mb),
            ("efidisk0", format!("{}:1,efitype=4m,pre-enrolled-keys=1", p.disk_storage)),
            ("sata0", format!("{},media=cdrom", w.pe.volid)),
            ("sata1", format!("{}:{},discard=on,ssd=1", p.disk_storage, w.scratch_gb)),
            ("serial0", "socket"),
            ("net0", net0),
            ("boot", "order=sata0"),
            ("tags", crate::tags::WORKER),
            ("description", format!("PVE VM Studio: {} - removed when it is done.", w.what)),
        ];
        let created = pve.run_task(&format!("/nodes/{}/qemu", enc(&p.node)), create, |_| {}).await;
        drop(guard);
        if pve.vm_status(&p.node, vmid).await.is_ok() {
            vm = Some(vmid);
        }
        created.context("creating the worker VM")?;
        seed::attach(pve, &p.node, vmid, "sata2", &p.disk_storage, seed_disk, &seed_name).await.context("attaching the worker's seed disk")?;
        windows::run_pass(pve, log, pr, &p.node, vmid, "worker", w.minutes, &w.units).await
    }
    .await;
    if let Some(vmid) = vm {
        match pve.vm_destroy(&p.node, vmid).await {
            Ok(()) => log.ok(format!("Worker VM {vmid} removed")).await,
            Err(e) => log.warn(format!("Worker VM {vmid} could not be removed: {e:#}")).await,
        }
    }
    RUNS.lock().unwrap().remove(w.run_id);
    result
}

/// The file in a run's work folder that says how far the run got.
pub const CHECKPOINT: &str = "checkpoint.json";

/// The stages after which a media build can be continued.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Stage {
    /// The image is put together and the worker's share is ready.
    Prepared,
    /// The worker is done (or none was needed): install.wim and the Setup tree are final.
    Serviced,
    /// The ISO is built in the work folder; only the upload is left.
    Iso,
}

/// What the first stage worked out, as the later ones need it.
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Prepared {
    pub editions: Vec<String>,
    pub applied: Vec<String>,
    pub worker: bool,
    pub extra: Extras,
    pub chain: Vec<String>,
    pub image: Vec<String>,
    pub winre: Vec<String>,
    pub ssu: Option<String>,
    pub scratch_gb: u64,
    pub edge: Option<PathBuf>,
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Checkpoint {
    pub stage: Stage,
    pub prep: Prepared,
    /// The ISO's size and SHA-256, once built.
    pub iso: Option<(u64, String)>,
}

impl Checkpoint {
    pub async fn load(dir: &Path) -> Option<Self> {
        serde_json::from_slice(&tokio::fs::read(dir.join(CHECKPOINT)).await.ok()?).ok()
    }
    async fn save(&self, dir: &Path) -> Result<()> {
        let tmp = dir.join(format!("{CHECKPOINT}.tmp"));
        tokio::fs::write(&tmp, serde_json::to_vec(self)?).await?;
        tokio::fs::rename(&tmp, dir.join(CHECKPOINT)).await?;
        Ok(())
    }
    /// What is done, in the words of the job's steps.
    pub fn done(&self) -> &'static str {
        match self.stage {
            Stage::Prepared => "the image is put together, the worker comes next",
            Stage::Serviced => "the images are serviced, the ISO comes next",
            Stage::Iso => "the ISO is built, the upload comes next",
        }
    }
}

/// Builds the ISO. Returns what the blade's history records.
pub async fn build(pve: &Pve, db: &SqlitePool, log: &JobLog, web: &reqwest::Client, work: &Path, p: &Placement, link: Link, req: Request) -> Result<MediaIso> {
    let prod = req.product;
    let mut pr = Progress::new(log, format!("Building {} {}", prod.name, req.build));
    let run_id = req.run.clone();
    let dir: PathBuf = work.join(format!("media-{run_id}"));
    // What the worker fetches and sends back, served by worker_router while it runs.
    let share = dir.join("worker");
    // The stages a continued build skips: what the interrupted run finished, written into its
    // work folder after each one (Jobs → Continue).
    let mut ck: Option<Checkpoint> = Checkpoint::load(&dir).await;

    let result: Result<MediaIso> = async {
        // Downloads go to a cache a failed build leaves behind: the next try keeps what is
        // already here (the work folder's cleanup removes it after six idle hours).
        // One cache per build: files of other builds (or of a FoD ISO) share names, not
        // content - Microsoft-Windows-Media-Features-Package-amd64.cab is a client's here and a
        // server's there.
        let dl = work.join("uup-files").join(&req.uuid);
        tokio::fs::create_dir_all(&dl).await?;
        let keep: bool = settings::load::<WorkerSettings>(db, "worker").await.unwrap_or_default().keep_downloads;
        // Half a first stage is not worth anything: without a checkpoint it starts clean (the
        // downloads it needs are still in the cache - the stage links them, it never moves them).
        if ck.is_none() {
            let _ = tokio::fs::remove_dir_all(&dir).await;
        }
        tokio::fs::create_dir_all(&dir).await?;
        let base: Vec<String> = req.editions.clone();
        if base.is_empty() {
            bail!("pick at least one edition");
        }
        let tree = dir.join("iso");
        let install = dir.join("install.wim");
        let install_s = install.display().to_string();
        let target_rev = req.build.rsplit('.').next().unwrap_or_default().to_owned();
        if let Some(c) = &ck {
            log.line(format!("Continuing the interrupted build: {} - kept in its work folder", c.done())).await;
        }

        if ck.is_none() {

        // ---- the files ----
        pr.stage(0.0, 2.0, "asking the catalog");
        log.get(format!("Asking the UUP dump catalog for {} {} ({}), {}: {}", prod.name, req.build, req.uuid, uup::lang_tag(&req.lang), base.join(", "))).await;
        let mut files: Vec<uup::File> = Vec::new();
        for ed in &base {
            for f in uup::files(web, &req.uuid, &req.lang, ed).await? {
                if wanted(prod.kind, &f, &base, &req.lang) && !files.iter().any(|x| x.name == f.name) {
                    files.push(f);
                }
            }
        }
        for ed in &base {
            if !files.iter().any(|f| is_metadata(&f.name, ed, &req.lang)) {
                bail!("the catalog lists no {ed} image in {} for this build", uup::lang_tag(&req.lang));
            }
        }
        // A client set's package CABs wait until an export asks for them.
        let mut deferred: Vec<uup::File> = files.iter().filter(|f| deferrable(prod.kind, &f.name)).cloned().collect();
        files.retain(|f| !deferrable(prod.kind, &f.name));
        let update_count = files.iter().filter(|f| is_update(&f.name)).count();
        let total: u64 = files.iter().map(|f| f.size).sum();
        log.ok(format!(
            "{} file(s), {:.2} GB: {} edition image(s), {update_count} update file(s){}",
            files.len(),
            total as f64 / 1e9,
            base.len(),
            if prod.kind == Kind::Client { ", the package ESDs the images are put together from" } else { "" }
        ))
        .await;
        if !deferred.is_empty() {
            log.debug(format!("{} package CAB(s), {:.2} GB, wait until an export needs them", deferred.len(), deferred.iter().map(|f| f.size).sum::<u64>() as f64 / 1e9)).await;
        }
        let free = statvfs_free(work)?;
        if free < total * 3 {
            bail!("the studio has {:.1} GB free in {}; this build needs about {:.1} GB while it runs", free as f64 / 1e9, work.display(), total as f64 * 3.0 / 1e9);
        }

        pr.stage(2.0, 35.0, "downloading from Microsoft");
        let (uuid, lang, eds) = (req.uuid.clone(), req.lang.clone(), base.clone());
        let refresh = || {
            let (uuid, lang, eds) = (uuid.clone(), lang.clone(), eds.clone());
            async move {
                let mut all = Vec::new();
                for e in &eds {
                    all.extend(uup::files(web, &uuid, &lang, e).await?);
                }
                Ok(all)
            }
        };
        uup::download_all(web, log, &mut pr, &mut files, &dl, &refresh).await?;

        // Where each update goes, from Microsoft's CompDB names.
        let info = match files.iter().find(|f| is_aggregated(&f.name)) {
            Some(f) => update_targets(&dl.join(&f.name)).await,
            None => UpdateInfo::default(),
        };
        let picks = pick_updates(&files, &info);
        let named = |t: Target| picks.iter().filter(|(_, x)| *x == t).map(|(f, _)| kb_of(&f.name).unwrap_or_else(|| f.name.clone())).collect::<Vec<_>>().join(", ");
        log.ok(format!(
            "Updates: install image {}; WinRE (Safe OS) {}; Setup {}",
            or_none(&named(Target::Image)),
            or_none(&named(Target::WinRe)),
            or_none(&named(Target::Setup))
        ))
        .await;
        let updates: Vec<uup::File> = picks.iter().filter(|(_, t)| *t == Target::Image).map(|(f, _)| f.clone()).collect();
        let winre_updates: Vec<uup::File> = picks.iter().filter(|(_, t)| *t == Target::WinRe).map(|(f, _)| f.clone()).collect();

        // ---- Linux: the media, boot.wim, install.wim ----
        pr.stage(35.0, 42.0, "putting the image together");
        let first_meta = files.iter().find(|f| is_metadata(&f.name, &base[0], &req.lang)).map(|f| dl.join(&f.name)).unwrap();
        let first_s = first_meta.display().to_string();
        log.run(format!("Putting the image together: Setup media, boot.wim, install.wim ({})", base.join(", "))).await;
        let cabs: Vec<PathBuf> = files.iter().filter(|f| f.name.to_lowercase().ends_with(".cab") && !is_update(&f.name) && !is_aggregated(&f.name)).map(|f| dl.join(&f.name)).collect();
        cabs_to_esd(log, &dir, &cabs).await?;

        let tree = dir.join("iso");
        log.line("Applying the Setup media (ESD image 1)").await;
        run(log, "wimlib-imagex", &["apply", &first_s, "1", &tree.display().to_string(), "--no-acls", "--no-attributes"]).await?;
        // The Setup dynamic update: its files into sources\ - before boot.wim takes Setup from there.
        for (f, _) in picks.iter().filter(|(_, t)| *t == Target::Setup) {
            let x = dir.join("setupdu");
            let _ = tokio::fs::remove_dir_all(&x).await;
            tokio::fs::create_dir_all(&x).await?;
            run(log, "cabextract", &["-q", "-d", &x.display().to_string(), &dl.join(&f.name).display().to_string()]).await?;
            let n = merge_ci(&x, &tree.join("sources"))?;
            let _ = tokio::fs::remove_dir_all(&x).await;
            log.ok(format!("Setup dynamic update {}: {n} file(s) into sources\\", kb_of(&f.name).unwrap_or_default())).await;
        }
        let winre = dir.join("winre.wim");
        let winre_s = winre.display().to_string();
        run(log, "wimlib-imagex", &["export", &first_s, "2", &winre_s, "--compress=maximum", "--boot"]).await?;

        log.line("Building boot.wim: WinPE and the Setup environment").await;
        let n = build_boot_wim(log, &tree, &winre).await?;
        log.ok(format!("boot.wim: WinPE and the Setup environment ({n} Setup files)")).await;

        // install.wim: one image per edition, put together from its ESD (and, for a client
        // set, the package ESDs it refers to), with WinRE inside as Setup puts it there.
        let install = dir.join("install.wim");
        let install_s = install.display().to_string();
        // Both spellings: Microsoft ships some packages as .ESD (UUP dump's converter globs
        // *.[eE][sS][dD] for the same reason).
        let refs = format!("--ref={}/*.[eE][sS][dD]", dl.display());
        let mut editions_out: Vec<String> = Vec::new();
        let mut base_rev = String::new();
        for (i, ed) in base.iter().enumerate() {
            let meta = files.iter().find(|f| is_metadata(&f.name, ed, &req.lang)).map(|f| dl.join(&f.name)).unwrap();
            let meta_s = meta.display().to_string();
            let info = run(log, "wimlib-imagex", &["info", &meta_s, "3"]).await?;
            let (edition_id, itype, img_name) = (kv(&info, "Edition ID:"), kv(&info, "Installation Type:"), kv(&info, "Name:"));
            let flag = if itype == "Server Core" && edition_id.starts_with("Server") { format!("{edition_id}Core") } else { edition_id.clone() };
            base_rev = kv(&info, "Service Pack Build:");
            let name = if flag.starts_with("Server") {
                format!("{} {flag}", prod.name.trim_end_matches(" vNext"))
            } else {
                format!("{} {flag}", if img_name.contains("Windows 11") || prod.id.starts_with("w11") { "Windows 11" } else { "Windows" })
            };
            log.line(format!("Exporting {name} into install.wim")).await;
            let mut args = vec!["export", meta_s.as_str(), "3", install_s.as_str(), name.as_str(), name.as_str(), "--compress=LZX"];
            if prod.kind == Kind::Client {
                args.push(refs.as_str());
            }
            if let Err(e) = run(log, "wimlib-imagex", &args).await {
                if deferred.is_empty() {
                    return Err(e);
                }
                // The image refers to a package that came as a CAB: fetch them all, once.
                log.warn(format!(
                    "The image needs packages that come as CABs - downloading the {} held back ({:.2} GB)",
                    deferred.len(),
                    deferred.iter().map(|f| f.size).sum::<u64>() as f64 / 1e9
                ))
                .await;
                if i == 0 {
                    let _ = tokio::fs::remove_file(&install).await;
                }
                uup::download_all(web, log, &mut pr, &mut deferred, &dl, &refresh).await?;
                let more: Vec<PathBuf> = deferred.iter().map(|f| dl.join(&f.name)).collect();
                cabs_to_esd(log, &dir, &more).await?;
                files.append(&mut deferred);
                run(log, "wimlib-imagex", &args).await?;
            }
            let idx = (i + 1).to_string();
            run(log, "wimlib-imagex", &["info", &install_s, &idx, "--image-property", &format!("FLAGS={flag}")]).await?;
            winpe_update_index(&install, i + 1, &format!("add '{winre_s}' /Windows/System32/Recovery/winre.wim\n")).await?;
            editions_out.push(flag);
        }
        if !deferred.is_empty() {
            log.ok(format!("No export needed the {} held-back package CAB(s) - not downloaded", deferred.len())).await;
        }
        log.ok(format!("install.wim: {} image(s) at build {}.{base_rev}; the catalog's build is {}", editions_out.len(), req.build.split('.').next().unwrap_or(""), req.build)).await;

        // ---- Windows 11: Edge and the inbox apps, which its edition ESD no longer carries ----
        let mut extra = Extras::default();
        let edge_file = files.iter().find(|f| f.name.eq_ignore_ascii_case("edge.wim")).map(|f| dl.join(&f.name)).filter(|p| p.exists());
        let mut apps_root: Option<(PathBuf, Vec<uup::File>)> = None;
        if prod.kind == Kind::Client {
            extra.edge = edge_file.is_some();
            if let Some(agg) = files.iter().find(|f| is_aggregated(&f.name)).map(|f| dl.join(&f.name)) {
                let tmp = dir.join("compdb");
                if let Some(app_xml) = crate::apps::compdb(log, &agg, &tmp, "DesktopTargetCompDB_App_Neutral").await? {
                    let mut eds = Vec::new();
                    for ed in &base {
                        eds.push(crate::apps::compdb(log, &agg, &tmp, &format!("DesktopTargetCompDB_{}_{}", ed.to_lowercase(), req.lang.to_lowercase())).await?);
                    }
                    log.get("Asking the UUP dump catalog for the inbox apps").await;
                    let catalog = uup::files(web, &req.uuid, "neutral", "app").await.context("asking the catalog for the inbox apps")?;
                    let plan = crate::apps::plan(&app_xml, &eds, &catalog)?;
                    for (i, apps) in plan.per_image.iter().enumerate() {
                        log.ok(format!("{}: {} inbox app(s) from its CompDB", editions_out.get(i).cloned().unwrap_or_default(), apps.len())).await;
                    }
                    if !plan.missing.is_empty() {
                        log.debug(format!("Listed, but not in this set: {}", plan.missing.join(", "))).await;
                    }
                    let mut want = plan.files.clone();
                    let uuid = req.uuid.clone();
                    uup::download_all(web, log, &mut pr, &mut want, &dl, || {
                        let uuid = uuid.clone();
                        async move { uup::files(web, &uuid, "neutral", "app").await }
                    })
                    .await?;
                    let root = dir.join("apps");
                    crate::apps::lay_out(&plan, &dl, &root).await?;
                    extra.frameworks = plan.frameworks.clone();
                    extra.apps = plan.per_image.clone();
                    apps_root = Some((root, want));
                }
            }
        }
        let has_apps = extra.apps.iter().any(|a| !a.is_empty());

        // ---- the worker: the cumulative update, which only DISM can apply ----
        let behind = base_rev.parse::<u64>().unwrap_or(0) < target_rev.parse::<u64>().unwrap_or(0);
        if behind && updates.is_empty() {
            bail!("the images are at revision {base_rev}, the build is {} - and the catalog lists no update to get there", req.build);
        }
        let worker = behind || extra.edge || has_apps;
        let applied: Vec<String> = if worker { updates.iter().chain(&winre_updates).map(|u| u.name.clone()).collect() } else { Vec::new() };
        // Linked, never moved, until the checkpoint below: a first stage cut off half-way
        // finds every download still in the cache.
        let keep_dl = true;
        let (chain_names, image_names, winre_names, ssu_name, scratch_gb) = if worker {
            let pe: winpe::WinPe = settings::load(db, "winpe").await?;
            if pe.volid.is_empty() {
                bail!("the worker boots the studio's WinPE - build it under Media first");
            }
            // curl.exe from the image itself (its DLLs are all in WinPE), for the seed disk.
            run(log, "wimlib-imagex", &["extract", &install_s, "1", "/Windows/System32/curl.exe", &format!("--dest-dir={}", dir.display()), "--no-acls"]).await
                .context("taking curl.exe out of the image for the worker")?;
            // The worker's input: the image, WinRE, the updates in the order they go in.
            tokio::fs::create_dir_all(share.join("upd")).await?;
            tokio::fs::create_dir_all(share.join("logs")).await?;
            move_file(&install, &share.join("install.wim")).await?;
            // The cumulative chain (checkpoints and the target .msu): one folder, the target
            // named; everything else one by one, in order.
            let in_chain = |u: &uup::File| u.name.to_lowercase().ends_with(".msu") && kb_of(&u.name).is_some_and(|k| info.cumulative.contains(&k));
            let chain: Vec<&uup::File> = updates.iter().filter(|u| in_chain(u)).collect();
            let target = chain.iter().max_by_key(|u| kb_of(&u.name).and_then(|k| k[2..].parse::<u64>().ok()).unwrap_or(0)).map(|u| u.name.clone());
            let mut chain_names = Vec::new();
            let mut image_names = Vec::new();
            // The rest first, the enablement package among them (uup-converter's order: it goes
            // in before the cumulative update); .NET the worker holds back until after the
            // cleanup.
            let single = if chain.len() <= 1 { chain.clone() } else { Vec::new() };
            for (i, u) in updates.iter().filter(|u| !in_chain(u)).chain(single).enumerate() {
                let n = format!("{:02}-{}", i + 1, u.name);
                take_file(&dl.join(&u.name), &share.join("upd").join(&n), keep_dl).await?;
                image_names.push(n);
            }
            if chain.len() > 1 && prod.kind == Kind::Client {
                // Windows 11: each update of the chain on its own, the checkpoint first
                // (Microsoft's second checkpoint procedure). Given the target alone, DISM left
                // the checkpoint Staged and the target's forward deltas found no base for the
                // client's own components - 72 corrupt files in 25H2 26200.9539 (2026-10-06),
                // the image healthy right before. Each .msu sits alone in its own folder.
                let mut ordered = chain.clone();
                ordered.sort_by_key(|u| kb_of(&u.name).and_then(|k| k[2..].parse::<u64>().ok()).unwrap_or(0));
                for (i, u) in ordered.iter().enumerate() {
                    let dir = format!("lcu{}", i + 1);
                    tokio::fs::create_dir_all(share.join("upd").join(&dir)).await?;
                    take_file(&dl.join(&u.name), &share.join("upd").join(&dir).join(&u.name), keep_dl).await?;
                    // Plain image updates for the worker: fetched as named and applied one by one
                    // (chain_names is the one-call chain's upd/lcu folder).
                    image_names.push(format!("{dir}/{}", u.name));
                }
                log.line(format!("Cumulative chain {} - one DISM call each, the checkpoint first",
                    ordered.iter().filter_map(|u| kb_of(&u.name)).collect::<Vec<_>>().join(" -> "))).await;
            } else if chain.len() > 1 {
                tokio::fs::create_dir_all(share.join("upd/lcu")).await?;
                for u in &chain {
                    take_file(&dl.join(&u.name), &share.join("upd/lcu").join(&u.name), keep_dl).await?;
                    chain_names.push(u.name.clone());
                }
                if let Some(t) = &target {
                    image_names.push(format!("lcu/{t}"));
                }
                log.line(format!("Cumulative chain {} - DISM gets {} alone, the checkpoint(s) beside it",
                    chain.iter().filter_map(|u| kb_of(&u.name)).collect::<Vec<_>>().join(" -> "),
                    target.as_deref().and_then(kb_of).unwrap_or_default())).await;
            }
            let mut winre_names = Vec::new();
            for (i, u) in winre_updates.iter().enumerate() {
                let n = format!("re{:02}-{}", i + 1, u.name);
                take_file(&dl.join(&u.name), &share.join("upd").join(&n), keep_dl).await?;
                winre_names.push(n);
            }
            if !winre_names.is_empty() {
                tokio::fs::copy(&winre, share.join("winre.wim")).await?;
            }
            if let Some(edge) = &edge_file {
                take_file(edge, &share.join("Edge.wim"), keep_dl).await?;
            }
            let mut apps_gb = 0.0;
            if let Some((root, want)) = &apps_root {
                run(log, "wimlib-imagex", &["capture", &root.display().to_string(), &share.join("apps.wim").display().to_string(), "Apps", "--compress=none", "--no-acls"]).await
                    .context("packing the inbox apps for the worker")?;
                let _ = tokio::fs::remove_dir_all(root).await;
                apps_gb = want.iter().map(|f| f.size).sum::<u64>() as f64 / 1e9;
            }
            // boot.wim to the cumulative update: the chain's .msu files, as the image gets them.
            // Off: a UUP set has no WinPE of its own - boot.wim is WinRE, and the cumulative
            // update finds no WinPE foundation in it ("Unable to resolve Package: @Foundation;
            // skipping ... CumulativeUpdate_KB5124010", 25H2 26200.9550, 2026-10-06): only its
            // servicing stack went in, DISM still said success. The Safe OS update is WinRE's
            // update, so boot.wim is built from the serviced WinRE instead.
            const BOOT_LCU: bool = false;
            if behind && BOOT_LCU {
                extra.boot = image_names.iter().filter(|n| n.to_lowercase().ends_with(".msu")).cloned().collect();
                if !extra.boot.is_empty() {
                    tokio::fs::copy(tree.join("sources/boot.wim"), share.join("boot.wim")).await?;
                }
            }
            let wim_gb = tokio::fs::metadata(share.join("install.wim")).await?.len() as f64 / 1e9;
            let upd_gb = updates.iter().chain(&winre_updates).map(|u| u.size).sum::<u64>() as f64 / 1e9;
            let scratch_gb = ((wim_gb * 4.0 + upd_gb * 2.0 + apps_gb * 3.0 + 20.0).ceil() as u64).max(60);

            // WinRE's servicing stack: SSU-*.cab out of the cumulative update's .msu - since 24H2
            // a WIM (MSWIM header), which wimlib opens and WinPE's expand.exe cannot.
            let mut ssu_name: Option<String> = None;
            if !winre_names.is_empty()
                // The servicing stack of the newest cumulative update - never a checkpoint's.
                && let Some(lcu) = image_names
                    .iter()
                    .filter(|n| n.to_lowercase().ends_with(".msu"))
                    .max_by_key(|n| kb_of(n).and_then(|k| k[2..].parse::<u64>().ok()).unwrap_or(0))
            {
                let msu = share.join("upd").join(lcu.replace('/', std::path::MAIN_SEPARATOR_STR));
                if let Some(name) = extract_ssu(log, &msu, &share.join("upd")).await? {
                    log.line(format!("WinRE's servicing stack: {name}, out of {}", lcu.rsplit('/').next().unwrap_or(lcu))).await;
                    ssu_name = Some(name);
                } else {
                    log.line("No servicing stack inside the cumulative update - WinRE gets the Safe OS update alone").await;
                }
            }
            (chain_names, image_names, winre_names, ssu_name, scratch_gb)
        } else {
            Default::default()
        };
        let prep = Prepared {
            editions: editions_out.clone(),
            applied: applied.clone(),
            worker,
            extra,
            chain: chain_names,
            image: image_names,
            winre: winre_names,
            ssu: ssu_name,
            scratch_gb,
            edge: edge_file.clone(),
        };
        let c = Checkpoint { stage: Stage::Prepared, prep, iso: None };
        c.save(&dir).await?;
        ck = Some(c);
        // The downloads the images are made of are done with now - unless they are kept for
        // the next build. The updates stay until the worker has them in (the share links them).
        if !keep {
            let mut gone: Vec<String> = files.iter().filter(|f| !f.name.eq_ignore_ascii_case("edge.wim")).map(|f| f.name.clone()).collect();
            if let Some((_, want)) = &apps_root {
                gone.extend(want.iter().map(|f| f.name.clone()));
            }
            for n in gone {
                let _ = tokio::fs::remove_file(dl.join(&n)).await;
                let _ = tokio::fs::remove_file(dl.join(&n).with_extension("esd")).await;
            }
        }
        }

        // ---- the worker: the cumulative update, which only DISM can apply ----
        let c = ck.clone().expect("a checkpoint after the first stage");
        let Prepared { editions: editions_out, applied, worker, extra, chain: chain_names, image: image_names, winre: winre_names, ssu: ssu_name, scratch_gb, edge: edge_file } = c.prep.clone();
        let has_apps = extra.apps.iter().any(|a| !a.is_empty());
        if c.stage == Stage::Prepared && worker {
            pr.stage(42.0, 90.0, "the worker applies the updates");
            let pe: winpe::WinPe = settings::load(db, "winpe").await?;
            if pe.volid.is_empty() {
                bail!("the worker boots the studio's WinPE - build it under Media first");
            }
            let curl = tokio::fs::read(dir.join("curl.exe")).await.context("reading curl.exe for the worker")?;
            // What an earlier worker of this run sent back is not this one's answer.
            for f in ["serviced.wim", "winre-serviced.wim", "boot-serviced.wim"] {
                let _ = tokio::fs::remove_file(share.join(f)).await;
            }
            if let Ok(mut rd) = tokio::fs::read_dir(&share).await {
                while let Ok(Some(e)) = rd.next_entry().await {
                    let n = e.file_name().to_string_lossy().into_owned();
                    if (n.starts_with("packages-") || n.starts_with("health-")) && n.ends_with(".txt") {
                        let _ = tokio::fs::remove_file(e.path()).await;
                    }
                }
            }
            let _ = tokio::fs::remove_dir_all(share.join("logs")).await;
            tokio::fs::create_dir_all(share.join("logs")).await?;
            let mut what = vec![format!("{} update(s)", applied.len())];
            if extra.edge {
                what.push("Microsoft Edge".into());
            }
            if has_apps {
                what.push(format!("{} inbox app(s)", extra.apps.iter().map(Vec::len).max().unwrap_or(0)));
            }
            log.run(format!("Worker: {} into {} image(s){} - a WinPE VM applies them with DISM", what.join(", "), base.len(), if extra.boot.is_empty() { "" } else { " and boot.wim" })).await;
            log.line("DISM: about 15-30 min per image, health scan included; about 20 more for the apps, 20 for boot.wim").await;
            let app_minutes: u64 = extra.apps.iter().map(|a| a.len() as u64).sum::<u64>() / 2 + if extra.edge { 5 * base.len() as u64 } else { 0 };
            let minutes = 60 + 60 * base.len() as u64 + if winre_names.is_empty() { 0 } else { 20 } + app_minutes + if extra.boot.is_empty() { 0 } else { 40 };
            let spec = WorkerSpec {
                run_id: &run_id,
                share: &share,
                pe: &pe,
                curl: &curl,
                scratch_gb,
                minutes,
                what: format!("media worker for {} {}", prod.name, req.build),
                units: worker_units(base.len(), &image_names, &winre_names, ssu_name.as_deref(), &extra),
            };
            let (n_base, chain_n, image_n, winre_n, ssu_n) = (base.len(), chain_names.clone(), image_names.clone(), winre_names.clone(), ssu_name.clone());
            let m = run_worker(pve, db, log, &mut pr, work, p, &link, spec, |url, pin| {
                worker_cmd(url, pin, n_base, &chain_n, &image_n, &winre_n, ssu_n.as_deref(), &extra)
            })
            .await?;
            report_dism_logs(log, work, &share, "media", &run_id).await?;
            if !m.iter().any(|l| l == "PVS-WORKER-OK") {
                bail!("the worker failed: {}", m.iter().rev().find(|l| l.contains("FAIL") || l.starts_with("PVS-NO")).or(m.last()).map(|l| crate::markers::text(l)).unwrap_or_else(|| "nothing on its serial console".into()));
            }
            // Every update's verdict, as the worker reported it.
            let mut failed = Vec::new();
            let mut winre_ok = !winre_names.is_empty();
            let mut boot_ok = !extra.boot.is_empty();
            // Per image: (apps provisioned, apps failed), Edge in or not.
            let mut prov: HashMap<String, (usize, Vec<String>)> = HashMap::new();
            let mut edge_in: HashMap<String, bool> = HashMap::new();
            for l in &m {
                let parts: Vec<&str> = l.split_whitespace().collect();
                match parts.as_slice() {
                    ["PVS-PROV-OK", at, "edge"] => {
                        edge_in.insert(at.to_string(), true);
                    }
                    ["PVS-PROV-FAIL", at, "edge", code] => {
                        edge_in.insert(at.to_string(), false);
                        log.warn(format!("Microsoft Edge into {}: DISM failed with {}", where_label(at), dism_code(code))).await;
                    }
                    ["PVS-PROV-OK", at, name] if !name.starts_with("fw:") => prov.entry(at.to_string()).or_default().0 += 1,
                    ["PVS-PROV-OK", ..] => {}
                    ["PVS-PROV-FAIL", at, name, code] => {
                        let code = dism_code(code);
                        log.warn(format!("{} into {}: DISM failed with {code}", name.trim_start_matches("fw:"), where_label(at))).await;
                        prov.entry(at.to_string()).or_default().1.push(name.trim_start_matches("fw:").to_owned());
                    }
                    ["PVS-UPD-FAIL", at, name, code] if at.starts_with("boot") => {
                        log.warn(format!("{} into {}: DISM failed with {}", update_label(name), where_label(at), dism_code(code))).await;
                        boot_ok = false;
                    }
                    ["PVS-UPD-OK", at, "cleanup"] => log.ok(format!("Component store of {} cleaned up", where_label(at))).await,
                    ["PVS-UPD-FAIL", at, "cleanup", code] => {
                        let code = dism_code(code);
                        if *at == "winre" {
                            log.warn(format!("Cleaning up {} failed with {code}", where_label(at))).await;
                            winre_ok = false;
                        } else if code.contains("800F0806") {
                            // CBS_E_PENDING: Microsoft's procedure takes it as a warning - the
                            // image is fine, only larger until it boots once.
                            log.warn(format!("Cleanup of {} skipped - an operation is pending until the image boots ({code})", where_label(at))).await;
                        } else {
                            log.warn(format!("Cleaning up {} failed with {code}", where_label(at))).await;
                            failed.push(format!("component cleanup ({code})"));
                        }
                    }
                    ["PVS-UPD-OK", at, name] => log.ok(format!("{} into {}: installed", update_label(name), where_label(at))).await,
                    ["PVS-UPD-FAIL", at, name, code] => {
                        let code = dism_code(code);
                        log.warn(format!("{} into {}: DISM failed with {code}", update_label(name), where_label(at))).await;
                        if *at == "winre" {
                            winre_ok = false;
                        } else {
                            failed.push(format!("{} ({code})", update_label(name)));
                        }
                    }
                    _ => {}
                }
            }
            // Edge and the apps per image: what went in, what did not (a warning - the image
            // still installs; the job names each one).
            for i in 1..=editions_out.len() {
                let at = i.to_string();
                let want = extra.apps.get(i - 1).map(Vec::len).unwrap_or(0);
                let (ok, bad) = prov.get(&at).cloned().unwrap_or_default();
                let mut parts = Vec::new();
                match edge_in.get(&at) {
                    Some(true) => parts.push("Microsoft Edge added".to_owned()),
                    Some(false) => parts.push("Microsoft Edge NOT added".to_owned()),
                    None if extra.edge => parts.push("Microsoft Edge not reported".to_owned()),
                    None => {}
                }
                if want > 0 {
                    parts.push(format!("{ok} of {want} inbox app(s) provisioned"));
                }
                if parts.is_empty() {
                    continue;
                }
                let line = format!("Image {i}: {}", parts.join(", "));
                if bad.is_empty() && ok == want && edge_in.get(&at).copied().unwrap_or(!extra.edge) {
                    log.ok(line).await;
                } else {
                    log.warn(format!("{line}{}", if bad.is_empty() { String::new() } else { format!(" - not: {}", bad.join(", ")) })).await;
                }
            }
            // The package lists: nothing half-installed in any image.
            for i in 1..=editions_out.len() {
                let Ok(raw) = tokio::fs::read(share.join(format!("packages-{i}.txt"))).await else {
                    bail!("the worker sent no package list for image {i}");
                };
                let report = package_report(&String::from_utf8_lossy(&raw));
                log.ok(format!("Image {i}: {}", report.summary)).await;
                if !report.broken.is_empty() {
                    bail!("image {i} has package(s) not fully installed: {}", report.broken.join(", "));
                }
            }
            if !failed.is_empty() {
                bail!("update(s) failed in the install image: {} - DISM's log is kept under dism-logs", failed.join(", "));
            }
            // Health: Windows' own scan of every image's component store (not WinRE's - DISM
            // refuses it on a Windows PE image, error 50).
            for i in 1..=editions_out.len() {
                let read = |n: String| async move { tokio::fs::read(n).await.map(|b| String::from_utf8_lossy(&b).into_owned()).unwrap_or_default() };
                // Before the updates: Some(verdict), or None when no answer came back - unknown,
                // never counted as damaged.
                let raw = read(share.join(format!("health-{i}-before.txt")).display().to_string()).await;
                let before = (!raw.trim().is_empty()).then(|| health_verdict(&raw));
                match &before {
                    Some(Ok(_)) => log.ok(format!("Image {i} before the updates: healthy (DISM /ScanHealth)")).await,
                    Some(Err(why)) => log.warn(format!("Image {i} before the updates: {why} - it was put together damaged (DISM /ScanHealth)")).await,
                    None => log.warn(format!("Image {i} before the updates: no scan result came back")).await,
                }
                // After each stage: which one damaged the store, if one did.
                for (stage, what) in [("updated", "after the updates"), ("cleaned", "after the cleanup")] {
                    let raw = read(share.join(format!("health-{i}-{stage}.txt")).display().to_string()).await;
                    if raw.trim().is_empty() {
                        continue;
                    }
                    match health_verdict(&raw) {
                        Ok(_) => log.ok(format!("Image {i} {what}: healthy (DISM /ScanHealth)")).await,
                        Err(why) => log.warn(format!("Image {i} {what}: {why}{}", reverse_note(&read(share.join(format!("logs/health-{i}-{stage}.log")).display().to_string()).await))).await,
                    }
                }
                match health_verdict(&read(share.join(format!("health-{i}.txt")).display().to_string()).await) {
                    Ok(v) => log.ok(format!("Image {i} is healthy: {v} (DISM /ScanHealth)")).await,
                    Err(why) => {
                        let cbs = read(share.join(format!("logs/health-{i}.log")).display().to_string()).await;
                        if let Some(n) = reverse_delta_only(&cbs) {
                            // Microsoft's scan error, not damage: the image ships, the job says so.
                            log.warn(format!("Image {i}: /ScanHealth flags {n} reverse-delta file(s) (WinSxS \\r\\) and nothing else - the known scan error of the 2026 cumulative updates, not damage")).await;
                        } else {
                            bail!(
                                "image {i} is not healthy: {why} - DISM /ScanHealth; {}",
                                match &before {
                                    Some(Ok(_)) => "it was healthy before the updates, so an update damaged it",
                                    Some(Err(_)) => "it was already damaged before the updates",
                                    None => "whether it was damaged before the updates is not known",
                                }
                            );
                        }
                    }
                }
            }
            move_file(&share.join("serviced.wim"), &install).await.context("reading the serviced image the worker sent back")?;
            // The proof: every image now reports the catalog's build.
            for i in 1..=editions_out.len() {
                let info = run(log, "wimlib-imagex", &["info", &install_s, &i.to_string()]).await?;
                let rev = kv(&info, "Service Pack Build:");
                if rev != target_rev {
                    bail!("image {i} is at revision {rev} after the worker, not {target_rev} - the cumulative update did not go in");
                }
            }
            // The serviced WinRE replaces the one each image carries.
            let serviced_re = share.join("winre-serviced.wim");
            if winre_ok && serviced_re.exists() {
                let re_s = serviced_re.display().to_string();
                for i in 1..=editions_out.len() {
                    winpe_update_index(&install, i, &format!("add '{re_s}' /Windows/System32/Recovery/winre.wim\n")).await?;
                }
                log.ok("WinRE in every image carries the Safe OS update").await;
            } else if !winre_names.is_empty() {
                log.warn("WinRE keeps its base build - the Safe OS update did not go in").await;
            }
            // boot.wim: the worker's, with the cumulative update in WinPE and Setup (Microsoft's
            // steps 17-25). Without it, built again from the serviced WinRE as before - Setup
            // still boots a patched build. Either way the boot manager comes from it onto the
            // media, as Microsoft's step 28.
            let serviced_boot = share.join("boot-serviced.wim");
            // Taken only when the cumulative update is really in it (its RollupFix package).
            if boot_ok && serviced_boot.exists() && rollup_in(log, &serviced_boot, "2").await.is_none() {
                log.warn("boot.wim: DISM reported the cumulative update installed, but the image carries none - built from the serviced WinRE instead").await;
                boot_ok = false;
            }
            let boot_from = if boot_ok && serviced_boot.exists() {
                let boot = tree.join("sources/boot.wim");
                move_file(&serviced_boot, &boot).await?;
                let boot_s = boot.display().to_string();
                run(log, "wimlib-imagex", &["info", &boot_s, "1", "--image-property", "FLAGS=9"]).await?;
                run(log, "wimlib-imagex", &["info", &boot_s, "2", "--image-property", "FLAGS=2"]).await?;
                run(log, "wimlib-imagex", &["info", &boot_s, "2", "--boot"]).await?;
                Some("the cumulative update in WinPE and Setup")
            } else if winre_ok && serviced_re.exists() {
                if !extra.boot.is_empty() {
                    log.warn("boot.wim did not take the cumulative update - built from the serviced WinRE instead").await;
                }
                build_boot_wim(log, &tree, &serviced_re).await?;
                Some("built again from the serviced WinRE")
            } else {
                None
            };
            if let Some(how) = boot_from {
                let boot = tree.join("sources/boot.wim");
                // What the Setup environment really carries: the WIM's own build field is only
                // as new as whoever wrote it, the cumulative update's package is the fact.
                let b = winpe::image_build(log, &boot, "2").await?;
                let copied = boot_files_from(log, &dir, &tree).await?;
                log.ok(format!("boot.wim {how}: {b}; boot manager onto the media: {}", if copied.is_empty() { "nothing".into() } else { copied.join(", ") })).await;
            }
            if let Some(edge) = &edge_file
                && !keep
            {
                let _ = tokio::fs::remove_file(edge).await;
            }
            log.ok(format!("Every image is at {} now", req.build)).await;
            // The worker's share (a copy of every update while downloads are kept, apps.wim,
            // boot.wim, Edge.wim, WinRE) is done with: its room goes to the ISO.
            let _ = tokio::fs::remove_dir_all(&share).await;
            // The updates the share linked: in now.
            if !keep {
                for n in &applied {
                    let _ = tokio::fs::remove_file(dl.join(n)).await;
                }
            }
        } else if c.stage == Stage::Prepared {
            log.ok(format!("The images are at {} already - no worker needed", req.build)).await;
        }
        let mut c = c;
        if c.stage == Stage::Prepared {
            c.stage = Stage::Serviced;
            c.save(&dir).await?;
        }

        // ---- the ISO ----
        let name = iso_name(prod, &req.build, &req.editions, &req.lang);
        let iso = dir.join(&name);
        if c.stage == Stage::Serviced {
        pr.stage(90.0, 93.0, "building the ISO");
        // The tree and the ISO beside it: about twice the tree's size, checked before
        // genisoimage writes half an ISO into a full disk.
        let tree_bytes = dir_size(&tree).await;
        let free = statvfs_free(work)?;
        if free < tree_bytes + tree_bytes / 10 + 1_000_000_000 {
            bail!("the studio has {:.1} GB free in {}; the ISO needs about {:.1} GB - clear the kept downloads (Studio settings → Debug tools)", free as f64 / 1e9, work.display(), tree_bytes as f64 * 1.1 / 1e9);
        }
        move_file(&install, &tree.join("sources/install.wim")).await?;
        let label: String = format!("{}_{}", prod.short.to_uppercase().replace('-', "_"), req.build.replace('.', "_")).chars().take(32).collect();
        log.run(format!("Building the ISO: {name}")).await;
        let tree_s = tree.display().to_string();
        let mut args = vec!["-quiet"];
        if tree.join("boot/etfsboot.com").exists() {
            args.extend(["-b", "boot/etfsboot.com", "-no-emul-boot", "-eltorito-alt-boot"]);
        }
        let iso_s = iso.display().to_string();
        args.extend(["-b", "efi/microsoft/boot/efisys.bin", "-no-emul-boot", "-udf", "-iso-level", "3", "-allow-limited-size", "-hide", "*", "-V", &label, "-o", &iso_s, &tree_s]);
        run(log, "genisoimage", &args).await?;
        let _ = tokio::fs::remove_dir_all(&tree).await;
        let size = tokio::fs::metadata(&iso).await?.len();
        let sum = run(log, "sha256sum", &[&iso_s]).await?;
        let sha256 = sum.split_whitespace().next().unwrap_or_default().to_owned();
        log.ok(format!("{name}: {:.2} GB, SHA-256 {sha256}", size as f64 / 1e9)).await;
        c.stage = Stage::Iso;
        c.iso = Some((size, sha256));
        c.save(&dir).await?;
        }
        let (size, sha256) = c.iso.clone().unwrap_or_default();

        pr.stage(93.0, 100.0, "uploading to PVE");
        let volid = format!("{}:iso/{name}", p.iso_storage);
        if pve.storage_content(&p.node, &p.iso_storage, "iso").await?.iter().any(|v| v.volid == volid) {
            pve.delete_volume(&p.node, &volid).await?;
        }
        log.run(format!("Uploading into {} on {}", p.iso_storage, p.node)).await;
        let volid = pve.upload(&p.node, &p.iso_storage, "iso", &iso, &name).await?;
        log.ok(format!("{volid} is ready - bake a gold from it under Media")).await;
        Ok(MediaIso {
            volid,
            product: prod.id.to_owned(),
            build: req.build.clone(),
            uuid: req.uuid.clone(),
            lang: req.lang.clone(),
            editions: editions_out.clone(),
            built: chrono::Utc::now().to_rfc3339(),
            size,
            sha256,
            updates: applied,
        })
    }
    .await;

    // A failed run past its first stage keeps its folder for Continue (the work folder's
    // cleanup takes it after six idle hours); a finished one, or one with nothing kept, goes.
    if result.is_ok() || !tokio::fs::try_exists(dir.join(CHECKPOINT)).await.unwrap_or(false) {
        let _ = tokio::fs::remove_dir_all(&dir).await;
    }
    let iso = result?;
    let mut list: Vec<MediaIso> = settings::load(db, "media_isos").await.unwrap_or_default();
    list.retain(|m| m.volid != iso.volid);
    list.insert(0, iso.clone());
    settings::save(db, "media_isos", &list).await?;
    Ok(iso)
}

fn or_none(s: &str) -> &str {
    if s.is_empty() { "none" } else { s }
}

/// A client set's package CABs become ESDs, so wimlib can refer to them. One converted on an
/// earlier try (its ESD newer than the CAB) is kept; the CAB stays in the download cache.
async fn cabs_to_esd(log: &JobLog, dir: &Path, cabs: &[PathBuf]) -> Result<()> {
    if cabs.is_empty() {
        return Ok(());
    }
    log.line(format!("Turning {} package CAB(s) into ESDs for wimlib", cabs.len())).await;
    let newer = |p: &Path| std::fs::metadata(p).and_then(|m| m.modified()).ok();
    for cab in cabs {
        let esd = cab.with_extension("esd");
        if newer(&esd).zip(newer(cab)).is_some_and(|(e, c)| e >= c) {
            continue;
        }
        let x = dir.join("cabx");
        let _ = tokio::fs::remove_dir_all(&x).await;
        tokio::fs::create_dir_all(&x).await?;
        run(log, "cabextract", &["-q", "-d", &x.display().to_string(), &cab.display().to_string()]).await?;
        run(log, "wimlib-imagex", &["capture", &x.display().to_string(), &esd.display().to_string(), "--no-acls", "--norpfix", "Edition Package", "Edition Package"]).await?;
    }
    let _ = tokio::fs::remove_dir_all(dir.join("cabx")).await;
    Ok(())
}

/// "KB5043080 (.msu)" out of the worker's "01-Windows11.0-KB5043080-x64.msu".
fn update_label(name: &str) -> String {
    let ext = name.rsplit('.').next().unwrap_or("");
    match kb_of(name) {
        Some(kb) => format!("{kb} (.{ext})"),
        None => name.to_owned(),
    }
}

fn where_label(at: &str) -> String {
    match at {
        "winre" => "WinRE".into(),
        b if b.starts_with("boot") => format!("boot.wim image {}", &b[4..]),
        _ => format!("image {at}"),
    }
}

/// DISM's exit code as Windows writes HRESULTs: -2146498530 is 0x800F081E.
pub(crate) fn dism_code(raw: &str) -> String {
    match raw.parse::<i64>() {
        Ok(n) if n < 0 => format!("0x{:08X}", n as i32 as u32),
        Ok(n) if n > 0xFFFF => format!("0x{n:08X}"),
        Ok(n) => format!("{n} (0x{n:X})"),
        Err(_) => raw.to_owned(),
    }
}

pub(crate) struct PackageReport {
    pub(crate) summary: String,
    pub(crate) broken: Vec<String>,
}

/// An image's package list (dism /Get-Packages /Format:Table): how many in which state, the
/// cumulative update levels (RollupFix), and anything left half-done. "Install Pending" is
/// normal offline - the first boot finishes it.
pub(crate) fn package_report(table: &str) -> PackageReport {
    let mut states: Vec<(String, usize)> = Vec::new();
    let (mut rollups, mut broken) = (Vec::new(), Vec::new());
    for line in table.lines() {
        let cols: Vec<&str> = line.split('|').map(str::trim).collect();
        if cols.len() < 2 || !cols[0].contains('~') {
            continue;
        }
        let (id, state) = (cols[0], cols[1]);
        match states.iter_mut().find(|(s, _)| s == state) {
            Some(e) => e.1 += 1,
            None => states.push((state.to_owned(), 1)),
        }
        if id.starts_with("Package_for_RollupFix") {
            rollups.push(format!("{} {state}", id.rsplit('~').next().unwrap_or("")));
        }
        if matches!(state, "Partially Installed" | "Install Failed" | "Uninstall Pending" | "Uninstall Failed") {
            broken.push(format!("{id} ({state})"));
        }
    }
    let total: usize = states.iter().map(|(_, n)| n).sum();
    let parts: Vec<String> = states.iter().map(|(s, n)| format!("{n} {s}")).collect();
    PackageReport {
        summary: format!("{total} packages - {}; cumulative update {}", parts.join(", "), if rollups.is_empty() { "none".into() } else { rollups.join(", ") }),
        broken,
    }
}

async fn winpe_update_index(wim: &Path, index: usize, cmds: &str) -> Result<()> {
    use tokio::io::AsyncWriteExt;
    let mut child = tokio::process::Command::new("wimlib-imagex")
        .args(["update", &wim.display().to_string(), &index.to_string()])
        .env("WIMLIB_IMAGEX_IGNORE_CASE", "1")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()?;
    {
        let mut stdin = child.stdin.take().unwrap();
        stdin.write_all(cmds.as_bytes()).await?;
    }
    let out = child.wait_with_output().await?;
    if !out.status.success() {
        bail!("wimlib-imagex update failed: {}", String::from_utf8_lossy(&out.stderr).lines().last().unwrap_or(""));
    }
    Ok(())
}

/// A downloaded file into the worker's share: moved, or - downloads kept - hard-linked
/// (copied across file systems), so the download stays where the next build finds it.
pub(crate) async fn take_file(from: &Path, to: &Path, keep: bool) -> Result<()> {
    if !keep {
        return move_file(from, to).await;
    }
    if tokio::fs::hard_link(from, to).await.is_err() {
        tokio::fs::copy(from, to).await.with_context(|| format!("copying {} to {}", from.display(), to.display()))?;
    }
    Ok(())
}

/// A rename when both sides share a file system (the studio's data and the share do), a
/// copy otherwise.
/// The cumulative update an image carries: its Package_for_RollupFix version (26100.9550.1.28).
async fn rollup_in(log: &JobLog, wim: &Path, index: &str) -> Option<String> {
    let out = run(log, "wimlib-imagex", &["dir", &wim.display().to_string(), index, "--path=/Windows/servicing/Packages"]).await.ok()?;
    let mut v: Vec<String> = out
        .lines()
        .filter_map(|l| l.rsplit('/').next())
        .filter(|n| n.starts_with("Package_for_RollupFix") && n.ends_with(".mum"))
        .filter_map(|n| n.trim_end_matches(".mum").rsplit('~').next().map(str::to_owned))
        .collect();
    let num = |s: &String| s.split('.').map(|x| x.parse::<u64>().unwrap_or(0)).collect::<Vec<_>>();
    v.sort_by_key(num);
    v.pop()
}

/// A folder's size, every file below it.
async fn dir_size(dir: &Path) -> u64 {
    let mut total = 0;
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(mut rd) = tokio::fs::read_dir(&d).await else { continue };
        while let Ok(Some(e)) = rd.next_entry().await {
            match e.metadata().await {
                Ok(m) if m.is_dir() => stack.push(e.path()),
                Ok(m) => total += m.len(),
                Err(_) => {}
            }
        }
    }
    total
}

async fn move_file(from: &Path, to: &Path) -> Result<()> {
    if tokio::fs::rename(from, to).await.is_err() {
        tokio::fs::copy(from, to).await.with_context(|| format!("copying {} to {}", from.display(), to.display()))?;
        tokio::fs::remove_file(from).await?;
    }
    Ok(())
}

fn statvfs_free(path: &Path) -> Result<u64> {
    let out = std::process::Command::new("df").args(["-B1", "--output=avail"]).arg(path).output().context("running df")?;
    Ok(String::from_utf8_lossy(&out.stdout).lines().nth(1).and_then(|l| l.trim().parse().ok()).unwrap_or(0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn health_verdicts() {
        let ok = "Deployment Image Servicing and Management tool\r\nVersion: 10.0.26100.1\r\n\r\nImage Version: 10.0.26100.33438\r\n\r\n[==========================100.0%==========================] No component store corruption detected.\r\nThe operation completed successfully.\r\n";
        assert!(health_verdict(ok).is_ok());
        assert!(health_verdict("[===100.0%===] The component store is repairable.\r\nThe operation completed successfully.").unwrap_err().contains("repairable"));
        assert!(health_verdict("The component store is not repairable.").unwrap_err().contains("not repairable"));
        assert!(health_verdict("Error: 5\r\n\r\nAccess is denied.").unwrap_err().contains("Access is denied."));
        assert!(health_verdict("Error: 50\r\n\r\nThe request is not supported.\r\n\r\nThe DISM log file can be found at X:\\windows\\Logs\\DISM\\dism.log").unwrap_err().contains("Error: 50 The request is not supported."));
        assert!(health_verdict("").is_err());
    }

    fn f(name: &str) -> uup::File {
        uup::File { name: name.into(), url: String::new(), sha1: String::new(), size: 1 }
    }

    #[test]
    fn updates_in_order() {
        let files = vec![
            f("Windows11.0-KB5124010-x64.msu"),
            f("Windows11.0-KB5125758-x64.cab"),
            f("Windows11.0-KB5125758-x64.msu"),
            f("Windows11.0-KB5125758-x64-baseless.cab"),
            f("Windows11.0-KB5043080-x64.msu"),
            f("Windows11.0-KB5121794-x64.cab"),
            f("Windows11.0-KB5121794-x64.msu"),
            f("Windows11.0-KB5127216-x64.cab"),
            f("Windows11.0-KB5126052-x64-NDP481.cab"),
        ];
        let info = UpdateInfo {
            targets: HashMap::from([("KB5125758".to_owned(), Target::WinRe), ("KB5127216".to_owned(), Target::Setup)]),
            cumulative: vec!["KB5124010".into(), "KB5043080".into()],
        };
        let picked: Vec<(String, Target)> = pick_updates(&files, &info).into_iter().map(|(f, t)| (f.name, t)).collect();
        assert_eq!(
            picked,
            vec![
                ("Windows11.0-KB5043080-x64.msu".into(), Target::Image),
                ("Windows11.0-KB5124010-x64.msu".into(), Target::Image),
                ("Windows11.0-KB5121794-x64.msu".into(), Target::Image),
                ("Windows11.0-KB5125758-x64.cab".into(), Target::WinRe),
                ("Windows11.0-KB5126052-x64-NDP481.cab".into(), Target::Image),
                ("Windows11.0-KB5127216-x64.cab".into(), Target::Setup),
            ]
        );
    }

    #[test]
    fn iso_names() {
        let e = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        let ws = uup::product("ws2025").unwrap();
        assert_eq!(iso_name(ws, "26100.33438", &e(&["SERVERDATACENTERCORE"]), "en-us"), "enus-ws2025-dc-core-26100.33438.iso");
        assert_eq!(iso_name(ws, "26100.33438", &e(&["SERVERDATACENTERCORE", "SERVERDATACENTER"]), "en-us"), "enus-ws2025-dc-26100.33438.iso");
        assert_eq!(iso_name(ws, "26100.33438", &e(&["SERVERDATACENTER"]), "en-us"), "enus-ws2025-dc-desktop-26100.33438.iso");
        assert_eq!(iso_name(ws, "26100.33438", &e(&["SERVERSTANDARD", "SERVERDATACENTER", "SERVERDATACENTERCORE"]), "de-de"), "dede-ws2025-26100.33438.iso");
        assert_eq!(iso_name(ws, "26100.33438", &e(&["SERVERSTANDARDCORE", "SERVERDATACENTERCORE"]), "en-us"), "enus-ws2025-core-26100.33438.iso");
        assert_eq!(iso_name(uup::product("w11-26h2").unwrap(), "26300.9550", &e(&["PROFESSIONAL"]), "en-us"), "enus-w11-pro-26300.9550.iso");
        assert_eq!(iso_name(uup::product("w11-26h2").unwrap(), "26300.9550", &e(&["PROFESSIONAL", "CORE"]), "en-us"), "enus-w11-26300.9550.iso");
        assert_eq!(iso_name(uup::product("w11-canary").unwrap(), "28100.1", &e(&["PROFESSIONAL"]), "en-us"), "enus-w11-canary-pro-28100.1.iso");
    }

    #[test]
    fn chain_one_update_at_a_time() {
        // Windows 11: no one-call chain; each .msu in its own folder, the checkpoint first.
        let image = vec!["lcu1/Windows11.0-KB5043080-x64.msu".to_owned(), "lcu2/Windows11.0-KB5124010-x64.msu".to_owned()];
        let cmd = worker_cmd_body(1, &[], &image, &[], None, &Extras::default());
        assert!(cmd.contains("mkdir W:\\upd\\lcu1") && cmd.contains("mkdir W:\\upd\\lcu2"));
        assert!(cmd.contains("-o W:\\upd\\lcu1\\Windows11.0-KB5043080-x64.msu %U%/upd/lcu1/Windows11.0-KB5043080-x64.msu"));
        assert!(!cmd.contains("%U%/upd/lcu/"));
        let a = cmd.find("/PackagePath:W:\\upd\\lcu1\\").unwrap();
        let b = cmd.find("/PackagePath:W:\\upd\\lcu2\\").unwrap();
        assert!(a < b, "the checkpoint goes in first");
    }

    #[test]
    fn net_after_cleanup_scan_each_stage() {
        let image = vec!["01-Windows11.0-KB5054156-x64.cab".to_owned(), "02-Windows11.0-KB5126052-x64-NDP481.cab".to_owned(), "lcu1/Windows11.0-KB5043080-x64.msu".to_owned(), "lcu2/Windows11.0-KB5124010-x64.msu".to_owned()];
        let cmd = worker_cmd_body(1, &[], &image, &[], None, &Extras::default());
        let at = |n: &str| cmd.find(n).unwrap_or_else(|| panic!("{n} missing"));
        assert!(at("KB5054156-x64.cab /Scratch") < at("PackagePath:W:\\upd\\lcu1\\"), "the enablement package before the cumulative chain");
        assert!(at("PackagePath:W:\\upd\\lcu2\\") < at("health-%1-updated.txt"));
        assert!(at("health-%1-updated.txt") < at("/StartComponentCleanup"));
        assert!(at("/StartComponentCleanup") < at("health-%1-cleaned.txt"));
        assert!(at("health-%1-cleaned.txt") < at("NDP481.cab /Scratch"), ".NET after the cleanup");
        assert!(at("NDP481.cab /Scratch") < at("health-%1.txt"));
        assert!(cmd.contains("%U%/logs/health-%1.log"));
    }

    #[test]
    fn reverse_delta_scan_error() {
        let log = |lines: &str, total: usize, payload: usize| format!(
            "2026-10-06 14:07:29, Info CBS Total Detected Corruption:\t{total}\n2026-10-06 14:07:29, Info CBS \tCSI Payload Corruption:\t{payload}\n{lines}"
        );
        let r = "2026-10-06 14:07:29, Info CBS (p)\tCSI Payload Corrupt\t(n)\t\t\tamd64_microsoft-windows-nfs-admincmdtools_31bf3856ad364e35_10.0.26100.3323_none_507c8beb43054047\\r\\showmount.exe\n";
        let f = "2026-10-06 14:07:29, Info CBS (p)\tCSI Payload Corrupt\t(n)\t\t\tamd64_microsoft-windows-nfs-admincmdtools_31bf3856ad364e35_10.0.26100.3323_none_507c8beb43054047\\f\\showmount.exe\n";
        assert_eq!(reverse_delta_only(&log(&r.repeat(2), 2, 2)), Some(2));
        assert_eq!(reverse_delta_only(&log(&format!("{r}{f}"), 2, 2)), None, "a forward payload is damage");
        assert_eq!(reverse_delta_only(&log(r, 2, 1)), None, "a manifest or metadata corruption is damage");
        assert_eq!(reverse_delta_only(&log("", 0, 0)), None);
        assert_eq!(reverse_delta_only(""), None);
    }

    #[test]
    fn worker_units_follow_the_script() {
        let image = vec!["01-Windows11.0-KB5121794-x64.cab".to_owned(), "02-Windows11.0-KB5126052-x64-NDP481.cab".to_owned(), "lcu1/Windows11.0-KB5043080-x64.msu".to_owned(), "lcu2/Windows11.0-KB5129195-x64.msu".to_owned()];
        let winre = vec!["re01-Windows11.0-KB5124015-x64.cab".to_owned()];
        let app = |id: &str| crate::apps::App { id: id.into(), main: format!("{id}.msixbundle"), stub: false };
        let extra = Extras {
            edge: true,
            frameworks: vec!["MSIXFramework\\Microsoft.VCLibs.x64.14.00.appx".into()],
            apps: vec![vec![app("Microsoft.BingNews_8wekyb3d8bbwe"), app("Microsoft.WindowsCalculator_8wekyb3d8bbwe")]],
            boot: vec![],
        };
        let ssu = Some("SSU-26100.9441-x64.cab");
        let cmd = worker_cmd_body(1, &[], &image, &winre, ssu, &extra);
        let units = worker_units(1, &image, &winre, ssu, &extra);
        // Every unit's marker is in the script (the image's number is %1 there), in that order.
        let mut last = 0;
        for (key, w) in &units {
            assert!(*w > 0.0);
            if let Some(rest) = key.strip_prefix("PROV 1 ") {
                assert!(cmd.contains(&format!("PVS-PROV-OK 1 {rest}")), "{key}");
                continue;
            }
            let (k, args) = key.split_once(' ').unwrap_or((key, ""));
            let args = match args.strip_prefix('1') { Some(r) if k != "APPS" => format!("%1{r}"), _ => args.to_owned() };
            let echo = if args.is_empty() { format!("echo PVS-{k} ") } else { format!("echo PVS-{k} {args} ") };
            let at = cmd.find(&echo).unwrap_or_else(|| panic!("{echo} not in the script"));
            // :service and :winre are subroutines after the main flow: order within each.
            // :apps<n> and :winre are subroutines written after :service; the flow of :service
            // itself (and the main flow before it) is checked in order.
            let sub = key.starts_with("UPD winre") || key == "WINRE" || key.starts_with("APPS") || key == "EXPORT" || key == "COPY-OUT";
            if !sub {
                assert!(at >= last, "{key} out of order");
                last = at;
            }
        }
        let total: f64 = units.iter().map(|(_, w)| w).sum();
        assert!(total > 1000.0, "two cumulative updates weigh most: {total}");
        assert_eq!(crate::windows::unit_key("PVS-PROV-FAIL 1 Microsoft.BingNews_8wekyb3d8bbwe 0x80070057").as_deref(), Some("PROV 1 Microsoft.BingNews_8wekyb3d8bbwe"));
        assert_eq!(crate::windows::unit_key("PVS-UPD-OK 1 cleanup"), None);
        assert_eq!(crate::windows::unit_key("PVS-HEALTH 1-before").as_deref(), Some("HEALTH 1-before"));
    }

    #[test]
    fn edge_apps_and_boot() {
        let image = vec!["01-Windows11.0-KB5054156-x64.cab".to_owned(), "02-Windows11.0-KB5126052-x64-NDP481.cab".to_owned(), "lcu1/Windows11.0-KB5043080-x64.msu".to_owned(), "lcu2/Windows11.0-KB5124010-x64.msu".to_owned()];
        let extra = Extras {
            edge: true,
            frameworks: vec!["MSIXFramework\\Microsoft.VCLibs.x64.14.00.appx".into()],
            apps: vec![vec![crate::apps::App { id: "Microsoft.BingNews_8wekyb3d8bbwe".into(), main: "Microsoft.BingNews_8wekyb3d8bbwe.msixbundle".into(), stub: true }]],
            boot: vec!["lcu1/Windows11.0-KB5043080-x64.msu".into(), "lcu2/Windows11.0-KB5124010-x64.msu".into()],
        };
        let cmd = worker_cmd_body(1, &[], &image, &[], None, &extra);
        let at = |n: &str| cmd.find(n).unwrap_or_else(|| panic!("{n} missing"));
        assert!(cmd.contains("%U%/Edge.wim") && cmd.contains("%U%/apps.wim") && cmd.contains("%U%/boot.wim"));
        assert!(at("NDP481.cab /Scratch") < at("/Add-Edge /SupportPath:W:\\edge"), "Edge after the updates");
        assert!(at("/Add-Edge") < at("call :apps%1"));
        assert!(at("call :apps%1") < at("health-%1.txt"));
        assert!(at("VCLibs.x64.14.00.appx\" /SkipLicense") < at("BingNews_8wekyb3d8bbwe.msixbundle\""), "frameworks first");
        assert!(cmd.contains("/LicensePath:\"W:\\apps\\Microsoft.BingNews_8wekyb3d8bbwe\\License.xml\" /Region:all /StubPackageOption:InstallFull"));
        assert!(cmd.contains("call :boot\r\n") && !cmd.contains("call :boot ||"), "boot.wim never fails the run");
        assert!(at("WinPE-Rejuv-Package") < at("/PackagePath:W:\\upd\\lcu1\\Windows11.0-KB5043080-x64.msu /ScratchDir:W:\\scratch /LogPath:W:\\logs\\boot%1"));
        assert!(cmd.contains("boot-serviced.wim"));
    }

    #[test]
    fn checkpoint_chain() {
        let chain = vec!["Windows11.0-KB5043080-x64.msu".to_owned(), "Windows11.0-KB5124010-x64.msu".to_owned()];
        let image = vec!["lcu/Windows11.0-KB5124010-x64.msu".to_owned(), "01-Windows11.0-KB5121794-x64.cab".to_owned()];
        let cmd = worker_cmd("https://x/worker/r/t", "", 1, &chain, &image, &["re01-Windows11.0-KB5125758-x64.cab".to_owned()], Some("SSU-26100.9539-x64.cab"), &Extras::default());
        assert!(cmd.contains("/ScanHealth") && !cmd.contains("health-winre"), "every install image scanned, WinRE not");
        assert!(cmd.contains("-o W:\\upd\\SSU-26100.9539-x64.cab %U%/upd/SSU-26100.9539-x64.cab"));
        let ssu_at = cmd.find("/PackagePath:W:\\upd\\SSU-26100.9539-x64.cab").unwrap();
        let safeos_at = cmd.find("/PackagePath:W:\\upd\\re01-Windows11.0-KB5125758-x64.cab").unwrap();
        assert!(ssu_at < safeos_at, "the servicing stack goes into WinRE before the Safe OS update");
        assert!(cmd.contains("mkdir W:\\upd\\lcu"));
        assert!(cmd.contains("-o W:\\upd\\lcu\\Windows11.0-KB5043080-x64.msu %U%/upd/lcu/Windows11.0-KB5043080-x64.msu"));
        assert!(cmd.contains("/PackagePath:W:\\upd\\lcu\\Windows11.0-KB5124010-x64.msu"));
        // The checkpoint is never named to DISM.
        assert!(!cmd.contains("/PackagePath:W:\\upd\\lcu\\Windows11.0-KB5043080-x64.msu"));
        assert!(cmd.contains("/PackagePath:W:\\upd\\01-Windows11.0-KB5121794-x64.cab"));
    }

    #[test]
    fn codes_and_packages() {
        assert_eq!(dism_code("-2146498530"), "0x800F081E");
        assert_eq!(dism_code("552"), "552 (0x228)");
        let t = "Package Identity | State | Release Type | Install Time\n------\nPackage_for_RollupFix~31bf3856ad364e35~amd64~~26100.9550.1.10 | Installed | Security Update | 1/1/2026\nFoo~31bf3856ad364e35~amd64~~1 | Partially Installed | Feature Pack |\n";
        let r = package_report(t);
        assert!(r.summary.contains("26100.9550.1.10 Installed"));
        assert_eq!(r.broken.len(), 1);
        assert_eq!(update_label("01-Windows11.0-KB5043080-x64.msu"), "KB5043080 (.msu)");
    }
}
