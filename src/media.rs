//! Windows install media built from Microsoft's own update files - the "Windows media" blade.
//! The way Microsoft refreshes its media every month, done here (docs/uup-media-worker.md):
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
    let list = path.strip_prefix("packages-").and_then(|r| r.strip_suffix(".txt")).is_some_and(|n| !n.is_empty() && n.chars().all(|c| c.is_ascii_digit()));
    let step_log = path.strip_prefix("logs/").and_then(|r| r.strip_suffix(".log")).is_some_and(|n| !n.is_empty() && n.chars().all(|c| c.is_ascii_alphanumeric() || "-_.%".contains(c)) && !n.contains(".."));
    if !matches!(path.as_str(), "serviced.wim" | "winre-serviced.wim" | "dism.log") && !list && !step_log {
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

/// The media worker VM's size (Studio settings): DISM servicing a whole install image wants
/// memory - 4 GB kept it paging.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct WorkerSettings {
    pub memory_mb: u32,
    pub cores: u32,
}

impl Default for WorkerSettings {
    fn default() -> Self {
        Self { memory_mb: 8192, cores: 4 }
    }
}

pub struct Request {
    pub product: &'static Product,
    pub uuid: String,
    pub build: String,
    pub lang: String,
    pub editions: Vec<String>,
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

fn is_aggregated(name: &str) -> bool {
    name.to_lowercase().ends_with(".aggregatedmetadata.cab")
}

/// KB5125758 out of Windows11.0-KB5125758-x64.cab.
fn kb_of(name: &str) -> Option<String> {
    let up = name.to_uppercase();
    let at = up.find("-KB")? + 1;
    let digits: String = up[at + 2..].chars().take_while(|c| c.is_ascii_digit()).collect();
    (!digits.is_empty()).then(|| format!("KB{digits}"))
}

/// Where an update goes, as Microsoft's media servicing steps put it: the install image,
/// WinRE (the Safe OS dynamic update), or the media's sources\ folder (the Setup dynamic
/// update - a CAB of files, not a package).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Target {
    Image,
    WinRe,
    Setup,
}

/// What the build's AggregatedMetadata.cab says about its updates: each one's target
/// (SafeOSDUCompDB_KB…, SetupDUCompDB_KB…; the rest go into the image), and which are the
/// cumulative update chain (outer.AggregatedMetadata_KB… - a checkpoint and the target).
#[derive(Default)]
struct UpdateInfo {
    targets: HashMap<String, Target>,
    cumulative: Vec<String>,
}

async fn update_targets(agg: &Path) -> UpdateInfo {
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
fn pick_updates(files: &[uup::File], info: &UpdateInfo) -> Vec<(uup::File, Target)> {
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
    (n.ends_with(".esd") && !other_meta) || n.ends_with(".cab")
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
/// sent back to the studio when the step fails.
fn dism_step(s: &mut String, what: &str, log: &str, dism: &str) {
    s.push_str(&format!("echo PVS-UPD {what} > COM1\r\n{dism} /LogPath:W:\\logs\\{log}.log > COM1 2>&1\r\nset RC=!errorlevel!\r\nif \"!RC!\"==\"3010\" set RC=0\r\n"));
    s.push_str(&format!(
        "if \"!RC!\"==\"0\" (echo PVS-UPD-OK {what} > COM1) else (echo PVS-UPD-FAIL {what} !RC! > COM1 & set ERR=1 & %C% -T W:\\logs\\{log}.log %U%/logs/{log}.log > nul 2>&1)\r\n"
    ));
}

/// A step's log file name: the update's file name without its extension, per image.
fn log_name(at: &str, file: &str) -> String {
    let stem = file.rsplit_once('.').map_or(file, |(s, _)| s);
    format!("{}-{stem}", if at == "winre" { "winre".to_owned() } else { format!("image{at}") })
}

/// The worker's script: the install image's updates one at a time (each with its verdict),
/// the package list of every image for the studio to check, the Safe OS update into WinRE,
/// and DISM's own log back to the studio whatever happened.
fn worker_cmd(url: &str, pin: &str, indexes: usize, chain: &[String], image: &[String], winre: &[String], ssu: Option<&str>) -> String {
    let mut s = String::new();
    s += "@echo off\r\nrem PVE VM Studio media worker: install.wim + updates -> serviced install.wim.\r\n";
    s += "setlocal enabledelayedexpansion\r\nset ERR=0\r\necho PVS-WORKER-START > COM1\r\nwpeutil InitializeNetwork > nul 2>&1\r\n";
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
    s += "echo PVS-COPY-IN > COM1\r\n%C% -o W:\\install.wim %U%/install.wim > COM1 2>&1 || goto :fail\r\n";
    if !winre.is_empty() {
        s += "%C% -o W:\\winre.wim %U%/winre.wim > COM1 2>&1 || goto :fail\r\n";
    }
    if !chain.is_empty() {
        s += "mkdir W:\\upd\\lcu\r\n";
    }
    for u in chain.iter().map(|c| format!("lcu/{c}")).chain(image.iter().filter(|u| !u.starts_with("lcu/")).cloned()).chain(winre.iter().cloned()).chain(ssu.filter(|_| !winre.is_empty()).map(str::to_owned)) {
        let local = u.replace('/', "\\");
        s += &format!("%C% -o W:\\upd\\{local} %U%/upd/{u} > COM1 2>&1 || goto :fail\r\n");
    }
    s += &format!("for /l %%i in (1,1,{indexes}) do call :service %%i || goto :fail\r\n");
    if !winre.is_empty() {
        s += "call :winre || goto :fail\r\n";
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
    for u in image {
        // lcu/<target>: the cumulative update chain sits in its own folder, the target named
        // alone - DISM takes the checkpoints in that folder first (Microsoft's checkpoint
        // procedure; naming the checkpoint itself fails with 0x80070228).
        let (file, local) = (u.rsplit('/').next().unwrap_or(u), u.replace('/', "\\"));
        dism_step(&mut s, &format!("%1 {file}"), &log_name("%1", file), &format!("dism /English /Image:W:\\mount /Add-Package /PackagePath:W:\\upd\\{local} /ScratchDir:W:\\scratch"));
    }
    s += "echo PVS-CLEANUP %1 > COM1\r\ndism /English /Image:W:\\mount /Cleanup-Image /StartComponentCleanup /ResetBase /ScratchDir:W:\\scratch > COM1 2>&1\r\n";
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
        s += "dism /English /Image:W:\\mount /Cleanup-Image /StartComponentCleanup /ResetBase /ScratchDir:W:\\scratch > COM1 2>&1\r\n";
        s += "dism /English /Unmount-Image /MountDir:W:\\mount /Commit /ScratchDir:W:\\scratch > COM1 2>&1 || exit /b 1\r\n";
        s += "dism /English /Export-Image /SourceImageFile:W:\\winre.wim /SourceIndex:1 /DestinationImageFile:W:\\winre-serviced.wim /Compress:max /Bootable /ScratchDir:W:\\scratch > COM1 2>&1 || exit /b 1\r\n";
        s += "%C% -T W:\\winre-serviced.wim %U%/winre-serviced.wim > COM1 2>&1 || exit /b 1\r\nexit /b 0\r\n";
    }
    // DISM's own log - the why behind any error code - goes back in every case.
    s += ":log\r\n%C% -T X:\\Windows\\Logs\\DISM\\dism.log %U%/dism.log > nul 2>&1\r\nexit /b 0\r\n";
    s += ":fail\r\ncall :log\r\necho PVS-WORKER-FAILED > COM1\r\n";
    s
}

/// Builds the ISO. Returns what the blade's history records.
pub async fn build(pve: &Pve, db: &SqlitePool, log: &JobLog, web: &reqwest::Client, work: &Path, p: &Placement, link: Link, req: Request) -> Result<MediaIso> {
    let prod = req.product;
    let mut pr = Progress::new(log, format!("Building {} {}", prod.name, req.build));
    let run_id = format!("run-{}", uuid::Uuid::new_v4().simple());
    let dir: PathBuf = work.join(format!("media-{run_id}"));
    // What the worker fetches and sends back, served by worker_router while it runs.
    let share = dir.join("worker");
    let mut worker: Option<u32> = None;

    let result: Result<MediaIso> = async {
        // Downloads go to a cache a failed build leaves behind: the next try keeps what is
        // already here (the work folder's cleanup removes it after six idle hours).
        // One cache per build: files of other builds (or of a FoD ISO) share names, not
        // content - Microsoft-Windows-Media-Features-Package-amd64.cab is a client's here and a
        // server's there.
        let dl = work.join("uup-files").join(&req.uuid);
        tokio::fs::create_dir_all(&dl).await?;
        tokio::fs::create_dir_all(&dir).await?;
        let base: Vec<String> = req.editions.clone();
        if base.is_empty() {
            bail!("pick at least one edition");
        }

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

        // boot.wim: 1 is WinPE, 2 the Setup environment (Setup and its own DISM in X:\sources).
        log.line("Building boot.wim: WinPE and the Setup environment").await;
        let boot = tree.join("sources/boot.wim");
        let boot_s = boot.display().to_string();
        let _ = tokio::fs::remove_file(&boot).await;
        run(log, "wimlib-imagex", &["export", &winre_s, "1", &boot_s, "Microsoft Windows PE", "Microsoft Windows PE", "--compress=maximum"]).await?;
        run(log, "wimlib-imagex", &["info", &boot_s, "1", "--image-property", "FLAGS=9"]).await?;
        winpe::wim_update(&boot, "delete --force /Windows/System32/winpeshl.ini\n").await?;
        run(log, "wimlib-imagex", &["export", &winre_s, "1", &boot_s, "Microsoft Windows Setup", "Microsoft Windows Setup", "--boot"]).await?;
        run(log, "wimlib-imagex", &["info", &boot_s, "2", "--image-property", "FLAGS=2"]).await?;
        let (mut setup, n) = winpe::setup_source_cmds(&tree).await?;
        setup.insert_str(0, "delete --force /Windows/System32/winpeshl.ini\n");
        winpe_update_index(&boot, 2, &setup).await?;
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
        let target_rev = req.build.rsplit('.').next().unwrap_or_default().to_owned();
        log.ok(format!("install.wim: {} image(s) at build {}.{base_rev}; the catalog's build is {}", editions_out.len(), req.build.split('.').next().unwrap_or(""), req.build)).await;
        // Downloaded ESDs are no longer needed once the images are out of them.
        for f in files.iter().filter(|f| !is_update(&f.name)) {
            let _ = tokio::fs::remove_file(dl.join(&f.name)).await;
            let _ = tokio::fs::remove_file(dl.join(&f.name).with_extension("esd")).await;
        }

        // ---- the worker: the cumulative update, which only DISM can apply ----
        let behind = base_rev.parse::<u64>().unwrap_or(0) < target_rev.parse::<u64>().unwrap_or(0);
        if behind && updates.is_empty() {
            bail!("the images are at revision {base_rev}, the build is {} - and the catalog lists no update to get there", req.build);
        }
        let mut applied = Vec::new();
        if behind {
            pr.stage(42.0, 90.0, "the worker applies the updates");
            applied = updates.iter().chain(&winre_updates).map(|u| u.name.clone()).collect();
            let ip = studio_ip()?;
            let pe: winpe::WinPe = settings::load(db, "winpe").await?;
            if pe.volid.is_empty() {
                bail!("the worker boots the studio's WinPE - build it under Media first");
            }
            // curl.exe from the image itself (its DLLs are all in WinPE), for the seed disk.
            run(log, "wimlib-imagex", &["extract", &install_s, "1", "/Windows/System32/curl.exe", &format!("--dest-dir={}", dir.display()), "--no-acls"]).await
                .context("taking curl.exe out of the image for the worker")?;
            let curl = tokio::fs::read(dir.join("curl.exe")).await?;
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
            if chain.len() > 1 {
                tokio::fs::create_dir_all(share.join("upd/lcu")).await?;
                for u in &chain {
                    move_file(&dl.join(&u.name), &share.join("upd/lcu").join(&u.name)).await?;
                    chain_names.push(u.name.clone());
                }
                if let Some(t) = &target {
                    image_names.push(format!("lcu/{t}"));
                }
                log.line(format!("Cumulative chain {} - DISM gets {} alone, the checkpoint(s) beside it",
                    chain.iter().filter_map(|u| kb_of(&u.name)).collect::<Vec<_>>().join(" -> "),
                    target.as_deref().and_then(kb_of).unwrap_or_default())).await;
            }
            for (i, u) in updates.iter().filter(|u| chain.len() <= 1 || !in_chain(u)).enumerate() {
                let n = format!("{:02}-{}", i + 1, u.name);
                move_file(&dl.join(&u.name), &share.join("upd").join(&n)).await?;
                image_names.push(n);
            }
            let mut winre_names = Vec::new();
            for (i, u) in winre_updates.iter().enumerate() {
                let n = format!("re{:02}-{}", i + 1, u.name);
                move_file(&dl.join(&u.name), &share.join("upd").join(&n)).await?;
                winre_names.push(n);
            }
            if !winre_names.is_empty() {
                tokio::fs::copy(&winre, share.join("winre.wim")).await?;
            }
            let wim_gb = tokio::fs::metadata(share.join("install.wim")).await?.len() as f64 / 1e9;
            let upd_gb = updates.iter().chain(&winre_updates).map(|u| u.size).sum::<u64>() as f64 / 1e9;
            let scratch_gb = ((wim_gb * 4.0 + upd_gb * 2.0 + 20.0).ceil() as u64).max(60);

            let seed_name = format!("pvs-seed-media-{}", &run_id[4..12]);
            let token: String = uuid::Uuid::new_v4().simple().to_string() + &uuid::Uuid::new_v4().simple().to_string();
            let url = format!("{}/worker/{run_id}/{token}", link.base.replace("{ip}", &ip));
            tokio::fs::write(share.join("ping"), "ok").await?;
            RUNS.lock().unwrap().insert(run_id.clone(), (token.clone(), share.clone()));
            // WinRE's servicing stack: SSU-*.cab out of the cumulative update's .msu - since 24H2
            // a WIM (MSWIM header), which wimlib opens and WinPE's expand.exe cannot.
            let mut ssu_name: Option<String> = None;
            if !winre_names.is_empty()
                && let Some(lcu) = image_names.iter().find(|n| n.to_lowercase().ends_with(".msu"))
            {
                let msu = share.join("upd").join(lcu.replace('/', std::path::MAIN_SEPARATOR_STR));
                let listing = run(log, "wimlib-imagex", &["dir", &msu.display().to_string(), "1"]).await.unwrap_or_default();
                if let Some(path) = listing.lines().map(str::trim).find(|l| l.trim_start_matches('/').to_uppercase().starts_with("SSU-") && l.to_lowercase().ends_with(".cab")) {
                    let name = path.trim_start_matches('/').to_owned();
                    run(log, "wimlib-imagex", &["extract", &msu.display().to_string(), "1", path, &format!("--dest-dir={}", share.join("upd").display()), "--no-acls"]).await?;
                    log.line(format!("WinRE's servicing stack: {name}, out of {}", lcu.rsplit('/').next().unwrap_or(lcu))).await;
                    ssu_name = Some(name);
                } else {
                    log.line("No servicing stack inside the cumulative update - WinRE gets the Safe OS update alone").await;
                }
            }
            let cmd = worker_cmd(&url, &link.pin, base.len(), &chain_names, &image_names, &winre_names, ssu_name.as_deref());
            let seed_disk = SeedDisk::build_bytes(work, &seed_name, "PVSSEED", &[("pvs/pe.cmd", cmd.as_bytes()), ("pvs/curl.exe", &curl)]).await?;
            log.ok(format!("Worker fetches from the studio at {} over {}", link.base.replace("{ip}", &ip), if link.pin.is_empty() { "HTTP" } else { "HTTPS, the studio's key pinned" })).await;
            let size: WorkerSettings = settings::load(db, "worker").await?;
            golds::check_node_memory(pve, log, &p.node, size.memory_mb).await?;
            pve.ensure_pool(GOLD_POOL, "PVE VM Studio: golds (templates) and the bakes that make them").await?;
            let guard = pve.vmid_guard().await;
            let vmid = pve.free_vmid_in(GOLD_IDS).await?;
            let mut net0 = format!("e1000,bridge={}", p.bridge);
            if let Some(v) = p.vlan {
                net0 += &format!(",tag={v}");
            }
            log.run(format!("Worker: {} update(s) into {} image(s) - a WinPE VM applies them with DISM", applied.len(), base.len())).await;
            let vm_name = format!("media-{}", &run_id[4..12]);
            log.line(format!(
                "Creating worker VM {vmid} ({vm_name}): WinPE {}, {} GB memory, {} cores, {scratch_gb} GB scratch disk on {}",
                pe.build,
                size.memory_mb / 1024,
                size.cores,
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
                ("balloon", 0),
                ("efidisk0", format!("{}:1,efitype=4m,pre-enrolled-keys=1", p.disk_storage)),
                ("sata0", format!("{},media=cdrom", pe.volid)),
                ("sata1", format!("{}:{scratch_gb},discard=on,ssd=1", p.disk_storage)),
                ("serial0", "socket"),
                ("net0", net0),
                ("boot", "order=sata0"),
                ("tags", crate::tags::WORKER),
                ("description", format!("PVE VM Studio: media worker for {} {} - removed when it is done.", prod.name, req.build)),
            ];
            let created = pve.run_task(&format!("/nodes/{}/qemu", enc(&p.node)), create, |_| {}).await;
            drop(guard);
            if pve.vm_status(&p.node, vmid).await.is_ok() {
                worker = Some(vmid);
            }
            created.context("creating the worker VM")?;
            seed::attach(pve, &p.node, vmid, "sata2", &p.disk_storage, seed_disk, &seed_name).await.context("attaching the worker's seed disk")?;
            log.line(format!("DISM: about 15-25 min per image")).await;
            let minutes = 30 + 45 * base.len() as u64 + if winre_names.is_empty() { 0 } else { 15 };
            let m = windows::run_pass(pve, log, &mut pr, &p.node, vmid, "worker", minutes).await?;
            // DISM's log first - whatever the verdict, it is what explains it.
            let dism_log = share.join("dism.log");
            if dism_log.exists() {
                let keep = work.parent().unwrap_or(work).join("dism-logs").join(format!("media-{}.log", &run_id[4..12]));
                tokio::fs::create_dir_all(keep.parent().unwrap()).await?;
                tokio::fs::copy(&dism_log, &keep).await?;
                let text = String::from_utf8_lossy(&tokio::fs::read(&dism_log).await?).into_owned();
                let errors: Vec<&str> = text.lines().filter(|l| l.contains(", Error ")).collect();
                if !errors.is_empty() {
                    log.line(format!("DISM logged {} error line(s) - the whole log is {}", errors.len(), keep.display())).await;
                    for l in errors.iter().take(40) {
                        log.debug(format!("dism.log | {}", l.trim())).await;
                    }
                }
            }
            // The failed steps' own logs: their error lines in the job, the files kept.
            if let Ok(mut rd) = tokio::fs::read_dir(share.join("logs")).await {
                let keep_dir = work.parent().unwrap_or(work).join("dism-logs");
                tokio::fs::create_dir_all(&keep_dir).await?;
                while let Ok(Some(e)) = rd.next_entry().await {
                    let name = e.file_name().to_string_lossy().into_owned();
                    let keep = keep_dir.join(format!("media-{}-{name}", &run_id[4..12]));
                    tokio::fs::copy(e.path(), &keep).await?;
                    let text = String::from_utf8_lossy(&tokio::fs::read(e.path()).await?).into_owned();
                    let errors: Vec<&str> = text.lines().filter(|l| l.contains(", Error ") || l.contains("0x8")).collect();
                    log.line(format!("{name}: {} error line(s) - kept as {}", errors.len(), keep.display())).await;
                    for l in errors.iter().take(30) {
                        log.debug(format!("{name} | {}", l.trim())).await;
                    }
                }
            }
            if !m.iter().any(|l| l == "PVS-WORKER-OK") {
                bail!("the worker failed: {}", m.iter().rev().find(|l| l.contains("FAIL") || l.starts_with("PVS-NO")).or(m.last()).cloned().unwrap_or_else(|| "no markers on its serial console".into()));
            }
            // Every update's verdict, as the worker reported it.
            let mut failed = Vec::new();
            let mut winre_ok = !winre_names.is_empty();
            for l in &m {
                let parts: Vec<&str> = l.split_whitespace().collect();
                match parts.as_slice() {
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
            if let Some(vmid) = worker.take() {
                pve.vm_destroy(&p.node, vmid).await?;
                log.ok(format!("Worker VM {vmid} removed")).await;
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
            log.ok(format!("Every image is at {} now", req.build)).await;
        } else {
            log.ok(format!("The images are at {} already - no worker needed", req.build)).await;
        }

        // ---- the ISO ----
        pr.stage(90.0, 93.0, "building the ISO");
        move_file(&install, &tree.join("sources/install.wim")).await?;
        let name = iso_name(prod, &req.build, &req.editions, &req.lang);
        let iso = dir.join(&name);
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

    if let Some(vmid) = worker
        && pve.vm_destroy(&p.node, vmid).await.is_ok()
    {
        log.line(format!("Removed worker VM {vmid}")).await;
    }
    let _ = tokio::fs::remove_dir_all(&dir).await;
    RUNS.lock().unwrap().remove(&run_id);
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
    if at == "winre" { "WinRE".into() } else { format!("image {at}") }
}

/// DISM's exit code as Windows writes HRESULTs: -2146498530 is 0x800F081E.
fn dism_code(raw: &str) -> String {
    match raw.parse::<i64>() {
        Ok(n) if n < 0 => format!("0x{:08X}", n as i32 as u32),
        Ok(n) if n > 0xFFFF => format!("0x{n:08X}"),
        Ok(n) => format!("{n} (0x{n:X})"),
        Err(_) => raw.to_owned(),
    }
}

struct PackageReport {
    summary: String,
    broken: Vec<String>,
}

/// An image's package list (dism /Get-Packages /Format:Table): how many in which state, the
/// cumulative update levels (RollupFix), and anything left half-done. "Install Pending" is
/// normal offline - the first boot finishes it.
fn package_report(table: &str) -> PackageReport {
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

/// A rename when both sides share a file system (the studio's data and the share do), a
/// copy otherwise.
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
    fn checkpoint_chain() {
        let chain = vec!["Windows11.0-KB5043080-x64.msu".to_owned(), "Windows11.0-KB5124010-x64.msu".to_owned()];
        let image = vec!["lcu/Windows11.0-KB5124010-x64.msu".to_owned(), "01-Windows11.0-KB5121794-x64.cab".to_owned()];
        let cmd = worker_cmd("https://x/worker/r/t", "", 1, &chain, &image, &["re01-Windows11.0-KB5125758-x64.cab".to_owned()], Some("SSU-26100.9539-x64.cab"));
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
