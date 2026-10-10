//! The maintenance console: `pve-vm-studio console`, a service of its own
//! (pve-vm-studio-console.service, root) on a port of its own (console_listen, 8443).
//!
//! It is there for when the studio cannot help itself: PVE's certificate not trusted (so
//! nobody can sign in - the studio's sign-in goes through PVE), the studio not starting,
//! a network or certificate to fix. One local user, `maint`, with a password the installer
//! shows once; it never signs in to the studio, and no PVE account signs in here.
//!
//! It shares the studio's files rather than talking to it: config.toml, the database, the
//! trusted CAs and pinned certificates, the TLS certificate. The studio picks changes up by
//! itself (studio_watch); what only the studio can do - start a job - goes to it as a
//! request file. Everything it changes is logged with "console:" in front.

mod configfile;
mod password;
mod probe;
mod routes;
mod shell;

use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime},
};

use anyhow::{Context, Result};
use axum::{
    extract::{ConnectInfo, FromRequestParts},
    http::{header, request::Parts, Method, StatusCode, Uri},
    response::{IntoResponse, Response},
};
use axum_extra::extract::CookieJar;
use rust_embed::RustEmbed;
use sqlx::SqlitePool;

use crate::{cas, config::Config, error::ApiError, settings, AppState};

#[derive(RustEmbed)]
#[folder = "web-console/"]
struct Assets;

const COOKIE: &str = "pvs_console";
/// Sent by the page with every change: a form on another site cannot set it.
const CHANGE_HEADER: &str = "x-console";
const IDLE: Duration = Duration::from_secs(60 * 60);
const MAX_AGE: Duration = Duration::from_secs(12 * 60 * 60);
const MAX_FAILS: u32 = 5;
const LOCK: Duration = Duration::from_secs(5 * 60);

struct Session {
    from: IpAddr,
    started: Instant,
    seen: Instant,
}

#[derive(Default)]
struct Fails {
    count: u32,
    locked_until: Option<Instant>,
}

#[derive(Clone)]
pub struct Console(Arc<Inner>);

pub struct Inner {
    config_path: PathBuf,
    /// As it was at start; `cfg()` reads the file again for what the console may change.
    boot: Config,
    db: SqlitePool,
    web: reqwest::Client,
    sessions: Mutex<HashMap<String, Session>>,
    fails: Mutex<HashMap<IpAddr, Fails>>,
    /// Whether the configured PVE node's certificate is trusted, checked every minute: the
    /// mark on "PVE connection". None: not reached.
    pve_ok: Mutex<Option<bool>>,
}

impl std::ops::Deref for Console {
    type Target = Inner;
    fn deref(&self) -> &Inner {
        &self.0
    }
}

impl Console {
    /// config.toml as it is now.
    pub fn cfg(&self) -> Config {
        Config::load_from(&self.config_path).unwrap_or_else(|_| self.boot.clone())
    }

    pub fn data_dir(&self) -> &Path {
        &self.boot.data_dir
    }

    fn off_flag(&self) -> PathBuf {
        off_flag(&self.boot.data_dir)
    }
}

/// A PVE error that comes from its certificate not being trusted.
pub fn cert_problem(msg: &str) -> bool {
    probe::is_tls_error(msg)
}

/// Present: the console is switched off (Studio settings → Maintenance console).
pub fn off_flag(data_dir: &Path) -> PathBuf {
    data_dir.join("console-off")
}

/// Where the console leaves what only the studio can do (rebuilds), and finds its answer.
pub fn requests_dir(data_dir: &Path) -> PathBuf {
    data_dir.join("console-requests")
}

/// Files the console writes into the data folder belong to the studio's user, like the
/// folder: the studio runs unprivileged and must read and replace them.
pub fn give_to_studio(data_dir: &Path, path: &Path) {
    use std::os::unix::fs::MetadataExt;
    if let Ok(m) = std::fs::metadata(data_dir) {
        let _ = std::os::unix::fs::chown(path, Some(m.uid()), Some(m.gid()));
    }
}

/// Jobs the studio runs or has queued - what a restart would cut off.
pub async fn busy_jobs(db: &SqlitePool) -> Vec<(String, String)> {
    sqlx::query_as("SELECT id, title FROM jobs WHERE status IN ('running', 'queued') ORDER BY created_at")
        .fetch_all(db)
        .await
        .unwrap_or_default()
}

// ---- the service ----

pub async fn run(config: Config) -> Result<()> {
    let addr = config.console_listen;
    if addr == config.listen {
        anyhow::bail!("console_listen ({addr}) is the studio's own listen address - give the console a port of its own");
    }
    tokio::fs::create_dir_all(&config.data_dir).await.ok();
    let db = crate::open_db(&config.data_dir).await?;
    // A file SQLite creates for root would lock the studio out of its own database.
    for f in ["studio.db", "studio.db-wal", "studio.db-shm"] {
        give_to_studio(&config.data_dir, &config.data_dir.join(f));
    }
    let log: crate::logging::LogSettings = settings::load(&db, "log").await.unwrap_or_default();
    crate::logging::apply(log.effective());
    let console = Console(Arc::new(Inner {
        config_path: config.path.clone(),
        boot: config.clone(),
        db,
        web: reqwest::Client::builder()
            .user_agent(concat!("pve-vm-studio-console/", env!("CARGO_PKG_VERSION")))
            .timeout(Duration::from_secs(120))
            .build()?,
        sessions: Default::default(),
        fails: Default::default(),
        pve_ok: Default::default(),
    }));
    if password::read(&config.console_password_file())?.is_none() {
        tracing::warn!("console: no password set yet - on the node: pct exec <ct> -- pve-vm-studio console-password --reset");
    }
    let app = routes::router(console.clone()).fallback(static_file);
    tokio::spawn(console_watch(console.clone()));
    let paths = crate::tls::Paths::new(&config.data_dir);
    if config.plain_http {
        tracing::warn!("console: plain_http is set - serving HTTP on http://{addr}");
        let listener = tokio::net::TcpListener::bind(addr).await.with_context(|| format!("binding {addr}"))?;
        axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await?;
    } else {
        // The studio's certificate. Until the studio has made one, the console waits for it.
        while !paths.cert.exists() {
            tracing::info!("console: waiting for the studio's certificate ({})", paths.cert.display());
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
        let tls = axum_server::tls_rustls::RustlsConfig::from_pem_file(&paths.cert, &paths.key).await.context("loading the TLS certificate")?;
        tokio::spawn(reload_tls(paths, tls.clone()));
        tracing::info!("console: listening on https://{addr}");
        axum_server::bind_rustls(addr, tls).serve(app.into_make_service_with_connect_info::<SocketAddr>()).await?;
    }
    Ok(())
}

fn mtime(p: &Path) -> Option<SystemTime> {
    std::fs::metadata(p).and_then(|m| m.modified()).ok()
}

/// A new certificate (from the studio's renewal or from here) is served from the next connection.
async fn reload_tls(paths: crate::tls::Paths, tls: axum_server::tls_rustls::RustlsConfig) {
    let mut last = mtime(&paths.cert);
    loop {
        tokio::time::sleep(Duration::from_secs(5)).await;
        let now = mtime(&paths.cert);
        if now != last {
            last = now;
            match tls.reload_from_pem_file(&paths.cert, &paths.key).await {
                Ok(()) => tracing::info!("console: TLS certificate reloaded"),
                Err(e) => tracing::warn!("console: reloading the TLS certificate: {e}"),
            }
        }
    }
}

/// The console's own housekeeping: the log level, sessions nobody uses any more, and
/// whether PVE is trusted.
async fn console_watch(c: Console) {
    let mut level = String::new();
    let mut checked: Option<Instant> = None;
    loop {
        if checked.is_none_or(|t| t.elapsed() >= Duration::from_secs(60)) {
            checked = Some(Instant::now());
            let ok = routes::probe_configured(&c).await;
            *c.pve_ok.lock().unwrap() = ok;
        }
        let s: crate::logging::LogSettings = settings::load(&c.db, "log").await.unwrap_or_default();
        if s.effective() != level {
            level = s.effective().to_owned();
            crate::logging::apply(&level);
        }
        c.sessions.lock().unwrap().retain(|_, s| s.seen.elapsed() < IDLE && s.started.elapsed() < MAX_AGE);
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

async fn static_file(uri: Uri) -> Response {
    let path = uri.path().trim_start_matches('/');
    let (path, file) = match Assets::get(path) {
        Some(f) if !path.is_empty() => (path, f),
        _ => match Assets::get("index.html") {
            Some(f) => ("index.html", f),
            None => return StatusCode::NOT_FOUND.into_response(),
        },
    };
    let mime = mime_guess::from_path(path).first_or_octet_stream();
    ([(header::CONTENT_TYPE, mime.as_ref().to_owned()), (header::CACHE_CONTROL, "no-cache".to_owned())], file.data).into_response()
}

// ---- signing in ----

/// The signed-in console user. A handler that takes it is private; it also refuses
/// everything while the console is switched off, and a change without the page's header.
pub struct Maint {
    pub from: IpAddr,
}

impl FromRequestParts<Console> for Maint {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, c: &Console) -> Result<Self, ApiError> {
        if c.off_flag().exists() {
            return Err(switched_off());
        }
        let jar = CookieJar::from_headers(&parts.headers);
        let id = jar.get(COOKIE).map(|k| k.value().to_owned()).ok_or_else(not_signed_in)?;
        let from = peer(parts);
        {
            let mut sessions = c.sessions.lock().unwrap();
            let s = sessions.get_mut(&id).ok_or_else(not_signed_in)?;
            if s.seen.elapsed() >= IDLE || s.started.elapsed() >= MAX_AGE {
                sessions.remove(&id);
                return Err(not_signed_in());
            }
            s.seen = Instant::now();
            if s.from != from {
                tracing::info!("console: session moved from {} to {from}", s.from);
                s.from = from;
            }
        }
        if parts.method != Method::GET && parts.method != Method::HEAD && !parts.headers.contains_key(CHANGE_HEADER) {
            return Err(ApiError::new(StatusCode::FORBIDDEN, "missing the console's header"));
        }
        Ok(Maint { from })
    }
}

fn peer(parts: &Parts) -> IpAddr {
    parts.extensions.get::<ConnectInfo<SocketAddr>>().map(|c| c.0.ip()).unwrap_or(IpAddr::from([0, 0, 0, 0]))
}

fn not_signed_in() -> ApiError {
    ApiError::new(StatusCode::UNAUTHORIZED, "not signed in")
}

fn switched_off() -> ApiError {
    ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "the maintenance console is switched off (Studio settings) - on the node: pct exec <ct> -- pve-vm-studio console-enable")
}

/// One line per sign-in attempt, the newest last; kept to the last 500.
fn signin_log(data_dir: &Path) -> PathBuf {
    data_dir.join("console-signins.log")
}

fn note_signin(data_dir: &Path, from: IpAddr, ok: bool, what: &str) {
    let p = signin_log(data_dir);
    let mut lines: Vec<String> = std::fs::read_to_string(&p).unwrap_or_default().lines().map(str::to_owned).collect();
    lines.push(serde_json::json!({ "at": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true), "from": from.to_string(), "ok": ok, "what": what }).to_string());
    let keep = lines.len().saturating_sub(500);
    let _ = std::fs::write(&p, lines[keep..].join("\n") + "\n");
    give_to_studio(data_dir, &p);
}

pub fn recent_signins(data_dir: &Path, n: usize) -> Vec<serde_json::Value> {
    let text = std::fs::read_to_string(signin_log(data_dir)).unwrap_or_default();
    let mut v: Vec<serde_json::Value> = text.lines().filter_map(|l| serde_json::from_str(l).ok()).collect();
    v.reverse();
    v.truncate(n);
    v
}

/// Checks the password; a new session id on success.
pub async fn sign_in(c: &Console, from: IpAddr, pw: String) -> Result<String, ApiError> {
    if c.off_flag().exists() {
        return Err(switched_off());
    }
    {
        let mut fails = c.fails.lock().unwrap();
        let f = fails.entry(from).or_default();
        if let Some(until) = f.locked_until {
            if until > Instant::now() {
                let mins = (until - Instant::now()).as_secs().div_ceil(60);
                return Err(ApiError::new(StatusCode::TOO_MANY_REQUESTS, format!("too many wrong passwords - locked for {mins} more minute(s)")));
            }
            f.locked_until = None;
            f.count = 0;
        }
    }
    let file = c.boot.console_password_file();
    let stored = password::read(&file).map_err(|e| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, format!("{e:#}")))?;
    let Some(stored) = stored else {
        return Err(ApiError::new(StatusCode::CONFLICT, "no console password is set - on the node: pct exec <ct> -- pve-vm-studio console-password --reset"));
    };
    // PBKDF2 at 600,000 rounds: off the async threads.
    let ok = tokio::task::spawn_blocking(move || password::verify(&stored, &pw)).await.unwrap_or(false);
    if !ok {
        let left = {
            let mut fails = c.fails.lock().unwrap();
            let f = fails.entry(from).or_default();
            f.count += 1;
            if f.count >= MAX_FAILS {
                f.locked_until = Some(Instant::now() + LOCK);
            }
            MAX_FAILS.saturating_sub(f.count)
        };
        note_signin(c.data_dir(), from, false, "wrong password");
        tracing::warn!("console: wrong password from {from}");
        return Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            match left {
                0 => "Wrong password. The console is locked for 5 minutes.".to_owned(),
                1 => "Wrong password. 1 try left before a 5-minute lock.".to_owned(),
                n => format!("Wrong password. {n} tries left before a 5-minute lock."),
            },
        ));
    }
    c.fails.lock().unwrap().remove(&from);
    let id = random_id();
    c.sessions.lock().unwrap().insert(id.clone(), Session { from, started: Instant::now(), seen: Instant::now() });
    note_signin(c.data_dir(), from, true, "signed in");
    tracing::info!("console: {} signed in from {from}", password::USER);
    Ok(id)
}

pub fn sign_out(c: &Console, jar: &CookieJar) {
    if let Some(k) = jar.get(COOKIE) {
        c.sessions.lock().unwrap().remove(k.value());
    }
}

/// Every session but this one ends (after a password change).
pub fn end_other_sessions(c: &Console, jar: &CookieJar) {
    let keep = jar.get(COOKIE).map(|k| k.value().to_owned()).unwrap_or_default();
    c.sessions.lock().unwrap().retain(|id, _| *id == keep);
}

pub fn session_cookie(id: String, secure: bool) -> axum_extra::extract::cookie::Cookie<'static> {
    axum_extra::extract::cookie::Cookie::build((COOKIE, id))
        .path("/")
        .http_only(true)
        .secure(secure)
        .same_site(axum_extra::extract::cookie::SameSite::Strict)
        .build()
}

fn random_id() -> String {
    use ring::rand::SecureRandom;
    let mut b = [0u8; 32];
    ring::rand::SystemRandom::new().fill(&mut b).expect("system random");
    b.iter().map(|x| format!("{x:02x}")).collect()
}

// ---- commands on the node ----

/// `pve-vm-studio console-password [--init] [--reset] [--quiet]`:
/// --init sets one only when none is set (installer, update), --reset always sets a new one.
/// The new password goes to stdout - with --quiet alone on its line, for a script to show.
pub fn password_command(config: &Config, args: Vec<String>) -> Result<()> {
    let file = config.console_password_file();
    let quiet = args.iter().any(|a| a == "--quiet");
    let init = args.iter().any(|a| a == "--init");
    if !init && !args.iter().any(|a| a == "--reset") {
        println!("pve-vm-studio console-password --reset    a new password for the maintenance console's user {}", password::USER);
        println!("pve-vm-studio console-password --init     the same, only when none is set yet");
        return Ok(());
    }
    if init && password::read(&file)?.is_some() {
        return Ok(());
    }
    let pw = password::generate();
    password::write(&file, &pw, if init { "installer" } else { "console-password --reset" })?;
    let shown = password::grouped(&pw);
    if quiet {
        println!("{shown}");
    } else {
        println!();
        println!("  Maintenance console   https://<studio>:{}", config.console_listen.port());
        println!("  User                  {}", password::USER);
        println!("  Password              {shown}");
        println!();
        println!("  Write the password down now - it is shown only this once.");
        println!();
    }
    Ok(())
}

/// `pve-vm-studio console-enable`: switches the console back on.
pub fn enable_command(config: &Config) -> Result<()> {
    match std::fs::remove_file(off_flag(&config.data_dir)) {
        Ok(()) => println!("The maintenance console is on again: https://<studio>:{}", config.console_listen.port()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => println!("The maintenance console is on."),
        Err(e) => return Err(e).context("switching the console on"),
    }
    Ok(())
}

// ---- the studio's side ----

/// In the studio: what the console changed takes effect within seconds - trusted CAs and
/// pinned certificates, the TLS certificate, the log level - and its requests are run.
pub async fn studio_watch(app: AppState) {
    let data = app.config.data_dir.clone();
    let (cas_p, pins_p, cert_p) = (cas::path(&data), cas::pins_path(&data), crate::tls::Paths::new(&data).cert);
    let (mut cas_t, mut pins_t, mut cert_t) = (mtime(&cas_p), mtime(&pins_p), mtime(&cert_p));
    let mut level = String::new();
    loop {
        tokio::time::sleep(Duration::from_secs(3)).await;
        if mtime(&cas_p) != cas_t {
            cas_t = mtime(&cas_p);
            let added: Vec<Vec<u8>> = cas::read_file(&cas_p).into_iter().map(|c| c.der).collect();
            match app.pve.set_extra_cas(&added) {
                Ok(()) => tracing::info!("trusted CAs reloaded: {} added", added.len()),
                Err(e) => tracing::warn!("reloading the trusted CAs: {e:#}"),
            }
        }
        if mtime(&pins_p) != pins_t {
            pins_t = mtime(&pins_p);
            let pins = cas::read_pins(&data);
            app.pve.set_pins(cas::pin_digests(&pins));
            tracing::info!("pinned PVE certificates reloaded: {}", pins.len());
        }
        if mtime(&cert_p) != cert_t {
            cert_t = mtime(&cert_p);
            if let Some(tls) = &app.tls {
                let paths = crate::tls::Paths::new(&data);
                match tls.reload_from_pem_file(&paths.cert, &paths.key).await {
                    Ok(()) => tracing::info!("TLS certificate reloaded"),
                    Err(e) => tracing::warn!("reloading the TLS certificate: {e}"),
                }
            }
        }
        let s: crate::logging::LogSettings = settings::load(&app.db, "log").await.unwrap_or_default();
        if s.effective() != level {
            if !level.is_empty() {
                tracing::info!("log level: {}", s.effective());
            }
            level = s.effective().to_owned();
            crate::logging::apply(&level);
        }
        take_requests(&app).await;
    }
}

/// A request file: {"action": "rebuild", "kind": "winpe" | "media"}. The answer goes beside
/// it as <id>.done: {"job": id} or {"error": text}.
async fn take_requests(app: &AppState) {
    let dir = requests_dir(&app.config.data_dir);
    let Ok(mut rd) = tokio::fs::read_dir(&dir).await else { return };
    while let Ok(Some(e)) = rd.next_entry().await {
        let p = e.path();
        if p.extension().and_then(|x| x.to_str()) != Some("json") {
            // Answers nobody fetched go after ten minutes.
            if mtime(&p).and_then(|t| t.elapsed().ok()).is_some_and(|a| a > Duration::from_secs(600)) {
                let _ = tokio::fs::remove_file(&p).await;
            }
            continue;
        }
        let text = tokio::fs::read_to_string(&p).await.unwrap_or_default();
        let _ = tokio::fs::remove_file(&p).await;
        let req: serde_json::Value = serde_json::from_str(&text).unwrap_or_default();
        let answer = match (req["action"].as_str(), req["kind"].as_str()) {
            (Some("rebuild"), Some(kind @ ("winpe" | "media"))) => match crate::api::rebuild_last(app, kind, "console (maint)").await {
                Ok(job) => {
                    tracing::info!("console: rebuild of the last {kind} started as job {job}");
                    serde_json::json!({ "job": job })
                }
                Err(e) => serde_json::json!({ "error": e.to_string() }),
            },
            _ => serde_json::json!({ "error": "the studio does not know that request" }),
        };
        let _ = tokio::fs::write(p.with_extension("done"), answer.to_string()).await;
    }
}
