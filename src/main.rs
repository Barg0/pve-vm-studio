//! PVE VM Studio - design VMs in the browser, bake golds and deploy them on Proxmox VE.
//!
//! One binary: the REST API, the job runner and the web UI (embedded at build time).
//! It runs in an LXC and talks to the cluster through the PVE API only.

mod api;
mod apps;
mod auth;
mod autoupdate;
mod cas;
mod catalog;
mod config;
mod console;
mod error;
mod cis;
mod fod;
mod golds;
mod guest;
mod hardware;
mod jobs;
mod labs;
mod linux;
mod logging;
mod mail;
mod maintenance;
mod markers;
mod notify;
mod progress;
mod pve;
mod seed;
mod selfnet;
mod serial;
mod settings;
mod tags;
mod tls;
mod units;
mod uup;
mod virtio;
mod vms;
mod web;
mod wim;
mod winget;
mod wu;
mod windows;
mod winpe;
mod media;
mod update;

use std::sync::Arc;

use anyhow::{Context, Result};
use axum::{
    extract::{Path, Request},
    http::{header, StatusCode, Uri},
    response::{IntoResponse, Redirect, Response},
    routing::get,
    Router,
};
use axum_server::tls_rustls::RustlsConfig;
use sqlx::{
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions},
    SqlitePool,
};

use crate::{auth::Sessions, config::Config, jobs::Jobs, pve::Pve};

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub pve: Pve,
    pub db: SqlitePool,
    /// For the outside world (published checksums), not for PVE.
    pub web: reqwest::Client,
    pub sessions: Sessions,
    pub jobs: Jobs,
    /// The live TLS configuration, reloaded when the certificate changes. None on plain HTTP.
    pub tls: Option<RustlsConfig>,
}

impl AppState {
    pub fn bake_ctx(&self) -> golds::BakeCtx {
        golds::BakeCtx {
            pve: self.pve.clone(),
            db: self.db.clone(),
            web: self.web.clone(),
            work: self.config.data_dir.join("work"),
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    logging::init();

    // Two crypto back-ends end up linked (ring and aws-lc-rs, through different crates);
    // rustls then needs to be told which one serves the process.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let config = Config::load()?;

    // The maintenance console and its user: `console` is the service of its own
    // (pve-vm-studio-console.service), the rest are run by hand or by the installer.
    match std::env::args().nth(1).as_deref() {
        Some("console") => return console::run(config).await,
        Some("console-password") => return console::password_command(&config, std::env::args().skip(2).collect()),
        Some("console-enable") => return console::enable_command(&config),
        Some("install-units") => return units::install(),
        // The studio itself takes no arguments: a word it does not know is a mistake (or a
        // command of a newer version), never a reason to start a second studio.
        Some("serial") | None => {}
        Some(other) => anyhow::bail!("unknown command '{other}' - pve-vm-studio [console | console-password | console-enable | install-units | serial]"),
    }

    // `pve-vm-studio serial <node> <vmid> [seconds]`: print a VM's serial console - what
    // the Windows bake reads WinPE's markers through - for checking that path by hand.
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("serial") && args.len() >= 4 {
        let pve = Pve::new(&config.pve)?;
        let vmid: u32 = args[3].parse().context("vmid")?;
        let secs: u64 = args.get(4).and_then(|s| s.parse().ok()).unwrap_or(20);
        let mut lines = serial::open(&pve, &args[2], vmid).await?;
        let deadline = tokio::time::sleep(std::time::Duration::from_secs(secs));
        tokio::pin!(deadline);
        loop {
            tokio::select! {
                l = lines.recv() => match l { Some(l) => println!("{l}"), None => break },
                () = &mut deadline => break,
            }
        }
        return Ok(());
    }
    tokio::fs::create_dir_all(&config.data_dir)
        .await
        .with_context(|| format!("creating {}", config.data_dir.display()))?;

    let db = open_db(&config.data_dir).await?;
    tokio::fs::create_dir_all(config.data_dir.join("work")).await?;
    // Debug tools off: none of them stays on from a time they were.
    if !config.debug_tools {
        let mut w: media::WorkerSettings = settings::load(&db, "worker").await.unwrap_or_default();
        if w.keep_downloads {
            w.keep_downloads = false;
            settings::save(&db, "worker", &w).await?;
        }
    }
    // A gold whose bake was cut off by a restart never finished.
    sqlx::query("UPDATE golds SET status = 'failed' WHERE status = 'baking'").execute(&db).await?;

    // ---- TLS ----
    let paths = tls::Paths::new(&config.data_dir);
    let tls_live = if config.plain_http {
        None
    } else {
        if let Some(old) = &config.tls
            && !paths.cert.exists()
            && old.cert.exists()
        {
            // Take over the certificate an older install named in config.toml.
            let (c, k) = (tokio::fs::read(&old.cert).await?, tokio::fs::read(&old.key).await?);
            tls::install(&paths, None, &c, &k).await.context("taking over the configured certificate")?;
        }
        let mut server: tls::ServerSettings = settings::load(&db, "server").await?;
        if server.fqdn.is_empty()
            && let Some(f) = config.fqdn.as_ref().filter(|f| !f.is_empty())
        {
            server.fqdn = f.clone();
            settings::save(&db, "server", &server).await?;
        }
        tls::ensure(&paths, &server.fqdn).await?;
        Some(RustlsConfig::from_pem_file(&paths.cert, &paths.key).await.context("loading the TLS certificate")?)
    };
    let (renewed_tx, mut renewed_rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(tls::renew_loop(db.clone(), tls::Paths::new(&config.data_dir), tls_live.clone(), renewed_tx));
    let update_outcome;

    let state = AppState {
        pve: Pve::new(&config.pve)?,
        web: reqwest::Client::builder()
            .user_agent(concat!("pve-vm-studio/", env!("CARGO_PKG_VERSION")))
            .timeout(std::time::Duration::from_secs(60))
            .build()?,
        sessions: Sessions::load(config.data_dir.join("sessions.json")),
        jobs: {
            // An update ends in the process after the restart: close it before the jobs
            // table marks the running ones interrupted.
            update_outcome = update::finish_pending(&db, &config.data_dir, &config.jobs_dir()).await;
            Jobs::new(db.clone(), config.jobs_dir()).await?
        },
        db,
        tls: tls_live.clone(),
        config: Arc::new(config),
    };

    // The CAs an admin added in Studio settings, trusted for PVE before the first call to it.
    let added: Vec<Vec<u8>> = cas::read_file(&cas::path(&state.config.data_dir)).into_iter().map(|c| c.der).collect();
    if let Err(e) = state.pve.set_extra_cas(&added) {
        tracing::warn!("trusting the added CAs: {e:#}");
    }
    // And the node certificates trusted as they are (maintenance console).
    state.pve.set_pins(cas::pin_digests(&cas::read_pins(&state.config.data_dir)));
    tokio::spawn(console::studio_watch(state.clone()));

    // ISO builds at a time, as Image settings has it.
    let worker: media::WorkerSettings = settings::load(&state.db, "worker").await.unwrap_or_default();
    state.jobs.set_lane_limit("media", worker.parallel as usize);
    tokio::spawn(pve_nodes_loop(state.clone()));
    tokio::spawn(reconcile_after_restart(state.clone()));
    tokio::spawn(warm_caches(state.clone()));
    tokio::spawn(wu_loop(state.clone()));
    tokio::spawn(clean_work(state.clone()));
    tokio::spawn(autoupdate::scheduler(state.clone()));
    tokio::spawn(notify::watch_loop(state.clone()));
    // Mails: every job's end, the certificate renewal, and what the last stop cut off.
    {
        let app = state.clone();
        state.jobs.on_end(Arc::new(move |id| {
            tokio::spawn(notify::job_ended(app.clone(), id));
        }));
        let app = state.clone();
        tokio::spawn(async move {
            while let Some(r) = renewed_rx.recv().await {
                notify::cert_renewal(app.clone(), r).await;
            }
        });
        let interrupted = state.jobs.interrupted.as_ref().clone();
        tokio::spawn(notify::after_restart(state.clone(), update_outcome, interrupted));
    }

    let app = Router::new()
        .nest("/api", api::router().layer(axum::middleware::from_fn(time_request)))
        .merge(media::worker_router())
        .fallback(web::static_file)
        .with_state(state.clone());

    if let Some(addr) = state.config.http_listen {
        let webroot = paths.webroot.clone();
        let https_port = state.config.listen.port();
        let plain = Router::new()
            .route(
                "/.well-known/acme-challenge/{token}",
                get(move |Path(token): Path<String>| acme_challenge(webroot.clone(), token)),
            )
            .fallback(move |req: Request| async move { to_https(req.uri(), req.headers(), https_port) });
        let listener = tokio::net::TcpListener::bind(addr).await.with_context(|| format!("binding {addr}"))?;
        tracing::info!("listening on http://{addr} (ACME challenges, redirect to HTTPS)");
        tokio::spawn(async move {
            if let Err(e) = axum::serve(listener, plain).await {
                tracing::error!("port-80 listener: {e}");
            }
        });
    }

    let addr = state.config.listen;
    match tls_live {
        Some(rustls) => {
            tracing::info!("listening on https://{addr}");
            axum_server::bind_rustls(addr, rustls).serve(app.into_make_service()).await?;
        }
        None => {
            tracing::warn!("plain_http is set - serving HTTP on http://{addr}");
            let listener = tokio::net::TcpListener::bind(addr).await?;
            axum::serve(listener, app).await?;
        }
    }
    Ok(())
}

/// The studio's database, its schema up to date - the studio's and the console's.
pub async fn open_db(data_dir: &std::path::Path) -> Result<SqlitePool> {
    let db = SqlitePoolOptions::new()
        .max_connections(8)
        .connect_with(
            SqliteConnectOptions::new()
                .filename(data_dir.join("studio.db"))
                .create_if_missing(true)
                .journal_mode(SqliteJournalMode::Wal)
                .busy_timeout(std::time::Duration::from_secs(10)),
        )
        .await?;
    sqlx::migrate!().run(&db).await?;
    Ok(db)
}

/// A file certbot put into the webroot for Let's Encrypt to fetch.
async fn acme_challenge(webroot: std::path::PathBuf, token: String) -> Response {
    if token.is_empty() || !token.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
        return StatusCode::NOT_FOUND.into_response();
    }
    match tokio::fs::read(webroot.join(".well-known/acme-challenge").join(&token)).await {
        Ok(body) => ([(header::CONTENT_TYPE, "text/plain")], body).into_response(),
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}

fn to_https(uri: &Uri, headers: &axum::http::HeaderMap, port: u16) -> Response {
    let host = headers
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .map(|h| h.split(':').next().unwrap_or(h).to_owned())
        .unwrap_or_default();
    if host.is_empty() {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let port = if port == 443 { String::new() } else { format!(":{port}") };
    let path = uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
    Redirect::permanent(&format!("https://{host}{port}{path}")).into_response()
}

/// Every API call's time: slow ones (250 ms and up) at info, the rest at debug - where the
/// studio spends its time, without a profiler. The event stream of a job is left out; it
/// is meant to stay open.
async fn time_request(req: axum::extract::Request, next: axum::middleware::Next) -> axum::response::Response {
    let (method, path) = (req.method().clone(), req.uri().path().to_owned());
    let start = std::time::Instant::now();
    let res = next.run(req).await;
    let ms = start.elapsed().as_millis();
    if !path.ends_with("/events") {
        if ms >= 250 {
            tracing::info!("{method} /api{path} -> {} in {ms} ms", res.status().as_u16());
        } else {
            tracing::debug!("{method} /api{path} -> {} in {ms} ms", res.status().as_u16());
        }
    }
    res
}

/// Everything slow the UI waits for on a first visit, done in the background instead: the
/// editions of every Windows ISO (7z reads through the whole install.wim to its index), each
/// ISO's SHA-256 for the sidecar, the virtio-win releases, lego's DNS providers. All of it
/// is cached, so after the first pass a round costs a directory listing. Repeated every
/// ten minutes for ISOs uploaded since.
/// The work folder holds only what running jobs build - seed disks, WinPE trees, media
/// downloads; every job removes its own. What a crash or a restart left behind goes here:
/// every five minutes, and only while no job runs, anything in it untouched for ten minutes
/// (a job that is just starting has written seconds ago) - the download cache of Windows
/// media builds after six hours, so a failed build can be retried without downloading again. The volume is mounted with
/// discard, so the space goes back to the storage at once.
async fn clean_work(app: AppState) {
    let work = app.config.data_dir.join("work");
    loop {
        if app.jobs.idle().await
            && let Ok(mut entries) = tokio::fs::read_dir(&work).await
        {
            let mut freed = 0u64;
            let mut removed = Vec::new();
            while let Ok(Some(e)) = entries.next_entry().await {
                let Ok(meta) = e.metadata().await else { continue };
                // The Windows media download cache waits six hours for a retry of a failed build.
                // So does the work folder of a media build that can be continued (Jobs → Continue).
                let resumable = e.file_name().to_string_lossy().starts_with("media-run-") && e.path().join(media::CHECKPOINT).exists();
                let limit = if e.file_name() == "uup-files" || resumable { 6 * 3600 } else { 600 };
                // Kept downloads (Media worker card) stay until the switch goes off.
                if e.file_name() == "uup-files"
                    && settings::load::<media::WorkerSettings>(&app.db, "worker").await.unwrap_or_default().keep_downloads
                {
                    continue;
                }
                let old = meta.modified().ok().and_then(|m| m.elapsed().ok()).is_some_and(|age| age.as_secs() > limit);
                // lost+found belongs to the volume's file system, not to a job.
                if !old || e.file_name() == "lost+found" || !app.jobs.idle().await {
                    continue;
                }
                let path = e.path();
                let size = dir_size(&path).await;
                let gone = if meta.is_dir() { tokio::fs::remove_dir_all(&path).await } else { tokio::fs::remove_file(&path).await };
                if gone.is_ok() {
                    freed += size;
                    removed.push(e.file_name().to_string_lossy().into_owned());
                }
            }
            if !removed.is_empty() {
                tracing::info!("work folder: removed {} leftover(s), {:.1} GB: {}", removed.len(), freed as f64 / 1e9, removed.join(", "));
            }
        }
        tokio::time::sleep(std::time::Duration::from_secs(300)).await;
    }
}

pub async fn dir_size(path: &std::path::Path) -> u64 {
    let mut total = 0;
    let mut stack = vec![path.to_path_buf()];
    while let Some(p) = stack.pop() {
        let Ok(meta) = tokio::fs::symlink_metadata(&p).await else { continue };
        if meta.is_dir() {
            if let Ok(mut rd) = tokio::fs::read_dir(&p).await {
                while let Ok(Some(e)) = rd.next_entry().await {
                    stack.push(e.path());
                }
            }
        } else {
            total += meta.len();
        }
    }
    total
}

/// The cluster's nodes as further ways to the PVE API (failover when the configured node is
/// down): the ones known from before right away - so a restart with that node down still
/// gets through - then asked of PVE every two minutes, so a certificate name configured in
/// PVE (an ACME domain) is known before the certificate is ordered.
async fn pve_nodes_loop(app: AppState) {
    let known: Vec<pve::NodeEndpoint> = settings::load(&app.db, "pve_nodes").await.unwrap_or_default();
    app.pve.set_nodes(&known);
    let mut last = known;
    loop {
        match app.pve.discover_nodes().await.map(|mut nodes| {
            // Names only grow: a node that is offline, or a call that failed, keeps the ones
            // learned before - they are what lets its new certificate through later.
            for n in &mut nodes {
                if let Some(old) = last.iter().find(|o| o.node == n.node) {
                    for name in &old.names {
                        if !n.names.contains(name) {
                            n.names.push(name.clone());
                        }
                    }
                    n.names.sort();
                }
            }
            nodes
        }) {
            Ok(nodes) if nodes != last => {
                tracing::info!("PVE reachable through {} node(s): {}", nodes.len(), nodes.iter().map(|n| if n.tls_name.is_empty() { format!("{} ({})", n.node, n.ip) } else { format!("{} ({} as {})", n.node, n.ip, n.tls_name) }).collect::<Vec<_>>().join(", "));
                app.pve.set_nodes(&nodes);
                if let Err(e) = settings::save(&app.db, "pve_nodes", &nodes).await {
                    tracing::warn!("saving the PVE nodes: {e:#}");
                }
                last = nodes;
            }
            Ok(_) => {}
            Err(e) => tracing::warn!("asking PVE for its nodes: {e:#}"),
        }
        tokio::time::sleep(std::time::Duration::from_secs(120)).await;
    }
}

async fn warm_caches(app: AppState) {
    virtio::load_known(&app.db).await;
    // Right after a boot the resolver can fail for minutes; ask fedorapeople again until it
    // answers in full, beside the rest of the warming.
    let a = app.clone();
    tokio::spawn(async move {
        for _ in 0..20 {
            if virtio::complete(&virtio::upstream(&a.web, &a.db).await) {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_secs(61)).await;
        }
    });
    tls::dns_providers().await;
    loop {
        let mut isos = Vec::new();
        if let Ok(mut stores) = tokio::fs::read_dir(&app.config.iso_root).await {
            while let Ok(Some(store)) = stores.next_entry().await {
                let Ok(mut files) = tokio::fs::read_dir(store.path()).await else { continue };
                while let Ok(Some(f)) = files.next_entry().await {
                    let name = f.file_name().to_string_lossy().to_lowercase();
                    if name.ends_with(".iso") && !name.starts_with("pvs-") && !name.starts_with("virtio-win") {
                        isos.push(f.path());
                    }
                }
            }
        }
        for iso in isos {
            let started = std::time::Instant::now();
            if wim::inspect(&iso, &app.config.data_dir.join("wim-cache.json")).await.is_ok() {
                let _ = golds::iso_sha256(&iso, &app.config.data_dir.join("iso-sha256-cache.json")).await;
            }
            if started.elapsed().as_secs() >= 1 {
                tracing::info!("cached {} in {} s", iso.display(), started.elapsed().as_secs());
            }
        }
        tokio::time::sleep(std::time::Duration::from_secs(600)).await;
    }
}

/// What a restart leaves behind. A job dies with the process (Jobs::new marks it
/// interrupted) and never reaches its own cleanup, so at startup - when no job can be
/// running - the studio does it: the golds and VMs those jobs were making are marked failed,
/// every seed ISO goes (they carry passwords, and none can be in use now), and every bake VM
/// is destroyed. Bake VMs are only ever bake-<id>, tagged bake (pvs-bake before), never a template.
async fn reconcile_after_restart(app: AppState) {
    let db = &app.db;
    for (what, sql) in [
        ("golds left baking", "UPDATE golds SET status = 'failed' WHERE status = 'baking'"),
        ("VMs left building", "UPDATE vms SET status = 'failed' WHERE status = 'building'"),
    ] {
        if let Ok(r) = sqlx::query(sql).execute(db).await
            && r.rows_affected() > 0
        {
            tracing::info!("{} {what} by the restart are marked failed", r.rows_affected());
        }
    }
    let Ok(res) = app.pve.resources().await else { return };
    let mut seen = std::collections::HashSet::new();
    // Seeds were ISOs once and are uploaded disk images (content "import") now - both go.
    let mut stores: Vec<(&pve::Resource, &str)> = Vec::new();
    for r in res.iter().filter(|r| r.kind == "storage" && r.status.as_deref() == Some("available")) {
        for c in ["iso", "import"] {
            if r.has_content(c) {
                stores.push((r, c));
            }
        }
    }
    for (st, content) in stores {
        let (Some(node), Some(storage)) = (st.node.as_deref(), st.storage.as_deref()) else { continue };
        for v in app.pve.storage_content(node, storage, content).await.unwrap_or_default() {
            let file = v.volid.rsplit('/').next().unwrap_or("");
            if file.starts_with("pvs-seed-") && seen.insert(v.volid.clone()) {
                match app.pve.delete_volume(node, &v.volid).await {
                    Ok(()) => tracing::info!("removed leftover seed {}", v.volid),
                    Err(e) => tracing::warn!("could not remove leftover seed {}: {e:#}", v.volid),
                }
            }
        }
    }
    // Older golds were named pve-<id>; a gold is its id alone now - template and record.
    let golds: Vec<(String, String, String, Option<i64>)> =
        sqlx::query_as("SELECT id, name, node, vmid FROM golds WHERE status = 'ready' AND name LIKE 'pve-%'").fetch_all(db).await.unwrap_or_default();
    for (id, name, node, vmid) in golds {
        let Some(vmid) = vmid else { continue };
        if name != format!("pve-{id}") {
            continue;
        }
        if app.pve.vm_set(&node, vmid as u32, crate::form![("name", &id)]).await.is_ok() {
            let _ = sqlx::query("UPDATE golds SET name = ? WHERE id = ?").bind(&id).bind(&id).execute(db).await;
            tracing::info!("gold {name} is named {id} now");
        }
    }
    retag(&app, &res).await;
    for vm in res.iter().filter(|r| {
        r.kind == "qemu" && r.template != Some(1) && r.name.as_deref().is_some_and(golds::is_bake_vm_name) && r.tags.as_deref().is_some_and(|t| t.split(';').any(|t| t == tags::BAKE || t == "pvs-bake"))
    }) {
        let (Some(node), Some(vmid)) = (vm.node.as_deref(), vm.vmid) else { continue };
        match app.pve.vm_destroy(node, vmid).await {
            Ok(()) => tracing::info!("removed leftover bake VM {vmid}"),
            Err(e) => tracing::warn!("could not remove leftover bake VM {vmid}: {e:#}"),
        }
    }
    // Worker VMs (media, FoD) the same: the job that watched them is gone, and a continued
    // build boots a fresh one. Only worker-<id>, tagged worker, never a template.
    for vm in res.iter().filter(|r| {
        r.kind == "qemu" && r.template != Some(1) && r.name.as_deref().is_some_and(|n| n.starts_with("worker-")) && r.tags.as_deref().is_some_and(|t| t.split(';').any(|t| t == tags::WORKER))
    }) {
        let (Some(node), Some(vmid)) = (vm.node.as_deref(), vm.vmid) else { continue };
        match app.pve.vm_destroy(node, vmid).await {
            Ok(()) => tracing::info!("removed leftover worker VM {vmid}"),
            Err(e) => tracing::warn!("could not remove leftover worker VM {vmid}: {e:#}"),
        }
    }
}

/// Golds and VMs made before the tags were clean (pvs, pvs-gold, pvs-vm, pvs-img-<id>) get
/// today's (tags.rs), and a VM's notes lose the user and address rows they used to carry.
/// Runs at every start, touches only what still has a pvs tag; the colours are checked each time.
async fn retag(app: &AppState, res: &[pve::Resource]) {
    let old = |r: &pve::Resource| r.tags.as_deref().is_some_and(|t| t.split(';').any(|t| t.starts_with("pvs")));
    let at = |vmid: i64| res.iter().find(|r| r.kind == "qemu" && r.vmid == Some(vmid as u32) && old(r));
    let golds: Vec<(String, String, String, Option<i64>, String)> =
        sqlx::query_as("SELECT id, image_id, os, vmid, manifest FROM golds WHERE status = 'ready'").fetch_all(&app.db).await.unwrap_or_default();
    for (id, image, os, vmid, manifest) in &golds {
        let Some(r) = vmid.and_then(at) else { continue };
        let (Some(node), Some(vmid)) = (r.node.as_deref(), r.vmid) else { continue };
        let tags = tags::gold(os, image, &serde_json::from_str(manifest).unwrap_or_default());
        if app.pve.vm_set(node, vmid, crate::form![("tags", tags.join(";"))]).await.is_ok() {
            tags::paint(&app.pve, &tags).await;
            tracing::info!("gold {id}: tags {}", tags.join(", "));
        }
    }
    let vms: Vec<(String, String, Option<i64>)> =
        sqlx::query_as("SELECT name, gold_id, vmid FROM vms WHERE status = 'ready'").fetch_all(&app.db).await.unwrap_or_default();
    // Every studio tag in use gets its colour (once the token may set it, see install.sh).
    let mut all: Vec<String> = vec![tags::BAKE.into(), tags::WORKER.into()];
    for (_, image, os, _, manifest) in &golds {
        all.extend(tags::gold(os, image, &serde_json::from_str(manifest).unwrap_or_default()));
        all.push(tags::os(os, image, None));
    }
    all.sort();
    all.dedup();
    tags::paint(&app.pve, &all).await;
    for (name, gold, vmid) in vms {
        let Some(r) = vmid.and_then(at) else { continue };
        let (Some(node), Some(vmid)) = (r.node.as_deref(), r.vmid) else { continue };
        let Some((_, image, os, _, _)) = golds.iter().find(|g| g.0 == gold) else { continue };
        let os_tag = tags::os(os, image, None);
        let mut tags = vec![os_tag.clone()];
        for t in r.tags.as_deref().unwrap_or("").split(';').filter(|t| !t.is_empty() && !t.starts_with("pvs")) {
            if !tags.iter().any(|x| x == t) {
                tags.push(t.to_owned());
            }
        }
        let mut form = crate::form![("tags", tags.join(";"))];
        if let Ok(cfg) = app.pve.vm_config(node, vmid).await
            && let Some(d) = cfg.get("description").and_then(|d| d.as_str())
            && d.contains("| User |")
        {
            let d: Vec<&str> = d.lines().filter(|l| !l.starts_with("| User |") && !l.starts_with("| Address |")).collect();
            let d = d.join("\n").replace("\n\n| | |\n|---|---|", "");
            form.push(("description".into(), d.trim_end().to_owned() + "\n"));
        }
        if app.pve.vm_set(node, vmid, form).await.is_ok() {
            tags::paint(&app.pve, &[os_tag]).await;
            tracing::info!("VM {name}: tags {}", tags.join(", "));
        }
    }
}

/// Microsoft Update's security releases (wu.rs): what an earlier sync left on disk at once,
/// then asked again every six hours - only updates not seen before are fetched.
async fn wu_loop(app: AppState) {
    wu::load(&app.config.data_dir).await;
    loop {
        if let Err(e) = wu::refresh(&app.config.data_dir, std::time::Duration::from_secs(6 * 3600)).await {
            tracing::warn!("Microsoft Update not asked: {e:#}");
        }
        tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
    }
}
