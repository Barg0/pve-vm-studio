//! PVE VM Studio - design VMs in the browser, bake golds and deploy them on Proxmox VE.
//!
//! One binary: the REST API, the job runner and the web UI (embedded at build time).
//! It runs in an LXC and talks to the cluster through the PVE API only.

mod api;
mod auth;
mod catalog;
mod config;
mod error;
mod golds;
mod guest;
mod jobs;
mod labs;
mod linux;
mod progress;
mod pve;
mod seed;
mod serial;
mod settings;
mod tls;
mod virtio;
mod vms;
mod web;
mod wim;
mod windows;
mod winpe;

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
use tracing_subscriber::EnvFilter;

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
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info,sqlx=warn".into()))
        .init();

    // Two crypto back-ends end up linked (ring and aws-lc-rs, through different crates);
    // rustls then needs to be told which one serves the process.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let config = Config::load()?;

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

    let db = SqlitePoolOptions::new()
        .max_connections(8)
        .connect_with(
            SqliteConnectOptions::new()
                .filename(config.data_dir.join("studio.db"))
                .create_if_missing(true)
                .journal_mode(SqliteJournalMode::Wal),
        )
        .await?;
    sqlx::migrate!().run(&db).await?;
    tokio::fs::create_dir_all(config.data_dir.join("work")).await?;
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
    tokio::spawn(tls::renew_loop(db.clone(), tls::Paths::new(&config.data_dir), tls_live.clone()));

    let state = AppState {
        pve: Pve::new(&config.pve)?,
        web: reqwest::Client::builder()
            .user_agent(concat!("pve-vm-studio/", env!("CARGO_PKG_VERSION")))
            .timeout(std::time::Duration::from_secs(60))
            .build()?,
        sessions: Sessions::default(),
        jobs: Jobs::new(db.clone(), config.jobs_dir()).await?,
        db,
        tls: tls_live.clone(),
        config: Arc::new(config),
    };

    let app = Router::new()
        .nest("/api", api::router())
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
