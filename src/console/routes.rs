//! The console's API, one block per page of it. Changes are logged with "console:" in
//! front; anything that restarts the studio or its container is refused while jobs run.

use std::{net::SocketAddr, time::Duration};

use axum::{
    extract::{ws::WebSocketUpgrade, ConnectInfo, Path as UrlPath, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{delete, get, post, put},
    Json, Router,
};
use axum_extra::extract::CookieJar;
use serde::Deserialize;
use serde_json::{json, Value};

use super::{busy_jobs, configfile, give_to_studio, password, probe, Console, Maint};
use crate::{
    cas,
    error::{ApiError, ApiResult},
    pve::{NodeEndpoint, Pve},
    settings, tls,
};

pub fn router(c: Console) -> Router {
    Router::new()
        .route("/api/session", get(session).post(login).delete(logout))
        .route("/api/status", get(status))
        .route("/api/pve", get(pve_get))
        .route("/api/pve/trust", post(pve_trust))
        .route("/api/pve/connection", put(pve_connection))
        .route("/api/cas", get(cas_get).post(cas_add))
        .route("/api/cas/{fp}", delete(cas_remove))
        .route("/api/pins/{fp}", delete(pin_remove))
        .route("/api/network", get(net_get).put(net_put))
        .route("/api/certificate", get(cert_get))
        .route("/api/certificate/fqdn", put(fqdn_put))
        .route("/api/certificate/import", post(cert_import))
        .route("/api/certificate/self-signed", post(cert_self_signed))
        .route("/api/time", get(time_get).put(time_put))
        .route("/api/version", get(version_get).put(version_put))
        .route("/api/version/update", post(version_update))
        .route("/api/debug", get(debug_get).put(debug_put))
        .route("/api/debug/downloads", delete(debug_clear))
        .route("/api/debug/rebuild", post(debug_rebuild))
        .route("/api/debug/bundle", get(debug_bundle))
        .route("/api/service", get(service_get))
        .route("/api/service/restart", post(service_restart))
        .route("/api/service/log", get(service_log))
        .route("/api/shell", get(shell_ws))
        .route("/api/password", get(pw_get).put(pw_put))
        .with_state(c)
}

fn bad(msg: impl Into<String>) -> ApiError {
    ApiError::bad_request(msg)
}

fn err(e: anyhow::Error) -> ApiError {
    bad(format!("{e:#}"))
}

/// A command's output; None when it did not run.
async fn cmd(prog: &str, args: &[&str]) -> Option<(bool, String)> {
    let out = tokio::process::Command::new(prog).args(args).output().await.ok()?;
    let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
    if !out.status.success() {
        text.push_str(&String::from_utf8_lossy(&out.stderr));
    }
    Some((out.status.success(), text))
}

/// Refused while the studio has jobs: what follows restarts it.
async fn refuse_if_busy(c: &Console, what: &str) -> ApiResult<()> {
    let busy = busy_jobs(&c.db).await;
    if busy.is_empty() {
        return Ok(());
    }
    Err(ApiError::new(
        StatusCode::CONFLICT,
        format!("{} job(s) running in the studio ({}) - {what} restarts it; wait until they end", busy.len(), busy.iter().map(|b| b.1.as_str()).collect::<Vec<_>>().join(", ")),
    ))
}

async fn restart_studio() -> ApiResult<()> {
    match cmd("systemctl", &["restart", "pve-vm-studio"]).await {
        Some((true, _)) => Ok(()),
        Some((false, e)) => Err(bad(format!("systemctl restart pve-vm-studio: {}", e.trim()))),
        None => Err(bad("systemctl is not there to restart the studio")),
    }
}

/// The PVE client the studio itself would use now: its config, CAs, pins and nodes.
async fn studio_pve(c: &Console) -> ApiResult<Pve> {
    let cfg = c.cfg();
    let pve = Pve::new(&cfg.pve).map_err(err)?;
    let added: Vec<Vec<u8>> = cas::read_file(&cas::path(c.data_dir())).into_iter().map(|x| x.der).collect();
    pve.set_extra_cas(&added).map_err(err)?;
    pve.set_pins(cas::pin_digests(&cas::read_pins(c.data_dir())));
    let nodes: Vec<NodeEndpoint> = settings::load(&c.db, "pve_nodes").await.unwrap_or_default();
    pve.set_nodes(&nodes);
    Ok(pve)
}

/// The container restarts (network, time zone) a moment after the answer went out - the
/// console with it.
fn reboot_container_soon(pve: Pve, node: String, vmid: u32) {
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(2)).await;
        if let Err(e) = crate::selfnet::reboot(&pve, &node, vmid).await {
            tracing::warn!("console: restart of container {vmid}: {e:#}");
        }
    });
}

// ---- session ----

#[derive(Deserialize)]
struct Login {
    password: String,
}

async fn session(State(c): State<Console>, jar: CookieJar) -> Json<Value> {
    let signed_in = jar.get(super::COOKIE).is_some_and(|k| c.sessions.lock().unwrap().contains_key(k.value()));
    let server: tls::ServerSettings = settings::load(&c.db, "server").await.unwrap_or_default();
    Json(json!({
        "signed_in": signed_in && !c.off_flag().exists(),
        "off": c.off_flag().exists(),
        "password_set": password::read(&c.boot.console_password_file()).ok().flatten().is_some(),
        "user": password::USER,
        "fqdn": server.fqdn,
        "host": hostname(),
        "port": c.boot.console_listen.port(),
        "studio_port": c.boot.listen.port(),
        "plain_http": c.boot.plain_http,
    }))
}

fn hostname() -> String {
    std::fs::read_to_string("/etc/hostname").map(|h| h.trim().to_owned()).unwrap_or_default()
}

async fn login(State(c): State<Console>, ConnectInfo(addr): ConnectInfo<SocketAddr>, jar: CookieJar, Json(l): Json<Login>) -> ApiResult<impl IntoResponse> {
    let id = super::sign_in(&c, addr.ip(), l.password).await?;
    Ok((jar.add(super::session_cookie(id, !c.boot.plain_http)), StatusCode::NO_CONTENT))
}

async fn logout(State(c): State<Console>, jar: CookieJar) -> impl IntoResponse {
    super::sign_out(&c, &jar);
    (jar.remove(super::COOKIE), StatusCode::NO_CONTENT)
}

// ---- status (the line under the navigation) ----

/// systemctl show, as key -> value.
async fn unit_state(unit: &str) -> Value {
    let Some((_, text)) = cmd("systemctl", &["show", unit, "-p", "ActiveState", "-p", "SubState", "-p", "MainPID", "-p", "MemoryCurrent", "-p", "ActiveEnterTimestamp", "-p", "NRestarts"]).await else {
        return json!({ "active": "unknown" });
    };
    let get = |k: &str| text.lines().find_map(|l| l.strip_prefix(&format!("{k}="))).unwrap_or("").to_owned();
    let mem = get("MemoryCurrent").parse::<u64>().ok();
    json!({
        "active": if get("ActiveState").is_empty() { "unknown".to_owned() } else { get("ActiveState") },
        "sub": get("SubState"),
        "pid": get("MainPID"),
        "memory": mem,
        "since": get("ActiveEnterTimestamp"),
        "restarts": get("NRestarts"),
    })
}

fn uptime() -> u64 {
    std::fs::read_to_string("/proc/uptime").ok().and_then(|t| t.split('.').next().and_then(|s| s.parse().ok())).unwrap_or(0)
}

async fn status(State(c): State<Console>, _m: Maint) -> Json<Value> {
    let busy = busy_jobs(&c.db).await;
    Json(json!({
        "studio": unit_state("pve-vm-studio").await,
        "jobs": busy.len(),
        "uptime": uptime(),
        "version": crate::update::current_label(),
        "pve_trusted": *c.pve_ok.lock().unwrap(),
    }))
}

// ---- PVE connection ----

/// The configured way in, and the nodes the studio learned.
async fn targets(c: &Console) -> (Vec<probe::Target>, Vec<String>) {
    let cfg = c.cfg();
    let nodes: Vec<NodeEndpoint> = settings::load(&c.db, "pve_nodes").await.unwrap_or_default();
    let host_of = |u: &str| reqwest::Url::parse(u).ok().and_then(|u| u.host_str().map(|h| h.trim_matches(['[', ']']).to_owned())).unwrap_or_default();
    let configured = host_of(&cfg.pve.url);
    let label = nodes.iter().find(|n| n.ip == configured).map(|n| n.node.clone()).unwrap_or_else(|| "configured node".into());
    let mut t = vec![probe::Target { node: label, url: cfg.pve.url.clone(), tls_name: cfg.pve.tls_name.clone() }];
    for n in nodes.iter().filter(|n| !n.ip.is_empty() && n.ip != configured) {
        let host = if n.ip.contains(':') { format!("[{}]", n.ip) } else { n.ip.clone() };
        t.push(probe::Target { node: n.node.clone(), url: format!("https://{host}:8006"), tls_name: (!n.tls_name.is_empty()).then(|| n.tls_name.clone()) });
    }
    let mut names: Vec<String> = nodes.iter().flat_map(|n| n.names.iter().chain(std::iter::once(&n.tls_name))).filter(|n| !n.is_empty()).cloned().collect();
    names.sort();
    names.dedup();
    (t, names)
}

pub async fn probe_configured(c: &Console) -> Option<bool> {
    let (t, names) = targets(c).await;
    let p = probe::probe(&c.cfg().pve, c.data_dir(), &names, t.first()?).await;
    if p.unreachable.is_some() { None } else { Some(p.trusted) }
}

async fn pve_get(State(c): State<Console>, _m: Maint) -> ApiResult<Json<Value>> {
    let cfg = c.cfg();
    let (t, names) = targets(&c).await;
    let base = cfg.pve.clone();
    let probes = futures::future::join_all(t.iter().map(|t| probe::probe(&base, c.data_dir(), &names, t))).await;
    if let Some(first) = probes.first() {
        *c.pve_ok.lock().unwrap() = if first.unreachable.is_some() { None } else { Some(first.trusted) };
    }
    Ok(Json(json!({
        "config": { "url": cfg.pve.url, "tls_name": cfg.pve.tls_name, "token_id": cfg.pve.token_id, "ca_file": cfg.pve.ca_file, "insecure": cfg.pve.insecure },
        "nodes": probes,
        "learned": t.len() > 1,
    })))
}

#[derive(Deserialize)]
struct Trust {
    url: String,
    fingerprint: String,
    /// "ca": trust the CA with this fingerprint from the chain; "pin": this node certificate alone.
    how: String,
}

async fn pve_trust(State(c): State<Console>, m: Maint, Json(r): Json<Trust>) -> ApiResult<Json<Value>> {
    let (targets, names) = targets(&c).await;
    let t = targets.into_iter().find(|t| t.url == r.url).ok_or_else(|| bad("that is not one of the studio's ways to PVE"))?;
    // Fresh from the node, not what the page showed: the fingerprint has to match it.
    let chain = probe::chain(&t).await.map_err(err)?;
    let (i, der) = chain.iter().enumerate().find(|(_, d)| cas::fingerprint(d).eq_ignore_ascii_case(&r.fingerprint)).ok_or_else(|| bad("the node no longer sends that certificate - reload the page"))?;
    let sum = cas::summary(der).map_err(err)?;
    match r.how.as_str() {
        "ca" => {
            if !sum.is_ca {
                return Err(bad("that certificate is not a CA - trust its issuer, or this certificate only"));
            }
            let parsed = cas::parse(der).map_err(err)?;
            cas::add(c.data_dir(), parsed.cas).map_err(err)?;
            give_to_studio(c.data_dir(), &cas::path(c.data_dir()));
            tracing::info!("console: trusted for PVE from {}: {} ({})", m.from, sum.subject, sum.fingerprint);
        }
        "pin" => {
            if i != 0 {
                return Err(bad("only the node's own certificate is trusted on its own"));
            }
            let mut pins = cas::read_pins(c.data_dir());
            if !pins.iter().any(|p| p.fingerprint == sum.fingerprint) {
                pins.push(cas::Pin {
                    node: t.node.clone(),
                    subject: sum.subject.clone(),
                    not_after: sum.not_after.clone(),
                    fingerprint: sum.fingerprint.clone(),
                    added_by: format!("console ({} from {})", password::USER, m.from),
                    added_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                });
            }
            cas::write_pins(c.data_dir(), &pins).map_err(err)?;
            give_to_studio(c.data_dir(), &cas::pins_path(c.data_dir()));
            tracing::info!("console: PVE certificate of {} trusted as it is, from {}: {}", t.node, m.from, sum.fingerprint);
        }
        _ => return Err(bad("how: ca or pin")),
    }
    let p = probe::probe(&c.cfg().pve, c.data_dir(), &names, &t).await;
    Ok(Json(json!(p)))
}

#[derive(Deserialize)]
struct Connection {
    url: String,
    #[serde(default)]
    tls_name: String,
    #[serde(default)]
    token_id: String,
    /// Left empty: the token's secret stays.
    #[serde(default)]
    token_secret: String,
}

async fn pve_connection(State(c): State<Console>, m: Maint, Json(r): Json<Connection>) -> ApiResult<Json<Value>> {
    let u = reqwest::Url::parse(r.url.trim()).map_err(|_| bad("the API address is a URL: https://<node>:8006"))?;
    if u.scheme() != "https" || u.host_str().is_none() {
        return Err(bad("the API address is a URL: https://<node>:8006"));
    }
    let tls_name = r.tls_name.trim().trim_end_matches('.').to_lowercase();
    if !tls_name.is_empty() && !tls::valid_fqdn(&tls_name) {
        return Err(bad(format!("'{tls_name}' is not a DNS name")));
    }
    let token_id = r.token_id.trim();
    if !token_id.is_empty() && !(token_id.contains('@') && token_id.contains('!')) {
        return Err(bad("the token id looks like user@realm!name"));
    }
    let path = c.cfg().path;
    let url = u.as_str().trim_end_matches('/').to_owned();
    configfile::set(&path, Some("pve"), "url", Some(&configfile::string(&url))).map_err(err)?;
    configfile::set(&path, Some("pve"), "tls_name", (!tls_name.is_empty()).then(|| configfile::string(&tls_name)).as_deref()).map_err(err)?;
    if !token_id.is_empty() {
        configfile::set(&path, Some("pve"), "token_id", Some(&configfile::string(token_id))).map_err(err)?;
    }
    if !r.token_secret.trim().is_empty() {
        configfile::set(&path, Some("pve"), "token_secret", Some(&configfile::string(r.token_secret.trim()))).map_err(err)?;
    }
    tracing::info!("console: PVE connection changed from {}: {url}{}", m.from, if r.token_secret.trim().is_empty() { "" } else { ", new token secret" });
    let restarted = busy_jobs(&c.db).await.is_empty() && restart_studio().await.is_ok();
    Ok(Json(json!({ "restarted": restarted })))
}

// ---- trusted CAs and pins ----

async fn cas_get(State(c): State<Console>, _m: Maint) -> Json<Value> {
    let cfg = c.cfg();
    let cluster = cfg.pve.ca_file.as_deref().map(cas::read_file).unwrap_or_default();
    Json(json!({ "cluster": cluster, "added": cas::read_file(&cas::path(c.data_dir())), "pins": cas::read_pins(c.data_dir()) }))
}

#[derive(Deserialize)]
struct CaUpload {
    data: String,
    #[serde(default)]
    commit: bool,
}

async fn cas_add(State(c): State<Console>, m: Maint, Json(u): Json<CaUpload>) -> ApiResult<Json<Value>> {
    use base64::Engine;
    let bytes = base64::engine::general_purpose::STANDARD.decode(u.data.trim()).map_err(|_| bad("the file did not arrive whole"))?;
    let parsed = cas::parse(&bytes).map_err(err)?;
    if !u.commit {
        return Ok(Json(json!(parsed)));
    }
    if parsed.cas.is_empty() {
        return Err(bad("the file holds no CA certificate"));
    }
    let names = parsed.cas.iter().map(|x| x.name.clone()).collect::<Vec<_>>().join(", ");
    let all = cas::add(c.data_dir(), parsed.cas).map_err(err)?;
    give_to_studio(c.data_dir(), &cas::path(c.data_dir()));
    tracing::info!("console: trusted for PVE from {}: {names}", m.from);
    Ok(Json(json!({ "added": all })))
}

async fn cas_remove(State(c): State<Console>, m: Maint, UrlPath(fp): UrlPath<String>) -> ApiResult<Json<Value>> {
    let all = cas::remove(c.data_dir(), &fp).map_err(err)?;
    give_to_studio(c.data_dir(), &cas::path(c.data_dir()));
    tracing::info!("console: no longer trusted for PVE, from {}: {fp}", m.from);
    Ok(Json(json!({ "added": all })))
}

async fn pin_remove(State(c): State<Console>, m: Maint, UrlPath(fp): UrlPath<String>) -> ApiResult<Json<Value>> {
    let mut pins = cas::read_pins(c.data_dir());
    let before = pins.len();
    pins.retain(|p| !p.fingerprint.eq_ignore_ascii_case(&fp));
    if pins.len() == before {
        return Err(ApiError::not_found("no such pinned certificate"));
    }
    cas::write_pins(c.data_dir(), &pins).map_err(err)?;
    give_to_studio(c.data_dir(), &cas::pins_path(c.data_dir()));
    tracing::info!("console: pinned PVE certificate removed, from {}: {fp}", m.from);
    Ok(Json(json!({ "pins": pins })))
}

// ---- network ----

/// What the container has right now, whatever PVE says.
async fn net_now(c: &Console) -> Value {
    let addr = cmd("ip", &["-br", "addr"]).await.map(|o| o.1).unwrap_or_default();
    let route = cmd("ip", &["route", "show", "default"]).await.map(|o| o.1).unwrap_or_default();
    let resolv = std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default();
    let dns: Vec<&str> = resolv.lines().filter_map(|l| l.strip_prefix("nameserver ")).collect();
    let search: Vec<&str> = resolv.lines().filter_map(|l| l.strip_prefix("search ")).collect();
    let cfg = c.cfg();
    let u = reqwest::Url::parse(&cfg.pve.url).ok();
    let (host, port) = (u.as_ref().and_then(|u| u.host_str()).unwrap_or("").trim_matches(['[', ']']).to_owned(), u.as_ref().and_then(|u| u.port()).unwrap_or(8006));
    let reach = match tokio::time::timeout(Duration::from_secs(4), tokio::net::TcpStream::connect((host.as_str(), port))).await {
        Ok(Ok(_)) => "open".to_owned(),
        Ok(Err(e)) => e.to_string(),
        Err(_) => "no answer in 4 s".into(),
    };
    let server: tls::ServerSettings = settings::load(&c.db, "server").await.unwrap_or_default();
    let resolves = if server.fqdn.is_empty() {
        Value::Null
    } else {
        match tokio::time::timeout(Duration::from_secs(4), tokio::net::lookup_host((server.fqdn.as_str(), 443))).await {
            Ok(Ok(a)) => json!(a.map(|a| a.ip().to_string()).collect::<Vec<_>>()),
            _ => json!([]),
        }
    };
    json!({ "addr": addr.trim(), "route": route.trim(), "dns": dns, "search": search.join(" "), "pve": format!("{host}:{port}"), "pve_reach": reach, "fqdn": server.fqdn, "fqdn_resolves": resolves })
}

async fn net_get(State(c): State<Console>, _m: Maint) -> Json<Value> {
    let own = match studio_pve(&c).await {
        Ok(pve) => crate::selfnet::read(&pve).await.map_err(|e| format!("{e:#}")),
        Err(e) => Err(e.to_string()),
    };
    let now = net_now(&c).await;
    match own {
        Ok(o) => Json(json!({ "own": o, "now": now })),
        Err(e) => Json(json!({ "error": e, "now": now })),
    }
}

async fn net_put(State(c): State<Console>, m: Maint, Json(ch): Json<crate::selfnet::Change>) -> ApiResult<Json<Value>> {
    refuse_if_busy(&c, "a network change").await?;
    let pve = studio_pve(&c).await?;
    let server: tls::ServerSettings = settings::load(&c.db, "server").await.unwrap_or_default();
    let own = crate::selfnet::apply(&pve, &ch, &server.fqdn).await.map_err(err)?;
    tracing::info!("console: network of container {} set from {} ({}), restarting", own.vmid, m.from, if own.mode == "dhcp" { "DHCP".to_owned() } else { own.ip.clone() });
    reboot_container_soon(pve, own.node.clone(), own.vmid);
    Ok(Json(json!(own)))
}

// ---- DNS name and certificate ----

async fn cert_get(State(c): State<Console>, _m: Maint) -> Json<Value> {
    let paths = tls::Paths::new(c.data_dir());
    let info = tokio::fs::read(&paths.cert).await.ok().and_then(|p| tls::cert_info(&p).ok());
    let s: tls::TlsSettings = settings::load(&c.db, "tls").await.unwrap_or_default();
    let server: tls::ServerSettings = settings::load(&c.db, "server").await.unwrap_or_default();
    let fp = tokio::fs::read(&paths.cert).await.ok().and_then(|p| x509_parser::pem::parse_x509_pem(&p).ok().map(|(_, pem)| cas::fingerprint(&pem.contents)));
    Json(json!({ "fqdn": server.fqdn, "certificate": info, "fingerprint": fp, "settings": s, "plain_http": c.boot.plain_http }))
}

#[derive(Deserialize)]
struct Fqdn {
    fqdn: String,
}

async fn fqdn_put(State(c): State<Console>, m: Maint, Json(f): Json<Fqdn>) -> ApiResult<StatusCode> {
    let f = f.fqdn.trim().trim_end_matches('.').to_lowercase();
    if !f.is_empty() && !tls::valid_fqdn(&f) {
        return Err(bad(format!("'{f}' is not a fully qualified DNS name")));
    }
    let mut s: tls::ServerSettings = settings::load(&c.db, "server").await.unwrap_or_default();
    s.fqdn = f.clone();
    settings::save(&c.db, "server", &s).await.map_err(err)?;
    tracing::info!("console: DNS name set to '{f}' from {}", m.from);
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct Import {
    #[serde(default)]
    cert: String,
    #[serde(default)]
    key: String,
    /// A PKCS#12 file (.pfx / .p12), base64 - instead of cert and key.
    #[serde(default)]
    pfx: String,
    #[serde(default)]
    password: String,
}

/// cert.pem and key.pem out of a .pfx, with openssl (legacy algorithms allowed: Windows
/// exports with them).
async fn from_pfx(pfx: &[u8], pw: &str) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    let dir = std::env::temp_dir().join(format!("pvs-pfx-{}", uuid::Uuid::new_v4()));
    tokio::fs::create_dir_all(&dir).await?;
    let f = dir.join("in.pfx");
    tokio::fs::write(&f, pfx).await?;
    let run = |extra: &'static [&'static str]| {
        let f = f.clone();
        let pw = pw.to_owned();
        async move {
            for legacy in [false, true] {
                let mut c = tokio::process::Command::new("openssl");
                c.arg("pkcs12").arg("-in").arg(&f).args(["-passin", "env:PVS_PFX_PW"]).args(extra).env("PVS_PFX_PW", &pw);
                if legacy {
                    c.arg("-legacy");
                }
                let out = c.output().await?;
                if out.status.success() {
                    return Ok(out.stdout);
                }
                if legacy {
                    anyhow::bail!("openssl could not read the .pfx (wrong password?): {}", String::from_utf8_lossy(&out.stderr).lines().next().unwrap_or(""));
                }
            }
            unreachable!()
        }
    };
    let certs = run(&["-nokeys"]).await;
    let key = run(&["-nocerts", "-nodes"]).await;
    let _ = tokio::fs::remove_dir_all(&dir).await;
    // The server certificate first: openssl lists the key's own certificate first already.
    Ok((certs?, key?))
}

async fn cert_import(State(c): State<Console>, m: Maint, Json(r): Json<Import>) -> ApiResult<Json<Value>> {
    if c.boot.plain_http {
        return Err(bad("the studio runs with plain_http - it has no certificate to replace"));
    }
    let (cert, key) = if !r.pfx.is_empty() {
        use base64::Engine;
        let bytes = base64::engine::general_purpose::STANDARD.decode(r.pfx.trim()).map_err(|_| bad("the file did not arrive whole"))?;
        from_pfx(&bytes, &r.password).await.map_err(err)?
    } else {
        (r.cert.into_bytes(), r.key.into_bytes())
    };
    let paths = tls::Paths::new(c.data_dir());
    let info = tls::install(&paths, None, &cert, &key).await.map_err(err)?;
    give_to_studio(c.data_dir(), &paths.cert);
    give_to_studio(c.data_dir(), &paths.key);
    let mut s: tls::TlsSettings = settings::load(&c.db, "tls").await.unwrap_or_default();
    s.mode = "imported".into();
    s.last_error = None;
    settings::save(&c.db, "tls", &s).await.map_err(err)?;
    tracing::info!("console: certificate {} installed from {}", info.subject, m.from);
    Ok(Json(json!(info)))
}

async fn cert_self_signed(State(c): State<Console>, m: Maint) -> ApiResult<Json<Value>> {
    if c.boot.plain_http {
        return Err(bad("the studio runs with plain_http - it has no certificate to replace"));
    }
    let server: tls::ServerSettings = settings::load(&c.db, "server").await.unwrap_or_default();
    let (cert, key) = tls::self_signed(&tls::local_names(&server.fqdn)).map_err(err)?;
    let paths = tls::Paths::new(c.data_dir());
    let info = tls::install(&paths, None, cert.as_bytes(), key.as_bytes()).await.map_err(err)?;
    give_to_studio(c.data_dir(), &paths.cert);
    give_to_studio(c.data_dir(), &paths.key);
    let mut s: tls::TlsSettings = settings::load(&c.db, "tls").await.unwrap_or_default();
    s.mode = "self-signed".into();
    s.last_error = None;
    settings::save(&c.db, "tls", &s).await.map_err(err)?;
    tracing::info!("console: self-signed certificate made from {}", m.from);
    Ok(Json(json!(info)))
}

// ---- time ----

async fn time_get(State(c): State<Console>, _m: Maint) -> Json<Value> {
    let tz = match studio_pve(&c).await {
        Ok(pve) => crate::selfnet::read_timezone(&pve).await.map(|t| json!(t)).unwrap_or_else(|e| json!({ "error": format!("{e:#}") })),
        Err(e) => json!({ "error": e.to_string() }),
    };
    let zones = cmd("timedatectl", &["list-timezones"]).await.filter(|o| o.0).map(|o| o.1.lines().map(str::to_owned).collect::<Vec<_>>()).unwrap_or_default();
    let sync = cmd("timedatectl", &["show", "-p", "NTPSynchronized", "--value"]).await.filter(|o| o.0).map(|o| o.1.trim() == "yes");
    let server: tls::ServerSettings = settings::load(&c.db, "server").await.unwrap_or_default();
    let now = chrono::Local::now();
    Json(json!({
        "zone": tz,
        "local": now.format("%a %Y-%m-%d %H:%M:%S %Z").to_string(),
        "utc": chrono::Utc::now().format("%H:%M:%S UTC").to_string(),
        "epoch_ms": now.timestamp_millis(),
        "synced": sync,
        "clock": if server.clock.is_empty() { "12h".to_owned() } else { server.clock },
        "zones": zones,
    }))
}

#[derive(Deserialize)]
struct TimeChange {
    #[serde(default)]
    timezone: String,
    #[serde(default)]
    clock: String,
}

async fn time_put(State(c): State<Console>, m: Maint, Json(t): Json<TimeChange>) -> ApiResult<Json<Value>> {
    if !t.clock.is_empty() {
        if !matches!(t.clock.as_str(), "12h" | "24h") {
            return Err(bad("the clock is 12h or 24h"));
        }
        let mut s: tls::ServerSettings = settings::load(&c.db, "server").await.unwrap_or_default();
        s.clock = t.clock.clone();
        settings::save(&c.db, "server", &s).await.map_err(err)?;
    }
    let mut rebooting = false;
    if !t.timezone.is_empty() {
        let pve = studio_pve(&c).await?;
        let cur = crate::selfnet::read_timezone(&pve).await.map_err(err)?;
        if cur.config != t.timezone {
            refuse_if_busy(&c, "a time zone change").await?;
            let tz = crate::selfnet::set_timezone(&pve, &t.timezone).await.map_err(err)?;
            tracing::info!("console: time zone of container {} set to {} from {}, restarting", tz.vmid, tz.config, m.from);
            reboot_container_soon(pve, tz.node, tz.vmid);
            rebooting = true;
        }
    }
    Ok(Json(json!({ "rebooting": rebooting })))
}

// ---- version ----

#[derive(Deserialize)]
struct Fresh {
    #[serde(default)]
    fresh: bool,
}

async fn version_get(State(c): State<Console>, _m: Maint, Query(q): Query<Fresh>) -> Json<Value> {
    let s: crate::update::UpdateSettings = settings::load(&c.db, "update").await.unwrap_or_default();
    let st = crate::update::status(&c.web, q.fresh, s.development()).await;
    let os = std::fs::read_to_string("/etc/os-release").ok().and_then(|t| t.lines().find_map(|l| l.strip_prefix("PRETTY_NAME=").map(|v| v.trim_matches('"').to_owned()))).unwrap_or_default();
    let lego = cmd("dpkg-query", &["-W", "-f", "${Version}", "lego"]).await.filter(|o| o.0).map(|o| o.1).unwrap_or_default();
    let history: Vec<(String, String, String, String)> = sqlx::query_as("SELECT title, created_by, status, created_at FROM jobs WHERE kind = 'update' ORDER BY created_at DESC LIMIT 8")
        .fetch_all(&c.db)
        .await
        .unwrap_or_default();
    Json(json!({
        "status": st,
        "settings": { "channel": if s.development() { "development" } else { "stable" }, "auto": s.auto },
        "os": os,
        "lego": lego,
        "jobs": busy_jobs(&c.db).await.len(),
        "history": history.into_iter().map(|(t, by, st, at)| json!({ "title": t, "by": by, "status": st, "at": at })).collect::<Vec<_>>(),
    }))
}

#[derive(Deserialize)]
struct VersionSettings {
    channel: String,
    auto: bool,
}

async fn version_put(State(c): State<Console>, m: Maint, Json(v): Json<VersionSettings>) -> ApiResult<StatusCode> {
    if !matches!(v.channel.as_str(), "stable" | "development") {
        return Err(bad("the channel is stable or development"));
    }
    settings::save(&c.db, "update", &crate::update::UpdateSettings { auto: v.auto, channel: v.channel.clone() }).await.map_err(err)?;
    tracing::info!("console: update channel {}, automatic {} - from {}", v.channel, if v.auto { "on" } else { "off" }, m.from);
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct UpdateTo {
    tag: String,
}

async fn version_update(State(c): State<Console>, m: Maint, Json(u): Json<UpdateTo>) -> ApiResult<Json<Value>> {
    refuse_if_busy(&c, "an update").await?;
    let (rel, target) = crate::update::find(&c.web, &u.tag).await.map_err(err)?;
    tracing::info!("console: update to {target} from {}", m.from);
    let sha = crate::update::download_checked(&c.web, c.data_dir(), &rel).await.map_err(err)?;
    crate::update::hand_over(c.data_dir(), &u.tag, &target, "", &sha).await.map_err(err)?;
    Ok(Json(json!({ "target": target })))
}

// ---- debug tools ----

async fn last_build(c: &Console, kind: &str) -> Value {
    let row: Option<(String, String, String, String)> = sqlx::query_as("SELECT title, status, created_at, params FROM jobs WHERE kind = ? ORDER BY created_at DESC LIMIT 1")
        .bind(kind)
        .fetch_optional(&c.db)
        .await
        .ok()
        .flatten();
    match row {
        Some((title, status, at, params)) => {
            let p: Value = serde_json::from_str(&params).unwrap_or_default();
            json!({ "title": title, "status": status, "at": at, "from_iso": kind == "winpe" && p["uup"].as_str().unwrap_or("").is_empty() })
        }
        None => Value::Null,
    }
}

async fn debug_get(State(c): State<Console>, _m: Maint) -> Json<Value> {
    let w: crate::media::WorkerSettings = settings::load(&c.db, "worker").await.unwrap_or_default();
    let log: crate::logging::LogSettings = settings::load(&c.db, "log").await.unwrap_or_default();
    Json(json!({
        "debug_tools": c.cfg().debug_tools,
        "keep_downloads": w.keep_downloads,
        "downloads_bytes": crate::dir_size(&c.data_dir().join("work").join("uup-files")).await,
        "log_level": log.effective(),
        "levels": crate::logging::LEVELS,
        "recommended": crate::logging::RECOMMENDED,
        "last_winpe": last_build(&c, "winpe").await,
        "last_media": last_build(&c, "media").await,
        "jobs": busy_jobs(&c.db).await.len(),
    }))
}

#[derive(Deserialize)]
struct DebugChange {
    debug_tools: bool,
    keep_downloads: bool,
    log_level: String,
}

async fn debug_put(State(c): State<Console>, m: Maint, Json(d): Json<DebugChange>) -> ApiResult<Json<Value>> {
    if !crate::logging::LEVELS.contains(&d.log_level.as_str()) {
        return Err(bad("unknown log level"));
    }
    let cfg = c.cfg();
    let mut restarted = false;
    if d.debug_tools != cfg.debug_tools {
        refuse_if_busy(&c, "switching debug tools").await?;
        configfile::set(&cfg.path, None, "debug_tools", d.debug_tools.then_some("true")).map_err(err)?;
        tracing::info!("console: debug tools {} from {}, restarting the studio", if d.debug_tools { "on" } else { "off" }, m.from);
        restart_studio().await?;
        restarted = true;
    }
    let mut w: crate::media::WorkerSettings = settings::load(&c.db, "worker").await.unwrap_or_default();
    // A debug tool: only while debug tools are on (the studio clears it at start otherwise).
    let keep = d.keep_downloads && d.debug_tools;
    if w.keep_downloads != keep {
        w.keep_downloads = keep;
        settings::save(&c.db, "worker", &w).await.map_err(err)?;
        tracing::info!("console: keep downloads {} from {}", if keep { "on" } else { "off" }, m.from);
    }
    let level = if d.log_level == crate::logging::RECOMMENDED { String::new() } else { d.log_level.clone() };
    let mut log: crate::logging::LogSettings = settings::load(&c.db, "log").await.unwrap_or_default();
    if log.level != level {
        log.level = level;
        settings::save(&c.db, "log", &log).await.map_err(err)?;
        tracing::info!("console: log level {} from {}", log.effective(), m.from);
    }
    Ok(Json(json!({ "restarted": restarted })))
}

async fn debug_clear(State(c): State<Console>, m: Maint) -> ApiResult<Json<Value>> {
    if !busy_jobs(&c.db).await.is_empty() {
        return Err(ApiError::new(StatusCode::CONFLICT, "a job is running - it may be using the downloads; clear them once it has finished"));
    }
    let dir = c.data_dir().join("work").join("uup-files");
    let freed = crate::dir_size(&dir).await;
    match tokio::fs::remove_dir_all(&dir).await {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(bad(format!("clearing {}: {e}", dir.display()))),
    }
    tracing::info!("console: download cache cleared from {}: {:.1} GB", m.from, freed as f64 / 1e9);
    Ok(Json(json!({ "freed": freed })))
}

#[derive(Deserialize)]
struct Rebuild {
    kind: String,
}

/// Only the studio starts jobs: a request file it picks up within seconds, and its answer.
async fn debug_rebuild(State(c): State<Console>, m: Maint, Json(r): Json<Rebuild>) -> ApiResult<Json<Value>> {
    if !matches!(r.kind.as_str(), "winpe" | "media") {
        return Err(bad("kind: winpe or media"));
    }
    let dir = super::requests_dir(c.data_dir());
    tokio::fs::create_dir_all(&dir).await.map_err(|e| bad(e.to_string()))?;
    give_to_studio(c.data_dir(), &dir);
    let id = uuid::Uuid::new_v4().to_string();
    let req = dir.join(format!("{id}.json"));
    let tmp = dir.join(format!("{id}.tmp"));
    tokio::fs::write(&tmp, json!({ "action": "rebuild", "kind": r.kind }).to_string()).await.map_err(|e| bad(e.to_string()))?;
    give_to_studio(c.data_dir(), &tmp);
    tokio::fs::rename(&tmp, &req).await.map_err(|e| bad(e.to_string()))?;
    tracing::info!("console: rebuild of the last {} requested from {}", r.kind, m.from);
    let done = dir.join(format!("{id}.done"));
    for _ in 0..30 {
        tokio::time::sleep(Duration::from_millis(500)).await;
        if let Ok(text) = tokio::fs::read_to_string(&done).await {
            let _ = tokio::fs::remove_file(&done).await;
            let v: Value = serde_json::from_str(&text).unwrap_or_default();
            if let Some(e) = v["error"].as_str() {
                return Err(bad(e.to_owned()));
            }
            return Ok(Json(v));
        }
    }
    let _ = tokio::fs::remove_file(&req).await;
    Err(ApiError::new(StatusCode::GATEWAY_TIMEOUT, "the studio did not take the request within 15 s - is it running? (Service)"))
}

/// A .tar.gz for whoever helps: config.toml without secrets, the logs, job logs of the last
/// seven days, versions, the network, every PVE node's certificate chain.
async fn debug_bundle(State(c): State<Console>, m: Maint) -> ApiResult<impl IntoResponse> {
    let dir = std::env::temp_dir().join(format!("pvs-support-{}", uuid::Uuid::new_v4()));
    let root = dir.join("pve-vm-studio-support");
    tokio::fs::create_dir_all(root.join("jobs")).await.map_err(|e| bad(e.to_string()))?;
    let cfg = c.cfg();
    let conf = std::fs::read_to_string(&cfg.path).unwrap_or_default();
    let redacted: String = conf
        .lines()
        .map(|l| {
            let k = l.split('=').next().unwrap_or("").trim();
            if ["token_secret", "password", "secret"].iter().any(|s| k.contains(s)) { format!("{k} = \"(removed)\"") } else { l.to_owned() }
        })
        .collect::<Vec<_>>()
        .join("\n");
    let write = |name: &str, text: String| {
        let p = root.join(name);
        async move {
            let _ = tokio::fs::write(p, text).await;
        }
    };
    write("config.toml", redacted + "\n").await;
    for (unit, file) in [("pve-vm-studio", "studio.log"), ("pve-vm-studio-console", "console.log")] {
        let log = cmd("journalctl", &["-u", unit, "-n", "5000", "--no-pager", "-o", "short-iso"]).await.map(|o| o.1).unwrap_or_default();
        write(file, log).await;
    }
    let mut versions = format!("studio {}\n", crate::update::current_label());
    versions += &std::fs::read_to_string("/etc/os-release").unwrap_or_default();
    versions += &cmd("dpkg-query", &["-W", "lego", "wimtools", "p7zip-full", "genisoimage"]).await.map(|o| o.1).unwrap_or_default();
    write("versions.txt", versions).await;
    let now = net_now(&c).await;
    write("network.json", serde_json::to_string_pretty(&now).unwrap_or_default()).await;
    let (t, names) = targets(&c).await;
    let probes = futures::future::join_all(t.iter().map(|t| probe::probe(&cfg.pve, c.data_dir(), &names, t))).await;
    write("pve-nodes.json", serde_json::to_string_pretty(&probes).unwrap_or_default()).await;
    let week = std::time::SystemTime::now() - Duration::from_secs(7 * 86400);
    if let Ok(mut rd) = tokio::fs::read_dir(cfg.jobs_dir()).await {
        while let Ok(Some(e)) = rd.next_entry().await {
            if e.metadata().await.ok().and_then(|md| md.modified().ok()).is_some_and(|t| t > week) {
                let _ = tokio::fs::copy(e.path(), root.join("jobs").join(e.file_name())).await;
            }
        }
    }
    let out = tokio::process::Command::new("tar").arg("-czf").arg("-").arg("-C").arg(&dir).arg("pve-vm-studio-support").output().await.map_err(|e| bad(format!("tar: {e}")))?;
    let _ = tokio::fs::remove_dir_all(&dir).await;
    if !out.status.success() {
        return Err(bad(format!("tar: {}", String::from_utf8_lossy(&out.stderr))));
    }
    tracing::info!("console: support bundle downloaded from {}", m.from);
    let name = format!("pve-vm-studio-support-{}.tar.gz", chrono::Local::now().format("%Y%m%d-%H%M"));
    Ok(([(header::CONTENT_TYPE, "application/gzip".to_owned()), (header::CONTENT_DISPOSITION, format!("attachment; filename=\"{name}\""))], out.stdout))
}

// ---- service ----

async fn service_get(State(c): State<Console>, _m: Maint) -> Json<Value> {
    let cfg = c.cfg();
    let vol = crate::media::volume(c.data_dir());
    Json(json!({
        "studio": unit_state("pve-vm-studio").await,
        "console": unit_state("pve-vm-studio-console").await,
        "listen": { "studio": cfg.listen.to_string(), "http": cfg.http_listen.map(|a| a.to_string()), "console": cfg.console_listen.to_string() },
        "jobs": busy_jobs(&c.db).await.into_iter().map(|(id, title)| json!({ "id": id, "title": title })).collect::<Vec<_>>(),
        "disk": vol.map(|(total, free)| json!({ "path": c.data_dir(), "total": total, "free": free })),
    }))
}

#[derive(Deserialize)]
struct Restart {
    #[serde(default)]
    force: bool,
}

async fn service_restart(State(c): State<Console>, m: Maint, Json(r): Json<Restart>) -> ApiResult<StatusCode> {
    if !r.force {
        refuse_if_busy(&c, "a restart").await?;
    }
    tracing::info!("console: studio restart from {}{}", m.from, if r.force { " (forced, jobs cut off)" } else { "" });
    restart_studio().await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct LogQuery {
    #[serde(default)]
    unit: String,
    #[serde(default)]
    level: String,
    #[serde(default)]
    grep: String,
    #[serde(default)]
    cursor: String,
    #[serde(default)]
    lines: Option<u32>,
}

async fn service_log(State(_c): State<Console>, _m: Maint, Query(q): Query<LogQuery>) -> Json<Value> {
    let unit = if q.unit == "console" { "pve-vm-studio-console" } else { "pve-vm-studio" };
    let n = q.lines.unwrap_or(300).clamp(10, 5000).to_string();
    let mut args: Vec<String> = vec!["-u".into(), unit.into(), "--no-pager".into(), "-o".into(), "short-iso".into(), "--show-cursor".into()];
    if q.cursor.is_empty() {
        args.extend(["-n".into(), n]);
    } else {
        args.extend(["--after-cursor".into(), q.cursor.clone()]);
    }
    match q.level.as_str() {
        "warn" => args.extend(["-p".into(), "warning".into()]),
        "info" => args.extend(["-p".into(), "info".into()]),
        _ => {}
    }
    if !q.grep.trim().is_empty() {
        args.extend(["--grep".into(), q.grep.trim().into(), "--case-sensitive=false".into()]);
    }
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let Some((_, text)) = cmd("journalctl", &refs).await else {
        return Json(json!({ "lines": [], "cursor": q.cursor, "error": "journalctl is not there" }));
    };
    let mut cursor = q.cursor.clone();
    let mut lines = Vec::new();
    for l in text.lines() {
        if let Some(c) = l.strip_prefix("-- cursor: ") {
            cursor = c.trim().to_owned();
        } else if !l.starts_with("-- No entries --") {
            lines.push(l.to_owned());
        }
    }
    Json(json!({ "lines": lines, "cursor": cursor }))
}

// ---- shell ----

#[derive(Deserialize)]
struct Size {
    #[serde(default)]
    cols: Option<u16>,
    #[serde(default)]
    rows: Option<u16>,
}

async fn shell_ws(State(c): State<Console>, m: Maint, headers: HeaderMap, uri: axum::http::Uri, Query(s): Query<Size>, ws: WebSocketUpgrade) -> ApiResult<impl IntoResponse> {
    // A page of another site cannot open it with this one's cookie: the origin must be ours
    // (Host under HTTP/1.1, the request's authority under HTTP/2).
    let authority = uri.authority().map(|a| a.as_str().to_owned());
    let host = authority.as_deref().or_else(|| headers.get(header::HOST).and_then(|h| h.to_str().ok())).unwrap_or("");
    let origin = headers.get(header::ORIGIN).and_then(|h| h.to_str().ok()).unwrap_or("");
    if origin.split("://").nth(1) != Some(host) {
        return Err(ApiError::new(StatusCode::FORBIDDEN, "the shell opens from the console's own page only"));
    }
    let data = c.data_dir().to_path_buf();
    let from = m.from.to_string();
    Ok(ws.on_upgrade(move |socket| super::shell::session(socket, data, from, s.cols.unwrap_or(120), s.rows.unwrap_or(36))))
}

// ---- password ----

async fn pw_get(State(c): State<Console>, _m: Maint) -> ApiResult<Json<Value>> {
    let stored = password::read(&c.boot.console_password_file()).map_err(err)?;
    Ok(Json(json!({
        "user": password::USER,
        "set_at": stored.as_ref().map(|s| s.set_at.clone()),
        "set_by": stored.as_ref().map(|s| s.set_by.clone()),
        "min": password::MIN_LEN,
        "signins": super::recent_signins(c.data_dir(), 20),
        "port": c.boot.console_listen.port(),
    })))
}

#[derive(Deserialize)]
struct PwChange {
    current: String,
    new: String,
}

async fn pw_put(State(c): State<Console>, m: Maint, jar: CookieJar, Json(p): Json<PwChange>) -> ApiResult<StatusCode> {
    let file = c.boot.console_password_file();
    let stored = password::read(&file).map_err(err)?.ok_or_else(|| bad("no password is set"))?;
    let cur = p.current.clone();
    if !tokio::task::spawn_blocking(move || password::verify(&stored, &cur)).await.unwrap_or(false) {
        return Err(ApiError::new(StatusCode::FORBIDDEN, "the current password is wrong"));
    }
    let new: String = p.new.chars().filter(|c| !c.is_whitespace() && *c != '-').collect();
    if new.chars().count() < password::MIN_LEN {
        return Err(bad(format!("at least {} characters", password::MIN_LEN)));
    }
    let by = format!("console from {}", m.from);
    tokio::task::spawn_blocking(move || password::write(&file, &new, &by)).await.map_err(|e| bad(e.to_string()))?.map_err(err)?;
    super::end_other_sessions(&c, &jar);
    tracing::info!("console: password changed from {}", m.from);
    Ok(StatusCode::NO_CONTENT)
}
