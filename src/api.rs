//! The REST API under /api. The browser UI is its only client, but nothing in here
//! assumes that.

use std::{convert::Infallible, time::Duration};

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{
        sse::{Event as SseEvent, KeepAlive, Sse},
        IntoResponse,
    },
    routing::{get, post},
    Json, Router,
};
use axum_extra::extract::CookieJar;
use futures::Stream;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::sync::{broadcast, mpsc};
use tokio_stream::wrappers::ReceiverStream;

use crate::{update,
    auth::{session_cookie, User, COOKIE},
    catalog,
    error::{ApiError, ApiResult},
    cis,
    fod,
    golds,
    jobs::Event,
    labs,
    linux::BakeOptions,
    pve::{Bridge, Resource, Vnet},
    settings::{self, BakeSettings},
    tls::{self, AcmeSettings, ServerSettings, TlsSettings},
    virtio,
    vms::{self, VmSpec},
    media, uup, wim, windows, winpe,
    AppState,
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/realms", get(realms))
        .route("/session", get(session).post(login).delete(logout))
        .route("/inventory", get(inventory))
        .route("/jobs", get(list_jobs).delete(delete_jobs))
        .route("/jobs/cluster-check", post(start_cluster_check))
        .route("/jobs/{id}", get(get_job))
        .route("/jobs/{id}/retry", post(retry_job))
        .route("/jobs/{id}/abort", post(abort_job))
        .route("/jobs/{id}/events", get(job_events))
        .route("/catalog", get(catalog_info))
        .route("/settings/bake", get(get_bake_settings).put(put_bake_settings))
        .route("/golds", get(list_golds).post(start_bake))
        .route("/golds/{id}", axum::routing::delete(remove_gold).patch(label_gold))
        .route("/golds/{id}/cis", get(gold_cis_report))
        .route("/cis/rules/{image}", get(cis_rules))
        .route("/golds/{id}/cis.html", get(gold_cis_html))
        .route("/golds/{id}/cis/grub", get(gold_cis_grub))
        .route("/vms", get(list_vms).post(start_deploy))
        .route("/vms/{id}", axum::routing::delete(remove_vm))
        .route("/settings/server", get(get_server).put(put_server))
        .route("/settings/region", get(get_region).put(put_region))
        .route("/pools", get(list_pools).post(create_pool))
        .route("/tls", get(get_tls))
        .route("/tls/acme", post(start_acme))
        .route("/tls/providers/{code}", get(provider_help))
        .route("/tls/import", post(import_cert))
        .route("/tls/self-signed", post(new_self_signed))
        .route("/settings/windows", get(get_windows).put(put_windows))
        .route("/settings/fod", get(get_fod).put(put_fod))
        .route("/fod/build", post(build_fod))
        .route("/settings/worker", get(get_worker).put(put_worker))
        .route("/virtio/fetch", post(fetch_virtio))
        .route("/windows/isos", get(windows_isos))
        .route("/windows/images", get(windows_images))
        .route("/golds/windows", post(start_windows_bake))
        .route("/winpe", get(get_winpe))
        .route("/winpe/build", post(build_winpe))
        .route("/winpe/build-uup", post(build_winpe_uup))
        .route("/uup/builds", get(uup_builds))
        .route("/media/products", get(media_products))
        .route("/media/builds", get(media_builds))
        .route("/media/editions", get(media_editions))
        .route("/media/size", get(media_size))
        .route("/media/build", post(media_build))
        .route("/media/isos", get(media_isos))
        .route("/studio/version", get(studio_version))
        .route("/studio/update", post(studio_update))
        .route("/settings/update", get(get_update_settings).put(put_update_settings))
        .route("/uup/languages", get(uup_languages))
        .route("/labs", get(list_labs).post(create_lab))
        .route("/labs/{id}", get(get_lab).put(save_lab).delete(delete_lab))
        .route("/labs/{id}/deploy", post(deploy_lab))
}

// ---- session ----

#[derive(Serialize)]
struct SessionInfo {
    user: String,
    csrf: String,
}

#[derive(Serialize, Deserialize)]
struct Realm {
    realm: String,
    #[serde(rename = "type")]
    kind: String,
    comment: Option<String>,
    default: Option<u8>,
}

/// The login page's realm picker. PVE answers this one without authentication too.
async fn realms(State(app): State<AppState>) -> ApiResult<Json<Vec<Realm>>> {
    Ok(Json(app.pve.get("/access/domains").await?))
}

async fn session(user: User) -> Json<SessionInfo> {
    Json(SessionInfo { user: user.session.user, csrf: user.session.csrf })
}

#[derive(Deserialize)]
struct LoginForm {
    /// With the realm: "root@pam", "alice@pve".
    username: String,
    password: String,
}

async fn login(
    State(app): State<AppState>,
    jar: CookieJar,
    Json(form): Json<LoginForm>,
) -> ApiResult<impl IntoResponse> {
    if !form.username.contains('@') {
        return Err(ApiError::bad_request("the user name needs its realm, e.g. root@pam"));
    }
    let ticket = app
        .pve
        .login(&form.username, &form.password)
        .await
        .map_err(|_| ApiError::new(StatusCode::UNAUTHORIZED, "login failed"))?;
    let (id, s) = app.sessions.create(ticket).await;
    tracing::info!("{} logged in", s.user);
    let jar = jar.add(session_cookie(id, !app.config.plain_http));
    Ok((jar, Json(SessionInfo { user: s.user, csrf: s.csrf })))
}

async fn logout(State(app): State<AppState>, jar: CookieJar, user: User) -> impl IntoResponse {
    app.sessions.remove(&user.session_id).await;
    (jar.remove(COOKIE), StatusCode::NO_CONTENT)
}

// ---- inventory ----

#[derive(Serialize)]
struct Inventory {
    cluster: Option<ClusterInfo>,
    version: String,
    nodes: Vec<NodeInfo>,
    storages: Vec<Resource>,
    vnets: Vec<Vnet>,
    guests: Vec<Resource>,
}

#[derive(Serialize)]
struct ClusterInfo {
    name: String,
    quorate: bool,
    nodes: u32,
}

#[derive(Serialize)]
struct NodeInfo {
    #[serde(flatten)]
    resource: Resource,
    ip: Option<String>,
    bridges: Vec<Bridge>,
}

/// Everything the studio needs to know about the cluster, in one call.
async fn inventory(State(app): State<AppState>, user: User) -> ApiResult<Json<Inventory>> {
    user.require(&app, "/", "Sys.Audit").await?;

    let (version, status, resources) =
        tokio::try_join!(app.pve.version(), app.pve.cluster_status(), app.pve.resources())?;
    let vnets = app.pve.vnets().await;

    let cluster = status.iter().find(|s| s.kind == "cluster").map(|c| ClusterInfo {
        name: c.name.clone(),
        quorate: c.quorate == Some(1),
        nodes: c.nodes.unwrap_or(0),
    });

    let mut nodes = Vec::new();
    let mut storages = Vec::new();
    let mut guests = Vec::new();
    for r in resources {
        match r.kind.as_str() {
            "node" => {
                let name = r.node.clone().unwrap_or_default();
                let online = r.status.as_deref() == Some("online");
                // An offline node cannot list its bridges; show it without them.
                let bridges = if online { app.pve.bridges(&name).await.unwrap_or_default() } else { vec![] };
                let ip = status.iter().find(|s| s.kind == "node" && s.name == name).and_then(|s| s.ip.clone());
                nodes.push(NodeInfo { resource: r, ip, bridges });
            }
            "storage" => storages.push(r),
            "qemu" | "lxc" => guests.push(r),
            _ => {}
        }
    }
    nodes.sort_by(|a, b| a.resource.node.cmp(&b.resource.node));
    storages.sort_by(|a, b| (&a.storage, &a.node).cmp(&(&b.storage, &b.node)));
    guests.sort_by_key(|g| g.vmid);

    Ok(Json(Inventory {
        cluster,
        version: format!("{}-{}", version.version, version.release),
        nodes,
        storages,
        vnets,
        guests,
    }))
}

// ---- jobs ----

/// The jobs, newest first; a running one carries its progress bar as `progress`.
async fn list_jobs(State(app): State<AppState>, _user: User) -> ApiResult<impl IntoResponse> {
    let progress = app.jobs.progress().await;
    let out: Vec<serde_json::Value> = app
        .jobs
        .list(200)
        .await?
        .into_iter()
        .map(|j| {
            let mut v = serde_json::to_value(&j).unwrap_or_default();
            if let Some(p) = progress.get(&j.id) {
                v["progress"] = serde_json::to_value(p).unwrap_or_default();
            }
            v
        })
        .collect();
    Ok(Json(out))
}

#[derive(Deserialize)]
struct JobIds {
    ids: Vec<String>,
}

/// Clears jobs from the history - a whole subject's runs at once. A running job stays, and
/// so does the log of a gold the studio keeps or of a VM that still exists in PVE.
async fn delete_jobs(State(app): State<AppState>, user: User, Json(q): Json<JobIds>) -> ApiResult<impl IntoResponse> {
    require_admin(&app, &user).await?;
    let mut deleted = 0;
    let mut kept = Vec::new();
    let live: std::collections::HashSet<(String, u32, String)> = app
        .pve
        .resources()
        .await?
        .into_iter()
        .filter(|r| r.kind == "qemu")
        .filter_map(|r| Some((r.node?, r.vmid?, r.name.unwrap_or_default().to_lowercase())))
        .collect();
    for id in &q.ids {
        let Some(job) = app.jobs.get(id).await? else { continue };
        if app.jobs.is_running(id).await || matches!(job.status.as_str(), "queued" | "running") {
            kept.push(json!({ "id": id, "why": "it is running" }));
            continue;
        }
        let gold: Option<(String,)> = sqlx::query_as("SELECT id FROM golds WHERE job_id = ? AND status != 'removed'").bind(id).fetch_optional(&app.db).await?;
        // A VM record keeps its build log only while the VM is still in PVE.
        let vm: Option<(String, String, Option<i64>)> = sqlx::query_as("SELECT name, node, vmid FROM vms WHERE job_id = ? AND status != 'removed'").bind(id).fetch_optional(&app.db).await?;
        let vm = match vm {
            Some((name, node, Some(vmid))) if live.contains(&(node.clone(), vmid as u32, name.to_lowercase())) => Some((name,)),
            _ => None,
        };
        if let Some((g,)) = gold {
            kept.push(json!({ "id": id, "why": format!("it is the bake log of gold {g}") }));
        } else if let Some((v,)) = vm {
            kept.push(json!({ "id": id, "why": format!("it is the build log of {v}") }));
        } else {
            app.jobs.delete(id).await?;
            deleted += 1;
        }
    }
    Ok(Json(json!({ "deleted": deleted, "kept": kept })))
}

/// Runs a job again with what it ran with - for the jobs whose parameters say everything:
/// Windows media, WinPE, virtio-win, the cluster check. Bakes and VM builds are retried
/// from their own blades (the gold's Rebake, Deploy), where the form shows what goes in.
/// A job of this kind is running already with params[key] == value (two builds of the same
/// thing would download into the same cache at the same time).
async fn already_running(app: &AppState, kind: &str, key: &str, value: &str) -> ApiResult<()> {
    let rows: Vec<(String, String)> = sqlx::query_as("SELECT title, params FROM jobs WHERE status = 'running' AND kind = ?")
        .bind(kind)
        .fetch_all(&app.db)
        .await?;
    for (title, params) in rows {
        let p: serde_json::Value = serde_json::from_str(&params).unwrap_or_default();
        if p[key].as_str().is_some_and(|v| v.eq_ignore_ascii_case(value)) {
            return Err(ApiError::new(StatusCode::CONFLICT, format!("{title} is running already - wait for it, or abort it")));
        }
    }
    Ok(())
}

/// Asks a running job to stop: it ends at its next check and cleans up like a failed one.
async fn abort_job(State(app): State<AppState>, user: User, Path(id): Path<String>) -> ApiResult<impl IntoResponse> {
    user.require(&app, "/vms", "VM.Allocate").await?;
    if !app.jobs.abort(&id, &user.session.user).await {
        return Err(ApiError::bad_request("this job is not running"));
    }
    Ok(StatusCode::ACCEPTED)
}

async fn retry_job(State(app): State<AppState>, user: User, Path(id): Path<String>) -> ApiResult<axum::response::Response> {
    let job = app.jobs.get(&id).await?.ok_or_else(|| ApiError::not_found("no such job"))?;
    if app.jobs.is_running(&id).await {
        return Err(ApiError::bad_request("this job is still running"));
    }
    let p: serde_json::Value = serde_json::from_str(&job.params).unwrap_or_default();
    let s = |k: &str| p[k].as_str().unwrap_or_default().to_owned();
    let r = match job.kind.as_str() {
        "media" => {
            let editions = p["editions"].as_array().into_iter().flatten().filter_map(|e| e.as_str().map(str::to_owned)).collect();
            media_build(State(app), user, Json(MediaBuild { product: s("media"), uuid: s("uuid"), build: s("build"), lang: s("lang"), editions })).await?.into_response()
        }
        "winpe" if !s("uup").is_empty() => build_winpe_uup(State(app), user, Json(UupWinPe { uuid: s("uup"), lang: s("lang"), build: s("build") })).await?.into_response(),
        "winpe" => build_winpe(State(app), user, Json(IsoQuery { volid: s("iso") })).await?.into_response(),
        "virtio" => fetch_virtio(State(app), user).await?.into_response(),
        "fod" => build_fod(State(app), user, Json(FodBuild { slot: s("fod"), lang: s("lang") })).await?.into_response(),
        "cluster-check" => start_cluster_check(State(app), user).await?.into_response(),
        other => return Err(ApiError::bad_request(format!("a {other} job is retried from its own page"))),
    };
    Ok(r)
}

async fn get_job(State(app): State<AppState>, _user: User, Path(id): Path<String>) -> ApiResult<impl IntoResponse> {
    let job = app.jobs.get(&id).await?.ok_or_else(|| ApiError::not_found("no such job"))?;
    Ok(Json(job))
}

/// The job's log as Server-Sent Events: everything so far, then live lines, then one
/// "status" event when it ends.
async fn job_events(
    State(app): State<AppState>,
    _user: User,
    Path(id): Path<String>,
) -> ApiResult<Sse<impl Stream<Item = Result<SseEvent, Infallible>>>> {
    app.jobs.get(&id).await?.ok_or_else(|| ApiError::not_found("no such job"))?;
    let (lines, progress, feed) = app.jobs.watch(&id).await?;

    let (tx, rx) = mpsc::channel::<Event>(256);
    tokio::spawn(async move {
        for (n, text) in lines.into_iter().enumerate() {
            if tx.send(Event::Line { n, text }).await.is_err() {
                return;
            }
        }
        if let Some(p) = progress
            && tx.send(p).await.is_err()
        {
            return;
        }
        if let Some(mut feed) = feed {
            loop {
                match feed.recv().await {
                    Ok(ev) => {
                        let done = matches!(ev, Event::Status { .. });
                        if tx.send(ev).await.is_err() || done {
                            return;
                        }
                    }
                    // Too slow to keep up with a burst (cloud-init's output): the lines in
                    // between are skipped for this watcher - the file has them - and the
                    // stream goes on, so the final status still arrives.
                    Err(broadcast::error::RecvError::Lagged(missed)) => {
                        let _ = tx.send(Event::Line { n: 0, text: format!("… {missed} line(s) skipped - the full log is kept in the job") }).await;
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        }
        // Finished before we started watching, or ended between snapshot and subscribe.
        if let Ok(Some(job)) = app.jobs.get(&id).await {
            let _ = tx.send(Event::Status { status: job.status, error: job.error }).await;
        }
    });

    let stream = futures::StreamExt::map(ReceiverStream::new(rx), |ev| {
        let name = match ev {
            Event::Line { .. } => "line",
            Event::Progress { .. } => "progress",
            Event::Status { .. } => "status",
        };
        Ok(SseEvent::default().event(name).json_data(&ev).expect("event serializes"))
    });
    Ok(Sse::new(stream).keep_alive(KeepAlive::new().interval(Duration::from_secs(15))))
}

/// A read-only job that walks the cluster the way a bake will: proves the token, the
/// runner and the live log end to end before anything real depends on them.
async fn start_cluster_check(State(app): State<AppState>, user: User) -> ApiResult<impl IntoResponse> {
    user.require(&app, "/", "Sys.Audit").await?;
    let pve = app.pve.clone();
    let id = app
        .jobs
        .spawn("cluster-check", "Cluster check", &user.session.user, json!({}), move |log| async move {
            let v = pve.version().await?;
            log.line(format!("Proxmox VE {}-{}, reached with the studio's token", v.version, v.release)).await;

            let status = pve.cluster_status().await?;
            match status.iter().find(|s| s.kind == "cluster") {
                Some(c) => {
                    log.line(format!(
                        "Cluster {}: {} node(s), {}",
                        c.name,
                        c.nodes.unwrap_or(0),
                        if c.quorate == Some(1) { "quorate" } else { "NOT quorate" }
                    ))
                    .await
                }
                None => log.line("Single node, no cluster").await,
            }

            let resources = pve.resources().await?;
            for n in resources.iter().filter(|r| r.kind == "node") {
                let name = n.node.as_deref().unwrap_or("?");
                if n.status.as_deref() != Some("online") {
                    log.line(format!("Node {name}: offline")).await;
                    continue;
                }
                log.line(format!(
                    "Node {name}: {} CPUs, {} of {} GiB RAM in use",
                    n.maxcpu.unwrap_or(0.0),
                    gib(n.mem),
                    gib(n.maxmem)
                ))
                .await;
                for b in pve.bridges(name).await? {
                    log.line(format!("  bridge {}{}", b.iface, b.cidr.map(|c| format!(" ({c})")).unwrap_or_default()))
                        .await;
                }
                for s in resources.iter().filter(|r| r.kind == "storage" && r.node.as_deref() == Some(name)) {
                    let content = s.content.as_deref().unwrap_or("");
                    log.line(format!(
                        "  storage {} [{}]: {} of {} GiB free, holds {}{}",
                        s.storage.as_deref().unwrap_or("?"),
                        s.plugintype.as_deref().unwrap_or("?"),
                        gib(s.maxdisk.zip(s.disk).map(|(m, d)| m.saturating_sub(d))),
                        gib(s.maxdisk),
                        content,
                        if s.shared == Some(1) { ", shared" } else { "" }
                    ))
                    .await;
                }
                tokio::time::sleep(Duration::from_millis(300)).await;
            }

            let vnets = pve.vnets().await;
            log.line(format!("{} SDN VNet(s)", vnets.len())).await;

            let templates = resources.iter().filter(|r| r.kind == "qemu" && r.template == Some(1)).count();
            let vms = resources.iter().filter(|r| r.kind == "qemu" && r.template != Some(1)).count();
            log.line(format!("{vms} VM(s), {templates} template(s)")).await;
            log.line("Cluster check done").await;
            Ok(())
        })
        .await?;
    Ok((StatusCode::ACCEPTED, Json(json!({ "id": id }))))
}

fn gib(bytes: Option<u64>) -> String {
    format!("{:.1}", bytes.unwrap_or(0) as f64 / (1u64 << 30) as f64)
}

// ---- catalog, settings ----

/// What new bakes and Windows media downloads preselect (Studio settings → Region
/// preselection). Only a starting point - every form can still change it.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct RegionPrefs {
    pub language: String,
    pub locale: String,
    pub keyboard: String,
    /// IANA, "Europe/Berlin"; Windows bakes get the Windows name for it.
    pub timezone: String,
}

async fn get_region(State(app): State<AppState>, _user: User) -> ApiResult<impl IntoResponse> {
    let r: RegionPrefs = settings::load(&app.db, "region").await?;
    Ok(Json(r))
}

async fn put_region(State(app): State<AppState>, user: User, Json(r): Json<RegionPrefs>) -> ApiResult<impl IntoResponse> {
    require_admin(&app, &user).await?;
    let tag = |s: &str| s.is_empty() || (s.len() <= 16 && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'));
    let tz = |s: &str| s.is_empty() || (s.len() <= 64 && s.chars().all(|c| c.is_ascii_alphanumeric() || "/_-+".contains(c)));
    if !tag(&r.language) || !tag(&r.locale) || !tag(&r.keyboard) || !tz(&r.timezone) {
        return Err(ApiError::bad_request("not a language tag or time zone"));
    }
    settings::save(&app.db, "region", &r).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// The images that can be baked, the gold features, and the region data for the menus.
async fn catalog_info(State(app): State<AppState>, _user: User) -> ApiResult<impl IntoResponse> {
    let parse = |s: &str| serde_json::from_str::<serde_json::Value>(s).unwrap_or_default();
    let locales = parse(catalog::LOCALES);
    // Only what the menus show: tag -> display name.
    let names: serde_json::Map<String, serde_json::Value> = locales["locales"]
        .as_object()
        .map(|m| {
            m.iter()
                .map(|(k, v)| (k.clone(), v["languageName"].clone()))
                .collect()
        })
        .unwrap_or_default();
    let zones: Vec<serde_json::Value> = parse(catalog::TIMEZONES)["zones"]
        .as_array()
        .map(|a| a.iter().map(|z| json!({ "id": z["id"], "offset": z["offsetMinutes"] })).collect())
        .unwrap_or_default();
    let mut region = parse(catalog::LINUX_REGION)["defaults"].clone();
    let pre: RegionPrefs = settings::load(&app.db, "region").await.unwrap_or_default();
    for (k, v) in [("language", &pre.language), ("locale", &pre.locale), ("keyboard", &pre.keyboard), ("timeZone", &pre.timezone)] {
        if !v.is_empty() {
            region[k] = json!(v);
        }
    }
    let tz = region["timeZone"].as_str().unwrap_or("").to_owned();
    if !tz.is_empty() {
        region["windowsTimeZone"] = json!(windows::windows_tz_for(&tz));
    }
    let cis_images: serde_json::Map<String, serde_json::Value> = cis::BENCHMARKS
        .iter()
        .flat_map(|b| b.images.iter().map(move |i| ((*i).to_owned(), json!({ "name": b.name, "version": b.version }))))
        .collect();
    Ok(Json(json!({
        "linux": catalog::LINUX,
        "features": catalog::FEATURES,
        "cis": cis_images,
        "region": region,
        "locales": names,
        "timezones": zones,
    })))
}

async fn get_bake_settings(State(app): State<AppState>, _user: User) -> ApiResult<impl IntoResponse> {
    let s: BakeSettings = settings::load(&app.db, "bake").await?;
    // What "auto" currently resolves to, so the page can show it.
    let resolved = s.resolve(&app.pve).await.map_err(|e| format!("{e:#}"));
    let disks = match &resolved {
        Ok(p) => settings::disk_storages(&app.pve, &p.node).await.unwrap_or_default(),
        Err(_) => vec![],
    };
    Ok(Json(json!({
        "settings": s,
        "resolved": resolved.as_ref().ok(),
        "problem": resolved.err(),
        "disk_storages": disks,
    })))
}

async fn put_bake_settings(
    State(app): State<AppState>,
    user: User,
    Json(s): Json<BakeSettings>,
) -> ApiResult<impl IntoResponse> {
    user.require(&app, "/vms", "VM.Allocate").await?;
    // Refused when it does not resolve - a bake would only fail later.
    s.resolve(&app.pve).await.map_err(|e| ApiError::bad_request(format!("{e:#}")))?;
    settings::save(&app.db, "bake", &s).await?;
    Ok(StatusCode::NO_CONTENT)
}

// ---- golds ----

/// The golds, each with its language, how many VMs were built from it (`used_by` - a
/// linked clone needs its gold), and which designed VMs in every lab would build from it
/// today (`picked_by`, "lab: vm" - Build-Vms' Show golds).
async fn list_golds(State(app): State<AppState>, _user: User) -> ApiResult<impl IntoResponse> {
    let usage = golds::usage(&app.db, &app.pve).await?;
    let rows = golds::list(&app.db).await?;
    let mut picked: std::collections::HashMap<String, Vec<String>> = Default::default();
    for l in labs::list(&app.db).await.unwrap_or_default() {
        let Ok(Some(full)) = labs::get(&app.db, &l.id).await else { continue };
        let state: serde_json::Value = serde_json::from_str(&full.state).unwrap_or_default();
        for s in state["servers"].as_array().into_iter().flatten() {
            let str_of = |k: &str| s[k].as_str().unwrap_or("");
            if let Some(g) = golds::resolve(&rows, str_of("imageId"), str_of("goldLanguage"), str_of("goldId")) {
                picked.entry(g.id.clone()).or_default().push(format!("{}: {}", full.name, str_of("name")));
            }
        }
    }
    // A gold from before schema 2 kept only "26100"; the ISO it came from, if the studio
    // has read it, still says which cumulative update that was.
    let mut full_build: std::collections::HashMap<String, String> = Default::default();
    for g in rows.iter().filter(|g| g.os == "windows") {
        let m: serde_json::Value = serde_json::from_str(&g.manifest).unwrap_or_default();
        if m["build"].as_str().is_some_and(|b| b.contains('.')) {
            continue;
        }
        let iso = m["sourceMedia"].as_str().or_else(|| m["sourceIso"].as_str()).unwrap_or("");
        let (Some(path), Some(index)) = (iso_path(&app, iso), m["imageIndex"].as_u64()) else { continue };
        if let Some(images) = wim::cached(&path, &app.config.data_dir.join("wim-cache.json")).await
            && let Some(i) = images.iter().find(|i| u64::from(i.index) == index && !i.version.is_empty())
        {
            full_build.insert(g.id.clone(), i.version.clone());
        }
    }
    // Microsoft's 2011 Secure Boot certificates expired in June 2026: an EFI disk created
    // before pve-edk2-firmware 4.2025.05 holds only those and refuses loaders signed with the
    // 2023 ones. PVE marks a current disk ms-cert=2023k (qm "Secure Boot Certificate Expiration").
    let mut old_certs = std::collections::HashSet::new();
    for g in rows.iter().filter(|g| g.os == "windows" && g.status == "ready") {
        if let Some(vmid) = g.vmid
            && let Ok(cfg) = app.pve.vm_config(&g.node, vmid as u32).await
            && cfg.get("efidisk0").and_then(|v| v.as_str()).is_some_and(|e| !e.contains("ms-cert=2023"))
        {
            old_certs.insert(g.id.clone());
        }
    }
    let out: Vec<serde_json::Value> = rows
        .iter()
        .map(|g| {
            let mut v = serde_json::to_value(g).unwrap_or_default();
            if old_certs.contains(&g.id) {
                v["old_secure_boot_certs"] = json!(true);
            }
            if let Some(b) = full_build.get(&g.id) {
                v["build_full"] = json!(b);
            }
            v["language"] = json!(golds::language(g));
            v["build_version"] = json!(golds::build_version(g));
            v["used_by"] = json!(usage.get(&g.id).copied().unwrap_or(0));
            v["picked_by"] = json!(picked.get(&g.id).cloned().unwrap_or_default());
            v
        })
        .collect();
    Ok(Json(out))
}

#[derive(Deserialize)]
struct GoldLabel {
    label: String,
}

/// Sets a gold's label - the one thing about a gold that is edited after the bake.
async fn label_gold(State(app): State<AppState>, user: User, Path(id): Path<String>, Json(req): Json<GoldLabel>) -> ApiResult<impl IntoResponse> {
    user.require(&app, "/vms", "VM.Allocate").await?;
    if req.label.chars().count() > 80 {
        return Err(ApiError::bad_request("a label is at most 80 characters"));
    }
    golds::set_label(&app.db, &id, &req.label).await.map_err(|e| ApiError::bad_request(format!("{e:#}")))?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct BakeRequest {
    image: String,
    #[serde(flatten)]
    options: BakeOptions,
}

async fn start_bake(
    State(app): State<AppState>,
    user: User,
    Json(req): Json<BakeRequest>,
) -> ApiResult<impl IntoResponse> {
    user.require(&app, "/vms", "VM.Allocate").await?;
    let img = catalog::linux(&req.image).ok_or_else(|| ApiError::bad_request(format!("unknown image {}", req.image)))?;
    if let Some(bad) = req.options.features.iter().find(|f| !catalog::FEATURES.iter().any(|x| x.id == f.as_str())) {
        return Err(ApiError::bad_request(format!("unknown feature {bad}")));
    }
    if let Some(c) = &req.options.cis
        && c.level > 0
    {
        if c.level > 2 {
            return Err(ApiError::bad_request("CIS is Level 1 or Level 2 Server"));
        }
        if cis::benchmark_for(img.id).is_none() {
            return Err(ApiError::bad_request(format!("the studio has no CIS benchmark for {}", img.name)));
        }
        let id_ok = |id: &str| !id.is_empty() && id.len() <= 16 && id.chars().all(|ch| ch.is_ascii_digit() || ch == '.');
        if let Some(e) = c.exceptions.iter().find(|e| !id_ok(&e.id) || e.reason.trim().is_empty() || e.reason.len() > 300) {
            return Err(ApiError::bad_request(format!("CIS exception '{}': a recommendation number and a reason", e.id)));
        }
    }
    let bake: BakeSettings = settings::load(&app.db, "bake").await?;

    let gold_id = golds::new_build_id(&app.db, &app.pve).await?;
    let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    sqlx::query(
        "INSERT INTO golds (id, image_id, os, name, node, storage, status, options, created_at) \
         VALUES (?, ?, 'linux', ?, '', '', 'baking', ?, ?)",
    )
    .bind(&gold_id)
    .bind(img.id)
    .bind(golds::working_name(&gold_id))
    .bind(serde_json::to_string(&req.options).unwrap_or_default())
    .bind(&now)
    .execute(&app.db)
    .await?;

    let ctx = app.bake_ctx();
    let gid = gold_id.clone();
    let opts = req.options.clone();
    let job = app
        .jobs
        .spawn(
            "bake",
            &format!("Bake {} ({})", img.name, golds::working_name(&gold_id)),
            &user.session.user,
            json!({ "image": img.id, "gold": gold_id, "options": req.options }),
            move |log| golds::bake_linux(ctx, log, gid, img, opts, bake),
        )
        .await?;
    sqlx::query("UPDATE golds SET job_id = ? WHERE id = ?").bind(&job).bind(&gold_id).execute(&app.db).await?;
    Ok((StatusCode::ACCEPTED, Json(json!({ "id": job, "gold": gold_id }))))
}

// ---- CIS reports ----

fn gold_id_ok(id: &str) -> bool {
    !id.is_empty() && id.len() <= 64 && id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
}

async fn read_cis(app: &AppState, id: &str) -> ApiResult<serde_json::Value> {
    if !gold_id_ok(id) {
        return Err(ApiError::bad_request("not a gold id"));
    }
    let raw = tokio::fs::read(cis::report_path(&app.config.data_dir, id)).await.map_err(|_| ApiError::not_found("this gold has no CIS report"))?;
    serde_json::from_slice(&raw).map_err(|e| ApiError::from(anyhow::anyhow!("reading the CIS report: {e}")))
}

/// A gold's CIS report: every rule with its status and evidence. ?download=1 as a file.
async fn gold_cis_report(State(app): State<AppState>, _user: User, Path(id): Path<String>, axum::extract::Query(q): axum::extract::Query<std::collections::HashMap<String, String>>) -> ApiResult<axum::response::Response> {
    let v = read_cis(&app, &id).await?;
    let mut resp = Json(v).into_response();
    if q.get("download").is_some_and(|d| d == "1") {
        resp.headers_mut().insert(axum::http::header::CONTENT_DISPOSITION, format!("attachment; filename=\"cis-{id}.json\"").parse().unwrap());
    }
    Ok(resp)
}

/// A benchmark's rules as the studio runs them - the bake form's rules overlay.
async fn cis_rules(_user: User, Path(image): Path<String>) -> ApiResult<Json<serde_json::Value>> {
    let b = cis::benchmark_for(&image).ok_or_else(|| ApiError::not_found(format!("no CIS benchmark for {image}")))?;
    Ok(Json(json!({ "benchmark": b.name, "version": b.version, "rules": cis::rules(b) })))
}

/// The report as one HTML page, for an auditor without the studio.
async fn gold_cis_html(State(app): State<AppState>, _user: User, Path(id): Path<String>) -> ApiResult<axum::response::Response> {
    let v = read_cis(&app, &id).await?;
    let mut resp = axum::response::Html(cis::html(&v, &id)).into_response();
    resp.headers_mut().insert(axum::http::header::CONTENT_DISPOSITION, format!("attachment; filename=\"cis-{id}.html\"").parse().unwrap());
    Ok(resp)
}

/// The GRUB password a CIS bake set (editing the boot menu needs it) - for admins only.
async fn gold_cis_grub(State(app): State<AppState>, user: User, Path(id): Path<String>) -> ApiResult<impl IntoResponse> {
    require_admin(&app, &user).await?;
    if !gold_id_ok(&id) {
        return Err(ApiError::bad_request("not a gold id"));
    }
    let pw = tokio::fs::read_to_string(cis::grub_path(&app.config.data_dir, &id)).await.map_err(|_| ApiError::not_found("no GRUB password kept for this gold"))?;
    Ok(Json(json!({ "user": "root", "password": pw.trim() })))
}

async fn remove_gold(State(app): State<AppState>, user: User, Path(id): Path<String>) -> ApiResult<impl IntoResponse> {
    user.require(&app, "/vms", "VM.Allocate").await?;
    let gold = golds::get(&app.db, &id).await?.ok_or_else(|| ApiError::not_found("no such gold"))?;
    if gold.status == "baking" {
        return Err(ApiError::bad_request("this gold is still baking"));
    }
    let used = golds::usage(&app.db, &app.pve).await?.get(&gold.id).copied().unwrap_or(0);
    if used > 0 {
        return Err(ApiError::bad_request(format!("{used} VM(s) in PVE are linked clones of {} - PVE keeps a template while a clone uses it; remove those VMs in PVE first", gold.name)));
    }
    let (pve, db, data) = (app.pve.clone(), app.db.clone(), app.config.data_dir.clone());
    let title = format!("Remove {}", gold.name);
    let job = app
        .jobs
        .spawn("remove-gold", &title, &user.session.user, json!({ "gold": id }), move |log| async move {
            golds::remove(&pve, &db, &gold, &log).await?;
            cis::remove(&data, &gold.id).await;
            Ok(())
        })
        .await?;
    Ok((StatusCode::ACCEPTED, Json(json!({ "id": job }))))
}

// ---- VMs ----

/// The studio's VMs, with what PVE says about each right now.
/// The design card a VM row was built from; empty for rows from before cards were recorded.
fn vm_card(v: &vms::VmRow) -> String {
    serde_json::from_str::<serde_json::Value>(&v.spec).ok().and_then(|s| s["card"].as_str().map(str::to_owned)).unwrap_or_default()
}

async fn list_vms(State(app): State<AppState>, _user: User) -> ApiResult<impl IntoResponse> {
    let rows = vms::list(&app.db).await?;
    let res = app.pve.resources().await.unwrap_or_default();
    let out: Vec<serde_json::Value> = rows
        .into_iter()
        .map(|v| {
            // The same VM, not just the same number: a VMID is reused once its VM is gone (a
            // record of a removed vm-01 must not show the cis-01 that has its id now).
            let live = v.vmid.and_then(|id| {
                res.iter().find(|r| {
                    r.kind == "qemu"
                        && r.vmid == Some(id as u32)
                        && r.name.as_deref().is_some_and(|n| n.eq_ignore_ascii_case(&v.name))
                        && (v.node.is_empty() || r.node.as_deref() == Some(v.node.as_str()))
                })
            });
            let spec: serde_json::Value = serde_json::from_str(&v.spec).unwrap_or_default();
            json!({
                "id": v.id, "name": v.name, "lab": v.lab_id, "gold": v.gold_id, "node": v.node,
                "vmid": v.vmid, "status": v.status, "ip": v.ip, "job_id": v.job_id,
                "created_at": v.created_at, "card": vm_card(&v), "spec": spec,
                "power": live.and_then(|l| l.status.clone()).unwrap_or_else(|| "missing".into()),
                "cpu": live.and_then(|l| l.cpu), "mem": live.and_then(|l| l.mem), "maxmem": live.and_then(|l| l.maxmem),
                "uptime": live.and_then(|l| l.uptime),
            })
        })
        .collect();
    Ok(Json(out))
}

async fn start_deploy(State(app): State<AppState>, user: User, Json(spec): Json<VmSpec>) -> ApiResult<impl IntoResponse> {
    user.require(&app, "/vms", "VM.Allocate").await?;
    spec.validate().map_err(|e| ApiError::bad_request(format!("{e:#}")))?;
    let gold = golds::get(&app.db, &spec.gold).await?.ok_or_else(|| ApiError::bad_request("unknown gold"))?;
    if gold.status != "ready" {
        return Err(ApiError::bad_request(format!("gold {} is not ready", gold.name)));
    }
    let taken: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM vms WHERE name = ? AND status IN ('building', 'ready')")
        .bind(&spec.name)
        .fetch_one(&app.db)
        .await?;
    if taken.0 > 0 {
        return Err(ApiError::bad_request(format!("the studio already has a VM named {}", spec.name)));
    }
    let id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    sqlx::query("INSERT INTO vms (id, name, lab_id, gold_id, status, spec, created_at) VALUES (?, ?, ?, ?, 'building', ?, ?)")
        .bind(&id)
        .bind(&spec.name)
        .bind(&spec.lab)
        .bind(&spec.gold)
        .bind(serde_json::to_string(&spec).unwrap_or_default()) // the password is skipped
        .bind(&now)
        .execute(&app.db)
        .await?;
    let (pve, db, work) = (app.pve.clone(), app.db.clone(), app.config.data_dir.join("work"));
    let (vid, sp) = (id.clone(), spec.clone());
    let job = app
        .jobs
        .spawn("deploy", &format!("Build {}", spec.name), &user.session.user, json!({ "vm": id, "name": spec.name, "gold": spec.gold }), move |log| {
            vms::deploy(pve, db, work, log, vid, sp)
        })
        .await?;
    sqlx::query("UPDATE vms SET job_id = ? WHERE id = ?").bind(&job).bind(&id).execute(&app.db).await?;
    Ok((StatusCode::ACCEPTED, Json(json!({ "id": job, "vm": id }))))
}

/// Clears a VM from the studio's view: the record is set aside ("cleared"), the VM in
/// Proxmox VE is never touched. The studio deletes no VM it has handed over - deleting a
/// production VM stays a deliberate act in PVE, under its permissions and confirmations.
async fn remove_vm(State(app): State<AppState>, _user: User, Path(id): Path<String>) -> ApiResult<impl IntoResponse> {
    let vm = vms::get(&app.db, &id).await?.ok_or_else(|| ApiError::not_found("no such VM"))?;
    if vm.status == "building" {
        return Err(ApiError::bad_request("this VM is still being built"));
    }
    sqlx::query("UPDATE vms SET status = 'cleared' WHERE id = ?").bind(&id).execute(&app.db).await?;
    Ok(StatusCode::NO_CONTENT)
}

// ---- the studio's name and certificate ----

/// Studio-level changes (name, certificate) are for PVE administrators.
async fn require_admin(app: &AppState, user: &User) -> ApiResult<()> {
    user.require(app, "/", "Sys.Modify").await
}

async fn get_server(State(app): State<AppState>, _user: User) -> ApiResult<impl IntoResponse> {
    let s: ServerSettings = settings::load(&app.db, "server").await?;
    Ok(Json(json!({ "settings": s, "suggested": tls::local_names("") })))
}

async fn get_worker(State(app): State<AppState>, _user: User) -> ApiResult<impl IntoResponse> {
    let s: media::WorkerSettings = settings::load(&app.db, "worker").await?;
    Ok(Json(s))
}

/// The media worker VM's memory and cores.
async fn put_worker(State(app): State<AppState>, user: User, Json(s): Json<media::WorkerSettings>) -> ApiResult<impl IntoResponse> {
    require_admin(&app, &user).await?;
    if !(2048..=262_144).contains(&s.memory_mb) || !(1..=64).contains(&s.cores) {
        return Err(ApiError::bad_request("memory is 2048-262144 MiB, cores 1-64"));
    }
    settings::save(&app.db, "worker", &s).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn put_server(State(app): State<AppState>, user: User, Json(s): Json<ServerSettings>) -> ApiResult<impl IntoResponse> {
    require_admin(&app, &user).await?;
    let f = s.fqdn.trim().trim_end_matches('.').to_lowercase();
    let label_ok = |l: &str| {
        !l.is_empty() && l.len() <= 63 && !l.starts_with('-') && !l.ends_with('-')
            && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    };
    if !f.is_empty() && (!f.contains('.') || !f.split('.').all(label_ok)) {
        return Err(ApiError::bad_request(format!("'{f}' is not a fully qualified DNS name")));
    }
    if !matches!(s.clock.as_str(), "" | "12h" | "24h") {
        return Err(ApiError::bad_request(format!("'{}' is not a time format - 12h or 24h", s.clock)));
    }
    settings::save(&app.db, "server", &ServerSettings { fqdn: f, clock: s.clock }).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn get_tls(State(app): State<AppState>, _user: User) -> ApiResult<impl IntoResponse> {
    let paths = tls::Paths::new(&app.config.data_dir);
    let s: TlsSettings = settings::load(&app.db, "tls").await?;
    let info = tokio::fs::read(&paths.cert).await.ok().and_then(|c| tls::cert_info(&c).ok());
    let providers: Vec<serde_json::Value> = tls::dns_providers()
        .await
        .into_iter()
        .map(|id| {
            let saved = tls::has_credentials(&paths, &id);
            json!({ "id": id, "saved": saved })
        })
        .collect();
    Ok(Json(json!({
        "settings": s,
        "certificate": info,
        "providers": providers,
        "plain_http": app.config.plain_http,
        "http_listen": app.config.http_listen.map(|a| a.to_string()),
        "listen": app.config.listen.to_string(),
    })))
}

#[derive(Deserialize)]
struct AcmeRequest {
    #[serde(flatten)]
    acme: AcmeSettings,
    /// New credentials for the DNS provider; left out, the saved ones are used.
    credentials: Option<String>,
}

async fn provider_help(_user: User, Path(code): Path<String>) -> ApiResult<impl IntoResponse> {
    let help = tls::provider_help(&code).await.map_err(|e| ApiError::bad_request(format!("{e:#}")))?;
    Ok(Json(json!({ "help": help })))
}

async fn start_acme(State(app): State<AppState>, user: User, Json(req): Json<AcmeRequest>) -> ApiResult<impl IntoResponse> {
    require_admin(&app, &user).await?;
    if app.tls.is_none() {
        return Err(ApiError::bad_request("the studio runs with plain_http - it has no certificate to replace"));
    }
    let paths = tls::Paths::new(&app.config.data_dir);
    let mut acme = req.acme;
    let dns01 = acme.challenge == "dns-01";
    acme.extra_names = acme.extra_names.iter().map(|n| n.trim().trim_end_matches('.').to_lowercase()).filter(|n| !n.is_empty()).collect();
    if let Some(bad) = acme.extra_names.iter().find(|n| !tls::valid_cert_name(n, dns01)) {
        return Err(ApiError::bad_request(if bad.starts_with("*.") {
            format!("'{bad}': a wildcard needs the DNS-01 challenge")
        } else {
            format!("'{bad}' is not a DNS name")
        }));
    }
    if acme.challenge == "dns-01" {
        if let Some(c) = req.credentials.as_deref().filter(|c| !c.trim().is_empty()) {
            tls::save_credentials(&paths, &acme.dns_provider, c)
                .await
                .map_err(|e| ApiError::bad_request(format!("{e:#}")))?;
        } else if !tls::has_credentials(&paths, &acme.dns_provider) {
            return Err(ApiError::bad_request(format!("enter the credentials for {}", acme.dns_provider)));
        }
    } else if app.config.http_listen.is_none() {
        return Err(ApiError::bad_request("HTTP-01 needs the port-80 listener (http_listen in config.toml) - or use DNS-01"));
    }
    let server: ServerSettings = settings::load(&app.db, "server").await?;
    let (db, live) = (app.db.clone(), app.tls.clone());
    let job = app
        .jobs
        .spawn("certificate", "Let's Encrypt certificate", &user.session.user, json!({ "fqdn": server.fqdn, "extra": acme.extra_names }), move |log| async move {
            let result = tls::acme_issue(&paths, live.as_ref(), &server.fqdn, &acme, &log).await;
            let mut s: TlsSettings = settings::load(&db, "tls").await.unwrap_or_default();
            s.last_check = Some(chrono::Utc::now().to_rfc3339());
            s.last_error = result.as_ref().err().map(|e| format!("{e:#}"));
            if result.is_ok() {
                s.mode = "acme".into();
                s.acme = acme;
            }
            settings::save(&db, "tls", &s).await?;
            result.map(|_| ())
        })
        .await?;
    Ok((StatusCode::ACCEPTED, Json(json!({ "id": job }))))
}

#[derive(Deserialize)]
struct ImportRequest {
    cert: String,
    key: String,
}

async fn import_cert(State(app): State<AppState>, user: User, Json(req): Json<ImportRequest>) -> ApiResult<impl IntoResponse> {
    require_admin(&app, &user).await?;
    if app.tls.is_none() {
        return Err(ApiError::bad_request("the studio runs with plain_http - it has no certificate to replace"));
    }
    let paths = tls::Paths::new(&app.config.data_dir);
    let info = tls::install(&paths, app.tls.as_ref(), req.cert.as_bytes(), req.key.as_bytes())
        .await
        .map_err(|e| ApiError::bad_request(format!("{e:#}")))?;
    let mut s: TlsSettings = settings::load(&app.db, "tls").await?;
    s.mode = "imported".into();
    s.last_error = None;
    settings::save(&app.db, "tls", &s).await?;
    Ok(Json(info))
}

async fn new_self_signed(State(app): State<AppState>, user: User) -> ApiResult<impl IntoResponse> {
    require_admin(&app, &user).await?;
    if app.tls.is_none() {
        return Err(ApiError::bad_request("the studio runs with plain_http - it has no certificate to replace"));
    }
    let server: ServerSettings = settings::load(&app.db, "server").await?;
    let (cert, key) = tls::self_signed(&tls::local_names(&server.fqdn)).map_err(anyhow::Error::from)?;
    let paths = tls::Paths::new(&app.config.data_dir);
    let info = tls::install(&paths, app.tls.as_ref(), cert.as_bytes(), key.as_bytes()).await?;
    let mut s: TlsSettings = settings::load(&app.db, "tls").await?;
    s.mode = "self-signed".into();
    s.last_error = None;
    settings::save(&app.db, "tls", &s).await?;
    Ok(Json(info))
}

// ---- Windows: virtio-win ----

async fn get_windows(State(app): State<AppState>, _user: User) -> ApiResult<impl IntoResponse> {
    let s: virtio::WindowsSettings = settings::load(&app.db, "windows").await?;
    let virtio::Upstream { releases, stable, latest } = virtio::upstream(&app.web).await;
    // Which releases PVE already holds, on the bake node's ISO storage.
    let bake: BakeSettings = settings::load(&app.db, "bake").await?;
    let mut present = Vec::new();
    if let Ok(p) = bake.resolve(&app.pve).await {
        let storage = if s.iso_storage.is_empty() { p.iso_storage.clone() } else { s.iso_storage.clone() };
        if let Ok(vols) = app.pve.storage_content(&p.node, &storage, "iso").await {
            present = vols
                .iter()
                .filter_map(|v| v.volid.rsplit('/').next())
                .filter_map(|f| f.strip_prefix("virtio-win-")?.strip_suffix(".iso").map(str::to_owned))
                .collect();
        }
    }
    let mut pe: winpe::WinPe = settings::load(&app.db, "winpe").await?;
    // A WinPE deleted in PVE is not ready: the record goes with it (the bakes would boot nothing).
    if !pe.volid.is_empty()
        && let Some((storage, _)) = pe.volid.split_once(':')
        && let Ok(vols) = app.pve.storage_content(&pe.node, storage, "iso").await
        && !vols.iter().any(|v| v.volid == pe.volid)
    {
        pe = winpe::WinPe::default();
        settings::save(&app.db, "winpe", &pe).await?;
    }
    Ok(Json(json!({ "settings": s, "releases": releases, "stable": stable, "latest": latest, "present": present, "winpe": pe })))
}

async fn put_windows(State(app): State<AppState>, user: User, Json(s): Json<virtio::WindowsSettings>) -> ApiResult<impl IntoResponse> {
    user.require(&app, "/vms", "VM.Allocate").await?;
    virtio::resolve(&s.virtio).await.map_err(|e| ApiError::bad_request(format!("{e:#}")))?;
    settings::save(&app.db, "windows", &s).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// The FoD ISO of each family and what is on it (read through the ISO mount, cached).
async fn get_fod(State(app): State<AppState>, _user: User) -> ApiResult<impl IntoResponse> {
    let s: fod::FodSettings = settings::load(&app.db, "fod").await?;
    let mut media = serde_json::Map::new();
    for (family, volid) in [("server", &s.server), ("server2022", &s.server2022), ("client", &s.client)] {
        if volid.is_empty() {
            continue;
        }
        let v = match iso_path(&app, volid) {
            // Deleted in PVE: missing - a deploy then takes the capabilities from Windows Update.
            Some(p) if !p.exists() => json!({ "ok": false, "missing": true, "error": "the ISO is not in PVE any more" }),
            Some(p) => match fod::inspect(&p, &app.config.data_dir.join("fod-cache.json")).await {
                Ok(m) => json!({ "ok": true, "media": m }),
                Err(e) => json!({ "ok": false, "error": format!("{e:#}") }),
            },
            None => json!({ "ok": false, "error": "not an ISO volume" }),
        };
        media.insert(family.into(), v);
    }
    Ok(Json(json!({ "settings": s, "media": media })))
}

#[derive(Deserialize)]
struct FodBuild {
    slot: String,
    lang: String,
}

/// Builds a release's FoD ISO from Microsoft's update servers and sets it for that release.
async fn build_fod(State(app): State<AppState>, user: User, Json(q): Json<FodBuild>) -> ApiResult<impl IntoResponse> {
    user.require(&app, "/vms", "VM.Allocate").await?;
    let src = fod::source(&q.slot).ok_or_else(|| ApiError::bad_request("no such release"))?;
    already_running(&app, "fod", "fod", src.key).await?;
    let lang = q.lang.trim().to_owned();
    if lang.is_empty() || lang.len() > 16 || !lang.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        return Err(ApiError::bad_request("not a language tag"));
    }
    let bake: BakeSettings = settings::load(&app.db, "bake").await?;
    let win: virtio::WindowsSettings = settings::load(&app.db, "windows").await?;
    let (pve, db, web, work) = (app.pve.clone(), app.db.clone(), app.web.clone(), app.config.data_dir.join("work"));
    let title = format!("Build {} Features on Demand ({lang})", src.name);
    let job = app
        .jobs
        .spawn("fod", &title, &user.session.user, json!({ "fod": src.key, "lang": lang }), move |log| async move {
            let p = bake.resolve(&pve).await?;
            let storage = if win.iso_storage.is_empty() { p.iso_storage.clone() } else { win.iso_storage.clone() };
            let built = fod::build_uup(&pve, &log, &web, &work, &p.node, &storage, src, &lang).await?;
            let mut s: fod::FodSettings = settings::load(&db, "fod").await?;
            if let Some(slot) = s.slot_mut(src.key) {
                *slot = built.volid.clone();
            }
            settings::save(&db, "fod", &s).await?;
            log.ok(format!("{} VMs use {} now ({} packages, {} satellites)", src.name, built.volid, built.packages, built.satellites)).await;
            Ok(())
        })
        .await?;
    Ok((StatusCode::ACCEPTED, Json(json!({ "id": job }))))
}

async fn put_fod(State(app): State<AppState>, user: User, Json(s): Json<fod::FodSettings>) -> ApiResult<impl IntoResponse> {
    user.require(&app, "/vms", "VM.Allocate").await?;
    for volid in [&s.server, &s.server2022, &s.client].into_iter().filter(|v| !v.is_empty()) {
        let path = iso_path(&app, volid).ok_or_else(|| ApiError::bad_request(format!("{volid} is not an ISO volume")))?;
        fod::inspect(&path, &app.config.data_dir.join("fod-cache.json"))
            .await
            .map_err(|e| ApiError::bad_request(format!("{volid}: {e:#}")))?;
    }
    settings::save(&app.db, "fod", &s).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn fetch_virtio(State(app): State<AppState>, user: User) -> ApiResult<impl IntoResponse> {
    user.require(&app, "/vms", "VM.Allocate").await?;
    let s: virtio::WindowsSettings = settings::load(&app.db, "windows").await?;
    let bake: BakeSettings = settings::load(&app.db, "bake").await?;
    let pve = app.pve.clone();
    let job = app
        .jobs
        .spawn("virtio", "virtio-win drivers", &user.session.user, json!({ "virtio": s.virtio }), move |log| async move {
            let p = bake.resolve(&pve).await?;
            let release = virtio::resolve(&s.virtio).await?;
            log.line(format!("virtio-win {} resolves to {release}", s.virtio)).await;
            let storage = if s.iso_storage.is_empty() { p.iso_storage.clone() } else { s.iso_storage.clone() };
            virtio::fetch(&pve, &log, &p.node, &storage, &release).await.map(|_| ())
        })
        .await?;
    Ok((StatusCode::ACCEPTED, Json(json!({ "id": job }))))
}

// ---- Windows golds ----

/// Where the studio sees an ISO volume: <iso_root>/<storage>/<file>.
fn iso_path(app: &AppState, volid: &str) -> Option<std::path::PathBuf> {
    let (storage, rest) = volid.split_once(':')?;
    let file = rest.strip_prefix("iso/")?;
    if file.contains('/') || file.contains("..") || storage.contains('/') {
        return None;
    }
    Some(app.config.iso_root.join(storage).join(file))
}

/// Why an ISO PVE has is not readable here: the container's bind mount of that storage
/// holds a directory the host has deleted (link count 0) - a storage directory removed and
/// made again on the host leaves the mount on the old one until the container restarts.
fn iso_unreadable_why(iso_root: &std::path::Path, volid: &str) -> String {
    use std::os::unix::fs::MetadataExt;
    let storage = volid.split_once(':').map(|(s, _)| s).unwrap_or("");
    match std::fs::metadata(iso_root.join(storage)) {
        Ok(m) if m.nlink() == 0 => format!(
            " - the studio's mount of storage {storage} is stale (its directory was deleted and made again on the node); restart the studio's container to remount it"
        ),
        _ => String::new(),
    }
}

/// The ISO volumes on the bake node, and whether the studio can read each one.
async fn windows_isos(State(app): State<AppState>, _user: User) -> ApiResult<impl IntoResponse> {
    let bake: BakeSettings = settings::load(&app.db, "bake").await?;
    let p = bake.resolve(&app.pve).await?;
    let res = app.pve.resources().await?;
    let mut out = Vec::new();
    for s in res.iter().filter(|r| r.kind == "storage" && r.node.as_deref() == Some(&p.node) && r.has_content("iso")) {
        let storage = s.storage.clone().unwrap_or_default();
        for v in app.pve.storage_content(&p.node, &storage, "iso").await.unwrap_or_default() {
            let file = v.volid.rsplit('/').next().unwrap_or("").to_owned();
            // The studio's own ISOs (seeds, WinPE) and the driver ISOs are not Windows media.
            if file.starts_with("pvs-") || file.starts_with("virtio-win") {
                continue;
            }
            let readable = iso_path(&app, &v.volid).is_some_and(|p| p.exists());
            out.push(json!({ "volid": v.volid, "file": file, "size": v.size, "storage": storage, "readable": readable }));
        }
    }
    Ok(Json(json!({ "node": p.node, "isos": out, "iso_root": app.config.iso_root })))
}

#[derive(Deserialize)]
struct IsoQuery {
    volid: String,
}

async fn windows_images(State(app): State<AppState>, _user: User, axum::extract::Query(q): axum::extract::Query<IsoQuery>) -> ApiResult<impl IntoResponse> {
    let path = iso_path(&app, &q.volid).ok_or_else(|| ApiError::bad_request("not an ISO volume"))?;
    if !path.exists() {
        return Err(ApiError::bad_request(format!(
            "the studio cannot read {} - its ISO storage is not mounted into the container at {}",
            q.volid,
            app.config.iso_root.display()
        )));
    }
    let images = wim::inspect(&path, &app.config.data_dir.join("wim-cache.json"))
        .await
        .map_err(|e| ApiError::bad_request(format!("{e:#}")))?;
    let out: Vec<serde_json::Value> = images
        .iter()
        .map(|i| {
            json!({
                "index": i.index, "name": i.name, "edition_id": i.edition_id,
                "installation_type": i.installation_type, "language": i.language, "build": i.build, "version": i.version,
                "size_gb": (i.total_bytes as f64 / (1u64 << 30) as f64 * 10.0).round() / 10.0,
                "image_id": windows::image_id(i),
                // The virtual editions this index can be baked as, with the gold id each gives.
                // ...unless the ISO holds that edition as an image of its own: then that index
                // is the honest way to it, and the upgrade would only bake the same gold twice.
                "virtual": windows::VIRTUAL_EDITIONS.iter().filter(|v| windows::virtual_edition_fits(v.key, i) && !windows::virtual_on_media(v.key, &images))
                    .map(|v| json!({ "key": v.key, "label": v.display, "image_id": windows::gold_image_id(i, v.key) })).collect::<Vec<_>>(),
            })
        })
        .collect();
    Ok(Json(json!({
        "images": out,
        "timezones": windows::TIME_ZONES.iter().map(|(w, i)| json!({ "id": w, "iana": i })).collect::<Vec<_>>(),
        // The container runs in the node's time zone (installed with --timezone host).
        "default_timezone": windows::windows_tz_for(
            std::fs::read_to_string("/etc/timezone").unwrap_or_default().trim()
        ),
        "features": windows::WIN_FEATURES.iter().map(|(id, l)| json!({ "id": id, "label": l })).collect::<Vec<_>>(),
    })))
}

async fn start_windows_bake(
    State(app): State<AppState>,
    user: User,
    Json(opt): Json<windows::WinBakeOptions>,
) -> ApiResult<impl IntoResponse> {
    user.require(&app, "/vms", "VM.Allocate").await?;
    let path = iso_path(&app, &opt.iso).ok_or_else(|| ApiError::bad_request("not an ISO volume"))?;
    let images = wim::inspect(&path, &app.config.data_dir.join("wim-cache.json"))
        .await
        .map_err(|e| ApiError::bad_request(format!("{e:#}")))?;
    let img = images
        .into_iter()
        .find(|i| i.index == opt.index)
        .ok_or_else(|| ApiError::bad_request(format!("{} has no image {}", opt.iso, opt.index)))?;
    if let Some(bad) = opt.features.iter().find(|f| !windows::WIN_FEATURES.iter().any(|(id, _)| id == f)) {
        return Err(ApiError::bad_request(format!("unknown policy {bad}")));
    }
    let bake: BakeSettings = settings::load(&app.db, "bake").await?;
    let win: virtio::WindowsSettings = settings::load(&app.db, "windows").await?;
    let pe: winpe::WinPe = settings::load(&app.db, "winpe").await?;
    if pe.volid.is_empty() {
        return Err(ApiError::bad_request("no WinPE yet - build it under Settings → Windows first"));
    }
    let gold_id = golds::new_build_id(&app.db, &app.pve).await?;
    let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    if !opt.edition_upgrade.is_empty() {
        let v = windows::virtual_edition(&opt.edition_upgrade)
            .ok_or_else(|| ApiError::bad_request(format!("unknown virtual edition {}", opt.edition_upgrade)))?;
        if !windows::virtual_edition_fits(v.key, &img) {
            return Err(ApiError::bad_request(format!("{} cannot become {}. {}", img.name, v.display, v.hint)));
        }
    }
    let image_id = windows::gold_image_id(&img, &opt.edition_upgrade);
    sqlx::query(
        "INSERT INTO golds (id, image_id, os, name, node, storage, status, options, created_at) \
         VALUES (?, ?, 'windows', ?, '', '', 'baking', ?, ?)",
    )
    .bind(&gold_id)
    .bind(&image_id)
    .bind(golds::working_name(&gold_id))
    .bind(serde_json::to_string(&opt).unwrap_or_default())
    .bind(&now)
    .execute(&app.db)
    .await?;

    let (pve, db, work) = (app.pve.clone(), app.db.clone(), app.config.data_dir.join("work"));
    let sha_cache = app.config.data_dir.join("iso-sha256-cache.json");
    let gid = gold_id.clone();
    let title = format!(
        "Bake {} ({})",
        windows::virtual_edition(&opt.edition_upgrade).map(|v| v.display.to_owned()).unwrap_or_else(|| img.name.clone()),
        golds::working_name(&gold_id)
    );
    let job = app
        .jobs
        .spawn("bake", &title, &user.session.user, json!({ "gold": gold_id, "iso": opt.iso, "index": opt.index }), move |log| async move {
            let result = async {
                let p = bake.resolve(&pve).await?.with_disk_storage(&pve, opt.disk_storage.as_deref()).await?;
                sqlx::query("UPDATE golds SET node = ?, storage = ? WHERE id = ?")
                    .bind(&p.node)
                    .bind(&p.disk_storage)
                    .bind(&gid)
                    .execute(&db)
                    .await?;
                log.run(format!(
                    "Baking {} (index {} of {}) on {}: disk on {}",
                    img.name, img.index, opt.iso, p.node, p.disk_storage
                ))
                .await;
                log.run(format!("Hashing {} (SHA-256)", opt.iso)).await;
                let clock = std::time::Instant::now();
                let iso_sha256 = golds::iso_sha256(&path, &sha_cache).await?;
                log.ok(format!("SHA-256 {iso_sha256} ({}s)", clock.elapsed().as_secs())).await;
                let release = virtio::resolve(&win.virtio).await?;
                let iso_storage = if win.iso_storage.is_empty() { p.iso_storage.clone() } else { win.iso_storage.clone() };
                let virtio_volid = virtio::fetch(&pve, &log, &p.node, &iso_storage, &release).await?;
                if pe.node != p.node {
                    anyhow::bail!("the WinPE was built on {}, the bake runs on {} - rebuild it there under Settings", pe.node, p.node);
                }
                windows::bake(
                    windows::WinBake { pve: &pve, db: &db, log: &log, work: &work },
                    &gid,
                    &p,
                    &img,
                    &opt,
                    &pe.volid,
                    &virtio_volid,
                    &release,
                    &iso_sha256,
                )
                .await
            }
            .await;
            if result.is_err() {
                let _ = sqlx::query("UPDATE golds SET status = 'failed' WHERE id = ? AND status = 'baking'")
                    .bind(&gid)
                    .execute(&db)
                    .await;
            }
            result
        })
        .await?;
    sqlx::query("UPDATE golds SET job_id = ? WHERE id = ?").bind(&job).bind(&gold_id).execute(&app.db).await?;
    Ok((StatusCode::ACCEPTED, Json(json!({ "id": job, "gold": gold_id }))))
}

// ---- WinPE ----

async fn get_winpe(State(app): State<AppState>, _user: User) -> ApiResult<impl IntoResponse> {
    let pe: winpe::WinPe = settings::load(&app.db, "winpe").await?;
    Ok(Json(pe))
}

async fn build_winpe(State(app): State<AppState>, user: User, Json(q): Json<IsoQuery>) -> ApiResult<impl IntoResponse> {
    user.require(&app, "/vms", "VM.Allocate").await?;
    let path = iso_path(&app, &q.volid).ok_or_else(|| ApiError::bad_request("not an ISO volume"))?;
    if !path.exists() {
        return Err(ApiError::bad_request(format!("the studio cannot read {}", q.volid)));
    }
    let bake: BakeSettings = settings::load(&app.db, "bake").await?;
    let win: virtio::WindowsSettings = settings::load(&app.db, "windows").await?;
    let (pve, db, work) = (app.pve.clone(), app.db.clone(), app.config.data_dir.join("work"));
    let iso_root = app.config.iso_root.clone();
    let volid = q.volid.clone();
    let job = app
        .jobs
        .spawn("winpe", "Build WinPE", &user.session.user, json!({ "iso": q.volid }), move |log| async move {
            let p = bake.resolve(&pve).await?;
            let storage = if win.iso_storage.is_empty() { p.iso_storage.clone() } else { win.iso_storage.clone() };
            // The virtio ISO, for the vioscsi driver WinPE carries from now on.
            let release = virtio::resolve(&win.virtio).await?;
            let vio_volid = virtio::fetch(&pve, &log, &p.node, &storage, &release).await?;
            let vio_path = iso_root.join(storage.as_str()).join(virtio::iso_name(&release));
            let vio = vio_path.exists().then_some((release.as_str(), vio_path.as_path()));
            // vioscsi is not optional: every pass reaches its virtio-scsi disk through it.
            if vio.is_none() {
                anyhow::bail!("{vio_volid} is not readable through the studio's ISO mount, and WinPE is never built without vioscsi{}", iso_unreadable_why(&iso_root, &vio_volid));
            }
            winpe::build(&pve, &db, &log, &work, &volid, &path, &p.node, &storage, vio).await.map(|_| ())
        })
        .await?;
    Ok((StatusCode::ACCEPTED, Json(json!({ "id": job }))))
}

#[derive(Deserialize)]
struct UupProduct {
    #[serde(default)]
    product: String,
}

/// The full builds of a product in the UUP dump catalog, newest first.
async fn uup_builds(State(app): State<AppState>, _user: User, axum::extract::Query(q): axum::extract::Query<UupProduct>) -> ApiResult<impl IntoResponse> {
    let product = if q.product.is_empty() { "Windows Server 2025" } else { q.product.as_str() };
    if !matches!(product, "Windows Server 2025" | "Windows 11, version 26H2") {
        return Err(ApiError::bad_request(format!("'{product}' is not a product the studio builds from")));
    }
    let builds = uup::builds(&app.web, product).await?;
    Ok(Json(json!({ "product": product, "builds": builds.into_iter().take(12).collect::<Vec<_>>() })))
}

#[derive(Deserialize)]
struct UupId {
    id: String,
}

async fn uup_languages(State(app): State<AppState>, _user: User, axum::extract::Query(q): axum::extract::Query<UupId>) -> ApiResult<impl IntoResponse> {
    let langs = uup::languages(&app.web, &q.id).await?;
    Ok(Json(langs))
}

#[derive(Deserialize)]
struct UupWinPe {
    uuid: String,
    lang: String,
    #[serde(default)]
    build: String,
}

/// WinPE from Microsoft's own files - no Windows ISO needed.
async fn build_winpe_uup(State(app): State<AppState>, user: User, Json(q): Json<UupWinPe>) -> ApiResult<impl IntoResponse> {
    user.require(&app, "/vms", "VM.Allocate").await?;
    let ok = |s: &str| !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-');
    if !ok(&q.uuid) || !ok(&q.lang) {
        return Err(ApiError::bad_request("not a UUP build id and language"));
    }
    let bake: BakeSettings = settings::load(&app.db, "bake").await?;
    let win: virtio::WindowsSettings = settings::load(&app.db, "windows").await?;
    let (pve, db, web, work) = (app.pve.clone(), app.db.clone(), app.web.clone(), app.config.data_dir.join("work"));
    let iso_root = app.config.iso_root.clone();
    let title = if q.build.is_empty() { "Build WinPE from Microsoft".to_owned() } else { format!("Build WinPE {} from Microsoft", q.build) };
    let job = app
        .jobs
        .spawn("winpe", &title, &user.session.user, json!({ "uup": q.uuid, "lang": q.lang, "build": q.build }), move |log| async move {
            let p = bake.resolve(&pve).await?;
            let storage = if win.iso_storage.is_empty() { p.iso_storage.clone() } else { win.iso_storage.clone() };
            let release = virtio::resolve(&win.virtio).await?;
            let vio_volid = virtio::fetch(&pve, &log, &p.node, &storage, &release).await?;
            let vio_path = iso_root.join(storage.as_str()).join(virtio::iso_name(&release));
            let vio = vio_path.exists().then_some((release.as_str(), vio_path.as_path()));
            // vioscsi is not optional: every pass reaches its virtio-scsi disk through it.
            if vio.is_none() {
                anyhow::bail!("{vio_volid} is not readable through the studio's ISO mount, and WinPE is never built without vioscsi{}", iso_unreadable_why(&iso_root, &vio_volid));
            }
            winpe::build_uup(&pve, &db, &log, &web, &work, &q.uuid, &q.lang, &p.node, &storage, vio).await.map(|_| ())
        })
        .await?;
    Ok((StatusCode::ACCEPTED, Json(json!({ "id": job }))))
}

// ---- resource pools ----

/// PVE's resource pools, for the VM card's Pool picker - every pool, also the empty ones.
async fn list_pools(State(app): State<AppState>, _user: User) -> ApiResult<impl IntoResponse> {
    let pools: Vec<serde_json::Value> = app.pve.get("/pools").await?;
    let mut out: Vec<serde_json::Value> = pools
        .into_iter()
        .map(|p| json!({ "id": p["poolid"], "comment": p["comment"].as_str().unwrap_or("") }))
        .collect();
    out.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
    Ok(Json(out))
}

#[derive(Deserialize)]
struct NewPool {
    name: String,
    #[serde(default)]
    comment: String,
}

/// Creates a pool now, so the picker can select it (PVE's own rule: Pool.Allocate).
async fn create_pool(State(app): State<AppState>, user: User, Json(q): Json<NewPool>) -> ApiResult<impl IntoResponse> {
    user.require(&app, "/pool", "Pool.Allocate").await?;
    let name = q.name.trim();
    let ok = !name.is_empty() && name.len() <= 64 && name.chars().all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c));
    if !ok {
        return Err(ApiError::bad_request("a pool name is letters, digits, '-', '_' and '.' - up to 64"));
    }
    app.pve.ensure_pool(name, q.comment.trim()).await?;
    Ok((StatusCode::CREATED, Json(json!({ "id": name }))))
}

// ---- Windows media (UUP) ----

#[derive(Deserialize)]
struct MediaQuery {
    #[serde(default)]
    product: String,
    #[serde(default)]
    id: String,
    #[serde(default)]
    lang: String,
    #[serde(default)]
    editions: String,
    #[serde(default)]
    fresh: bool,
}

/// Every product with its newest build, from one reading of the catalog.
async fn media_products(State(app): State<AppState>, _user: User, axum::extract::Query(q): axum::extract::Query<MediaQuery>) -> ApiResult<impl IntoResponse> {
    let mut out = Vec::new();
    for p in uup::PRODUCTS {
        let builds = uup::product_builds(&app.web, p, q.fresh).await?;
        let newest = builds.first().map(|b| json!({ "build": b.build, "created": b.created, "kind": uup::release_kind(p, b.created) }));
        out.push(json!({ "id": p.id, "name": p.name, "group": p.group, "kind": p.kind, "insider": p.insider, "support": p.support, "count": builds.len(), "newest": newest }));
    }
    Ok(Json(json!({ "products": out, "checked": uup::catalog_age().await })))
}

/// A product's builds, newest first - every one of them can be built.
async fn media_builds(State(app): State<AppState>, _user: User, axum::extract::Query(q): axum::extract::Query<MediaQuery>) -> ApiResult<impl IntoResponse> {
    let p = uup::product(&q.product).ok_or_else(|| ApiError::bad_request("no such product"))?;
    let builds = uup::product_builds(&app.web, p, q.fresh).await?;
    let built = live_media_isos(&app).await;
    let out: Vec<serde_json::Value> = builds
        .iter()
        .take(60)
        .map(|b| {
            let isos: Vec<&media::MediaIso> = built.iter().filter(|m| m.uuid == b.uuid || (m.product == p.id && m.build == b.build)).collect();
            json!({ "uuid": b.uuid, "build": b.build, "title": b.title, "created": b.created, "kind": uup::release_kind(p, b.created), "isos": isos })
        })
        .collect();
    Ok(Json(json!({ "product": p.id, "builds": out })))
}

/// A build's languages and, in one of them, its editions with Microsoft's names.
async fn media_editions(State(app): State<AppState>, _user: User, axum::extract::Query(q): axum::extract::Query<MediaQuery>) -> ApiResult<impl IntoResponse> {
    let ok = |s: &str| !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-');
    if !ok(&q.id) {
        return Err(ApiError::bad_request("not a UUP build id"));
    }
    let langs = uup::languages(&app.web, &q.id).await?;
    let lang = if ok(&q.lang) && langs.contains(&q.lang) { q.lang.clone() } else if langs.iter().any(|l| l == "en-us") { "en-us".into() } else { langs.first().cloned().unwrap_or_default() };
    let mut editions = if lang.is_empty() { vec![] } else { uup::editions_named(&app.web, &q.id, &lang).await? };
    // Azure Edition (SERVERTURBINE) is a bake choice - an edition upgrade of Datacenter - not media.
    editions.retain(|(code, _)| !code.to_uppercase().starts_with("SERVERTURBINE"));
    Ok(Json(json!({ "langs": langs, "lang": lang,
        "editions": editions.into_iter().map(|(code, name)| json!({ "code": code, "name": name })).collect::<Vec<_>>() })))
}

/// What a build downloads, before it starts: the edition images, the updates, the rest.
async fn media_size(State(app): State<AppState>, _user: User, axum::extract::Query(q): axum::extract::Query<MediaQuery>) -> ApiResult<impl IntoResponse> {
    let p = uup::product(&q.product).ok_or_else(|| ApiError::bad_request("no such product"))?;
    let editions: Vec<String> = q.editions.split(',').filter(|e| !e.is_empty()).map(str::to_owned).collect();
    if editions.is_empty() {
        return Ok(Json(json!({ "total": 0, "updates": 0, "files": 0 })));
    }
    let mut files: Vec<uup::File> = Vec::new();
    for e in &editions {
        for f in uup::files_cached(&app.web, &q.id, &q.lang, e).await? {
            if media::wanted(p.kind, &f, &editions, &q.lang) && !media::deferrable(p.kind, &f.name) && !files.iter().any(|x| x.name == f.name) {
                files.push(f);
            }
        }
    }
    let updates: u64 = files.iter().filter(|f| media::is_update(&f.name)).map(|f| f.size).sum();
    let total: u64 = files.iter().map(|f| f.size).sum();
    let free = std::process::Command::new("df").args(["-B1", "--output=avail"]).arg(app.config.data_dir.join("work")).output().ok()
        .and_then(|o| String::from_utf8_lossy(&o.stdout).lines().nth(1).and_then(|l| l.trim().parse::<u64>().ok()));
    Ok(Json(json!({ "total": total, "updates": updates, "files": files.len(), "free": free,
        "worker": files.iter().any(|f| media::is_update(&f.name)) })))
}

#[derive(Deserialize)]
struct MediaBuild {
    product: String,
    uuid: String,
    build: String,
    lang: String,
    editions: Vec<String>,
}

async fn media_build(State(app): State<AppState>, user: User, Json(q): Json<MediaBuild>) -> ApiResult<impl IntoResponse> {
    user.require(&app, "/vms", "VM.Allocate").await?;
    let p = uup::product(&q.product).ok_or_else(|| ApiError::bad_request("no such product"))?;
    let ok = |s: &str| !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.');
    if !ok(&q.uuid) || !ok(&q.lang) || !ok(&q.build) || q.editions.is_empty() || !q.editions.iter().all(|e| ok(e) && !e.to_uppercase().starts_with("SERVERTURBINE")) {
        return Err(ApiError::bad_request("pick a build, a language and at least one edition"));
    }
    already_running(&app, "media", "uuid", &q.uuid).await?;
    let bake: BakeSettings = settings::load(&app.db, "bake").await?;
    let (pve, db, web, work) = (app.pve.clone(), app.db.clone(), app.web.clone(), app.config.data_dir.join("work"));
    // How the worker reaches the studio: this very server, its key pinned.
    let port = app.config.listen.port();
    let link = if app.config.plain_http {
        media::Link { base: format!("http://{{ip}}:{port}"), pin: String::new() }
    } else {
        let cert = tokio::fs::read(tls::Paths::new(&app.config.data_dir).cert).await.map_err(|e| ApiError::from(anyhow::anyhow!("reading the studio's certificate: {e}")))?;
        let pin = media::cert_pin(&cert).ok_or_else(|| ApiError::from(anyhow::anyhow!("could not read the studio's certificate key")))?;
        media::Link { base: format!("https://{{ip}}:{port}"), pin }
    };
    let title = format!("Build {} {} media ({})", p.name, q.build, uup::lang_tag(&q.lang));
    let job = app
        .jobs
        .spawn("media", &title, &user.session.user, json!({ "media": p.id, "build": q.build, "uuid": q.uuid, "lang": q.lang, "editions": q.editions }), move |log| async move {
            let pl = bake.resolve(&pve).await?;
            let req = media::Request { product: p, uuid: q.uuid, build: q.build, lang: q.lang, editions: q.editions };
            media::build(&pve, &db, &log, &web, &work, &pl, link, req).await.map(|_| ())
        })
        .await?;
    Ok((StatusCode::ACCEPTED, Json(json!({ "id": job }))))
}

// ---- the studio's own version and updates ----

#[derive(Deserialize, Default)]
struct VersionQuery {
    #[serde(default)]
    fresh: Option<String>,
}

/// This build, GitHub's releases and the update settings.
async fn studio_version(State(app): State<AppState>, _user: User, axum::extract::Query(q): axum::extract::Query<VersionQuery>) -> ApiResult<impl IntoResponse> {
    let s: update::UpdateSettings = settings::load(&app.db, "update").await.unwrap_or_default();
    let mut v = update::status(&app.web, q.fresh.is_some(), s.development()).await;
    v["auto"] = json!(s.auto);
    Ok(Json(v))
}

#[derive(Deserialize)]
struct UpdateBody {
    tag: String,
}

/// Installs a release: an admin action, one at a time.
async fn studio_update(State(app): State<AppState>, user: User, Json(q): Json<UpdateBody>) -> ApiResult<impl IntoResponse> {
    require_admin(&app, &user).await?;
    let busy: Option<(String,)> = sqlx::query_as("SELECT title FROM jobs WHERE status = 'running' AND kind = 'update'").fetch_optional(&app.db).await?;
    if let Some((t,)) = busy {
        return Err(ApiError::new(StatusCode::CONFLICT, format!("{t} is running already")));
    }
    let id = start_update(&app, &q.tag, &user.session.user).await?;
    Ok((StatusCode::ACCEPTED, Json(json!({ "id": id }))))
}

pub async fn start_update(app: &AppState, tag: &str, by: &str) -> anyhow::Result<String> {
    let (web, data, jobs, tag) = (app.web.clone(), app.config.data_dir.clone(), app.jobs.clone(), tag.to_owned());
    let title = format!("Update the studio to {}", tag.trim_start_matches('v'));
    let jobs2 = jobs.clone();
    // The job learns its own id once spawned (it writes it into the helper's request).
    let (tx, rx) = tokio::sync::oneshot::channel::<String>();
    let id = jobs
        .spawn("update", &title, by, json!({ "tag": tag }), move |log| async move {
            let id = rx.await.unwrap_or_default();
            update::run(web, data, log, jobs2, id, tag).await
        })
        .await?;
    let _ = tx.send(id.clone());
    Ok(id)
}

async fn get_update_settings(State(app): State<AppState>, _user: User) -> ApiResult<impl IntoResponse> {
    let s: update::UpdateSettings = settings::load(&app.db, "update").await.unwrap_or_default();
    Ok(Json(s))
}

async fn put_update_settings(State(app): State<AppState>, user: User, Json(s): Json<update::UpdateSettings>) -> ApiResult<impl IntoResponse> {
    require_admin(&app, &user).await?;
    settings::save(&app.db, "update", &s).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn media_isos(State(app): State<AppState>, _user: User) -> ApiResult<impl IntoResponse> {
    Ok(Json(live_media_isos(&app).await))
}

/// The ISOs the studio built that are still in PVE - one deleted in PVE (or by a clean-up)
/// drops out of the record too, so nothing claims "built" for what is gone.
async fn live_media_isos(app: &AppState) -> Vec<media::MediaIso> {
    let list: Vec<media::MediaIso> = settings::load(&app.db, "media_isos").await.unwrap_or_default();
    let Ok(res) = app.pve.resources().await else { return list };
    let mut have = std::collections::HashSet::new();
    for s in res.iter().filter(|r| r.kind == "storage" && r.has_content("iso")) {
        let (Some(node), Some(storage)) = (s.node.as_deref(), s.storage.as_deref()) else { continue };
        match app.pve.storage_content(node, storage, "iso").await {
            Ok(v) => have.extend(v.into_iter().map(|v| v.volid)),
            // A storage that does not answer: keep the record rather than drop a real ISO.
            Err(_) => return list,
        }
    }
    let live: Vec<media::MediaIso> = list.iter().filter(|i| have.contains(&i.volid)).cloned().collect();
    if live.len() != list.len() {
        let _ = settings::save(&app.db, "media_isos", &live).await;
    }
    live
}

// ---- labs ----

async fn list_labs(State(app): State<AppState>, _user: User) -> ApiResult<impl IntoResponse> {
    Ok(Json(labs::list(&app.db).await?))
}

#[derive(Deserialize)]
struct LabBody {
    name: String,
    #[serde(default)]
    state: serde_json::Value,
    #[serde(default)]
    revision: i64,
}

fn lab_json(l: labs::LabRow) -> serde_json::Value {
    json!({
        "id": l.id, "name": l.name, "revision": l.revision, "updated_by": l.updated_by,
        "updated_at": l.updated_at, "state": serde_json::from_str::<serde_json::Value>(&l.state).unwrap_or_default(),
    })
}

async fn create_lab(State(app): State<AppState>, user: User, Json(b): Json<LabBody>) -> ApiResult<impl IntoResponse> {
    let name = b.name.trim();
    if name.is_empty() {
        return Err(ApiError::bad_request("a lab needs a name"));
    }
    let state = if b.state.is_null() { "{}".to_owned() } else { b.state.to_string() };
    let l = labs::create(&app.db, name, &state, &user.session.user).await?;
    Ok((StatusCode::CREATED, Json(lab_json(l))))
}

async fn get_lab(State(app): State<AppState>, _user: User, Path(id): Path<String>) -> ApiResult<impl IntoResponse> {
    let l = labs::get(&app.db, &id).await?.ok_or_else(|| ApiError::not_found("no such lab"))?;
    Ok(Json(lab_json(l)))
}

async fn save_lab(State(app): State<AppState>, user: User, Path(id): Path<String>, Json(b): Json<LabBody>) -> ApiResult<impl IntoResponse> {
    let name = b.name.trim();
    if name.is_empty() {
        return Err(ApiError::bad_request("a lab needs a name"));
    }
    match labs::save(&app.db, &id, name, &b.state.to_string(), b.revision, &user.session.user).await? {
        Some(rev) => Ok(Json(json!({ "revision": rev }))),
        None => {
            let current = labs::get(&app.db, &id).await?.ok_or_else(|| ApiError::not_found("no such lab"))?;
            Err(ApiError::new(
                StatusCode::CONFLICT,
                format!("{} saved this lab in the meantime (revision {}) - reload it", current.updated_by, current.revision),
            ))
        }
    }
}

async fn delete_lab(State(app): State<AppState>, user: User, Path(id): Path<String>) -> ApiResult<impl IntoResponse> {
    user.require(&app, "/vms", "VM.Allocate").await?;
    labs::delete(&app.db, &id).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct DeployRequest {
    /// Which of the lab's VMs; empty = every one not built yet.
    #[serde(default)]
    names: Vec<String>,
}

/// One designed VM (the studio's `servers[]` entry) as a build on PVE - what Build-Vms.ps1
/// read out of config.json, mapped: vSwitch → bridge, differencing disk → linked clone,
/// automatic start → start with the node.
/// The join account that applies to a designed VM - the studio's effectiveDomainJoinAccount:
/// the image may refuse, "use for every VM" wins when there is exactly one account, else
/// the VM's own attachment.
fn domain_join_for(s: &serde_json::Value, state: &serde_json::Value) -> Option<crate::guest::DomainJoin> {
    let image = s["imageId"].as_str().unwrap_or("");
    if catalog::linux(image).is_some_and(|i| !i.domain_join) {
        return None;
    }
    let accounts = state["domainJoinAccounts"].as_array().cloned().unwrap_or_default();
    let acc = if state["defaults"]["domainJoinAllVms"].as_bool().unwrap_or(false) && accounts.len() == 1 {
        accounts[0].clone()
    } else if s["domainJoin"]["enabled"].as_bool().unwrap_or(false) {
        let id = s["domainJoin"]["accountId"].as_str().unwrap_or("");
        accounts.iter().find(|a| a["id"].as_str() == Some(id)).cloned()?
    } else {
        return None;
    };
    let list = |v: &serde_json::Value| -> Vec<String> {
        v.as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_owned)).filter(|x| !x.trim().is_empty()).collect()).unwrap_or_default()
    };
    // A VM's own sudo groups replace the account's (the studio's per-VM override).
    let own = list(&s["djSudoGroups"]);
    Some(crate::guest::DomainJoin {
        domain: acc["domain"].as_str().unwrap_or("").trim().to_owned(),
        user: acc["joinUser"].as_str().unwrap_or("").trim().to_owned(),
        password: acc["joinPassword"].as_str().unwrap_or("").to_owned(),
        ou: s["domainJoin"]["ouPath"].as_str().unwrap_or("").trim().to_owned(),
        sudo_groups: if own.is_empty() { list(&acc["sudoGroups"]) } else { own },
        login_groups: list(&acc["loginGroups"]),
        // The studio's effectiveDomainJoinMode: pinned on the card, else a client with an
        // OU defers (its join needs the OU's rights after OOBE), everything else specialize.
        mode: match s["domainJoin"]["mode"].as_str() {
            Some(m @ ("specialize" | "deferred")) => m.to_owned(),
            _ => {
                let client = image.starts_with("w11-") || image.starts_with("w10-");
                let ou = s["domainJoin"]["ouPath"].as_str().unwrap_or("").trim();
                if client && !ou.is_empty() { "deferred".into() } else { "specialize".into() }
            }
        },
    })
}

/// The Arc principal for a designed VM - effectiveAzureArcPrincipal. hostContext is gone
/// with Hyper-V (it was PowerShell Direct); only service principals onboard.
fn arc_for(s: &serde_json::Value, state: &serde_json::Value) -> Option<crate::guest::AzureArc> {
    let image = s["imageId"].as_str().unwrap_or("");
    if catalog::linux(image).is_some_and(|i| !i.azure_arc) {
        return None;
    }
    let principals = state["azureArcPrincipals"].as_array().cloned().unwrap_or_default();
    let p = if state["defaults"]["azureArcAllVms"].as_bool().unwrap_or(false) && principals.len() == 1 {
        principals[0].clone()
    } else if s["azureArc"]["enabled"].as_bool().unwrap_or(false) {
        let id = s["azureArc"]["principalId"].as_str().unwrap_or("");
        principals.iter().find(|a| a["id"].as_str() == Some(id)).cloned()?
    } else {
        return None;
    };
    if p["authMode"].as_str() != Some("servicePrincipal") {
        return None;
    }
    let f = |k: &str| p[k].as_str().unwrap_or("").trim().to_owned();
    Some(crate::guest::AzureArc {
        auth_mode: "servicePrincipal".into(),
        app_id: f("servicePrincipalAppId"),
        secret: p["servicePrincipalSecret"].as_str().unwrap_or("").to_owned(),
        tenant_id: f("tenantId"),
        subscription_id: f("subscriptionId"),
        resource_group: f("resourceGroup"),
        location: f("location"),
    })
}

/// The Windows licenses blade: the key of the licence the VM is attached to, when that
/// licence's gold is the VM's image; "" otherwise (the gold's KMS client key stays).
fn license_for(s: &serde_json::Value, state: &serde_json::Value) -> String {
    let image = s["imageId"].as_str().unwrap_or("");
    let lid = s["windowsLicense"]["licenseId"].as_str().unwrap_or("");
    if lid.is_empty() {
        return String::new();
    }
    state["windowsLicenses"]
        .as_array()
        .and_then(|l| l.iter().find(|x| x["id"].as_str() == Some(lid) && x["imageId"].as_str() == Some(image)))
        .and_then(|x| x["productKey"].as_str())
        .map(|k| k.trim().to_uppercase())
        .filter(|k| crate::windows::product_key_ok(k))
        .unwrap_or_default()
}

fn spec_from_design(s: &serde_json::Value, state: &serde_json::Value, lab_name: &str, gold_id: &str, default_bridge: &str) -> VmSpec {
    let defaults = &state["defaults"];
    let str_of = |k: &str| s[k].as_str().unwrap_or("").trim().to_owned();
    let builtin_admin = s["builtInAdminOnly"].as_bool().unwrap_or(false);
    let user = if builtin_admin { "Administrator".to_owned() } else { str_of("localUserName") };
    let bridge = str_of("switchName");
    VmSpec {
        name: str_of("name").to_lowercase(),
        card: str_of("_id"),
        gold: gold_id.to_owned(),
        cores: s["cpuCount"].as_u64().unwrap_or(2).max(1) as u32,
        memory_mb: (s["memoryGB"].as_f64().unwrap_or(4.0) * 1024.0) as u32,
        disk_gb: s["osDiskGB"].as_u64().or_else(|| s["osDiskGB"].as_str().and_then(|v| v.parse().ok())).map(|v| v as u32),
        // Linked only when asked for in so many words: a full copy is the default.
        linked: s["useDifferencingDisk"].as_bool().unwrap_or(false) && s["linkedCloneChosen"].as_bool().unwrap_or(false),
        // The card's placement, else General Settings', else the gold's (empty).
        node: [str_of("pveNode"), defaults["pveNode"].as_str().unwrap_or("").to_owned()].into_iter().find(|v| !v.is_empty()).unwrap_or_default(),
        storage: [str_of("pveStorage"), defaults["pveStorage"].as_str().unwrap_or("").to_owned()].into_iter().find(|v| !v.is_empty()).unwrap_or_default(),
        bridge: if bridge.is_empty() { default_bridge.to_owned() } else { bridge },
        vlan: s["vlanId"].as_u64().map(|v| v as u16),
        ip: str_of("ipAddress"),
        prefix: s["prefixLength"].as_u64().unwrap_or(24) as u8,
        gateway: str_of("defaultGateway"),
        dns: s["dnsServers"].as_array().map(|a| a.iter().filter_map(|d| d.as_str().map(str::to_owned)).filter(|d| !d.is_empty()).collect()).unwrap_or_default(),
        search: String::new(),
        user: if user.is_empty() { "admin".into() } else { user },
        password: str_of("localUserPassword"),
        ssh_key: str_of("sshAuthorizedKey"),
        packages: s["linuxPackages"].as_array().map(|a| a.iter().filter_map(|d| d.as_str().map(str::to_owned)).collect()).unwrap_or_default(),
        data_disks: s["additionalDisks"]
            .as_array()
            .map(|a| {
                a.iter()
                    .map(|d| vms::DataDisk {
                        size_gb: d["sizeGB"].as_u64().or_else(|| d["sizeGB"].as_str().and_then(|v| v.parse().ok())).unwrap_or(100) as u32,
                        storage: String::new(),
                        letter: d["letter"].as_str().unwrap_or("").to_owned(),
                        file_system: d["fileSystem"].as_str().unwrap_or("NTFS").to_owned(),
                        label: d["label"].as_str().unwrap_or("").to_owned(),
                    })
                    .collect()
            })
            .unwrap_or_default(),
        start_after: s["startAfterCreate"].as_bool().unwrap_or(true),
        onboot: matches!(s["automaticStartAction"].as_str(), Some("Start") | Some("StartIfRunning")),
        extra_nics: s["nics"]
            .as_array()
            .map(|a| {
                a.iter()
                    .map(|n| vms::ExtraNic {
                        name: n["name"].as_str().unwrap_or("").to_owned(),
                        bridge: n["switchName"].as_str().filter(|b| !b.is_empty()).unwrap_or(default_bridge).to_owned(),
                        vlan: n["vlanId"].as_u64().map(|v| v as u16),
                        ip: n["ipAddress"].as_str().unwrap_or("").trim().to_owned(),
                        prefix: n["prefixLength"].as_u64().unwrap_or(24) as u8,
                    })
                    .collect()
            })
            .unwrap_or_default(),
        nested: s["nestedVirtualization"].as_bool().unwrap_or(false),
        startup_delay: s["automaticStartDelay"].as_u64().unwrap_or(0) as u32,
        vtpm: s["enableVtpm"].as_bool().unwrap_or(false),
        domain_join: domain_join_for(s, state),
        arc: arc_for(s, state),
        product_key: license_for(s, state),
        nic_name: str_of("nicName"),
        windows_features: s["windowsFeatures"].as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_owned)).collect()).unwrap_or_default(),
        include_management_tools: s["includeManagementTools"].as_bool().unwrap_or(true),
        rsat: s["rsatCapabilities"].as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_owned)).collect()).unwrap_or_default(),
        app_compat: s["appCompatFod"].as_bool().unwrap_or(false),
        client_features: s["clientFeatures"].as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_owned)).collect()).unwrap_or_default(),
        // The design: removeBuiltInApps on, removeApps the picked subset or null for all of them.
        remove_apps: if s["removeBuiltInApps"].as_bool().unwrap_or(false) {
            match s["removeApps"].as_array() {
                Some(a) => a.iter().filter_map(|x| x.as_str().map(str::to_owned)).collect(),
                None => windows::APP_REMOVAL.iter().map(|a| a.to_string()).collect(),
            }
        } else {
            vec![]
        },
        fod: None,
        pool: str_of("pvePool"),
        // The card keeps them as typed ("prod, sql"); an imported design may carry a list.
        tags: match &s["pveTags"] {
            serde_json::Value::Array(a) => a.iter().filter_map(|x| x.as_str().map(str::to_owned)).collect(),
            serde_json::Value::String(t) => t.split([',', ';', ' ']).map(str::trim).filter(|t| !t.is_empty()).map(str::to_owned).collect(),
            _ => vec![],
        },
        lab: Some(lab_name.to_owned()),
    }
}

/// The FoD ISO a VM's capabilities come from: its release's (Windows 11, Server 2025 or
/// Server 2022, by the gold), when one is set and the studio can read it.
async fn fod_plan(app: &AppState, gold: &golds::GoldRow) -> Option<fod::FodPlan> {
    let s: fod::FodSettings = settings::load(&app.db, "fod").await.ok()?;
    let m: serde_json::Value = serde_json::from_str(&gold.manifest).unwrap_or_default();
    let client = m["installationType"].as_str() == Some("Client") || m["requiresTpm"].as_bool() == Some(true);
    let volid = s.for_gold(client, m["build"].as_str().unwrap_or("")).to_owned();
    if volid.is_empty() {
        return None;
    }
    let media = fod::inspect(&iso_path(app, &volid)?, &app.config.data_dir.join("fod-cache.json")).await.ok()?;
    Some(fod::FodPlan { volid, root: media.root, marker: media.marker })
}

async fn deploy_lab(State(app): State<AppState>, user: User, Path(id): Path<String>, Json(req): Json<DeployRequest>) -> ApiResult<impl IntoResponse> {
    user.require(&app, "/vms", "VM.Allocate").await?;
    let lab = labs::get(&app.db, &id).await?.ok_or_else(|| ApiError::not_found("no such lab"))?;
    let state: serde_json::Value = serde_json::from_str(&lab.state).unwrap_or_default();
    let servers = state["servers"].as_array().cloned().unwrap_or_default();
    let golds = golds::list(&app.db).await?;
    let bake: BakeSettings = settings::load(&app.db, "bake").await?;
    let default_bridge = bake.resolve(&app.pve).await.map(|p| p.bridge).unwrap_or_else(|_| "vmbr0".into());
    let existing = vms::list(&app.db).await?;
    let guests = app.pve.resources().await.map_err(ApiError::from)?.into_iter().filter(|r| r.kind == "qemu" || r.kind == "lxc").collect::<Vec<_>>();

    // Everything is checked before anything is built, as Build-Vms' preflight did.
    let mut plan = Vec::new();
    let mut problems = Vec::new();
    for s in &servers {
        let name = s["name"].as_str().unwrap_or("").trim().to_lowercase();
        if name.is_empty() || (!req.names.is_empty() && !req.names.contains(&name)) {
            continue;
        }
        // A VM is the card's own when the card built it; any other VM of that name blocks the build.
        let card = s["_id"].as_str().unwrap_or("");
        if let Some(v) = existing.iter().find(|v| v.name == name && v.status != "failed") {
            if vm_card(v) == card {
                continue;
            }
            problems.push(format!("{name}: name already in use - the studio built a VM called {name}{} from another card", v.vmid.map(|id| format!(" (VM {id} on {})", v.node)).unwrap_or_default()));
            continue;
        }
        if let Some(g) = guests.iter().find(|g| g.name.as_deref().map(str::to_lowercase).as_deref() == Some(name.as_str())) {
            problems.push(format!("{name}: name already in use - {} {} on {} in Proxmox VE is called {name}", if g.kind == "lxc" { "CT" } else { "VM" }, g.vmid.unwrap_or_default(), g.node.as_deref().unwrap_or("?")));
            continue;
        }
        let image = s["imageId"].as_str().unwrap_or("");
        let lang = s["goldLanguage"].as_str().unwrap_or("");
        let pin = s["goldId"].as_str().unwrap_or("");
        let Some(gold) = golds::resolve(&golds, image, lang, pin) else {
            let what = if !pin.is_empty() { format!("pinned gold {pin}") } else if lang.is_empty() { image.to_owned() } else { format!("{image} ({lang})") };
            problems.push(format!("{name}: no ready gold for {what} - bake one under Golds"));
            continue;
        };
        let mut spec = spec_from_design(s, &state, &lab.name, &gold.id, &default_bridge);
        if gold.os == "windows" && (!spec.rsat.is_empty() || spec.app_compat) {
            spec.fod = fod_plan(&app, gold).await;
        }
        // vTPM comes from the gold's sidecar too: Windows 11 does not install without one.
        let m: serde_json::Value = serde_json::from_str(&gold.manifest).unwrap_or_default();
        if m["requiresTpm"].as_bool().unwrap_or(false) {
            spec.vtpm = true;
        }
        if let Err(e) = spec.validate() {
            problems.push(format!("{name}: {e:#}"));
            continue;
        }
        plan.push(spec);
    }
    if !problems.is_empty() {
        return Err(ApiError::bad_request(problems.join("; ")));
    }
    if plan.is_empty() {
        return Err(ApiError::bad_request("nothing to build - every VM of this lab exists already"));
    }

    let mut jobs = Vec::new();
    for spec in plan {
        // A VM that failed before is built again under a fresh row.
        sqlx::query("UPDATE vms SET status = 'removed' WHERE name = ? AND status = 'failed'").bind(&spec.name).execute(&app.db).await?;
        let vm_id = uuid::Uuid::new_v4().to_string();
        let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        sqlx::query("INSERT INTO vms (id, name, lab_id, gold_id, status, spec, created_at) VALUES (?, ?, ?, ?, 'building', ?, ?)")
            .bind(&vm_id)
            .bind(&spec.name)
            .bind(&lab.id)
            .bind(&spec.gold)
            .bind(serde_json::to_string(&spec).unwrap_or_default())
            .bind(&now)
            .execute(&app.db)
            .await?;
        let (pve, db, work) = (app.pve.clone(), app.db.clone(), app.config.data_dir.join("work"));
        let (vid, sp) = (vm_id.clone(), spec.clone());
        let job = app
            .jobs
            .spawn("deploy", &format!("Build {}", spec.name), &user.session.user, json!({ "vm": vm_id, "lab": lab.id }), move |log| {
                vms::deploy(pve, db, work, log, vid, sp)
            })
            .await?;
        sqlx::query("UPDATE vms SET job_id = ? WHERE id = ?").bind(&job).bind(&vm_id).execute(&app.db).await?;
        jobs.push(json!({ "job": job, "vm": vm_id, "name": spec.name }));
    }
    Ok((StatusCode::ACCEPTED, Json(json!({ "jobs": jobs }))))
}
