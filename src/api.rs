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

use crate::{
    auth::{session_cookie, User, COOKIE},
    catalog,
    error::{ApiError, ApiResult},
    golds,
    jobs::Event,
    labs,
    linux::BakeOptions,
    pve::{Bridge, Resource, Vnet},
    settings::{self, BakeSettings},
    tls::{self, AcmeSettings, ServerSettings, TlsSettings},
    virtio,
    vms::{self, VmSpec},
    wim, windows, winpe,
    AppState,
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/realms", get(realms))
        .route("/session", get(session).post(login).delete(logout))
        .route("/inventory", get(inventory))
        .route("/jobs", get(list_jobs))
        .route("/jobs/cluster-check", post(start_cluster_check))
        .route("/jobs/{id}", get(get_job))
        .route("/jobs/{id}/events", get(job_events))
        .route("/catalog", get(catalog_info))
        .route("/settings/bake", get(get_bake_settings).put(put_bake_settings))
        .route("/golds", get(list_golds).post(start_bake))
        .route("/golds/{id}", axum::routing::delete(remove_gold))
        .route("/vms", get(list_vms).post(start_deploy))
        .route("/vms/{id}", axum::routing::delete(remove_vm))
        .route("/vms/{id}/{action}", post(vm_power))
        .route("/settings/server", get(get_server).put(put_server))
        .route("/tls", get(get_tls))
        .route("/tls/acme", post(start_acme))
        .route("/tls/providers/{code}", get(provider_help))
        .route("/tls/import", post(import_cert))
        .route("/tls/self-signed", post(new_self_signed))
        .route("/settings/windows", get(get_windows).put(put_windows))
        .route("/virtio/fetch", post(fetch_virtio))
        .route("/windows/isos", get(windows_isos))
        .route("/windows/images", get(windows_images))
        .route("/golds/windows", post(start_windows_bake))
        .route("/winpe", get(get_winpe))
        .route("/winpe/build", post(build_winpe))
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

async fn list_jobs(State(app): State<AppState>, _user: User) -> ApiResult<impl IntoResponse> {
    Ok(Json(app.jobs.list(200).await?))
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

/// The images that can be baked, the gold features, and the region data for the menus.
async fn catalog_info(_user: User) -> ApiResult<impl IntoResponse> {
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
    Ok(Json(json!({
        "linux": catalog::LINUX,
        "features": catalog::FEATURES,
        "region": parse(catalog::LINUX_REGION)["defaults"],
        "locales": names,
        "timezones": zones,
    })))
}

async fn get_bake_settings(State(app): State<AppState>, _user: User) -> ApiResult<impl IntoResponse> {
    let s: BakeSettings = settings::load(&app.db, "bake").await?;
    // What "auto" currently resolves to, so the page can show it.
    let resolved = s.resolve(&app.pve).await.map_err(|e| format!("{e:#}"));
    Ok(Json(json!({
        "settings": s,
        "resolved": resolved.as_ref().ok(),
        "problem": resolved.err(),
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

async fn list_golds(State(app): State<AppState>, _user: User) -> ApiResult<impl IntoResponse> {
    Ok(Json(golds::list(&app.db).await?))
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
    let bake: BakeSettings = settings::load(&app.db, "bake").await?;

    let gold_id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    sqlx::query(
        "INSERT INTO golds (id, image_id, os, name, node, storage, status, options, created_at) \
         VALUES (?, ?, 'linux', ?, '', '', 'baking', ?, ?)",
    )
    .bind(&gold_id)
    .bind(img.id)
    .bind(format!("gold-{}", img.id))
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
            &format!("Bake {}", img.name),
            &user.session.user,
            json!({ "image": img.id, "gold": gold_id, "options": req.options }),
            move |log| golds::bake_linux(ctx, log, gid, img, opts, bake),
        )
        .await?;
    sqlx::query("UPDATE golds SET job_id = ? WHERE id = ?").bind(&job).bind(&gold_id).execute(&app.db).await?;
    Ok((StatusCode::ACCEPTED, Json(json!({ "id": job, "gold": gold_id }))))
}

async fn remove_gold(State(app): State<AppState>, user: User, Path(id): Path<String>) -> ApiResult<impl IntoResponse> {
    user.require(&app, "/vms", "VM.Allocate").await?;
    let gold = golds::get(&app.db, &id).await?.ok_or_else(|| ApiError::not_found("no such gold"))?;
    if gold.status == "baking" {
        return Err(ApiError::bad_request("this gold is still baking"));
    }
    let (pve, db) = (app.pve.clone(), app.db.clone());
    let title = format!("Remove {}", gold.name);
    let job = app
        .jobs
        .spawn("remove-gold", &title, &user.session.user, json!({ "gold": id }), move |log| async move {
            golds::remove(&pve, &db, &gold, &log).await
        })
        .await?;
    Ok((StatusCode::ACCEPTED, Json(json!({ "id": job }))))
}

// ---- VMs ----

/// The studio's VMs, with what PVE says about each right now.
async fn list_vms(State(app): State<AppState>, _user: User) -> ApiResult<impl IntoResponse> {
    let rows = vms::list(&app.db).await?;
    let res = app.pve.resources().await.unwrap_or_default();
    let out: Vec<serde_json::Value> = rows
        .into_iter()
        .map(|v| {
            let live = v
                .vmid
                .and_then(|id| res.iter().find(|r| r.kind == "qemu" && r.vmid == Some(id as u32)));
            let spec: serde_json::Value = serde_json::from_str(&v.spec).unwrap_or_default();
            json!({
                "id": v.id, "name": v.name, "lab": v.lab_id, "gold": v.gold_id, "node": v.node,
                "vmid": v.vmid, "status": v.status, "ip": v.ip, "job_id": v.job_id,
                "created_at": v.created_at, "spec": spec,
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
        .spawn("deploy", &format!("Build {}", spec.name), &user.session.user, json!({ "vm": id, "name": spec.name }), move |log| {
            vms::deploy(pve, db, work, log, vid, sp)
        })
        .await?;
    sqlx::query("UPDATE vms SET job_id = ? WHERE id = ?").bind(&job).bind(&id).execute(&app.db).await?;
    Ok((StatusCode::ACCEPTED, Json(json!({ "id": job, "vm": id }))))
}

async fn remove_vm(State(app): State<AppState>, user: User, Path(id): Path<String>) -> ApiResult<impl IntoResponse> {
    let vm = vms::get(&app.db, &id).await?.ok_or_else(|| ApiError::not_found("no such VM"))?;
    if let Some(vmid) = vm.vmid {
        user.require(&app, &format!("/vms/{vmid}"), "VM.Allocate").await?;
    }
    if vm.status == "building" {
        return Err(ApiError::bad_request("this VM is still being built"));
    }
    let (pve, db) = (app.pve.clone(), app.db.clone());
    let title = format!("Remove {}", vm.name);
    let job = app
        .jobs
        .spawn("remove-vm", &title, &user.session.user, json!({ "vm": id }), move |log| async move {
            vms::remove(&pve, &db, &vm, &log).await
        })
        .await?;
    Ok((StatusCode::ACCEPTED, Json(json!({ "id": job }))))
}

/// start | shutdown | stop | reboot - straight through to PVE, as the user may.
async fn vm_power(
    State(app): State<AppState>,
    user: User,
    Path((id, action)): Path<(String, String)>,
) -> ApiResult<impl IntoResponse> {
    if !matches!(action.as_str(), "start" | "shutdown" | "stop" | "reboot") {
        return Err(ApiError::not_found("no such action"));
    }
    let vm = vms::get(&app.db, &id).await?.ok_or_else(|| ApiError::not_found("no such VM"))?;
    let vmid = vm.vmid.ok_or_else(|| ApiError::bad_request("this VM has no PVE id yet"))? as u32;
    user.require(&app, &format!("/vms/{vmid}"), "VM.PowerMgmt").await?;
    let upid: String = app
        .pve
        .post(&format!("/nodes/{}/qemu/{vmid}/status/{action}", crate::pve::enc(&vm.node)), vec![])
        .await?;
    Ok(Json(json!({ "upid": upid })))
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
    settings::save(&app.db, "server", &ServerSettings { fqdn: f }).await?;
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
    let acme = req.acme;
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
        .spawn("certificate", "Let's Encrypt certificate", &user.session.user, json!({ "fqdn": server.fqdn }), move |log| async move {
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
    let pe: winpe::WinPe = settings::load(&app.db, "winpe").await?;
    Ok(Json(json!({ "settings": s, "releases": releases, "stable": stable, "latest": latest, "present": present, "winpe": pe })))
}

async fn put_windows(State(app): State<AppState>, user: User, Json(s): Json<virtio::WindowsSettings>) -> ApiResult<impl IntoResponse> {
    user.require(&app, "/vms", "VM.Allocate").await?;
    virtio::resolve(&s.virtio).await.map_err(|e| ApiError::bad_request(format!("{e:#}")))?;
    settings::save(&app.db, "windows", &s).await?;
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
            // The studio's own seeds and the driver ISOs are not Windows media.
            if file.starts_with("pvs-seed-") || file.starts_with("virtio-win") {
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
                "installation_type": i.installation_type, "language": i.language, "build": i.build,
                "size_gb": (i.total_bytes as f64 / (1u64 << 30) as f64 * 10.0).round() / 10.0,
                "image_id": windows::image_id(i), "key": windows::gvlk(&i.edition_id, &i.build).is_some(),
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
    let gold_id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let image_id = windows::image_id(&img);
    sqlx::query(
        "INSERT INTO golds (id, image_id, os, name, node, storage, status, options, created_at) \
         VALUES (?, ?, 'windows', ?, '', '', 'baking', ?, ?)",
    )
    .bind(&gold_id)
    .bind(&image_id)
    .bind(format!("gold-{image_id}"))
    .bind(serde_json::to_string(&opt).unwrap_or_default())
    .bind(&now)
    .execute(&app.db)
    .await?;

    let (pve, db, work) = (app.pve.clone(), app.db.clone(), app.config.data_dir.join("work"));
    let gid = gold_id.clone();
    let title = format!("Bake {}", img.name);
    let job = app
        .jobs
        .spawn("bake", &title, &user.session.user, json!({ "gold": gold_id, "iso": opt.iso, "index": opt.index }), move |log| async move {
            let result = async {
                let p = bake.resolve(&pve).await?;
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
    let volid = q.volid.clone();
    let job = app
        .jobs
        .spawn("winpe", "Build WinPE", &user.session.user, json!({ "iso": q.volid }), move |log| async move {
            let p = bake.resolve(&pve).await?;
            let storage = if win.iso_storage.is_empty() { p.iso_storage.clone() } else { win.iso_storage.clone() };
            winpe::build(&pve, &db, &log, &work, &volid, &path, &p.node, &storage).await.map(|_| ())
        })
        .await?;
    Ok((StatusCode::ACCEPTED, Json(json!({ "id": job }))))
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

fn spec_from_design(s: &serde_json::Value, state: &serde_json::Value, lab_name: &str, gold_id: &str, default_bridge: &str) -> VmSpec {
    let defaults = &state["defaults"];
    let str_of = |k: &str| s[k].as_str().unwrap_or("").trim().to_owned();
    let builtin_admin = s["builtInAdminOnly"].as_bool().unwrap_or(false);
    let user = if builtin_admin { "Administrator".to_owned() } else { str_of("localUserName") };
    let bridge = str_of("switchName");
    VmSpec {
        name: str_of("name").to_lowercase(),
        gold: gold_id.to_owned(),
        cores: s["cpuCount"].as_u64().unwrap_or(2).max(1) as u32,
        memory_mb: (s["memoryGB"].as_f64().unwrap_or(4.0) * 1024.0) as u32,
        disk_gb: s["osDiskGB"].as_u64().or_else(|| s["osDiskGB"].as_str().and_then(|v| v.parse().ok())).map(|v| v as u32),
        linked: s["useDifferencingDisk"].as_bool().unwrap_or(true),
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
        nic_name: str_of("nicName"),
        windows_features: s["windowsFeatures"].as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_owned)).collect()).unwrap_or_default(),
        include_management_tools: s["includeManagementTools"].as_bool().unwrap_or(true),
        rsat: s["rsatCapabilities"].as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_owned)).collect()).unwrap_or_default(),
        app_compat: s["appCompatFod"].as_bool().unwrap_or(false),
        lab: Some(lab_name.to_owned()),
    }
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

    // Everything is checked before anything is built, as Build-Vms' preflight did.
    let mut plan = Vec::new();
    let mut problems = Vec::new();
    for s in &servers {
        let name = s["name"].as_str().unwrap_or("").trim().to_lowercase();
        if name.is_empty() || (!req.names.is_empty() && !req.names.contains(&name)) {
            continue;
        }
        if existing.iter().any(|v| v.name == name && v.status != "failed") {
            continue;
        }
        let image = s["imageId"].as_str().unwrap_or("");
        let Some(gold) = golds.iter().filter(|g| g.status == "ready" && g.image_id == image).max_by(|a, b| a.created_at.cmp(&b.created_at)) else {
            problems.push(format!("{name}: no ready gold for {image} - bake one under Golds"));
            continue;
        };
        let spec = spec_from_design(s, &state, &lab.name, &gold.id, &default_bridge);
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
