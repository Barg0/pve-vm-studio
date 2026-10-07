//! Windows auto-update: golds with Keep current follow the product their ISO was built
//! from. A newer Patch Tuesday build gives one new ISO with the same editions and language,
//! every follower is baked again from it with its own options, and the old ISO and the
//! golds beyond the kept number go.
//!
//! A run never leaves the branch it started on: the same product, the same base build,
//! Patch Tuesday ("B") releases only unless previews are allowed, nothing from Insider.
//! Work starts only inside a maintenance window (or when someone presses Start now); the
//! check for new builds runs any time - it is cheap.

use std::collections::{HashMap, HashSet};

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::SqlitePool;

use crate::{
    AppState, api, golds,
    golds::GoldRow,
    jobs::JobLog,
    maintenance::MaintenanceSettings,
    mail::{self, Report, Tone, fact, mono},
    media::MediaIso,
    notify, settings, uup,
    windows::WinBakeOptions,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AutoUpdateSettings {
    /// Golds kept per kind (image, language, disk size) after a run - the newest first.
    pub keep_golds: u32,
    /// Also the optional non-security releases later in the month.
    pub include_previews: bool,
    /// WinPE - what every bake, deploy and media build boots - rebuilt from the newest build
    /// of the product it is built from in a maintenance window, before anything else of
    /// the chain runs.
    pub keep_winpe_current: bool,
    /// virtio-win on "stable" (or "latest"): a newer release of that channel is downloaded
    /// into PVE in a maintenance window - and WinPE built again, for its vioscsi driver.
    pub keep_virtio_current: bool,
}

impl Default for AutoUpdateSettings {
    fn default() -> Self {
        Self { keep_golds: 2, include_previews: false, keep_winpe_current: true, keep_virtio_current: true }
    }
}

/// The virtio-win release the setting stands for now ("stable" and "latest" followed),
/// asked at most every six hours; None while the project's server does not answer.
pub async fn virtio_now(app: &AppState) -> Option<String> {
    type Now = Option<(std::time::Instant, String, Option<String>)>;
    static CACHE: std::sync::Mutex<Now> = std::sync::Mutex::new(None);
    let win: crate::virtio::WindowsSettings = settings::load(&app.db, "windows").await.unwrap_or_default();
    if let Some((at, wanted, v)) = CACHE.lock().unwrap().clone()
        && wanted == win.virtio
        && at.elapsed() < std::time::Duration::from_secs(6 * 3600)
    {
        return v;
    }
    let v = crate::virtio::resolve(&win.virtio).await.ok();
    *CACHE.lock().unwrap() = Some((std::time::Instant::now(), win.virtio.clone(), v.clone()));
    v
}

// ---- WinPE ----

/// The newest build WinPE is built from: (build, uuid, release) - Windows Server vNext's
/// newest, or Windows Server 2025's newest Patch Tuesday ("B") build, as picked. Asked of
/// UUP dump at most every six hours; None while the catalog does not answer.
pub async fn winpe_newest(app: &AppState) -> Option<(String, String, String)> {
    type Newest = Option<(std::time::Instant, String, Option<(String, String, String)>)>;
    static CACHE: std::sync::Mutex<Newest> = std::sync::Mutex::new(None);
    let win: crate::virtio::WindowsSettings = settings::load(&app.db, "windows").await.unwrap_or_default();
    if let Some((at, from, v)) = CACHE.lock().unwrap().clone()
        && from == win.winpe_from
        && at.elapsed() < std::time::Duration::from_secs(6 * 3600)
    {
        return v;
    }
    let p = uup::product(&win.winpe_from)?;
    let found = match uup::product_builds(&app.web, p, false).await {
        Ok(list) => list
            .into_iter()
            .filter(|b| p.insider || uup::is_release(&uup::release_kind(p, &b.build, b.created)))
            .max_by_key(|b| version(&b.build))
            .map(|b| (b.build.clone(), b.uuid.clone(), uup::release_kind(p, &b.build, b.created))),
        Err(e) => {
            tracing::warn!("WinPE: asking UUP dump for the newest build: {e:#}");
            return None;
        }
    };
    *CACHE.lock().unwrap() = Some((std::time::Instant::now(), win.winpe_from.clone(), found.clone()));
    found
}

/// Where the studio's WinPE stands: "missing", "outdated" (not built from the newest set of
/// the product picked - `newest` is that set's (build, uuid)), "virtio" (its vioscsi is not the virtio-win
/// release in use), "current" - or "unknown" without an answer from the catalog.
pub fn winpe_state(pe: &crate::winpe::WinPe, newest: Option<(&str, &str)>, virtio: Option<&str>) -> &'static str {
    if pe.volid.is_empty() {
        return "missing";
    }
    // From a UUP set: the set decides ("uup:<uuid> ..."); from an ISO: its build.
    let from_set = |uuid: &str| pe.source_iso.starts_with("uup:") && pe.source_iso.contains(uuid);
    if newest.is_some_and(|(b, uuid)| if pe.source_iso.starts_with("uup:") { !from_set(uuid) } else { version(b) > version(&pe.build) }) {
        return "outdated";
    }
    if virtio.is_some_and(|v| v != pe.vioscsi || v != pe.netkvm) {
        return "virtio";
    }
    if newest.is_none() { "unknown" } else { "current" }
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Run {
    pub id: String,
    pub source_iso: String,
    pub product: String,
    pub from_build: String,
    pub to_build: String,
    pub to_uuid: String,
    pub release: String,
    pub step: String,
    pub new_iso: Option<String>,
    pub golds: String,
    pub job_id: Option<String>,
    pub error: Option<String>,
    pub failed_step: Option<String>,
    pub force: i64,
    pub created_at: String,
    pub updated_at: String,
}

/// One follower in a run: the gold it replaces, the gold it bakes, the bake's job.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Follower {
    pub from: String,
    pub to: Option<String>,
    pub job: Option<String>,
}

impl Run {
    fn followers(&self) -> Vec<Follower> {
        serde_json::from_str(&self.golds).unwrap_or_default()
    }
    fn active(&self) -> bool {
        !["done", "failed", "stopped"].contains(&self.step.as_str())
    }
}

fn now() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// 26100.4061 -> [26100, 4061], to compare builds.
fn version(b: &str) -> Vec<u64> {
    b.split('.').map(|p| p.parse().unwrap_or(0)).collect()
}

fn base(b: &str) -> &str {
    b.split('.').next().unwrap_or(b)
}

fn options(g: &GoldRow) -> Option<WinBakeOptions> {
    serde_json::from_str(&g.options).ok()
}

/// What makes two golds the same kind - one replaces the other: image, language, disk.
fn kind(g: &GoldRow) -> (String, String, u32) {
    (g.image_id.clone(), golds::language(g).to_lowercase(), options(g).map(|o| o.disk_gb()).unwrap_or(0))
}

fn newer_gold(a: &GoldRow, b: &GoldRow) -> bool {
    (golds::build_version(a), &a.created_at) > (golds::build_version(b), &b.created_at)
}

pub async fn list_runs(db: &SqlitePool) -> Result<Vec<Run>> {
    Ok(sqlx::query_as("SELECT * FROM update_runs ORDER BY created_at DESC LIMIT 50").fetch_all(db).await?)
}

async fn get_run(db: &SqlitePool, id: &str) -> Result<Option<Run>> {
    Ok(sqlx::query_as("SELECT * FROM update_runs WHERE id = ?").bind(id).fetch_optional(db).await?)
}

async fn save_run(db: &SqlitePool, r: &Run) -> Result<()> {
    sqlx::query(
        "UPDATE update_runs SET step = ?, new_iso = ?, golds = ?, job_id = ?, error = ?, failed_step = ?, force = ?, updated_at = ? WHERE id = ?",
    )
    .bind(&r.step)
    .bind(&r.new_iso)
    .bind(&r.golds)
    .bind(&r.job_id)
    .bind(&r.error)
    .bind(&r.failed_step)
    .bind(r.force)
    .bind(now())
    .bind(&r.id)
    .execute(db)
    .await?;
    Ok(())
}

// ---- who follows what ----

/// Whether a gold can follow its ISO's product, and why not.
pub fn eligibility(g: &GoldRow, isos: &[MediaIso]) -> Result<(&'static uup::Product, MediaIso), String> {
    if g.os != "windows" {
        return Err("Only Windows golds follow a product".into());
    }
    let opt = options(g).ok_or("The gold's bake options are unreadable")?;
    let iso = isos
        .iter()
        .find(|i| i.volid == opt.iso)
        .ok_or("Baked from an ISO the studio did not build, or one that is gone - only ISOs built under Media know their product")?;
    let p = uup::product(&iso.product).ok_or("The ISO's product is not in the studio's list any more")?;
    if p.insider {
        return Err("Insider builds are never updated automatically".into());
    }
    Ok((p, iso.clone()))
}

/// The golds that follow, grouped by their ISO: the newest gold of each kind with Keep
/// current on, whose ISO the studio built and still has.
pub async fn tracks(app: &AppState) -> Result<Vec<(MediaIso, Vec<GoldRow>)>> {
    let isos = api::live_media_isos(app).await;
    let all: Vec<GoldRow> = golds::list(&app.db).await?.into_iter().filter(|g| g.status == "ready" && g.os == "windows").collect();
    let mut newest: HashMap<(String, String, u32), GoldRow> = HashMap::new();
    for g in &all {
        let k = kind(g);
        if newest.get(&k).is_none_or(|n| newer_gold(g, n)) {
            newest.insert(k, g.clone());
        }
    }
    let mut out: Vec<(MediaIso, Vec<GoldRow>)> = Vec::new();
    for g in newest.into_values().filter(|g| options(g).is_some_and(|o| o.keep_current)) {
        let Ok((_, iso)) = eligibility(&g, &isos) else { continue };
        match out.iter_mut().find(|(i, _)| i.volid == iso.volid) {
            Some((_, list)) => list.push(g),
            None => out.push((iso, vec![g])),
        }
    }
    Ok(out)
}

// ---- the check ----

/// The build an ISO may move to: newer, on the same base build, and a Patch Tuesday ("B")
/// release unless previews are allowed - the branch locks, in one place.
pub fn newest_fit<'a>(p: &uup::Product, builds: &'a [uup::Build], from: &str, previews: bool) -> Option<&'a uup::Build> {
    builds
        .iter()
        .filter(|b| version(&b.build) > version(from) && base(&b.build) == base(from))
        .filter(|b| previews || uup::is_release(&uup::release_kind(p, &b.build, b.created)))
        .max_by_key(|b| version(&b.build))
}

/// Built ISOs no gold follows, each with the newer build it could be rebuilt from - for the
/// "newer build" notification. ISOs that golds follow are the auto-update's to report.
pub async fn newer_for_untracked(app: &AppState) -> Result<Vec<(MediaIso, &'static uup::Product, uup::Build)>> {
    let s: AutoUpdateSettings = settings::load(&app.db, "auto_update").await.unwrap_or_default();
    let tracked: Vec<String> = tracks(app).await?.into_iter().map(|(i, _)| i.volid).collect();
    let mut out = Vec::new();
    for iso in api::live_media_isos(app).await.into_iter().filter(|i| !tracked.contains(&i.volid)) {
        let Some(p) = uup::product(&iso.product) else { continue };
        if p.insider {
            continue;
        }
        let builds = uup::product_builds(&app.web, p, true).await.with_context(|| format!("asking UUP dump for {}", p.name))?;
        if let Some(b) = newest_fit(p, &builds, &iso.build, s.include_previews) {
            let b = b.clone();
            out.push((iso, p, b));
        }
    }
    Ok(out)
}

/// Asks UUP dump for each tracked product's builds and records a run for a newer one that
/// passes the branch locks. Returns how many runs it recorded.
pub async fn check(app: &AppState) -> Result<usize> {
    let s: AutoUpdateSettings = settings::load(&app.db, "auto_update").await.unwrap_or_default();
    let runs = list_runs(&app.db).await?;
    let mut made = 0;
    for (iso, followers) in tracks(app).await? {
        if runs.iter().any(|r| r.source_iso == iso.volid && r.active()) {
            continue;
        }
        let p = uup::product(&iso.product).ok_or_else(|| anyhow!("unknown product {}", iso.product))?;
        let builds = uup::product_builds(&app.web, p, true).await.with_context(|| format!("asking UUP dump for {}", p.name))?;
        let newer: Vec<&uup::Build> = builds.iter().filter(|b| version(&b.build) > version(&iso.build)).collect();
        let (b, step) = match newest_fit(p, &builds, &iso.build, s.include_previews) {
            Some(b) => (b, "pending"),
            // Only a new base build is newer: that is another release, never followed.
            None => match newer.iter().filter(|b| base(&b.build) != base(&iso.build)).max_by_key(|b| version(&b.build)) {
                Some(b) => (*b, "stopped"),
                None => continue,
            },
        };
        if runs.iter().any(|r| r.source_iso == iso.volid && r.to_build == b.build) {
            continue;
        }
        let fl: Vec<Follower> = followers.iter().map(|g| Follower { from: g.id.clone(), ..Default::default() }).collect();
        let run = Run {
            id: uuid::Uuid::new_v4().simple().to_string()[..12].to_owned(),
            source_iso: iso.volid.clone(),
            product: p.id.to_owned(),
            from_build: iso.build.clone(),
            to_build: b.build.clone(),
            to_uuid: b.uuid.clone(),
            release: uup::release_kind(p, &b.build, b.created),
            step: step.into(),
            new_iso: None,
            golds: serde_json::to_string(&fl)?,
            job_id: None,
            error: (step == "stopped").then(|| format!("{} is a new base build - auto-update stays on {}", b.build, base(&iso.build))),
            failed_step: None,
            force: 0,
            created_at: now(),
            updated_at: now(),
        };
        sqlx::query(
            "INSERT INTO update_runs (id, source_iso, product, from_build, to_build, to_uuid, release, step, golds, error, created_at, updated_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&run.id)
        .bind(&run.source_iso)
        .bind(&run.product)
        .bind(&run.from_build)
        .bind(&run.to_build)
        .bind(&run.to_uuid)
        .bind(&run.release)
        .bind(&run.step)
        .bind(&run.golds)
        .bind(&run.error)
        .bind(&run.created_at)
        .bind(&run.updated_at)
        .execute(&app.db)
        .await?;
        tracing::info!("auto-update: {} {} -> {} ({step})", p.name, iso.build, b.build);
        made += 1;
        if step == "stopped" {
            mail_stopped(app, &run, p, &iso).await;
        } else {
            mail_found(app, &run, p, &iso, &followers).await;
        }
    }
    Ok(made)
}

// ---- the steps ----

/// What a job of the chain carries in its params, so the chain finds its own jobs and the
/// per-job mails leave them to the chain's.
fn tag(run: &Run) -> serde_json::Value {
    json!({ "auto_update": run.id })
}

/// A run's job ended: take its outcome.
async fn settle(app: &AppState, run: &mut Run) -> Result<()> {
    let Some(job) = run.job_id.clone() else { return Ok(()) };
    if app.jobs.is_running(&job).await {
        return Ok(());
    }
    let row = app.jobs.get(&job).await?;
    let ok = row.as_ref().is_some_and(|r| r.status == "succeeded");
    let err = row.as_ref().and_then(|r| r.error.clone()).unwrap_or_else(|| "the job is gone".into());
    run.job_id = None;
    match run.step.as_str() {
        "iso" if ok => {
            let src = api::live_media_isos(app).await;
            let old = src.iter().find(|i| i.volid == run.source_iso).cloned();
            let new = src.iter().find(|i| i.uuid == run.to_uuid && old.as_ref().is_none_or(|o| o.lang.eq_ignore_ascii_case(&i.lang)));
            match new {
                Some(n) => {
                    run.new_iso = Some(n.volid.clone());
                    run.step = "bake".into();
                }
                None => fail(app, run, "the media build ended, but its ISO is not in the catalog".into()).await?,
            }
        }
        "bake" if ok => {
            let mut fl = run.followers();
            if let Some(f) = fl.iter_mut().find(|f| f.job.as_deref() == Some(&job)) {
                f.job = None;
                let ready = match f.to.as_deref() {
                    Some(t) => golds::get(&app.db, t).await?.is_some_and(|g| g.status == "ready"),
                    None => false,
                };
                if !ready {
                    run.golds = serde_json::to_string(&fl)?;
                    return fail(app, run, "the bake ended, but its gold is not ready".into()).await;
                }
            }
            run.golds = serde_json::to_string(&fl)?;
            if fl.iter().all(|f| f.to.is_some()) {
                run.step = "cleanup".into();
            }
        }
        "cleanup" => {
            run.step = "done".into();
            if !ok {
                run.error = Some(format!("cleanup: {err}"));
            }
            save_run(&app.db, run).await?;
            mail_done(app, run).await;
            return Ok(());
        }
        _ if !ok => fail(app, run, err).await?,
        _ => {}
    }
    save_run(&app.db, run).await
}

async fn fail(app: &AppState, run: &mut Run, error: String) -> Result<()> {
    run.failed_step = Some(run.step.clone());
    run.step = "failed".into();
    run.error = Some(error);
    run.force = 0;
    save_run(&app.db, run).await?;
    mail_failed(app, run).await;
    Ok(())
}

/// Starts a run's next step. The caller has made sure nothing else runs.
async fn start_step(app: &AppState, run: &mut Run) -> Result<()> {
    let result = async {
        match run.step.as_str() {
            "pending" => {
                let iso = api::live_media_isos(app)
                    .await
                    .into_iter()
                    .find(|i| i.volid == run.source_iso)
                    .ok_or_else(|| anyhow!("{} is gone - nothing to build its successor from", run.source_iso))?;
                let q = api::MediaBuild { product: run.product.clone(), uuid: run.to_uuid.clone(), build: run.to_build.clone(), lang: iso.lang.clone(), editions: iso.editions.clone() };
                let job = api::spawn_media_build(app, "auto-update", q, tag(run)).await.map_err(|e| anyhow!("{e}"))?;
                run.job_id = Some(job);
                run.step = "iso".into();
            }
            "bake" => {
                let mut fl = run.followers();
                let Some(f) = fl.iter_mut().find(|f| f.to.is_none()) else {
                    run.step = "cleanup".into();
                    return Ok(());
                };
                let old = golds::get(&app.db, &f.from).await?.ok_or_else(|| anyhow!("gold {} is gone", f.from))?;
                let mut opt = options(&old).ok_or_else(|| anyhow!("gold {} has no readable bake options", old.id))?;
                let new_iso = run.new_iso.clone().ok_or_else(|| anyhow!("no new ISO recorded"))?;
                // The image again by what it is, not by its index - a new ISO may order its
                // editions differently.
                let cache = app.config.data_dir.join("wim-cache.json");
                let read = |volid: &str| api::iso_path(app, volid).ok_or_else(|| anyhow!("{volid} is not an ISO volume"));
                let was = crate::wim::inspect(&read(&opt.iso)?, &cache).await.with_context(|| format!("reading {}", opt.iso))?;
                let was = was.into_iter().find(|i| i.index == opt.index).ok_or_else(|| anyhow!("{} has no image {}", opt.iso, opt.index))?;
                let now_imgs = crate::wim::inspect(&read(&new_iso)?, &cache).await.with_context(|| format!("reading {new_iso}"))?;
                let img = now_imgs
                    .iter()
                    .find(|i| i.edition_id.eq_ignore_ascii_case(&was.edition_id) && i.installation_type == was.installation_type)
                    .ok_or_else(|| anyhow!("{new_iso} has no {} ({}) image", was.edition_id, was.installation_type))?;
                opt.iso = new_iso;
                opt.index = img.index;
                opt.keep_current = true;
                let (job, gold) = api::spawn_windows_bake(app, "auto-update", opt, tag(run)).await.map_err(|e| anyhow!("{e}"))?;
                f.to = Some(gold);
                f.job = Some(job.clone());
                run.golds = serde_json::to_string(&fl)?;
                run.job_id = Some(job);
            }
            "cleanup" => {
                let job = spawn_cleanup(app, run).await?;
                run.job_id = Some(job);
            }
            s => bail!("nothing to start in step {s}"),
        }
        anyhow::Ok(())
    }
    .await;
    match result {
        Ok(()) => save_run(&app.db, run).await,
        Err(e) => fail(app, run, format!("{e:#}")).await,
    }
}

/// The last step, as one job: the old ISO goes, then the golds beyond the kept number.
async fn spawn_cleanup(app: &AppState, run: &Run) -> Result<String> {
    let s: AutoUpdateSettings = settings::load(&app.db, "auto_update").await.unwrap_or_default();
    let (a, r) = (app.clone(), run.clone());
    let title = format!("Clean up after the update to {}", run.to_build);
    app.jobs
        .spawn("auto-update", &title, "auto-update", json!({ "auto_update": run.id, "step": "cleanup" }), move |log| async move {
            cleanup(&a, &log, &r, s.keep_golds.max(1)).await
        })
        .await
}

async fn cleanup(app: &AppState, log: &JobLog, run: &Run, keep: u32) -> Result<()> {
    // The old ISO: every follower is baked from the new one now.
    let res = app.pve.resources().await?;
    let storage = run.source_iso.split(':').next().unwrap_or_default();
    let mut gone = false;
    for s in res.iter().filter(|r| r.kind == "storage" && r.storage.as_deref() == Some(storage)) {
        let Some(node) = s.node.as_deref() else { continue };
        if app.pve.storage_content(node, storage, "iso").await.is_ok_and(|v| v.iter().any(|v| v.volid == run.source_iso)) {
            app.pve.delete_volume(node, &run.source_iso).await.with_context(|| format!("deleting {}", run.source_iso))?;
            log.ok(format!("Deleted {} on {node}", run.source_iso)).await;
            gone = true;
            break;
        }
    }
    if !gone {
        log.line(format!("{} is not in PVE any more", run.source_iso)).await;
    }

    // Golds beyond the kept number, per kind of each new gold. A gold with linked clones
    // stays (PVE keeps it anyway), and so does one a design pins by id.
    let all = golds::list(&app.db).await?;
    let usage = golds::usage(&app.db, &app.pve).await.unwrap_or_default();
    let pinned = pinned_golds(&app.db).await;
    let mut kinds = HashSet::new();
    for f in run.followers() {
        if let Some(g) = f.to.as_deref().and_then(|t| all.iter().find(|g| g.id == t)) {
            kinds.insert(kind(g));
        }
    }
    for k in kinds {
        let mut same: Vec<&GoldRow> = all.iter().filter(|g| g.status == "ready" && kind(g) == k).collect();
        same.sort_by(|a, b| if newer_gold(a, b) { std::cmp::Ordering::Less } else { std::cmp::Ordering::Greater });
        for g in same.into_iter().skip(keep as usize) {
            if usage.get(&g.id).copied().unwrap_or(0) > 0 {
                log.line(format!("Keeping {}: linked clones use it", g.id)).await;
                continue;
            }
            if pinned.contains(&g.id) {
                log.line(format!("Keeping {}: a design pins it", g.id)).await;
                continue;
            }
            log.run(format!("Removing gold {} ({})", g.id, g.image_id)).await;
            golds::remove(&app.pve, &app.db, g, log).await?;
            crate::cis::remove(&app.config.data_dir, &g.id).await;
        }
    }
    Ok(())
}

/// Golds a design names by id (goldId) rather than "newest".
async fn pinned_golds(db: &SqlitePool) -> HashSet<String> {
    let mut out = HashSet::new();
    for l in crate::labs::list(db).await.unwrap_or_default() {
        let Ok(Some(full)) = crate::labs::get(db, &l.id).await else { continue };
        let state: serde_json::Value = serde_json::from_str(&full.state).unwrap_or_default();
        for s in state["servers"].as_array().into_iter().flatten() {
            if let Some(id) = s["goldId"].as_str().filter(|s| !s.is_empty()) {
                out.insert(id.to_owned());
            }
        }
    }
    out
}

// ---- the scheduler ----

/// One loop for everything the studio does on its own: every minute it takes the outcome
/// of a chain's finished job; every six hours it asks UUP dump; inside a maintenance window
/// (and with nothing running) it first installs a newer studio, then starts the next step.
pub async fn scheduler(app: AppState) {
    tokio::time::sleep(std::time::Duration::from_secs(90)).await;
    let mut checked: Option<std::time::Instant> = None;
    let mut self_checked: Option<std::time::Instant> = None;
    let six_hours = std::time::Duration::from_secs(6 * 3600);
    loop {
        if let Err(e) = tick(&app, &mut checked, &mut self_checked, six_hours).await {
            tracing::warn!("scheduler: {e:#}");
        }
        tokio::time::sleep(std::time::Duration::from_secs(60)).await;
    }
}

async fn tick(app: &AppState, checked: &mut Option<std::time::Instant>, self_checked: &mut Option<std::time::Instant>, every: std::time::Duration) -> Result<()> {
    let mut runs = list_runs(&app.db).await?;
    for r in runs.iter_mut().filter(|r| r.active() && r.job_id.is_some()) {
        settle(app, r).await?;
    }
    if checked.is_none_or(|c| c.elapsed() >= every) {
        *checked = Some(std::time::Instant::now());
        if let Err(e) = check(app).await {
            tracing::warn!("auto-update check: {e:#}");
        }
    }
    if !app.jobs.running_ids().await.is_empty() {
        return Ok(());
    }
    let windows: MaintenanceSettings = settings::load(&app.db, "maintenance").await.unwrap_or_default();
    let open = windows.open_now();
    // The studio's own update first: a minute and a restart, and the chain goes on after it.
    if open && self_checked.is_none_or(|c| c.elapsed() >= every) {
        *self_checked = Some(std::time::Instant::now());
        let s: crate::update::UpdateSettings = settings::load(&app.db, "update").await.unwrap_or_default();
        if s.auto {
            let v = crate::update::status(&app.web, true, s.development()).await;
            let tag = if s.development() { Some(crate::update::DEVELOPMENT) } else { v["releases"][0]["tag"].as_str() };
            if v["state"] == "update"
                && let Some(tag) = tag
            {
                match api::start_update(app, tag, "automatic update").await {
                    Ok(id) => {
                        tracing::info!("automatic update to {tag} started (job {id})");
                        return Ok(());
                    }
                    Err(e) => tracing::warn!("automatic update to {tag} could not start: {e:#}"),
                }
            }
        }
    }
    let au: AutoUpdateSettings = settings::load(&app.db, "auto_update").await.unwrap_or_default();
    // virtio-win next: the release its channel points at, into PVE - WinPE and the bakes take it.
    let win: crate::virtio::WindowsSettings = settings::load(&app.db, "windows").await.unwrap_or_default();
    let vio = if matches!(win.virtio.as_str(), "stable" | "latest") { virtio_now(app).await } else { None };
    if open
        && au.keep_virtio_current
        && let Some(rel) = vio.as_deref()
        && !virtio_present(app, &win, rel).await
        && !tried(&app.db, "virtio", "automatic virtio-win update", "release", rel).await
    {
        match api::spawn_virtio(app, "automatic virtio-win update").await {
            Ok(id) => {
                tracing::info!("automatic virtio-win update to {rel} started (job {id})");
                return Ok(());
            }
            Err(e) => tracing::warn!("automatic virtio-win update to {rel} could not start: {e:#}"),
        }
    }
    // WinPE next: every media build and bake of the chain boots it, so it is current first -
    // its build and its vioscsi driver.
    if open && au.keep_winpe_current {
        let pe: crate::winpe::WinPe = settings::load(&app.db, "winpe").await.unwrap_or_default();
        let vio_for_pe = if au.keep_virtio_current { vio.as_deref() } else { None };
        if let Some((build, uuid, release)) = winpe_newest(app).await
            && matches!(winpe_state(&pe, Some((&build, &uuid)), vio_for_pe), "missing" | "outdated" | "virtio")
            && !tried(&app.db, "winpe", "automatic WinPE update", "build", &build).await
        {
            match api::spawn_winpe_uup(app, "automatic WinPE update", &uuid, "en-us", &build).await {
                Ok(id) => {
                    tracing::info!("automatic WinPE update to {build} ({release}) started (job {id})");
                    return Ok(());
                }
                Err(e) => tracing::warn!("automatic WinPE update to {build} could not start: {e:#}"),
            }
        }
    }
    let mut runs = list_runs(&app.db).await?;
    // The oldest waiting run first; one step at a time across all of them.
    runs.reverse();
    if let Some(r) = runs.iter_mut().find(|r| r.active() && r.job_id.is_none() && (open || r.force != 0)) {
        start_step(app, r).await?;
    }
    Ok(())
}

/// Whether an automatic job of `kind` for `value` (its params' `key`) failed in the last
/// 20 hours - one try a day, not one every few minutes of the window.
async fn tried(db: &SqlitePool, kind: &str, by: &str, key: &str, value: &str) -> bool {
    let since = (chrono::Utc::now() - chrono::Duration::hours(20)).to_rfc3339();
    let rows: Vec<(String,)> = sqlx::query_as("SELECT params FROM jobs WHERE kind = ? AND status = 'failed' AND created_by = ? AND created_at > ?")
        .bind(kind)
        .bind(by)
        .bind(since)
        .fetch_all(db)
        .await
        .unwrap_or_default();
    rows.iter().any(|(p,)| serde_json::from_str::<serde_json::Value>(p).is_ok_and(|v| v[key] == value))
}

/// Whether PVE holds virtio-win `release` on the bake node's ISO storage.
async fn virtio_present(app: &AppState, win: &crate::virtio::WindowsSettings, release: &str) -> bool {
    let bake: crate::settings::BakeSettings = settings::load(&app.db, "bake").await.unwrap_or_default();
    let Ok(p) = bake.resolve(&app.pve).await else { return true };
    let storage = if win.iso_storage.is_empty() { p.iso_storage.clone() } else { win.iso_storage.clone() };
    let name = crate::virtio::iso_name(release);
    app.pve.storage_content(&p.node, &storage, "iso").await.map(|v| v.iter().any(|x| x.volid.ends_with(&format!("/{name}")))).unwrap_or(true)
}

// ---- what the page asks ----

/// Start now: the run goes on as soon as nothing else runs, window or not - every step
/// of it, to the end.
pub async fn start_now(db: &SqlitePool, id: &str) -> Result<()> {
    let mut r = get_run(db, id).await?.ok_or_else(|| anyhow!("no such run"))?;
    if !r.active() {
        bail!("this run is {}", r.step);
    }
    r.force = 1;
    save_run(db, &r).await
}

/// Retry: a failed run goes back to the step it failed in, and starts as soon as nothing runs.
pub async fn retry(db: &SqlitePool, id: &str) -> Result<()> {
    let mut r = get_run(db, id).await?.ok_or_else(|| anyhow!("no such run"))?;
    if r.step != "failed" {
        bail!("only a failed run can be retried");
    }
    r.step = r.failed_step.clone().unwrap_or_else(|| "pending".into());
    if r.step == "bake" {
        // The follower whose bake failed bakes again.
        let mut fl = r.followers();
        let ready: HashSet<String> = golds::list(db).await?.into_iter().filter(|g| g.status == "ready").map(|g| g.id).collect();
        for f in fl.iter_mut() {
            if f.to.as_ref().is_some_and(|t| !ready.contains(t)) {
                f.to = None;
                f.job = None;
            }
        }
        r.golds = serde_json::to_string(&fl)?;
    }
    if r.step == "iso" {
        r.step = "pending".into();
    }
    r.error = None;
    r.failed_step = None;
    r.force = 1;
    save_run(db, &r).await
}

/// Drops a finished run from the list (a failed one is then found again by the next check).
pub async fn dismiss(db: &SqlitePool, id: &str) -> Result<()> {
    let r = get_run(db, id).await?.ok_or_else(|| anyhow!("no such run"))?;
    if r.active() {
        bail!("this run is still going");
    }
    sqlx::query("DELETE FROM update_runs WHERE id = ?").bind(id).execute(db).await?;
    Ok(())
}

// ---- mails ----

async fn next_window(app: &AppState) -> String {
    let w: MaintenanceSettings = settings::load(&app.db, "maintenance").await.unwrap_or_default();
    match w.next_open(chrono::Local::now().naive_local()) {
        Some(t) => t.format("%a %Y-%m-%d %H:%M").to_string(),
        None => "no maintenance window is set".into(),
    }
}

/// A gold as one line of a mail's list: its image, its id, its state.
fn gold_row(g: &GoldRow, state: Option<(Tone, &str)>) -> mail::Row {
    let m: serde_json::Value = serde_json::from_str(&g.manifest).unwrap_or_default();
    let name = m["displayName"].as_str().map(str::to_owned).unwrap_or_else(|| g.image_id.clone());
    mail::Row {
        icon: "gold-image",
        name,
        detail: m["id"].as_str().unwrap_or(&g.name).to_owned(),
        right: m["build"].as_str().unwrap_or("").trim_start_matches("10.0.").to_owned(),
        state: state.map(|(t, s)| (t, s.to_owned())),
    }
}

async fn mail_found(app: &AppState, run: &Run, p: &uup::Product, iso: &MediaIso, followers: &[GoldRow]) {
    let mut r = Report::new(
        format!("{} {} available - golds update in the next window", p.name, run.to_build),
        "update",
        format!("{} {} is available", p.name, run.to_build),
        "FOUND",
        Tone::Accent,
    );
    r.subtitle = format!("{} · builds in the next maintenance window", run.release);
    r.compare = Some(mail::Compare { was: run.from_build.clone(), was_sub: "in the golds now".into(), now: run.to_build.clone(), now_sub: run.release.clone() });
    let mut rows = Vec::new();
    for g in followers {
        rows.push(gold_row(g, None));
    }
    r.sections.push(mail::Section { title: "Golds that follow".into(), icon: "gold-image", rows, ..Default::default() });
    r.sections.push(notify::section("Details", "first-boot", vec![
        mono("ISO", iso.volid.clone()).icon("iso-media"),
        fact("Editions", iso.editions.join(", ")).icon("first-boot"),
        fact("Next window", next_window(app).await).icon("clock"),
    ]));
    r.buttons = vec![mail::button("Windows updates", "#/media", "update", true)];
    r.link = Some("#/media".into());
    notify::send(app, "update_found", r).await;
}

async fn mail_stopped(app: &AppState, run: &Run, p: &uup::Product, iso: &MediaIso) {
    let mut r = Report::new(format!("{}: new base build {}, auto-update stays put", p.name, run.to_build), "update", "New base build", "STOPPED", Tone::Warn);
    r.subtitle = format!("{} moved past base build {}", p.name, base(&iso.build));
    r.facts = vec![mono("ISO", iso.volid.clone()), fact("Current", run.from_build.clone()), fact("Newest", run.to_build.clone())];
    r.notice = Some((Tone::Warn, "Keep current never crosses to another base build. Build media of the new release under Media and bake from it when you want it.".into()));
    r.link = Some("#/media".into());
    notify::send(app, "update_stopped", r).await;
}

async fn mail_failed(app: &AppState, run: &Run) {
    let p = uup::product(&run.product).map(|p| p.name).unwrap_or("Windows");
    let step = match run.failed_step.as_deref() {
        Some("pending") | Some("iso") => "building the new ISO",
        Some("bake") => "baking a gold",
        Some("cleanup") => "cleaning up",
        _ => "a step",
    };
    let mut r = Report::new(format!("{p} update to {} failed", run.to_build), "update", format!("Update to {} failed", run.to_build), "FAILED", Tone::Danger);
    r.subtitle = format!("Stopped while {step}");
    r.compare = Some(mail::Compare { was: run.from_build.clone(), was_sub: "stays current".into(), now: run.to_build.clone(), now_sub: "not reached".into() });
    r.facts = vec![mono("Source ISO", run.source_iso.clone()).icon("iso-media")];
    if let Some(n) = &run.new_iso {
        r.facts.push(mono("New ISO", n.clone()).icon("iso-media"));
    }
    r.error = Some(run.error.clone().unwrap_or_default());
    r.buttons = vec![mail::button("Windows updates", "#/media", "update", true), mail::button("Jobs", "#/jobs", "log", false)];
    r.notice = Some((Tone::Accent, "The old ISO and golds stay current. Retry the run under Image settings → Windows updates, or wait for the next build.".into()));
    r.link = Some("#/media".into());
    notify::send(app, "update_failed", r).await;
}

async fn mail_done(app: &AppState, run: &Run) {
    let p = uup::product(&run.product).map(|p| p.name).unwrap_or("Windows");
    let mut r = Report::new(format!("{p} golds updated to {}", run.to_build), "update", format!("Updated to {}", run.to_build), "DONE", Tone::Success);
    r.subtitle = format!("{} · {}", p, run.release);
    r.compare = Some(mail::Compare { was: run.from_build.clone(), was_sub: String::new(), now: run.to_build.clone(), now_sub: run.release.clone() });
    let mut rows = Vec::new();
    for f in run.followers() {
        let new = match &f.to {
            Some(t) => golds::get(&app.db, t).await.ok().flatten(),
            None => None,
        };
        match new {
            Some(g) => rows.push(gold_row(&g, Some((Tone::Success, "Ready")))),
            None => rows.push(mail::Row { icon: "gold-image", name: f.from.clone(), state: Some((Tone::Danger, "Not baked".into())), ..Default::default() }),
        }
    }
    r.sections.push(mail::Section { title: "Golds".into(), icon: "gold-image", rows, note: "VMs pick the new golds at their next deploy.".into(), ..Default::default() });
    r.sections.push(notify::section("Details", "first-boot", vec![
        mono("New ISO", run.new_iso.clone().unwrap_or_default()).icon("iso-media"),
        fact("Next window", next_window(app).await).icon("clock"),
    ]));
    if let Some(e) = &run.error {
        r.notice = Some((Tone::Warn, e.clone()));
    }
    r.buttons = vec![mail::button("Open Golds", "#/golds", "gold-image", true)];
    r.link = Some("#/golds".into());
    notify::send(app, "update_done", r).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn winpe_states() {
        let pe = |volid: &str, build: &str, vio: &str, src: &str| crate::winpe::WinPe { volid: volid.into(), build: build.into(), vioscsi: vio.into(), netkvm: vio.into(), source_iso: src.into(), ..Default::default() };
        let newest = ("29667.1000", "73639666");
        let set = "uup:73639666 MetadataESD_ServerStandardCore_en-us.esd en-us";
        assert_eq!(winpe_state(&pe("", "", "", ""), Some(newest), None), "missing");
        assert_eq!(winpe_state(&pe("v", "29667.1000", "0.1.302-1", set), Some(newest), Some("0.1.302-1")), "current");
        assert_eq!(winpe_state(&pe("v", "29659.1000", "0.1.302-1", "uup:7d583949 x en-us"), Some(newest), Some("0.1.302-1")), "outdated");
        // A Server 2025 WinPE from before: another set - outdated.
        assert_eq!(winpe_state(&pe("v", "26100.1", "0.1.302-1", "uup:649e1310 x en-us"), Some(newest), None), "outdated");
        assert_eq!(winpe_state(&pe("v", "26100.1", "0.1.302-1", "local:iso/x.iso"), Some(newest), None), "outdated");
        assert_eq!(winpe_state(&pe("v", "29667.1000", "0.1.285-1", set), Some(newest), Some("0.1.302-1")), "virtio");
        assert_eq!(winpe_state(&pe("v", "29667.1000", "0.1.302-1", set), None, None), "unknown");
    }
}
