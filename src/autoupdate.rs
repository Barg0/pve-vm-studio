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
    /// An ISO build may start until the window ends and finish after it. Off: one starts
    /// only when its last build's time still fits in the window.
    pub iso_after_window: bool,
    /// The bakes for an ISO built in the window still start after it ends, until all are
    /// done. Off: no bake starts after the window; the rest waits for the next one.
    pub bakes_after_window: bool,
}

impl Default for AutoUpdateSettings {
    fn default() -> Self {
        Self { keep_golds: 2, include_previews: false, keep_winpe_current: true, keep_virtio_current: true, iso_after_window: true, bakes_after_window: true }
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
    /// Why its bake did not give a ready gold - it is not queued again until Retry.
    pub failed: Option<String>,
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
/// Golds of one kind replace each other: image, release (a 25H2 gold is its own branch
/// beside 26H2), language and disk size.
fn kind(g: &GoldRow) -> (String, &'static str, String, u32) {
    (g.image_id.clone(), golds::release(g).unwrap_or(""), golds::language(g).to_lowercase(), options(g).map(|o| o.disk_gb()).unwrap_or(0))
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
    let mut newest: HashMap<(String, &'static str, String, u32), GoldRow> = HashMap::new();
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

/// A run's jobs ended: take their outcome. The ISO and the cleanup are one job each
/// (run.job_id); the bakes run side by side, one job per follower.
async fn settle(app: &AppState, run: &mut Run) -> Result<()> {
    if run.step == "bake" {
        // Before 2026-10-11 a bake was also the run's job; the follower carries it now.
        run.job_id = None;
        return settle_bakes(app, run).await;
    }
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
        "cleanup" => {
            run.step = "done".into();
            if !ok {
                run.error = Some(format!("cleanup: {err}"));
            }
            save_run(&app.db, run).await?;
            if run.force != 0 {
                mail_done(app, run).await;
            }
            return Ok(());
        }
        _ if !ok => fail(app, run, err).await?,
        _ => {}
    }
    save_run(&app.db, run).await
}

/// The bakes of a run: each follower's job that ended is taken in - its gold, found by the
/// job (a window's bake makes its gold when it starts). When none runs or waits and every
/// follower has its gold, the run cleans up; a bake that failed fails the run once the
/// others are through - Retry bakes only that one again.
async fn settle_bakes(app: &AppState, run: &mut Run) -> Result<()> {
    let mut fl = run.followers();
    for f in fl.iter_mut() {
        let Some(j) = f.job.clone() else { continue };
        if app.jobs.is_running(&j).await {
            continue;
        }
        f.job = None;
        let gold: Option<golds::GoldRow> = match f.to.as_deref() {
            Some(t) => golds::get(&app.db, t).await?,
            None => match sqlx::query_as::<_, (String,)>("SELECT id FROM golds WHERE job_id = ?").bind(&j).fetch_optional(&app.db).await? {
                Some((id,)) => golds::get(&app.db, &id).await?,
                None => None,
            },
        };
        f.to = gold.as_ref().map(|g| g.id.clone());
        if !gold.is_some_and(|g| g.status == "ready") {
            let row = app.jobs.get(&j).await?;
            f.failed = Some(row.and_then(|r| r.error).unwrap_or_else(|| "the bake ended without a ready gold".into()));
        }
    }
    run.golds = serde_json::to_string(&fl)?;
    if fl.iter().any(|f| f.job.is_some() || (f.to.is_none() && f.failed.is_none())) {
        return save_run(&app.db, run).await;
    }
    let failed: Vec<String> = fl.iter().filter(|f| f.failed.is_some()).map(|f| format!("{} ({})", f.from, f.failed.clone().unwrap_or_default())).collect();
    if failed.is_empty() {
        run.step = "cleanup".into();
        save_run(&app.db, run).await
    } else {
        run.step = "bake".into();
        fail(app, run, format!("bake for {} did not end with a ready gold", failed.join("; "))).await
    }
}

async fn fail(app: &AppState, run: &mut Run, error: String) -> Result<()> {
    run.failed_step = Some(run.step.clone());
    run.step = "failed".into();
    run.error = Some(error);
    let forced = run.force != 0;
    run.force = 0;
    save_run(&app.db, run).await?;
    // In a window the window's report tells it; Start now and Retry mail on their own.
    if forced {
        mail_failed(app, run).await;
    }
    Ok(())
}

/// Starts a run's ISO build or its cleanup.
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
                // Its bakes go into the queue with it, each waiting for this build to succeed.
                let mut fl = run.followers();
                for f in fl.iter_mut() {
                    *f = Follower { from: f.from.clone(), ..Default::default() };
                    match queue_bake(app, run, &f.from, Some(&job)).await {
                        Ok(b) => f.job = Some(b),
                        Err(e) => run.error = Some(format!("{e:#}")),
                    }
                }
                run.golds = serde_json::to_string(&fl)?;
                run.job_id = Some(job);
                run.step = "iso".into();
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

/// Every follower of a run that has no bake yet (and none that failed) gets one, all at
/// once - after a Retry, or when the window's end took them out of the queue. The queue
/// runs as many side by side as Jobs at a time allows.
async fn spawn_bakes(app: &AppState, run: &mut Run) -> Result<()> {
    let mut fl = run.followers();
    let mut problem = None;
    for f in fl.iter_mut().filter(|f| f.to.is_none() && f.job.is_none() && f.failed.is_none()) {
        match queue_bake(app, run, &f.from, None).await {
            Ok(job) => f.job = Some(job),
            Err(e) => {
                f.failed = Some(format!("{e:#}"));
                problem = Some(format!("{e:#}"));
            }
        }
    }
    run.golds = serde_json::to_string(&fl)?;
    if let Some(e) = problem {
        run.error = Some(e);
    }
    save_run(&app.db, run).await
}

/// Puts a follower's bake into the queue: behind `after` (the run's ISO build) when given.
/// It reads the new ISO only when it starts (window_bake_job) - it can never bake the old one.
async fn queue_bake(app: &AppState, run: &Run, from: &str, after: Option<&str>) -> Result<String> {
    let old = golds::get(&app.db, from).await?.ok_or_else(|| anyhow!("gold {from} is gone"))?;
    let title = format!("Bake {} {}", short_name(&old.image_id), run.to_build);
    let params = json!({ "auto_update": run.id, "from": from, "after": after, "image": old.image_id, "build": run.to_build });
    let (a, rid, f) = (app.clone(), run.id.clone(), from.to_owned());
    app.jobs.spawn("bake", &title, "auto-update", params, move |log| window_bake_job(a, log, rid, f)).await
}

/// The ISO a run built, from the studio's list - there as soon as the build ended.
async fn new_iso_of(app: &AppState, run: &Run) -> Option<String> {
    let src = api::live_media_isos(app).await;
    let old = src.iter().find(|i| i.volid == run.source_iso).cloned();
    src.iter().find(|i| i.uuid == run.to_uuid && old.as_ref().is_none_or(|o| o.lang.eq_ignore_ascii_case(&i.lang))).map(|i| i.volid.clone())
}

/// A window's bake: when it starts, the run's new ISO, the replaced gold's options on it
/// (the image again by what it is - a new ISO may order its editions differently), the new
/// gold's record, then the bake. Also what a queued one runs after a restart.
pub async fn window_bake_job(app: AppState, log: JobLog, run_id: String, from: String) -> Result<()> {
    let run = get_run(&app.db, &run_id).await?.ok_or_else(|| anyhow!("update run {run_id} is gone"))?;
    let new_iso = match run.new_iso.clone() {
        Some(v) => v,
        None => new_iso_of(&app, &run).await.ok_or_else(|| anyhow!("the new ISO for {} is not in the studio's list", run.to_build))?,
    };
    let old = golds::get(&app.db, &from).await?.ok_or_else(|| anyhow!("gold {from} is gone"))?;
    let mut opt = options(&old).ok_or_else(|| anyhow!("gold {} has no readable bake options", old.id))?;
    let cache = app.config.data_dir.join("wim-cache.json");
    let read = |volid: &str| api::iso_path(&app, volid).ok_or_else(|| anyhow!("{volid} is not an ISO volume"));
    let was = crate::wim::inspect(&read(&opt.iso)?, &cache).await.with_context(|| format!("reading {}", opt.iso))?;
    let was = was.into_iter().find(|i| i.index == opt.index).ok_or_else(|| anyhow!("{} has no image {}", opt.iso, opt.index))?;
    let now_imgs = crate::wim::inspect(&read(&new_iso)?, &cache).await.with_context(|| format!("reading {new_iso}"))?;
    let img = now_imgs
        .iter()
        .find(|i| i.edition_id.eq_ignore_ascii_case(&was.edition_id) && i.installation_type == was.installation_type)
        .ok_or_else(|| anyhow!("{new_iso} has no {} ({}) image", was.edition_id, was.installation_type))?;
    opt.iso = new_iso.clone();
    opt.index = img.index;
    opt.keep_current = true;
    let (gid, img, path) = api::prepare_windows_bake(&app, &mut opt).await.map_err(|e| anyhow!("{e}"))?;
    sqlx::query("UPDATE golds SET job_id = ? WHERE id = ?").bind(log.id()).bind(&gid).execute(&app.db).await?;
    log.line(format!("Gold {gid} from {new_iso} - it replaces {from} ({})", run.from_build)).await;
    api::windows_bake_job(app, log, gid, opt, img, path).await
}

/// Short names for narrow places: ws2025-datacenter-core -> WS2025 Core, w11-25h2 -> W11 25H2.
pub fn short_name(id: &str) -> String {
    id.split('-')
        .filter(|t| *t != "datacenter")
        .enumerate()
        .map(|(i, t)| match t {
            _ if i == 0 => t.to_uppercase(),
            "standard" => "Std".into(),
            _ if t.chars().any(|c| c.is_ascii_digit()) => t.to_uppercase(),
            _ => t[..1].to_uppercase() + &t[1..],
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// The last step, as one job: the old ISO goes, then the golds beyond the kept number.
async fn spawn_cleanup(app: &AppState, run: &Run) -> Result<String> {
    let (a, id) = (app.clone(), run.id.clone());
    let title = format!("Clean up after the update to {}", run.to_build);
    app.jobs
        .spawn("auto-update", &title, "auto-update", json!({ "auto_update": run.id, "step": "cleanup" }), move |log| cleanup_job(a, log, id))
        .await
}

/// A run's cleanup, the kept number read when it starts - also what a queued one runs
/// after a restart.
pub async fn cleanup_job(app: AppState, log: JobLog, run_id: String) -> Result<()> {
    let s: AutoUpdateSettings = settings::load(&app.db, "auto_update").await.unwrap_or_default();
    let run = get_run(&app.db, &run_id).await?.ok_or_else(|| anyhow!("update run {run_id} is gone"))?;
    cleanup(&app, &log, &run, s.keep_golds.max(1)).await
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

/// What one maintenance window has done so far - for its preflight and its report. Saved,
/// so the restart of the studio's own update does not start the window over.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
struct Pass {
    /// When the window closes (the studio's local time, %Y-%m-%dT%H:%M).
    end: String,
    /// When the studio first saw it open (UTC, RFC 3339) - its jobs are the ones since.
    since: String,
    /// Why the preflight failed; empty: it passed, the window works.
    failed: String,
    reported: bool,
}

#[derive(Default)]
struct State {
    checked: Option<std::time::Instant>,
    self_checked: Option<std::time::Instant>,
}

/// One loop for everything the studio does on its own: every minute it takes the outcome
/// of the runs' finished jobs; every six hours it asks UUP dump; in a maintenance window it
/// works in a fixed order - preflight, the studio's own update, virtio-win, WinPE, Features
/// on Demand, then the ISOs one after another with each ISO's bakes beside the next one.
pub async fn scheduler(app: AppState) {
    tokio::time::sleep(std::time::Duration::from_secs(90)).await;
    let mut st = State::default();
    loop {
        if let Err(e) = tick(&app, &mut st).await {
            tracing::warn!("scheduler: {e:#}");
        }
        tokio::time::sleep(std::time::Duration::from_secs(60)).await;
    }
}

/// A job of `kind` queued or running - an earlier stage the next one waits for.
async fn in_flight(db: &SqlitePool, kind: &str) -> bool {
    sqlx::query_as::<_, (i64,)>("SELECT COUNT(*) FROM jobs WHERE kind = ? AND status IN ('queued', 'running')")
        .bind(kind)
        .fetch_one(db)
        .await
        .is_ok_and(|(n,)| n > 0)
}

/// How long the last good job of `kind` took (whose params' `key` is `value`, when given).
async fn last_took(db: &SqlitePool, kind: &str, key: &str, value: &str) -> Option<i64> {
    let rows: Vec<(String, Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT params, started_at, ended_at FROM jobs WHERE kind = ? AND status = 'succeeded' AND started_at IS NOT NULL ORDER BY created_at DESC LIMIT 40",
    )
    .bind(kind)
    .fetch_all(db)
    .await
    .ok()?;
    rows.iter().find_map(|(p, s, e)| {
        let v: serde_json::Value = serde_json::from_str(p).unwrap_or_default();
        if !key.is_empty() && v[key].as_str() != Some(value) {
            return None;
        }
        let at = |t: &Option<String>| t.as_deref().and_then(|t| chrono::DateTime::parse_from_rfc3339(t).ok());
        Some((at(e)? - at(s)?).num_seconds())
    })
}

/// Before a window does anything: PVE answers, the bake node is there, the cluster has
/// quorum, and the work volume has room for an ISO build when one is due - a download
/// cache nobody keeps is cleared first when that makes the room.
async fn preflight(app: &AppState, iso_due: bool) -> Result<(), String> {
    app.pve.version().await.map_err(|e| format!("PVE does not answer: {e:#}"))?;
    let bake: crate::settings::BakeSettings = settings::load(&app.db, "bake").await.unwrap_or_default();
    bake.resolve(&app.pve).await.map_err(|e| format!("the bake node: {e:#}"))?;
    if let Ok(status) = app.pve.cluster_status().await
        && status.iter().any(|s| s.kind == "cluster" && s.quorate == Some(0))
    {
        return Err("the cluster has no quorum".into());
    }
    if iso_due {
        let work = app.config.data_dir.join("work");
        let room = |w: &std::path::Path| crate::media::volume(w).map(|(_, free)| free).unwrap_or(u64::MAX);
        if room(&work) < crate::media::BUILD_ROOM {
            let keep = settings::load::<crate::media::WorkerSettings>(&app.db, "worker").await.unwrap_or_default().keep_downloads;
            if !keep && app.jobs.idle().await {
                let cache = work.join("uup-files");
                let freed = crate::dir_size(&cache).await;
                if tokio::fs::remove_dir_all(&cache).await.is_ok() {
                    tracing::info!("maintenance window: cleared the download cache ({:.1} GB) for the ISO builds", freed as f64 / 1e9);
                }
            }
            let free = room(&work);
            if free < crate::media::BUILD_ROOM {
                return Err(format!(
                    "the work volume has {:.0} GB free, an ISO build needs about {:.0} GB",
                    free as f64 / 1e9,
                    crate::media::BUILD_ROOM as f64 / 1e9
                ));
            }
        }
    }
    Ok(())
}

async fn tick(app: &AppState, st: &mut State) -> Result<()> {
    let mut runs = list_runs(&app.db).await?;
    for r in runs.iter_mut().filter(|r| r.active()) {
        settle(app, r).await?;
    }
    let six_hours = std::time::Duration::from_secs(6 * 3600);
    if st.checked.is_none_or(|c| c.elapsed() >= six_hours) {
        st.checked = Some(std::time::Instant::now());
        if let Err(e) = check(app).await {
            tracing::warn!("auto-update check: {e:#}");
        }
    }
    let au: AutoUpdateSettings = settings::load(&app.db, "auto_update").await.unwrap_or_default();
    let windows: MaintenanceSettings = settings::load(&app.db, "maintenance").await.unwrap_or_default();
    let now = chrono::Local::now().naive_local();
    let end = windows.open_at(now);
    let mut runs = list_runs(&app.db).await?;
    runs.reverse(); // oldest first

    // A window that just opened: its preflight, once.
    let mut pass: Pass = settings::load(&app.db, "window_pass").await.unwrap_or_default();
    if let Some(end) = end {
        let key = end.format("%Y-%m-%dT%H:%M").to_string();
        if pass.end != key {
            let iso_due = runs.iter().any(|r| r.step == "pending");
            let failed = preflight(app, iso_due).await.err().unwrap_or_default();
            if !failed.is_empty() {
                tracing::warn!("maintenance window skipped: {failed}");
                mail_skipped(app, &failed, end).await;
            }
            pass = Pass { end: key, since: now_utc(), failed, reported: false };
            settings::save(&app.db, "window_pass", &pass).await?;
        }
    }
    let open = end.is_some() && pass.failed.is_empty();
    if end.is_none() {
        window_closed(app, &au, &mut runs).await?;
        if !pass.end.is_empty() && !pass.reported && pass.failed.is_empty() && !auto_in_flight(&app.db).await {
            pass.reported = true;
            settings::save(&app.db, "window_pass", &pass).await?;
            mail_window(app, &pass.since).await;
        }
    }

    // 1. The studio's own update: a minute and a restart, and the window goes on after it.
    if open && st.self_checked.is_none_or(|c| c.elapsed() >= six_hours) {
        st.self_checked = Some(std::time::Instant::now());
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
    if in_flight(&app.db, "update").await {
        return Ok(());
    }

    // 2. virtio-win: the release its channel points at, into PVE - WinPE and the bakes take it.
    let win: crate::virtio::WindowsSettings = settings::load(&app.db, "windows").await.unwrap_or_default();
    let vio = if matches!(win.virtio.as_str(), "stable" | "latest") { virtio_now(app).await } else { None };
    if open
        && au.keep_virtio_current
        && let Some(rel) = vio.as_deref()
        && !virtio_present(app, &win, rel).await
        && !in_flight(&app.db, "virtio").await
        && !tried(&app.db, "virtio", "automatic virtio-win update", "release", rel).await
    {
        match api::spawn_virtio(app, "automatic virtio-win update").await {
            Ok(id) => tracing::info!("automatic virtio-win update to {rel} started (job {id})"),
            Err(e) => tracing::warn!("automatic virtio-win update to {rel} could not start: {e:#}"),
        }
    }
    // WinPE carries virtio-win's storage driver: it waits for that download. A failed one
    // does not stop it - WinPE is then built with the driver PVE has.
    if in_flight(&app.db, "virtio").await {
        return Ok(());
    }

    // 3. WinPE: every media build and bake boots it, so it is current first.
    if open && au.keep_winpe_current {
        let pe: crate::winpe::WinPe = settings::load(&app.db, "winpe").await.unwrap_or_default();
        let vio_for_pe = if au.keep_virtio_current { vio.as_deref() } else { None };
        if let Some((build, uuid, release)) = winpe_newest(app).await
            && matches!(winpe_state(&pe, Some((&build, &uuid)), vio_for_pe), "missing" | "outdated" | "virtio")
            && !in_flight(&app.db, "winpe").await
            && !tried(&app.db, "winpe", "automatic WinPE update", "build", &build).await
        {
            match api::spawn_winpe_uup(app, "automatic WinPE update", &uuid, "en-us", &build).await {
                Ok(id) => tracing::info!("automatic WinPE update to {build} ({release}) started (job {id})"),
                Err(e) => tracing::warn!("automatic WinPE update to {build} could not start: {e:#}"),
            }
        }
    }
    if in_flight(&app.db, "winpe").await {
        return Ok(());
    }

    // 4. Features on Demand: a release the golds follow that has no FoD ISO gets one. A
    // download only - it runs beside the first ISO.
    if open {
        let fod: crate::fod::FodSettings = settings::load(&app.db, "fod").await.unwrap_or_default();
        // One FoD ISO per release, with the satellites of every language.
        for r in runs.iter().filter(|r| r.step == "pending") {
            let key = fod_key(&r.product);
            let have = match key {
                "server" => !fod.server.is_empty(),
                "server2022" => !fod.server2022.is_empty(),
                "client" => !fod.client.is_empty(),
                _ => true,
            };
            if !have && !in_flight(&app.db, "fod").await && !tried(&app.db, "fod", "automatic FoD build", "fod", key).await {
                match api::spawn_fod(app, "automatic FoD build", key).await {
                    Ok(id) => tracing::info!("automatic FoD build for {key} started (job {id})"),
                    Err(e) => tracing::warn!("automatic FoD build for {key} could not start: {e:#}"),
                }
            }
        }
    }

    // 5. The ISOs, one after another, the oldest run first. With "ISO builds may finish
    // after the window" off, one starts only when its last build's time still fits.
    if !runs.iter().any(|r| r.step == "iso") {
        let left = end.map(|e| (e - now).num_seconds()).unwrap_or(0);
        let mut next = None;
        for (i, r) in runs.iter().enumerate().filter(|(_, r)| r.step == "pending" && r.job_id.is_none()) {
            let fits = au.iso_after_window || left >= last_took(&app.db, "media", "media", &r.product).await.unwrap_or(2 * 3600);
            if r.force != 0 || (open && fits) {
                next = Some(i);
                break;
            }
        }
        if let Some(i) = next {
            start_step(app, &mut runs[i]).await?;
        }
    }

    // 6. The bakes: as soon as a run's ISO is there, all of its golds at once - the queue
    // runs them beside the next ISO. After the window only when that is allowed.
    for r in runs.iter_mut().filter(|r| r.step == "bake") {
        if r.force != 0 || open || au.bakes_after_window {
            spawn_bakes(app, r).await?;
        }
    }

    // 7. A run's cleanup, right after its last bake.
    for r in runs.iter_mut().filter(|r| r.step == "cleanup" && r.job_id.is_none()) {
        if r.force != 0 || open || au.bakes_after_window {
            start_step(app, r).await?;
        }
    }
    Ok(())
}

/// Any job of the window's own still queued or running.
async fn auto_in_flight(db: &SqlitePool) -> bool {
    sqlx::query_as::<_, (i64,)>("SELECT COUNT(*) FROM jobs WHERE status IN ('queued', 'running') AND (created_by = 'auto-update' OR created_by LIKE 'automatic %')")
        .fetch_one(db)
        .await
        .is_ok_and(|(n,)| n > 0)
}

/// The window has closed: what has not begun waits for the next one. A queued ISO build
/// leaves the queue (its run waits again); a queued bake too, unless gold bakes may finish
/// after the window. What runs, finishes. Runs started with Start now are not touched.
async fn window_closed(app: &AppState, au: &AutoUpdateSettings, runs: &mut [Run]) -> Result<()> {
    let queued = app.jobs.queued_ids().await;
    let waits = |j: &Option<String>| j.as_ref().is_some_and(|j| queued.contains(j));
    for r in runs.iter_mut().filter(|r| r.force == 0) {
        if r.step == "iso" && waits(&r.job_id) {
            if let Some(j) = r.job_id.take() {
                app.jobs.abort(&j, "the maintenance window's end").await;
            }
            // Its bakes leave with it (skipped); they are queued again with the next build.
            let fl: Vec<Follower> = r.followers().into_iter().map(|f| Follower { from: f.from, ..Default::default() }).collect();
            r.golds = serde_json::to_string(&fl)?;
            r.step = "pending".into();
            save_run(&app.db, r).await?;
            continue;
        }
        if matches!(r.step.as_str(), "iso" | "bake") && !au.bakes_after_window {
            let mut fl = r.followers();
            let mut changed = false;
            for f in fl.iter_mut().filter(|f| waits(&f.job)) {
                if let Some(j) = f.job.take() {
                    app.jobs.abort(&j, "the maintenance window's end").await;
                }
                if let Some(g) = f.to.take() {
                    sqlx::query("DELETE FROM golds WHERE id = ? AND status = 'baking'").bind(&g).execute(&app.db).await?;
                }
                changed = true;
            }
            if changed {
                r.golds = serde_json::to_string(&fl)?;
                save_run(&app.db, r).await?;
            }
        }
    }
    Ok(())
}

/// What the next window will do, each block's length from that job's last run (marked when
/// there is none to go by) - the preview under Windows updates. Times are seconds from the
/// window's start; ISO builds run one after another, each ISO's bakes as soon as it is
/// there, in the slots Jobs at a time leaves beside the ISO.
pub async fn plan(app: &AppState) -> serde_json::Value {
    let w: MaintenanceSettings = settings::load(&app.db, "maintenance").await.unwrap_or_default();
    let now = chrono::Local::now().naive_local();
    let Some(start) = w.next_open(now) else { return serde_json::Value::Null };
    let end = w.open_at(start).unwrap_or(start);
    let au: AutoUpdateSettings = settings::load(&app.db, "auto_update").await.unwrap_or_default();
    let queue: crate::jobs::QueueSettings = settings::load(&app.db, "queue").await.unwrap_or_default();
    let mut runs: Vec<Run> = list_runs(&app.db).await.unwrap_or_default().into_iter().filter(|r| matches!(r.step.as_str(), "pending" | "iso" | "bake" | "cleanup")).collect();
    runs.reverse();
    let block = |label: String, start: i64, secs: Option<i64>, fallback: i64, kind: &str| {
        json!({ "label": label, "start": start, "end": start + secs.unwrap_or(fallback), "known": secs.is_some(), "kind": kind })
    };
    let short = short_name;
    // Before the ISOs: virtio-win, then WinPE, when they are due.
    let mut t = 0i64;
    let mut pre = Vec::new();
    let win: crate::virtio::WindowsSettings = settings::load(&app.db, "windows").await.unwrap_or_default();
    let vio = if au.keep_virtio_current && matches!(win.virtio.as_str(), "stable" | "latest") { virtio_now(app).await } else { None };
    if !runs.is_empty() || vio.is_some() {
        if let Some(rel) = vio.as_deref()
            && !virtio_present(app, &win, rel).await
        {
            let b = block(format!("virtio-win {rel}"), t, last_took(&app.db, "virtio", "", "").await, 300, "virtio");
            t = b["end"].as_i64().unwrap_or(t);
            pre.push(b);
        }
        if au.keep_winpe_current {
            let pe: crate::winpe::WinPe = settings::load(&app.db, "winpe").await.unwrap_or_default();
            if let Some((build, uuid, _)) = winpe_newest(app).await
                && matches!(winpe_state(&pe, Some((&build, &uuid)), vio.as_deref()), "missing" | "outdated" | "virtio")
            {
                let b = block(format!("WinPE {build}"), t, last_took(&app.db, "winpe", "", "").await, 1800, "winpe");
                t = b["end"].as_i64().unwrap_or(t);
                pre.push(b);
            }
        }
    }
    let mut iso = Vec::new();
    let mut bakes: Vec<(i64, serde_json::Value, Option<i64>)> = Vec::new();
    let mut ti = t;
    for r in &runs {
        let name = uup::product(&r.product).map(|p| p.name).unwrap_or("Windows");
        let ready = if matches!(r.step.as_str(), "pending" | "iso") {
            let mut b = block(format!("{} · {}", short(&r.product), r.to_build), ti, last_took(&app.db, "media", "media", &r.product).await, 5400, "iso");
            b["title"] = json!(format!("{name} {}", r.to_build));
            ti = b["end"].as_i64().unwrap_or(ti);
            iso.push(b);
            ti
        } else {
            t
        };
        for f in r.followers().iter().filter(|f| f.to.is_none() || f.job.is_some()) {
            let Ok(Some(g)) = golds::get(&app.db, &f.from).await else { continue };
            let m: serde_json::Value = serde_json::from_str(&g.manifest).unwrap_or_default();
            let full = m["displayName"].as_str().map(str::to_owned).unwrap_or_else(|| g.image_id.clone());
            let took = match g.job_id.as_deref() {
                Some(j) => app.jobs.get(j).await.ok().flatten().and_then(|row| {
                    let at = |t: &Option<String>| t.as_deref().and_then(|t| chrono::DateTime::parse_from_rfc3339(t).ok());
                    Some((at(&row.ended_at)? - at(&row.started_at)?).num_seconds())
                }),
                None => None,
            };
            let kind = if g.image_id.starts_with("w1") { "client" } else { "server" };
            bakes.push((ready, json!({ "label": short(&g.image_id), "title": full, "kind": kind }), took));
        }
    }
    // The bakes into the slots beside the ISO lane, each at the earliest free one.
    let slots = if queue.limit == 0 { bakes.len().max(1) } else { (queue.limit as usize).saturating_sub(1).max(1) };
    let mut free = vec![t; slots];
    let mut lanes: Vec<Vec<serde_json::Value>> = vec![Vec::new(); slots];
    bakes.sort_by_key(|b| b.0);
    for (ready, v, took) in bakes {
        let i = (0..slots).min_by_key(|&i| free[i]).unwrap_or(0);
        let s = ready.max(free[i]);
        let mut b = block(v["label"].as_str().unwrap_or("").to_owned(), s, took, 2700, v["kind"].as_str().unwrap_or("server"));
        b["title"] = v["title"].clone();
        free[i] = b["end"].as_i64().unwrap_or(s);
        lanes[i].push(b);
    }
    lanes.retain(|l| !l.is_empty());
    json!({
        "start": start.format("%Y-%m-%dT%H:%M").to_string(),
        "end": end.format("%Y-%m-%dT%H:%M").to_string(),
        "length": (end - start).num_seconds(),
        "open": w.open_at(now).is_some(),
        "pre": pre, "iso": iso, "bakes": lanes,
        "limit": queue.limit,
    })
}

/// The FoD slot a product's golds use.
fn fod_key(product: &str) -> &'static str {
    if product.starts_with("ws2022") {
        "server2022"
    } else if product.starts_with("ws") {
        "server"
    } else {
        "client"
    }
}

fn now_utc() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
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
            if f.failed.is_some() || f.to.as_ref().is_some_and(|t| !ready.contains(t)) {
                f.to = None;
                f.job = None;
                f.failed = None;
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

/// A window that could not work: why, and when the next one opens.
async fn mail_skipped(app: &AppState, why: &str, end: chrono::NaiveDateTime) {
    let mut r = Report::new("Maintenance window skipped", "clock", "Window skipped", "SKIPPED", Tone::Warn);
    r.subtitle = format!("The window until {} did nothing: the check before it failed", end.format("%H:%M"));
    r.error = Some(why.to_owned());
    r.facts = vec![fact("Next window", next_window(app).await).icon("clock")];
    r.link = Some("#/studio".into());
    notify::send(app, "window_skipped", r).await;
}

/// One report for a window, once its work is through: every job it started and how it
/// ended, the golds it made, and what waits for the next window.
async fn mail_window(app: &AppState, since: &str) {
    let jobs: Vec<(String, String, String, Option<String>)> = sqlx::query_as(
        "SELECT kind, title, status, error FROM jobs WHERE created_at >= ? AND (created_by = 'auto-update' OR created_by LIKE 'automatic %') ORDER BY created_at",
    )
    .bind(since)
    .fetch_all(&app.db)
    .await
    .unwrap_or_default();
    if jobs.is_empty() {
        return;
    }
    let failed = jobs.iter().filter(|j| j.2 != "succeeded").count();
    let icon = |k: &str| match k {
        "media" => "iso-media",
        "bake" => "gold-image",
        "update" => "update",
        _ => "first-boot",
    };
    let rows = jobs
        .iter()
        .map(|(k, t, s, e)| mail::Row {
            icon: icon(k),
            name: t.clone(),
            detail: e.clone().unwrap_or_default(),
            state: Some(match s.as_str() {
                "succeeded" => (Tone::Success, "Done".into()),
                "skipped" => (Tone::Warn, "Skipped".into()),
                _ => (Tone::Danger, cap(s)),
            }),
            ..Default::default()
        })
        .collect();
    let (tone, status) = if failed == 0 { (Tone::Success, "DONE") } else { (Tone::Warn, "ISSUES") };
    let mut r = Report::new(
        if failed == 0 { format!("Maintenance window: {} job(s) done", jobs.len()) } else { format!("Maintenance window: {failed} of {} job(s) did not finish", jobs.len()) },
        "clock",
        "Maintenance window",
        status,
        tone,
    );
    r.subtitle = format!("{} job(s) since {}", jobs.len(), since.get(11..16).unwrap_or(since));
    r.sections.push(mail::Section { title: "Jobs".into(), icon: "first-boot", rows, ..Default::default() });
    let mut golds_rows = Vec::new();
    let mut waiting = Vec::new();
    for run in list_runs(&app.db).await.unwrap_or_default() {
        if run.updated_at.as_str() < since {
            continue;
        }
        if run.step == "done" {
            for f in run.followers() {
                if let Some(g) = match &f.to {
                    Some(t) => golds::get(&app.db, t).await.ok().flatten(),
                    None => None,
                } {
                    golds_rows.push(gold_row(&g, Some((Tone::Success, "Ready"))));
                }
            }
        } else if run.active() {
            let p = uup::product(&run.product).map(|p| p.name).unwrap_or("Windows");
            waiting.push(fact(p, format!("{} → {} · {}", run.from_build, run.to_build, run.step)));
        }
    }
    if !golds_rows.is_empty() {
        r.sections.push(mail::Section { title: "New golds".into(), icon: "gold-image", rows: golds_rows, note: "VMs pick the new golds at their next deploy.".into(), ..Default::default() });
    }
    if !waiting.is_empty() {
        waiting.push(fact("Next window", next_window(app).await).icon("clock"));
        r.sections.push(notify::section("Waits for the next window", "clock", waiting));
    }
    r.buttons = vec![mail::button("Jobs", "#/jobs", "log", true), mail::button("Golds", "#/golds", "gold-image", false)];
    r.link = Some("#/jobs".into());
    notify::send(app, "window_report", r).await;
}

fn cap(s: &str) -> String {
    let mut c = s.chars();
    c.next().map(|f| f.to_uppercase().collect::<String>() + c.as_str()).unwrap_or_default()
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
