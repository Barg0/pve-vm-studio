//! The queue across a restart. A queued job has not begun, so the studio starts it again
//! from what it saved - its params, its gold or VM record, a deploy's passwords kept for
//! the wait - under its own id and in its own place. The queue holds after a start until
//! the studio has been up a minute and PVE answers.

use anyhow::{anyhow, Context, Result};

use crate::{
    api, autoupdate, catalog, golds,
    jobs::JobRow,
    mail::{fact, Report, Tone},
    notify, settings, vms, wim, AppState,
};

/// Every job that was queued at the stop, back in the queue in its place; one that cannot
/// be started again is closed as interrupted, with why.
pub async fn restore(app: &AppState) {
    for row in app.jobs.take_pending() {
        match relaunch(app, &row).await {
            Ok(()) => tracing::info!("queued job back in the queue: {}", row.title),
            Err(e) => {
                tracing::warn!("queued job {} not started again: {e:#}", row.title);
                app.jobs.give_up(&row, &format!("the studio restarted and could not queue this job again: {e:#}")).await;
            }
        }
    }
}

async fn relaunch(app: &AppState, row: &JobRow) -> Result<()> {
    let p: serde_json::Value = serde_json::from_str(&row.params).unwrap_or_default();
    let s = |k: &str| p[k].as_str().unwrap_or_default().to_owned();
    let a = app.clone();
    match row.kind.as_str() {
        "cluster-check" => {
            let pve = app.pve.clone();
            app.jobs.restore(row, None, move |log| api::cluster_check(pve, log)).await?;
        }
        "virtio" => {
            app.jobs.restore(row, None, move |log| api::virtio_job(a, log)).await?;
        }
        "fod" => {
            let key = s("fod");
            app.jobs.restore(row, None, move |log| api::fod_job(a, log, key)).await?;
        }
        "winpe" if !s("uup").is_empty() => {
            let (uuid, lang) = (s("uup"), s("lang"));
            app.jobs.restore(row, None, move |log| api::winpe_uup_job(a, log, uuid, lang)).await?;
        }
        "winpe" => {
            let volid = s("iso");
            app.jobs.restore(row, None, move |log| api::winpe_iso_job(a, log, volid)).await?;
        }
        "media" => {
            let editions = p["editions"].as_array().into_iter().flatten().filter_map(|e| e.as_str().map(str::to_owned)).collect();
            let q = api::MediaBuild { product: s("media"), uuid: s("uuid"), build: s("build"), lang: s("lang"), editions };
            let run = s("run");
            app.jobs.restore(row, Some("media"), move |log| api::media_job(a, log, q, run)).await?;
        }
        "update" => {
            let tag = s("tag");
            app.jobs.restore(row, None, move |log| api::update_job(a, log, tag)).await?;
        }
        "certificate" => {
            let acme = serde_json::from_value(p["acme"].clone()).context("the request's Let's Encrypt settings are not saved with it")?;
            let fqdn = s("fqdn");
            app.jobs.restore(row, None, move |log| api::certificate_job(a, log, fqdn, acme)).await?;
        }
        "remove-gold" => {
            let gold = golds::get(&app.db, &s("gold")).await?.ok_or_else(|| anyhow!("gold {} is gone", s("gold")))?;
            let (pve, db, data) = (app.pve.clone(), app.db.clone(), app.config.data_dir.clone());
            app.jobs.restore(row, None, move |log| api::remove_gold_job(pve, db, data, gold, log)).await?;
        }
        // A window's bake: it makes its gold from the run's new ISO when it starts.
        "bake" if !s("from").is_empty() && s("gold").is_empty() => {
            let (id, from) = (s("auto_update"), s("from"));
            app.jobs.restore(row, None, move |log| autoupdate::window_bake_job(a, log, id, from)).await?;
        }
        "bake" => {
            let gold = golds::get(&app.db, &s("gold")).await?.ok_or_else(|| anyhow!("its gold {} is gone", s("gold")))?;
            if gold.status != "baking" {
                return Err(anyhow!("its gold {} is {}", gold.id, gold.status));
            }
            if gold.os == "windows" {
                let opt: crate::windows::WinBakeOptions = serde_json::from_str(&gold.options).context("reading the bake's options")?;
                let path = api::iso_path(app, &opt.iso).ok_or_else(|| anyhow!("{} is not an ISO volume", opt.iso))?;
                let img = wim::inspect(&path, &app.config.data_dir.join("wim-cache.json"))
                    .await?
                    .into_iter()
                    .find(|i| i.index == opt.index)
                    .ok_or_else(|| anyhow!("{} has no image {}", opt.iso, opt.index))?;
                let gid = gold.id.clone();
                app.jobs.restore(row, None, move |log| api::windows_bake_job(a, log, gid, opt, img, path)).await?;
            } else {
                let img = catalog::linux(&gold.image_id).ok_or_else(|| anyhow!("unknown image {}", gold.image_id))?;
                let opts: crate::linux::BakeOptions = serde_json::from_str(&gold.options).context("reading the bake's options")?;
                let bake: settings::BakeSettings = settings::load(&app.db, "bake").await?;
                let (ctx, gid) = (app.bake_ctx(), gold.id.clone());
                app.jobs.restore(row, None, move |log| golds::bake_linux(ctx, log, gid, img, opts, bake)).await?;
            }
        }
        "deploy" => {
            let vm = vms::get(&app.db, &s("vm")).await?.ok_or_else(|| anyhow!("its VM record is gone"))?;
            if vm.status != "building" {
                return Err(anyhow!("{} is {}", vm.name, vm.status));
            }
            let mut spec: vms::VmSpec = serde_json::from_str(&vm.spec).context("reading the VM's design")?;
            let secrets = app.jobs.secret(&row.id).await.ok_or_else(|| anyhow!("its passwords were not kept for the wait - deploy {} again", vm.name))?;
            spec.put_secrets(&secrets);
            let (pve, db, work, vid) = (app.pve.clone(), app.db.clone(), app.config.data_dir.join("work"), vm.id.clone());
            app.jobs.restore(row, None, move |log| vms::deploy(pve, db, work, log, vid, spec)).await?;
        }
        "auto-update" if s("step") == "cleanup" => {
            let id = s("auto_update");
            app.jobs.restore(row, None, move |log| autoupdate::cleanup_job(a, log, id)).await?;
        }
        other => return Err(anyhow!("a {other} job is not started again on its own")),
    }
    Ok(())
}

/// After a start the queue waits: at least a minute, then until PVE answers. Without PVE
/// for a quarter of an hour, one notification says so.
pub async fn release_after_start(app: AppState) {
    let started = std::time::Instant::now();
    tokio::time::sleep(std::time::Duration::from_secs(60)).await;
    let mut down_since: Option<(std::time::Instant, String)> = None;
    let mut told = false;
    loop {
        match app.pve.version().await {
            Ok(_) => {
                app.jobs.release();
                tracing::info!("queue released {}s after the start", started.elapsed().as_secs());
                return;
            }
            Err(e) => {
                let (since, at) = down_since.get_or_insert_with(|| (std::time::Instant::now(), chrono::Local::now().format("%H:%M").to_string()));
                app.jobs.hold(&format!("PVE does not answer since {at} - the queue waits"));
                if !told && since.elapsed() >= std::time::Duration::from_secs(15 * 60) {
                    told = true;
                    let mut r = Report::new("Queue waits for PVE", "security", "Queue waits", "WAITING", Tone::Warn);
                    r.subtitle = format!("The studio restarted at {at}; PVE has not answered since, so no queued job starts");
                    r.facts = vec![fact("PVE", format!("{e:#}"))];
                    r.link = Some("#/jobs".into());
                    notify::send(&app, "queue_waits", r).await;
                }
            }
        }
        tokio::time::sleep(std::time::Duration::from_secs(15)).await;
    }
}
