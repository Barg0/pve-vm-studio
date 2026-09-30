//! Golds: bake one, list them, remove one. A gold is a PVE template made by a bake job;
//! the `golds` table remembers what went into it.
//!
//! Linux bake, in order (New-Vhdx.ps1's Linux path, by way of kiln.sh):
//!   1. PVE downloads the cloud image into an "import" storage and checks its checksum
//!      (reused on the next bake while the published checksum is the same).
//!   2. The studio builds the bake seed (cloud-init NoCloud) and uploads it as an ISO.
//!   3. A bake VM imports the image as its disk, boots, and runs the seed: updates,
//!      packages, region, features, generalize.
//!   4. The studio follows cloud-init's log and the bake's report through the guest agent,
//!      and shuts the VM down once the report says BAKE-OK.
//!   5. Seed detached and deleted, VM renamed, tagged and made a template.

use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use chrono::Utc;
use serde::Serialize;
use serde_json::json;
use sqlx::SqlitePool;

use crate::{
    catalog::LinuxImage,
    form,
    jobs::{JobLog, Tag},
    linux::{self, BakeOptions, REPORT},
    pve::{enc, Pve},
    progress::{self, PackageCounter, Progress},
    seed::SeedIso,
    settings::{BakeSettings, Placement},
};

/// Where golds and their bakes live in PVE.
pub const GOLD_POOL: &str = "vm-studio";
pub const GOLD_IDS: std::ops::RangeInclusive<u32> = 9000..=9999;

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct GoldRow {
    pub id: String,
    pub image_id: String,
    pub os: String,
    pub name: String,
    pub node: String,
    pub vmid: Option<i64>,
    pub storage: String,
    pub status: String,
    pub options: String,
    pub manifest: String,
    pub job_id: Option<String>,
    pub created_at: String,
}

pub async fn list(db: &SqlitePool) -> Result<Vec<GoldRow>> {
    Ok(sqlx::query_as("SELECT * FROM golds WHERE status != 'removed' ORDER BY created_at DESC")
        .fetch_all(db)
        .await?)
}

pub async fn get(db: &SqlitePool, id: &str) -> Result<Option<GoldRow>> {
    Ok(sqlx::query_as("SELECT * FROM golds WHERE id = ?").bind(id).fetch_optional(db).await?)
}

/// Everything a bake job needs, cloned into the job.
#[derive(Clone)]
pub struct BakeCtx {
    pub pve: Pve,
    pub db: SqlitePool,
    pub web: reqwest::Client,
    pub work: std::path::PathBuf,
}

/// What a failed bake leaves behind, taken away again.
#[derive(Default)]
struct Leftovers {
    vm: Option<(String, u32)>,
    volumes: Vec<(String, String)>,
}

impl Leftovers {
    async fn clean(&mut self, pve: &Pve, log: &JobLog) {
        if let Some((node, vmid)) = self.vm.take() {
            match pve.vm_destroy(&node, vmid).await {
                Ok(()) => log.line(format!("Removed bake VM {vmid}")).await,
                Err(e) => log.warn(format!("Could not remove bake VM {vmid}: {e:#}")).await,
            }
        }
        for (node, volid) in self.volumes.drain(..) {
            if let Err(e) = pve.delete_volume(&node, &volid).await {
                log.warn(format!("Could not delete {volid}: {e:#}")).await;
            }
        }
    }
}

pub async fn bake_linux(
    ctx: BakeCtx,
    log: JobLog,
    gold_id: String,
    img: &'static LinuxImage,
    opt: BakeOptions,
    settings: BakeSettings,
) -> Result<()> {
    let mut left = Leftovers::default();
    let result = bake_linux_inner(&ctx, &log, &gold_id, img, &opt, &settings, &mut left).await;
    if result.is_err() {
        left.clean(&ctx.pve, &log).await;
        let _ = sqlx::query("UPDATE golds SET status = 'failed' WHERE id = ?")
            .bind(&gold_id)
            .execute(&ctx.db)
            .await;
    }
    result
}

async fn bake_linux_inner(
    ctx: &BakeCtx,
    log: &JobLog,
    gold_id: &str,
    img: &'static LinuxImage,
    opt: &BakeOptions,
    settings: &BakeSettings,
    left: &mut Leftovers,
) -> Result<()> {
    let pve = &ctx.pve;
    let mut pr = Progress::new(log, format!("Baking {}", img.name));
    pr.stage(0.0, 25.0, "cloud image");
    let p: Placement = settings.resolve(pve).await?;
    let node = p.node.as_str();
    log.run(format!(
        "Baking {} on {node}: disk on {}, image cache on {}, seed on {}, network {}{}",
        img.name,
        p.disk_storage,
        p.import_storage,
        p.iso_storage,
        p.bridge,
        p.vlan.map(|v| format!(" VLAN {v}")).unwrap_or_default()
    ))
    .await;
    sqlx::query("UPDATE golds SET node = ?, storage = ? WHERE id = ?")
        .bind(node)
        .bind(&p.disk_storage)
        .bind(gold_id)
        .execute(&ctx.db)
        .await?;

    // ---- 1. the cloud image ----
    let checksum = match img.pinned_checksum {
        Some(c) => c.to_owned(),
        None => {
            let listing = ctx
                .web
                .get(img.checksum_url)
                .send()
                .await
                .and_then(|r| r.error_for_status())
                .with_context(|| format!("fetching {}", img.checksum_url))?
                .text()
                .await?;
            let file = img.url.rsplit('/').next().unwrap_or_default();
            checksum_from_listing(&listing, file)
                .ok_or_else(|| anyhow!("{} lists no checksum for {file}", img.checksum_url))?
        }
    };
    log.line(format!("Published {}: {checksum}", img.algorithm)).await;
    // Named by content: a new release gets a new file, a rebake of the same one reuses it.
    let import_name = format!("pvs-{}-{}.qcow2", img.id, &checksum[..16]);
    let import_volid = format!("{}:import/{import_name}", p.import_storage);
    let cached = pve
        .storage_content(node, &p.import_storage, "import")
        .await?
        .iter()
        .any(|v| v.volid == import_volid);
    if cached {
        log.ok(format!("Cloud image already in {} ({import_name})", p.import_storage)).await;
        pr.within(1.0, "cloud image cached");
    } else {
        log.get(format!("PVE downloads {}", img.url)).await;
        let file = img.url.rsplit('/').next().unwrap_or_default().to_owned();
        // A mirror that stops sending never ends the task by itself: no progress for five
        // minutes stops it, and the download starts over once (a redirector such as
        // download.fedoraproject.org then usually picks another mirror).
        let mut attempt = 1;
        loop {
            match download(pve, log, &mut pr, node, &p.import_storage, &import_name, img, &checksum, &file).await {
                Ok(()) => break,
                Err(e) if attempt == 1 && format!("{e:#}").contains("stalled") => {
                    log.warn(format!("{e:#} - trying once more")).await;
                    attempt += 1;
                }
                Err(e) => return Err(e),
            }
        }
    }

    // ---- 2. the bake seed ----
    pr.stage(25.0, 27.0, "building the seed");
    let stamp = Utc::now().format("%Y%m%d-%H%M").to_string();
    let user_data = linux::bake_user_data(img, opt);
    let seed_name = format!("pvs-seed-bake-{}-{stamp}", img.id);
    let seed = SeedIso::build(
        &ctx.work,
        &seed_name,
        "cidata",
        &[("user-data", &user_data), ("meta-data", &linux::bake_meta_data(img.id, &stamp))],
    )
    .await?;
    let seed_volid = pve
        .upload(node, &p.iso_storage, "iso", &seed.iso, &format!("{seed_name}.iso"))
        .await;
    seed.remove().await;
    let seed_volid = seed_volid?;
    left.volumes.push((node.to_owned(), seed_volid.clone()));
    log.ok(format!("Seed uploaded as {seed_volid}")).await;

    // ---- 3. the bake VM ----
    pr.stage(27.0, 32.0, "creating the bake VM, importing the disk");
    // Golds are parked out of the way: a pool of their own, ids from 9000 up.
    pve.ensure_pool(GOLD_POOL, "PVE VM Studio: golds (templates) and the bakes that make them").await?;
    let vmid_guard = pve.vmid_guard().await;
    let vmid = pve.free_vmid_in(GOLD_IDS).await?;
    let name = format!("bake-{}-{stamp}", img.id);
    let mut net0 = format!("virtio,bridge={}", p.bridge);
    if let Some(v) = p.vlan {
        net0 += &format!(",tag={v}");
    }
    log.run(format!("Creating bake VM {vmid} ({name}), Secure Boot {}", if img.secure_boot { "on" } else { "off" }))
        .await;
    let create = pve
        .run_task(
            &format!("/nodes/{}/qemu", enc(node)),
            form![
                ("vmid", vmid),
                ("name", &name),
                ("pool", GOLD_POOL),
                ("ostype", "l26"),
                ("machine", "q35"),
                ("bios", "ovmf"),
                ("cpu", &p.cpu),
                ("cores", p.cores),
                ("memory", p.memory_mb),
                ("balloon", 0),
                ("efidisk0", format!("{}:1,efitype=4m,pre-enrolled-keys={}", p.disk_storage, u8::from(img.secure_boot))),
                ("scsihw", "virtio-scsi-single"),
                ("scsi0", format!("{}:0,import-from={import_volid},discard=on,iothread=1,ssd=1", p.disk_storage)),
                ("ide2", format!("{seed_volid},media=cdrom")),
                ("net0", net0),
                ("serial0", "socket"),
                ("agent", "enabled=1,fstrim_cloned_disks=1"),
                ("boot", "order=scsi0"),
                ("tags", "pvs;pvs-bake"),
                ("description", format!("PVE VM Studio: baking {} - removed or made a template when done.", img.name)),
            ],
            |_| {},
        )
        .await;
    drop(vmid_guard);
    // The VM exists as soon as PVE took the request, even when the import then failed.
    left.vm = Some((node.to_owned(), vmid));
    create.context("creating the bake VM")?;
    sqlx::query("UPDATE golds SET vmid = ? WHERE id = ?").bind(vmid).bind(gold_id).execute(&ctx.db).await?;
    pve.vm_resize(node, vmid, "scsi0", &format!("{}G", img.disk_gb)).await?;
    pve.vm_action(node, vmid, "start").await?;
    log.line(format!("Bake VM started - console: {name} ({vmid}) in the PVE UI, user bake / bake")).await;
    pr.within(1.0, "started");

    // ---- 4. follow it ----
    let report = follow_bake(pve, log, &mut pr, node, vmid, p.timeout_min).await?;
    log.run("BAKE-OK - shutting the bake VM down").await;
    pr.stage(97.0, 99.0, "shutting down");
    if pve
        .run_task(&format!("/nodes/{}/qemu/{vmid}/status/shutdown", enc(node)), form![("timeout", 180)], |_| {})
        .await
        .is_err()
    {
        log.warn("Clean shutdown timed out - stopping").await;
        pve.vm_action(node, vmid, "stop").await?;
    }

    for l in report.lines().filter(|l| l.starts_with("BAKE-")) {
        if l.ends_with("MISSING") {
            log.warn(l).await;
        } else {
            log.line(l).await;
        }
    }
    if let Some(l) = report.lines().find(|l| l.starts_with("BAKE-LOCALE") && l.ends_with("MISSING")) {
        bail!("a locale is missing on the gold: {l}");
    }
    let missing: Vec<&str> = report
        .lines()
        .filter(|l| l.starts_with("BAKE-PKG") && l.ends_with("MISSING"))
        .filter_map(|l| l.split_whitespace().nth(1))
        .collect();
    let kernel = report
        .lines()
        .filter(|l| l.starts_with("BAKE-KERNEL "))
        .last()
        .and_then(|l| l.split_whitespace().nth(1))
        .unwrap_or("")
        .to_owned();

    // ---- 5. make it a gold ----
    pr.stage(99.0, 100.0, "making it a template");
    pve.vm_set(node, vmid, form![("delete", "ide2")]).await?;
    pve.delete_volume(node, &seed_volid).await?;
    left.volumes.clear();

    let gold_name = format!("gold-{}-{stamp}", img.id);
    let manifest = json!({
        "osFamily": "linux",
        "image": img.id,
        "name": img.name,
        "distro": img.distro,
        "family": img.family,
        "distroVersion": img.version,
        "secureBoot": img.secure_boot,
        "kernel": kernel,
        "sourceUrl": img.url,
        "sourceChecksum": checksum,
        "checksumAlgorithm": img.algorithm,
        "features": opt.features,
        "updates": opt.updates,
        "region": opt.region,
        "missingPackages": missing,
        "localeMode": "cloud-init",
        "createdUtc": Utc::now().to_rfc3339(),
    });
    let notes = format!(
        "## Gold: {}\n\nBaked by PVE VM Studio on {}. Do not start this template - clone it.\n\n\
         | | |\n|---|---|\n| Image | `{}` |\n| Kernel | `{}` |\n| Secure Boot | {} |\n| Updates | {} |\n| Features | {} |\n| Region | {} |\n| Source | {} |\n",
        img.name,
        Utc::now().format("%Y-%m-%d %H:%M UTC"),
        img.id,
        if kernel.is_empty() { "?" } else { &kernel },
        if img.secure_boot { "on" } else { "off" },
        if opt.updates { "applied" } else { "not applied" },
        if opt.features.is_empty() { "none".into() } else { opt.features.join(", ") },
        opt.region
            .as_ref()
            .map(|r| format!("{} / {} / {} / {}", r.language, r.format, r.keyboard, r.timezone))
            .unwrap_or_else(|| "image default".into()),
        img.url,
    );
    pve.vm_set(
        node,
        vmid,
        form![
            ("name", &gold_name),
            ("tags", format!("pvs;pvs-gold;pvs-img-{}", img.id)),
            ("description", notes),
        ],
    )
    .await?;
    pve.run_task(&format!("/nodes/{}/qemu/{vmid}/template", enc(node)), vec![], |_| {}).await?;
    left.vm = None;

    sqlx::query("UPDATE golds SET status = 'ready', name = ?, manifest = ? WHERE id = ?")
        .bind(&gold_name)
        .bind(manifest.to_string())
        .bind(gold_id)
        .execute(&ctx.db)
        .await?;
    if missing.is_empty() {
        log.ok(format!("Gold ready: {gold_name} (template {vmid}, kernel {kernel})")).await;
    } else {
        log.warn(format!(
            "Gold ready: {gold_name} (template {vmid}) - packages that did not arrive: {}",
            missing.join(" ")
        ))
        .await;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn download(
    pve: &Pve,
    log: &JobLog,
    pr: &mut Progress,
    node: &str,
    storage: &str,
    name: &str,
    img: &LinuxImage,
    checksum: &str,
    file: &str,
) -> Result<()> {
    let upid: String = pve
        .post(
            &format!("/nodes/{}/storage/{}/download-url", enc(node), enc(storage)),
            form![
                ("content", "import"),
                ("filename", name),
                ("url", img.url),
                ("checksum", checksum),
                ("checksum-algorithm", img.algorithm),
            ],
        )
        .await?;
    // wget's progress lines move the bar; the checksum verdict is logged.
    let last_move = std::sync::Arc::new(std::sync::Mutex::new((Instant::now(), -1.0f64)));
    let seen = last_move.clone();
    let mut last_line = String::new();
    let wait = pve.wait_task(&upid, |l| {
        last_line = l.to_owned();
        let words: Vec<&str> = l.split_whitespace().collect();
        if let Some(i) = words.iter().position(|w| w.ends_with('%') && w.trim_end_matches('%').parse::<f64>().is_ok()) {
            let pct = words[i].trim_end_matches('%').parse::<f64>().unwrap_or(0.0);
            let mut m = seen.lock().unwrap();
            if pct > m.1 {
                *m = (Instant::now(), pct);
            }
            // wget: "<offset>K ........ 25% 5.52M 17s" - speed and time left follow.
            let rest = words[i + 1..].join(" ").replace('=', " in ");
            pr.within(pct / 100.0, format!("downloading {file} {pct:.0}%  {rest}"));
        } else if l.contains("checksum") {
            log.tag_now(Tag::Ok, l.trim().to_owned());
        }
    });
    let watchdog = async {
        loop {
            tokio::time::sleep(Duration::from_secs(15)).await;
            if last_move.lock().unwrap().0.elapsed() > Duration::from_secs(300) {
                return;
            }
        }
    };
    let result = tokio::select! {
        r = wait => r.map_err(|e| anyhow!("download failed: {e:#} ({last_line})")),
        () = watchdog => {
            let _: Result<serde_json::Value> = pve
                .delete(&format!("/nodes/{}/tasks/{}", enc(node), enc(&upid)))
                .await;
            Err(anyhow!("the download stalled - no progress for 5 minutes"))
        }
    };
    result
}

/// Streams cloud-init's output and the bake's report into the job log until the report
/// says BAKE-OK, moving the bar by what can be measured: cloud-init's stages while it
/// boots, the package manager's own counters while it installs, the report's milestones
/// while it configures and generalizes. Returns the report.
async fn follow_bake(pve: &Pve, log: &JobLog, pr: &mut Progress, node: &str, vmid: u32, timeout_min: u64) -> Result<String> {
    let started = Instant::now();
    let mut agent_up = false;
    let mut out_offset = 0u64;
    let mut last_note = Instant::now();
    let mut packages = PackageCounter::default();
    // 0 booting, 1 packages, 2 configuring
    let mut phase = 0u8;
    pr.stage(32.0, 35.0, "booting");
    loop {
        if started.elapsed() > Duration::from_secs(timeout_min * 60) {
            bail!("the bake did not finish within {timeout_min} minutes (see the console of VM {vmid})");
        }
        let status = pve.vm_status(node, vmid).await?;
        if status.status != "running" {
            bail!("the bake VM stopped before it reported BAKE-OK");
        }
        if !agent_up {
            if pve.agent_ping(node, vmid).await {
                agent_up = true;
                log.ok("Guest agent is up - following cloud-init").await;
            } else {
                if last_note.elapsed() > Duration::from_secs(60) {
                    last_note = Instant::now();
                    log.line(format!("Booting ({} min) - waiting for the guest agent", started.elapsed().as_secs() / 60)).await;
                }
                tokio::time::sleep(Duration::from_secs(4)).await;
                continue;
            }
        }
        // cloud-init's own log, from where we left off. `cloud-init clean --logs` removes it
        // near the end; the report carries on from there.
        if let Some((chunk, n)) = pve.agent_read(node, vmid, "/var/log/cloud-init-output.log", out_offset).await {
            out_offset += n;
            for l in chunk.lines().map(str::trim_end).filter(|l| !l.is_empty()) {
                log.debug(format!("| {l}")).await;
                if phase == 0
                    && let Some(st) = progress::cloud_init_stage(l)
                {
                    pr.within(f64::from(st) / 4.0, format!("booting - cloud-init stage {st} of 4"));
                    if st == 4 {
                        // modules:final starts with the package module.
                        phase = 1;
                        pr.stage(35.0, 85.0, "installing packages");
                    }
                }
                if phase == 1 && packages.line(l)
                    && let Some(f) = packages.fraction()
                {
                    pr.within(f, packages.summary());
                }
            }
        }
        if let Some((report, _)) = pve.agent_read(node, vmid, REPORT, 0).await {
            if report.lines().any(|l| l.trim() == "BAKE-OK") {
                return Ok(report);
            }
            // The report starts once packages are done: the configure/generalize stage,
            // moved on by its milestones.
            if phase < 2 && report.lines().any(|l| l.starts_with("BAKE-")) {
                phase = 2;
                pr.stage(85.0, 97.0, "configuring");
            }
            if phase == 2 {
                let f = if report.contains("BAKE-PKG") {
                    0.6
                } else if report.contains("BAKE-KERNEL") {
                    0.3
                } else {
                    0.1
                };
                pr.within(f, if f >= 0.6 { "generalizing" } else { "configuring" });
            }
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
}

/// One file's hash out of a published listing: coreutils `<hash>  <name>` or BSD
/// `SHA256 (<name>) = <hash>` (Fedora wraps the latter in a PGP clearsign, whose lines
/// match neither and fall through).
pub fn checksum_from_listing(listing: &str, file: &str) -> Option<String> {
    for line in listing.lines().map(|l| l.trim_end_matches('\r')) {
        if let Some((head, hash)) = line.split_once(") = ")
            && let Some((_, name)) = head.split_once(" (")
        {
            if name == file && hash.chars().all(|c| c.is_ascii_hexdigit()) {
                return Some(hash.to_lowercase());
            }
            continue;
        }
        let mut parts = line.split_whitespace();
        if let (Some(hash), Some(name)) = (parts.next(), parts.next())
            && name.trim_start_matches('*') == file
            && hash.chars().all(|c| c.is_ascii_hexdigit())
        {
            return Some(hash.to_lowercase());
        }
    }
    None
}

/// Removes a gold's template - refused while a VM the studio built still uses it.
pub async fn remove(pve: &Pve, db: &SqlitePool, gold: &GoldRow, log: &JobLog) -> Result<()> {
    let users: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM vms WHERE gold_id = ? AND status != 'removed'")
        .bind(&gold.id)
        .fetch_one(db)
        .await
        .unwrap_or((0,));
    if users.0 > 0 {
        bail!("{} VM(s) still use this gold - remove them first", users.0);
    }
    if let Some(vmid) = gold.vmid {
        match pve.vm_status(&gold.node, vmid as u32).await {
            Ok(s) if s.template == Some(1) => {
                // Linked clones made outside the studio block this too; PVE says so.
                pve.vm_destroy(&gold.node, vmid as u32).await?;
                log.ok(format!("Removed template {vmid}")).await;
            }
            Ok(_) => bail!("VM {vmid} is no longer a template - not touching it"),
            Err(_) => log.line(format!("Template {vmid} is gone already")).await,
        }
    }
    sqlx::query("UPDATE golds SET status = 'removed' WHERE id = ?").bind(&gold.id).execute(db).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::checksum_from_listing;

    #[test]
    fn listings() {
        let gnu = "abc123  debian-13-genericcloud-amd64.qcow2\nfff  other.qcow2\n";
        assert_eq!(checksum_from_listing(gnu, "debian-13-genericcloud-amd64.qcow2").as_deref(), Some("abc123"));
        let bsd = "-----BEGIN PGP SIGNED MESSAGE-----\nSHA256 (Fedora-Cloud-Base-Generic-44-1.7.x86_64.qcow2) = ABCDEF\n";
        assert_eq!(checksum_from_listing(bsd, "Fedora-Cloud-Base-Generic-44-1.7.x86_64.qcow2").as_deref(), Some("abcdef"));
        let star = "0123 *ubuntu-24.04-server-cloudimg-amd64.img\n";
        assert_eq!(checksum_from_listing(star, "ubuntu-24.04-server-cloudimg-amd64.img").as_deref(), Some("0123"));
        assert!(checksum_from_listing(gnu, "missing").is_none());
    }
}
