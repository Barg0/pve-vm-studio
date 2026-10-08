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
    cis,
    form,
    jobs::{JobLog, Tag},
    linux::{self, BakeOptions, REPORT},
    pve::{enc, Pve},
    progress::{self, PackageCounter, Progress},
    seed::{self, SeedDisk},
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

/// Eight random hex digits naming one build from start to finish - New-Vhdx's buildId:
/// the bake VM (bake-7c41e09a), its seeds, the log, and then the gold itself (7c41e09a). Drawn until it is free: no gold the studio ever recorded has it (removed
/// ones included, so an old log never points at a new gold), and no VM or template in the
/// cluster carries it in its name - one made by hand or by another studio included.
/// [diff] Hyper-V names the finished gold by the first 8 of its SHA-256; the studio reaches
/// disks through the PVE API only and cannot hash one, so the random id stays its name.
pub async fn new_build_id(db: &SqlitePool, pve: &Pve) -> Result<String> {
    let names: Vec<String> = pve
        .resources()
        .await
        .context("reading the cluster's VMs to pick a free gold id")?
        .into_iter()
        .filter(|r| r.kind == "qemu" || r.kind == "lxc")
        .filter_map(|r| r.name.map(|n| n.to_lowercase()))
        .collect();
    for _ in 0..64 {
        let id = uuid::Uuid::new_v4().simple().to_string()[..8].to_owned();
        let taken: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM golds WHERE id = ?").bind(&id).fetch_one(db).await?;
        if taken.0 == 0 && !names.iter().any(|n| n.contains(&id)) {
            return Ok(id);
        }
    }
    bail!("no free gold id after 64 draws")
}

/// bake-<id>: the bake VM and its working name, until it is a gold.
pub fn working_name(id: &str) -> String {
    format!("bake-{id}")
}

/// The finished gold's template name: the id alone. [diff] Hyper-V prefixes hv-/azl- because
/// Azure Local golds share the folder; on PVE there is one kind of gold and its pool says
/// what it is.
pub fn gold_name(id: &str) -> String {
    id.to_owned()
}

/// Whether a VM name is one of the studio's bake VMs (bake-<8 hex>, older bake-pve-<8 hex>).
pub fn is_bake_vm_name(name: &str) -> bool {
    let id = name.strip_prefix("bake-pve-").or_else(|| name.strip_prefix("bake-")).unwrap_or("");
    id.len() == 8 && id.chars().all(|c| c.is_ascii_hexdigit())
}

fn manifest_of(g: &GoldRow) -> serde_json::Value {
    serde_json::from_str(&g.manifest).unwrap_or_default()
}

/// The language a gold speaks - the sidecar's `language` (Windows: the image's own UI
/// language; Linux: LANG). Golds from before schema 2 kept it elsewhere.
pub fn language(g: &GoldRow) -> String {
    let m = manifest_of(g);
    let pick = |v: &serde_json::Value| v.as_str().filter(|s| !s.is_empty()).map(str::to_owned);
    pick(&m["language"])
        .or_else(|| pick(&m["imageLanguage"]))
        .or_else(|| pick(&m["region"]["language"]))
        .or_else(|| if g.os == "windows" { pick(&m["locale"]) } else { None })
        .unwrap_or_default()
}

/// The sidecar's build as something that sorts (Build-Vms' ConvertTo-GoldBuildVersion):
/// 10.0.26100.4061 as itself, "24.04" as 24.4, "13" as 13.0; anything that is not a
/// version - "rolling" - below every real one, leaving the bake date to decide.
pub fn build_version(g: &GoldRow) -> Vec<u64> {
    let m = manifest_of(g);
    // Windows writes 10.0.26300.9457; without the 10.0 every build compares as it reads.
    let raw = m["build"].as_str().or_else(|| m["distroVersion"].as_str()).unwrap_or("").trim();
    let text = raw.strip_prefix("10.0.").filter(|r| r.contains('.')).unwrap_or(raw).to_owned();
    let parts: Option<Vec<u64>> = text.split('.').map(|p| p.parse().ok()).collect();
    match parts {
        Some(mut v) if !text.is_empty() => {
            if v.len() == 1 {
                v.push(0);
            }
            v
        }
        _ => vec![0, 0],
    }
}

/// The gold a designed VM builds from (Build-Vms' Select-GoldByInstruction): a pinned
/// gold id first, then the design's language, then the newest - highest build, then the
/// latest bake.
/// Windows client releases by base build: 26300 is 26H2. Server builds have no such name
/// (26100 is Windows Server 2025 there), so only Windows 11 golds get one.
pub const CLIENT_RELEASES: &[(u64, &str)] = &[(26300, "26H2"), (26200, "25H2"), (26100, "24H2"), (22631, "23H2"), (22621, "22H2"), (22000, "21H2")];

/// A Windows 11 gold's release (25H2, 26H2), from its build.
pub fn release(g: &GoldRow) -> Option<&'static str> {
    if !g.image_id.starts_with("w11") {
        return None;
    }
    let major = build_version(g).first().copied()?;
    CLIENT_RELEASES.iter().find(|(b, _)| *b == major).map(|(_, r)| *r)
}

/// The gold a VM builds from: a pinned one, else the newest build of its image - in its
/// language and its release (25H2, 26H2) when the design names them.
pub fn resolve<'a>(golds: &'a [GoldRow], image: &str, lang: &str, pin: &str, rel: &str) -> Option<&'a GoldRow> {
    if !pin.is_empty() {
        return golds.iter().find(|g| g.status == "ready" && g.id == pin);
    }
    golds
        .iter()
        .filter(|g| g.status == "ready" && g.image_id == image && (lang.is_empty() || language(g).eq_ignore_ascii_case(lang)))
        .filter(|g| rel.is_empty() || release(g).is_some_and(|r| r.eq_ignore_ascii_case(rel)))
        .max_by(|a, b| build_version(a).cmp(&build_version(b)).then_with(|| a.created_at.cmp(&b.created_at)))
}

/// What a gold was made with, for the sidecar fields every bake shares (Complete-GoldImage):
/// which studio baked it - its binary's SHA-256, since a release has no git to ask.
pub async fn studio_sha256() -> String {
    static HASH: tokio::sync::OnceCell<String> = tokio::sync::OnceCell::const_new();
    HASH.get_or_init(|| async {
        match std::env::current_exe() {
            Ok(exe) => sha256_file(&exe).await.unwrap_or_default(),
            Err(_) => String::new(),
        }
    })
    .await
    .clone()
}

/// SHA-256 of a file, through sha256sum.
pub async fn sha256_file(path: &std::path::Path) -> Result<String> {
    let out = tokio::process::Command::new("sha256sum").arg(path).output().await.context("running sha256sum")?;
    if !out.status.success() {
        bail!("sha256sum {}: {}", path.display(), String::from_utf8_lossy(&out.stderr).trim());
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let hash = text.split_whitespace().next().unwrap_or("");
    if hash.len() != 64 {
        bail!("sha256sum {}: unexpected output", path.display());
    }
    Ok(hash.to_owned())
}

/// The sidecar keys every gold carries after what the bake knows about the image:
/// identity first (schema, id, buildId), the bake host and studio, the disk, the time.
pub async fn complete_manifest(id: &str, image: serde_json::Value, node: &str, storage: &str, disk_gb: u32) -> serde_json::Value {
    let mut out = serde_json::Map::new();
    out.insert("schema".into(), json!(2));
    out.insert("id".into(), json!(id));
    // [diff] No sha256: the studio cannot read the disk (see new_build_id).
    out.insert("buildId".into(), json!(id));
    if let serde_json::Value::Object(m) = image {
        out.extend(m);
    }
    out.insert("bakeHost".into(), json!(node));
    out.insert("scriptSha256".into(), json!(studio_sha256().await));
    out.insert("target".into(), json!("pve"));
    out.insert("generation".into(), json!(2));
    out.insert("storage".into(), json!(storage));
    out.insert("diskSizeGB".into(), json!(disk_gb));
    out.insert("createdUtc".into(), json!(Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()));
    serde_json::Value::Object(out)
}

/// SHA-256 of a source ISO for the sidecar's sourceMediaSha256 - New-Vhdx hashes its
/// media too. Cached per path, size and mtime, as the image list is: 5 GB once, not per bake.
pub async fn iso_sha256(path: &std::path::Path, cache_file: &std::path::Path) -> Result<String> {
    let meta = tokio::fs::metadata(path).await.with_context(|| format!("reading {}", path.display()))?;
    let mtime = meta.modified().ok().and_then(|m| m.duration_since(std::time::UNIX_EPOCH).ok()).map(|d| d.as_secs()).unwrap_or(0);
    let key = format!("{}|{}|{mtime}", path.display(), meta.len());
    let mut cache: std::collections::HashMap<String, String> =
        tokio::fs::read(cache_file).await.ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default();
    if let Some(hit) = cache.get(&key) {
        return Ok(hit.clone());
    }
    let hash = sha256_file(path).await?;
    cache.insert(key, hash.clone());
    if let Ok(b) = serde_json::to_vec(&cache) {
        let _ = tokio::fs::write(cache_file, b).await;
    }
    Ok(hash)
}

/// New-Vhdx's preflight: the node has the bake VM's memory free, so a bake does not
/// start only to be starved (or to starve what already runs there).
pub async fn check_node_memory(pve: &Pve, log: &JobLog, node: &str, memory_mb: u32) -> Result<()> {
    let res = pve.resources().await?;
    let Some(n) = res.iter().find(|r| r.kind == "node" && r.node.as_deref() == Some(node)) else {
        bail!("node {node} is not in the cluster's resources");
    };
    let (mem, max) = (n.mem.unwrap_or(0), n.maxmem.unwrap_or(0));
    let free_mb = max.saturating_sub(mem) / (1024 * 1024);
    if max > 0 && free_mb < u64::from(memory_mb) {
        bail!("{node} has {free_mb} MiB memory free, the bake VM needs {memory_mb} MiB");
    }
    log.debug(format!("{node}: {free_mb} MiB free, the bake VM takes {memory_mb} MiB")).await;
    Ok(())
}

/// Sets a gold's free-text label (Show golds' L).
pub async fn set_label(db: &SqlitePool, id: &str, label: &str) -> Result<()> {
    let g = get(db, id).await?.ok_or_else(|| anyhow!("no such gold"))?;
    let mut m = manifest_of(&g);
    if !m.is_object() {
        m = json!({});
    }
    m["label"] = json!(label.trim());
    sqlx::query("UPDATE golds SET manifest = ? WHERE id = ?").bind(m.to_string()).bind(id).execute(db).await?;
    Ok(())
}

/// How many of the studio's VMs were cloned from each gold - a linked clone needs its
/// gold for as long as it lives.
/// How many linked clones of each gold still exist in PVE - a linked clone needs its gold,
/// and PVE refuses to remove a template one still uses; a full copy does not count. A record the studio cleared from
/// view counts while its VM is there; a VM that is gone from PVE does not count, whatever
/// the record says. Matched on node, VMID and name, so a reused VMID is not mistaken for it.
pub async fn usage(db: &SqlitePool, pve: &Pve) -> Result<std::collections::HashMap<String, i64>> {
    let rows: Vec<(String, String, Option<i64>, String)> =
        sqlx::query_as("SELECT gold_id, node, vmid, name FROM vms WHERE status != 'removed' AND vmid IS NOT NULL").fetch_all(db).await?;
    let live: std::collections::HashSet<(String, u32, String)> = pve
        .resources()
        .await?
        .into_iter()
        .filter(|r| r.kind == "qemu")
        .filter_map(|r| Some((r.node?, r.vmid?, r.name.unwrap_or_default().to_lowercase())))
        .collect();
    let mut out = std::collections::HashMap::new();
    for (gold, node, vmid, name) in rows {
        let Some(v) = vmid else { continue };
        if !live.contains(&(node.clone(), v as u32, name.to_lowercase())) {
            continue;
        }
        // Linked clones only: their disks live on the template's base volume
        // ("base-9002-disk-1/vm-102-disk-1"); a full copy has its own and does not need the gold.
        // A config that cannot be read counts, to be safe.
        let linked = match pve.vm_config(&node, v as u32).await {
            Ok(cfg) => cfg.iter().any(|(k, val)| {
                (k.starts_with("scsi") || k.starts_with("virtio") || k.starts_with("sata") || k.starts_with("ide") || k.starts_with("efidisk") || k.starts_with("tpmstate"))
                    && val.as_str().is_some_and(|s| s.contains(":base-"))
            }),
            Err(_) => true,
        };
        if linked {
            *out.entry(gold).or_insert(0) += 1;
        }
    }
    Ok(out)
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

/// A Linux gold's disk: the bake's ask, never below the image's size - and 40 GiB at least
/// for CIS Level 2 (/home, /var, /var/tmp, /var/log, /var/log/audit beside a 12 GiB root).
/// Level 2's volumes beside a root that cannot shrink (an LVM root image).
const CIS_VOLUMES_GB: u32 = 28;

/// scsi0's size in whole GB, as PVE reports it ("...,size=37G").
async fn disk_size_gb(pve: &Pve, node: &str, vmid: u32) -> Option<u32> {
    let cfg = pve.vm_config(node, vmid).await.ok()?;
    let v = cfg.get("scsi0")?.as_str()?;
    let size = v.split(',').find_map(|p| p.strip_prefix("size="))?;
    let (n, unit) = size.split_at(size.find(|c: char| !c.is_ascii_digit() && c != '.')?);
    let n: f64 = n.parse().ok()?;
    let gb = match unit {
        "T" => n * 1024.0,
        "G" => n,
        "M" => n / 1024.0,
        _ => return None,
    };
    Some(gb.ceil() as u32)
}

pub fn gold_disk_gb(img: &LinuxImage, opt: &BakeOptions) -> u32 {
    let gb = opt.disk_gb.unwrap_or(img.disk_gb).max(img.disk_gb);
    if opt.cis_level(img.id) == 2 { gb.max(40) } else { gb }
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
    pr.calibrate("cloud image").await;
    pr.stage(0.0, 25.0, "cloud image");
    // The bake form's node and network for this bake, over the bake settings'.
    let settings = opt.placement_over(settings);
    let p: Placement = settings.resolve(pve).await?.with_disk_storage(pve, opt.disk_storage.as_deref()).await?;
    let node = p.node.as_str();
    check_node_memory(pve, log, node, p.memory_mb).await?;
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
            log.check_abort()?;
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
    let seed_name = format!("pvs-seed-{}", working_name(&gold_id));
    let cis_level = opt.cis_level(img.id);
    // A small disk labelled CIDATA (NoCloud reads it as it reads the ISO), attached once
    // the VM exists. A CIS bake carries the pvs-cis bundle on it as well.
    let meta = linux::bake_meta_data(img.id, &stamp);
    let mut files: Vec<(String, Vec<u8>)> = vec![("user-data".into(), user_data.into_bytes()), ("meta-data".into(), meta.into_bytes())];
    // A network without DHCP: the bake VM gets the static address from the bake settings,
    // matched by the MAC it is created with. The clone's first boot writes its own.
    let bake_mac = crate::vms::new_mac();
    if let Some(ip) = opt.bake_address.clone().filter(|a| !a.is_empty()) {
        let prefix = p.linux_address.rsplit_once('/').and_then(|(_, b)| b.trim().parse::<u8>().ok()).unwrap_or(24);
        let nic = linux::NicCfg { mac: bake_mac.clone(), address: ip.clone(), prefix, gateway: p.linux_gateway.clone(), dns: p.linux_dns.clone(), search: String::new() };
        if let Some(n) = linux::vm_network_config(&[nic], false) {
            files.push(("network-config".into(), n.into_bytes()));
        }
        log.line(format!("Bake address {ip}/{prefix}, gateway {}, DNS {}", p.linux_gateway, p.linux_dns.join(", "))).await;
    }
    if cis_level > 0
        && let (Some(b), Some(c)) = (cis::benchmark_for(img.id), &opt.cis)
    {
        files.extend(cis::seed_files(b, c));
        log.line(format!("CIS: {} v{}, Level {cis_level} Server{}", b.name, b.version,
            if c.exceptions.is_empty() { String::new() } else { format!(", {} exception(s)", c.exceptions.len()) })).await;
    }
    let refs: Vec<(&str, &[u8])> = files.iter().map(|(n, c)| (n.as_str(), c.as_slice())).collect();
    let seed = SeedDisk::build_bytes(&ctx.work, &seed_name, "CIDATA", &refs).await?;

    // ---- 3. the bake VM ----
    pr.stage(27.0, 32.0, "creating the bake VM, importing the disk");
    // Golds are parked out of the way: a pool of their own, ids from 9000 up.
    pve.ensure_pool(GOLD_POOL, "PVE VM Studio: golds (templates) and the bakes that make them").await?;
    let vmid_guard = pve.vmid_guard().await;
    let vmid = pve.free_vmid_in(GOLD_IDS).await?;
    let name = working_name(&gold_id);
    let mut net0 = format!("virtio={bake_mac},bridge={}", p.bridge);
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
                ("numa", 1),
                ("efidisk0", format!("{}:1,efitype=4m,pre-enrolled-keys={}", p.disk_storage, u8::from(img.secure_boot))),
                ("scsihw", "virtio-scsi-single"),
                ("scsi0", format!("{}:0,import-from={import_volid},discard=on,iothread=1,ssd=1", p.disk_storage)),
                ("net0", net0),
                ("serial0", "socket"),
                ("agent", "enabled=1,fstrim_cloned_disks=1"),
                ("boot", "order=scsi0"),
                ("tags", crate::tags::BAKE),
                ("description", format!("PVE VM Studio: baking {} - removed or made a template when done.", img.name)),
            ],
            |l| {
                if let Some(f) = crate::pve::Pve::transferred(l) {
                    pr.within(f, format!("importing the disk · {:.0}%", f * 100.0));
                }
            },
        )
        .await;
    drop(vmid_guard);
    // The VM exists as soon as PVE took the request, even when the import then failed.
    left.vm = Some((node.to_owned(), vmid));
    create.context("creating the bake VM")?;
    seed::attach(pve, node, vmid, linux::SEED_SLOT, &p.disk_storage, seed, &seed_name).await.context("attaching the seed disk")?;
    log.ok(format!("Seed attached as a disk ({})", linux::SEED_SLOT)).await;
    sqlx::query("UPDATE golds SET vmid = ? WHERE id = ?").bind(vmid).bind(gold_id).execute(&ctx.db).await?;
    // Level 2 puts /home, /var, /var/tmp, /var/log and /var/log/audit on volumes of their own
    // beside a 12 GiB root: 40 GiB at least.
    let disk_gb = gold_disk_gb(img, opt);
    // Level 2: the disk starts at the root's size and grows once the guest agent answers -
    // an image that grows its root to the disk before cloud-init (Debian) then takes only
    // that much, and the rest becomes the LVM volumes (guest-files/cis/layout.sh).
    let mut grow_later = (cis_level == 2).then_some(disk_gb);
    // The root's size exactly: the catalog's disk_gb is the studio's default for a gold, not
    // what the image needs (cloud images are 2-4 GB).
    let mut first_gb = if grow_later.is_some() { linux::CIS_ROOT_GB } else { disk_gb };
    // An image larger than that (Oracle Linux's KVM template: 37 GB, the root an LV filling
    // it) keeps its size - a disk does not shrink - and gets the volumes' space on top.
    let image_gb = disk_size_gb(pve, node, vmid).await.unwrap_or(0);
    if image_gb > first_gb {
        first_gb = image_gb;
        if grow_later.is_some() {
            grow_later = Some((image_gb + CIS_VOLUMES_GB).max(disk_gb));
        }
    }
    pve.vm_resize(node, vmid, "scsi0", &format!("{first_gb}G")).await?;
    pve.vm_action(node, vmid, "start").await?;
    log.line(format!("Bake VM started - console: {name} ({vmid}) in the PVE UI, user bake / bake")).await;
    pr.within(1.0, "started");

    // ---- 4. follow it ----
    // The CIS fix, the reboot and the check take their time on top.
    let timeout = p.timeout_min + if cis_level > 0 { 30 } else { 0 };
    let report = follow_bake(pve, log, &mut pr, node, vmid, timeout, grow_later).await?;
    // The CIS report and the GRUB password, from /run - gone with the shutdown.
    let mut cis_report: Option<(Vec<u8>, Option<String>)> = None;
    if cis_level > 0 {
        let mut raw = Vec::new();
        let mut off = 0u64;
        while let Some((chunk, n)) = pve.agent_read(node, vmid, "/run/pvs-cis/report.json", off).await {
            if n == 0 {
                break;
            }
            raw.extend_from_slice(chunk.as_bytes());
            off += n;
        }
        if raw.is_empty() {
            bail!("the CIS check left no report (/run/pvs-cis/report.json) - see the console of VM {vmid}");
        }
        let grub = pve.agent_read(node, vmid, "/run/pvs-cis/grub-password", 0).await.map(|(p, _)| p);
        cis_report = Some((raw, grub));
    }
    log.run("Bake finished - shutting the bake VM down").await;
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
            log.warn(crate::markers::text(l)).await;
        } else {
            log.line(crate::markers::text(l)).await;
        }
    }
    if let Some(l) = report.lines().find(|l| l.starts_with("BAKE-LOCALE") && l.ends_with("MISSING")) {
        bail!("a locale is missing on the gold: {}", crate::markers::text(l));
    }
    if let Some(l) = report.lines().find(|l| l.starts_with("BAKE-LAYOUT-FAILED")) {
        bail!("the CIS Level 2 filesystems could not be set up: {}", crate::markers::text(l));
    }
    for l in report.lines().filter(|l| l.starts_with("CIS-FIX-FAILED")) {
        log.warn(l).await;
    }
    let cis_summary = match &cis_report {
        Some((raw, grub)) => {
            let v: serde_json::Value = serde_json::from_slice(raw).context("reading the CIS report")?;
            let sum = cis::summarize(&v)?;
            let data = ctx.work.parent().unwrap_or(&ctx.work);
            cis::store(data, gold_id, raw, grub.as_deref()).await?;
            log.ok(format!(
                "CIS {}: {} pass, {} fail, {} exception, {} review, {} n/a{}",
                sum.line(), sum.pass, sum.fail, sum.exception, sum.review, sum.na,
                if grub.as_deref().is_some_and(|g| !g.trim().is_empty()) { " - GRUB password kept with the report" } else { "" }
            ))
            .await;
            for r in v["results"].as_array().into_iter().flatten().filter(|r| matches!(r["status"].as_str(), Some("fail" | "error"))) {
                log.line(format!("CIS {} {}: {}", r["status"].as_str().unwrap_or(""), r["id"].as_str().unwrap_or(""), r["title"].as_str().unwrap_or(""))).await;
            }
            Some(sum)
        }
        None => None,
    };
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
    seed::detach(pve, node, vmid, linux::SEED_SLOT).await?;

    let gold_name = self::gold_name(&gold_id);
    // New-Vhdx's New-LinuxGoldManifest, then the keys every gold shares.
    let region = opt.region.as_ref();
    let r = |f: fn(&linux::Region) -> &String| region.map(|x| f(x).clone()).unwrap_or_default();
    let manifest = complete_manifest(
        &gold_id,
        json!({
            "label": "",
            "osFamily": "linux",
            "imageId": img.id,
            "displayName": img.name,
            "build": img.version,
            // language and locale are separate on Linux: LANG, and the LC_* format family.
            "language": r(|x| &x.language),
            "locale": r(|x| &x.format),
            "keyboardLayout": r(|x| &x.keyboard),
            "timeZone": r(|x| &x.timezone),
            "localeMode": "cloud-init",
            "distro": img.distro,
            "family": img.family,
            "secureBoot": img.secure_boot,
            "secureBootTemplate": if img.secure_boot { "MicrosoftUEFICertificateAuthority" } else { "" },
            "requiresTpm": false,
            "generalized": true,
            "kernel": kernel,
            "updatesApplied": opt.updates,
            "features": opt.features,
            "aptMirror": opt.mirror_uri(&img).unwrap_or_default(),
            "sourceUrl": img.url,
            "sourceFormat": img.url.rsplit('.').next().unwrap_or(""),
            "sourceChecksum": checksum,
            "checksumAlgorithm": img.algorithm,
            "missingPackages": missing,
            "cis": cis_summary.as_ref().map(|s| json!({
                "benchmark": s.benchmark, "version": s.version, "level": s.level, "profile": s.profile,
                "checked": s.checked, "score": s.score, "pass": s.pass, "fail": s.fail, "na": s.na,
                "review": s.review, "exception": s.exception, "error": s.error,
                "exceptions": opt.cis.as_ref().map(|c| c.exceptions.clone()).unwrap_or_default(),
            })),
        }),
        node,
        &p.disk_storage,
        disk_gb,
    )
    .await;
    let notes = format!(
        "## Gold: {}\n\nBaked by PVE VM Studio on {}. Do not start this template - clone it.\n\n\
         | | |\n|---|---|\n| Image | `{}` |\n| Kernel | `{}` |\n| Secure Boot | {} |\n| Updates | {} |\n| Features | {} |\n| Region | {} |\n| Source | {} |\n{}",
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
        cis_summary
            .as_ref()
            .map(|c| format!("| CIS | {} v{} - {} (self-assessed) |\n", c.benchmark, c.version, c.line()))
            .unwrap_or_default(),
    );
    let tags = crate::tags::gold("linux", img.id, &manifest);
    pve.vm_set(node, vmid, form![("name", &gold_name), ("tags", tags.join(";")), ("description", notes)]).await?;
    crate::tags::paint(pve, &tags).await;
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
async fn follow_bake(pve: &Pve, log: &JobLog, pr: &mut Progress, node: &str, vmid: u32, timeout_min: u64, grow_to: Option<u32>) -> Result<String> {
    let started = Instant::now();
    let mut agent_up = false;
    let mut grown = false;
    let mut out_offset = 0u64;
    let mut last_note = Instant::now();
    let mut packages = PackageCounter::default();
    // 0 booting, 1 packages, 2 configuring
    let mut phase = 0u8;
    pr.stage(32.0, 35.0, "booting");
    loop {
        log.check_abort()?;
        if started.elapsed() > Duration::from_secs(timeout_min * 60) {
            bail!("the bake did not finish within {timeout_min} minutes (see the console of VM {vmid})");
        }
        let status = pve.vm_status(node, vmid).await?;
        if status.status != "running" {
            bail!("the bake VM stopped before the bake finished");
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
            // Level 2: the disk grows once the guest has its root at ROOT_GB and growing
            // switched off (BAKE-GROW-READY, runcmd) - the agent can answer before cloud-init's
            // growpart has run (Enterprise Linux), which would take the whole disk.
            if let Some(gb) = grow_to
                && !grown
                && report.lines().any(|l| l.trim() == "BAKE-GROW-READY")
            {
                pve.vm_resize(node, vmid, "scsi0", &format!("{gb}G")).await.context("growing the disk for the CIS volumes")?;
                grown = true;
                log.line(format!("Disk grown to {gb} GB for the CIS Level 2 volumes")).await;
            }
            if report.lines().any(|l| l.trim() == "BAKE-OK") {
                return Ok(report);
            }
            // The report starts once packages are done: the configure/generalize stage,
            // moved on by its milestones.
            if phase < 2 && report.lines().any(|l| l.starts_with("BAKE-") && l.trim() != "BAKE-GROW-READY") {
                phase = 2;
                pr.stage(85.0, 97.0, "configuring");
            }
            if phase == 2 {
                // A CIS bake: hardened, rebooted, checked, sealed - its markers move it on.
                let (f, what) = if report.contains("BAKE-CIS-SEALING") {
                    (0.95, "generalizing")
                } else if report.contains("BAKE-CIS-CHECKING") {
                    (0.8, "checking the CIS rules")
                } else if report.contains("BAKE-LAYOUT migrated") {
                    (0.7, "rebooted into the hardened system")
                } else if report.contains("BAKE-CIS-REBOOT") {
                    (0.65, "rebooting into the hardened system")
                } else if report.contains("CIS-FIX-DONE") {
                    (0.6, "hardened - rebooting")
                } else if report.contains("BAKE-PKG") {
                    (0.6, if report.contains("BAKE-CIS-BUNDLE") { "applying the CIS rules" } else { "generalizing" })
                } else if report.contains("BAKE-KERNEL") {
                    (0.3, "configuring")
                } else {
                    (0.1, "configuring")
                };
                pr.within(f, what);
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

/// The VM is this gold's: named after the gold (a template) or its bake ("bake-<id>").
fn owns_vm(gold: &GoldRow, vm_name: Option<&str>) -> bool {
    let Some(n) = vm_name else { return false };
    n == gold.id || n == format!("bake-{}", gold.id) || (!gold.name.is_empty() && n == gold.name)
}

/// Removes a gold's template - refused while a VM the studio built still uses it.
pub async fn remove(pve: &Pve, db: &SqlitePool, gold: &GoldRow, log: &JobLog) -> Result<()> {
    // Only VMs that exist in PVE count (usage) - a record of one that is gone does not.
    let users = usage(db, pve).await?.get(&gold.id).copied().unwrap_or(0);
    if users > 0 {
        bail!("{users} VM(s) in PVE are linked clones of this gold - PVE keeps a template while a clone uses its disk; remove those VMs first");
    }
    if let Some(vmid) = gold.vmid {
        match pve.vm_status(&gold.node, vmid as u32).await {
            // VMIDs are reused: an old record's VMID can be a newer gold's template by now.
            // Only a VM that carries this gold's name is this gold's.
            Ok(s) if !owns_vm(gold, s.name.as_deref()) => {
                log.line(format!("VM {vmid} is {} now, not this gold's template - left alone", s.name.as_deref().unwrap_or("unnamed"))).await;
            }
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
    use super::*;

    #[test]
    fn release_picks() {
        let g = |id: &str, build: &str| GoldRow {
            id: id.into(), image_id: "w11-enterprise".into(), os: "windows".into(), name: id.into(), node: "pve-01".into(), vmid: None,
            storage: "local-lvm".into(), status: "ready".into(), options: "{}".into(),
            manifest: format!(r#"{{"build":"{build}"}}"#), job_id: None, created_at: "2026-10-07".into(),
        };
        let golds = vec![g("a25", "10.0.26200.9550"), g("b26", "10.0.26300.9457"), g("c25", "26200.9601")];
        assert_eq!(release(&golds[0]), Some("25H2"));
        assert_eq!(release(&golds[1]), Some("26H2"));
        assert_eq!(resolve(&golds, "w11-enterprise", "", "", "").map(|g| g.id.as_str()), Some("b26"));
        assert_eq!(resolve(&golds, "w11-enterprise", "", "", "25H2").map(|g| g.id.as_str()), Some("c25"));
        assert!(resolve(&golds, "w11-enterprise", "", "", "24H2").is_none());
        let mut server = g("s", "10.0.26100.33438");
        server.image_id = "ws2025-datacenter-core".into();
        assert_eq!(release(&server), None);
    }

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
