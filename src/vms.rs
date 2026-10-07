//! VMs from golds - Build-Vms.ps1's per-VM path, on PVE:
//!
//!   1. Linked clone of the gold (or a full copy), on the gold's node or - with shared
//!      storage - another one.
//!   2. Hardware: CPU, memory, a NIC with a pinned MAC on the chosen bridge/VLAN, data
//!      disks, start-at-boot.
//!   3. A seed ISO of its own: cloud-init user-data, meta-data and network-config.
//!   4. First boot provisions and powers off (the signal, as on Hyper-V); the seed is
//!      detached and deleted - it holds the password in clear.
//!   5. Started again, and its address read from the guest agent.

use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

use crate::{
    catalog,
    form,
    golds::{self, GoldRow},
    jobs::JobLog,
    linux::{self, VmSeed},
    pve::{enc, Pve},
    progress::{self, PackageCounter, Progress},
    windows,
    seed::{self, SeedDisk},
};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VmSpec {
    pub name: String,
    /// The design card this VM was built from - what ties a built VM to its card, not the name.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub card: String,
    pub gold: String,
    #[serde(default = "two")]
    pub cores: u32,
    #[serde(default = "two_gib")]
    pub memory_mb: u32,
    /// The system disk's size; never smaller than the gold's.
    pub disk_gb: Option<u32>,
    /// Linked clone (the Hyper-V studio's differencing disk) or a full copy.
    #[serde(default = "yes")]
    pub linked: bool,
    /// Where it runs; the gold's node when empty.
    #[serde(default)]
    pub node: String,
    /// Where a full copy's disks go; the gold's storage when empty.
    #[serde(default)]
    pub storage: String,
    pub bridge: String,
    pub vlan: Option<u16>,
    /// Empty = DHCP.
    #[serde(default)]
    pub ip: String,
    #[serde(default = "prefix24")]
    pub prefix: u8,
    #[serde(default)]
    pub gateway: String,
    #[serde(default)]
    pub dns: Vec<String>,
    #[serde(default)]
    pub search: String,
    pub user: String,
    #[serde(default, skip_serializing)]
    pub password: String,
    #[serde(default)]
    pub ssh_key: String,
    #[serde(default)]
    pub packages: Vec<String>,
    #[serde(default)]
    pub data_disks: Vec<DataDisk>,
    /// Adapters beyond the primary one - address only, no gateway or DNS.
    #[serde(default)]
    pub extra_nics: Vec<ExtraNic>,
    /// Nested virtualization: the guest sees the CPU's virtualization extensions - for
    /// VBS, Credential Guard, Hotpatch, or a hypervisor of its own (host or a named model).
    #[serde(default)]
    pub nested: bool,
    /// The CPU type; empty: "auto", settled against the nodes at deploy (hardware.rs).
    #[serde(default)]
    pub cpu_type: String,
    /// The vendor's security flags on a generic x86-64-vX type.
    #[serde(default = "yes")]
    pub security_flags: bool,
    /// "auto", "on", "off" (hardware::numa_for).
    #[serde(default)]
    pub numa: String,
    /// KSM may share this VM's memory pages.
    #[serde(default = "yes")]
    pub ksm: bool,
    /// One network queue per vCPU (8 at most) - servers only.
    #[serde(default)]
    pub queues: bool,
    /// PVE's protection flag once built.
    #[serde(default)]
    pub protection: bool,
    /// Windows Server 2025: VBS on at first boot and checked to run - ready for Hotpatch.
    #[serde(default)]
    pub hotpatch: bool,
    /// Seconds after the node's start before this VM starts (with onboot).
    #[serde(default)]
    pub startup_delay: u32,
    /// A TPM 2.0 for the VM (Windows 11 needs one; the client golds carry it already).
    #[serde(default)]
    pub vtpm: bool,
    /// The primary adapter's name in the guest.
    #[serde(default)]
    pub nic_name: String,
    /// Windows: roles and features, RSAT capabilities (client), the Server Core App
    /// Compatibility FoD - installed by GuestProvision at first boot.
    #[serde(default)]
    pub windows_features: Vec<String>,
    #[serde(default = "yes")]
    pub include_management_tools: bool,
    #[serde(default)]
    pub rsat: Vec<String>,
    #[serde(default)]
    pub app_compat: bool,
    /// Client optional features (Hyper-V Management Tools) - enabled by the deploy pass.
    #[serde(default)]
    pub client_features: Vec<String>,
    /// Built-in apps removed by the deploy pass (Windows 11 only), by package family.
    #[serde(default)]
    pub remove_apps: Vec<String>,
    /// The Features on Demand ISO for the capabilities above, when one is set for the family.
    #[serde(default)]
    pub fod: Option<crate::fod::FodPlan>,
    /// The PVE resource pool the VM joins (created when missing); "" = none.
    #[serde(default)]
    pub pool: String,
    /// PVE tags beside the studio's own pvs ones.
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub domain_join: Option<crate::guest::DomainJoin>,
    #[serde(default)]
    pub arc: Option<crate::guest::AzureArc>,
    #[serde(default = "yes")]
    pub start_after: bool,
    #[serde(default)]
    pub onboot: bool,
    /// Set by a lab deploy.
    #[serde(default)]
    pub lab: Option<String>,
    /// Windows: the product key the Windows licenses blade gives the VM's image, installed and
    /// activated at first boot (SetupComplete). Never stored with the record.
    #[serde(default, skip_serializing)]
    pub product_key: String,
    /// Windows with Desktop Experience: applications from WinGet, installed at first boot by
    /// GuestProvision as SYSTEM, machine-wide, always the newest version. A failure is
    /// reported, never fatal - the VM still comes up.
    #[serde(default)]
    pub winget_apps: Vec<WingetApp>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WingetApp {
    /// The WinGet package id (7zip.7zip).
    pub id: String,
    /// Installer switches passed with --override, as the app is listed in the design.
    #[serde(default)]
    pub over: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtraNic {
    /// The name the guest gives the adapter (Windows: GuestProvision renames by MAC).
    #[serde(default)]
    pub name: String,
    pub bridge: String,
    pub vlan: Option<u16>,
    /// Empty = DHCP.
    #[serde(default)]
    pub ip: String,
    #[serde(default = "prefix24")]
    pub prefix: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataDisk {
    pub size_gb: u32,
    #[serde(default)]
    pub storage: String,
    /// Windows: the drive letter, file system (NTFS, ReFS, None = leave raw) and label
    /// GuestProvision gives it at first boot.
    #[serde(default)]
    pub letter: String,
    #[serde(default)]
    pub file_system: String,
    #[serde(default)]
    pub label: String,
}

fn two() -> u32 {
    2
}
fn two_gib() -> u32 {
    2048
}
fn yes() -> bool {
    true
}
fn prefix24() -> u8 {
    24
}

impl VmSpec {
    /// The checks that need no cluster: the rest happen in the job.
    pub fn validate(&self) -> Result<()> {
        let n = &self.name;
        let ok = !n.is_empty()
            && n.len() <= 63
            && n.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
            && !n.starts_with('-')
            && !n.ends_with('-');
        if !ok {
            bail!("name '{n}': 1-63 characters, a-z 0-9 and -, not starting or ending with -");
        }
        if self.user.is_empty() || !self.user.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') {
            bail!("user name '{}' is not a valid Linux user name", self.user);
        }
        if matches!(self.user.as_str(), "root" | "bake") {
            bail!("user name '{}' is reserved", self.user);
        }
        if self.password.len() < 8 {
            bail!("the password needs at least 8 characters");
        }
        if !self.ip.is_empty() {
            self.ip.parse::<std::net::Ipv4Addr>().map_err(|_| anyhow!("'{}' is not an IPv4 address", self.ip))?;
            if !(8..=32).contains(&self.prefix) {
                bail!("prefix length must be 8-32");
            }
            if !self.gateway.is_empty() {
                self.gateway.parse::<std::net::Ipv4Addr>().map_err(|_| anyhow!("gateway '{}' is not an IPv4 address", self.gateway))?;
            }
        }
        for (i, n) in self.extra_nics.iter().enumerate() {
            if n.bridge.is_empty() {
                bail!("adapter {} has no bridge", i + 2);
            }
            if !n.ip.is_empty() {
                n.ip.parse::<std::net::Ipv4Addr>().map_err(|_| anyhow!("adapter {}: '{}' is not an IPv4 address", i + 2, n.ip))?;
            }
        }
        if self.cores == 0 || self.memory_mb < 512 {
            bail!("at least 1 core and 512 MiB");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct VmRow {
    pub id: String,
    pub name: String,
    pub lab_id: Option<String>,
    pub gold_id: String,
    pub node: String,
    pub vmid: Option<i64>,
    pub status: String,
    pub spec: String,
    pub ip: Option<String>,
    pub job_id: Option<String>,
    pub created_at: String,
}

pub async fn list(db: &SqlitePool) -> Result<Vec<VmRow>> {
    // Cleared VMs still exist in PVE (and still need their gold) - only the view drops them.
    // Gone ones were removed in PVE.
    Ok(sqlx::query_as("SELECT * FROM vms WHERE status NOT IN ('removed', 'cleared', 'gone') ORDER BY name").fetch_all(db).await?)
}

/// The same VM, not just the same number: a VMID is reused once its VM is gone (a record of a
/// removed vm-01 must not show the cis-01 that has its id now). The node is left out - a
/// migrated VM keeps its VMID and name.
pub fn is_same_vm(r: &crate::pve::Resource, name: &str, vmid: i64) -> bool {
    r.kind == "qemu" && r.vmid == Some(vmid as u32) && r.name.as_deref().is_some_and(|n| n.eq_ignore_ascii_case(name))
}

/// Built VMs that PVE no longer lists - removed in Proxmox VE - leave the studio's view as
/// 'gone': their card is free to be built again. `res` must be a full answer of
/// /cluster/resources (a VM on a node that is down is still listed there, as "unknown").
/// Returns the ids it marked.
pub async fn mark_gone(db: &SqlitePool, rows: &[VmRow], res: &[crate::pve::Resource]) -> Result<Vec<String>> {
    let mut gone = Vec::new();
    for v in rows.iter().filter(|v| v.status == "ready") {
        let Some(id) = v.vmid else { continue };
        if res.iter().any(|r| is_same_vm(r, &v.name, id)) {
            continue;
        }
        sqlx::query("UPDATE vms SET status = 'gone' WHERE id = ? AND status = 'ready'").bind(&v.id).execute(db).await?;
        tracing::info!("VM {} ({id} on {}) is gone from Proxmox VE - its card can be built again", v.name, v.node);
        gone.push(v.id.clone());
    }
    Ok(gone)
}

pub async fn get(db: &SqlitePool, id: &str) -> Result<Option<VmRow>> {
    Ok(sqlx::query_as("SELECT * FROM vms WHERE id = ?").bind(id).fetch_optional(db).await?)
}

/// A MAC in Proxmox's own OUI (BC:24:11), as PVE itself assigns them.
pub fn new_mac() -> String {
    let b = uuid::Uuid::new_v4();
    let r = b.as_bytes();
    format!("BC:24:11:{:02X}:{:02X}:{:02X}", r[0], r[1], r[2])
}

pub async fn deploy(pve: Pve, db: SqlitePool, work: std::path::PathBuf, log: JobLog, vm_id: String, spec: VmSpec) -> Result<()> {
    let mut made: Option<(String, u32)> = None;
    let result = deploy_inner(&pve, &db, &work, &log, &vm_id, &spec, &mut made).await;
    if result.is_err() {
        if let Some((node, vmid)) = made {
            match pve.vm_destroy(&node, vmid).await {
                Ok(()) => log.line(format!("Removed the half-built VM {vmid}")).await,
                Err(e) => log.warn(format!("Could not remove VM {vmid}: {e:#}")).await,
            }
        }
        let _ = sqlx::query("UPDATE vms SET status = 'failed' WHERE id = ?").bind(&vm_id).execute(&db).await;
    }
    result
}

#[allow(clippy::too_many_arguments)]
async fn deploy_inner(
    pve: &Pve,
    db: &SqlitePool,
    work: &std::path::Path,
    log: &JobLog,
    vm_id: &str,
    spec: &VmSpec,
    made: &mut Option<(String, u32)>,
) -> Result<()> {
    let gold: GoldRow = golds::get(db, &spec.gold).await?.ok_or_else(|| anyhow!("gold {} does not exist", spec.gold))?;
    if gold.status != "ready" {
        bail!("gold {} is {}, not ready", gold.name, gold.status);
    }
    let win = gold.os == "windows";
    let manifest: serde_json::Value = serde_json::from_str(&gold.manifest).unwrap_or_default();
    let img = if win {
        windows::check_name(&spec.name)?;
        None
    } else {
        Some(catalog::linux(&gold.image_id).ok_or_else(|| anyhow!("{} is not a known gold image", gold.image_id))?)
    };
    let image_name = img.map(|i| i.name.to_owned()).unwrap_or_else(|| manifest["name"].as_str().unwrap_or("Windows").to_owned());
    // The gold's own size (its sidecar), else the catalog's: a clone never shrinks.
    let gold_disk_gb = manifest["diskSizeGB"].as_u64().map(|g| g as u32).or(img.map(|i| i.disk_gb)).unwrap_or(64);
    let template = gold.vmid.ok_or_else(|| anyhow!("gold {} has no template", gold.name))? as u32;
    let node = if spec.node.is_empty() { gold.node.clone() } else { spec.node.clone() };

    // A clone to another node needs the gold on shared storage (PVE refuses otherwise).
    if node != gold.node {
        let shared = pve
            .resources()
            .await?
            .iter()
            .any(|r| r.kind == "storage" && r.storage.as_deref() == Some(&gold.storage) && r.shared == Some(1));
        if !shared {
            bail!("{} lives on {}'s local storage {} - it can only be cloned there", gold.name, gold.node, gold.storage);
        }
    }
    if pve.resources().await?.iter().any(|r| r.kind == "qemu" && r.name.as_deref() == Some(&spec.name)) {
        bail!("a VM named {} exists already", spec.name);
    }

    // ---- 1. clone ----
    let mut pr = Progress::new(log, format!("Building {}", spec.name));
    pr.stage(0.0, 20.0, "cloning the gold");
    log.run(format!(
        "{} clone of {} (template {template}) on {node}",
        if spec.linked { "Linked" } else { "Full" },
        gold.name
    ))
    .await;
    let guard = pve.vmid_guard().await;
    let vmid = pve.next_vmid().await?;
    let mut clone = form![("newid", vmid), ("name", &spec.name), ("full", u8::from(!spec.linked))];
    if node != gold.node {
        clone.push(("target".into(), node.clone()));
    }
    if !spec.linked && !spec.storage.is_empty() {
        clone.push(("storage".into(), spec.storage.clone()));
    }
    // The pool is how admins group VMs in PVE - the studio's grouping too.
    if !spec.pool.is_empty() {
        pve.ensure_pool(&spec.pool, "PVE VM Studio").await.with_context(|| format!("creating the pool {}", spec.pool))?;
        clone.push(("pool".into(), spec.pool.clone()));
    }
    let cloned = pve
        .run_task(&format!("/nodes/{}/qemu/{template}/clone", enc(&gold.node)), clone, |_| {})
        .await;
    drop(guard);
    if cloned.is_err() && pve.vm_status(&node, vmid).await.is_ok() {
        *made = Some((node.clone(), vmid));
    }
    cloned.context("cloning the gold")?;
    *made = Some((node.clone(), vmid));
    sqlx::query("UPDATE vms SET node = ?, vmid = ? WHERE id = ?").bind(&node).bind(vmid).bind(vm_id).execute(db).await?;
    log.ok(format!("VM {vmid} ({}) created", spec.name)).await;

    // ---- 2. hardware ----
    pr.stage(20.0, 30.0, "hardware");
    // Every adapter gets its MAC here, so the seed can match each one by it.
    let mac = new_mac();
    let mut net0 = format!("virtio={mac},bridge={}", spec.bridge);
    if let Some(v) = spec.vlan {
        net0 += &format!(",tag={v}");
    }
    // Servers: one queue per vCPU (8 at most) spreads the traffic over the cores. A Windows
    // client gains little from it.
    let client = manifest["installationType"].as_str() == Some("Client") || manifest["requiresTpm"].as_bool() == Some(true);
    let queues = if spec.queues && !client && spec.cores > 1 { spec.cores.min(8) } else { 0 };
    if queues > 1 {
        net0 += &format!(",queues={queues}");
    }
    let extra_macs: Vec<String> = spec.extra_nics.iter().map(|_| new_mac()).collect();
    // Its OS without a build (it updates), then the design's own tags.
    let os_tag = crate::tags::os(&gold.os, &gold.image_id, None);
    let mut tags = vec![os_tag.clone()];
    for t in &spec.tags {
        let t = crate::tags::clean(t);
        if !t.is_empty() && !tags.contains(&t) {
            tags.push(t);
        }
    }
    crate::tags::paint(pve, &[os_tag]).await;
    // No user and no address: the notes are readable by anyone who sees the VM.
    let notes = format!("## {}\n\nBuilt by PVE VM Studio from gold `{}` ({}).\n", spec.name, gold.name, image_name);
    // CPU type from the bake settings, so a gold baked under older defaults follows them too.
    // Balloon deleted, not 0: the device stays (PVE sees the guest's real memory use) with
    // its target at full memory, so nothing is ever taken back - static memory.
    let bake: crate::settings::BakeSettings = crate::settings::load(db, "bake").await?;
    // The CPU: "auto" settled against the nodes (host when they all have the same CPU),
    // its security flags on a generic type, nesting as the design says.
    let nodes = crate::hardware::cluster(pve).await.unwrap_or_default();
    let here = nodes.iter().find(|n| n.node == node);
    let (mut cpu_type, why) = if spec.cpu_type.is_empty() { crate::hardware::pick_cpu(&nodes) } else { (spec.cpu_type.clone(), "the design's".to_owned()) };
    // Windows on host stops KVM on a node that is itself a VM (PVE in Hyper-V).
    if win && cpu_type == "host" && here.is_some_and(|n| n.virtual_node) {
        cpu_type = bake.cpu_for(true);
    }
    let flags = if spec.security_flags { crate::hardware::security_flags(&nodes, &cpu_type) } else { vec![] };
    let generic = cpu_type.starts_with("x86-64-v");
    if spec.nested && generic {
        log.warn(format!("Nested virtualization needs host or a named CPU model - {cpu_type} has none to give")).await;
    }
    let cpu = crate::hardware::cpu_value(&cpu_type, spec.nested, &flags, crate::hardware::nested_flag(pve).await);
    let (numa, sockets) = crate::hardware::numa_for(&spec.numa, here, spec.cores, spec.memory_mb);
    log.line(format!(
        "CPU {cpu} ({why}){}{}",
        if numa { format!(", NUMA with {sockets} socket(s)") } else { String::new() },
        if queues > 1 { format!(", {queues} network queues") } else { String::new() }
    ))
    .await;
    let mut hw = form![
        ("cores", spec.cores / sockets),
        ("sockets", sockets),
        ("memory", spec.memory_mb),
        ("cpu", cpu),
        ("delete", "balloon"),
        ("net0", &net0),
        ("onboot", u8::from(spec.onboot)),
        ("tags", tags.join(";")),
        ("description", notes),
    ];
    if numa {
        hw.push(("numa".into(), "1".into()));
    }
    if !spec.ksm {
        hw.push(("allow-ksm".into(), "0".into()));
    }
    for (i, (n, m)) in spec.extra_nics.iter().zip(&extra_macs).enumerate() {
        let mut v = format!("virtio={m},bridge={}", n.bridge);
        if let Some(t) = n.vlan {
            v += &format!(",tag={t}");
        }
        hw.push((format!("net{}", i + 1), v));
    }
    pve.vm_set(&node, vmid, hw).await?;
    // PVE counts a start delay as host behaviour and wants Sys.Modify on / for it - more
    // than the studio's token has by design. Without it the VM is built anyway.
    if spec.onboot && spec.startup_delay > 0
        && let Err(e) = pve.vm_set(&node, vmid, form![("startup", format!("up={}", spec.startup_delay))]).await
    {
        if format!("{e:#}").contains("Sys.Modify") {
            log.warn(format!(
                "Start delay of {} s not set: PVE wants Sys.Modify on / for it, which the studio's token does not have - set it on the VM in PVE, or grant that right",
                spec.startup_delay
            ))
            .await;
        } else {
            return Err(e);
        }
    }
    if spec.nested || !spec.extra_nics.is_empty() || spec.startup_delay > 0 {
        log.run(format!(
            "{} adapter(s){}{}",
            1 + spec.extra_nics.len(),
            if spec.nested { ", nested virtualization (CPU type host)" } else { "" },
            String::new()
        ))
        .await;
    }
    // A TPM from the gold (golds baked before 2026-10-07 kept the bake's) is never reused:
    // swtpm creates its keys only on an empty volume, so a copied one is the gold's identity.
    if pve.vm_config(&node, vmid).await?.contains_key("tpmstate0") {
        pve.vm_set(&node, vmid, form![("delete", "tpmstate0"), ("force", 1)]).await?;
    }
    if spec.vtpm {
        let storage = if spec.storage.is_empty() { gold.storage.clone() } else { spec.storage.clone() };
        pve.vm_set_task(&node, vmid, form![("tpmstate0", format!("{storage}:1,version=v2.0"))], |_| {}).await?;
        log.run("TPM 2.0 added").await;
    }
    if let Some(gb) = spec.disk_gb.filter(|gb| *gb > gold_disk_gb) {
        pve.vm_resize(&node, vmid, "scsi0", &format!("{gb}G")).await?;
        log.run(format!("System disk grown to {gb} GiB")).await;
    }
    for (i, d) in spec.data_disks.iter().enumerate() {
        let storage = if d.storage.is_empty() { gold.storage.clone() } else { d.storage.clone() };
        let slot = format!("scsi{}", i + 1);
        pve.vm_set_task(
            &node,
            vmid,
            form![(slot.as_str(), format!("{storage}:{},discard=on,iothread=1,ssd=1", d.size_gb))],
            |_| {},
        )
        .await
        .with_context(|| format!("adding data disk {slot}"))?;
        log.run(format!("Data disk {slot}: {} GiB on {storage}", d.size_gb)).await;
    }

    // ---- Windows: the WinPE deploy pass, when WinPE can boot here ----
    let pass_media = if win { deploy_pass_media(pve, db, log, &node, &manifest).await? } else { None };

    // The join: in specialize when the answer file reaches it (the deploy pass writes it
    // into Panther), as the design asks; on the seed-CD path the VM's file only reaches
    // oobeSystem, so the join is deferred to GuestProvision's task.
    let join_mode = match &spec.domain_join {
        Some(d) if win && pass_media.is_some() && d.mode != "deferred" => "specialize",
        Some(d) if win => {
            if d.mode == "specialize" {
                log.line("The join is deferred to after first boot - without the WinPE deploy pass the answer file does not reach specialize").await;
            }
            "deferred"
        }
        _ => "deferred",
    };

    // Roles and features: offline in the deploy pass where Windows' own table knows them
    // (Install-WindowsFeature -Vhd on Hyper-V); GuestProvision keeps the full list - a
    // feature already installed is "no change needed" there, one that failed offline gets
    // its second chance online, and the guest-only ones are installed there for the first time.
    let feature_plan = if win && pass_media.is_some() && manifest["installationType"].as_str() != Some("Client") {
        let build = manifest["build"].as_str().unwrap_or("");
        windows::plan_server_features(&spec.windows_features, spec.include_management_tools, build)
    } else {
        windows::FeaturePlan { dism: vec![], online: spec.windows_features.clone(), groups: vec![] }
    };
    let (server_dism, server_online) = (feature_plan.dism.clone(), feature_plan.online.clone());
    if !server_dism.is_empty() {
        log.line(format!(
            "Roles and features offline as {} DISM feature(s){}",
            server_dism.len(),
            if server_online.is_empty() { String::new() } else { format!("; at first boot: {}", server_online.join(", ")) }
        ))
        .await;
    }
    // .NET 3.5's payload is not in the image; the gold's source ISO carries it (sources\sxs).
    let sxs_iso = if server_dism.iter().any(|d| d.starts_with("NetFx3")) {
        manifest["sourceMedia"].as_str().or_else(|| manifest["sourceIso"].as_str()).filter(|v| !v.is_empty()).map(str::to_owned)
    } else {
        None
    };

    // ---- 3. seed ----
    pr.stage(30.0, 35.0, "building the seed");
    let stamp = Utc::now().format("%Y%m%d%H%M%S").to_string();
    let seed_name = format!("pvs-seed-{}-{stamp}", spec.name);
    // The seed is a small disk (a FAT partition labelled CIDATA for cloud-init, PVSVM for
    // Windows), on the VM's own storage. Windows: sata2 beside the deploy pass's CDs, else
    // sata0. Linux: scsi30 (data disks count up from scsi1) - Debian 12's cloud kernel has no
    // AHCI driver and would not see a SATA seed.
    let slot = if !win { linux::SEED_SLOT } else if pass_media.is_some() { "sata2" } else { "sata0" };
    let seed_storage = if spec.storage.is_empty() { gold.storage.clone() } else { spec.storage.clone() };
    let seed_disk = if let Some(img) = img {
        let mut nics = vec![linux::NicCfg {
            mac: mac.clone(),
            address: spec.ip.clone(),
            prefix: spec.prefix,
            gateway: spec.gateway.clone(),
            dns: spec.dns.clone(),
            search: spec.search.clone(),
        }];
        for (n, m) in spec.extra_nics.iter().zip(&extra_macs) {
            nics.push(linux::NicCfg { mac: m.clone(), address: n.ip.clone(), prefix: n.prefix, gateway: String::new(), dns: vec![], search: String::new() });
        }
        let seed = VmSeed {
            hostname: spec.name.clone(),
            user: spec.user.clone(),
            password: spec.password.clone(),
            ssh_key: spec.ssh_key.clone(),
            packages: spec.packages.clone(),
            domain_join: spec.domain_join.clone(),
            arc: spec.arc.clone(),
            cis: manifest["cis"].is_object(),
        };
        let user_data = linux::vm_user_data(img, &seed);
        let meta_data = linux::vm_meta_data(&spec.name, &stamp);
        let net_cfg = linux::vm_network_config(&nics, seed.cis && img.family == "debian");
        let mut files = vec![("user-data", user_data.as_str()), ("meta-data", meta_data.as_str())];
        if let Some(n) = &net_cfg {
            files.push(("network-config", n.as_str()));
        }
        SeedDisk::build(work, &seed_name, "CIDATA", &files).await?
    } else {
        let ws = windows::WinVmSeed {
            name: spec.name.clone(),
            user: spec.user.clone(),
            password: spec.password.clone(),
            builtin_admin_only: false,
            client: manifest["installationType"].as_str() == Some("Client"),
            mac: mac.clone(),
            ip: spec.ip.clone(),
            prefix: spec.prefix,
            gateway: spec.gateway.clone(),
            dns: spec.dns.clone(),
            extra: spec.extra_nics.iter().zip(&extra_macs).filter(|(n, _)| !n.ip.is_empty()).map(|(n, m)| (m.clone(), n.ip.clone(), n.prefix)).collect(),
            manifest: guest_manifest(spec, &mac, &extra_macs, join_mode),
            arc_secret: spec.arc.as_ref().filter(|a| !a.secret.is_empty()).map(|a| {
                serde_json::json!({ "servicePrincipalAppId": a.app_id, "servicePrincipalSecret": a.secret })
            }),
            // The sealed credential and DomainJoin.ps1 only for a deferred join (Build-Vms);
            // a specialize join carries its credential in the answer file, which Setup
            // scrubs once it is used.
            join_secret: spec.domain_join.as_ref().filter(|_| join_mode == "deferred").map(|d| {
                serde_json::json!({ "domain": d.domain, "ouPath": d.ou, "joinUser": d.user, "joinPassword": d.password })
            }),
            specialize: pass_media.is_some(),
            join_specialize: spec.domain_join.clone().filter(|_| join_mode == "specialize"),
            product_key: spec.product_key.clone(),
        };
        let unattend = windows::vm_unattend(&ws, &manifest);
        let vmcmd = windows::vm_cmd(&ws);
        let complete = windows::setupcomplete_cmd(&ws);
        let mut files: Vec<(&str, String)> = vec![
            ("pvs-vm/unattend.xml", unattend),
            ("pvs-vm/vm.cmd", vmcmd),
            ("pvs-vm/setupcomplete.cmd", complete),
        ];
        // The GuestProvision payload, laid out as Build-Vms laid it out in the VHDX -
        // firstboot.cmd copies it next to SetupComplete.cmd. JSON without a BOM (serde
        // writes none): a BOM breaks the consumers.
        if windows::needs_guest(&ws.manifest) {
            files.push(("pvs-vm/GuestProvision/GuestProvision.ps1", windows::GUEST_PROVISION_PS1.to_owned()));
            if pass_media.is_some() {
                // What GuestProvision still has to do once the deploy pass has done its part:
                // features it cannot stage offline, and capabilities only when there is no
                // FoD ISO to install them from. The full lists ride along as the fallback the
                // pass switches in when anything failed offline.
                let mut online = ws.manifest.clone();
                online["pendingWindowsFeatures"] = serde_json::json!(server_online);
                if spec.fod.is_some() {
                    online["pendingCapabilities"] = serde_json::json!([]);
                    online["pendingRsatCapabilities"] = serde_json::json!([]);
                }
                files.push(("pvs-vm/GuestProvision/manifest.json", serde_json::to_string_pretty(&online)?));
                files.push(("pvs-vm/GuestProvision/manifest-fallback.json", serde_json::to_string_pretty(&ws.manifest)?));
            } else {
                files.push(("pvs-vm/GuestProvision/manifest.json", serde_json::to_string_pretty(&ws.manifest)?));
            }
            if let Some(a) = &ws.arc_secret {
                files.push(("pvs-vm/GuestProvision/arc-deploy.json", a.to_string()));
            }
            if let Some(j) = &ws.join_secret {
                files.push(("pvs-vm/GuestProvision/DomainJoin.ps1", windows::DOMAIN_JOIN_PS1.to_owned()));
                files.push(("pvs-vm/GuestProvision/domain-join.json", j.to_string()));
            }
        }
        if pass_media.is_some() {
            let mut caps = spec.rsat.clone();
            if spec.app_compat {
                caps.push("ServerCore.AppCompatibility~~~~0.0.1.0".into());
            }
            let fod = spec.fod.as_ref();
            files.push((
                "pvs/pe.cmd",
                windows::pe_deploy_cmd(&windows::DeployPass {
                    capabilities: &caps,
                    fod_root: fod.map(|f| f.root.as_str()).unwrap_or(""),
                    fod_marker: fod.map(|f| f.marker.as_str()).unwrap_or(""),
                    client_features: if ws.client { &spec.client_features } else { &[] },
                    server_features: &server_dism,
                    remove_apps: if ws.client { &spec.remove_apps } else { &[] },
                }),
            ));
        }
        let refs: Vec<(&str, &str)> = files.iter().map(|(n, c)| (*n, c.as_str())).collect();
        SeedDisk::build(work, &seed_name, "PVSVM", &refs).await?
    };
    seed::attach(pve, &node, vmid, slot, &seed_storage, seed_disk, &seed_name).await.context("attaching the seed disk")?;
    log.ok(format!("Seed attached as a disk ({slot})")).await;
    // ---- 4. first boot ----
    if let (true, Some((winpe, virtio))) = (win, &pass_media) {
        // Build-Vms serviced the VHDX offline before the first boot; WinPE does it here: the
        // VM boots it once, it services the disk and writes the answer file and
        // GuestProvision in, and powers off. Every CD then goes while the VM is off - no
        // drive is left behind and no shutdown is needed just to unplug one.
        let mut drives = vec![("sata0", winpe.clone())];
        if let Some(v) = virtio {
            drives.push(("sata1", v.clone()));
        }
        if let Some(f) = &spec.fod {
            drives.push(("sata3", f.volid.clone()));
            log.run(format!("Features on Demand from {}", f.volid)).await;
        }
        if let Some(src) = &sxs_iso {
            drives.push(("sata4", src.clone()));
            log.run(format!(".NET 3.5 payload from {src}")).await;
        }
        let set: crate::pve::Form = drives.iter().map(|(k, v)| ((*k).to_owned(), format!("{v},media=cdrom"))).collect();
        pve.vm_set(&node, vmid, set).await?;
        windows::set_boot(pve, &node, vmid, "sata0").await?;
        log.run("WinPE deploy pass: capabilities, features, app removal, the VM's answer file and GuestProvision").await;
        pr.stage(35.0, 50.0, "WinPE deploy pass");
        let m = windows::run_pass(pve, log, &mut pr, &node, vmid, "deploy pass", 30, &[]).await?;
        let count = |p: &str| m.iter().filter(|l| l.starts_with(p)).count();
        for l in m.iter().filter(|l| l.starts_with("PVS-CAP-FAIL") || l.starts_with("PVS-FEATURE-FAIL") || l.starts_with("PVS-APP-FAIL")) {
            log.warn(format!("{} - see the debug lines above", crate::markers::text(l))).await;
        }
        if !m.iter().any(|l| l == "PVS-DEPLOY-OK") {
            let why = m.iter().rev().find(|l| l.starts_with("PVS-NO-") || l.ends_with("FAILED")).cloned();
            bail!("the deploy pass failed: {}", why.or_else(|| m.last().cloned()).map(|l| crate::markers::text(&l)).unwrap_or_else(|| "nothing on the serial console".into()));
        }
        // As Hyper-V's log names them: per Server Manager feature, per capability, apps summed.
        let ok = |p: &str, name: &str| m.iter().any(|l| l.strip_prefix(p).is_some_and(|r| r.trim() == name));
        for (feature, dism) in &feature_plan.groups {
            let failed: Vec<&String> = dism.iter().filter(|d| !ok("PVS-FEATURE-OK", d)).collect();
            if dism.is_empty() {
                log.ok(format!("{feature}: came with the features above")).await;
            } else if failed.is_empty() {
                log.ok(format!("{feature}: {} DISM feature{} enabled offline", dism.len(), if dism.len() == 1 { "" } else { "s" })).await;
            } else {
                log.warn(format!(
                    "{feature}: {} of {} DISM features enabled offline - not {} (GuestProvision installs it online)",
                    dism.len() - failed.len(),
                    dism.len(),
                    failed.iter().map(|f| f.as_str()).collect::<Vec<_>>().join(", ")
                ))
                .await;
            }
        }
        for c in m.iter().filter_map(|l| l.strip_prefix("PVS-CAP-OK ")) {
            log.ok(format!("{} installed offline", c.trim())).await;
        }
        for c in m.iter().filter_map(|l| l.strip_prefix("PVS-CAP-SKIP ")) {
            log.line(format!("{} - no FoD ISO for this family, GuestProvision installs it online", c.trim())).await;
        }
        for f in spec.client_features.iter().filter(|f| ok("PVS-FEATURE-OK", f)) {
            log.ok(format!("{f} enabled offline")).await;
        }
        if count("PVS-APP-REMOVED") > 0 {
            log.ok(format!("{} built-in app(s) removed offline", count("PVS-APP-REMOVED"))).await;
        }
        if m.iter().any(|l| l == "PVS-FALLBACK") {
            log.warn("Something failed offline - GuestProvision gets the full lists and installs the rest at first boot").await;
        }
        log.ok("Deploy pass done").await;
        let names: Vec<&str> = drives.iter().map(|(k, _)| *k).collect();
        pve.vm_set(&node, vmid, form![("delete", names.join(","))]).await?;
        seed::detach(pve, &node, vmid, slot).await?;
        log.ok("CDs removed, the seed disk deleted").await;
        windows::set_boot(pve, &node, vmid, "scsi0").await?;

        pve.vm_action(&node, vmid, "start").await?;
        pr.stage(50.0, 90.0, "first boot");
        log.run("First boot: specialize names the VM, OOBE takes its answer file").await;
        windows::follow_first_boot(pve, log, &mut pr, &node, vmid).await?;
        if m.iter().any(|l| l.contains("-FAIL ")) {
            deploy_pass_dism_errors(pve, log, &node, vmid).await;
        }
        if guest_provision_result(pve, db, log, vm_id, &node, vmid).await? {
            pr.stage(90.0, 93.0, "restarting");
            log.run("Restarting - a role asked for it").await;
            pve.run_task(
                &format!("/nodes/{}/qemu/{vmid}/status/shutdown", crate::pve::enc(&node)),
                form![("timeout", "300"), ("forceStop", "1")],
                |_| {},
            )
            .await
            .context("shutting the VM down")?;
            pve.vm_action(&node, vmid, "start").await?;
        }
    } else if win {
        pve.vm_action(&node, vmid, "start").await?;
        pr.stage(35.0, 90.0, "first boot");
        log.run("First boot: specialize names the VM, OOBE takes the VM's answer file").await;
        windows::follow_first_boot(pve, log, &mut pr, &node, vmid).await?;
        let restart = guest_provision_result(pve, db, log, vm_id, &node, vmid).await?;
        // [diff] Hyper-V's VMs never had a seed drive: everything went into the VHDX. Here the
        // seed rides in on a SATA disk, which cannot be unplugged from a running VM - so
        // one clean shutdown, the drive goes, and the VM starts again. A role that asked for
        // a restart (GuestProvision's restartNeeded) gets it from the same stop.
        pr.stage(90.0, 93.0, "removing the seed drive");
        log.run(if restart {
            "Shutting down to remove the seed drive - also the restart a role asked for"
        } else {
            "Shutting down to remove the seed drive"
        })
        .await;
        pve.run_task(
            &format!("/nodes/{}/qemu/{vmid}/status/shutdown", crate::pve::enc(&node)),
            form![("timeout", "300"), ("forceStop", "1")],
            |_| {},
        )
        .await
        .context("shutting the VM down")?;
        seed::detach(pve, &node, vmid, slot).await?;
        log.ok("Seed disk removed and deleted").await;
        pve.vm_action(&node, vmid, "start").await?;
    } else {
        pve.vm_action(&node, vmid, "start").await?;
        pr.stage(35.0, 90.0, "first boot");
        log.run("First boot: cloud-init provisions, then powers off").await;
        follow_first_boot(pve, log, &mut pr, &node, vmid, 20).await?;
        pr.stage(90.0, 93.0, "removing the seed");
        seed::detach(pve, &node, vmid, slot).await?;
        log.ok("Seed disk removed and deleted").await;
    }

    // ---- 5. running ----
    let mut ip = spec.ip.clone();
    if win || spec.start_after {
        pr.stage(93.0, 100.0, "waiting for an address");
        if !win {
            pve.vm_action(&node, vmid, "start").await?;
        }
        let started = Instant::now();
        while started.elapsed() < Duration::from_secs(180) {
            if let Some(a) = pve.agent_ipv4(&node, vmid).await.into_iter().next() {
                ip = a;
                break;
            }
            tokio::time::sleep(Duration::from_secs(3)).await;
        }
        if ip.is_empty() {
            log.warn("Running, but the guest agent reported no address yet").await;
        }
    }
    if spec.hotpatch && win {
        hotpatch_check(pve, db, log, vm_id, &node, vmid, &gold.image_id).await;
    }
    // Built: PVE refuses to remove it, or its disks, until protection is taken off.
    if spec.protection {
        if let Err(e) = pve.vm_set(&node, vmid, form![("protection", 1)]).await {
            log.warn(format!("Protection not set: {e:#}")).await;
        }
    }
    sqlx::query("UPDATE vms SET status = 'ready', ip = ? WHERE id = ?").bind(&ip).bind(vm_id).execute(db).await?;
    *made = None;
    log.ok(format!(
        "{} is ready{}{}",
        spec.name,
        if ip.is_empty() { String::new() } else { format!(" at {ip}") },
        if spec.start_after { "" } else { " (left off)" }
    ))
    .await;
    Ok(())
}

/// Follows cloud-init's log through the agent until the VM powers itself off. The bar
/// moves with cloud-init's four stages, and inside the last with the package counters
/// when the VM installs packages.
async fn follow_first_boot(pve: &Pve, log: &JobLog, pr: &mut Progress, node: &str, vmid: u32, timeout_min: u64) -> Result<()> {
    let started = Instant::now();
    let mut offset = 0u64;
    let mut stage = 0u8;
    let mut packages = PackageCounter::default();
    let mut refused: Option<String> = None;
    loop {
        log.check_abort()?;
        let s = pve.vm_status(node, vmid).await?;
        if s.status == "stopped" {
            // A CIS gold's password policy refused the design's password: the account has none.
            if let Some(why) = refused {
                bail!("the gold's password policy refused the admin password ({why}) - pick one that meets it (14 characters, 3 kinds, no runs) and deploy again");
            }
            return Ok(());
        }
        if started.elapsed() > Duration::from_secs(timeout_min * 60) {
            bail!("first boot did not finish within {timeout_min} minutes (see the console of VM {vmid})");
        }
        if let Some((chunk, n)) = pve.agent_read(node, vmid, "/var/log/cloud-init-output.log", offset).await {
            offset += n;
            for l in chunk.lines().map(str::trim_end).filter(|l| !l.is_empty()) {
                if let Some(why) = l.strip_prefix("PASSWORD-FAILED") {
                    log.warn(format!("The admin password was refused:{why}")).await;
                    refused = Some(why.trim().to_owned());
                    continue;
                }
                if l == "PASSWORD-SET" {
                    log.ok("Admin password set through PAM").await;
                    continue;
                }
                // The join and Arc steps report with markers; those are worth a tag of their own.
                let marker = ["DOMAIN-", "ARC-", "SUDO-", "MKHOMEDIR-", "NSS-SSS-", "TIME-SYNC"].iter().any(|m| l.starts_with(m));
                if marker && (l.contains("FAILED") || l.contains("UNRESOLVED") || l.contains("NOT-INSTALLED") || l.contains("MISSING")) {
                    log.warn(l).await;
                } else if marker {
                    log.ok(l).await;
                } else {
                    log.debug(format!("| {l}")).await;
                }
                if let Some(st) = progress::cloud_init_stage(l)
                    && st > stage
                {
                    stage = st;
                    // Stages 1-3 take a quarter of the bar each; the final one (packages,
                    // runcmd, power off) the last quarter.
                    pr.within(f64::from(st - 1) / 4.0, format!("cloud-init stage {st} of 4"));
                }
                if stage == 4 && packages.line(l)
                    && let Some(f) = packages.fraction()
                {
                    pr.within(0.75 + 0.25 * f, packages.summary());
                }
                if l.contains("SEED-SCRUBBED") {
                    pr.within(0.95, "powering off");
                }
            }
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
}

/// An ISO storage on the node: `local` when it holds ISOs, otherwise the first that does.
pub async fn iso_storage_on(pve: &Pve, node: &str) -> Result<String> {
    let res = pve.resources().await?;
    let mut fit: Vec<_> = res
        .iter()
        .filter(|r| r.kind == "storage" && r.node.as_deref() == Some(node) && r.has_content("iso") && r.status.as_deref() == Some("available"))
        .filter_map(|r| r.storage.clone())
        .collect();
    fit.sort_by_key(|s| s != "local");
    fit.into_iter().next().ok_or_else(|| anyhow!("no storage on {node} holds ISOs"))
}


/// GuestProvision's manifest.json for a Windows VM - the fields Build-Vms'
/// Set-OfflineGuestProvisionPayload writes. Everything lands online at first boot here:
/// the studio cannot service the disk offline.
fn guest_manifest(spec: &VmSpec, mac: &str, extra_macs: &[String], join_mode: &str) -> serde_json::Value {
    let letter = |i: usize| ((b'd' + i as u8) as char).to_string();
    let data_disks: Vec<serde_json::Value> = spec
        .data_disks
        .iter()
        .enumerate()
        .filter(|(_, d)| !d.file_system.eq_ignore_ascii_case("none"))
        .map(|(i, d)| {
            let l = if d.letter.trim().is_empty() { letter(i) } else { d.letter.trim().trim_end_matches(':').to_lowercase() };
            let fs = if d.file_system.eq_ignore_ascii_case("refs") { "ReFS" } else { "NTFS" };
            let label = if d.label.trim().is_empty() { format!("Data {}", l.to_uppercase()) } else { d.label.trim().to_owned() };
            // scsiN is on LUN N (PVE numbers the LUN after the slot, virtio-scsi-single too).
            serde_json::json!({ "scsiLocation": i + 1, "sizeGB": d.size_gb, "letter": l, "fileSystem": fs, "label": label })
        })
        .collect();
    // As PVE names the VM's network devices: net0 is the primary, net1 the first extra.
    let auto = |i: usize| format!("net{i}");
    let mut nics = vec![serde_json::json!({
        "name": if spec.nic_name.trim().is_empty() { auto(0) } else { spec.nic_name.trim().to_owned() },
        "macAddress": mac.replace(':', "-").to_uppercase(),
    })];
    for (i, (n, m)) in spec.extra_nics.iter().zip(extra_macs).enumerate() {
        nics.push(serde_json::json!({
            "name": if n.name.trim().is_empty() { auto(i + 1) } else { n.name.trim().to_owned() },
            "macAddress": m.replace(':', "-").to_uppercase(),
        }));
    }
    serde_json::json!({
        "pendingWindowsFeatures": spec.windows_features,
        "pendingRsatCapabilities": spec.rsat,
        "pendingCapabilities": if spec.app_compat { vec!["ServerCore.AppCompatibility~~~~0.0.1.0"] } else { vec![] },
        "includeManagementTools": spec.include_management_tools,
        "sharedDiskCount": 0,
        "networkAdapters": nics,
        "dataDisks": data_disks,
        // "specialize": the answer file joined (the deploy pass wrote it into Panther);
        // "deferred": GuestProvision registers the join task (research §7).
        "domainJoin": spec.domain_join.as_ref().map(|d| serde_json::json!({ "enabled": true, "mode": join_mode, "domain": d.domain, "ouPath": d.ou })),
        "wingetApps": spec.winget_apps.iter().map(|a| serde_json::json!({ "id": a.id, "override": a.over })).collect::<Vec<_>>(),
        "hotpatchReady": spec.hotpatch,
        "azureArc": spec.arc.as_ref().map(|a| serde_json::json!({
            "enabled": true, "authMode": a.auth_mode, "subscriptionId": a.subscription_id, "tenantId": a.tenant_id,
            "resourceGroup": a.resource_group, "location": a.location, "servicePrincipalAppId": a.app_id,
        })),
    })
}

/// What GuestProvision reported (C:\ProgramData\VmDeployLogs\state.json), read through the
/// agent. It never reboots itself - a reboot inside SetupComplete leaves Windows in a bad
/// state - so when it asks for one, the studio restarts the VM from outside (§6).
/// Returns whether it asked for a restart; the caller gives it one.
async fn guest_provision_result(pve: &Pve, db: &SqlitePool, log: &JobLog, vm_id: &str, node: &str, vmid: u32) -> Result<bool> {
    let Some((text, _)) = pve.agent_read(node, vmid, r"C:\ProgramData\VmDeployLogs\state.json", 0).await else {
        return Ok(false); // nothing for GuestProvision to do on this VM
    };
    let text = text.trim_start_matches('\u{feff}');
    let st: serde_json::Value = serde_json::from_str(text).unwrap_or_default();
    let list = |k: &str| st[k].as_array().map(|a| a.len()).unwrap_or(0);
    if st["success"].as_bool() == Some(true) {
        log.ok(format!(
            "GuestProvision: {} feature(s), {} RSAT, {} capability(ies), {} data disk(s), {} adapter(s){}{}",
            list("featuresOnline"),
            list("rsatOnline"),
            list("capabilitiesOnline"),
            list("dataDisks"),
            list("networkAdapters"),
            if st["arc"]["attempted"].as_bool() == Some(true) { ", Azure Arc" } else { "" },
            if st["domainJoin"].is_object() { ", domain join registered (runs in 5 minutes, then reboots)" } else { "" },
        ))
        .await;
        for d in st["dataDisks"].as_array().into_iter().flatten().filter(|d| d["success"].as_bool() == Some(false)) {
            log.warn(format!(
                "Data disk {}: was not provisioned - see C:\\ProgramData\\VmDeployLogs in the VM",
                d["letter"].as_str().unwrap_or("?")
            ))
            .await;
        }
    } else {
        log.warn("GuestProvision reported a failure - see C:\\ProgramData\\VmDeployLogs in the VM").await;
    }
    // Applications from WinGet: each one in the log, a failure as a warning only - and the
    // results onto the VM's record, where Connect and the mail read them.
    if let Some(apps) = st["wingetApps"].as_array().filter(|a| !a.is_empty()) {
        let ok = apps.iter().filter(|a| a["success"].as_bool() == Some(true)).count();
        log.line(format!("WinGet: {ok} of {} application(s) installed", apps.len())).await;
        for a in apps {
            let id = a["id"].as_str().unwrap_or("?");
            if a["success"].as_bool() == Some(true) {
                log.ok(format!("{id} {}", a["version"].as_str().unwrap_or(""))).await;
            } else {
                log.warn(format!("{id} was not installed: {} - C:\\ProgramData\\VmDeployLogs\\winget in the VM", a["message"].as_str().unwrap_or("failed"))).await;
            }
        }
        if let Ok(Some(row)) = get(db, vm_id).await {
            let mut spec: serde_json::Value = serde_json::from_str(&row.spec).unwrap_or_default();
            spec["winget_result"] = serde_json::Value::Array(apps.clone());
            let _ = sqlx::query("UPDATE vms SET spec = ? WHERE id = ?").bind(spec.to_string()).bind(vm_id).execute(db).await;
        }
    }
    Ok(st["restartNeeded"].as_bool() == Some(true))
}

/// Hotpatch ready: after the restart, VBS must run (Win32_DeviceGuard status 2) - what
/// Azure's Hotpatch enrolment checks first. The answer goes onto the VM's record (the card's
/// status line). A VM that is not ready is still built: the job warns.
async fn hotpatch_check(pve: &Pve, db: &SqlitePool, log: &JobLog, vm_id: &str, node: &str, vmid: u32, image: &str) {
    let ps = "$d = Get-CimInstance -Namespace root\\Microsoft\\Windows\\DeviceGuard -ClassName Win32_DeviceGuard; $o = Get-CimInstance Win32_OperatingSystem; \"$($d.VirtualizationBasedSecurityStatus)|$($d.SecurityServicesRunning -join ',')|$($o.Version).$((Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion').UBR)\"";
    let mut answer = None;
    // The agent is up before Windows has every service going: a few tries.
    for _ in 0..12 {
        if let Ok((0, out)) = pve.agent_exec(node, vmid, &["powershell", "-NoProfile", "-Command", ps]).await
            && let Some(line) = out.lines().map(str::trim).find(|l| l.contains('|'))
        {
            answer = Some(line.to_owned());
            if line.starts_with('2') {
                break;
            }
        }
        tokio::time::sleep(Duration::from_secs(10)).await;
    }
    let (vbs, running, build) = match answer.as_deref().map(|a| a.split('|').collect::<Vec<_>>()) {
        Some(p) if p.len() == 3 => (p[0].parse::<u8>().unwrap_or(0), p[1].to_owned(), p[2].trim_start_matches("10.0.").to_owned()),
        _ => (0, String::new(), String::new()),
    };
    let ready = vbs == 2;
    if ready {
        log.ok(format!("Hotpatch ready: VBS running, build {build} - switch Hotpatch on for it in Azure")).await;
    } else {
        log.warn(format!(
            "Not Hotpatch ready: VBS {} - {}",
            match vbs { 1 => "configured, not running", 0 => "off", _ => "unknown" },
            if image.starts_with("ws2025-") { "the CPU type needs nested virtualization (host or a named model)" } else { "Hotpatch needs Windows Server 2025" }
        ))
        .await;
    }
    if let Ok(Some(row)) = get(db, vm_id).await {
        let mut spec: serde_json::Value = serde_json::from_str(&row.spec).unwrap_or_default();
        spec["hotpatch_result"] = serde_json::json!({ "ready": ready, "vbs": vbs, "running": running, "build": build, "checked": chrono::Utc::now().to_rfc3339() });
        let _ = sqlx::query("UPDATE vms SET spec = ? WHERE id = ?").bind(spec.to_string()).bind(vm_id).execute(db).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec() -> VmSpec {
        serde_json::from_value(serde_json::json!({
            "name": "dc-01", "gold": "g", "bridge": "vmbr0", "user": "admin", "password": "Passw0rd!Passw0rd",
            "nic_name": "LAN", "extra_nics": [{ "bridge": "vmbr1", "vlan": null, "name": "" }],
            "data_disks": [{ "size_gb": 20, "letter": "", "file_system": "NTFS", "label": "" }, { "size_gb": 5, "file_system": "None" }],
            "windows_features": ["AD-Domain-Services"], "app_compat": true,
        }))
        .unwrap()
    }

    #[test]
    fn manifest_like_build_vms() {
        let m = guest_manifest(&spec(), "BC:24:11:AA:BB:CC", &["BC:24:11:00:00:01".into()], "deferred");
        assert_eq!(m["pendingWindowsFeatures"][0], "AD-Domain-Services");
        assert_eq!(m["pendingCapabilities"][0], "ServerCore.AppCompatibility~~~~0.0.1.0");
        assert_eq!(m["networkAdapters"][0]["name"], "LAN");
        assert_eq!(m["networkAdapters"][0]["macAddress"], "BC-24-11-AA-BB-CC");
        assert_eq!(m["networkAdapters"][1]["name"], "net1");
        // The raw disk stays out; the first data disk is scsi1 = LUN 1, drive D:.
        assert_eq!(m["dataDisks"].as_array().unwrap().len(), 1);
        assert_eq!(m["dataDisks"][0]["scsiLocation"], 1);
        assert_eq!(m["dataDisks"][0]["letter"], "d");
        assert_eq!(m["dataDisks"][0]["label"], "Data D");
        assert!(m["domainJoin"].is_null() && m["azureArc"].is_null());
        assert!(crate::windows::needs_guest(&m));
    }
}

/// The WinPE ISO the deploy pass boots, and the virtio-win ISO when that WinPE does not carry
/// vioscsi itself (built before it did) - or None, and the VM takes the seed-CD path: no
/// WinPE yet, or one on a node-local storage of another node.
async fn deploy_pass_media(pve: &Pve, db: &SqlitePool, log: &JobLog, node: &str, manifest: &serde_json::Value) -> Result<Option<(String, Option<String>)>> {
    let pe: crate::winpe::WinPe = crate::settings::load(db, "winpe").await?;
    if pe.volid.is_empty() {
        log.line("No WinPE built yet (Media) - capabilities, features and app removal wait for the guest, the seed CD carries the answer file").await;
        return Ok(None);
    }
    if pe.node != node {
        let storage = pe.volid.split(':').next().unwrap_or("");
        let shared = pve.resources().await?.iter().any(|r| r.kind == "storage" && r.storage.as_deref() == Some(storage) && r.shared == Some(1));
        if !shared {
            log.warn(format!("WinPE lives on {}'s local storage {storage} - this VM runs on {node}, so it takes the seed-CD path", pe.node)).await;
            return Ok(None);
        }
    }
    if !pe.vioscsi.is_empty() {
        return Ok(Some((pe.volid, None)));
    }
    log.line("This WinPE was built without vioscsi - the virtio ISO rides along (rebuild WinPE under Media to drop it)").await;
    let win: crate::virtio::WindowsSettings = crate::settings::load(db, "windows").await?;
    let release = match manifest["virtio"].as_str().filter(|r| !r.is_empty()) {
        Some(r) => r.to_owned(),
        None => crate::virtio::resolve(&win.virtio).await?,
    };
    let storage = if win.iso_storage.is_empty() { iso_storage_on(pve, node).await? } else { win.iso_storage.clone() };
    let virtio = crate::virtio::fetch(pve, log, node, &storage, &release).await?;
    Ok(Some((pe.volid, Some(virtio))))
}

/// The deploy pass's DISM log, copied onto the disk by WinPE, read back once the guest agent
/// answers: the errors in it say why a capability or feature failed offline (the serial
/// console only carries DISM's one-line summary).
async fn deploy_pass_dism_errors(pve: &Pve, log: &JobLog, node: &str, vmid: u32) {
    let file = r"C:\Windows\Temp\pvs-deploy-dism.log";
    let (mut offset, mut errors) = (0u64, Vec::new());
    while let Some((text, n)) = pve.agent_read(node, vmid, file, offset).await {
        errors.extend(text.lines().filter(|l| l.contains(", Error")).map(|l| l.trim().to_owned()));
        offset += n;
        if n < 1 << 20 {
            break;
        }
    }
    if errors.is_empty() {
        log.line(format!("No DISM errors in {file} (or the guest agent could not read it)")).await;
        return;
    }
    log.warn(format!("Offline servicing failures - the last DISM errors from {file}:")).await;
    let skip = errors.len().saturating_sub(15);
    for e in errors.into_iter().skip(skip) {
        log.warn(e).await;
    }
}
