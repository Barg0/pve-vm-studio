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
    seed::SeedIso,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmSpec {
    pub name: String,
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
    /// Nested virtualization: the guest sees the CPU's virtualization extensions (CPU
    /// type host) - for a guest that runs Hyper-V or KVM itself.
    #[serde(default)]
    pub nested: bool,
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
    Ok(sqlx::query_as("SELECT * FROM vms WHERE status != 'removed' ORDER BY name").fetch_all(db).await?)
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
    let mut seed_vol: Option<(String, String)> = None;
    let result = deploy_inner(&pve, &db, &work, &log, &vm_id, &spec, &mut made, &mut seed_vol).await;
    if result.is_err() {
        if let Some((node, volid)) = seed_vol {
            let _ = pve.delete_volume(&node, &volid).await;
        }
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
    seed_vol: &mut Option<(String, String)>,
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
    let gold_disk_gb = img.map(|i| i.disk_gb).unwrap_or(64);
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
    let extra_macs: Vec<String> = spec.extra_nics.iter().map(|_| new_mac()).collect();
    let mut tags = vec!["pvs".to_owned(), "pvs-vm".to_owned(), format!("pvs-img-{}", gold.image_id)];
    if let Some(lab) = &spec.lab {
        tags.push(format!("pvs-lab-{}", lab.to_lowercase().replace(|c: char| !c.is_ascii_alphanumeric(), "-")));
    }
    let notes = format!(
        "## {}\n\nBuilt by PVE VM Studio from gold `{}` ({}).\n\n| | |\n|---|---|\n| User | `{}` |\n| Address | {} |\n",
        spec.name,
        gold.name,
        image_name,
        spec.user,
        if spec.ip.is_empty() { "DHCP".into() } else { format!("`{}/{}`", spec.ip, spec.prefix) },
    );
    let mut hw = form![
        ("cores", spec.cores),
        ("memory", spec.memory_mb),
        ("balloon", 0),
        ("net0", &net0),
        ("onboot", u8::from(spec.onboot)),
        ("tags", tags.join(";")),
        ("description", notes),
    ];
    for (i, (n, m)) in spec.extra_nics.iter().zip(&extra_macs).enumerate() {
        let mut v = format!("virtio={m},bridge={}", n.bridge);
        if let Some(t) = n.vlan {
            v += &format!(",tag={t}");
        }
        hw.push((format!("net{}", i + 1), v));
    }
    if spec.nested {
        hw.push(("cpu".into(), "host".into()));
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
    if spec.vtpm && !pve.vm_config(&node, vmid).await?.contains_key("tpmstate0") {
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

    // ---- 3. seed ----
    pr.stage(30.0, 35.0, "building the seed");
    let stamp = Utc::now().format("%Y%m%d%H%M%S").to_string();
    let iso_storage = iso_storage_on(pve, &node).await?;
    let seed_name = format!("pvs-seed-{}-{stamp}", spec.name);
    // The CD slot: ide2 on Linux (cloud-init's NoCloud), sata0 on Windows (the gold's
    // CD slots were emptied when it was sealed).
    let slot = if win { "sata0" } else { "ide2" };
    let iso = if let Some(img) = img {
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
        };
        let user_data = linux::vm_user_data(img, &seed);
        let meta_data = linux::vm_meta_data(&spec.name, &stamp);
        let net_cfg = linux::vm_network_config(&nics);
        let mut files = vec![("user-data", user_data.as_str()), ("meta-data", meta_data.as_str())];
        if let Some(n) = &net_cfg {
            files.push(("network-config", n.as_str()));
        }
        SeedIso::build(work, &seed_name, "cidata", &files).await?
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
            manifest: guest_manifest(spec, &mac, &extra_macs),
            arc_secret: spec.arc.as_ref().filter(|a| !a.secret.is_empty()).map(|a| {
                serde_json::json!({ "servicePrincipalAppId": a.app_id, "servicePrincipalSecret": a.secret })
            }),
            join_secret: spec.domain_join.as_ref().map(|d| {
                serde_json::json!({ "domain": d.domain, "ouPath": d.ou, "joinUser": d.user, "joinPassword": d.password })
            }),
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
            files.push(("pvs-vm/GuestProvision/manifest.json", serde_json::to_string_pretty(&ws.manifest)?));
            if let Some(a) = &ws.arc_secret {
                files.push(("pvs-vm/GuestProvision/arc-deploy.json", a.to_string()));
            }
            if let Some(j) = &ws.join_secret {
                files.push(("pvs-vm/GuestProvision/DomainJoin.ps1", windows::DOMAIN_JOIN_PS1.to_owned()));
                files.push(("pvs-vm/GuestProvision/domain-join.json", j.to_string()));
            }
        }
        let refs: Vec<(&str, &str)> = files.iter().map(|(n, c)| (*n, c.as_str())).collect();
        SeedIso::build(work, &seed_name, "PVSVM", &refs).await?
    };
    let uploaded = pve.upload(&node, &iso_storage, "iso", &iso.iso, &format!("{seed_name}.iso")).await;
    iso.remove().await;
    let volid = uploaded?;
    *seed_vol = Some((node.clone(), volid.clone()));
    pve.vm_set(&node, vmid, form![(slot, format!("{volid},media=cdrom"))]).await?;

    // ---- 4. first boot ----
    pve.vm_action(&node, vmid, "start").await?;
    pr.stage(35.0, 90.0, "first boot");
    if win {
        log.run("First boot: specialize names the VM, OOBE takes the VM's answer file").await;
        windows::follow_first_boot(pve, log, &mut pr, &node, vmid).await?;
        let restart = guest_provision_result(pve, log, &node, vmid).await?;
        // [diff] Hyper-V's VMs never had a DVD drive: everything went into the VHDX. Here the
        // seed rode in on one, and a SATA drive cannot be unplugged from a running VM - so
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
        pve.vm_set(&node, vmid, form![("delete", slot)]).await?;
        pve.delete_volume(&node, &volid).await?;
        *seed_vol = None;
        log.ok("Seed drive removed and its ISO deleted - it held the passwords").await;
        pve.vm_action(&node, vmid, "start").await?;
    } else {
        log.run("First boot: cloud-init provisions, then powers off").await;
        follow_first_boot(pve, log, &mut pr, &node, vmid, 20).await?;
        pr.stage(90.0, 93.0, "removing the seed");
        pve.vm_set(&node, vmid, form![("delete", slot)]).await?;
        pve.delete_volume(&node, &volid).await?;
        *seed_vol = None;
        log.ok("Seed detached and deleted").await;
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
    loop {
        let s = pve.vm_status(node, vmid).await?;
        if s.status == "stopped" {
            return Ok(());
        }
        if started.elapsed() > Duration::from_secs(timeout_min * 60) {
            bail!("first boot did not finish within {timeout_min} minutes (see the console of VM {vmid})");
        }
        if let Some((chunk, n)) = pve.agent_read(node, vmid, "/var/log/cloud-init-output.log", offset).await {
            offset += n;
            for l in chunk.lines().map(str::trim_end).filter(|l| !l.is_empty()) {
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

pub async fn remove(pve: &Pve, db: &SqlitePool, vm: &VmRow, log: &JobLog) -> Result<()> {
    if let Some(vmid) = vm.vmid {
        let vmid = vmid as u32;
        match pve.vm_config(&vm.node, vmid).await {
            Ok(cfg) => {
                // Only a VM that still is the one the studio built.
                let tags = cfg.get("tags").and_then(|t| t.as_str()).unwrap_or("");
                let name = cfg.get("name").and_then(|t| t.as_str()).unwrap_or("");
                if !tags.split(';').any(|t| t == "pvs-vm") || name != vm.name {
                    bail!("VM {vmid} is no longer {} built by the studio - not touching it", vm.name);
                }
                pve.vm_destroy(&vm.node, vmid).await?;
                log.ok(format!("Removed VM {vmid} ({})", vm.name)).await;
            }
            Err(_) => log.line(format!("VM {vmid} is gone already")).await,
        }
    }
    sqlx::query("UPDATE vms SET status = 'removed' WHERE id = ?").bind(&vm.id).execute(db).await?;
    Ok(())
}

/// GuestProvision's manifest.json for a Windows VM - the fields Build-Vms'
/// Set-OfflineGuestProvisionPayload writes. Everything lands online at first boot here:
/// the studio cannot service the disk offline.
fn guest_manifest(spec: &VmSpec, mac: &str, extra_macs: &[String]) -> serde_json::Value {
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
    let auto = |i: usize| format!("vnic-{:02}", i + 1);
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
        // Specialize joins are not available off Hyper-V (the VM's answer file only reaches
        // oobeSystem), so every Windows join is deferred - research §7.
        "domainJoin": spec.domain_join.as_ref().map(|d| serde_json::json!({ "enabled": true, "mode": "deferred", "domain": d.domain, "ouPath": d.ou })),
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
async fn guest_provision_result(pve: &Pve, log: &JobLog, node: &str, vmid: u32) -> Result<bool> {
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
    Ok(st["restartNeeded"].as_bool() == Some(true))
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
        let m = guest_manifest(&spec(), "BC:24:11:AA:BB:CC", &["BC:24:11:00:00:01".into()]);
        assert_eq!(m["pendingWindowsFeatures"][0], "AD-Domain-Services");
        assert_eq!(m["pendingCapabilities"][0], "ServerCore.AppCompatibility~~~~0.0.1.0");
        assert_eq!(m["networkAdapters"][0]["name"], "LAN");
        assert_eq!(m["networkAdapters"][0]["macAddress"], "BC-24-11-AA-BB-CC");
        assert_eq!(m["networkAdapters"][1]["name"], "vnic-02");
        // The raw disk stays out; the first data disk is scsi1 = LUN 1, drive D:.
        assert_eq!(m["dataDisks"].as_array().unwrap().len(), 1);
        assert_eq!(m["dataDisks"][0]["scsiLocation"], 1);
        assert_eq!(m["dataDisks"][0]["letter"], "d");
        assert_eq!(m["dataDisks"][0]["label"], "Data D");
        assert!(m["domainJoin"].is_null() && m["azureArc"].is_null());
        assert!(crate::windows::needs_guest(&m));
    }
}
