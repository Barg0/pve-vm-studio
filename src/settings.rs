//! Studio-wide settings: where bakes run and which storages they use. One JSON document
//! per key in the `settings` table; missing fields fall back to defaults, and "auto"
//! choices are resolved against the cluster when a job starts.

use anyhow::{anyhow, bail, Result};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sqlx::SqlitePool;

use crate::pve::{Pve, Resource};

pub async fn load<T: DeserializeOwned + Default>(db: &SqlitePool, key: &str) -> Result<T> {
    let row: Option<(String,)> = sqlx::query_as("SELECT value FROM settings WHERE key = ?")
        .bind(key)
        .fetch_optional(db)
        .await?;
    Ok(match row {
        Some((v,)) => serde_json::from_str(&v)?,
        None => T::default(),
    })
}

pub async fn save<T: Serialize>(db: &SqlitePool, key: &str, value: &T) -> Result<()> {
    sqlx::query("INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value")
        .bind(key)
        .bind(serde_json::to_string(value)?)
        .execute(db)
        .await?;
    Ok(())
}

/// Where and how golds are baked. Empty strings mean "pick one".
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct BakeSettings {
    pub node: String,
    /// Holds the gold's disks (content "images"). Clones land here too when linked.
    pub disk_storage: String,
    /// Where PVE downloads cloud images to (content "import").
    pub import_storage: String,
    /// Where seed ISOs go (content "iso").
    pub iso_storage: String,
    pub bridge: String,
    pub vlan: Option<u16>,
    /// The VMs' CPU type. x86-64-v3 by default: EL10 needs it, and unlike `host` a clone still
    /// live-migrates between nodes of different CPU generations. Bakes too, without bake_host.
    pub cpu: String,
    /// Windows VMs: a named model. Windows on `host` under nested virtualization (PVE in
    /// Hyper-V, say) stops KVM with an internal error as soon as it sees VMX.
    pub cpu_windows: String,
    /// Bake, WinPE and worker VMs on the node's own CPU: they never migrate, so `host` costs
    /// nothing and gives them every instruction the node has. Windows ones without VMX
    /// (-nested-virt): no KVM stop under nested virtualization, and Windows Setup decides
    /// nothing about VBS from a CPU the clones may not have.
    #[serde(default = "yes")]
    pub bake_host: bool,
    pub memory_mb: u32,
    pub cores: u32,
    pub timeout_min: u64,
    /// Linux bakes' addresses on the bake network: one (10.10.0.60/24) or a range for parallel
    /// bakes (10.10.0.60-69/24, or 10.10.0.60-10.10.0.69/24); "" = DHCP. For networks without
    /// DHCP (New-Vhdx asks for it too). Each bake takes the first one no running bake holds.
    /// Windows bakes stay offline.
    #[serde(default)]
    pub linux_address: String,
    #[serde(default)]
    pub linux_gateway: String,
    #[serde(default)]
    pub linux_dns: Vec<String>,
}

impl Default for BakeSettings {
    fn default() -> Self {
        Self {
            node: String::new(),
            disk_storage: String::new(),
            import_storage: String::new(),
            iso_storage: String::new(),
            bridge: String::new(),
            vlan: None,
            cpu: CPU_DEFAULT.into(),
            cpu_windows: CPU_DEFAULT.into(),
            bake_host: true,
            // New-Vhdx's bake VMs get 4 GB; the Windows bake raised anything smaller to it anyway.
            memory_mb: 4096,
            // New-Vhdx gives every bake VM 4 vCPUs.
            cores: 4,
            timeout_min: 60,
            linux_address: String::new(),
            linux_gateway: String::new(),
            linux_dns: vec![],
        }
    }
}

/// BakeSettings with every "auto" filled in and checked against the cluster.
#[derive(Debug, Clone, Serialize)]
pub struct Placement {
    pub node: String,
    pub disk_storage: String,
    pub import_storage: String,
    pub iso_storage: String,
    pub bridge: String,
    pub vlan: Option<u16>,
    /// The bake, WinPE and worker VMs' CPU types (Linux, Windows).
    pub cpu: String,
    pub cpu_windows: String,
    pub memory_mb: u32,
    pub cores: u32,
    pub timeout_min: u64,
    pub linux_address: String,
    pub linux_gateway: String,
    pub linux_dns: Vec<String>,
}

const CPU_DEFAULT: &str = "x86-64-v3";

fn yes() -> bool {
    true
}

impl BakeSettings {
    /// The Linux bake addresses and their prefix, checked; None for DHCP.
    pub fn linux_pool(&self) -> Result<Option<(Vec<std::net::Ipv4Addr>, u8)>> {
        use std::net::Ipv4Addr;
        let a = self.linux_address.trim();
        if a.is_empty() {
            return Ok(None);
        }
        let (range, prefix) = a.split_once('/').ok_or_else(|| anyhow!("the bake addresses need their prefix: 10.10.0.60-69/24"))?;
        let prefix: u8 = prefix.trim().parse().ok().filter(|p| (1..=32).contains(p)).ok_or_else(|| anyhow!("the prefix is 1 to 32"))?;
        let (first, last) = range.split_once('-').map(|(f, l)| (f.trim(), Some(l.trim()))).unwrap_or((range.trim(), None));
        let first: Ipv4Addr = first.parse().map_err(|_| anyhow!("'{first}' is not an IPv4 address"))?;
        let last: Ipv4Addr = match last {
            None => first,
            // 10.10.0.60-69: the last octet only.
            Some(l) if !l.contains('.') => {
                let o: u8 = l.parse().map_err(|_| anyhow!("'{l}' is not the last part of an address"))?;
                let f = first.octets();
                Ipv4Addr::new(f[0], f[1], f[2], o)
            }
            Some(l) => l.parse().map_err(|_| anyhow!("'{l}' is not an IPv4 address"))?,
        };
        let (f, l) = (u32::from(first), u32::from(last));
        if l < f {
            bail!("the range ends before it starts");
        }
        if l - f >= 256 {
            bail!("at most 256 bake addresses");
        }
        let mask = if prefix == 32 { u32::MAX } else { !(u32::MAX >> prefix) };
        if f & mask != l & mask {
            bail!("the range leaves the /{prefix} network");
        }
        let pool: Vec<Ipv4Addr> = (f..=l).map(Ipv4Addr::from).collect();
        let gw = self.linux_gateway.trim();
        if gw.is_empty() {
            bail!("a static bake address needs a gateway - the bake installs packages");
        }
        gw.parse::<std::net::Ipv4Addr>().map_err(|_| anyhow!("'{gw}' is not an IPv4 address"))?;
        if self.linux_dns.is_empty() {
            bail!("a static bake address needs a DNS server");
        }
        for d in &self.linux_dns {
            d.parse::<std::net::IpAddr>().map_err(|_| anyhow!("'{d}' is not an IP address"))?;
        }
        Ok(Some((pool, prefix)))
    }

    /// The CPU type for a Linux or a Windows VM, the default when left empty.
    pub fn cpu_for(&self, windows: bool) -> String {
        let v = if windows { &self.cpu_windows } else { &self.cpu };
        if v.is_empty() { CPU_DEFAULT.into() } else { v.clone() }
    }

    pub async fn resolve(&self, pve: &Pve) -> Result<Placement> {
        let resources = pve.resources().await?;
        let online = |r: &&Resource| r.kind == "node" && r.status.as_deref() == Some("online");
        let node = if self.node.is_empty() {
            // The online node with the most free memory.
            resources
                .iter()
                .filter(online)
                .max_by_key(|n| n.maxmem.unwrap_or(0).saturating_sub(n.mem.unwrap_or(0)))
                .and_then(|n| n.node.clone())
                .ok_or_else(|| anyhow!("no online node"))?
        } else {
            if !resources.iter().filter(online).any(|n| n.node.as_deref() == Some(&self.node)) {
                bail!("node {} is not online", self.node);
            }
            self.node.clone()
        };

        let storages: Vec<&Resource> = resources
            .iter()
            .filter(|r| r.kind == "storage" && r.node.as_deref() == Some(&node) && r.status.as_deref() == Some("available"))
            .collect();
        let pick = |wanted: &str, content: &str, prefer: &[&str]| -> Result<String> {
            if !wanted.is_empty() {
                return storages
                    .iter()
                    .find(|s| s.storage.as_deref() == Some(wanted))
                    .filter(|s| s.has_content(content))
                    .and_then(|s| s.storage.clone())
                    .ok_or_else(|| anyhow!("storage {wanted} on {node} does not hold '{content}'"));
            }
            let mut fit: Vec<&&Resource> = storages.iter().filter(|s| s.has_content(content)).collect();
            // Shared storage first (one gold for every node), then a storage of its own over
            // `local` - the node's root disk, which also carries PVE itself - then the preferred
            // names, then the most free space.
            fit.sort_by_key(|s| {
                let free = s.maxdisk.unwrap_or(0).saturating_sub(s.disk.unwrap_or(0));
                let root = s.storage.as_deref() == Some("local");
                let preferred = prefer.iter().position(|p| s.storage.as_deref() == Some(*p)).unwrap_or(99);
                (std::cmp::Reverse(s.shared.unwrap_or(0)), root, preferred, std::cmp::Reverse(free))
            });
            fit.first()
                .and_then(|s| s.storage.clone())
                .ok_or_else(|| anyhow!("no storage on {node} holds '{content}' - enable it under Datacenter → Storage"))
        };
        let disk_storage = pick(&self.disk_storage, "images", &["local-lvm", "local-zfs"])?;
        let import_storage = pick(&self.import_storage, "import", &[])?;
        let iso_storage = pick(&self.iso_storage, "iso", &[])?;

        let bridges = pve.bridges(&node).await?;
        let bridge = if self.bridge.is_empty() {
            bridges
                .iter()
                .find(|b| b.iface == "vmbr0")
                .or_else(|| bridges.first())
                .map(|b| b.iface.clone())
                .ok_or_else(|| anyhow!("no bridge on {node}"))?
        } else {
            if !bridges.iter().any(|b| b.iface == self.bridge) && !pve.vnets().await.iter().any(|v| v.vnet == self.bridge) {
                bail!("bridge {} does not exist on {node}", self.bridge);
            }
            self.bridge.clone()
        };

        // The bake VMs' CPU: `host` - unless the node is itself a VM (its CPU says
        // "hypervisor": PVE in Hyper-V or VMware, where Windows on host stops KVM) or PVE
        // predates the nested-virt flag (9.1), which takes VMX off Windows.
        let (mut bake_cpu, mut bake_cpu_windows) = (self.cpu_for(false), self.cpu_for(true));
        if self.bake_host {
            #[derive(Deserialize)]
            struct Cpu {
                #[serde(default)]
                flags: String,
            }
            #[derive(Deserialize)]
            struct Status {
                cpuinfo: Cpu,
            }
            let virtual_node = match pve.get::<Status>(&format!("/nodes/{}/status", crate::pve::enc(&node))).await {
                Ok(s) => s.cpuinfo.flags.split_whitespace().any(|f| f == "hypervisor"),
                Err(_) => true,
            };
            let nested_flag = pve.version().await.ok().and_then(|v| {
                let mut it = v.release.split('.').map(|x| x.parse::<u32>().unwrap_or(0));
                Some((it.next()?, it.next().unwrap_or(0)))
            }).is_some_and(|(maj, min)| maj > 9 || (maj == 9 && min >= 1));
            if !virtual_node {
                bake_cpu = "host".into();
                if nested_flag {
                    bake_cpu_windows = "host,flags=-nested-virt".into();
                }
            }
        }

        Ok(Placement {
            node,
            disk_storage,
            import_storage,
            iso_storage,
            bridge,
            vlan: self.vlan,
            cpu: bake_cpu,
            cpu_windows: bake_cpu_windows,
            memory_mb: self.memory_mb.max(1024),
            cores: self.cores.max(1),
            timeout_min: self.timeout_min.max(10),
            linux_address: self.linux_address.trim().to_owned(),
            linux_gateway: self.linux_gateway.trim().to_owned(),
            linux_dns: self.linux_dns.clone(),
        })
    }
}

/// Whether a storage allocates a disk up front ("thick") or on write ("thin") - New-Vhdx's
/// Fixed/Dynamic. On PVE it is the storage's property, never the disk's: LVM-thin and Ceph
/// are thin, plain LVM thick, ZFS thick unless the storage is `sparse`, directory-like
/// storages thick only with `preallocation` full or falloc.
pub fn provisioning(cfg: &serde_json::Value) -> &'static str {
    let flag = |k: &str| cfg[k].as_u64() == Some(1) || cfg[k].as_str() == Some("1");
    match cfg["type"].as_str().unwrap_or("") {
        "lvm" => "thick",
        "zfspool" => if flag("sparse") { "thin" } else { "thick" },
        "dir" | "nfs" | "cifs" | "glusterfs" | "btrfs" => match cfg["preallocation"].as_str() {
            Some("full" | "falloc") => "thick",
            _ => "thin",
        },
        _ => "thin",
    }
}

/// The storages on a node that hold VM disks, each with its provisioning - what the bake
/// form offers as Thin and Thick.
pub async fn disk_storages(pve: &Pve, node: &str) -> Result<Vec<serde_json::Value>> {
    let configs = pve.storage_configs().await?;
    let res = pve.resources().await?;
    Ok(res
        .iter()
        .filter(|r| r.kind == "storage" && r.node.as_deref() == Some(node) && r.has_content("images") && r.status.as_deref() == Some("available"))
        .filter_map(|r| {
            let name = r.storage.clone()?;
            let cfg = configs.iter().find(|c| c["storage"].as_str() == Some(name.as_str()))?;
            Some(serde_json::json!({
                "storage": name, "type": cfg["type"], "shared": r.shared == Some(1),
                "provisioning": provisioning(cfg), "free": r.maxdisk.unwrap_or(0).saturating_sub(r.disk.unwrap_or(0)),
            }))
        })
        .collect())
}

impl Placement {
    /// One bake's own disk storage (the form's Thin / Thick), checked against the node.
    pub async fn with_disk_storage(mut self, pve: &Pve, wanted: Option<&str>) -> Result<Self> {
        if let Some(w) = wanted.filter(|w| !w.is_empty()) {
            if !disk_storages(pve, &self.node).await?.iter().any(|s| s["storage"].as_str() == Some(w)) {
                bail!("storage {w} does not hold VM disks on {}", self.node);
            }
            self.disk_storage = w.to_owned();
        }
        Ok(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with(addr: &str) -> BakeSettings {
        BakeSettings { linux_address: addr.into(), linux_gateway: "10.10.0.1".into(), linux_dns: vec!["10.10.0.1".into()], ..Default::default() }
    }

    #[test]
    fn bake_address_ranges() {
        assert!(with("").linux_pool().unwrap().is_none());
        let (one, p) = with("10.10.0.60/24").linux_pool().unwrap().unwrap();
        assert_eq!((one.len(), p), (1, 24));
        let (short, _) = with("10.10.0.60-69/24").linux_pool().unwrap().unwrap();
        assert_eq!((short.len(), short[9].to_string()), (10, "10.10.0.69".to_owned()));
        let (full, _) = with("10.10.0.60 - 10.10.0.63/24").linux_pool().unwrap().unwrap();
        assert_eq!(full.len(), 4);
        assert!(with("10.10.0.69-60/24").linux_pool().is_err(), "backwards");
        assert!(with("10.10.0.250-10.10.1.5/24").linux_pool().is_err(), "leaves the /24");
        assert!(with("10.10.0.60").linux_pool().is_err(), "no prefix");
        assert!(BakeSettings { linux_gateway: String::new(), ..with("10.10.0.60/24") }.linux_pool().is_err(), "no gateway");
    }
}
