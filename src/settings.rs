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
    /// "host" by default: EL10 needs x86-64-v3, which PVE's default CPU type lacks.
    pub cpu: String,
    /// Windows bakes: a named model. Windows on `host` under nested virtualization (PVE in
    /// Hyper-V, say) stops KVM with an internal error as soon as it sees VMX.
    pub cpu_windows: String,
    pub memory_mb: u32,
    pub cores: u32,
    pub timeout_min: u64,
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
            cpu: "host".into(),
            cpu_windows: "x86-64-v2-AES".into(),
            memory_mb: 2048,
            cores: 2,
            timeout_min: 60,
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
    pub cpu: String,
    pub cpu_windows: String,
    pub memory_mb: u32,
    pub cores: u32,
    pub timeout_min: u64,
}

impl BakeSettings {
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
            // Shared storage first (one gold for every node), then the most free space.
            fit.sort_by_key(|s| {
                let free = s.maxdisk.unwrap_or(0).saturating_sub(s.disk.unwrap_or(0));
                let preferred = prefer.iter().position(|p| s.storage.as_deref() == Some(*p)).unwrap_or(99);
                (std::cmp::Reverse(s.shared.unwrap_or(0)), preferred, std::cmp::Reverse(free))
            });
            fit.first()
                .and_then(|s| s.storage.clone())
                .ok_or_else(|| anyhow!("no storage on {node} holds '{content}' - enable it under Datacenter → Storage"))
        };
        let disk_storage = pick(&self.disk_storage, "images", &["local-lvm", "local-zfs"])?;
        let import_storage = pick(&self.import_storage, "import", &["local"])?;
        let iso_storage = pick(&self.iso_storage, "iso", &["local"])?;

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

        Ok(Placement {
            node,
            disk_storage,
            import_storage,
            iso_storage,
            bridge,
            vlan: self.vlan,
            cpu: if self.cpu.is_empty() { "host".into() } else { self.cpu.clone() },
            cpu_windows: if self.cpu_windows.is_empty() { "x86-64-v2-AES".into() } else { self.cpu_windows.clone() },
            memory_mb: self.memory_mb.max(1024),
            cores: self.cores.max(1),
            timeout_min: self.timeout_min.max(10),
        })
    }
}
