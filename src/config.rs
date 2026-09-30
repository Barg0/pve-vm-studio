//! Settings, from one TOML file (default /etc/pve-vm-studio/config.toml, or the path in
//! PVS_CONFIG). Everything that differs between installations lives here; nothing else
//! reads the environment.

use std::{net::SocketAddr, path::PathBuf};

use anyhow::{Context, Result};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    /// Where the studio listens for HTTPS, e.g. "0.0.0.0:443".
    #[serde(default = "default_listen")]
    pub listen: SocketAddr,
    /// Plain HTTP: answers Let's Encrypt's HTTP-01 challenges and redirects everything
    /// else to HTTPS. Usually "0.0.0.0:80"; left out, there is none.
    pub http_listen: Option<SocketAddr>,
    /// Serve plain HTTP on `listen` instead of HTTPS - behind a proxy or for development
    /// only, since PVE passwords cross it.
    #[serde(default)]
    pub plain_http: bool,
    /// The studio's DNS name as the installer was told it - the starting value for the
    /// Settings page, which owns it after the first start.
    pub fqdn: Option<String>,
    /// Database, job logs, certificates and media live below this directory.
    #[serde(default = "default_data_dir")]
    pub data_dir: PathBuf,
    /// Older installs named their certificate here; it is taken over into
    /// <data_dir>/tls on the first start, where the studio manages it since.
    pub tls: Option<TlsConfig>,
    /// Where PVE's ISO storages are mounted into the studio's container, read-only, one
    /// folder per storage (<iso_root>/<storage>/<file>). The studio reads the editions on
    /// a Windows ISO from there; the installer sets the mounts up.
    #[serde(default = "default_iso_root")]
    pub iso_root: PathBuf,
    pub pve: PveConfig,
}

fn default_iso_root() -> PathBuf {
    PathBuf::from("/mnt/pve-iso")
}

#[derive(Debug, Clone, Deserialize)]
pub struct TlsConfig {
    pub cert: PathBuf,
    pub key: PathBuf,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PveConfig {
    /// Any node of the cluster, e.g. "https://pve-01.lab.local:8006". The API is cluster-wide.
    pub url: String,
    /// The studio's own token, "user@realm!tokenid". Background jobs run with it.
    pub token_id: String,
    pub token_secret: String,
    /// The cluster's CA (a copy of /etc/pve/pve-root-ca.pem). Without it the system roots apply.
    pub ca_file: Option<PathBuf>,
    /// Skip certificate checks entirely. Development only.
    #[serde(default)]
    pub insecure: bool,
}

fn default_listen() -> SocketAddr {
    "0.0.0.0:8443".parse().unwrap()
}

fn default_data_dir() -> PathBuf {
    PathBuf::from("/var/lib/pve-vm-studio")
}

impl Config {
    pub fn load() -> Result<Self> {
        let path = std::env::var_os("PVS_CONFIG")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/etc/pve-vm-studio/config.toml"));
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;
        let cfg: Config =
            toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
        Ok(cfg)
    }

    pub fn jobs_dir(&self) -> PathBuf {
        self.data_dir.join("jobs")
    }
}
