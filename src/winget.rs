//! WinGet's community catalog, read without winget: the studio searches it for the VM card's
//! Applications section, and a VM installs what was picked at first boot (GuestProvision).
//!
//! Microsoft publishes the catalog as files on its CDN - the same ones winget itself fetches:
//!   cache/source2.msix                          a zip; Public/index.db is SQLite, one row per
//!                                               package (id, name, moniker, latest_version, hash)
//!   cache/packages/<id>/<hash8>/versionData.mszyml  MSZIP-compressed YAML: every version and
//!                                               the path of its manifest
//!   cache/<manifest path>                       the merged manifest, plain YAML: publisher,
//!                                               licence, each installer with its scope
//! The index is fetched once a day (about 4 MB); a package's manifest when it is picked.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use serde::Serialize;

const CDN: &str = "https://cdn.winget.microsoft.com/cache";

/// One catalog entry, as the picker lists it.
#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct Hit {
    pub id: String,
    pub name: String,
    pub version: String,
}

/// What the picker needs before a package goes into a VM's list.
#[derive(Debug, Serialize)]
pub struct Package {
    pub id: String,
    pub name: String,
    pub publisher: String,
    pub license: String,
    pub version: String,
    /// The installers' scopes ("machine", "user"); empty when the manifest names none -
    /// such an installer takes --scope machine like any other.
    pub scopes: Vec<String>,
    /// GuestProvision installs as SYSTEM with --scope machine: false for a package that
    /// only installs per user.
    pub machine: bool,
}

static FETCH: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// The catalog index on disk, fetched again when it is a day old. A failed refresh keeps
/// the index there is.
async fn index(web: &reqwest::Client, data_dir: &Path) -> Result<PathBuf> {
    let _one = FETCH.lock().await;
    let dir = data_dir.join("winget");
    let db = dir.join("index.db");
    let fresh = tokio::fs::metadata(&db).await.ok().and_then(|m| m.modified().ok()).and_then(|t| t.elapsed().ok()).is_some_and(|age| age < Duration::from_secs(24 * 3600));
    if fresh {
        return Ok(db);
    }
    match refresh(web, &dir, &db).await {
        Ok(()) => Ok(db),
        Err(e) if tokio::fs::metadata(&db).await.is_ok() => {
            tracing::warn!("WinGet catalog not refreshed, the old index stays: {e:#}");
            Ok(db)
        }
        Err(e) => Err(e),
    }
}

async fn refresh(web: &reqwest::Client, dir: &Path, db: &Path) -> Result<()> {
    tokio::fs::create_dir_all(dir).await?;
    let bytes = web.get(format!("{CDN}/source2.msix")).send().await?.error_for_status()?.bytes().await.context("downloading WinGet's catalog")?;
    let msix = dir.join("source2.msix");
    tokio::fs::write(&msix, &bytes).await?;
    // The msix is a zip; 7z (in the container for the Windows media) takes the one file out.
    let out = tokio::process::Command::new("7z").arg("e").arg("-so").arg(&msix).arg("Public/index.db").output().await.context("running 7z")?;
    let _ = tokio::fs::remove_file(&msix).await;
    if !out.status.success() || out.stdout.len() < 1024 {
        bail!("no Public/index.db in WinGet's catalog");
    }
    let tmp = db.with_extension("tmp");
    tokio::fs::write(&tmp, &out.stdout).await?;
    tokio::fs::rename(&tmp, db).await?;
    tracing::info!("WinGet catalog refreshed ({:.1} MB index)", out.stdout.len() as f64 / 1e6);
    Ok(())
}

async fn open(db: &Path) -> Result<sqlx::SqlitePool> {
    let opts = sqlx::sqlite::SqliteConnectOptions::new().filename(db).read_only(true).immutable(true);
    Ok(sqlx::sqlite::SqlitePoolOptions::new().max_connections(1).connect_with(opts).await?)
}

/// Packages whose id, name or moniker holds `q`; exact ids and monikers first, then names
/// that start with it.
pub async fn search(web: &reqwest::Client, data_dir: &Path, q: &str) -> Result<Vec<Hit>> {
    let q = q.trim();
    if q.len() < 2 {
        return Ok(vec![]);
    }
    let pool = open(&index(web, data_dir).await?).await?;
    let like = format!("%{}%", q.replace(['%', '_'], ""));
    let prefix = format!("{}%", q.replace(['%', '_'], ""));
    let hits = sqlx::query_as::<_, Hit>(
        "SELECT id, name, latest_version AS version FROM packages
         WHERE id LIKE ?1 OR name LIKE ?1 OR moniker LIKE ?1
         ORDER BY (lower(id) = lower(?2) OR lower(moniker) = lower(?2)) DESC, (name LIKE ?3) DESC, length(name), name
         LIMIT 20",
    )
    .bind(&like)
    .bind(q)
    .bind(&prefix)
    .fetch_all(&pool)
    .await?;
    pool.close().await;
    Ok(hits)
}

/// MSZIP: a small header, then "CK" and one raw deflate block.
fn mszip(data: &[u8]) -> Result<String> {
    use std::io::Read;
    let at = data.windows(2).position(|w| w == b"CK").ok_or_else(|| anyhow!("not MSZIP data"))?;
    let mut out = String::new();
    flate2::read::DeflateDecoder::new(&data[at + 2..]).read_to_string(&mut out)?;
    Ok(out)
}

/// A top-level `Key: value` of a YAML manifest (the first one), quotes taken off.
fn yaml_value(yaml: &str, key: &str) -> String {
    yaml.lines()
        .find_map(|l| l.strip_prefix(&format!("{key}:")))
        .map(|v| v.trim().trim_matches('"').trim_matches('\'').to_owned())
        .unwrap_or_default()
}

/// A package's newest manifest: who makes it, its licence, and which scopes it installs in.
pub async fn package(web: &reqwest::Client, data_dir: &Path, id: &str) -> Result<Package> {
    let pool = open(&index(web, data_dir).await?).await?;
    let row: Option<(String, String, String)> = sqlx::query_as("SELECT name, latest_version, lower(hex(hash)) FROM packages WHERE id = ?1")
        .bind(id)
        .fetch_optional(&pool)
        .await?;
    pool.close().await;
    let (name, version, hash) = row.ok_or_else(|| anyhow!("{id} is not in WinGet's catalog"))?;
    let hash8 = hash.get(..8).ok_or_else(|| anyhow!("{id} has no catalog hash"))?;
    let data = web.get(format!("{CDN}/packages/{id}/{hash8}/versionData.mszyml")).send().await?.error_for_status()?.bytes().await?;
    let versions = mszip(&data).context("reading the package's version list")?;
    // The newest version is listed first; its manifest path follows it.
    let path = versions.lines().find_map(|l| l.trim().strip_prefix("rP:")).map(str::trim).ok_or_else(|| anyhow!("no manifest listed for {id}"))?;
    let manifest = web.get(format!("{CDN}/{path}")).send().await?.error_for_status()?.text().await?;
    let mut scopes: Vec<String> = manifest
        .lines()
        .filter_map(|l| l.trim_start_matches(['-', ' ']).strip_prefix("Scope:"))
        .map(|s| s.trim().to_lowercase())
        .collect();
    scopes.sort();
    scopes.dedup();
    let machine = scopes.is_empty() || scopes.iter().any(|s| s == "machine");
    Ok(Package {
        id: id.to_owned(),
        name,
        publisher: yaml_value(&manifest, "Publisher"),
        license: yaml_value(&manifest, "License"),
        version,
        scopes,
        machine,
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn manifest_values() {
        let y = "PackageIdentifier: 7zip.7zip\nPublisher: Igor Pavlov\nLicense: \"LGPL-2.1\"\nInstallers:\n- Architecture: x64\n  Scope: machine\n";
        assert_eq!(super::yaml_value(y, "Publisher"), "Igor Pavlov");
        assert_eq!(super::yaml_value(y, "License"), "LGPL-2.1");
    }
}
