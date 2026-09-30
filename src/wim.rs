//! What is on a Windows ISO: the images in its install.wim/esd, read without unpacking.
//!
//! Microsoft ISOs keep their files in UDF only (the ISO 9660 side is one README), so
//! `7z` streams sources/install.wim out of the ISO; this reads the WIM header (208
//! bytes), skips to the XML metadata resource it points at, and stops. No temporary
//! copy of a 5 GB file, no loop mount (the studio runs unprivileged). Results are cached
//! per ISO (path, size, mtime).

use std::{collections::HashMap, path::Path, process::Stdio};

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use tokio::io::AsyncReadExt;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WimImage {
    pub index: u32,
    pub name: String,
    pub edition_id: String,
    /// "Server", "Server Core", "Client".
    pub installation_type: String,
    pub language: String,
    pub build: String,
    /// What applying it writes - the measure for the bake's progress bar.
    pub total_bytes: u64,
}

pub async fn inspect(iso: &Path, cache_file: &Path) -> Result<Vec<WimImage>> {
    let meta = tokio::fs::metadata(iso).await.with_context(|| format!("reading {}", iso.display()))?;
    let key = format!(
        "{}|{}|{}",
        iso.display(),
        meta.len(),
        meta.modified().ok().and_then(|m| m.duration_since(std::time::UNIX_EPOCH).ok()).map(|d| d.as_secs()).unwrap_or(0)
    );
    let mut cache: HashMap<String, Vec<WimImage>> = tokio::fs::read(cache_file)
        .await
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default();
    if let Some(hit) = cache.get(&key) {
        return Ok(hit.clone());
    }
    let mut last_err = anyhow!("no sources/install.wim or install.esd on {}", iso.display());
    for inner in ["sources/install.wim", "sources/install.esd"] {
        match read_xml(iso, inner).await {
            Ok(xml) => {
                let images = parse_images(&xml);
                if images.is_empty() {
                    bail!("{inner} on {} lists no images", iso.display());
                }
                cache.insert(key, images.clone());
                if let Ok(b) = serde_json::to_vec(&cache) {
                    let _ = tokio::fs::write(cache_file, b).await;
                }
                return Ok(images);
            }
            Err(e) => last_err = e,
        }
    }
    Err(last_err)
}

async fn read_xml(iso: &Path, inner: &str) -> Result<String> {
    let mut child = tokio::process::Command::new("7z")
        .args(["x", "-so", "-bd"])
        .arg(iso)
        .arg(inner)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .context("running 7z - is the 7zip package installed?")?;
    let mut out = child.stdout.take().ok_or_else(|| anyhow!("no output from 7z"))?;

    let mut header = [0u8; 208];
    out.read_exact(&mut header).await.map_err(|_| anyhow!("{inner} not on the ISO"))?;
    if &header[0..8] != b"MSWIM\0\0\0" {
        bail!("{inner} is not a WIM");
    }
    // The XML data's resource header sits at 0x48: 7 bytes size, 1 flag byte, 8 bytes
    // offset, 8 bytes original size. The XML itself is stored uncompressed.
    let rh = &header[0x48..0x60];
    let size = u64::from_le_bytes([rh[0], rh[1], rh[2], rh[3], rh[4], rh[5], rh[6], 0]);
    let offset = u64::from_le_bytes(rh[8..16].try_into().unwrap());
    if size == 0 || size > 64 << 20 || offset < 208 {
        bail!("{inner}: implausible XML resource ({size} bytes at {offset})");
    }
    // Skip to it - read and dropped, the stream cannot seek.
    let mut skip = offset - 208;
    let mut buf = vec![0u8; 1 << 20];
    while skip > 0 {
        let want = skip.min(buf.len() as u64) as usize;
        let n = out.read(&mut buf[..want]).await?;
        if n == 0 {
            bail!("{inner} ended before its metadata");
        }
        skip -= n as u64;
    }
    let mut xml = vec![0u8; size as usize];
    out.read_exact(&mut xml).await.context("reading the WIM metadata")?;
    let _ = child.kill().await;

    // UTF-16LE with a BOM.
    let units: Vec<u16> = xml.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    Ok(String::from_utf16_lossy(&units).trim_start_matches('\u{feff}').to_owned())
}

fn tag<'a>(block: &'a str, name: &str) -> Option<&'a str> {
    let open = format!("<{name}>");
    let start = block.find(&open)? + open.len();
    let end = block[start..].find(&format!("</{name}>"))?;
    Some(block[start..start + end].trim())
}

pub fn parse_images(xml: &str) -> Vec<WimImage> {
    let mut out = Vec::new();
    for part in xml.split("<IMAGE INDEX=\"").skip(1) {
        let Some((idx, rest)) = part.split_once('"') else { continue };
        let Ok(index) = idx.parse() else { continue };
        let block = rest.split("</IMAGE>").next().unwrap_or(rest);
        let windows = block.split("<WINDOWS>").nth(1).unwrap_or("");
        let version = windows.split("<VERSION>").nth(1).unwrap_or("");
        out.push(WimImage {
            index,
            name: tag(block, "NAME").unwrap_or("").to_owned(),
            edition_id: tag(windows, "EDITIONID").unwrap_or("").to_owned(),
            installation_type: tag(windows, "INSTALLATIONTYPE").unwrap_or("").to_owned(),
            language: tag(windows.split("<LANGUAGES>").nth(1).unwrap_or(""), "LANGUAGE").unwrap_or("").to_owned(),
            build: tag(version, "BUILD").unwrap_or("").to_owned(),
            total_bytes: tag(block, "TOTALBYTES").and_then(|t| t.parse().ok()).unwrap_or(0),
        });
    }
    out.sort_by_key(|i| i.index);
    out
}

#[cfg(test)]
mod tests {
    #[test]
    fn parses_images() {
        let xml = r#"<WIM><TOTALBYTES>1</TOTALBYTES><IMAGE INDEX="3"><TOTALBYTES>9123</TOTALBYTES><WINDOWS><EDITIONID>ServerDatacenter</EDITIONID><INSTALLATIONTYPE>Server Core</INSTALLATIONTYPE><LANGUAGES><LANGUAGE>en-US</LANGUAGE></LANGUAGES><VERSION><MAJOR>10</MAJOR><BUILD>26100</BUILD></VERSION></WINDOWS><NAME>Windows Server 2025 Datacenter</NAME></IMAGE></WIM>"#;
        let i = super::parse_images(xml);
        assert_eq!(i.len(), 1);
        assert_eq!(i[0].index, 3);
        assert_eq!(i[0].edition_id, "ServerDatacenter");
        assert_eq!(i[0].installation_type, "Server Core");
        assert_eq!(i[0].build, "26100");
        assert_eq!(i[0].total_bytes, 9123);
    }
}
