//! Features on Demand media: the "Languages and Optional Features" ISO per Windows family,
//! as Build-Vms.ps1 asks for it - one for Windows Server, one for Windows 11. 24H2 and 25H2
//! share build 26100's FoD, so one client ISO serves both; 23H2 is not offered.
//!
//! [diff] Build-Vms installs the capabilities offline into the VM's disk before it boots.
//! The studio cannot reach a disk (PVE API only), so the ISO rides along as a second CD and
//! GuestProvision installs from it (-Source, -LimitAccess) - no Windows Update, no internet.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    process::Stdio,
};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::{jobs::JobLog, progress::Progress, pve::Pve, uup, winpe::run};

/// Which FoD ISO each release uses (PVE volids; empty = none - capabilities then come from
/// Windows Update at first boot). `server` is Windows Server 2025; Server 2022 (build 20348)
/// has its own FoD set.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct FodSettings {
    pub server: String,
    pub server2022: String,
    pub client: String,
}

impl FodSettings {
    /// The FoD ISO for a gold: Windows 11 has one set for all its 26100-based releases,
    /// Windows Server one per release.
    pub fn for_gold(&self, client: bool, build: &str) -> &str {
        if client {
            &self.client
        } else if build.split('.').any(|p| p == "20348") {
            &self.server2022
        } else {
            &self.server
        }
    }

    pub fn slot_mut(&mut self, key: &str) -> Option<&mut String> {
        match key {
            "server" => Some(&mut self.server),
            "server2022" => Some(&mut self.server2022),
            "client" => Some(&mut self.client),
            _ => None,
        }
    }
}

/// Where each slot's FoD set comes from in the UUP catalog: the newest build of a product.
/// Windows 11's 24H2, 25H2 and 26H2 carry byte-identical FoD packages (build 26100's).
pub struct Source {
    pub key: &'static str,
    pub product: &'static str,
    pub short: &'static str,
    pub name: &'static str,
}

pub static SOURCES: &[Source] = &[
    Source { key: "server", product: "ws2025", short: "ws2025", name: "Windows Server 2025" },
    Source { key: "server2022", product: "ws2022", short: "ws2022", name: "Windows Server 2022" },
    Source { key: "client", product: "w11-26h2", short: "w11", name: "Windows 11" },
];

pub fn source(key: &str) -> Option<&'static Source> {
    SOURCES.iter().find(|s| s.key == key)
}

/// The FoD ISO a deploy uses and how WinPE finds its payload - resolved when the build is
/// planned, carried in the VM's spec.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FodPlan {
    pub volid: String,
    pub root: String,
    pub marker: String,
}

/// What is on a FoD ISO: where the payload sits (Build-Vms' candidate folders - Server 2022
/// and later keep it under LanguagesAndOptionalFeatures\, Windows 11's ISO at its root) and
/// how many packages it carries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FodMedia {
    pub root: String,
    /// One FoD package on it, relative to the ISO - how WinPE tells this CD from the others.
    #[serde(default)]
    pub marker: String,
    pub cabs: usize,
    pub fod_packages: usize,
    pub language_packs: usize,
}

pub async fn inspect(iso: &Path, cache_file: &Path) -> Result<FodMedia> {
    let meta = tokio::fs::metadata(iso).await.with_context(|| format!("reading {}", iso.display()))?;
    let key = format!(
        "{}|{}|{}",
        iso.display(),
        meta.len(),
        meta.modified().ok().and_then(|m| m.duration_since(std::time::UNIX_EPOCH).ok()).map(|d| d.as_secs()).unwrap_or(0)
    );
    let key = format!("v2|{key}");
    let mut cache: HashMap<String, FodMedia> =
        tokio::fs::read(cache_file).await.ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default();
    if let Some(hit) = cache.get(&key) {
        return Ok(hit.clone());
    }
    let out = tokio::process::Command::new("7z")
        .args(["l", "-ba", "-slt"])
        .arg(iso)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .await
        .context("running 7z - is the 7zip package installed?")?;
    let text = String::from_utf8_lossy(&out.stdout);
    let paths: Vec<String> = text.lines().filter_map(|l| l.strip_prefix("Path = ")).map(|p| p.replace('\\', "/")).collect();
    let media = classify(&paths)?;
    cache.insert(key, media.clone());
    if let Ok(b) = serde_json::to_vec(&cache) {
        let _ = tokio::fs::write(cache_file, b).await;
    }
    Ok(media)
}

fn classify(paths: &[String]) -> Result<FodMedia> {
    let in_lof: Vec<&String> = paths.iter().filter(|p| p.to_lowercase().starts_with("languagesandoptionalfeatures/")).collect();
    let (root, cabs): (String, Vec<&String>) = if in_lof.iter().any(|p| p.to_lowercase().ends_with(".cab")) {
        ("LanguagesAndOptionalFeatures".into(), in_lof.into_iter().filter(|p| p.to_lowercase().ends_with(".cab")).collect())
    } else {
        (String::new(), paths.iter().filter(|p| !p.contains('/') && p.to_lowercase().ends_with(".cab")).collect())
    };
    let fod = cabs.iter().filter(|p| p.contains("FoD-Package") || p.contains("~31bf3856ad364e35~")).count();
    if fod == 0 {
        bail!("no Features on Demand packages on this ISO - it is not a Languages and Optional Features ISO");
    }
    let marker = cabs.iter().find(|p| p.contains("FoD-Package")).or(cabs.first()).map(|p| p.to_string()).unwrap_or_default();
    Ok(FodMedia {
        root,
        marker,
        cabs: cabs.len(),
        fod_packages: fod,
        language_packs: cabs.iter().filter(|p| p.contains("Language-Pack")).count(),
    })
}

// ---- a FoD ISO from Microsoft's update servers ----

/// Not on the studio's FoD ISO: language features (handwriting, speech, OCR, fonts per
/// region) and Windows Mixed Reality - no VM uses them, and they are most of the bytes.
fn skipped(canonical: &str) -> bool {
    let n = canonical.to_lowercase();
    ["languagefeatures-", "internationalfeatures-", "holographic-"].iter().any(|k| n.contains(k))
}

/// The UUP file name of a canonical FoD package name:
/// X~31bf3856ad364e35~amd64~~.cab is X-amd64.cab, X~31bf3856ad364e35~amd64~en-US~.cab
/// is X-amd64-en-US.cab (compared without case).
fn uup_key(canonical: &str) -> String {
    let stem = canonical.strip_suffix(".cab").unwrap_or(canonical);
    let parts: Vec<&str> = stem.split('~').collect();
    let pick = |i: usize| parts.get(i).copied().unwrap_or("");
    [pick(0), pick(2), pick(3)].iter().filter(|p| !p.is_empty()).copied().collect::<Vec<_>>().join("-").to_lowercase()
}

/// An attribute's value inside one XML tag.
fn attr<'a>(tag: &'a str, name: &str) -> Option<&'a str> {
    let at = tag.find(&format!(" {name}=\""))? + name.len() + 3;
    tag[at..].split('"').next()
}

/// The canonical FoD payloads a target CompDB lists - FeaturesOnDemand\neutral\cabs\<name>
/// with its size - and the OS version it describes.
fn payloads(xml: &str) -> (Vec<(String, u64)>, Option<String>) {
    let version = xml.find("<CompDB ").and_then(|i| attr(&xml[i..xml[i..].find('>').map_or(xml.len(), |e| i + e)], "OSVersion")).map(str::to_owned);
    let mut out = Vec::new();
    for chunk in xml.split("<PayloadItem ").skip(1) {
        let tag = &chunk[..chunk.find('>').unwrap_or(chunk.len())];
        let (Some(path), Some(size)) = (attr(tag, "Path"), attr(tag, "PayloadSize").and_then(|v| v.parse().ok())) else { continue };
        if let Some(name) = path.strip_prefix("FeaturesOnDemand\\neutral\\cabs\\")
            && name.to_lowercase().ends_with(".cab")
        {
            out.push((name.to_owned(), size));
        }
    }
    (out, version)
}

/// <Prefix>BaselessCompDB_FOD_<lang>.CompDB.xml.cab in the extracted AggregatedMetadata.
fn baseless_lang_cab(agg: &Path, lang: &str) -> Option<PathBuf> {
    let want = format!("baselesscompdb_fod_{lang}.compdb.xml.cab");
    std::fs::read_dir(agg).ok()?.filter_map(|e| e.ok().map(|e| e.path())).find(|p| {
        p.file_name().and_then(|n| n.to_str()).is_some_and(|n| n.to_lowercase().ends_with(&want))
    })
}

/// SHA-256 of a file, base64 - the CompDB's PayloadHash.
async fn sha256_b64(path: &Path) -> Result<String> {
    let out = tokio::process::Command::new("sha256sum").arg(path).output().await?;
    let hex = String::from_utf8_lossy(&out.stdout).split_whitespace().next().unwrap_or("").to_owned();
    let bytes: Vec<u8> = (0..hex.len() / 2).filter_map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()).collect();
    if bytes.len() != 32 {
        bail!("sha256sum {}", path.display());
    }
    use base64::Engine;
    Ok(base64::engine::general_purpose::STANDARD.encode(bytes))
}

/// The Baseless satellite list turned into the ISO's: Type Build, UpdateType Canonical, one
/// Canonical payload per package (FeaturesOnDemand\<lang>\cabsforiso\<id>.cab). Packages
/// not on this ISO are dropped, and features left without a package with them.
pub fn for_iso_xml(baseless: &str, lang: &str, payloads: &HashMap<String, (String, u64)>) -> String {
    let mut out = String::new();
    let mut lines = baseless.lines().peekable();
    let mut block: Vec<&str> = Vec::new();
    let (mut in_feature, mut in_package) = (false, false);
    let keep_ids = |b: &[&str]| -> Vec<String> {
        b.iter().filter_map(|l| l.trim_start().strip_prefix("<Package ID=\"").and_then(|r| r.split('"').next())).map(str::to_owned).collect()
    };
    while let Some(line) = lines.next() {
        let t = line.trim_start();
        let indent = line.len() - t.len();
        // Top-level features and packages are four deep in Microsoft's pretty-printed XML.
        if indent == 4 && t.starts_with("<Feature ") && !t.ends_with("/>") {
            in_feature = true;
            block.clear();
        }
        if indent == 4 && t.starts_with("<Package ") && !t.ends_with("/>") {
            in_package = true;
            block.clear();
        }
        if in_feature {
            block.push(line);
            if indent == 4 && t == "</Feature>" {
                in_feature = false;
                let ids = keep_ids(&block);
                if ids.iter().any(|i| payloads.contains_key(&i.to_lowercase())) {
                    for l in &block {
                        let id = l.trim_start().strip_prefix("<Package ID=\"").and_then(|r| r.split('"').next());
                        if id.is_none_or(|i| payloads.contains_key(&i.to_lowercase())) {
                            out += l;
                            out.push('\n');
                        }
                    }
                }
            }
            continue;
        }
        if in_package {
            block.push(line);
            if indent == 4 && t == "</Package>" {
                in_package = false;
                let id = block[0].trim_start().strip_prefix("<Package ID=\"").and_then(|r| r.split('"').next()).unwrap_or("").to_owned();
                if let Some((hash, size)) = payloads.get(&id.to_lowercase()) {
                    let mut skipping = false;
                    for l in &block {
                        let lt = l.trim_start();
                        if lt == "<Payload>" {
                            skipping = true;
                            out += &format!(
                                "      <Payload>\n        <PayloadItem PayloadHash=\"{hash}\" PayloadSize=\"{size}\" Path=\"FeaturesOnDemand\\{lang}\\cabsforiso\\{id}.cab\" PayloadType=\"Canonical\" />\n      </Payload>\n"
                            );
                            continue;
                        }
                        if skipping {
                            if lt == "</Payload>" {
                                skipping = false;
                            }
                            continue;
                        }
                        out += l;
                        out.push('\n');
                    }
                }
            }
            continue;
        }
        let l = if t.starts_with("<CompDB ") {
            line.replace("Type=\"Baseless\"", "Type=\"Build\"").replace("Name=\"Baseless~", "Name=\"Build~").replace("_FOD~~", "_FOD_ISO~~")
        } else {
            line.replace("Value=\"Baseless\"", "Value=\"Canonical\"")
        };
        out += &l;
        out.push('\n');
    }
    out
}

/// Writes <Prefix>TargetCompDBForISO_FOD_<lang>.xml.cab for the satellites on the ISO.
async fn for_iso_compdb(log: &JobLog, dir: &Path, agg: &Path, lang: &str, sats: &[(String, uup::File)], dl: &Path) -> Result<Option<PathBuf>> {
    let Some(cab) = baseless_lang_cab(agg, lang) else { return Ok(None) };
    let x = dir.join("forso");
    let _ = tokio::fs::remove_dir_all(&x).await;
    tokio::fs::create_dir_all(&x).await?;
    run(log, "cabextract", &["-q", "-d", &x.display().to_string(), &cab.display().to_string()]).await?;
    let xml_in = std::fs::read_dir(&x)?.filter_map(|e| e.ok().map(|e| e.path())).find(|p| p.extension().is_some_and(|e| e == "xml")).context("no XML in the Baseless list")?;
    let text = String::from_utf8_lossy(&tokio::fs::read(&xml_in).await?).trim_start_matches('\u{feff}').to_owned();
    let mut payloads = HashMap::new();
    for (canonical, f) in sats {
        let id = canonical.trim_end_matches(".cab").to_lowercase();
        payloads.insert(id, (sha256_b64(&dl.join(&f.name)).await?, f.size));
    }
    let prefix = cab.file_name().and_then(|n| n.to_str()).and_then(|n| n.split("BaselessCompDB").next()).unwrap_or("Server").to_owned();
    let xml = for_iso_xml(&text, lang, &payloads);
    let name = format!("{prefix}TargetCompDBForISO_FOD_{lang}.xml");
    let out = dir.join(&name);
    tokio::fs::write(&out, xml).await?;
    let cab_out = dir.join(format!("{name}.cab"));
    let _ = tokio::fs::remove_file(&cab_out).await;
    // gcab -c: the file under its plain name inside the cabinet, MSZIP compressed.
    run(log, "gcab", &["-c", "-n", "-z", &cab_out.display().to_string(), &out.display().to_string()]).await?;
    Ok(Some(cab_out))
}

/// What one FoD ISO build makes: the volid and what is on it.
pub struct Built {
    pub volid: String,
    pub packages: usize,
    pub satellites: usize,
}

/// A Languages and Optional Features ISO, the way Microsoft lays it out
/// (LanguagesAndOptionalFeatures\ with the canonical .cab names, metadata\ with the target
/// CompDBs that list them), from the newest build of the source's product - every Feature
/// on Demand but the language ones, plus the satellites of one language. Plain Linux work:
/// the UUP files are the canonical packages already, their names and sizes in Microsoft's
/// own CompDBs.
#[allow(clippy::too_many_arguments)]
pub async fn build_uup(pve: &Pve, log: &JobLog, web: &reqwest::Client, work: &Path, node: &str, storage: &str, src: &Source, lang: &str) -> Result<Built> {
    let prod = uup::product(src.product).context("no such product in the catalog")?;
    let mut pr = Progress::new(log, format!("Building the {} Features on Demand ISO", src.name));
    let dir: PathBuf = work.join(format!("fod-{}", uuid::Uuid::new_v4().simple()));
    // Its own cache: a media build's files share names with these, not content.
    let dl = work.join("uup-files").join(format!("fod-{}", src.key));
    tokio::fs::create_dir_all(&dl).await?;
    let result: Result<Built> = async {
        pr.stage(0.0, 3.0, "asking the catalog");
        let build = uup::product_builds(web, prod, false).await?.into_iter().next().with_context(|| format!("the catalog lists no {} build", prod.name))?;
        log.get(format!("Asking the UUP dump catalog for the files of {} ({})", build.title, build.uuid)).await;
        let all = uup::files_all(web, &build.uuid).await?;
        let uuid = build.uuid.clone();
        let refresh = || {
            let uuid = uuid.clone();
            async move { uup::files_all(web, &uuid).await }
        };

        // ---- Microsoft's CompDBs: which packages, under which names ----
        let mut meta: Vec<uup::File> = all.iter().filter(|f| f.name.ends_with(".AggregatedMetadata.cab")).cloned().collect();
        if meta.is_empty() {
            bail!("the catalog lists no metadata for {}", build.title);
        }
        pr.stage(3.0, 5.0, "reading Microsoft's package lists");
        uup::download_all(web, log, &mut pr, &mut meta, &dl, &refresh).await?;
        let agg = dir.join("aggregated");
        tokio::fs::create_dir_all(&agg).await?;
        run(log, "cabextract", &["-q", "-d", &agg.display().to_string(), &dl.join(&meta[0].name).display().to_string()]).await?;
        let mut listed: Vec<(String, u64)> = Vec::new();
        let mut compdbs: Vec<PathBuf> = Vec::new();
        let mut version = String::new();
        let mut entries: Vec<PathBuf> = std::fs::read_dir(&agg)?.filter_map(|e| e.ok().map(|e| e.path())).collect();
        entries.sort();
        for cab in entries {
            let name = cab.file_name().and_then(|n| n.to_str()).unwrap_or("").to_owned();
            if !name.contains("TargetCompDB") || !name.ends_with(".xml.cab") {
                continue;
            }
            let x = dir.join("compdb");
            let _ = tokio::fs::remove_dir_all(&x).await;
            tokio::fs::create_dir_all(&x).await?;
            run(log, "cabextract", &["-q", "-d", &x.display().to_string(), &cab.display().to_string()]).await?;
            let mut found = false;
            for xml in std::fs::read_dir(&x)?.filter_map(|e| e.ok().map(|e| e.path())) {
                let text = String::from_utf8_lossy(&tokio::fs::read(&xml).await?).into_owned();
                let (list, v) = payloads(&text);
                if !list.is_empty() {
                    found = true;
                    if version.is_empty() {
                        version = v.unwrap_or_default();
                    }
                    for p in list {
                        if !listed.iter().any(|(n, _)| n == &p.0) {
                            listed.push(p);
                        }
                    }
                }
            }
            // On the ISO's metadata\ exactly what the Languages and Optional Features ISO has:
            // the FoD list, the FoD metadata, _Neutral and _Conditions (the per-edition and
            // language pack lists also name FoD packages, but are not the ISO's). Server 2022
            // has no FoD list of its own - its FoDs are in _Neutral.
            let _ = found;
            let keep = ["TargetCompDB_FOD_Neutral.xml.cab", "TargetCompDB_FOD_Metadata_Neutral.xml.cab", "TargetCompDB_Neutral.xml.cab", "TargetCompDB_Conditions.xml.cab"];
            if keep.iter().any(|k| name.ends_with(k)) {
                compdbs.push(cab);
            }
        }
        if listed.is_empty() {
            bail!("Microsoft's package lists for {} name no Features on Demand", build.title);
        }
        let base = version.split('.').nth(2).filter(|b| !b.is_empty()).unwrap_or_else(|| build.build.split('.').next().unwrap_or(""));
        log.ok(format!("{} Features on Demand packages listed for {} (build {base}), {} package list(s)", listed.len(), src.name, compdbs.len())).await;

        // ---- the packages: canonical name -> the UUP file ----
        let by_key: HashMap<String, &uup::File> = all
            .iter()
            .filter(|f| f.name.to_lowercase().ends_with(".cab"))
            .map(|f| (f.name[..f.name.len() - 4].to_lowercase(), f))
            .collect();
        let mut wanted: Vec<(String, uup::File)> = Vec::new();
        let (mut skipped_n, mut missing) = (0, Vec::new());
        let lang_l = lang.to_lowercase();
        for (canonical, size) in &listed {
            if skipped(canonical) {
                skipped_n += 1;
                continue;
            }
            match by_key.get(&uup_key(canonical)) {
                Some(f) if f.size == *size => wanted.push((canonical.clone(), (*f).clone())),
                _ => missing.push(canonical.clone()),
            }
        }
        let packages = wanted.len();
        // Each package's satellite in the image's language: X-amd64-en-us.cab.
        for i in 0..packages {
            let (canonical, _) = wanted[i].clone();
            let key = format!("{}-{lang_l}", uup_key(&canonical));
            if let Some(f) = by_key.get(&key) {
                let stem = canonical.trim_end_matches(".cab").trim_end_matches('~').trim_end_matches('~');
                let tail = &f.name[f.name.len() - 4 - lang.len()..f.name.len() - 4];
                wanted.push((format!("{stem}~{tail}~.cab"), (*f).clone()));
            }
        }
        let satellites = wanted.len() - packages;
        if let Some(f) = all.iter().find(|f| f.name.eq_ignore_ascii_case("FoDMetadata_Client.cab")) {
            wanted.push(("FoDMetadata_Client.cab".into(), f.clone()));
        }
        // The FoD metadata servicing packages sit in the official ISO's root as well.
        for f in all.iter().filter(|f| f.name.starts_with("Microsoft-Windows-FodMetadataServicing-") && f.name.ends_with("-Package.cab")) {
            wanted.push((f.name.clone(), f.clone()));
        }
        if !missing.is_empty() {
            log.warn(format!("{} listed package(s) not in the catalog's files - left out: {}", missing.len(), missing.iter().take(5).cloned().collect::<Vec<_>>().join(", "))).await;
        }
        let total: u64 = wanted.iter().map(|(_, f)| f.size).sum();
        log.ok(format!(
            "{packages} package(s) and {satellites} {lang} satellite(s), {:.2} GB - {skipped_n} language and Mixed Reality package(s) left out",
            total as f64 / 1e9
        ))
        .await;

        pr.stage(5.0, 80.0, "downloading from Microsoft");
        let mut files: Vec<uup::File> = wanted.iter().map(|(_, f)| f.clone()).collect();
        files.dedup_by(|a, b| a.name == b.name);
        uup::download_all(web, log, &mut pr, &mut files, &dl, &refresh).await?;

        // ---- the ISO ----
        pr.stage(80.0, 88.0, "building the ISO");
        let root = dir.join("iso/LanguagesAndOptionalFeatures");
        tokio::fs::create_dir_all(root.join("metadata")).await?;
        for (canonical, f) in &wanted {
            let (from, to) = (dl.join(&f.name), root.join(canonical));
            // Same volume: a hard link, no copy.
            if std::fs::hard_link(&from, &to).is_err() {
                tokio::fs::copy(&from, &to).await.with_context(|| format!("copying {}", f.name))?;
            }
        }
        for cab in &compdbs {
            tokio::fs::copy(cab, root.join("metadata").join(cab.file_name().unwrap())).await?;
        }
        // The satellites' own list (<Prefix>TargetCompDBForISO_FOD_<lang>), which Microsoft
        // puts on the ISO but not into UUP: made from UUP's Baseless list of the same
        // packages, its express payloads replaced by the full CABs' SHA-256 and size.
        match for_iso_compdb(log, &dir, &agg, &lang_l, &wanted[packages..packages + satellites], &dl).await {
            Ok(Some(cab)) => {
                let n = cab.file_name().unwrap().to_owned();
                tokio::fs::copy(&cab, root.join("metadata").join(&n)).await?;
                log.ok(format!("metadata\\{}: the {satellites} {lang} satellites, as the Languages and Optional Features ISO lists them", n.to_string_lossy())).await;
            }
            Ok(None) => log.line(format!("No Baseless FoD list for {lang} in the metadata - the satellites are on the ISO without a list of their own")).await,
            Err(e) => log.warn(format!("The satellites' list could not be made: {e:#}")).await,
        }
        // fod-<os>-<build>: one FoD ISO per release (its satellites are the studio's language).
        let name = format!("fod-{}-{base}.iso", src.short);
        let iso = dir.join(&name);
        let label: String = format!("FOD_{}_{base}", src.short.to_uppercase().replace('-', "_")).chars().take(32).collect();
        log.run(format!("Building the ISO: {name}")).await;
        let (iso_s, tree_s) = (iso.display().to_string(), dir.join("iso").display().to_string());
        run(log, "genisoimage", &["-quiet", "-udf", "-iso-level", "3", "-allow-limited-size", "-V", &label, "-o", &iso_s, &tree_s]).await?;
        let size = tokio::fs::metadata(&iso).await?.len();
        log.ok(format!("{name}: {:.2} GB", size as f64 / 1e9)).await;

        pr.stage(88.0, 100.0, "uploading to PVE");
        let volid = format!("{storage}:iso/{name}");
        if pve.storage_content(node, storage, "iso").await?.iter().any(|v| v.volid == volid) {
            pve.delete_volume(node, &volid).await?;
        }
        log.run(format!("Uploading into {storage} on {node}")).await;
        let volid = pve.upload(node, storage, "iso", &iso, &name).await?;
        log.ok(format!("{volid} is ready - new {} VMs install their capabilities from it", src.name)).await;
        Ok(Built { volid, packages, satellites })
    }
    .await;
    let _ = tokio::fs::remove_dir_all(&dir).await;
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layouts() {
        let server = vec![
            "LanguagesAndOptionalFeatures/Microsoft-Windows-Server-AppCompat-FoD-Package~31bf3856ad364e35~amd64~~.cab".to_owned(),
            "LanguagesAndOptionalFeatures/metadata/x.xml".to_owned(),
        ];
        assert_eq!(classify(&server).unwrap().root, "LanguagesAndOptionalFeatures");
        let client = vec!["Rsat.ActiveDirectory.DS-LDS.Tools-FoD-Package~31bf3856ad364e35~amd64~~.cab".to_owned()];
        assert_eq!(classify(&client).unwrap().root, "");
        assert!(classify(&["sources/install.wim".to_owned()]).is_err());
    }

    #[test]
    fn uup_names() {
        assert_eq!(uup_key("OpenSSH-Server-Package~31bf3856ad364e35~amd64~~.cab"), "openssh-server-package-amd64");
        assert_eq!(uup_key("Microsoft-Windows-DNS-Tools-FoD-Package~31bf3856ad364e35~wow64~en-US~.cab"), "microsoft-windows-dns-tools-fod-package-wow64-en-us");
        assert!(skipped("Microsoft-Windows-LanguageFeatures-Basic-de-de-Package~31bf3856ad364e35~amd64~~.cab"));
        assert!(!skipped("Microsoft-Windows-Server-AppCompat-FoD-Package~31bf3856ad364e35~amd64~~.cab"));
    }

    #[test]
    fn for_iso() {
        let baseless = r#"<?xml version="1.0" encoding="utf-8"?>
<CompDB OSVersion="10.0.26100.1" Type="Baseless" Name="Baseless~amd64~Server_FOD~~en-us" xmlns="x">
  <Tags Type="Language">
    <Tag Name="UpdateType" Value="Baseless" />
  </Tags>
  <Features>
    <Feature Type="OnDemandFeature" FeatureID="Rsat.Dns.Tools~~1.0" FMID="MSDN" Group="Microsoft">
      <Packages>
        <Package ID="DNS~31bf3856ad364e35~amd64~en-us~" PackageType="SatellitePackage" />
        <Package ID="DNS~31bf3856ad364e35~wow64~en-us~" PackageType="SatellitePackage" />
      </Packages>
    </Feature>
    <Feature Type="OnDemandFeature" FeatureID="Language.Speech~~~en-US~0.0.1.0" FMID="MSDN" Group="Microsoft">
      <Packages>
        <Package ID="Speech~31bf3856ad364e35~amd64~en-us~" PackageType="SatellitePackage" />
      </Packages>
    </Feature>
  </Features>
  <Packages>
    <Package ID="DNS~31bf3856ad364e35~amd64~en-us~" InstalledSize="1" Version="10.0.26100.1">
      <Payload>
        <PayloadItem PayloadHash="a" PayloadSize="1" Path="FeaturesOnDemand\en-usaseless\DNS.cab" PayloadType="ExpressCab" />
        <PayloadItem PayloadHash="b" PayloadSize="2" Path="FeaturesOnDemand\en-usaseless\DNS.psf" PayloadType="ExpressPSF" />
      </Payload>
    </Package>
    <Package ID="Speech~31bf3856ad364e35~amd64~en-us~" InstalledSize="1" Version="10.0.26100.1">
      <Payload>
        <PayloadItem PayloadHash="c" PayloadSize="3" Path="x" PayloadType="ExpressCab" />
      </Payload>
    </Package>
  </Packages>
</CompDB>"#;
        let p = HashMap::from([("dns~31bf3856ad364e35~amd64~en-us~".to_owned(), ("H=".to_owned(), 42u64))]);
        let x = for_iso_xml(baseless, "en-us", &p);
        assert!(x.contains(r#"Type="Build""#) && x.contains("Server_FOD_ISO~~en-us") && x.contains(r#"Value="Canonical""#));
        assert!(x.contains(r#"PayloadHash="H=" PayloadSize="42" Path="FeaturesOnDemand\en-us\cabsforiso\DNS~31bf3856ad364e35~amd64~en-us~.cab" PayloadType="Canonical""#));
        assert!(!x.contains("Speech") && !x.contains("wow64") && !x.contains("Express"));
    }

    #[test]
    fn compdb_payloads() {
        let xml = r#"<CompDB Product="Server" OSVersion="10.0.26100.1" Type="Build"><Packages>
          <PayloadItem PayloadHash="x" PayloadSize="2329588" Path="FeaturesOnDemand\neutral\cabs\OpenSSH-Server-Package~31bf3856ad364e35~amd64~~.cab" PayloadType="Canonical" />
          <PayloadItem PayloadHash="y" PayloadSize="9" Path="UUP\DESKTOP\FoDMetadata\FoDMetadata_Client.cab" PayloadType="Canonical" /></Packages></CompDB>"#;
        let (list, v) = payloads(xml);
        assert_eq!(list, vec![("OpenSSH-Server-Package~31bf3856ad364e35~amd64~~.cab".to_owned(), 2329588)]);
        assert_eq!(v.as_deref(), Some("10.0.26100.1"));
    }
}
