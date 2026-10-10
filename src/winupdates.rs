//! What each update of a UUP set is, and where and in which order it goes.
//!
//! Microsoft's media servicing steps (Learn: "Update Windows installation media with
//! Dynamic Update") name four kinds with a fixed place each: the servicing stack first (in
//! WinRE, the install image and WinPE), the Safe OS dynamic update into WinRE only, the
//! cumulative update last before the cleanup (its checkpoints first, since 24H2), .NET
//! after the cleanup, and the Setup dynamic update - a CAB of files, not a package - into
//! the media's sources\. Every failure stops the media; none is shipped.
//!
//! What a package is comes first from Microsoft's own metadata: the set's
//! AggregatedMetadata, and inside each .msu its onepackage.AggregatedMetadata.cab, name
//! every update by its CompDB - LCUCompDB_KB… (cumulative, with the build it needs and the
//! build it makes), SSUCompDB_KB…, SafeOSDUCompDB_KB…, SetupDUCompDB_KB…, EKBUpdateCompDB_KB…
//! (enablement). The checkpoint chain follows from those builds. Where a set has no
//! metadata (Server 2022 and older) or names nothing (.NET), the package itself says it -
//! update.mum's package name and the manifests it carries, as abbodi1406's W10UI (the
//! updater behind UUP dump's Windows converter) tells them apart.
//!
//! A Windows 11 23H2 set carries its cumulative update as Windows11.0-KB…-x64.wim and .psf
//! (PSFX). Its .msu is put together here as UUP dump's converter does (:uups_msu), the way
//! Microsoft's own .msu is built: an uncompressed WIM ("content") of the package's .wim
//! and .psf, the servicing stack, DesktopDeployment and onepackage.AggregatedMetadata.cab.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};

use anyhow::{bail, Context, Result};

use crate::uup;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Kind {
    /// A standalone servicing stack (SSU-20348.5614-x64.cab) - published only when a
    /// cumulative update needs it first.
    ServicingStack,
    /// Package_for_RollupFix: the cumulative update, or one of its checkpoints.
    Cumulative,
    /// Package_for_SafeOSDU: WinRE's own update.
    SafeOs,
    /// No update.mum: Setup's files, expanded into the media's sources\.
    Setup,
    /// .NET (netfx4): after the cleanup.
    DotNet,
    /// Boot firmware / Secure Boot.
    SecureBoot,
    /// A feature's enablement package (24H2 -> 25H2).
    Enablement,
    /// Any other package: into the install image, before the cumulative update.
    Other,
}

impl Kind {
    pub fn label(self) -> &'static str {
        match self {
            Kind::ServicingStack => "servicing stack",
            Kind::Cumulative => "cumulative update",
            Kind::SafeOs => "Safe OS update",
            Kind::Setup => "Setup update",
            Kind::DotNet => ".NET update",
            Kind::SecureBoot => "Secure Boot update",
            Kind::Enablement => "enablement package",
            Kind::Other => "update",
        }
    }
}

/// A cumulative update as its LCUCompDB describes it: the build it needs and the one it makes.
#[derive(Debug, Clone, PartialEq)]
pub struct Lcu {
    /// Package_for_RollupFix's version: 26100.33438.1.19.
    pub version: String,
    /// OSVersion: the build it is made on (26100.1742 - its checkpoint's target).
    pub base: String,
    /// TargetOSVersion: the build it makes (26100.33438).
    pub target: String,
}

/// What Microsoft's metadata says about a set.
#[derive(Debug, Default, Clone)]
pub struct Meta {
    /// KB -> kind, by the CompDB that names it.
    pub kinds: HashMap<String, Kind>,
    /// KB -> the cumulative update's builds.
    pub lcus: HashMap<String, Lcu>,
    /// KB -> its LCUCompDB_KB….xml.cab, for an .msu put together here.
    pub lcu_db: HashMap<String, PathBuf>,
    /// The servicing stack's SSUCompDB_KB….xml.cab (not the express one), and the SSU-*.cab
    /// it names (Path=).
    pub ssu_db: Option<(PathBuf, String)>,
    /// Any metadata at all.
    pub present: bool,
}

/// "10.0.26100.1742" -> "26100.1742".
fn os_version(v: &str) -> String {
    v.strip_prefix("10.0.").unwrap_or(v).to_owned()
}

/// An attribute of the first tag that starts with `tag` (and contains `with`, if given).
fn tag_attr(xml: &str, tag: &str, with: Option<&str>, attr: &str) -> Option<String> {
    let mut from = 0;
    while let Some(at) = xml[from..].find(tag).map(|i| from + i) {
        let end = xml[at..].find('>').map(|e| at + e).unwrap_or(xml.len());
        let t = &xml[at..end];
        from = end;
        if with.is_some_and(|w| !t.contains(w)) {
            continue;
        }
        let key = format!(" {attr}=\"");
        if let Some(i) = t.find(&key) {
            return Some(t[i + key.len()..].split('"').next().unwrap_or("").to_owned());
        }
    }
    None
}

/// An LCUCompDB: the builds, and the RollupFix package's version.
pub fn parse_lcu_compdb(xml: &str) -> Option<Lcu> {
    let base = os_version(&tag_attr(xml, "<CompDB", None, "OSVersion")?);
    let target = os_version(&tag_attr(xml, "<CompDB", None, "TargetOSVersion")?);
    let version = tag_attr(xml, "<Package ", Some("Package_for_RollupFix"), "Version").unwrap_or_default();
    Some(Lcu { version, base, target })
}

async fn run_ok(prog: &str, args: &[&str]) -> bool {
    tokio::process::Command::new(prog).args(args).output().await.map(|o| o.status.success()).unwrap_or(false)
}

/// The KB a CompDB file is named for: LCUCompDB_KB5129242.xml.cab -> KB5129242.
fn compdb_kb(name: &str) -> Option<String> {
    let at = name.find("_KB")? + 1;
    let digits: String = name[at + 2..].chars().take_while(|c| c.is_ascii_digit()).collect();
    (!digits.is_empty()).then(|| format!("KB{digits}"))
}

/// Reads an AggregatedMetadata cab (a set's, or an .msu's onepackage one) into `work`.
pub async fn read_meta(cab: &Path, work: &Path) -> Meta {
    let mut m = Meta::default();
    let dir = work.join(format!("meta-{}", cab.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default()));
    let _ = tokio::fs::remove_dir_all(&dir).await;
    if tokio::fs::create_dir_all(&dir).await.is_err() || !run_ok("cabextract", &["-q", "-d", &dir.display().to_string(), &cab.display().to_string()]).await {
        return m;
    }
    let Ok(mut rd) = tokio::fs::read_dir(&dir).await else { return m };
    let mut names = Vec::new();
    while let Ok(Some(e)) = rd.next_entry().await {
        names.push(e.file_name().to_string_lossy().into_owned());
    }
    names.sort();
    for name in names {
        let path = dir.join(&name);
        let Some(kb) = compdb_kb(&name) else { continue };
        if name.starts_with("LCUCompDB_") || name.starts_with("outer.AggregatedMetadata_") {
            // LCUCompDB_KB….xml.cab (a cab of the XML), or an outer cab holding LCUCompDB_KB….xml.
            let x = dir.join(format!("x-{kb}"));
            let _ = tokio::fs::create_dir_all(&x).await;
            if run_ok("cabextract", &["-q", "-d", &x.display().to_string(), &path.display().to_string()]).await
                && let Ok(mut xr) = tokio::fs::read_dir(&x).await
            {
                while let Ok(Some(e)) = xr.next_entry().await {
                    let n = e.file_name().to_string_lossy().into_owned();
                    if n.starts_with("LCUCompDB_") && n.ends_with(".xml") {
                        let raw = tokio::fs::read(e.path()).await.unwrap_or_default();
                        if let Some(l) = parse_lcu_compdb(&String::from_utf8_lossy(&raw)) {
                            m.lcus.insert(kb.clone(), l);
                        }
                    }
                }
            }
            m.kinds.insert(kb.clone(), Kind::Cumulative);
            if name.starts_with("LCUCompDB_") {
                m.lcu_db.insert(kb, path);
            }
        } else if name.starts_with("SSUCompDB_") {
            if !name.contains("-express") {
                // The file it names: only that one goes into an .msu beside it (the converter's :doSSU).
                let x = dir.join(format!("ssu-{kb}"));
                let _ = tokio::fs::create_dir_all(&x).await;
                let mut file = String::new();
                if run_ok("cabextract", &["-q", "-d", &x.display().to_string(), &path.display().to_string()]).await
                    && let Ok(mut xr) = tokio::fs::read_dir(&x).await
                {
                    while let Ok(Some(e)) = xr.next_entry().await {
                        let raw = tokio::fs::read(e.path()).await.unwrap_or_default();
                        if let Some(p) = tag_attr(&String::from_utf8_lossy(&raw), "<PayloadItem", None, "Path") {
                            file = p;
                        }
                    }
                }
                m.ssu_db = Some((path, file));
            }
        } else if name.starts_with("SafeOSDUCompDB_") {
            m.kinds.insert(kb, Kind::SafeOs);
        } else if name.starts_with("SetupDUCompDB_") {
            m.kinds.insert(kb, Kind::Setup);
        } else if name.starts_with("EKBUpdateCompDB_") {
            m.kinds.insert(kb, Kind::Enablement);
        }
    }
    m.present = !m.kinds.is_empty();
    m
}

/// An .msu's own metadata (onepackage.AggregatedMetadata.cab inside it).
pub async fn read_msu_meta(msu: &Path, work: &Path) -> Meta {
    let dir = work.join(format!("msu-meta-{}", msu.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default()));
    let _ = tokio::fs::remove_dir_all(&dir).await;
    let _ = tokio::fs::create_dir_all(&dir).await;
    let (m, d) = (msu.display().to_string(), dir.display().to_string());
    let got = match format(msu).await {
        Some("wim") => run_ok("wimlib-imagex", &["extract", &m, "1", "/onepackage.AggregatedMetadata.cab", &format!("--dest-dir={d}"), "--no-acls"]).await,
        Some("cab") => run_ok("cabextract", &["-q", "-F", "onepackage.AggregatedMetadata.cab", "-d", &d, &m]).await,
        _ => false,
    };
    let cab = dir.join("onepackage.AggregatedMetadata.cab");
    if !got || !cab.exists() {
        return Meta::default();
    }
    read_meta(&cab, &dir).await
}

/// One update as it was read.
#[derive(Debug, Clone)]
pub struct Pkg {
    pub file: uup::File,
    pub kind: Kind,
    /// update.mum's package name (Package_for_RollupFix, Package_for_KB5007374...).
    pub identity: String,
    /// Its version: 20348.5622.1.16.
    pub version: String,
    pub arch: String,
    /// Its kind came from Microsoft's metadata or from its own update.mum - not guessed.
    pub known: bool,
    /// A cumulative update's builds, from its LCUCompDB.
    pub lcu: Option<Lcu>,
    /// Where the metadata and the package disagree.
    pub note: Option<String>,
    /// Why it cannot be used at all (an express package without its payload, Hotpatch,
    /// Defender definitions, another processor).
    pub unusable: Option<String>,
}

/// "26100.33438.1.19" as numbers, for comparing.
fn nums(v: &str) -> Vec<u64> {
    v.split('.').map(|p| p.parse().unwrap_or(0)).collect()
}

impl Pkg {
    /// Its revision for "newest": the version as numbers - or, for a package that names
    /// none, its KB number.
    fn rev(&self) -> Vec<u64> {
        if let Some(l) = &self.lcu {
            return nums(&l.target);
        }
        if self.version.is_empty() {
            return vec![self.kb().and_then(|kb| kb[2..].parse().ok()).unwrap_or(0)];
        }
        nums(&self.version)
    }

    pub fn kb(&self) -> Option<String> {
        crate::media::kb_of(&self.file.name)
    }

    /// "KB5122882" or the file name, for the log.
    pub fn short(&self) -> String {
        self.kb().unwrap_or_else(|| self.file.name.clone())
    }

    /// A Windows 11 23H2 cumulative update as .wim + .psf: its .msu is put together here.
    pub fn is_psfx(&self) -> bool {
        self.kind == Kind::Cumulative && self.file.name.to_lowercase().ends_with(".wim")
    }
}

/// What a package says about itself: its file list, and update.mum's text.
pub struct Contents {
    pub files: Vec<String>,
    pub mum: Option<String>,
}

/// A CAB (MSCF) or a WIM (since 24H2 an .msu is one: MSWIM).
async fn format(path: &Path) -> Option<&'static str> {
    use tokio::io::AsyncReadExt;
    let mut f = tokio::fs::File::open(path).await.ok()?;
    let mut magic = [0u8; 8];
    f.read_exact(&mut magic).await.ok()?;
    if magic.starts_with(b"MSCF") {
        Some("cab")
    } else if magic.starts_with(b"MSWIM") {
        Some("wim")
    } else {
        None
    }
}

async fn output(prog: &str, args: &[&str]) -> Option<String> {
    let o = tokio::process::Command::new(prog).args(args).output().await.ok()?;
    o.status.success().then(|| String::from_utf8_lossy(&o.stdout).into_owned())
}

pub async fn read(path: &Path) -> Contents {
    let p = path.display().to_string();
    match format(path).await {
        Some("cab") => {
            let list = output("cabextract", &["-l", &p]).await.unwrap_or_default();
            // cabextract -l: "  size | date time | name"
            let files: Vec<String> = list.lines().filter(|l| l.contains('|')).filter_map(|l| l.rsplit('|').next()).map(|n| n.trim().to_owned()).filter(|n| !n.is_empty() && n != "File name").collect();
            let mum = if files.iter().any(|f| f.eq_ignore_ascii_case("update.mum")) { output("cabextract", &["-q", "-p", "-F", "update.mum", &p]).await } else { None };
            Contents { files, mum }
        }
        Some("wim") => {
            let list = output("wimlib-imagex", &["dir", &p, "1"]).await.unwrap_or_default();
            let files: Vec<String> = list.lines().map(|l| l.trim().trim_start_matches('/').to_owned()).filter(|n| !n.is_empty()).collect();
            let mum = if files.iter().any(|f| f.eq_ignore_ascii_case("update.mum")) { output("wimlib-imagex", &["extract", &p, "1", "/update.mum", "--to-stdout"]).await } else { None };
            Contents { files, mum }
        }
        _ => Contents { files: vec![], mum: None },
    }
}

/// An attribute of update.mum's first assemblyIdentity (the package's own).
fn identity_attr(mum: &str, attr: &str) -> String {
    let Some(at) = mum.find("<assemblyIdentity") else { return String::new() };
    let tag = &mum[at..mum[at..].find('>').map(|e| at + e).unwrap_or(mum.len())];
    let key = format!("{attr}=\"");
    tag.find(&key).map(|i| tag[i + key.len()..].split('"').next().unwrap_or("").to_owned()).unwrap_or_default()
}

/// What the package itself says, W10UI's order of questions (first match wins); then what
/// Microsoft's metadata says, which counts where it names the KB.
pub fn classify(file: &uup::File, c: &Contents, meta: &Meta) -> Pkg {
    let mut pkg = classify_contents(file, c);
    let Some(kb) = pkg.kb() else { return pkg };
    pkg.lcu = meta.lcus.get(&kb).cloned();
    if let Some(&k) = meta.kinds.get(&kb) {
        if pkg.known && pkg.kind != k {
            pkg.note = Some(format!("Microsoft's metadata names it a {}, the package reads as a {} - taken as the metadata says", k.label(), pkg.kind.label()));
        }
        pkg.kind = k;
        pkg.known = true;
    }
    pkg
}

fn classify_contents(file: &uup::File, c: &Contents) -> Pkg {
    let lower: Vec<String> = c.files.iter().map(|f| f.to_lowercase()).collect();
    let has = |s: &str| lower.iter().any(|f| f.contains(s));
    let mut pkg = Pkg { file: file.clone(), kind: Kind::Other, identity: String::new(), version: String::new(), arch: String::new(), known: false, lcu: None, note: None, unusable: None };
    let name = file.name.to_lowercase();
    if c.files.is_empty() {
        // Not a CAB or WIM the studio can read: judged by its name, and said so (known false).
        pkg.kind = if name.starts_with("ssu-") { Kind::ServicingStack } else if name.ends_with(".msu") { Kind::Cumulative } else { Kind::Other };
        return pkg;
    }
    let Some(mum) = &c.mum else {
        // A .msu without one carries its package inside - since 24H2 as Windows11.0-KB…-x64.wim
        // and .psf beside its own SSU-*.cab. Taken for a cumulative update; its own metadata
        // (read_msu_meta) is what makes it known.
        if name.ends_with(".msu") {
            pkg.kind = Kind::Cumulative;
            if has("hotpatch") {
                pkg.unusable = Some("a Hotpatch update - only for running machines enrolled in Hotpatch".into());
            }
        } else if has("defender") && has(".xml") {
            pkg.unusable = Some("Defender definitions - not part of the media".into());
        } else {
            pkg.kind = Kind::Setup;
            pkg.known = true;
        }
        return pkg;
    };
    pkg.known = true;
    pkg.identity = identity_attr(mum, "name");
    pkg.version = identity_attr(mum, "version");
    pkg.arch = identity_attr(mum, "processorArchitecture");
    let id = pkg.identity.to_lowercase();
    let m = mum.to_lowercase();
    pkg.kind = if id.contains("package_for_safeosdu") || (!m.contains("package_for_rollupfix") && (has("winre-tools") || has("winpe_tools") || has("sysreset") || has("rejuvenation"))) {
        Kind::SafeOs
    } else if id.contains("package_for_rollupfix") || m.contains("package_for_rollupfix") {
        Kind::Cumulative
    } else if id.contains("servicingstack") || has("servicingstack") || name.starts_with("ssu-") {
        Kind::ServicingStack
    } else if has("netfx4") || id.contains("dotnet") || name.contains("-ndp") {
        Kind::DotNet
    } else if has("boot-firmwareupdate") || has("secureboot") {
        Kind::SecureBoot
    } else if has("enablement-package") {
        Kind::Enablement
    } else {
        Kind::Other
    };
    if id.contains("hotpatch") || has("hotpatchcompdb") {
        pkg.unusable = Some("a Hotpatch update - only for running machines enrolled in Hotpatch".into());
    } else if has(".psf.cix.xml") && !name.ends_with(".wim") {
        // An express CAB (before 22621): its .psf would have to be expanded into it. A PSFX
        // .wim (23H2) is put together into an .msu with its .psf instead (build_msu).
        pkg.unusable = Some("an express package - its .psf payload is not part of what the studio downloads".into());
    } else if !pkg.arch.is_empty() && !matches!(pkg.arch.to_lowercase().as_str(), "amd64" | "neutral" | "wow64" | "msil") {
        pkg.unusable = Some(format!("for {} - the media is x64", pkg.arch));
    }
    pkg
}

/// The plan for one set: what goes where, in the order it goes in.
#[derive(Debug, Default)]
pub struct Plan {
    /// The install image, in order: the servicing stack, Secure Boot, the other packages,
    /// the cumulative update (its checkpoints first).
    pub image: Vec<Pkg>,
    /// .NET, after the image's cleanup.
    pub dotnet: Vec<Pkg>,
    /// WinRE: the Safe OS update (the servicing stack goes in ahead of it).
    pub winre: Vec<Pkg>,
    /// The media's sources\.
    pub setup: Vec<Pkg>,
    /// The standalone servicing stack, if the set has one - first everywhere.
    pub ssu: Option<Pkg>,
    /// The cumulative chain as KBs, oldest first, the target last.
    pub chain: Vec<String>,
    /// Left out, with why.
    pub skipped: Vec<(Pkg, String)>,
    /// What stops the build: an update the studio cannot tell what it is, that would
    /// otherwise be left out.
    pub blocking: Vec<(Pkg, String)>,
}

pub fn plan(pkgs: Vec<Pkg>) -> Plan {
    let mut p = Plan::default();
    // One form per KB: a set may carry an update as .cab and as .msu. The .msu for the
    // cumulative update (its servicing stack and checkpoints come with it), the .cab for
    // the rest (the Safe OS and Setup updates are CABs in Microsoft's steps).
    let mut forms: Vec<Pkg> = Vec::new();
    for k in pkgs {
        let Some(kb) = k.kb() else {
            forms.push(k);
            continue;
        };
        match forms.iter().position(|o| o.kb().as_deref() == Some(kb.as_str())) {
            None => forms.push(k),
            Some(i) => {
                let cumulative = k.kind == Kind::Cumulative || forms[i].kind == Kind::Cumulative;
                let msu = |x: &Pkg| x.file.name.to_lowercase().ends_with(".msu");
                let better = if cumulative { msu(&k) && !msu(&forms[i]) } else { !msu(&k) && msu(&forms[i]) };
                let (keep, drop) = if better { (k, forms[i].clone()) } else { (forms[i].clone(), k) };
                p.skipped.push((drop, format!("the same update as {}", keep.file.name)));
                forms[i] = keep;
            }
        }
    }
    let mut usable = Vec::new();
    for k in forms {
        match k.unusable.clone() {
            Some(why) => p.skipped.push((k, why)),
            None => usable.push(k),
        }
    }
    // One of each that only the newest counts for; the rest superseded by it.
    fn newest(kind: Kind, all: &mut Vec<Pkg>, skipped: &mut Vec<(Pkg, String)>) -> Option<Pkg> {
        let mut of: Vec<Pkg> = Vec::new();
        all.retain(|k| {
            if k.kind == kind {
                of.push(k.clone());
                false
            } else {
                true
            }
        });
        of.sort_by_key(|k| k.rev());
        let best = of.pop();
        for old in of {
            let by = best.as_ref().map(|b| format!("{} {}", b.short(), b.version)).unwrap_or_default();
            skipped.push((old, format!("superseded by {by}")));
        }
        best
    }
    p.ssu = newest(Kind::ServicingStack, &mut usable, &mut p.skipped);
    let safeos = newest(Kind::SafeOs, &mut usable, &mut p.skipped);
    let setup = newest(Kind::Setup, &mut usable, &mut p.skipped);
    // The cumulative chain: the update that makes the newest build, then - walking back -
    // the checkpoint that makes the build it needs, and so on (LCUCompDB's OSVersion ->
    // TargetOSVersion). Without that metadata: the newest alone.
    let mut cums: Vec<Pkg> = usable.iter().filter(|k| k.kind == Kind::Cumulative).cloned().collect();
    usable.retain(|k| k.kind != Kind::Cumulative);
    // The target: one Microsoft's builds describe beats one only its package or name does
    // (a KB number is no build to compare with).
    cums.sort_by_key(|k| (k.lcu.is_some(), k.known, k.rev()));
    let mut chain: Vec<Pkg> = Vec::new();
    if let Some(target) = cums.pop() {
        chain.push(target);
        while let Some(base) = chain[0].lcu.as_ref().map(|l| l.base.clone()) {
            let Some(i) = cums.iter().position(|c| c.lcu.as_ref().is_some_and(|l| l.target == base)) else { break };
            chain.insert(0, cums.remove(i));
        }
        let to = chain.last().map(|t| format!("{} ({})", t.short(), t.lcu.as_ref().map(|l| l.target.clone()).unwrap_or_else(|| t.version.clone()))).unwrap_or_default();
        for c in cums {
            if c.known {
                p.skipped.push((c, format!("superseded by {to}")));
            } else {
                p.blocking.push((c, format!("an .msu Microsoft's metadata does not name and whose package the studio cannot read - it would be left out beside {to}")));
            }
        }
    }
    p.chain = chain.iter().filter_map(|k| k.kb()).collect();
    let by_kb = |a: &Pkg, b: &Pkg| {
        let n = |k: &Pkg| k.kb().and_then(|kb| kb[2..].parse::<u64>().ok()).unwrap_or(u64::MAX);
        n(a).cmp(&n(b))
    };
    let mut secure: Vec<Pkg> = usable.iter().filter(|k| k.kind == Kind::SecureBoot).cloned().collect();
    let mut other: Vec<Pkg> = usable.iter().filter(|k| matches!(k.kind, Kind::Other | Kind::Enablement)).cloned().collect();
    let mut dotnet: Vec<Pkg> = usable.iter().filter(|k| k.kind == Kind::DotNet).cloned().collect();
    secure.sort_by(by_kb);
    other.sort_by(by_kb);
    dotnet.sort_by(by_kb);
    p.image = p.ssu.iter().cloned().chain(secure).chain(other).chain(chain).collect();
    p.dotnet = dotnet;
    p.winre = safeos.into_iter().collect();
    p.setup = setup.into_iter().collect();
    p
}

/// Reads every update of the set (in `dir`), with Microsoft's metadata - the set's, and
/// each .msu's own for one the set does not name - and plans them.
pub async fn plan_set(dir: &Path, files: &[uup::File], meta: &Meta) -> Plan {
    let work = dir.join(".plan");
    let mut meta = meta.clone();
    let mut pkgs = Vec::new();
    for f in files {
        let path = dir.join(&f.name);
        if f.name.to_lowercase().ends_with(".msu")
            && crate::media::kb_of(&f.name).is_some_and(|kb| !meta.kinds.contains_key(&kb))
        {
            let m = read_msu_meta(&path, &work).await;
            meta.kinds.extend(m.kinds);
            meta.lcus.extend(m.lcus);
        }
        let c = read(&path).await;
        let mut k = classify(f, &c, &meta);
        // A PSFX cumulative update needs its .psf beside it.
        if k.is_psfx() {
            let psf = format!("{}.psf", &f.name[..f.name.len() - 4]).to_lowercase();
            let here = std::fs::read_dir(dir).map(|rd| rd.flatten().any(|e| e.file_name().to_string_lossy().to_lowercase() == psf)).unwrap_or(false);
            if !here {
                k.unusable = Some(format!("its payload {psf} is not here"));
            }
        }
        pkgs.push(k);
    }
    let _ = tokio::fs::remove_dir_all(&work).await;
    let mut p = plan(pkgs);
    // The checkpoint the first update of the chain is made on, named by the metadata but not
    // in the set: DISM would fail on it later - said now.
    if let Some(first) = p.image.iter().find(|k| k.kind == Kind::Cumulative)
        && let Some(base) = first.lcu.as_ref().map(|l| l.base.clone())
        && let Some((kb, _)) = meta.lcus.iter().find(|(_, l)| l.target == base)
    {
        p.blocking.push((first.clone(), format!("it is made on {base}, which its checkpoint {kb} makes - and {kb} is not in the set")));
    }
    p
}

impl Plan {
    /// The plan as the job log shows it, one line per package.
    pub fn lines(&self) -> Vec<String> {
        let row = |k: &Pkg, to: &str| {
            let ver = match &k.lcu {
                Some(l) => format!(" {} -> {}", l.base, l.target),
                None if !k.version.is_empty() => format!(" {}", k.version),
                None => String::new(),
            };
            let made = if k.is_psfx() { " (.msu put together from its .wim and .psf)" } else { "" };
            format!("{} - {}{ver}{made} -> {to}", k.file.name, k.kind.label())
        };
        let mut v = Vec::new();
        let mut n = 0;
        for k in &self.image {
            n += 1;
            let to = if k.kind == Kind::ServicingStack && !self.winre.is_empty() {
                "install image (first), WinRE (first)".to_owned()
            } else if k.kind == Kind::Cumulative && self.chain.len() > 1 && k.kb().as_deref() != self.chain.last().map(String::as_str) {
                "install image, checkpoint".to_owned()
            } else {
                "install image".to_owned()
            };
            v.push(format!("{n}. {}", row(k, &to)));
        }
        for k in &self.dotnet {
            n += 1;
            v.push(format!("{n}. {}", row(k, "install image, after the cleanup")));
        }
        for k in &self.winre {
            n += 1;
            v.push(format!("{n}. {}", row(k, "WinRE")));
        }
        for k in &self.setup {
            n += 1;
            v.push(format!("{n}. {}", row(k, "the media's sources\\")));
        }
        for k in self.image.iter().chain(&self.dotnet).chain(&self.winre).chain(&self.setup) {
            if let Some(note) = &k.note {
                v.push(format!("note: {} - {note}", k.file.name));
            }
        }
        for (k, why) in &self.skipped {
            v.push(format!("left out: {} - {why}", k.file.name));
        }
        v
    }
}

// ---- an .msu for a PSFX cumulative update (Windows 11 23H2) ----

/// A CAB of these files, stored (no compression) - all onepackage.AggregatedMetadata.cab
/// needs (its members are CABs already). Microsoft's cabinet format: a header, one folder,
/// one entry per file, data blocks of up to 32 KiB without checksums (0 is "none").
pub fn write_cab(out: &Path, files: &[(String, Vec<u8>)]) -> Result<()> {
    const BLOCK: usize = 32768;
    let data: Vec<u8> = files.iter().flat_map(|(_, d)| d.iter().copied()).collect();
    let blocks: Vec<&[u8]> = if data.is_empty() { vec![] } else { data.chunks(BLOCK).collect() };
    let header = 36usize;
    let folder = 8usize;
    let entries: usize = files.iter().map(|(n, _)| 16 + n.len() + 1).sum();
    let data_start = header + folder + entries;
    let total = data_start + blocks.iter().map(|b| 8 + b.len()).sum::<usize>();
    if total > u32::MAX as usize || files.len() > u16::MAX as usize || blocks.len() > u16::MAX as usize {
        bail!("too much for one cabinet");
    }
    let now = chrono::Local::now();
    use chrono::{Datelike, Timelike};
    let date = (((now.year() - 1980) as u16) << 9) | ((now.month() as u16) << 5) | now.day() as u16;
    let time = ((now.hour() as u16) << 11) | ((now.minute() as u16) << 5) | (now.second() as u16 / 2);
    let mut b: Vec<u8> = Vec::with_capacity(total);
    b.extend_from_slice(b"MSCF");
    b.extend_from_slice(&0u32.to_le_bytes());
    b.extend_from_slice(&(total as u32).to_le_bytes());
    b.extend_from_slice(&0u32.to_le_bytes());
    b.extend_from_slice(&((header + folder) as u32).to_le_bytes());
    b.extend_from_slice(&0u32.to_le_bytes());
    b.extend_from_slice(&[3, 1]);
    b.extend_from_slice(&1u16.to_le_bytes());
    b.extend_from_slice(&(files.len() as u16).to_le_bytes());
    b.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    b.extend_from_slice(&(data_start as u32).to_le_bytes());
    b.extend_from_slice(&(blocks.len() as u16).to_le_bytes());
    b.extend_from_slice(&0u16.to_le_bytes());
    let mut offset = 0u32;
    for (name, d) in files {
        b.extend_from_slice(&(d.len() as u32).to_le_bytes());
        b.extend_from_slice(&offset.to_le_bytes());
        b.extend_from_slice(&0u16.to_le_bytes());
        b.extend_from_slice(&date.to_le_bytes());
        b.extend_from_slice(&time.to_le_bytes());
        b.extend_from_slice(&0x20u16.to_le_bytes());
        b.extend_from_slice(name.as_bytes());
        b.push(0);
        offset += d.len() as u32;
    }
    for blk in blocks {
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&(blk.len() as u16).to_le_bytes());
        b.extend_from_slice(&(blk.len() as u16).to_le_bytes());
        b.extend_from_slice(blk);
    }
    std::fs::write(out, b).with_context(|| format!("writing {}", out.display()))
}

fn link_or_copy(from: &Path, to: &Path) -> Result<()> {
    if std::fs::hard_link(from, to).is_err() {
        std::fs::copy(from, to).with_context(|| format!("copying {}", from.display()))?;
    }
    Ok(())
}

/// The .msu of a PSFX cumulative update, put together in `dl` as UUP dump's converter does:
/// an uncompressed WIM, image "content", of the package's .wim and .psf, the set's servicing
/// stack, DesktopDeployment (and _x86) and onepackage.AggregatedMetadata.cab with the
/// update's LCUCompDB and the servicing stack's SSUCompDB. Returns it as a file of the set.
pub async fn build_msu(dl: &Path, pkg: &Pkg, meta: &Meta) -> Result<uup::File> {
    let kb = pkg.kb().context("the update names no KB")?;
    let wim = dl.join(&pkg.file.name);
    let stem = &pkg.file.name[..pkg.file.name.len() - 4];
    let psf_name = format!("{stem}.psf");
    let psf = std::fs::read_dir(dl)?.flatten().map(|e| e.path()).find(|p| p.file_name().is_some_and(|n| n.to_string_lossy().eq_ignore_ascii_case(&psf_name)));
    let Some(psf) = psf else { bail!("{psf_name} is not here - the cumulative update's payload") };
    let db = meta.lcu_db.get(&kb).with_context(|| format!("the set's metadata has no LCUCompDB for {kb}"))?;
    let dir = dl.join(format!(".msu-{kb}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    link_or_copy(&wim, &dir.join(&pkg.file.name))?;
    link_or_copy(&psf, &dir.join(&psf_name))?;
    // The servicing stack only with the SSUCompDB that names it, and only when it is here.
    let ssu = meta.ssu_db.as_ref().filter(|(_, f)| !f.is_empty() && dl.join(f).exists());
    for e in std::fs::read_dir(dl)?.flatten() {
        let n = e.file_name().to_string_lossy().into_owned();
        let l = n.to_lowercase();
        if ssu.is_some_and(|(_, f)| f.eq_ignore_ascii_case(&n)) || (l.starts_with("desktopdeployment") && l.ends_with(".cab")) {
            link_or_copy(&e.path(), &dir.join(&n))?;
        }
    }
    let mut members = vec![(db.file_name().unwrap().to_string_lossy().into_owned(), std::fs::read(db)?)];
    if let Some((s, _)) = ssu {
        members.push((s.file_name().unwrap().to_string_lossy().into_owned(), std::fs::read(s)?));
    }
    write_cab(&dir.join("onepackage.AggregatedMetadata.cab"), &members)?;
    let name = format!("{stem}.msu");
    let out = dl.join(&name);
    let _ = std::fs::remove_file(&out);
    let o = tokio::process::Command::new("wimlib-imagex")
        .args(["capture", &dir.display().to_string(), &out.display().to_string(), "content", "--compress=none", "--no-acls"])
        .output()
        .await
        .context("running wimlib-imagex")?;
    let _ = std::fs::remove_dir_all(&dir);
    if !o.status.success() {
        bail!("putting {name} together: {}", String::from_utf8_lossy(&o.stderr).lines().last().unwrap_or(""));
    }
    let size = std::fs::metadata(&out)?.len();
    Ok(uup::File { name, url: String::new(), sha1: String::new(), size })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(name: &str) -> uup::File {
        uup::File { name: name.into(), url: String::new(), sha1: String::new(), size: 1 }
    }

    fn mum(id: &str, version: &str) -> Option<String> {
        Some(format!("<?xml version=\"1.0\"?><assembly><assemblyIdentity name=\"{id}\" version=\"{version}\" processorArchitecture=\"amd64\" language=\"neutral\" buildType=\"release\" publicKeyToken=\"31bf3856ad364e35\"/><package identifier=\"x\"/></assembly>"))
    }

    fn pkg(name: &str, files: &[&str], m: Option<String>) -> Pkg {
        classify(&file(name), &Contents { files: files.iter().map(|s| (*s).to_owned()).collect(), mum: m }, &Meta::default())
    }

    /// A real set's update files and metadata, read and planned:
    /// PVS_UUP_DIR=<folder> cargo test real_set -- --ignored --nocapture
    #[tokio::test]
    #[ignore]
    async fn real_set() {
        let dir = std::path::PathBuf::from(std::env::var("PVS_UUP_DIR").expect("PVS_UUP_DIR"));
        let mut files = Vec::new();
        for e in std::fs::read_dir(&dir).unwrap().flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if crate::media::is_update(&name) {
                files.push(uup::File { name, url: String::new(), sha1: String::new(), size: e.metadata().unwrap().len() });
            }
        }
        files.sort_by(|a, b| a.name.cmp(&b.name));
        let work = std::env::temp_dir().join(format!("pvs-meta-{}", std::process::id()));
        let meta = match std::fs::read_dir(&dir).unwrap().flatten().find(|e| crate::media::is_aggregated(&e.file_name().to_string_lossy())) {
            Some(e) => read_meta(&e.path(), &work).await,
            None => Meta::default(),
        };
        println!("metadata: {:?} {:?}", meta.kinds, meta.lcus);
        let p = plan_set(&dir, &files, &meta).await;
        for l in p.lines() {
            println!("{l}");
        }
        for (k, why) in &p.blocking {
            println!("BLOCKING {}: {why}", k.file.name);
        }
        if std::env::var("PVS_BUILD_MSU").is_ok() {
            for k in p.image.iter().filter(|k| k.is_psfx()) {
                let msu = build_msu(&dir, k, &meta).await.unwrap();
                println!("built {} ({} bytes)", msu.name, msu.size);
            }
        }
        let _ = std::fs::remove_dir_all(&work);
    }

    /// The Server 2022 set of 2026-10-10 (20348.5622): no AggregatedMetadata, a standalone
    /// servicing stack without a KB in its name, the Safe OS update beside the rest.
    #[test]
    fn server_2022() {
        let pkgs = vec![
            pkg("Windows10.0-KB5007374-x64.cab", &["update.mum", "Package_for_KB5007374~31bf3856ad364e35~amd64~~20348.371.1.1.mum"], mum("Package_for_KB5007374", "20348.371.1.1")),
            pkg("Windows10.0-KB5122882-x64.cab", &["update.mum", "Package_for_RollupFix~31bf3856ad364e35~amd64~~20348.5622.1.16.mum", "amd64_microsoft-windows-servicingstack_31bf3856ad364e35_10.0.20348.5614_none.manifest"], mum("Package_for_RollupFix", "20348.5622.1.16")),
            pkg("Windows10.0-KB5122889-x64.cab", &["update.mum", "amd64_microsoft-windows-winre-tools_31bf3856ad364e35.manifest"], mum("Package_for_SafeOSDU", "20348.5620.1.16")),
            pkg("Windows10.0-KB5126031-x64.cab", &["setuphost.exe", "setupprep.exe", "UpdateAgent.dll"], None),
            pkg("SSU-20348.5614-x64.cab", &["update.mum", "amd64_microsoft-windows-servicingstack_31bf3856ad364e35_10.0.20348.5614_none.manifest"], mum("Package_for_ServicingStack_5614", "20348.5614.1.1")),
        ];
        let p = plan(pkgs);
        let names: Vec<&str> = p.image.iter().map(|k| k.file.name.as_str()).collect();
        assert_eq!(names, ["SSU-20348.5614-x64.cab", "Windows10.0-KB5007374-x64.cab", "Windows10.0-KB5122882-x64.cab"], "servicing stack first, cumulative update last");
        assert_eq!(p.ssu.as_ref().unwrap().kind, Kind::ServicingStack);
        assert_eq!(p.winre[0].file.name, "Windows10.0-KB5122889-x64.cab");
        assert_eq!(p.setup[0].file.name, "Windows10.0-KB5126031-x64.cab");
        assert!(p.skipped.is_empty() && p.blocking.is_empty());
        assert_eq!(p.chain, ["KB5122882"]);
    }

    /// Server 2025 / 24H2: the chain from Microsoft's builds (OSVersion -> TargetOSVersion),
    /// not from KB numbers - here the checkpoint has the higher KB to prove it.
    #[test]
    fn chain_from_the_builds() {
        let lcu = |kb: &str, base: &str, target: &str| {
            let mut k = pkg(&format!("Windows11.0-{kb}-x64.msu"), &["Windows11.0-x-x64.wim", "SSU-26100.1-x64.cab"], None);
            k.known = true;
            k.lcu = Some(Lcu { version: format!("{target}.1.1"), base: base.into(), target: target.into() });
            k
        };
        let pkgs = vec![lcu("KB5999999", "26100.1", "26100.1742"), lcu("KB5122871", "26100.1742", "26100.33438"), pkg("Windows11.0-KB5126052-x64-NDP481.cab", &["update.mum", "amd64_netfx4-system_31bf3856ad364e35.manifest"], mum("Package_for_DotNetRollup_481", "10.0.9300.1"))];
        let p = plan(pkgs);
        assert_eq!(p.chain, ["KB5999999", "KB5122871"], "the checkpoint first, though its KB is higher");
        assert_eq!(p.image.iter().map(|k| k.short()).collect::<Vec<_>>(), ["KB5999999", "KB5122871"]);
        assert_eq!(p.dotnet[0].short(), "KB5126052");
        assert!(p.lines()[0].contains("checkpoint"));
    }

    /// An .msu nothing names and nothing can read, that would be left out: the build stops.
    #[test]
    fn an_unknown_msu_blocks() {
        let mut target = pkg("Windows11.0-KB5122871-x64.msu", &["x.wim"], None);
        target.known = true;
        target.lcu = Some(Lcu { version: String::new(), base: "26100.1".into(), target: "26100.33438".into() });
        let stray = pkg("Windows11.0-KB5121794-x64.msu", &["x.wim"], None);
        assert!(!stray.known);
        let p = plan(vec![target, stray]);
        assert_eq!(p.blocking.len(), 1);
        assert_eq!(p.blocking[0].0.short(), "KB5121794");
    }

    /// A PSFX .wim carries a .psf index too: not an express CAB to leave out, a cumulative
    /// update whose .msu is put together (23H2's KB5129242).
    #[test]
    fn psfx_wim_is_usable() {
        let k = pkg("Windows11.0-KB5129242-x64.wim", &["update.mum", "Windows11.0-KB5129242-x64.psf.cix.xml"], mum("Package_for_RollupFix", "22621.7584.1.0"));
        assert!(k.unusable.is_none() && k.is_psfx());
        let c = pkg("Windows11.0-KB5000003-x64.cab", &["update.mum", "express.psf.cix.xml"], mum("Package_for_RollupFix", "22621.1.1.1"));
        assert!(c.unusable.is_some(), "an express CAB stays out");
    }

    /// The metadata names the kind; where the package reads otherwise, it is noted.
    #[test]
    fn metadata_names_the_kind() {
        let mut meta = Meta::default();
        meta.kinds.insert("KB5054156".into(), Kind::Enablement);
        meta.kinds.insert("KB5125758".into(), Kind::SafeOs);
        let ep = classify(&file("Windows11.0-KB5054156-x64.cab"), &Contents { files: vec!["update.mum".into()], mum: mum("Package_for_KB5054156", "26100.6717.1.4") }, &meta);
        assert_eq!(ep.kind, Kind::Enablement);
        assert!(ep.note.is_some(), "the package alone read as an ordinary update");
        let re = classify(&file("Windows11.0-KB5125758-x64.cab"), &Contents { files: vec!["update.mum".into()], mum: mum("Package_for_SafeOSDU", "26100.9540.1.3") }, &meta);
        assert_eq!(re.kind, Kind::SafeOs);
        assert!(re.note.is_none());
    }

    #[test]
    fn lcu_compdb() {
        let xml = r#"<?xml version="1.0" encoding="utf-8"?><CompDB xmlns:xsi="x" CreatedDate="2026" Revision="1" OSVersion="10.0.26100.1742" BuildArch="amd64" Type="BuildUpdate" TargetOSVersion="10.0.26100.33438" xmlns="y"><Features><Feature Type="CumulativeUpdate"><Packages><Package ID="Package_for_RollupFix~~amd64~~26100.33438.1.19" PackageType="FeaturePackage" /></Packages></Feature></Features><Packages><Package ID="Package_for_RollupFix~~amd64~~26100.33438.1.19" InstalledSize="9" Version="26100.33438.1.19"></Package></Packages></CompDB>"#;
        assert_eq!(parse_lcu_compdb(xml), Some(Lcu { version: "26100.33438.1.19".into(), base: "26100.1742".into(), target: "26100.33438".into() }));
    }

    /// The cabinet writer, read back by cabextract.
    #[test]
    fn cabinet_round_trip() {
        let dir = std::env::temp_dir().join(format!("pvs-cab-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let big: Vec<u8> = (0..100_000u32).map(|i| (i % 251) as u8).collect();
        let cab = dir.join("t.cab");
        write_cab(&cab, &[("LCUCompDB_KB5129242.xml.cab".into(), b"first".to_vec()), ("big.bin".into(), big.clone())]).unwrap();
        let o = std::process::Command::new("cabextract").arg("-q").arg("-d").arg(&dir).arg(&cab).output().unwrap();
        assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
        assert_eq!(std::fs::read(dir.join("LCUCompDB_KB5129242.xml.cab")).unwrap(), b"first");
        assert_eq!(std::fs::read(dir.join("big.bin")).unwrap(), big);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The same KB as .cab and .msu: the .msu for the cumulative update, the .cab otherwise.
    #[test]
    fn one_form_per_kb() {
        let pkgs = vec![
            pkg("Windows11.0-KB5121794-x64.cab", &["update.mum"], mum("Package_for_RollupFix", "26100.9539.1.1")),
            pkg("Windows11.0-KB5121794-x64.msu", &["update.mum"], mum("Package_for_RollupFix", "26100.9539.1.1")),
            pkg("Windows11.0-KB5125758-x64.msu", &["update.mum"], mum("Package_for_SafeOSDU", "26100.9540.1.3")),
            pkg("Windows11.0-KB5125758-x64.cab", &["update.mum"], mum("Package_for_SafeOSDU", "26100.9540.1.3")),
        ];
        let p = plan(pkgs);
        assert_eq!(p.image[0].file.name, "Windows11.0-KB5121794-x64.msu");
        assert_eq!(p.winre[0].file.name, "Windows11.0-KB5125758-x64.cab");
        assert_eq!(p.skipped.len(), 2);
    }

    /// An older cumulative update beside a newer one: superseded. Unusable packages are left
    /// out with their reason.
    #[test]
    fn superseded_and_unusable() {
        let pkgs = vec![
            pkg("Windows10.0-KB5000001-x64.cab", &["update.mum"], mum("Package_for_RollupFix", "20348.5000.1.1")),
            pkg("Windows10.0-KB5000002-x64.cab", &["update.mum"], mum("Package_for_RollupFix", "20348.5622.1.16")),
            pkg("Windows11.0-KB5000003-x64.cab", &["update.mum", "express.psf.cix.xml"], mum("Package_for_RollupFix", "22631.1.1.1")),
            pkg("Windows10.0-KB5000004-arm64.cab", &["update.mum"], Some(mum("Package_for_KB5000004", "20348.1.1.1").unwrap().replace("amd64", "arm64"))),
            pkg("Windows10.0-KB5000005-x64.cab", &["update.mum", "HotpatchCompDB.cab"], mum("Package_for_KB5000005", "20348.1.1.1")),
        ];
        let p = plan(pkgs);
        assert_eq!(p.image.iter().map(|k| k.short()).collect::<Vec<_>>(), ["KB5000002"]);
        let why: Vec<&str> = p.skipped.iter().map(|s| s.1.as_str()).collect();
        assert!(why.iter().any(|w| w.starts_with("superseded by KB5000002")));
        assert!(why.iter().any(|w| w.contains("express")));
        assert!(why.iter().any(|w| w.contains("arm64")));
        assert!(why.iter().any(|w| w.contains("Hotpatch")));
    }
}
