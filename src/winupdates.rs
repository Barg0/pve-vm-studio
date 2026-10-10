//! What each update of a UUP set is, and where and in which order it goes - read from the
//! package itself, never from its file name.
//!
//! Microsoft's media servicing steps (Learn: "Update Windows installation media with
//! Dynamic Update") name four kinds with a fixed place each: the servicing stack first (in
//! WinRE, the install image and WinPE), the Safe OS dynamic update into WinRE only, the
//! cumulative update last before the cleanup (its checkpoints first, since 24H2), .NET
//! after the cleanup, and the Setup dynamic update - a CAB of files, not a package - into
//! the media's sources\. Every failure stops the media; none is shipped.
//!
//! Telling the kinds apart follows abbodi1406's W10UI (the updater behind UUP dump's
//! Windows converter), which has done it for every build since 10240: a CAB without an
//! update.mum is the Setup update; otherwise update.mum's own package name and the
//! manifests the package carries - Package_for_SafeOSDU, Package_for_RollupFix, a
//! servicing-stack manifest, netfx4, boot firmware, an enablement package.
//! AggregatedMetadata (24H2 and later) only cross-checks it, and names the checkpoints.

use std::path::Path;

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
    /// Why it cannot be used at all (an express package without its payload, Hotpatch,
    /// Defender definitions, another processor).
    pub unusable: Option<String>,
}

impl Pkg {
    /// Its revision for "newest": 20348.5622.1.16 as numbers - or, for a package that
    /// names no version (a 24H2 .msu carries its package as a WIM inside), its KB number.
    fn rev(&self) -> Vec<u64> {
        if self.version.is_empty() {
            return vec![self.kb().and_then(|kb| kb[2..].parse().ok()).unwrap_or(0)];
        }
        self.version.split('.').map(|p| p.parse().unwrap_or(0)).collect()
    }

    pub fn kb(&self) -> Option<String> {
        crate::media::kb_of(&self.file.name)
    }

    /// "KB5122882" or the file name, for the log.
    pub fn short(&self) -> String {
        self.kb().unwrap_or_else(|| self.file.name.clone())
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

/// W10UI's order of questions (first match wins) on what the package carries.
pub fn classify(file: &uup::File, c: &Contents) -> Pkg {
    let lower: Vec<String> = c.files.iter().map(|f| f.to_lowercase()).collect();
    let has = |s: &str| lower.iter().any(|f| f.contains(s));
    let mut pkg = Pkg { file: file.clone(), kind: Kind::Other, identity: String::new(), version: String::new(), arch: String::new(), unusable: None };
    let name = file.name.to_lowercase();
    if c.files.is_empty() {
        // Not a CAB or WIM the studio can read: judged by its name, and said so.
        pkg.kind = if name.starts_with("ssu-") { Kind::ServicingStack } else if name.ends_with(".msu") { Kind::Cumulative } else { Kind::Other };
        return pkg;
    }
    let Some(mum) = &c.mum else {
        // A .msu without one carries its package inside - since 24H2 as Windows11.0-KB…-x64.wim
        // and .psf beside its own SSU-*.cab: a combined cumulative update or a checkpoint.
        if name.ends_with(".msu") {
            pkg.kind = Kind::Cumulative;
            if has("hotpatch") {
                pkg.unusable = Some("a Hotpatch update - only for running machines enrolled in Hotpatch".into());
            }
        } else if has("defender") && has(".xml") {
            pkg.unusable = Some("Defender definitions - not part of the media".into());
        } else {
            pkg.kind = Kind::Setup;
        }
        return pkg;
    };
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
    } else if has(".psf.cix.xml") {
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
    /// Left out, with why.
    pub skipped: Vec<(Pkg, String)>,
}

/// `checkpoints`: the KBs AggregatedMetadata names as the cumulative chain (24H2 and later) -
/// those stay beside the newest; any other older cumulative update is superseded.
pub fn plan(pkgs: Vec<Pkg>, checkpoints: &[String]) -> Plan {
    let mut p = Plan::default();
    // One form per KB: a set may carry an update as .cab and as .msu. The .msu for the
    // cumulative update (its servicing stack and checkpoints come with it), the .cab for
    // the rest (the Safe OS and Setup updates are CABs in Microsoft's steps).
    let mut pkgs = pkgs;
    let mut forms: Vec<Pkg> = Vec::new();
    for k in pkgs.drain(..) {
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
    let newest = |kind: Kind, all: &mut Vec<Pkg>, skipped: &mut Vec<(Pkg, String)>, keep: &dyn Fn(&Pkg) -> bool| -> Option<Pkg> {
        let mut of: Vec<Pkg> = Vec::new();
        all.retain(|k| {
            if k.kind == kind && !keep(k) {
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
    };
    let in_chain = |k: &Pkg| k.kb().is_some_and(|kb| checkpoints.contains(&kb));
    p.ssu = newest(Kind::ServicingStack, &mut usable, &mut p.skipped, &|_| false);
    let lcu = newest(Kind::Cumulative, &mut usable, &mut p.skipped, &in_chain);
    let safeos = newest(Kind::SafeOs, &mut usable, &mut p.skipped, &|_| false);
    let setup = newest(Kind::Setup, &mut usable, &mut p.skipped, &|_| false);
    // The checkpoints the chain names: oldest first, then the newest cumulative update.
    let mut chain: Vec<Pkg> = usable.iter().filter(|k| k.kind == Kind::Cumulative).cloned().collect();
    usable.retain(|k| k.kind != Kind::Cumulative);
    chain.sort_by_key(|k| k.rev());
    if let Some(l) = lcu {
        // A checkpoint newer than the target would be a bad set; the target stays last.
        chain.retain(|c| c.rev() < l.rev());
        chain.push(l);
    }
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

/// Reads every update of the set (in `dir`) and plans them.
pub async fn plan_set(dir: &Path, files: &[uup::File], checkpoints: &[String]) -> Plan {
    let mut pkgs = Vec::new();
    for f in files {
        let c = read(&dir.join(&f.name)).await;
        pkgs.push(classify(f, &c));
    }
    plan(pkgs, checkpoints)
}

impl Plan {
    /// The plan as the job log shows it, one line per package.
    pub fn lines(&self) -> Vec<String> {
        let row = |k: &Pkg, to: &str| {
            let ver = if k.version.is_empty() { String::new() } else { format!(" {}", k.version) };
            format!("{} - {}{ver} -> {to}", k.file.name, k.kind.label())
        };
        let mut v = Vec::new();
        let mut n = 0;
        for k in &self.image {
            n += 1;
            let to = if k.kind == Kind::ServicingStack && !self.winre.is_empty() { "install image (first), WinRE (first)" } else { "install image" };
            v.push(format!("{n}. {}", row(k, to)));
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
        for (k, why) in &self.skipped {
            v.push(format!("left out: {} - {why}", k.file.name));
        }
        v
    }
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
        classify(&file(name), &Contents { files: files.iter().map(|s| (*s).to_owned()).collect(), mum: m })
    }

    /// A real set's update files, read and planned: PVS_UUP_DIR=<folder> cargo test real_set -- --ignored --nocapture
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
        let checkpoints = match std::fs::read_dir(&dir).unwrap().flatten().find(|e| crate::media::is_aggregated(&e.file_name().to_string_lossy())) {
            Some(e) => crate::media::update_targets(&e.path()).await.cumulative,
            None => vec![],
        };
        println!("checkpoint chain: {checkpoints:?}");
        let p = plan_set(&dir, &files, &checkpoints).await;
        for l in p.lines() {
            println!("{l}");
        }
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
        let p = plan(pkgs, &[]);
        let names: Vec<&str> = p.image.iter().map(|k| k.file.name.as_str()).collect();
        assert_eq!(names, ["SSU-20348.5614-x64.cab", "Windows10.0-KB5007374-x64.cab", "Windows10.0-KB5122882-x64.cab"], "servicing stack first, cumulative update last");
        assert_eq!(p.ssu.as_ref().unwrap().kind, Kind::ServicingStack);
        assert_eq!(p.winre[0].file.name, "Windows10.0-KB5122889-x64.cab");
        assert_eq!(p.setup[0].file.name, "Windows10.0-KB5126031-x64.cab");
        assert!(p.skipped.is_empty());
        assert_eq!(p.image[2].version, "20348.5622.1.16");
    }

    /// 24H2/25H2: the chain of .msu files (a checkpoint and the target), .NET after the cleanup.
    #[test]
    fn checkpoints_and_dotnet() {
        let lcu = |kb: &str, v: &str| pkg(&format!("Windows11.0-{kb}-x64.msu"), &["update.mum", "Windows11.0-x-x64.cab"], mum("Package_for_RollupFix", v));
        let pkgs = vec![
            lcu("KB5043080", "26100.1742.1.10"),
            lcu("KB5124010", "26100.9550.1.20"),
            pkg("Windows11.0-KB5126052-x64-NDP481.cab", &["update.mum", "amd64_netfx4-system_31bf3856ad364e35.manifest"], mum("Package_for_DotNetRollup_481", "10.0.9300.1")),
            pkg("Windows11.0-KB5125758-x64.cab", &["update.mum"], mum("Package_for_SafeOSDU", "26100.9540.1.3")),
        ];
        let p = plan(pkgs, &["KB5043080".into(), "KB5124010".into()]);
        let names: Vec<String> = p.image.iter().map(|k| k.short()).collect();
        assert_eq!(names, ["KB5043080", "KB5124010"], "the checkpoint first, the target last");
        assert_eq!(p.dotnet[0].short(), "KB5126052");
        assert_eq!(p.winre[0].short(), "KB5125758");
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
        let p = plan(pkgs, &[]);
        assert_eq!(p.image[0].file.name, "Windows11.0-KB5121794-x64.msu");
        assert_eq!(p.winre[0].file.name, "Windows11.0-KB5125758-x64.cab");
        assert_eq!(p.skipped.len(), 2);
    }

    /// An older cumulative update beside a newer one, no chain named: superseded. Unusable
    /// packages are left out with their reason.
    #[test]
    fn superseded_and_unusable() {
        let pkgs = vec![
            pkg("Windows10.0-KB5000001-x64.cab", &["update.mum"], mum("Package_for_RollupFix", "20348.5000.1.1")),
            pkg("Windows10.0-KB5000002-x64.cab", &["update.mum"], mum("Package_for_RollupFix", "20348.5622.1.16")),
            pkg("Windows11.0-KB5000003-x64.cab", &["update.mum", "express.psf.cix.xml"], mum("Package_for_RollupFix", "22631.1.1.1")),
            pkg("Windows10.0-KB5000004-arm64.cab", &["update.mum"], Some(mum("Package_for_KB5000004", "20348.1.1.1").unwrap().replace("amd64", "arm64"))),
            pkg("Windows10.0-KB5000005-x64.cab", &["update.mum", "HotpatchCompDB.cab"], mum("Package_for_KB5000005", "20348.1.1.1")),
        ];
        let p = plan(pkgs, &[]);
        assert_eq!(p.image.iter().map(|k| k.short()).collect::<Vec<_>>(), ["KB5000002"]);
        let why: Vec<&str> = p.skipped.iter().map(|s| s.1.as_str()).collect();
        assert!(why.iter().any(|w| w.starts_with("superseded by KB5000002")));
        assert!(why.iter().any(|w| w.contains("express")));
        assert!(why.iter().any(|w| w.contains("arm64")));
        assert!(why.iter().any(|w| w.contains("Hotpatch")));
    }
}
