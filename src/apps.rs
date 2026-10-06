//! The inbox apps of a Windows 11 image (Store, Notepad, Terminal, Calculator, Photos...).
//! Since 22H2 the UUP set no longer carries them inside the edition ESD: they come as their
//! own file set (the catalog's `neutral` / `app` list) and the official ISO has them
//! provisioned in install.wim. The way uup-converter (abbodi1406) and Microsoft's "Preinstall
//! apps using DISM" do it, done here:
//!
//!   1. the app CompDB (DesktopTargetCompDB_App_Neutral, in the build's AggregatedMetadata)
//!      names every app - its type (framework, bundle, single package), its packages, the
//!      licence as text - and where each package file sits (Apps\IPA\<group>\<path>);
//!   2. the edition's CompDB (DesktopTargetCompDB_<edition>_<lang>) lists the apps that
//!      edition ships (Group="PreinstalledApps");
//!   3. the files are laid out as DISM wants them - a bundle with every package and stub it
//!      refers to beside it, the frameworks in a folder of their own, License.xml per app -
//!      and go to the worker as one WIM;
//!   4. the worker provisions them after the updates: the frameworks, then each app with its
//!      licence for every region (Microsoft: an app not pinned to Start and without
//!      /Region is dropped at OOBE).

use std::{
    collections::{BTreeSet, HashMap},
    path::Path,
};

use anyhow::{bail, Context, Result};

use crate::{jobs::JobLog, uup, winpe::run};

/// One app of the CompDB.
#[derive(Debug, Clone)]
struct Feature {
    id: String,
    framework: bool,
    packages: Vec<String>,
    license: Option<String>,
}

/// What the worker provisions into one image.
#[derive(Debug, Clone, PartialEq)]
pub struct App {
    /// The app's family name (Microsoft.WindowsStore_8wekyb3d8bbwe), its folder under apps\.
    pub id: String,
    /// The file DISM is handed, relative to the app's folder.
    pub main: String,
    /// It ships stub packages (AppxMetadata\Stub): installed in full, as the converter does.
    pub stub: bool,
}

/// The apps of a build: the files to fetch, where each goes, what each image gets.
#[derive(Debug, Default)]
pub struct Plan {
    /// Catalog files the layout needs (frameworks and the picked apps' packages).
    pub files: Vec<uup::File>,
    /// file name -> path under apps\ (MSIXFramework\x.appx, <app>\<path>).
    pub layout: Vec<(String, String)>,
    /// (app, licence XML) - written as <app>\License.xml.
    pub licenses: Vec<(String, String)>,
    /// The frameworks, relative to apps\ - provisioned first, in every image.
    pub frameworks: Vec<String>,
    /// Per image, in install.wim order: its apps.
    pub per_image: Vec<Vec<App>>,
    /// Apps an edition lists that the catalog has no files for (China- or Team-only ones).
    pub missing: Vec<String>,
}

fn attr<'a>(tag: &'a str, name: &str) -> Option<&'a str> {
    let key = format!(" {name}=\"");
    let at = tag.find(&key)? + key.len();
    tag[at..].split('"').next()
}

/// The app CompDB: its features (top level only - a dependency is a <Feature FeatureID=...
/// Type="Required" /> inside one) and package id -> payload path under IPA\<group>\.
fn parse_app_compdb(xml: &str) -> (Vec<Feature>, HashMap<String, String>) {
    let (feats, packs) = xml.split_once("</Features>").unwrap_or((xml, ""));
    let mut out = Vec::new();
    for seg in feats.split("<Feature Type=\"").skip(1) {
        let head = format!(" Type=\"{}", seg.split('>').next().unwrap_or(""));
        let (Some(ty), Some(id)) = (attr(&head, "Type"), attr(&head, "FeatureID")) else { continue };
        let packages = seg.split("<Package ID=\"").skip(1).filter_map(|p| p.split('"').next()).map(str::to_owned).collect();
        let license = seg
            .split_once("<CustomInfo Key=\"licensedata\"><![CDATA[")
            .and_then(|(_, rest)| rest.split_once("]]>"))
            .map(|(l, _)| l.to_owned());
        out.push(Feature { id: id.to_owned(), framework: ty == "MSIXFramework", packages, license });
    }
    let mut paths = HashMap::new();
    for seg in packs.split("<Package ID=\"").skip(1) {
        let Some(id) = seg.split('"').next() else { continue };
        let body = seg.split("</Package>").next().unwrap_or("");
        if let Some(p) = body.split_once("Path=\"").and_then(|(_, r)| r.split('"').next()) {
            // UUP\Desktop\Apps\IPA\<group>\<path> -> <path> (it may hold AppxMetadata\Stub\...).
            let rel = p.split_once("\\IPA\\").map(|(_, r)| r).unwrap_or(p);
            let rel = rel.split_once('\\').map(|(_, r)| r).unwrap_or(rel);
            paths.insert(id.to_owned(), rel.to_owned());
        }
    }
    (out, paths)
}

/// The apps an edition ships: its CompDB's PreinstalledApps features.
fn edition_apps(xml: &str) -> Vec<String> {
    xml.split("<Feature ")
        .skip(1)
        .map(|s| format!(" {}", s.split('>').next().unwrap_or("")))
        .filter(|t| attr(t, "Group") == Some("PreinstalledApps"))
        .filter_map(|t| attr(&t, "FeatureID").map(str::to_owned))
        .collect()
}

/// The file DISM gets for an app: a bundle before a single package (the converter's order).
fn main_file(rels: &[&str]) -> Option<String> {
    let top: Vec<&&str> = rels.iter().filter(|r| !r.contains('\\')).collect();
    for ext in [".msixbundle", ".appxbundle", ".appx", ".msix"] {
        if let Some(r) = top.iter().find(|r| r.to_lowercase().ends_with(ext)) {
            return Some((**r).to_owned());
        }
    }
    None
}

/// The plan from the two CompDBs and the catalog's app file list.
pub fn plan(app_xml: &str, editions: &[Option<String>], catalog: &[uup::File]) -> Result<Plan> {
    let (features, paths) = parse_app_compdb(app_xml);
    if features.is_empty() {
        bail!("the app CompDB names no app");
    }
    let by_name: HashMap<String, &uup::File> = catalog.iter().map(|f| (f.name.to_lowercase(), f)).collect();
    let mut plan = Plan::default();
    let mut need: BTreeSet<String> = BTreeSet::new();
    // Lays out one feature's packages; false when a file is missing from the catalog.
    let mut place = |f: &Feature, plan: &mut Plan| -> Option<Vec<String>> {
        let mut rels = Vec::new();
        for pid in &f.packages {
            let rel = paths.get(pid)?;
            let name = rel.rsplit('\\').next().unwrap_or(rel).to_lowercase();
            let file = by_name.get(&name)?;
            let target = if f.framework { format!("MSIXFramework\\{rel}") } else { format!("{}\\{rel}", f.id) };
            if need.insert(file.name.clone()) {
                plan.files.push((*file).clone());
                plan.layout.push((file.name.clone(), target));
            }
            rels.push(rel.clone());
        }
        Some(rels)
    };
    for f in features.iter().filter(|f| f.framework) {
        if let Some(rels) = place(f, &mut plan) {
            plan.frameworks.extend(rels.iter().map(|r| format!("MSIXFramework\\{r}")));
        }
    }
    for list in editions {
        let mut apps = Vec::new();
        for id in list.as_deref().map(edition_apps).unwrap_or_default() {
            let Some(f) = features.iter().find(|f| f.id == id && !f.framework) else {
                plan.missing.push(id);
                continue;
            };
            let Some(license) = &f.license else {
                plan.missing.push(id);
                continue;
            };
            let Some(rels) = place(f, &mut plan) else {
                plan.missing.push(id);
                continue;
            };
            let refs: Vec<&str> = rels.iter().map(String::as_str).collect();
            let Some(main) = main_file(&refs) else {
                plan.missing.push(id);
                continue;
            };
            if !plan.licenses.iter().any(|(a, _)| *a == f.id) {
                plan.licenses.push((f.id.clone(), license.clone()));
            }
            apps.push(App { id: f.id.clone(), main, stub: rels.iter().any(|r| r.starts_with("AppxMetadata\\Stub\\")) });
        }
        plan.per_image.push(apps);
    }
    plan.missing.sort();
    plan.missing.dedup();
    Ok(plan)
}

/// One CompDB XML out of a build's AggregatedMetadata.cab (each sits in a cab of its own
/// inside it), or None when the build has none by that name.
pub async fn compdb(log: &JobLog, agg: &Path, tmp: &Path, name: &str) -> Result<Option<String>> {
    let list = tokio::process::Command::new("cabextract").arg("-l").arg(agg).output().await.context("running cabextract")?;
    let want = format!("{name}.xml.cab").to_lowercase();
    let Some(inner) = String::from_utf8_lossy(&list.stdout).lines().map(|l| l.rsplit('|').next().unwrap_or("").trim().to_owned()).find(|n| n.to_lowercase() == want) else {
        return Ok(None);
    };
    let _ = tokio::fs::remove_dir_all(tmp).await;
    tokio::fs::create_dir_all(tmp).await?;
    let tmp_s = tmp.display().to_string();
    run(log, "cabextract", &["-q", "-F", &inner, "-d", &tmp_s, &agg.display().to_string()]).await?;
    run(log, "cabextract", &["-q", "-d", &tmp_s, &tmp.join(&inner).display().to_string()]).await?;
    let xml_name = inner.trim_end_matches(".cab").trim_end_matches(".CAB").to_lowercase();
    let mut rd = tokio::fs::read_dir(tmp).await?;
    while let Some(e) = rd.next_entry().await? {
        if e.file_name().to_string_lossy().to_lowercase() == xml_name {
            let raw = tokio::fs::read(e.path()).await?;
            let _ = tokio::fs::remove_dir_all(tmp).await;
            return Ok(Some(String::from_utf8_lossy(&raw).trim_start_matches('\u{feff}').to_owned()));
        }
    }
    bail!("{inner} held no {xml_name}")
}

/// The layout on disk under `root` (hard links to the downloads, so nothing is copied twice),
/// the licences beside each app - ready to be captured into the worker's apps.wim.
pub async fn lay_out(plan: &Plan, dl: &Path, root: &Path) -> Result<()> {
    let _ = tokio::fs::remove_dir_all(root).await;
    for (name, target) in &plan.layout {
        let to = root.join(target.replace('\\', "/"));
        if let Some(parent) = to.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        if tokio::fs::hard_link(dl.join(name), &to).await.is_err() {
            tokio::fs::copy(dl.join(name), &to).await.with_context(|| format!("laying out {name}"))?;
        }
    }
    for (app, xml) in &plan.licenses {
        let dir = root.join(app);
        tokio::fs::create_dir_all(&dir).await?;
        tokio::fs::write(dir.join("License.xml"), xml.as_bytes()).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const APPS: &str = r#"<CompDB><Features>
    <Feature Type="MSIXFramework" FeatureID="Microsoft.VCLibs.140.00_8wekyb3d8bbwe" FMID="MSDN" Group="PreinstalledApps">
      <Packages><Package ID="VCLibs_x64" PackageType="MSIXFrameworkPackage" /></Packages>
    </Feature>
    <Feature Type="MSIXBundle" FeatureID="Microsoft.WindowsStore_8wekyb3d8bbwe" FMID="MSDN" Group="PreinstalledApps">
      <Dependencies><Feature FeatureID="Microsoft.VCLibs.140.00_8wekyb3d8bbwe" Type="Required" /></Dependencies>
      <CustomInformation><CustomInfo Key="licensedata"><![CDATA[<License ID="x"/>]]></CustomInfo></CustomInformation>
      <Packages><Package ID="Store_bundle" PackageType="MSIXBundlePackage" /><Package ID="Store_x64" PackageType="MSIXMainPackage" /></Packages>
    </Feature>
    <Feature Type="MSIXBundle" FeatureID="Microsoft.BingNews_8wekyb3d8bbwe" FMID="MSDN" Group="PreinstalledApps">
      <CustomInformation><CustomInfo Key="licensedata"><![CDATA[<License ID="n"/>]]></CustomInfo></CustomInformation>
      <Packages><Package ID="News_bundle" PackageType="MSIXBundlePackage" /><Package ID="News_stub" PackageType="MSIXStubPackage" /></Packages>
    </Feature>
  </Features>
  <Packages>
    <Package ID="VCLibs_x64"><Payload><PayloadItem PayloadHash="a" Path="UUP\Desktop\Apps\IPA\WinStore\Microsoft.VCLibs.x64.14.00.appx" /></Payload></Package>
    <Package ID="Store_bundle"><Payload><PayloadItem PayloadHash="b" Path="UUP\Desktop\Apps\IPA\WinStore\Microsoft.WindowsStore_8wekyb3d8bbwe.msixbundle" /></Payload></Package>
    <Package ID="Store_x64"><Payload><PayloadItem PayloadHash="c" Path="UUP\Desktop\Apps\IPA\WinStore\StorePackage_x64.msix" /></Payload></Package>
    <Package ID="News_bundle"><Payload><PayloadItem PayloadHash="d" Path="UUP\Desktop\Apps\IPA\BingNews\Microsoft.BingNews_8wekyb3d8bbwe.msixbundle" /></Payload></Package>
    <Package ID="News_stub"><Payload><PayloadItem PayloadHash="e" Path="UUP\Desktop\Apps\IPA\BingNews\AppxMetadata\Stub\NewsStub_x64.msix" /></Payload></Package>
  </Packages></CompDB>"#;

    fn f(name: &str) -> uup::File {
        uup::File { name: name.into(), url: String::new(), sha1: String::new(), size: 1 }
    }

    #[test]
    fn plans_frameworks_apps_and_stubs() {
        let pro = r#"<Feature FeatureID="Microsoft.WindowsStore_8wekyb3d8bbwe" FMID="MSDN" Group="PreinstalledApps" Type="Optional" />
            <Feature FeatureID="Microsoft.BingNews_8wekyb3d8bbwe" FMID="MSDN" Group="PreinstalledApps" Type="Optional" />
            <Feature FeatureID="Microsoft.MicrosoftPCManager_8wekyb3d8bbwe" FMID="MSDN" Group="PreinstalledApps" Type="Optional" />
            <Feature FeatureID="Microsoft-Windows-Foo" Group="Other" />"#;
        let catalog: Vec<uup::File> = ["Microsoft.VCLibs.x64.14.00.appx", "Microsoft.WindowsStore_8wekyb3d8bbwe.msixbundle", "StorePackage_x64.msix", "Microsoft.BingNews_8wekyb3d8bbwe.msixbundle", "NewsStub_x64.msix"].map(f).to_vec();
        let p = plan(APPS, &[Some(pro.into()), None], &catalog).unwrap();
        assert_eq!(p.frameworks, vec!["MSIXFramework\\Microsoft.VCLibs.x64.14.00.appx"]);
        assert_eq!(
            p.per_image[0],
            vec![
                App { id: "Microsoft.WindowsStore_8wekyb3d8bbwe".into(), main: "Microsoft.WindowsStore_8wekyb3d8bbwe.msixbundle".into(), stub: false },
                App { id: "Microsoft.BingNews_8wekyb3d8bbwe".into(), main: "Microsoft.BingNews_8wekyb3d8bbwe.msixbundle".into(), stub: true },
            ]
        );
        assert!(p.per_image[1].is_empty(), "an image without an edition CompDB gets no app");
        assert_eq!(p.missing, vec!["Microsoft.MicrosoftPCManager_8wekyb3d8bbwe"]);
        assert!(p.layout.contains(&("NewsStub_x64.msix".into(), "Microsoft.BingNews_8wekyb3d8bbwe\\AppxMetadata\\Stub\\NewsStub_x64.msix".into())));
        assert_eq!(p.licenses.len(), 2);
        assert_eq!(p.files.len(), 5);
    }
}

#[cfg(test)]
mod real {
    /// Against a real build's CompDBs and catalog list: APPS_REAL=<dir with
    /// DesktopTargetCompDB_App_Neutral.xml, DesktopTargetCompDB_professional_en-us.xml, appn.json>.
    #[test]
    #[ignore]
    fn real_build() {
        let dir = std::path::PathBuf::from(std::env::var("APPS_REAL").unwrap());
        let app = std::fs::read_to_string(dir.join("DesktopTargetCompDB_App_Neutral.xml")).unwrap();
        let pro = std::fs::read_to_string(dir.join("DesktopTargetCompDB_professional_en-us.xml")).unwrap();
        let j: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(dir.join("appn.json")).unwrap()).unwrap();
        let catalog: Vec<crate::uup::File> = j["response"]["files"].as_object().unwrap().iter()
            .map(|(n, f)| crate::uup::File { name: n.clone(), url: String::new(), sha1: String::new(), size: f["size"].as_str().unwrap().parse().unwrap() }).collect();
        let p = super::plan(&app, &[Some(pro)], &catalog).unwrap();
        let gb = p.files.iter().map(|f| f.size).sum::<u64>() as f64 / 1e9;
        println!("files {} ({gb:.2} GB), frameworks {}, apps {}, missing {:?}", p.files.len(), p.frameworks.len(), p.per_image[0].len(), p.missing);
        for a in &p.per_image[0] { println!("  {} | {} | stub {}", a.id, a.main, a.stub); }
        for f in &p.frameworks { println!("  fw {f}"); }
    }
}
