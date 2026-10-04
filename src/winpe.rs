//! The WinPE the Windows bakes boot, distilled from a Windows ISO - the path the kiln.sh
//! prototype proved (docs/windows-provisioning.md §0):
//!
//!   - the ISO's own boot files (bootmgr, boot/, efi/),
//!   - boot.wim **index 2**, the Setup environment. Index 1, the bare WinPE, applies images
//!     but cannot host DISM's offline servicing: every /Image: call fails with 0x80004002.
//!   - our startnet.cmd, and a winpeshl.ini that runs it instead of setup.exe,
//!   - efisys_noprompt.bin, so there is no "Press any key to boot from CD".
//!
//! Which ISO it is distilled from is a setting (General → Windows). The result is uploaded
//! into an ISO storage as winpe-<build>.iso (e.g. winpe-26100.1.iso) and reused by every bake.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

use crate::{jobs::JobLog, progress::Progress, pve::Pve, settings, uup};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct WinPe {
    /// The Windows ISO it was distilled from (volid).
    pub source_iso: String,
    /// The WinPE ISO in PVE (volid).
    pub volid: String,
    /// The node whose ISO storage holds it.
    pub node: String,
    pub built: String,
    /// boot.wim's build, for the page.
    pub build: String,
    /// The virtio-win release whose vioscsi driver is inside (X:\pvs\drivers\vioscsi), so
    /// a pass reaches a virtio-scsi disk without the virtio ISO; "" for a WinPE built before.
    #[serde(default)]
    pub vioscsi: String,
}

const STARTNET: &str = r#"@echo off
rem PVE VM Studio WinPE. Finds the bake's seed CD and runs the pass it carries; every
rem marker goes to COM1, which the studio reads through PVE's serial console.
wpeinit
rem COM1 has no name in WinPE: serial.sys is bound, but the ports class installer that
rem gives it PortName does not run here, so there is no COM1 to open. Name it, restart
rem the device, then wait until it takes a write (the first second it still refuses).
rem (No findstr in WinPE: the key itself is told apart from its instances by its name.)
for /f "delims=" %%k in ('reg query HKLM\SYSTEM\CurrentControlSet\Enum\ACPI\PNP0501 2^>nul') do if /i not "%%~nxk"=="PNP0501" (
  reg add "%%k\Device Parameters" /v PortName /t REG_SZ /d COM1 /f >nul
  pnputil /restart-device "ACPI\PNP0501\%%~nxk" >nul
)
set /a n=0
:com
(echo PVS-PE-START> COM1) 2>nul && goto com_ok
set /a n+=1
if %n% lss 30 (ping -n 2 127.0.0.1 >nul & goto com)
:com_ok
for %%d in (C D E F G H I J K L M N O P Q R S T U V W Y Z) do if exist %%d:\pvs\pe.cmd call %%d:\pvs\pe.cmd %%d: & goto :done
echo PVS-PE-NO-SEED > COM1
:done
rem winpeshl restarts WinPE whenever this script ends - a pass that stopped early must
rem power off, not loop.
wpeutil shutdown
"#;

const WINPESHL: &str = "[LaunchApps]\n%SYSTEMROOT%\\System32\\cmd.exe, /c %SYSTEMROOT%\\System32\\startnet.cmd\n";

fn crlf(s: &str) -> String {
    s.replace("\r\n", "\n").replace('\n', "\r\n")
}

pub(crate) async fn run(log: &JobLog, cmd: &str, args: &[&str]) -> Result<String> {
    let out = tokio::process::Command::new(cmd)
        .args(args)
        .output()
        .await
        .with_context(|| format!("running {cmd} - is it installed?"))?;
    let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    if !out.status.success() {
        for l in text.lines().rev().take(5).collect::<Vec<_>>().into_iter().rev() {
            log.debug(format!("{cmd} | {l}")).await;
        }
        bail!("{cmd} failed ({})", out.status);
    }
    Ok(text)
}

/// What either source hands the shared back end: the ISO tree's boot files (bootmgr,
/// bootmgr.efi, boot/, efi/ - nothing else), a one-image Setup-environment WIM, its build.
struct Staged {
    root: PathBuf,
    pe: PathBuf,
    build: String,
}

/// The full build number of a WIM image: Build plus Service Pack Build, 26100.1.
pub(crate) async fn image_build(log: &JobLog, wim: &Path, index: &str) -> Result<String> {
    let info = run(log, "wimlib-imagex", &["info", &wim.display().to_string(), index]).await?;
    let field = |k: &str| info.lines().find_map(|l| l.strip_prefix(k).map(|v| v.trim().to_owned())).unwrap_or_default();
    Ok(match (field("Build:"), field("Service Pack Build:")) {
        (b, _) if b.is_empty() => bail!("{} image {index} carries no build number", wim.display()),
        (b, sp) if sp.is_empty() => b,
        (b, sp) => format!("{b}.{sp}"),
    })
}

/// From a Windows ISO: its boot files, and boot.wim index 2 - the Setup environment.
/// Index 1, the bare WinPE, applies images but cannot host DISM's offline servicing: every
/// /Image: call fails with 0x80004002.
async fn stage_iso(log: &JobLog, dir: &Path, source_volid: &str, iso_path: &Path) -> Result<Staged> {
    let root = dir.join("root");
    log.run(format!("Extracting the boot files and boot.wim from {source_volid}")).await;
    let out = format!("-o{}", root.display());
    run(log, "7z", &["x", "-y", "-bd", &out, &iso_path.display().to_string(), "bootmgr", "bootmgr.efi", "boot", "efi", "sources/boot.wim"]).await?;
    let wim = root.join("sources/boot.wim");
    if !wim.exists() || !root.join("efi/microsoft/boot/efisys_noprompt.bin").exists() {
        bail!("{source_volid} has no sources/boot.wim or efi/microsoft/boot/efisys_noprompt.bin - not a Windows ISO?");
    }
    let info = run(log, "wimlib-imagex", &["info", &wim.display().to_string()]).await?;
    let count = info.lines().find_map(|l| l.strip_prefix("Image Count:")).map(str::trim).unwrap_or("0").to_owned();
    if count != "2" {
        bail!("boot.wim has {count} image(s); a Windows ISO's has two, and the bakes need index 2 (the Setup environment)");
    }
    let build = image_build(log, &wim, "2").await?;
    log.ok(format!("boot.wim: index 2 is the Setup environment, build {build}")).await;
    let pe = dir.join("pe.wim");
    run(log, "wimlib-imagex", &["export", &wim.display().to_string(), "2", &pe.display().to_string(), "--boot"]).await?;
    tokio::fs::remove_file(&wim).await?;
    Ok(Staged { root, pe, build })
}

/// What Setup's boot.wim index 2 carries in X:\sources beyond WinRE - Setup and its own
/// DISM (dism.exe, dismcore.dll, the providers), which is what lets the passes service an
/// offline image. Windows' media builder puts these in; UUP media has no boot.wim, so the
/// list is the one UUP dump's converter rebuilds index 2 with. Each also comes as
/// <lang>\<file>.mui when it has one.
const SETUP_SOURCES: &str = "alert.gif api-ms-win-core-apiquery-l1-1-0.dll api-ms-win-downlevel-advapi32-l1-1-0.dll \
api-ms-win-downlevel-advapi32-l1-1-1.dll api-ms-win-downlevel-advapi32-l2-1-0.dll api-ms-win-downlevel-advapi32-l2-1-1.dll \
api-ms-win-downlevel-advapi32-l3-1-0.dll api-ms-win-downlevel-advapi32-l4-1-0.dll api-ms-win-downlevel-kernel32-l1-1-0.dll \
api-ms-win-downlevel-kernel32-l2-1-0.dll api-ms-win-downlevel-ole32-l1-1-0.dll api-ms-win-downlevel-ole32-l1-1-1.dll \
api-ms-win-downlevel-shlwapi-l1-1-0.dll api-ms-win-downlevel-shlwapi-l1-1-1.dll api-ms-win-downlevel-user32-l1-1-0.dll \
api-ms-win-downlevel-user32-l1-1-1.dll api-ms-win-downlevel-version-l1-1-0.dll appcompat.xsl appcompat_bidi.xsl \
appcompat_detailed_bidi_txt.xsl appcompat_detailed_txt.xsl appraiser.dll ARUNIMG.dll arunres.dll autorun.dll bcd.dll \
bootsvc.dll cmisetup.dll compatctrl.dll compatprovider.dll compliance.ini cryptosetup.dll diager.dll diagnostic.dll \
diagtrack.dll diagtrackrunner.exe dism.exe dismapi.dll dismcore.dll dismcoreps.dll dismprov.dll \
ext-ms-win-advapi32-encryptedfile-l1-1-0.dll folderprovider.dll hwcompat.dll hwcompat.txt hwcompatPE.txt hwexclude.txt \
hwexcludePE.txt hwreqchk.dll idwbinfo.txt imagelib.dll imagingprovider.dll input.dll lang.ini locale.nls logprovider.dll \
MediaSetupUIMgr.dll ndiscompl.dll nlsbres.dll ntdsupg.dll offline.xml pnpibs.dll reagent.admx reagent.dll reagent.xml \
rollback.exe schema.dat segoeui.ttf ServicingCommon.dll setup.exe setupcompat.dll SetupCore.dll SetupHost.exe SetupMgr.dll \
SetupPlatform.cfg SetupPlatform.dll SetupPlatform.exe SetupPrep.exe SmiEngine.dll spflvrnt.dll spprgrss.dll spwizeng.dll \
spwizimg.dll spwizres.dll sqmapi.dll testplugin.dll unattend.dll unbcl.dll upgloader.dll upgrade_frmwrk.xml utcapi.dll \
uxlib.dll uxlibres.dll vhdprovider.dll w32uiimg.dll w32uires.dll warning.gif wdsclient.dll wdsclientapi.dll \
wdscommonlib.dll wdscore.dll wdscsl.dll wdsimage.dll wdstptc.dll wdsutil.dll wimgapi.dll wimprovider.dll win32ui.dll \
WinDlp.dll winsetup.dll wpx.dll xmllite.dll deployprovider.dll osimageprovider.dll pnppropmig.dll UnattendMgr.dll \
UpdateCompression.dll WinSetupBoot.hiv WinSetupBoot.sys WinSetupMon.hiv WinSetupMon.sys";
const SETUP_SOURCES_MUI: &str = "appraiser.dll.mui arunres.dll.mui cmisetup.dll.mui compatctrl.dll.mui compatprovider.dll.mui \
deployprovider.dll.mui dism.exe.mui dismapi.dll.mui dismcore.dll.mui dismprov.dll.mui folderprovider.dll.mui \
imagingprovider.dll.mui input.dll.mui logprovider.dll.mui MediaSetupUIMgr.dll.mui nlsbres.dll.mui osimageprovider.dll.mui \
pnpibs.dll.mui reagent.adml reagent.dll.mui rollback.exe.mui setup.exe.mui setup_help_upgrade_or_custom.rtf \
setupcompat.dll.mui SetupCore.dll.mui SetupMgr.dll.mui setupplatform.exe.mui SetupPrep.exe.mui smiengine.dll.mui \
spwizres.dll.mui upgloader.dll.mui uxlibres.dll.mui vhdprovider.dll.mui vofflps.rtf vofflps_server.rtf w32uires.dll.mui \
wdsclient.dll.mui wdsimage.dll.mui wimgapi.dll.mui wimprovider.dll.mui WinDlp.dll.mui winsetup.dll.mui";

/// From an edition's ESD (UUP media): image 1's boot files, and the Setup environment
/// built the way Windows' own media has it - WinRE (image 2) with Setup's sources added.
async fn stage_esd(log: &JobLog, dir: &Path, esd: &Path) -> Result<Staged> {
    let media = dir.join("media");
    let root = dir.join("root");
    tokio::fs::create_dir_all(&root).await?;
    let esd_s = esd.display().to_string();
    let info = run(log, "wimlib-imagex", &["info", &esd_s]).await?;
    let count = info.lines().find_map(|l| l.strip_prefix("Image Count:")).map(str::trim).unwrap_or("0").to_owned();
    if count.parse::<u32>().unwrap_or(0) < 3 {
        bail!("{} has {count} image(s); an edition's ESD has Setup media, WinRE and the install image", esd.display());
    }
    log.run("Building the Setup environment from the ESD").await;
    log.line("Applying the Setup media (ESD image 1)").await;
    run(log, "wimlib-imagex", &["apply", &esd_s, "1", &media.display().to_string(), "--no-acls", "--no-attributes"]).await?;
    for f in ["bootmgr", "bootmgr.efi", "boot", "efi"] {
        let from = media.join(f);
        if !from.exists() {
            bail!("the ESD's Setup media has no {f}");
        }
        tokio::fs::rename(&from, root.join(f)).await?;
    }
    if !root.join("efi/microsoft/boot/efisys_noprompt.bin").exists() {
        bail!("the ESD's Setup media has no efi/microsoft/boot/efisys_noprompt.bin");
    }
    let build = image_build(log, esd, "2").await?;
    log.line(format!("Exporting WinRE (ESD image 2, build {build}) as the Setup environment")).await;
    let pe = dir.join("pe.wim");
    let pe_s = pe.display().to_string();
    run(log, "wimlib-imagex", &["export", &esd_s, "2", &pe_s, "--compress=maximum", "--boot"]).await?;
    // Named and flagged as Setup's index 2 is (FLAGS 2), not as WinRE.
    run(log, "wimlib-imagex", &["info", &pe_s, "1", "Microsoft Windows Setup", "Microsoft Windows Setup", "--image-property", "FLAGS=2"]).await?;

    let (mut cmds, n) = setup_source_cmds(&media).await?;
    cmds.insert_str(0, "delete --force /Windows/System32/winpeshl.ini\n");
    wim_update(&pe, &cmds).await?;
    log.ok(format!("Setup environment built: WinRE {build} with {n} Setup files in X:\\sources (DISM among them)")).await;
    let _ = tokio::fs::remove_dir_all(&media).await;
    Ok(Staged { root, pe, build })
}

/// The wimlib update commands that put Setup's files into a Setup environment: X:\sources
/// (with each file's <lang>\*.mui), setup.exe and sources\inf\setup.cfg - matched
/// case-insensitively against `media`, an applied Setup media image. Returns them and how
/// many sources files they add.
pub(crate) async fn setup_source_cmds(media: &Path) -> Result<(String, usize)> {
    // Setup's files into X:\sources, matched case-insensitively against the media's own.
    let src = media.join("sources");
    let mut have = std::collections::HashMap::new();
    let mut rd = tokio::fs::read_dir(&src).await.context("the ESD's Setup media has no sources folder")?;
    while let Some(e) = rd.next_entry().await? {
        let name = e.file_name().to_string_lossy().into_owned();
        if e.file_type().await?.is_dir() {
            // Language folders (en-us, de-de) carry the .mui files.
            if name.len() == 5 && name.as_bytes()[2] == b'-' {
                let mut sub = tokio::fs::read_dir(e.path()).await?;
                while let Some(m) = sub.next_entry().await? {
                    have.insert(format!("{}/{}", name.to_lowercase(), m.file_name().to_string_lossy().to_lowercase()), format!("{name}/{}", m.file_name().to_string_lossy()));
                }
            }
        } else {
            have.insert(name.to_lowercase(), name);
        }
    }
    let langs: std::collections::BTreeSet<String> = have.keys().filter_map(|k| k.split_once('/').map(|(l, _)| l.to_owned())).collect();
    let mut cmds = String::new();
    let mut n = 0;
    let add = |rel: &str, cmds: &mut String| {
        cmds.push_str(&format!("add '{}' '/sources/{rel}'\n", src.join(rel).display()));
    };
    for f in SETUP_SOURCES.split_whitespace() {
        if let Some(real) = have.get(&f.to_lowercase()) {
            add(real, &mut cmds);
            n += 1;
        }
    }
    for l in &langs {
        for f in SETUP_SOURCES_MUI.split_whitespace() {
            if let Some(real) = have.get(&format!("{l}/{}", f.to_lowercase())) {
                add(real, &mut cmds);
                n += 1;
            }
        }
    }
    if !have.contains_key("dism.exe") || !have.contains_key("setup.exe") {
        bail!("the ESD's Setup media has no sources\\dism.exe or setup.exe - not an edition's ESD?");
    }
    cmds.push_str(&format!("add '{}' /setup.exe\n", media.join("setup.exe").display()));
    if media.join("sources/inf/setup.cfg").exists() {
        cmds.push_str(&format!("add '{}' /sources/inf/setup.cfg\n", media.join("sources/inf/setup.cfg").display()));
    }
    Ok((cmds, n))
}

pub(crate) async fn wim_update(wim: &Path, cmds: &str) -> Result<()> {
    use tokio::io::AsyncWriteExt;
    // Windows paths are case-insensitive: WinRE's sources\en-US takes the media's en-us
    // files instead of growing a second folder beside it.
    let mut child = tokio::process::Command::new("wimlib-imagex")
        .args(["update", &wim.display().to_string(), "1"])
        .env("WIMLIB_IMAGEX_IGNORE_CASE", "1")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()?;
    {
        let mut stdin = child.stdin.take().unwrap();
        stdin.write_all(cmds.as_bytes()).await?;
    }
    let out = child.wait_with_output().await?;
    if !out.status.success() {
        bail!("wimlib-imagex update failed: {}", String::from_utf8_lossy(&out.stderr).lines().last().unwrap_or(""));
    }
    Ok(())
}

/// The shared back end: our startnet.cmd and winpeshl.ini (and vioscsi) into the Setup
/// environment, the ISO around it, the upload, the setting.
#[allow(clippy::too_many_arguments)]
async fn finish(
    pve: &Pve,
    db: &SqlitePool,
    log: &JobLog,
    pr: &mut Progress,
    span: (f64, f64),
    dir: &Path,
    st: Staged,
    source: &str,
    node: &str,
    iso_storage: &str,
    virtio: Option<(&str, &Path)>,
) -> Result<WinPe> {
    let at = |f: f64| span.0 + (span.1 - span.0) * f;
    let files = dir.join("files");
    tokio::fs::create_dir_all(&files).await?;
    pr.stage(at(0.0), at(0.4), "startnet.cmd into the Setup environment");
    tokio::fs::write(files.join("startnet.cmd"), crlf(STARTNET)).await?;
    tokio::fs::write(files.join("winpeshl.ini"), crlf(WINPESHL)).await?;
    let mut cmds = format!(
        "add {} /Windows/System32/startnet.cmd\nadd {} /Windows/System32/winpeshl.ini\n",
        files.join("startnet.cmd").display(),
        files.join("winpeshl.ini").display()
    );
    // vioscsi for this WinPE's build into the image: the deploy pass reaches the VM's
    // virtio-scsi disk with no virtio ISO attached (drvload X:\pvs\drivers\vioscsi\...).
    let mut embedded = String::new();
    if let Some((release, viso)) = virtio {
        let drivers = dir.join("drivers");
        let out = format!("-o{}", drivers.display());
        run(log, "7z", &["x", "-y", "-bd", &out, &viso.display().to_string(), "vioscsi/2k25/amd64", "vioscsi/w11/amd64"]).await?;
        if drivers.join("vioscsi").exists() {
            cmds += &format!("add {} /pvs/drivers/vioscsi\n", drivers.join("vioscsi").display());
            embedded = release.to_owned();
            log.ok(format!("vioscsi from virtio-win {release} goes into WinPE")).await;
        } else {
            log.warn(format!("virtio-win {release} has no vioscsi for 2k25/w11 - the passes keep attaching the virtio ISO")).await;
        }
    }
    wim_update(&st.pe, &cmds).await?;
    tokio::fs::create_dir_all(st.root.join("sources")).await?;
    tokio::fs::rename(&st.pe, st.root.join("sources/boot.wim")).await?;
    log.ok("startnet.cmd and winpeshl.ini are in; WinPE runs our passes instead of Setup").await;

    pr.stage(at(0.4), at(0.6), "building the ISO");
    let iso = dir.join("winpe.iso");
    run(
        log,
        "xorriso",
        &[
            "-as", "mkisofs", "-quiet", "-iso-level", "3", "-J", "-joliet-long", "-R", "-V", "PVSWINPE",
            "-e", "efi/microsoft/boot/efisys_noprompt.bin", "-no-emul-boot",
            "-o", &iso.display().to_string(), &st.root.display().to_string(),
        ],
    )
    .await?;

    pr.stage(at(0.6), at(1.0), "uploading to PVE");
    let name = format!("winpe-{}.iso", st.build);
    let volid = format!("{iso_storage}:iso/{name}");
    // A rebuild replaces the old one; bakes read it only while they run.
    if pve.storage_content(node, iso_storage, "iso").await?.iter().any(|v| v.volid == volid) {
        pve.delete_volume(node, &volid).await?;
    }
    let volid = pve.upload(node, iso_storage, "iso", &iso, &name).await?;
    log.ok(format!("WinPE uploaded as {volid}")).await;
    let pe = WinPe {
        source_iso: source.to_owned(),
        volid,
        node: node.to_owned(),
        built: chrono::Utc::now().to_rfc3339(),
        build: st.build,
        vioscsi: embedded,
    };
    settings::save(db, "winpe", &pe).await?;
    Ok(pe)
}

/// Builds the WinPE ISO from `iso_path` (the source ISO, readable through the ISO mount)
/// and uploads it. Returns what the setting records.
#[allow(clippy::too_many_arguments)]
pub async fn build(
    pve: &Pve,
    db: &SqlitePool,
    log: &JobLog,
    work: &Path,
    source_volid: &str,
    iso_path: &Path,
    node: &str,
    iso_storage: &str,
    virtio: Option<(&str, &Path)>,
) -> Result<WinPe> {
    let mut pr = Progress::new(log, "Building WinPE");
    let dir: PathBuf = work.join(format!("winpe-{}", uuid::Uuid::new_v4().simple()));
    let result = async {
        tokio::fs::create_dir_all(&dir).await?;
        pr.stage(0.0, 25.0, "extracting the boot files");
        let st = stage_iso(log, &dir, source_volid, iso_path).await?;
        finish(pve, db, log, &mut pr, (25.0, 100.0), &dir, st, source_volid, node, iso_storage, virtio).await
    }
    .await;
    let _ = tokio::fs::remove_dir_all(&dir).await;
    result
}

/// Builds the WinPE ISO from Microsoft's own files: the UUP dump catalog names the files of
/// `uuid` in `lang`, the studio downloads the smallest edition's ESD from Microsoft's CDN,
/// checks its SHA-1 and builds the Setup environment from it - no Windows ISO needed.
#[allow(clippy::too_many_arguments)]
pub async fn build_uup(
    pve: &Pve,
    db: &SqlitePool,
    log: &JobLog,
    web: &reqwest::Client,
    work: &Path,
    uuid: &str,
    lang: &str,
    node: &str,
    iso_storage: &str,
    virtio: Option<(&str, &Path)>,
) -> Result<WinPe> {
    let mut pr = Progress::new(log, "Building WinPE");
    let dir: PathBuf = work.join(format!("winpe-{}", uuid::Uuid::new_v4().simple()));
    let result = async {
        tokio::fs::create_dir_all(&dir).await?;
        pr.stage(0.0, 2.0, "asking the UUP dump catalog");
        log.get(format!("Asking the UUP dump catalog for build {uuid} in {lang}")).await;
        let editions = uup::editions(web, uuid, lang).await?;
        let edition = uup::winpe_edition(&editions).ok_or_else(|| anyhow::anyhow!("the catalog lists no editions for {uuid} in {lang}"))?;
        let files = uup::files(web, uuid, lang, &edition).await?;
        let esd = uup::edition_esd(&files, &edition, lang).ok_or_else(|| anyhow::anyhow!("the catalog lists no {edition}_{lang}.esd for {uuid}"))?;
        log.ok(format!("{edition} carries the smallest Setup media and WinRE: {} ({:.1} GB)", esd.name, esd.size as f64 / 1e9)).await;

        pr.stage(2.0, 70.0, "downloading from Microsoft");
        let path = dir.join(&esd.name);
        uup::download(web, log, &mut pr, &esd, &path).await?;

        pr.stage(70.0, 85.0, "building the Setup environment");
        let st = stage_esd(log, &dir, &path).await?;
        let _ = tokio::fs::remove_file(&path).await;
        let source = format!("uup:{uuid} {} {lang}", esd.name);
        finish(pve, db, log, &mut pr, (85.0, 100.0), &dir, st, &source, node, iso_storage, virtio).await
    }
    .await;
    let _ = tokio::fs::remove_dir_all(&dir).await;
    result
}
