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
//! into an ISO storage as pvs-winpe-<iso>.iso and reused by every bake.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

use crate::{jobs::JobLog, progress::Progress, pve::Pve, settings};

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

async fn run(log: &JobLog, cmd: &str, args: &[&str]) -> Result<String> {
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

/// Builds the WinPE ISO from `iso_path` (the source ISO, readable through the ISO mount)
/// and uploads it. Returns what the setting records.
pub async fn build(
    pve: &Pve,
    db: &SqlitePool,
    log: &JobLog,
    work: &Path,
    source_volid: &str,
    iso_path: &Path,
    node: &str,
    iso_storage: &str,
) -> Result<WinPe> {
    let mut pr = Progress::new(log, "Building WinPE");
    let stem = iso_path.file_stem().and_then(|s| s.to_str()).unwrap_or("windows").to_owned();
    let dir: PathBuf = work.join(format!("winpe-{}", uuid::Uuid::new_v4().simple()));
    let root = dir.join("root");
    let files = dir.join("files");
    let result = async {
        tokio::fs::create_dir_all(&files).await?;

        pr.stage(0.0, 25.0, "extracting the boot files");
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
        let build = run(log, "wimlib-imagex", &["info", &wim.display().to_string(), "2"])
            .await?
            .lines()
            .find_map(|l| l.strip_prefix("Build:").map(|b| b.trim().to_owned()))
            .unwrap_or_default();
        log.ok(format!("boot.wim: index 2 is the Setup environment, build {build}")).await;

        pr.stage(25.0, 55.0, "boot.wim index 2 with startnet.cmd");
        // Index 2 alone, as a bootable image; then our two files into it.
        let pe = dir.join("boot.wim");
        run(log, "wimlib-imagex", &["export", &wim.display().to_string(), "2", &pe.display().to_string(), "--boot"]).await?;
        tokio::fs::write(files.join("startnet.cmd"), crlf(STARTNET)).await?;
        tokio::fs::write(files.join("winpeshl.ini"), crlf(WINPESHL)).await?;
        let cmds = format!(
            "add {} /Windows/System32/startnet.cmd\nadd {} /Windows/System32/winpeshl.ini\n",
            files.join("startnet.cmd").display(),
            files.join("winpeshl.ini").display()
        );
        let mut child = tokio::process::Command::new("wimlib-imagex")
            .args(["update", &pe.display().to_string(), "1"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .spawn()?;
        {
            use tokio::io::AsyncWriteExt;
            let mut stdin = child.stdin.take().unwrap();
            stdin.write_all(cmds.as_bytes()).await?;
        }
        if !child.wait().await?.success() {
            bail!("wimlib-imagex update failed");
        }
        tokio::fs::rename(&pe, &wim).await?;
        log.ok("startnet.cmd and winpeshl.ini are in; WinPE runs our passes instead of Setup").await;

        pr.stage(55.0, 70.0, "building the ISO");
        let iso = dir.join("winpe.iso");
        run(
            log,
            "xorriso",
            &[
                "-as", "mkisofs", "-quiet", "-iso-level", "3", "-J", "-joliet-long", "-R", "-V", "PVSWINPE",
                "-e", "efi/microsoft/boot/efisys_noprompt.bin", "-no-emul-boot",
                "-o", &iso.display().to_string(), &root.display().to_string(),
            ],
        )
        .await?;

        pr.stage(70.0, 100.0, "uploading to PVE");
        let name = format!("pvs-winpe-{stem}.iso");
        let volid = format!("{iso_storage}:iso/{name}");
        // A rebuild replaces the old one; bakes read it only while they run.
        if pve.storage_content(node, iso_storage, "iso").await?.iter().any(|v| v.volid == volid) {
            pve.delete_volume(node, &volid).await?;
        }
        let volid = pve.upload(node, iso_storage, "iso", &iso, &name).await?;
        log.ok(format!("WinPE uploaded as {volid}")).await;
        let pe = WinPe {
            source_iso: source_volid.to_owned(),
            volid,
            node: node.to_owned(),
            built: chrono::Utc::now().to_rfc3339(),
            build,
        };
        settings::save(db, "winpe", &pe).await?;
        Ok(pe)
    }
    .await;
    let _ = tokio::fs::remove_dir_all(&dir).await;
    result
}
