//! Windows golds and VMs on PVE.
//!
//! Bake, in order - an unattended Windows Setup, then audit mode, then sysprep:
//!   1. A bake VM (OVMF with Microsoft's keys, TPM 2.0, virtio-scsi, NIC link down so
//!      nothing updates between Setup and sysprep) with three CDs: the Windows ISO, the
//!      virtio-win ISO and the bake seed. The OVMF "press any key" prompt is answered
//!      through the API (sendkey).
//!   2. Setup reads autounattend.xml from the seed: virtio storage and network drivers in
//!      the windowsPE pass, disk layout, the chosen image, a KMS client key (GVLK) so the
//!      edition is set and OOBE has no key page. Progress: bytes written to the system disk
//!      against the image's size from install.wim.
//!   3. oobeSystem reseals into audit mode; auditUser runs audit.cmd from the seed: the
//!      QEMU guest agent first (from here the studio follows the log through it), then
//!      virtio-win-gt, the chosen policies, the gold's answer file, and
//!      `sysprep /generalize /oobe /mode:vm /quit`.
//!   4. The studio checks generalize worked (Sysprep_succeeded.tag, and State.ini saying
//!      IMAGE_STATE_GENERALIZE_RESEAL_TO_OOBE) before it shuts the VM down and makes it a
//!      template.
//!
//! A VM's first boot: the gold's specialize pass runs firstboot.cmd, which finds the VM's
//! own CD, names the machine and points Setup at the VM's answer file for oobeSystem
//! (Setup never searches a CD for one after generalize - see docs/windows-provisioning.md).
//! SetupComplete.cmd sets a static address when there is one and leaves the marker the
//! studio waits for; then the CD, which holds the passwords, is ejected and deleted.

use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use base64::Engine;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::SqlitePool;

use crate::{
    form,
    golds::{GOLD_IDS, GOLD_POOL},
    jobs::JobLog,
    progress::Progress,
    pve::{enc, Pve},
    seed::SeedIso,
    serial,
    settings::Placement,
    wim::WimImage,
};

// ---- catalog: keys, names ----

/// The KMS client (GVLK) keys Microsoft publishes. A GVLK activates against a KMS when
/// there is one; either way it selects the edition and keeps OOBE off its key page.
pub fn gvlk(edition_id: &str, build: &str) -> Option<&'static str> {
    let year = server_year(build);
    Some(match (edition_id, year) {
        ("ServerDatacenter", Some(2025)) => "D764K-2NDRG-47T6Q-P8T8W-YP6DF",
        ("ServerStandard", Some(2025)) => "TVRH6-WHNXV-R9WG3-9XRFY-MY832",
        ("ServerDatacenter", Some(2022)) => "WX4NM-KYWYW-QJJR4-XV3QB-6VM33",
        ("ServerStandard", Some(2022)) => "VDYBN-27WPP-V4HQT-9VMD4-VMK7H",
        ("ServerDatacenter", Some(2019)) => "WMDGN-G9PQG-XVVXX-R3X43-63DFG",
        ("ServerStandard", Some(2019)) => "N69G4-B89J2-4G8F4-WWYCC-J464C",
        ("ServerDatacenter", Some(2016)) => "CB7KF-BWN84-R7R2Y-793K2-8XDDG",
        ("ServerStandard", Some(2016)) => "WC2BQ-8NRM3-FDDYY-2BFGV-KHKQY",
        ("Professional", None) => "W269N-WFGWX-YVC9B-4J6C9-T83GX",
        ("ProfessionalN", None) => "MH37W-N47XK-V7XM9-C7227-GCQG9",
        ("Enterprise", None) => "NPPR9-FWDCX-D2C8J-H872K-2YT43",
        ("EnterpriseN", None) => "DPH2V-TTNVB-4X9Q3-TJR4H-KHJW4",
        ("Education", None) => "NW6C2-QMPVW-D7KKK-3GKT6-VCFB2",
        ("EducationN", None) => "2WH4N-8QGBV-H22JP-CT43Q-MDWWJ",
        ("ProfessionalWorkstation", None) => "NRG8B-VKK3Q-CXVCJ-9G2XF-6Q84J",
        ("ServerRdsh", None) => "CPWHC-NT2C7-VYW78-DHDB2-PG3GK",
        _ => return None,
    })
}

pub fn server_year(build: &str) -> Option<u32> {
    match build {
        "26100" => Some(2025),
        "20348" => Some(2022),
        "17763" => Some(2019),
        "14393" => Some(2016),
        _ => None,
    }
}

fn is_server(img: &WimImage) -> bool {
    img.installation_type.starts_with("Server")
}

/// The Hyper-V studio's image ids: ws2025-datacenter-core, w11-enterprise.
pub fn image_id(img: &WimImage) -> String {
    if let Some(year) = server_year(&img.build).filter(|_| is_server(img)) {
        let ed = img.edition_id.trim_start_matches("Server").to_lowercase();
        let kind = if img.installation_type == "Server Core" { "core" } else { "desktop" };
        format!("ws{year}-{ed}-{kind}")
    } else {
        let ed = match img.edition_id.as_str() {
            "Professional" => "pro",
            "ProfessionalN" => "pro-n",
            "Enterprise" => "enterprise",
            "EnterpriseN" => "enterprise-n",
            "ServerRdsh" => "enterprise-ms",
            "Education" => "education",
            other => return format!("w11-{}", other.to_lowercase()),
        };
        format!("w11-{ed}")
    }
}

/// virtio-win's folder for the drivers of this Windows.
fn virtio_dir(img: &WimImage) -> &'static str {
    match (server_year(&img.build), is_server(img)) {
        (Some(2025), true) => "2k25",
        (Some(2022), true) => "2k22",
        (Some(2019), true) => "2k19",
        (Some(2016), true) => "2k16",
        _ => "w11",
    }
}

// ---- region ----

/// Windows region settings, from the studio's locale catalog (HyperV-Scripts' locales.json).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WinRegion {
    /// Formats and system locale, e.g. de-DE.
    pub locale: String,
    /// Keyboard, as a locale tag (de-DE -> 0407:00000407).
    pub keyboard: String,
    /// A Windows time zone id ("W. Europe Standard Time").
    pub timezone: String,
}

/// "de-DE" -> "0407:00000407", from locales.json.
pub fn input_locale(tag: &str) -> String {
    let all: serde_json::Value = serde_json::from_str(crate::catalog::LOCALES).unwrap_or_default();
    let l = &all["locales"][tag];
    let lang = l["LangId"].as_str().unwrap_or("0409").to_lowercase();
    let kb = l["Keyboard"].as_str().unwrap_or("00000409").to_lowercase();
    format!("{lang}:{kb}")
}

/// The Windows time zones people pick, with the IANA name they correspond to.
pub static TIME_ZONES: &[(&str, &str)] = &[
    ("UTC", "UTC"),
    ("GMT Standard Time", "Europe/London"),
    ("W. Europe Standard Time", "Europe/Berlin"),
    ("Romance Standard Time", "Europe/Paris"),
    ("Central Europe Standard Time", "Europe/Prague"),
    ("Central European Standard Time", "Europe/Warsaw"),
    ("FLE Standard Time", "Europe/Helsinki"),
    ("GTB Standard Time", "Europe/Athens"),
    ("E. Europe Standard Time", "Europe/Chisinau"),
    ("Turkey Standard Time", "Europe/Istanbul"),
    ("Russian Standard Time", "Europe/Moscow"),
    ("Arabian Standard Time", "Asia/Dubai"),
    ("India Standard Time", "Asia/Kolkata"),
    ("China Standard Time", "Asia/Shanghai"),
    ("Singapore Standard Time", "Asia/Singapore"),
    ("Tokyo Standard Time", "Asia/Tokyo"),
    ("AUS Eastern Standard Time", "Australia/Sydney"),
    ("New Zealand Standard Time", "Pacific/Auckland"),
    ("Eastern Standard Time", "America/New_York"),
    ("Central Standard Time", "America/Chicago"),
    ("Mountain Standard Time", "America/Denver"),
    ("Pacific Standard Time", "America/Los_Angeles"),
    ("E. South America Standard Time", "America/Sao_Paulo"),
    ("South Africa Standard Time", "Africa/Johannesburg"),
];

pub fn windows_tz_for(iana: &str) -> &'static str {
    match iana {
        "Europe/Berlin" | "Europe/Amsterdam" | "Europe/Vienna" | "Europe/Zurich" | "Europe/Rome"
        | "Europe/Stockholm" | "Europe/Oslo" | "Europe/Luxembourg" => "W. Europe Standard Time",
        "Europe/Paris" | "Europe/Madrid" | "Europe/Brussels" | "Europe/Copenhagen" => "Romance Standard Time",
        "Europe/Warsaw" | "Europe/Zagreb" | "Europe/Sarajevo" => "Central European Standard Time",
        "Europe/Prague" | "Europe/Budapest" | "Europe/Belgrade" | "Europe/Bratislava" => "Central Europe Standard Time",
        "Europe/London" | "Europe/Dublin" | "Europe/Lisbon" => "GMT Standard Time",
        "Europe/Helsinki" | "Europe/Kyiv" | "Europe/Riga" | "Europe/Tallinn" | "Europe/Vilnius" => "FLE Standard Time",
        other => TIME_ZONES.iter().find(|(_, i)| *i == other).map(|(w, _)| *w).unwrap_or("UTC"),
    }
}

// ---- what a bake is asked for ----

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WinBakeOptions {
    /// The Windows ISO's volid in PVE, e.g. local:iso/enus-ws2025.iso.
    pub iso: String,
    pub index: u32,
    pub region: WinRegion,
    /// rdp | ping | svrmgr
    #[serde(default)]
    pub features: Vec<String>,
}

/// The opt-in policies of New-Vhdx's offline customization (doc §4). Client golds also
/// always get: no device encryption, high performance power, the OOBE bypass.
pub static WIN_FEATURES: &[(&str, &str)] = &[
    ("rdp", "Remote Desktop on (with NLA), firewall open"),
    ("ping", "Answer ping (ICMPv4/v6 echo)"),
    ("svrmgr", "Server Manager does not open at logon (server)"),
    ("signinkeyboard", "Sign-in screen keeps the system keyboard (STIG)"),
    ("welcome", "No Windows welcome experience (client)"),
    ("firstlogon", "No first sign-in animation (client)"),
];

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

/// CRLF, as cmd.exe and Setup expect.
fn crlf(s: &str) -> String {
    s.replace("\r\n", "\n").replace('\n', "\r\n")
}

const NS: &str = r#"xmlns="urn:schemas-microsoft-com:unattend" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State""#;
const COMP: &str = r#"processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS""#;

// ---- the bake's scripts - kiln.sh's win_seed, with COM1 where kiln had its log disk ----

/// The gold's own answer file, written into Panther by pass 2. Its specialize pass runs
/// firstboot.cmd, which hands oobeSystem to the VM's file on the VM's CD - Setup never
/// searches a CD for one after generalize.
pub fn gold_unattend() -> String {
    format!(
        r#"<?xml version="1.0" encoding="utf-8"?>
<unattend {NS}>
  <settings pass="specialize">
    <component name="Microsoft-Windows-Deployment" {COMP}>
      <RunSynchronous>
        <RunSynchronousCommand wcm:action="add">
          <Order>1</Order>
          <Path>cmd /c C:\Windows\PVS\firstboot.cmd</Path>
          <Description>PVE VM Studio: name the VM, hand oobeSystem to its own answer file</Description>
        </RunSynchronousCommand>
      </RunSynchronous>
    </component>
  </settings>
</unattend>
"#
    )
}

/// Written by pass 1: reseal into audit mode, then audit.cmd from the seed CD. auditUser
/// runs exactly once - nothing in it may ask for a reboot.
pub fn audit_unattend() -> String {
    format!(
        r#"<?xml version="1.0" encoding="utf-8"?>
<unattend {NS}>
  <settings pass="oobeSystem">
    <component name="Microsoft-Windows-Deployment" {COMP}>
      <Reseal><Mode>Audit</Mode></Reseal>
    </component>
  </settings>
  <settings pass="auditUser">
    <component name="Microsoft-Windows-Deployment" {COMP}>
      <RunSynchronous>
        <RunSynchronousCommand wcm:action="add">
          <Order>1</Order>
          <Path>cmd /c for %d in (D E F G H I J K L M N O P Q R S T U V W Y Z) do @if exist %d:\pvs\audit.cmd %d:\pvs\audit.cmd %d:</Path>
          <Description>PVE VM Studio audit step: virtio drivers, guest agent, then generalize</Description>
        </RunSynchronousCommand>
      </RunSynchronous>
    </component>
  </settings>
</unattend>
"#
    )
}

/// WinPE pass 1: partition, apply, drivers, boot files, the audit-mode answer file.
pub fn pe1_cmd(img: &WimImage) -> String {
    let vdir = virtio_dir(img);
    crlf(&format!(
        r#"@echo off
rem PVE VM Studio WinPE pass 1: partition, apply, virtio drivers, boot files, the
rem audit-mode answer file. Every marker goes to COM1 - the studio reads the serial console.
setlocal
set SEED=%1
set SRC=
set VIO=
for %%d in (C D E F G H I J K L M N O P Q R S T U V W Y Z) do (
    if exist %%d:\sources\install.wim set SRC=%%d:\sources\install.wim
    if exist %%d:\sources\install.esd set SRC=%%d:\sources\install.esd
    if exist %%d:\virtio-win_license.txt set VIO=%%d:
)
echo PVS-PASS1-START SRC=%SRC% VIO=%VIO% INDEX={index} > COM1
if "%SRC%"=="" (echo PVS-NO-INSTALL-WIM > COM1 & goto :fail)
if "%VIO%"=="" (echo PVS-NO-VIRTIO-CD > COM1 & goto :fail)
rem WinPE has no driver for the virtio-scsi disk; the one for this WinPE's build.
for %%v in (2k25 w11 2k22) do if exist %VIO%\vioscsi\%%v\amd64\vioscsi.inf (drvload %VIO%\vioscsi\%%v\amd64\vioscsi.inf > COM1 2>&1 & goto :disk)
echo PVS-NO-VIOSCSI > COM1
goto :fail
:disk
rem A disk that arrives with a driver loaded at runtime (vioscsi, above) falls under
rem WinPE's SAN policy: offline and read-only - "clean" works, then everything after it
rem is "The media is write protected".
(
echo select disk 0
echo online disk noerr
echo attributes disk clear readonly noerr
echo clean
echo convert gpt
echo create partition efi size=200
echo format quick fs=fat32 label=System
echo assign letter=S
echo create partition msr size=128
echo create partition primary
echo format quick fs=ntfs label=Windows
echo assign letter=W
) > X:\dp.txt
diskpart /s X:\dp.txt > COM1 2>&1 || goto :fail
echo PVS-PARTITIONED > COM1
dism /English /Apply-Image /ImageFile:%SRC% /Index:{index} /ApplyDir:W:\ > COM1 2>&1 || goto :fail
echo PVS-APPLIED > COM1
rem The gold boots on virtio-scsi from its first start: the storage, network and serial
rem drivers go into the image offline.
dism /English /Image:W:\ /Add-Driver /Driver:%VIO%\vioscsi\{vdir}\amd64 /Driver:%VIO%\NetKVM\{vdir}\amd64 /Driver:%VIO%\vioserial\{vdir}\amd64 > COM1 2>&1 || goto :fail
echo PVS-DRIVERS > COM1
dism /English /Image:W:\ /Get-TargetEditions > COM1 2>&1
bcdboot W:\Windows /s S: /f UEFI > COM1 2>&1
rem Judged by the loader being there, not by the exit code - a bcdboot that did nothing
rem once shipped a gold that could not boot.
if not exist S:\EFI\Microsoft\Boot\bootmgfw.efi (echo PVS-NO-BOOTLOADER > COM1 & goto :fail)
echo PVS-BCDBOOT > COM1
rem install.wim can ship this tag, and pass 2 reads it as proof sysprep worked.
if exist W:\Windows\System32\Sysprep\Sysprep_succeeded.tag del /f /q W:\Windows\System32\Sysprep\Sysprep_succeeded.tag
mkdir W:\Windows\Panther
copy /y %SEED%\pvs\audit.xml W:\Windows\Panther\unattend.xml > COM1 2>&1 || goto :fail
echo PVS-PASS1-OK > COM1
goto :eof
:fail
echo PVS-PASS1-FAILED > COM1
"#,
        index = img.index
    ))
}

/// Audit mode, the gold's first boot: virtio drivers and the guest agent, then generalize.
/// No NIC traffic (the NIC's link is down) - nothing may update between boot and sysprep.
pub fn audit_cmd() -> String {
    crlf(
        r#"@echo off
rem PVE VM Studio, audit mode. Installing the drivers here binds each one to a real device;
rem auditUser runs once: nothing here may ask for a reboot.
setlocal
set SEED=%1
set LOG=C:\Windows\Temp\pvs-audit.log
set VIO=
for %%d in (D E F G H I J K L M N O P Q R S T U V W Y Z) do if exist %%d:\virtio-win_license.txt set VIO=%%d:
echo PVS-AUDIT-START VIO=%VIO% > COM1
msiexec /i %VIO%\virtio-win-gt-x64.msi /qn /norestart /l*v C:\Windows\Temp\virtio-win-gt.log
echo PVS-VIRTIO %ERRORLEVEL% > COM1
msiexec /i %VIO%\guest-agent\qemu-ga-x86_64.msi /qn /norestart /l*v C:\Windows\Temp\qemu-ga.log
echo PVS-QGA %ERRORLEVEL% > COM1
sc qc vioscsi > COM1 2>&1
if not exist C:\Windows\PVS mkdir C:\Windows\PVS
copy /y %SEED%\pvs\firstboot.cmd C:\Windows\PVS\firstboot.cmd > COM1 2>&1
echo PVS-SYSPREP-START > COM1
rem No /unattend, as in New-Vhdx: a cached answer file that is in use is not replaced by
rem one, so the audit-mode file would survive into the gold. Pass 2 writes the gold's
rem answer file offline instead.
C:\Windows\System32\Sysprep\Sysprep.exe /generalize /oobe /mode:vm /shutdown
"#,
    )
}

/// The gold's specialize hook (kiln.sh's firstboot.cmd): finds the VM's CD, names the
/// machine, points Setup at the VM's own answer file for oobeSystem, and puts the VM's
/// SetupComplete.cmd in place. No CD: leaves the pointer alone.
pub fn firstboot_cmd() -> String {
    crlf(
        r#"@echo off
setlocal
set LOG=C:\Windows\Temp\pvs-firstboot.log
set VM=
for %%d in (D E F G H I J K L M N O P Q R S T U V W Y Z) do if exist %%d:\pvs-vm\unattend.xml set VM=%%d:\pvs-vm
echo PVS-FIRSTBOOT %DATE% %TIME% VM=%VM% >> %LOG%
if "%VM%"=="" exit /b 0
call %VM%\vm.cmd
reg add "HKLM\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName" /v ComputerName /t REG_SZ /d %PVS_NAME% /f >> %LOG% 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v Hostname /t REG_SZ /d %PVS_NAME% /f >> %LOG% 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "NV Hostname" /t REG_SZ /d %PVS_NAME% /f >> %LOG% 2>&1
rem The file first, then the pointer to it.
copy /y %VM%\unattend.xml C:\Windows\Panther\pvs-vm.xml >> %LOG% 2>&1 || exit /b 0
reg add "HKLM\SYSTEM\Setup" /v UnattendFile /t REG_SZ /d C:\Windows\Panther\pvs-vm.xml /f >> %LOG% 2>&1
if not exist C:\Windows\Setup\Scripts mkdir C:\Windows\Setup\Scripts
copy /y %VM%\setupcomplete.cmd C:\Windows\Setup\Scripts\SetupComplete.cmd >> %LOG% 2>&1
if exist %VM%\GuestProvision xcopy /e /i /q /y %VM%\GuestProvision C:\Windows\Setup\Scripts\GuestProvision >> %LOG% 2>&1
echo PVS-FIRSTBOOT-OK %PVS_NAME% >> %LOG%
"#,
    )
}

/// The offline policies of New-Vhdx's Set-OfflineImageCustomization (doc §4), as reg.exe
/// writes against the loaded hives KSYS (SYSTEM) and KSOFT (SOFTWARE).
fn pass2_policies(features: &[String], client: bool) -> String {
    let fw = r"HKLM\KSYS\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules";
    let mut p = String::new();
    let has = |f: &str| features.iter().any(|x| x == f);
    if has("rdp") {
        p += &format!(
            r#"reg add "HKLM\KSYS\ControlSet001\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f > COM1 2>&1
reg add "HKLM\KSYS\ControlSet001\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 1 /f > COM1 2>&1
reg add "{fw}" /v Baked-RDP-TCP-In /t REG_SZ /d "v2.31|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=3389|Name=Remote Desktop (TCP-In)|Desc=Allow inbound RDP over TCP|EmbedCtxt=Remote Desktop|" /f > COM1 2>&1
reg add "{fw}" /v Baked-RDP-UDP-In /t REG_SZ /d "v2.31|Action=Allow|Active=TRUE|Dir=In|Protocol=17|LPort=3389|Name=Remote Desktop (UDP-In)|Desc=Allow inbound RDP over UDP|EmbedCtxt=Remote Desktop|" /f > COM1 2>&1
echo PVS-POLICY rdp > COM1
"#
        );
    }
    if has("ping") {
        p += &format!(
            r#"reg add "{fw}" /v Baked-ICMPv4-Echo-In /t REG_SZ /d "v2.31|Action=Allow|Active=TRUE|Dir=In|Protocol=1|ICMP4=8:*|Name=Allow ICMPv4 Echo Request (ping)|Desc=Allow inbound ping IPv4|EmbedCtxt=Ping|" /f > COM1 2>&1
reg add "{fw}" /v Baked-ICMPv6-Echo-In /t REG_SZ /d "v2.31|Action=Allow|Active=TRUE|Dir=In|Protocol=58|ICMP6=128:*|Name=Allow ICMPv6 Echo Request (ping)|Desc=Allow inbound ping IPv6|EmbedCtxt=Ping|" /f > COM1 2>&1
echo PVS-POLICY ping > COM1
"#
        );
    }
    if has("svrmgr") && !client {
        p += "reg add \"HKLM\\KSOFT\\Policies\\Microsoft\\Windows\\Server\\ServerManager\" /v DoNotOpenAtLogon /t REG_DWORD /d 1 /f > COM1 2>&1\necho PVS-POLICY svrmgr > COM1\n";
    }
    if has("signinkeyboard") {
        p += "reg add \"HKLM\\KSOFT\\Policies\\Microsoft\\Control Panel\\International\" /v BlockUserInputMethodsForSignIn /t REG_DWORD /d 1 /f > COM1 2>&1\necho PVS-POLICY signinkeyboard > COM1\n";
    }
    if client {
        // 24H2 auto-encrypts with Secure Boot + TPM, and swtpm + OVMF qualifies.
        p += "reg add \"HKLM\\KSYS\\ControlSet001\\Control\\BitLocker\" /v PreventDeviceEncryption /t REG_DWORD /d 1 /f > COM1 2>&1\necho PVS-POLICY no-device-encryption > COM1\n";
        // High performance through policy - writing the scheme tree itself is denied.
        p += r#"reg add "HKLM\KSOFT\Policies\Microsoft\Power\PowerSettings" /v ActivePowerScheme /t REG_SZ /d 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c /f > COM1 2>&1
reg add "HKLM\KSYS\ControlSet001\Control\Power" /v HibernateEnabled /t REG_DWORD /d 0 /f > COM1 2>&1
reg add "HKLM\KSYS\ControlSet001\Control\Power" /v HibernateEnabledDefault /t REG_DWORD /d 0 /f > COM1 2>&1
echo PVS-POLICY power > COM1
"#;
        // The client OOBE bypass is the same for every client VM, so it lives in the gold.
        for (k, v) in [("HideOnlineAccountScreens", 1), ("DisablePrivacyExperience", 1), ("DisableVoice", 1), ("PrivacyConsentStatus", 1), ("Protectyourpc", 3), ("HideEULAPage", 1)] {
            p += &format!("reg add \"HKLM\\KSOFT\\Microsoft\\Windows\\CurrentVersion\\OOBE\" /v {k} /t REG_DWORD /d {v} /f > COM1 2>&1\n");
        }
        p += "echo PVS-POLICY oobe-bypass > COM1\n";
        if has("welcome") {
            p += "reg add \"HKLM\\KSOFT\\Policies\\Microsoft\\Windows\\CloudContent\" /v DisableWindowsSpotlightWindowsWelcomeExperience /t REG_DWORD /d 1 /f > COM1 2>&1\necho PVS-POLICY welcome > COM1\n";
        }
        if has("firstlogon") {
            p += "reg add \"HKLM\\KSOFT\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\" /v EnableFirstLogonAnimation /t REG_DWORD /d 0 /f > COM1 2>&1\necho PVS-POLICY firstlogon > COM1\n";
        }
    }
    p
}

/// WinPE pass 2, on the generalized gold: prove generalize worked, then locale, time zone,
/// policies and the product key - offline, after generalize, in New-Vhdx's order.
pub fn pe2_cmd(img: &WimImage, region: &WinRegion, features: &[String]) -> String {
    let client = img.installation_type == "Client";
    let locale = &region.locale;
    let input = input_locale(if region.keyboard.is_empty() { locale } else { &region.keyboard });
    let tz = &region.timezone;
    let policies = pass2_policies(features, client);
    let key = match gvlk(&img.edition_id, &img.build) {
        Some(k) => format!("call :dism /Image:W:\\ /Set-ProductKey:{k} || goto :fail\necho PVS-KEY > COM1"),
        None => "echo PVS-NO-KEY > COM1".into(),
    };
    crlf(&format!(
        r#"@echo off
rem PVE VM Studio WinPE pass 2. Markers to COM1.
setlocal
set SEED=%1
set VIO=
for %%d in (C D E F G H I J K L M N O P Q R S T U V W Y Z) do if exist %%d:\virtio-win_license.txt set VIO=%%d:
for %%v in (2k25 w11 2k22) do if exist %VIO%\vioscsi\%%v\amd64\vioscsi.inf (drvload %VIO%\vioscsi\%%v\amd64\vioscsi.inf > COM1 2>&1 & goto :disk)
echo PVS-NO-VIOSCSI > COM1
goto :fail
:disk
(
echo select disk 0
echo select partition 3
echo assign letter=W
) > X:\dp.txt
diskpart /s X:\dp.txt > COM1 2>&1
echo PVS-PASS2-START > COM1
type W:\Windows\Setup\State\State.ini > COM1 2>&1
rem Sysprep can exit 0 and still fail; the tag and the image state are the proof.
if not exist W:\Windows\System32\Sysprep\Sysprep_succeeded.tag (echo PVS-NO-SYSPREP-TAG > COM1 & goto :fail)
rem ImageState read by cmd itself: this WinPE has no findstr.exe.
set IMGSTATE=
for /f "usebackq tokens=1,* delims==" %%a in ("W:\Windows\Setup\State\State.ini") do if /i "%%a"=="ImageState" set IMGSTATE=%%b
if /i not "%IMGSTATE%"=="IMAGE_STATE_GENERALIZE_RESEAL_TO_OOBE" (echo PVS-NOT-GENERALIZED %IMGSTATE% > COM1 & goto :fail)
echo PVS-GENERALIZED > COM1
call :dism /Image:W:\ /Set-UserLocale:{locale} /Set-SysLocale:{locale} /Set-InputLocale:{input} || goto :fail
echo PVS-LOCALE {locale} {input} > COM1
call :dism /Image:W:\ /Set-TimeZone:"{tz}" || goto :fail
echo PVS-TIMEZONE {tz} > COM1
reg load HKLM\KSYS W:\Windows\System32\config\SYSTEM > COM1 2>&1 || goto :fail
reg load HKLM\KSOFT W:\Windows\System32\config\SOFTWARE > COM1 2>&1 || goto :fail
{policies}rem The answer file: whatever audit mode left cached goes, the pointer Setup searches
rem first goes, and the gold's own file takes Panther's place.
reg delete "HKLM\KSYS\Setup" /v UnattendFile /f >nul 2>&1
reg unload HKLM\KSOFT > COM1 2>&1
reg unload HKLM\KSYS > COM1 2>&1
if exist W:\Windows\Panther\Unattend rmdir /s /q W:\Windows\Panther\Unattend
if exist W:\Windows\System32\Sysprep\unattend.xml del /f /q W:\Windows\System32\Sysprep\unattend.xml
copy /y %SEED%\pvs\gold.xml W:\Windows\Panther\unattend.xml > COM1 2>&1 || goto :fail
if not exist W:\Windows\PVS\firstboot.cmd (echo PVS-NO-FIRSTBOOT > COM1 & goto :fail)
echo PVS-ANSWERFILE > COM1
{key}
echo PVS-PASS2-OK > COM1
goto :eof
:fail
type W:\Windows\System32\Sysprep\Panther\setuperr.log > COM1 2>&1
echo PVS-PASS2-FAILED > COM1
goto :eof
:dism
rem Back-to-back DISM sessions can collide on the image's still-mapped hives (exit 87,
rem nothing applied) - two retries, ten seconds apart.
for /l %%i in (1,1,3) do (
    dism /English %* > COM1 2>&1 && exit /b 0
    ping -n 11 127.0.0.1 >nul
)
exit /b 1
"#
    ))
}

// ---- bake ----

pub struct WinBake<'a> {
    pub pve: &'a Pve,
    pub db: &'a SqlitePool,
    pub log: &'a JobLog,
    pub work: &'a std::path::Path,
}

/// One boot of the bake VM, followed on its serial console until it powers itself off.
/// Returns every PVS- marker it wrote; DISM's own percentages move the bar.
async fn run_pass(
    pve: &Pve,
    log: &JobLog,
    pr: &mut Progress,
    node: &str,
    vmid: u32,
    label: &str,
    timeout_min: u64,
) -> Result<Vec<String>> {
    pve.vm_action(node, vmid, "start").await?;
    // The console is there once the VM runs; a few tries while QEMU sets it up.
    let mut lines = None;
    for _ in 0..10 {
        match serial::open(pve, node, vmid).await {
            Ok(l) => {
                lines = Some(l);
                break;
            }
            Err(_) => tokio::time::sleep(Duration::from_secs(1)).await,
        }
    }
    let mut lines = lines.ok_or_else(|| anyhow::anyhow!("could not open the serial console of VM {vmid}"))?;
    let started = Instant::now();
    let mut markers = Vec::new();
    let mut last_pct = -1.0;
    loop {
        if started.elapsed() > Duration::from_secs(timeout_min * 60) {
            let _ = pve.vm_action(node, vmid, "stop").await;
            bail!("{label} did not finish within {timeout_min} minutes (markers so far: {})", markers.join(" "));
        }
        match tokio::time::timeout(Duration::from_secs(5), lines.recv()).await {
            Ok(Some(line)) => {
                // DISM paints its bar with carriage returns: "[====   45.0%   ]".
                for part in line.split('\r').map(str::trim).filter(|p| !p.is_empty()) {
                    if let Some(pct) = part
                        .strip_prefix('[')
                        .and_then(|r| r.split('%').next())
                        .and_then(|r| r.rsplit(|c: char| c == ' ' || c == '=').next())
                        .and_then(|n| n.parse::<f64>().ok())
                    {
                        if (pct - last_pct).abs() >= 1.0 {
                            last_pct = pct;
                            pr.within(pct / 100.0, format!("{label}: DISM {pct:.0}%"));
                        }
                        continue;
                    }
                    if part.starts_with("PVS-") {
                        log.line(part).await;
                        markers.push(part.to_owned());
                    } else {
                        log.debug(format!("| {part}")).await;
                    }
                }
            }
            Ok(None) | Err(_) => {
                // The console closes when the VM stops; a quiet console is checked too.
                if pve.vm_status(node, vmid).await?.status == "stopped" {
                    return Ok(markers);
                }
                let st: serde_json::Value = pve.get(&format!("/nodes/{}/qemu/{vmid}/status/current", enc(node))).await?;
                if st["qmpstatus"].as_str() == Some("internal-error") {
                    let _ = pve.vm_action(node, vmid, "stop").await;
                    bail!("KVM stopped the bake VM with an internal error during {label}");
                }
                if lines.is_closed() {
                    match serial::open(pve, node, vmid).await {
                        Ok(l) => lines = l,
                        Err(_) => tokio::time::sleep(Duration::from_secs(2)).await,
                    }
                }
            }
        }
    }
}

/// Sets the boot order on its own and reads it back. Changed together with a drive, PVE
/// rebuilds the order from the drives instead ("order=scsi0;sata3") - and a generalized
/// disk that boots when WinPE should is a spent sysprep: specialize and OOBE run, and
/// the bake is lost.
async fn set_boot(pve: &Pve, node: &str, vmid: u32, order: &str) -> Result<()> {
    pve.vm_set(node, vmid, form![("boot", format!("order={order}"))]).await?;
    let cfg = pve.vm_config(node, vmid).await?;
    let got = cfg.get("boot").and_then(|v| v.as_str()).unwrap_or_default().to_owned();
    if got != format!("order={order}") {
        bail!("VM {vmid} should boot from {order} only, but its boot order is '{got}'");
    }
    Ok(())
}

pub async fn bake(
    b: WinBake<'_>,
    gold_id: &str,
    p: &Placement,
    img: &WimImage,
    opt: &WinBakeOptions,
    winpe_volid: &str,
    virtio_volid: &str,
    virtio_release: &str,
) -> Result<()> {
    let (pve, log) = (b.pve, b.log);
    let node = p.node.as_str();
    let id = image_id(img);
    let display = img.name.clone();
    let client = img.installation_type == "Client";
    let mut pr = Progress::new(log, format!("Baking {display}"));
    pr.stage(0.0, 3.0, "creating the bake VM");
    let mut made: Option<u32> = None;
    let mut seeds: Vec<String> = Vec::new();

    let result: Result<(u32, String)> = async {
        // ---- seeds: one per WinPE pass ----
        let stamp = Utc::now().format("%Y%m%d-%H%M").to_string();
        let seed_for = |n: u8| format!("pvs-seed-bake-{id}-{stamp}-pass{n}");
        let (s1, s2) = (seed_for(1), seed_for(2));
        let pass1 = SeedIso::build(
            b.work,
            &s1,
            "PVSSEED",
            &[
                ("pvs/pe.cmd", &pe1_cmd(img)),
                ("pvs/audit.xml", &audit_unattend()),
                ("pvs/audit.cmd", &audit_cmd()),
                ("pvs/firstboot.cmd", &firstboot_cmd()),
            ],
        )
        .await?;
        let up = pve.upload(node, &p.iso_storage, "iso", &pass1.iso, &format!("{s1}.iso")).await;
        pass1.remove().await;
        let seed1 = up?;
        seeds.push(seed1.clone());
        let pass2 = SeedIso::build(
            b.work,
            &s2,
            "PVSSEED",
            &[("pvs/pe.cmd", &pe2_cmd(img, &opt.region, &opt.features)), ("pvs/gold.xml", &gold_unattend())],
        )
        .await?;
        let up = pve.upload(node, &p.iso_storage, "iso", &pass2.iso, &format!("{s2}.iso")).await;
        pass2.remove().await;
        let seed2 = up?;
        seeds.push(seed2.clone());
        log.ok(format!("Seeds uploaded: {seed1}, {seed2}")).await;

        // ---- the bake VM ----
        pve.ensure_pool(GOLD_POOL, "PVE VM Studio: golds (templates) and the bakes that make them").await?;
        let guard = pve.vmid_guard().await;
        let vmid = pve.free_vmid_in(GOLD_IDS).await?;
        let name = format!("bake-{id}-{stamp}");
        // Link down: NetKVM binds in audit mode, but nothing updates between boot and sysprep.
        let mut net0 = format!("virtio,bridge={},link_down=1", p.bridge);
        if let Some(v) = p.vlan {
            net0 += &format!(",tag={v}");
        }
        let ostype = if server_year(&img.build).is_some_and(|y| y < 2022) && is_server(img) { "win10" } else { "win11" };
        log.run(format!("Creating bake VM {vmid} ({name}): {display}, index {} of {}", img.index, opt.iso)).await;
        let mut create = form![
            ("vmid", vmid),
            ("name", &name),
            ("pool", GOLD_POOL),
            ("ostype", ostype),
            ("machine", "q35"),
            ("bios", "ovmf"),
            ("cpu", &p.cpu_windows),
            ("cores", p.cores.max(2)),
            ("memory", p.memory_mb.max(4096)),
            ("balloon", 0),
            ("efidisk0", format!("{}:1,efitype=4m,pre-enrolled-keys=1", p.disk_storage)),
            ("scsihw", "virtio-scsi-single"),
            ("scsi0", format!("{}:64,discard=on,iothread=1,ssd=1", p.disk_storage)),
            ("sata0", format!("{winpe_volid},media=cdrom")),
            ("sata1", format!("{},media=cdrom", opt.iso)),
            ("sata2", format!("{virtio_volid},media=cdrom")),
            ("sata3", format!("{seed1},media=cdrom")),
            ("serial0", "socket"),
            ("net0", net0),
            ("agent", "enabled=1"),
            // Windows expects a local-time RTC.
            ("localtime", 1),
            ("boot", "order=sata0"),
            ("tags", "pvs;pvs-bake"),
            ("description", format!("PVE VM Studio: baking {display} - removed or made a template when done.")),
        ];
        if client {
            create.push(("tpmstate0".into(), format!("{}:1,version=v2.0", p.disk_storage)));
        }
        let created = pve.run_task(&format!("/nodes/{}/qemu", enc(node)), create, |_| {}).await;
        drop(guard);
        if pve.vm_status(node, vmid).await.is_ok() {
            made = Some(vmid);
        }
        created.context("creating the bake VM")?;
        sqlx::query("UPDATE golds SET vmid = ? WHERE id = ?").bind(vmid).bind(gold_id).execute(b.db).await?;
        pr.within(1.0, "created");

        // ---- WinPE pass 1: apply ----
        log.run("WinPE pass 1: partition, apply, drivers, boot files").await;
        pr.stage(3.0, 40.0, "WinPE pass 1");
        let m = run_pass(pve, log, &mut pr, node, vmid, "pass 1", 40).await?;
        if !m.iter().any(|l| l == "PVS-PASS1-OK") {
            bail!("pass 1 failed: {}", m.last().cloned().unwrap_or_else(|| "no markers on the serial console".into()));
        }

        // ---- audit boot: drivers, agent, generalize ----
        log.run("Audit mode: virtio drivers, guest agent, sysprep /generalize").await;
        pr.stage(40.0, 70.0, "audit mode and sysprep");
        set_boot(pve, node, vmid, "scsi0").await?;
        let m = run_pass(pve, log, &mut pr, node, vmid, "audit", 60).await?;
        if !m.iter().any(|l| l == "PVS-SYSPREP-START") {
            bail!("audit mode did not reach sysprep: {}", m.last().cloned().unwrap_or_else(|| "no markers".into()));
        }

        // ---- WinPE pass 2: verify, customize, key ----
        log.run("WinPE pass 2: verify generalize, locale, time zone, policies, key").await;
        pr.stage(70.0, 95.0, "WinPE pass 2");
        pve.vm_set(node, vmid, form![("sata3", format!("{seed2},media=cdrom"))]).await?;
        set_boot(pve, node, vmid, "sata0").await?;
        let m = run_pass(pve, log, &mut pr, node, vmid, "pass 2", 30).await?;
        if !m.iter().any(|l| l == "PVS-PASS2-OK") {
            let why = m.iter().find(|l| l.starts_with("PVS-NO-SYSPREP-TAG") || l.starts_with("PVS-NOT-GENERALIZED") || l.ends_with("FAILED")).cloned();
            bail!("pass 2 failed: {}", why.or_else(|| m.last().cloned()).unwrap_or_else(|| "no markers on the serial console".into()));
        }

        // ---- make it a gold ----
        pr.stage(95.0, 100.0, "making it a template");
        pve.vm_set(
            node,
            vmid,
            form![("delete", "sata0,sata1,sata2,sata3"), ("net0", format!("virtio,bridge={}", p.bridge))],
        )
        .await?;
        set_boot(pve, node, vmid, "scsi0").await?;
        for v in seeds.drain(..) {
            pve.delete_volume(node, &v).await?;
        }
        let gold_name = format!("gold-{id}-{stamp}");
        let notes = format!(
            "## Gold: {display}\n\nBaked by PVE VM Studio on {}. Do not start this template - clone it.\n\n\
             | | |\n|---|---|\n| Image | `{id}` (index {} of `{}`) |\n| Build | {} |\n| Language | {} |\n| Region | {} / keyboard {} / {} |\n| virtio-win | {virtio_release} |\n| Policies | {} |\n| Key | {} |\n",
            Utc::now().format("%Y-%m-%d %H:%M UTC"),
            img.index,
            opt.iso,
            img.build,
            img.language,
            opt.region.locale,
            opt.region.keyboard,
            opt.region.timezone,
            if opt.features.is_empty() { "none".into() } else { opt.features.join(", ") },
            if gvlk(&img.edition_id, &img.build).is_some() { "KMS client (GVLK)" } else { "none" },
        );
        pve.vm_set(
            node,
            vmid,
            form![("name", &gold_name), ("tags", format!("pvs;pvs-gold;pvs-img-{id}")), ("description", notes)],
        )
        .await?;
        pve.run_task(&format!("/nodes/{}/qemu/{vmid}/template", enc(node)), vec![], |_| {}).await?;
        Ok((vmid, gold_name))
    }
    .await;

    match result {
        Ok((vmid, gold_name)) => {
            let manifest = json!({
                "osFamily": "windows",
                "image": id,
                "name": display,
                "imageName": img.name,
                "imageIndex": img.index,
                "editionId": img.edition_id,
                "installationType": img.installation_type,
                "build": img.build,
                "imageLanguage": img.language,
                "sourceIso": opt.iso,
                "locale": opt.region.locale,
                "keyboardLayout": opt.region.keyboard,
                "inputLocale": input_locale(if opt.region.keyboard.is_empty() { &opt.region.locale } else { &opt.region.keyboard }),
                "timeZone": opt.region.timezone,
                "localeMode": "offline",
                "policies": opt.features,
                "virtio": virtio_release,
                "key": gvlk(&img.edition_id, &img.build).map(|_| "gvlk"),
                "secureBoot": true,
                "vtpm": client,
                "createdUtc": Utc::now().to_rfc3339(),
            });
            sqlx::query("UPDATE golds SET status = 'ready', name = ?, image_id = ?, manifest = ? WHERE id = ?")
                .bind(&gold_name)
                .bind(&id)
                .bind(manifest.to_string())
                .bind(gold_id)
                .execute(b.db)
                .await?;
            log.ok(format!("Gold ready: {gold_name} (template {vmid})")).await;
            Ok(())
        }
        Err(e) => {
            for v in seeds {
                let _ = pve.delete_volume(node, &v).await;
            }
            if let Some(vmid) = made
                && pve.vm_destroy(node, vmid).await.is_ok()
            {
                log.line(format!("Removed bake VM {vmid}")).await;
            }
            let _ = sqlx::query("UPDATE golds SET status = 'failed' WHERE id = ?").bind(gold_id).execute(b.db).await;
            Err(e)
        }
    }
}


// ---- VMs ----

/// base64(UTF-16LE(password + element name)) - what Setup wants for PlainText=false.
pub fn setup_password(password: &str, element: &str) -> String {
    let units: Vec<u8> = format!("{password}{element}").encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
    base64::engine::general_purpose::STANDARD.encode(units)
}

#[derive(Debug, Clone)]
pub struct WinVmSeed {
    pub name: String,
    pub user: String,
    pub password: String,
    pub builtin_admin_only: bool,
    pub client: bool,
    pub mac: String,
    pub ip: String,
    pub prefix: u8,
    pub gateway: String,
    pub dns: Vec<String>,
    /// Extra adapters with a static address: (MAC, address, prefix) - no gateway, no DNS.
    pub extra: Vec<(String, String, u8)>,
    /// GuestProvision's manifest.json (Build-Vms' Set-OfflineGuestProvisionPayload).
    pub manifest: serde_json::Value,
    /// arc-deploy.json and domain-join.json - the secrets, as separate files the guest
    /// scripts delete once used.
    pub arc_secret: Option<serde_json::Value>,
    pub join_secret: Option<serde_json::Value>,
}

/// Whether the VM has anything for GuestProvision to do (Build-Vms' $needsGuest).
pub fn needs_guest(m: &serde_json::Value) -> bool {
    let non_empty = |k: &str| m[k].as_array().is_some_and(|a| !a.is_empty());
    non_empty("pendingWindowsFeatures")
        || non_empty("pendingRsatCapabilities")
        || non_empty("pendingCapabilities")
        || non_empty("dataDisks")
        || non_empty("networkAdapters")
        || !m["azureArc"].is_null()
        || !m["domainJoin"].is_null()
}

pub static GUEST_PROVISION_PS1: &str = include_str!("../guest-files/GuestProvision.ps1");
pub static DOMAIN_JOIN_PS1: &str = include_str!("../guest-files/DomainJoin.ps1");

/// The VM's oobeSystem answer file. International-Core repeats the gold's locale: the
/// region page has no hide flag and is only skipped when this answers it.
pub fn vm_unattend(s: &WinVmSeed, manifest: &serde_json::Value) -> String {
    let input = manifest["inputLocale"].as_str().unwrap_or("0409:00000409");
    let locale = manifest["locale"].as_str().unwrap_or("en-US");
    let tz = manifest["timeZone"].as_str().unwrap_or("UTC");
    let user = xml_escape(&s.user);
    let accounts = if s.builtin_admin_only || s.user.eq_ignore_ascii_case("administrator") {
        String::new()
    } else {
        format!(
            r#"
        <LocalAccounts>
          <LocalAccount wcm:action="add">
            <Password><Value>{}</Value><PlainText>false</PlainText></Password>
            <Description>Local administrator (PVE VM Studio)</Description>
            <DisplayName>{user}</DisplayName>
            <Group>Administrators</Group>
            <Name>{user}</Name>
          </LocalAccount>
        </LocalAccounts>"#,
            setup_password(&s.password, "Password")
        )
    };
    let client_oobe = if s.client {
        "\n        <HideOnlineAccountScreens>true</HideOnlineAccountScreens>\n        <HideLocalAccountScreen>true</HideLocalAccountScreen>\n        <HideOEMRegistrationScreen>true</HideOEMRegistrationScreen>"
    } else {
        ""
    };
    format!(
        r#"<?xml version="1.0" encoding="utf-8"?>
<unattend {NS}>
  <settings pass="oobeSystem">
    <component name="Microsoft-Windows-International-Core" {COMP}>
      <InputLocale>{input}</InputLocale>
      <SystemLocale>{locale}</SystemLocale>
      <UserLocale>{locale}</UserLocale>
    </component>
    <component name="Microsoft-Windows-Shell-Setup" {COMP}>
      <TimeZone>{tz}</TimeZone>
      <UserAccounts>
        <AdministratorPassword><Value>{admin}</Value><PlainText>false</PlainText></AdministratorPassword>{accounts}
      </UserAccounts>
      <OOBE>
        <HideEULAPage>true</HideEULAPage>
        <HideWirelessSetupInOOBE>true</HideWirelessSetupInOOBE>
        <ProtectYourPC>3</ProtectYourPC>{client_oobe}
        <VMModeOptimizations>
          <SkipAdministratorProfileRemoval>true</SkipAdministratorProfileRemoval>
          <SkipNotifyUILanguageChange>true</SkipNotifyUILanguageChange>
        </VMModeOptimizations>
      </OOBE>
    </component>
  </settings>
</unattend>
"#,
        admin = setup_password(&s.password, "AdministratorPassword"),
    )
}

pub fn vm_cmd(s: &WinVmSeed) -> String {
    crlf(&format!("set PVS_NAME={}\n", s.name.to_uppercase()))
}

/// Runs as SYSTEM once OOBE is done: the static address (matched by MAC), then the marker.
pub fn setupcomplete_cmd(s: &WinVmSeed) -> String {
    let mut ip = String::new();
    if !s.ip.is_empty() {
        let mac = s.mac.replace(':', "-").to_uppercase();
        let gw = if s.gateway.is_empty() { String::new() } else { format!(" -DefaultGateway {}", s.gateway) };
        let dns = if s.dns.is_empty() {
            String::new()
        } else {
            format!("; Set-DnsClientServerAddress -InterfaceIndex $a.ifIndex -ServerAddresses {}", s.dns.join(","))
        };
        ip = format!(
            "powershell -NoProfile -ExecutionPolicy Bypass -Command \"$a = Get-NetAdapter | Where-Object MacAddress -eq '{mac}'; Set-NetIPInterface -InterfaceIndex $a.ifIndex -Dhcp Disabled; New-NetIPAddress -InterfaceIndex $a.ifIndex -IPAddress {} -PrefixLength {}{gw}{dns}\" >> C:\\Windows\\Temp\\pvs-firstboot.log 2>&1\n",
            s.ip, s.prefix
        );
    }
    for (mac, addr, prefix) in &s.extra {
        let mac = mac.replace(':', "-").to_uppercase();
        ip += &format!(
            "powershell -NoProfile -ExecutionPolicy Bypass -Command \"$a = Get-NetAdapter | Where-Object MacAddress -eq '{mac}'; Set-NetIPInterface -InterfaceIndex $a.ifIndex -Dhcp Disabled; New-NetIPAddress -InterfaceIndex $a.ifIndex -IPAddress {addr} -PrefixLength {prefix}\" >> C:\\Windows\\Temp\\pvs-firstboot.log 2>&1\n"
        );
    }
    // GuestProvision after the address (Arc and the join need the network), before the
    // marker - the studio waits for the marker, then reads GuestProvision's state.json.
    let guest = if needs_guest(&s.manifest) {
        "powershell.exe -NoProfile -ExecutionPolicy Bypass -File \"%~dp0GuestProvision\\GuestProvision.ps1\" >nul 2>&1\n"
    } else {
        ""
    };
    // [diff] Hyper-V had no CD here - New-Vhdx and Build-Vms wrote everything into the VHDX.
    // The seed CD takes the first free letter, D: mostly, which the design's data disks
    // want: every CD moves to the end of the alphabet before GuestProvision formats them.
    let cds = "powershell -NoProfile -ExecutionPolicy Bypass -Command \"$used = @(Get-Volume | ForEach-Object DriveLetter); $free = @([char[]]'ZYXWVUTSRQP' | Where-Object { $used -notcontains $_ }); $i = 0; Get-CimInstance Win32_Volume -Filter 'DriveType=5' | Where-Object { $_.DriveLetter } | ForEach-Object { Set-CimInstance -InputObject $_ -Property @{ DriveLetter = ('{0}:' -f $free[$i]) }; $i++ }\" >> C:\\Windows\\Temp\\pvs-firstboot.log 2>&1\n";
    crlf(&format!(
        "@echo off\n{ip}{cds}{guest}if not exist C:\\ProgramData\\PVS mkdir C:\\ProgramData\\PVS\necho done> C:\\ProgramData\\PVS\\provisioned.txt\n"
    ))
}

/// Waits until SetupComplete.cmd left its marker. The bar moves with the milestones of the
/// first boot: the agent answering, firstboot.cmd having run, the marker.
pub async fn follow_first_boot(pve: &Pve, log: &JobLog, pr: &mut Progress, node: &str, vmid: u32) -> Result<()> {
    let started = Instant::now();
    let mut agent = false;
    let mut first = false;
    loop {
        // Roles and features install in this boot (GuestProvision), which can take a while.
        if started.elapsed() > Duration::from_secs(60 * 60) {
            bail!("the VM did not finish its first boot within 60 minutes - its CD (with the passwords) is still attached");
        }
        if pve.vm_status(node, vmid).await?.status != "running" {
            bail!("the VM stopped during its first boot");
        }
        if !agent && pve.agent_ping(node, vmid).await {
            agent = true;
            log.ok("Guest agent answers").await;
        }
        if agent && !first
            && let Some((t, _)) = pve.agent_read(node, vmid, r"C:\Windows\Temp\pvs-firstboot.log", 0).await
            && t.contains("PVS-FIRSTBOOT-OK")
        {
            first = true;
            log.ok("Specialize: named, answer file handed over").await;
        }
        if agent && pve.agent_read(node, vmid, r"C:\ProgramData\PVS\provisioned.txt", 0).await.is_some() {
            return Ok(());
        }
        let f = if first { 0.6 } else if agent { 0.3 } else { 0.0 };
        pr.within(f, if first { "OOBE" } else if agent { "specialize" } else { "booting" });
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

/// A Windows computer name: 15 characters.
pub fn check_name(name: &str) -> Result<()> {
    if name.len() > 15 {
        bail!("a Windows computer name has at most 15 characters ('{name}' has {})", name.len());
    }
    if name.chars().all(|c| c.is_ascii_digit()) {
        bail!("a Windows computer name cannot be only digits");
    }
    Ok(())
}
