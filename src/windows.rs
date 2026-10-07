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
//! (Setup never searches a CD for one after generalize).
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
    golds::{self, GOLD_IDS, GOLD_POOL},
    jobs::JobLog,
    progress::Progress,
    pve::{enc, Pve},
    seed::{self, SeedDisk},
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
        ("ProfessionalWorkstationN", None) => "9FNHH-K3HBT-3W4TD-6383H-6XYWF",
        ("ProfessionalEducation", None) => "6TP4R-GNPTD-KYYHQ-7B7DP-J447Y",
        ("ProfessionalEducationN", None) => "YVWGF-BXNMC-HTQYQ-CPQ99-66QFC",
        // Multi-session: DISM names it ServerRdsh or EnterpriseMultiSession.
        ("ServerRdsh" | "EnterpriseMultiSession", None) => "CPWHC-NT2C7-VYW78-DHDB2-PG3GK",
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
        client_id(&img.edition_id)
    }
}

/// A Windows 11 edition's image id: w11-pro, w11-enterprise-n, w11-pro-workstation.
fn client_id(edition_id: &str) -> String {
    let ed = match edition_id {
        "Professional" => "pro",
        "ProfessionalN" => "pro-n",
        "Enterprise" => "enterprise",
        "EnterpriseN" => "enterprise-n",
        "ServerRdsh" | "EnterpriseMultiSession" => "enterprise-ms",
        "Education" => "education",
        "EducationN" => "education-n",
        "ProfessionalWorkstation" => "pro-workstation",
        "ProfessionalWorkstationN" => "pro-workstation-n",
        "ProfessionalEducation" => "pro-education",
        "ProfessionalEducationN" => "pro-education-n",
        other => return format!("w11-{}", other.to_lowercase()),
    };
    format!("w11-{ed}")
}

/// The virtual editions a gold can be changed to after generalize (New-Vhdx's
/// $script:VirtualEditionCatalog). `key` is what a bake request carries, `manifest` what
/// the sidecar records. DISM names every one of these SKUs differently depending on where
/// you read it, so the bake matches the family and hands /Set-Edition the exact string
/// DISM printed.
pub struct VirtualEdition {
    pub key: &'static str,
    pub display: &'static str,
    pub manifest: &'static str,
    /// Which index to pick - New-Vhdx's SourceHint, said when a bake stops early.
    pub hint: &'static str,
    /// For the editions made from Pro: the EditionID of the index it is made from, and the
    /// target DISM lists for it, word for word ("" for the two older entries, matched by
    /// family below).
    pub from: &'static str,
    pub target: &'static str,
}

const PRO_HINT: &str = "Use a Windows 11 Pro index: the edition packs are staged on the base edition, and an image already changed to a higher edition has none left to offer.";
const PRO_N_HINT: &str = "Use a Windows 11 Pro N index: the N editions are made from Pro N.";

pub static VIRTUAL_EDITIONS: &[VirtualEdition] = &[
    VirtualEdition {
        key: "MultiSession",
        display: "Windows 11 Enterprise multi-session",
        manifest: "EnterpriseMultiSession",
        hint: PRO_HINT,
        from: "",
        target: "",
    },
    VirtualEdition {
        key: "AzureEdition",
        display: "Windows Server 2025 Datacenter: Azure Edition",
        manifest: "DatacenterAzureEdition",
        hint: "Use a Windows Server 2025 Datacenter index: only Server 2025 media lists the Azure Edition target, and Standard Core does not list it directly.",
        from: "",
        target: "",
    },
    // What Microsoft's media builder makes from Pro - UUP media carries only Home and Pro.
    VirtualEdition { key: "Enterprise", display: "Windows 11 Enterprise", manifest: "Enterprise", hint: PRO_HINT, from: "Professional", target: "Enterprise" },
    VirtualEdition { key: "Education", display: "Windows 11 Education", manifest: "Education", hint: PRO_HINT, from: "Professional", target: "Education" },
    VirtualEdition { key: "ProWorkstation", display: "Windows 11 Pro for Workstations", manifest: "ProfessionalWorkstation", hint: PRO_HINT, from: "Professional", target: "ProfessionalWorkstation" },
    VirtualEdition { key: "ProEducation", display: "Windows 11 Pro Education", manifest: "ProfessionalEducation", hint: PRO_HINT, from: "Professional", target: "ProfessionalEducation" },
    VirtualEdition { key: "EnterpriseN", display: "Windows 11 Enterprise N", manifest: "EnterpriseN", hint: PRO_N_HINT, from: "ProfessionalN", target: "EnterpriseN" },
    VirtualEdition { key: "EducationN", display: "Windows 11 Education N", manifest: "EducationN", hint: PRO_N_HINT, from: "ProfessionalN", target: "EducationN" },
    VirtualEdition { key: "ProWorkstationN", display: "Windows 11 Pro N for Workstations", manifest: "ProfessionalWorkstationN", hint: PRO_N_HINT, from: "ProfessionalN", target: "ProfessionalWorkstationN" },
    VirtualEdition { key: "ProEducationN", display: "Windows 11 Pro Education N", manifest: "ProfessionalEducationN", hint: PRO_N_HINT, from: "ProfessionalN", target: "ProfessionalEducationN" },
];

pub fn virtual_edition(key: &str) -> Option<&'static VirtualEdition> {
    VIRTUAL_EDITIONS.iter().find(|v| v.key == key)
}

/// Whether the studio offers this virtual edition for an index - the source New-Vhdx's
/// hints name. DISM has the last word in pass 1 (/Get-TargetEditions).
pub fn virtual_edition_fits(key: &str, img: &WimImage) -> bool {
    match key {
        "MultiSession" => img.edition_id == "Professional",
        "AzureEdition" => server_year(&img.build) == Some(2025) && img.edition_id == "ServerDatacenter",
        k => virtual_edition(k).is_some_and(|v| !v.from.is_empty() && v.from == img.edition_id),
    }
}

/// Whether the media already carries a virtual edition's target as a real image (an ISO
/// with an Enterprise index needs no "Enterprise from Pro").
pub fn virtual_on_media(key: &str, images: &[WimImage]) -> bool {
    images.iter().any(|i| match key {
        "MultiSession" => i.edition_id == "ServerRdsh" || i.edition_id == "EnterpriseMultiSession",
        "AzureEdition" => i.edition_id.starts_with("ServerTurbine") || i.edition_id.starts_with("ServerAzure"),
        k => virtual_edition(k).is_some_and(|v| !v.manifest.is_empty() && i.edition_id == v.manifest),
    })
}

/// The target DISM listed that belongs to the wanted family (New-Vhdx's TargetPattern):
/// multi-session is ServerRdsh or EnterpriseMultiSession; Azure Edition is ServerTurbine*
/// or ServerAzure* - the whole token, since Core is ServerTurbineCor and stopping at
/// ServerTurbine would hand /Set-Edition a Desktop SKU for a Core image.
pub fn virtual_target(key: &str, targets: &[String]) -> Option<String> {
    targets
        .iter()
        .find(|t| match key {
            "MultiSession" => t.contains("ServerRdsh") || t.contains("EnterpriseMultiSession"),
            "AzureEdition" => t.starts_with("ServerTurbine") || t.starts_with("ServerAzure"),
            k => virtual_edition(k).is_some_and(|v| !v.target.is_empty() && t.as_str() == v.target),
        })
        .cloned()
}

/// The image id of what a gold IS when a VM boots it (New-Vhdx's Get-GoldImageId): a Pro
/// index that leaves as multi-session is w11-enterprise-ms, a Datacenter index that leaves
/// as Azure Edition is ws2025-datacenter-az-<core|desktop> - /Set-Edition changes the SKU,
/// not the installation type. The sidecar keeps the source index honest.
pub fn gold_image_id(img: &WimImage, upgrade: &str) -> String {
    let id = image_id(img);
    match upgrade {
        "MultiSession" => "w11-enterprise-ms".into(),
        "AzureEdition" => {
            let kind = if img.installation_type == "Server Core" { "core" } else { "desktop" };
            format!("ws{}-datacenter-az-{kind}", server_year(&img.build).unwrap_or(2025))
        }
        k => match virtual_edition(k) {
            Some(v) if !v.target.is_empty() => client_id(v.manifest),
            _ => id,
        },
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
    /// WIN_FEATURES ids.
    #[serde(default)]
    pub features: Vec<String>,
    /// 0: from before device encryption and the power plan were toggles - a client gold had
    /// both, always. 1: `features` says it all.
    #[serde(default)]
    pub policies: u32,
    /// "" for the edition on the ISO, else a VIRTUAL_EDITIONS key.
    #[serde(default)]
    pub edition_upgrade: String,
    /// The system disk in GiB (New-Vhdx's -VhdSizeGB); None = 64. Thin or thick is the
    /// storage's own property on PVE (LVM-thin and ZFS are thin, LVM thick), not the disk's.
    #[serde(default)]
    pub disk_gb: Option<u32>,
    /// This bake's disk storage (thin or thick by the storage); None = the bake settings'.
    #[serde(default)]
    pub disk_storage: Option<String>,
    /// Keep current: baked again from every newer Patch Tuesday build of its ISO's product
    /// (autoupdate.rs). A gold the auto-update bakes inherits it.
    #[serde(default)]
    pub keep_current: bool,
}

impl WinBakeOptions {
    /// Options of a gold baked before the client policies were toggles keep what it had.
    pub fn upgrade(&mut self) {
        if self.policies == 0 {
            for f in ["noencrypt", "power"] {
                if !self.features.iter().any(|x| x == f) {
                    self.features.push(f.to_owned());
                }
            }
            self.policies = 1;
        }
    }

    pub fn disk_gb(&self) -> u32 {
        self.disk_gb.unwrap_or(64).clamp(32, 2048)
    }
}

/// One of New-Vhdx's offline policies (doc §4): its id, the toggle's label, where it applies
/// ("" every image, "client", "server", "desktop" = every image but Server Core) and the tip.
pub struct WinFeature {
    pub id: &'static str,
    pub label: &'static str,
    pub scope: &'static str,
    pub tip: &'static str,
}

/// New-Vhdx's -EnableRdp ... -SetVmPowerPlan, same defaults in the form.
pub static WIN_FEATURES: &[WinFeature] = &[
    WinFeature { id: "rdp", label: "Remote Desktop", scope: "",
        tip: "Remote Desktop on, with Network Level Authentication, and the firewall open for it on TCP and UDP 3389." },
    WinFeature { id: "ping", label: "Answer ping", scope: "",
        tip: "Inbound ICMPv4 and ICMPv6 echo requests allowed in the firewall." },
    WinFeature { id: "svrmgr", label: "No Server Manager at logon", scope: "server",
        tip: "Machine policy DoNotOpenAtLogon: Server Manager no longer opens by itself when an administrator signs in." },
    WinFeature { id: "preferipv4", label: "Prefer IPv4", scope: "",
        tip: "DisabledComponents 0x20 (Tcpip6 parameters): Windows prefers IPv4 over IPv6 - ::ffff:0:0/96 ranks above ::/0 in its prefix policies - and IPv6 stays on. Microsoft's recommendation instead of turning IPv6 off. Check on a VM with: netsh interface ipv6 show prefixpolicies." },
    WinFeature { id: "signinkeyboard", label: "Sign-in keyboard (STIG)", scope: "",
        tip: "BlockUserInputMethodsForSignIn (STIG WN12-CC-000048): the sign-in screen keeps the baked keyboard - per-user input methods do not appear there." },
    WinFeature { id: "edge", label: "Edge baseline", scope: "desktop",
        tip: "Microsoft Edge machine policy: Google as the default and only search engine, no first-run experience, no mini menu, a cleared new tab page, required diagnostic data only. A domain GPO overrides it later." },
    WinFeature { id: "noencrypt", label: "No auto device encryption", scope: "client",
        tip: "PreventDeviceEncryption: Windows does not turn BitLocker on by itself after OOBE - a VM with Secure Boot and a vTPM qualifies for it. BitLocker is meant to be armed by policy after deployment." },
    WinFeature { id: "power", label: "VM power plan", scope: "client",
        tip: "High performance, display off and sleep set to never, hibernation off - as machine policy, so a domain GPO overrides it later." },
    WinFeature { id: "welcome", label: "No welcome experience", scope: "client",
        tip: "Policy DisableWindowsSpotlightWindowsWelcomeExperience: no Getting Started / Welcome screen at logon." },
    WinFeature { id: "firstlogon", label: "No first sign-in animation", scope: "client",
        tip: "EnableFirstLogonAnimation 0: the first logon lands straight on the desktop, without \"Hi\" and \"We're getting things ready\"." },
];

/// A reg.exe /d value, quoted for a cmd.exe line: inner quotes as \" for reg.exe, and every
/// cmd metacharacter that the \" pairs leave outside cmd's own quoting escaped with ^.
fn cmd_reg_data(v: &str) -> String {
    let mut out = String::from("\"");
    let mut quoted = true;
    for c in v.chars() {
        match c {
            '"' => {
                out.push_str("\\\"");
                quoted = !quoted;
            }
            '%' => out.push_str("%%"),
            '&' | '|' | '<' | '>' | '^' if !quoted => {
                out.push('^');
                out.push(c);
            }
            _ => out.push(c),
        }
    }
    out.push('"');
    out
}

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
rem The disk to clean is the virtio-scsi one ("Type : SAS" in DiskPart) - never the seed,
rem a SATA disk that may well be disk 0.
set OSDISK=
for /l %%n in (0,1,7) do (
  (echo select disk %%n& echo detail disk) > X:\dd.txt
  diskpart /s X:\dd.txt > X:\dd%%n.txt 2>&1
  for /f "usebackq tokens=1,2 delims=: " %%a in ("X:\dd%%n.txt") do if /i "%%a"=="Type" if /i "%%b"=="SAS" if not defined OSDISK set OSDISK=%%n
)
if not defined OSDISK (echo PVS-NO-OS-DISK > COM1 & goto :fail)
echo PVS-OS-DISK %OSDISK% > COM1
rem A disk that arrives with a driver loaded at runtime (vioscsi, above) falls under
rem WinPE's SAN policy: offline and read-only - "clean" works, then everything after it
rem is "The media is write protected".
(
echo select disk %OSDISK%
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
rem What this image can become - each target as a marker, so the studio can stop a
rem virtual-edition bake here instead of after twenty minutes of audit mode.
dism /English /Image:W:\ /Get-TargetEditions > X:\targets.txt 2>&1
type X:\targets.txt > COM1
for /f "usebackq tokens=1,2,3 delims=: " %%a in ("X:\targets.txt") do if /i "%%a %%b"=="Target Edition" echo PVS-TARGET %%c > COM1
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
fn pass2_policies(features: &[String], client: bool, core: bool) -> String {
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
    // Prefer IPv4 over IPv6 (Microsoft: "Configure IPv6 in Windows", DisabledComponents
    // bit 0x20) - the prefix policy table, not IPv6 itself. Read at boot, so the first boot
    // of every VM already has it.
    if has("preferipv4") {
        p += "reg add \"HKLM\\KSYS\\ControlSet001\\Services\\Tcpip6\\Parameters\" /v DisabledComponents /t REG_DWORD /d 32 /f > COM1 2>&1\necho PVS-POLICY preferipv4 > COM1\n";
    }
    // New-Vhdx's Set-OfflineEdgePolicy. Server Core has no Edge to manage.
    if has("edge") && !core {
        let search = "https://www.google.com/search?q={searchTerms}";
        let suggest = "https://www.google.com/complete/search?output=chrome&q={searchTerms}";
        let engines = format!(r#"[{{"suggest_url": "{suggest}", "image_search_url": "", "name": "Google", "keyword": "google", "is_default": true, "search_url": "{search}"}}]"#);
        for (name, value, kind) in [
            ("ManagedSearchEngines", engines.as_str(), "REG_SZ"),
            ("DefaultSearchProviderEnabled", "1", "REG_DWORD"),
            ("DefaultSearchProviderName", "Google", "REG_SZ"),
            ("DefaultSearchProviderSearchURL", search, "REG_SZ"),
            ("DefaultSearchProviderSuggestURL", suggest, "REG_SZ"),
            ("QuickSearchShowMiniMenu", "0", "REG_DWORD"),
            ("HideFirstRunExperience", "1", "REG_DWORD"),
            ("NewTabPageSearchBox", "redirect", "REG_SZ"),
            ("NewTabPageContentEnabled", "0", "REG_DWORD"),
            ("NewTabPageAllowedBackgroundTypes", "3", "REG_DWORD"),
            ("NewTabPageHideDefaultTopSites", "1", "REG_DWORD"),
            ("DiagnosticData", "1", "REG_DWORD"),
        ] {
            p += &format!("reg add \"HKLM\\KSOFT\\Policies\\Microsoft\\Edge\" /v {name} /t {kind} /d {} /f > COM1 2>&1\n", cmd_reg_data(value));
        }
        p += "echo PVS-POLICY edge > COM1\n";
    }
    if client {
        // 24H2 auto-encrypts with Secure Boot + TPM, and swtpm + OVMF qualifies.
        if has("noencrypt") {
            p += "reg add \"HKLM\\KSYS\\ControlSet001\\Control\\BitLocker\" /v PreventDeviceEncryption /t REG_DWORD /d 1 /f > COM1 2>&1\necho PVS-POLICY no-device-encryption > COM1\n";
        }
        // High performance through policy - writing the scheme tree itself is denied. Display
        // off and sleep never (0), AC and DC: a VM has no battery, Windows keeps the column.
        if has("power") {
            let pol = r"HKLM\KSOFT\Policies\Microsoft\Power\PowerSettings";
            p += &format!("reg add \"{pol}\" /v ActivePowerScheme /t REG_SZ /d 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c /f > COM1 2>&1\n");
            for guid in ["3c0bc021-c8a8-4e07-a973-6b14cbcb2b7e", "29f6c1db-86da-48c5-9fdb-f2b67b1f44da"] {
                for v in ["ACSettingIndex", "DCSettingIndex"] {
                    p += &format!("reg add \"{pol}\\{guid}\" /v {v} /t REG_DWORD /d 0 /f > COM1 2>&1\n");
                }
            }
            p += r#"reg add "HKLM\KSYS\ControlSet001\Control\Power" /v HibernateEnabled /t REG_DWORD /d 0 /f > COM1 2>&1
reg add "HKLM\KSYS\ControlSet001\Control\Power" /v HibernateEnabledDefault /t REG_DWORD /d 0 /f > COM1 2>&1
echo PVS-POLICY power > COM1
"#;
        }
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
pub fn pe2_cmd(img: &WimImage, region: &WinRegion, features: &[String], edition_target: Option<&str>) -> String {
    let client = img.installation_type == "Client";
    let locale = &region.locale;
    let input = input_locale(if region.keyboard.is_empty() { locale } else { &region.keyboard });
    let tz = &region.timezone;
    let policies = pass2_policies(features, client, img.installation_type == "Server Core");
    // New-Vhdx's Convert-ToVirtualEdition: after generalize, before the customization - a
    // base edition generalizes cleanly and takes the change afterwards; the staged work
    // completes in specialize on the VM's first boot. Read back with /Get-CurrentEdition,
    // never the EditionID string: a gold named for an edition it does not carry fails here.
    let edition = match edition_target {
        Some(t) => format!(
            "call :dism /Image:W:\\ /Set-Edition:{t} || goto :fail\n\
             dism /English /Image:W:\\ /Get-CurrentEdition > X:\\current.txt 2>&1\n\
             type X:\\current.txt > COM1\n\
             set CUREDITION=\n\
             for /f \"usebackq tokens=1,2,3 delims=: \" %%a in (\"X:\\current.txt\") do if /i \"%%a %%b\"==\"Current Edition\" set CUREDITION=%%c\n\
             if /i not \"%CUREDITION%\"==\"{t}\" (echo PVS-EDITION-NOT-CHANGED %CUREDITION% > COM1 & goto :fail)\n\
             echo PVS-EDITION {t} > COM1\n"
        ),
        None => String::new(),
    };
    let key = match gvlk(edition_target.unwrap_or(&img.edition_id), &img.build) {
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
rem Windows on partition 3 of whichever disk carries it - the seed is a disk of its own now
rem and may enumerate first.
for /l %%n in (0,1,7) do (
  if not exist W:\Windows\System32\config\SYSTEM (
    (echo select disk %%n& echo select partition 3& echo assign letter=W noerr) > X:\find.txt
    diskpart /s X:\find.txt > COM1 2>&1
    if not exist W:\Windows\System32\config\SYSTEM (
      (echo select volume W& echo remove letter=W noerr) > X:\drop.txt
      diskpart /s X:\drop.txt > nul 2>&1
    )
  )
)
if not exist W:\Windows\System32\config\SYSTEM (echo PVS-NO-WINDOWS > COM1 & goto :fail)
echo PVS-PASS2-START > COM1
type W:\Windows\Setup\State\State.ini > COM1 2>&1
rem Sysprep can exit 0 and still fail; the tag and the image state are the proof.
if not exist W:\Windows\System32\Sysprep\Sysprep_succeeded.tag (echo PVS-NO-SYSPREP-TAG > COM1 & goto :fail)
rem ImageState read by cmd itself: this WinPE has no findstr.exe.
set IMGSTATE=
for /f "usebackq tokens=1,* delims==" %%a in ("W:\Windows\Setup\State\State.ini") do if /i "%%a"=="ImageState" set IMGSTATE=%%b
if /i not "%IMGSTATE%"=="IMAGE_STATE_GENERALIZE_RESEAL_TO_OOBE" (echo PVS-NOT-GENERALIZED %IMGSTATE% > COM1 & goto :fail)
echo PVS-GENERALIZED > COM1
{edition}call :dism /Image:W:\ /Set-UserLocale:{locale} /Set-SysLocale:{locale} /Set-InputLocale:{input} || goto :fail
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

// ---- WinPE deploy pass ----

/// Built-in apps the studio may remove (Build-Vms' Remove-OfflineProvisionedApps target
/// list - the design's catalog). The protected set (Store, Terminal, Notepad, Photos...) is
/// never in it.
pub static APP_REMOVAL: &[&str] = &[
    "Microsoft.Microsoft3DViewer", "Microsoft.WindowsAlarms", "Microsoft.Copilot", "Microsoft.549981C3F5F10",
    "Microsoft.WindowsFeedbackHub", "Microsoft.ZuneVideo", "Microsoft.ZuneMusic", "Microsoft.GetHelp", "Microsoft.YourPhone",
    "microsoft.windowscommunicationsapps", "Microsoft.WindowsCamera", "Microsoft.WindowsMaps", "Microsoft.People",
    "Microsoft.MicrosoftSolitaireCollection", "Microsoft.MixedReality.Portal", "Microsoft.MicrosoftOfficeHub",
    "Microsoft.Office.OneNote", "Microsoft.OutlookForWindows", "Microsoft.MSPaint", "Microsoft.SkypeApp",
    "Microsoft.WindowsSoundRecorder", "Microsoft.MicrosoftStickyNotes", "Microsoft.BingWeather", "Microsoft.Getstarted",
    "Microsoft.Windows.DevHome", "Clipchamp.Clipchamp", "Microsoft.Todos", "Microsoft.BingNews",
    "MicrosoftCorporationII.QuickAssist", "Microsoft.PowerAutomateDesktop", "Microsoft.Whiteboard",
    "MicrosoftCorporationII.MicrosoftFamily", "Microsoft.MicrosoftJournal", "MicrosoftTeams", "Microsoft.BingSearch",
    "Microsoft.XboxApp", "Microsoft.GamingApp", "Microsoft.XboxGamingOverlay", "Microsoft.XboxGameOverlay",
    "Microsoft.XboxIdentityProvider", "Microsoft.XboxSpeechToTextOverlay", "Microsoft.Xbox.TCUI", "MSTeams",
];

/// Server Manager feature -> DISM feature table for Windows Server 2025 (build 26100), read
/// from the image's own package manifests by tools/gen-server-features.py.
static SERVER_FEATURES_26100: &str = include_str!("../data/server-features-26100.json");

/// Features Build-Vms never stages offline: their CBS advanced installer runs in Setup's
/// "Getting ready" phase, before specialize names the machine (Build-Vms'
/// $script:guestOnlyWindowsFeatures, evidence in its comments). GuestProvision installs them.
pub const GUEST_ONLY_FEATURES: &[&str] = &["RDS-Web-Access", "RDS-Connection-Broker"];

/// The DISM features the deploy pass enables for a VM's roles and features, as
/// Install-WindowsFeature would: each feature, its role (Parent), what it pulls in on its
/// own (NonAncestorDependencies) and, with management tools, its RSAT companions. Returns
/// the DISM names and the Server Manager names left for GuestProvision (guest-only ones,
/// and everything when there is no table for the gold's build).
pub struct FeaturePlan {
    /// DISM features for the deploy pass, in order.
    pub dism: Vec<String>,
    /// Server Manager names left for GuestProvision (guest-only, unknown, or no table).
    pub online: Vec<String>,
    /// Each requested Server Manager feature and the DISM features it brought in - how the
    /// log reports them, as Install-WindowsFeature names them on Hyper-V.
    pub groups: Vec<(String, Vec<String>)>,
}

pub fn plan_server_features(names: &[String], include_tools: bool, build: &str) -> FeaturePlan {
    static TABLE: std::sync::OnceLock<serde_json::Value> = std::sync::OnceLock::new();
    if !build.contains("26100") {
        return FeaturePlan { dism: vec![], online: names.to_vec(), groups: vec![] };
    }
    let table = TABLE.get_or_init(|| serde_json::from_str(SERVER_FEATURES_26100).unwrap_or_default());
    let (mut dism, mut online, mut groups) = (Vec::<String>::new(), Vec::new(), Vec::<(String, Vec<String>)>::new());
    let mut seen = std::collections::HashSet::new();
    for requested in names {
        if requested.is_empty() || seen.contains(requested) {
            continue;
        }
        if GUEST_ONLY_FEATURES.contains(&requested.as_str()) || table[requested.as_str()].is_null() {
            seen.insert(requested.clone());
            online.push(requested.clone());
            continue;
        }
        // Everything this feature pulls in that no earlier one did.
        let mut mine = Vec::new();
        let mut queue: std::collections::VecDeque<(String, bool)> = [(requested.clone(), true)].into();
        while let Some((name, top)) = queue.pop_front() {
            if name.is_empty() || !seen.insert(name.clone()) {
                continue;
            }
            let entry = &table[name.as_str()];
            if entry.is_null() || GUEST_ONLY_FEATURES.contains(&name.as_str()) {
                continue;
            }
            let list = |k: &str| entry[k].as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_owned)).collect::<Vec<_>>()).unwrap_or_default();
            if let Some(parent) = entry["parent"].as_str().filter(|p| !p.is_empty()) {
                queue.push_back((parent.to_owned(), false));
            }
            for d in list("deps") {
                queue.push_back((d, false));
            }
            if top && include_tools {
                for t in list("tools") {
                    queue.push_back((t, false));
                }
            }
            for d in list("dism") {
                if !dism.contains(&d) {
                    dism.push(d.clone());
                    mine.push(d);
                }
            }
        }
        groups.push((requested.clone(), mine));
    }
    FeaturePlan { dism, online, groups }
}

/// What the deploy pass does to a VM's disk before its first boot - Build-Vms' offline
/// servicing of the mounted VHDX, done by WinPE because the studio never touches a disk.
pub struct DeployPass<'a> {
    /// Capabilities (RSAT, Server Core App Compatibility), from the FoD ISO.
    pub capabilities: &'a [String],
    /// Where the FoD payload sits on its ISO ("LanguagesAndOptionalFeatures" or "") and one
    /// file on it that tells that CD apart from the others.
    pub fod_root: &'a str,
    pub fod_marker: &'a str,
    /// Client optional features (Hyper-V Management Tools) - in the image, no source.
    pub client_features: &'a [String],
    /// Server roles and features as DISM names (plan_server_features); a payload the image
    /// does not carry (.NET 3.5) comes from the source ISO's sources\sxs when it is attached.
    pub server_features: &'a [String],
    /// Provisioned apps to remove, by package family prefix.
    pub remove_apps: &'a [String],
}

/// The deploy pass's pe.cmd. Servicing failures are markers, not stops (the job log shows
/// each; GuestProvision retries capabilities online); a disk that cannot be reached or an
/// answer file that cannot be written ends the pass, and the build with it.
pub fn pe_deploy_cmd(p: &DeployPass) -> String {
    let marker = p.fod_marker.replace('/', "\\");
    let fod_find = if marker.is_empty() { String::new() } else { format!("if exist %%d:\\{marker} set FOD=%%d:\n") };
    let fod_src = if p.fod_root.is_empty() { "%FOD%\\".to_owned() } else { format!("%FOD%\\{}", p.fod_root) };
    let caps: String = p.capabilities.iter().map(|c| format!("call :cap {c}\n")).collect();
    let server: String = p
        .server_features
        .iter()
        .map(|f| {
            format!(
                "call :dism /Image:W:\\ /Enable-Feature /FeatureName:{f} /All %SXSARG% && (echo PVS-FEATURE-OK {f} > COM1) || (echo PVS-FEATURE-FAIL {f} > COM1 & set FALLBACK=1)\n"
            )
        })
        .collect();
    let features: String = p
        .client_features
        .iter()
        .map(|f| {
            format!(
                "call :dism /Image:W:\\ /Enable-Feature /FeatureName:{f} /All && (echo PVS-FEATURE-OK {f} > COM1) || (echo PVS-FEATURE-FAIL {f} > COM1 & set FALLBACK=1)\n"
            )
        })
        .collect();
    let app_checks: String = p
        .remove_apps
        .iter()
        .filter(|a| APP_REMOVAL.iter().any(|x| x.eq_ignore_ascii_case(a)))
        .map(|a| format!("if /i \"!p:~0,{}!\"==\"{a}_\" goto :rm\n", a.len() + 1))
        .collect();
    let apps = if app_checks.is_empty() {
        String::new()
    } else {
        concat!(
            "dism /English /Image:W:\\ /Get-ProvisionedAppxPackages > X:\\apps.txt 2>&1\n",
            "for /f \"usebackq tokens=1,* delims=:\" %%a in (\"X:\\apps.txt\") do (\n",
            "set \"k=%%a\"\n",
            "if \"!k:~0,11!\"==\"PackageName\" call :app %%b\n",
            ")\n",
            "echo PVS-APPS-DONE > COM1\n"
        )
        .to_owned()
    };
    crlf(&format!(
        r#"@echo off
rem PVE VM Studio WinPE deploy pass: Build-Vms' offline servicing of a new VM's disk, before
rem its first boot - capabilities, features, app removal, then the VM's own answer file and
rem GuestProvision written into the image. Markers to COM1.
setlocal EnableDelayedExpansion
set SEED=%1
set VIO=
set FOD=
set FALLBACK=
set SXSARG=
for %%d in (C D E F G H I J K L M N O P Q R S T U V W Y Z) do (
if exist %%d:\virtio-win_license.txt set VIO=%%d:
if exist %%d:\sources\sxs set SXSARG=/Source:%%d:\sources\sxs /LimitAccess
{fod_find})
echo PVS-DEPLOY-START VIO=%VIO% FOD=%FOD% > COM1
rem The SAN policy first: a disk that arrives under WinPE's default (offline, read-only) cannot
rem have the read-only flag cleared once its volumes are mounted. Under OnlineAll the VM's
rem disk arrives online and writable when drvload brings it in.
(echo san policy=OnlineAll) > X:\san.txt
diskpart /s X:\san.txt > COM1 2>&1
rem vioscsi from inside WinPE (built in since the studio carries it), else from the virtio CD.
for %%v in (2k25 w11) do if exist X:\pvs\drivers\vioscsi\%%v\amd64\vioscsi.inf (drvload X:\pvs\drivers\vioscsi\%%v\amd64\vioscsi.inf > COM1 2>&1 & goto :disk)
if "%VIO%"=="" (echo PVS-NO-VIOSCSI > COM1 & goto :fail)
for %%v in (2k25 w11 2k22) do if exist %VIO%\vioscsi\%%v\amd64\vioscsi.inf (drvload %VIO%\vioscsi\%%v\amd64\vioscsi.inf > COM1 2>&1 & goto :disk)
echo PVS-NO-VIOSCSI > COM1
goto :fail
:disk
rem Should a disk still be offline or read-only: the flag is cleared while the disk is
rem offline (with its volumes mounted it refuses), then online, rescan - a volume only shows
rem after one - and Windows is looked for on partition 3 of each disk (a data disk can
rem enumerate as disk 0), a few times while the volumes settle.
(
for /l %%n in (0,1,7) do (
echo select disk %%n
echo offline disk noerr
echo attributes disk clear readonly noerr
echo online disk noerr
)
echo rescan
) > X:\online.txt
diskpart /s X:\online.txt > COM1 2>&1
for /l %%t in (1,1,5) do (
  for /l %%n in (0,1,7) do (
    if not exist W:\Windows\System32\config\SYSTEM (
      (echo select disk %%n& echo select partition 3& echo assign letter=W noerr) > X:\find.txt
      diskpart /s X:\find.txt > COM1 2>&1
      if not exist W:\Windows\System32\config\SYSTEM (
        (echo select volume W& echo remove letter=W noerr) > X:\drop.txt
        diskpart /s X:\drop.txt > nul 2>&1
      )
    )
  )
  if not exist W:\Windows\System32\config\SYSTEM ping -n 3 127.0.0.1 >nul
)
if not exist W:\Windows\System32\config\SYSTEM (echo PVS-NO-WINDOWS > COM1 & goto :fail)
rem The volume has a read-only flag of its own, apart from the disk's.
(echo select volume W& echo attributes volume clear readonly noerr& echo attributes volume clear hidden noerr) > X:\rw.txt
diskpart /s X:\rw.txt > COM1 2>&1
echo pvs> W:\pvs-write-test.txt 2>nul
if not exist W:\pvs-write-test.txt (
  (echo select volume W& echo detail volume& echo attributes volume& echo select disk 0& echo detail disk& echo attributes disk) > X:\why.txt
  diskpart /s X:\why.txt > COM1 2>&1
  echo PVS-DISK-READONLY > COM1
  goto :fail
)
del /f /q W:\pvs-write-test.txt
echo PVS-DISK > COM1
{caps}{server}{features}{apps}if not exist W:\Windows\Panther mkdir W:\Windows\Panther
copy /y %SEED%\pvs-vm\unattend.xml W:\Windows\Panther\unattend.xml > COM1 2>&1 || goto :fail
if not exist W:\Windows\Setup\Scripts mkdir W:\Windows\Setup\Scripts
copy /y %SEED%\pvs-vm\setupcomplete.cmd W:\Windows\Setup\Scripts\SetupComplete.cmd > COM1 2>&1 || goto :fail
if exist %SEED%\pvs-vm\GuestProvision xcopy /e /i /q /y %SEED%\pvs-vm\GuestProvision W:\Windows\Setup\Scripts\GuestProvision > COM1 2>&1 || goto :fail
rem GuestProvision gets only what has to happen online - unless something here failed: then
rem the full lists, so it installs online what did not make it in offline (Build-Vms' fallback).
if defined FALLBACK (
  copy /y W:\Windows\Setup\Scripts\GuestProvision\manifest-fallback.json W:\Windows\Setup\Scripts\GuestProvision\manifest.json > COM1 2>&1
  echo PVS-FALLBACK > COM1
)
del /f /q W:\Windows\Setup\Scripts\GuestProvision\manifest-fallback.json > nul 2>&1
echo PVS-ANSWERFILE > COM1
rem DISM's log goes onto the disk: the studio reads it back through the guest agent when
rem something failed here (WinPE's own copy is gone with the RAM disk).
copy /y X:\Windows\Logs\DISM\dism.log W:\Windows\Temp\pvs-deploy-dism.log > nul 2>&1
echo PVS-DEPLOY-OK > COM1
goto :eof
:fail
echo PVS-DEPLOY-FAILED > COM1
goto :eof
:cap
if "%FOD%"=="" (echo PVS-CAP-SKIP %1 > COM1 & set FALLBACK=1 & exit /b 0)
call :dism /Image:W:\ /Add-Capability /CapabilityName:%1 /Source:{fod_src} /LimitAccess && (echo PVS-CAP-OK %1 > COM1) || (echo PVS-CAP-FAIL %1 > COM1 & set FALLBACK=1)
exit /b 0
:app
set "p=%~1"
{app_checks}exit /b 0
:rm
call :dism /Image:W:\ /Remove-ProvisionedAppxPackage /PackageName:!p! && (echo PVS-APP-REMOVED !p! > COM1) || (echo PVS-APP-FAIL !p! > COM1)
exit /b 0
:dism
rem Back-to-back DISM sessions can collide on the image's mapped hives - two retries.
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
pub(crate) async fn run_pass(
    pve: &Pve,
    log: &JobLog,
    pr: &mut Progress,
    node: &str,
    vmid: u32,
    label: &str,
    timeout_min: u64,
    units: &[(String, f64)],
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
    // The step's own progress: DISM paints 0-100 % for every operation (a mount, an update,
    // a scan), so its figure is the running operation's alone. With the pass's plan - its
    // operations in order, each weighted by how long it takes - a marker that starts one
    // moves the step to the sum of the ones before it, and DISM's figure fills only that
    // operation's share. Without a plan the step shows DISM's figure as text, never as
    // the step's percentage.
    let total: f64 = units.iter().map(|(_, w)| w).sum::<f64>().max(1.0);
    let (mut at, mut done, mut doing) = (None::<usize>, 0.0f64, String::new());
    loop {
        log.check_abort()?;
        if started.elapsed() > Duration::from_secs(timeout_min * 60) {
            let _ = pve.vm_action(node, vmid, "stop").await;
            bail!("{label} did not finish within {timeout_min} minutes (so far: {})", crate::markers::list(&markers));
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
                            let what = if doing.is_empty() { String::new() } else { format!("{doing} · ") };
                            match at {
                                Some(k) => pr.within((done + units[k].1 * pct / 100.0) / total, format!("{label}: {what}DISM {pct:.0}%")),
                                None => pr.note(format!("{label}: {what}DISM {pct:.0}%")),
                            }
                        }
                        continue;
                    }
                    if part.starts_with("PVS-") {
                        if let Some(key) = unit_key(part)
                            && let Some(k) = units.iter().enumerate().skip(at.unwrap_or(0)).find(|(_, (u, _))| *u == key || key.starts_with(&format!("{u} "))).map(|(k, _)| k)
                        {
                            at = Some(k);
                            done = units[..k].iter().map(|(_, w)| w).sum();
                            doing = crate::markers::text(part);
                            last_pct = -1.0;
                            pr.within(done / total, format!("{label}: {doing}"));
                        }
                        // One line per feature, capability or app is detail: the caller sums
                        // them up per Server Manager feature. So is a worker's verdict per
                        // update, which the media build words itself.
                        if ["PVS-FEATURE-", "PVS-CAP-", "PVS-APP-", "PVS-PROV-", "PVS-UPD-OK", "PVS-UPD-FAIL"].iter().any(|p| part.starts_with(p)) {
                            log.debug(crate::markers::text(part)).await;
                        } else {
                            log.line(crate::markers::text(part)).await;
                        }
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

/// The bake's passes as plans for run_pass, weighted in seconds as a Windows 11 bake took
/// them on pve-01 (2026-10-06, 5d0fd95c): pass 1 is the image (100 s, DISM's percentage) and
/// little else; audit mode waits for Windows' own boot (2 min, nothing to measure), then the
/// drivers, the agent and sysprep (46 s); pass 2 is short.
pub(crate) fn pass1_units() -> Vec<(String, f64)> {
    [("PASS1-START", 13.0), ("OS-DISK", 2.0), ("PARTITIONED", 100.0), ("APPLIED", 2.0), ("DRIVERS", 5.0), ("BCDBOOT", 1.0)]
        .iter().map(|(k, w)| (k.to_string(), *w)).collect()
}
pub(crate) fn audit_units() -> Vec<(String, f64)> {
    [("AUDIT-START", 8.0), ("VIRTIO", 5.0), ("QGA", 1.0), ("SYSPREP-START", 46.0)].iter().map(|(k, w)| (k.to_string(), *w)).collect()
}
pub(crate) fn pass2_units() -> Vec<(String, f64)> {
    [("PASS2-START", 1.0), ("GENERALIZED", 5.0), ("LOCALE", 2.0), ("TIMEZONE", 4.0), ("ANSWERFILE", 2.0)].iter().map(|(k, w)| (k.to_string(), *w)).collect()
}

/// The deploy pass as a plan: the disk found, then each capability and feature (each one's
/// verdict starts the next), the app removal, the answer file. A capability from the FoD ISO
/// takes about a minute, a feature half of one.
pub fn deploy_units(p: &DeployPass) -> Vec<(String, f64)> {
    let mut v: Vec<(String, f64)> = vec![("DEPLOY-START".into(), 12.0)];
    let mut items: Vec<(String, String, f64)> = Vec::new();
    items.extend(p.capabilities.iter().map(|c| (format!("CAP {c}"), c.clone(), 60.0)));
    items.extend(p.server_features.iter().chain(p.client_features).map(|f| (format!("FEATURE {f}"), f.clone(), 30.0)));
    let mut start = "DISK".to_owned();
    for (done, _, w) in &items {
        v.push((start.clone(), *w));
        start = done.clone();
    }
    if p.remove_apps.iter().any(|a| APP_REMOVAL.iter().any(|x| x.eq_ignore_ascii_case(a))) {
        v.push((start.clone(), 30.0));
        start = "APPS-DONE".into();
    }
    v.push((start, 2.0));
    v.push(("ANSWERFILE".into(), 1.0));
    v
}

/// The plan key a marker starts: "UPD 1 x.msu", "HEALTH 1-before", "INDEX 1". An app's
/// verdict ("PROV-OK 1 <app>", -FAIL with its code) starts the next app: "PROV 1 <app>". An
/// update's verdict starts nothing - the next marker does.
pub(crate) fn unit_key(marker: &str) -> Option<String> {
    let rest = marker.strip_prefix("PVS-")?.trim();
    let (key, args) = rest.split_once(' ').map_or((rest, ""), |(k, a)| (k, a.trim()));
    let first = || args.split_whitespace().next().map(str::to_owned);
    match key {
        "UPD-OK" | "UPD-FAIL" | "APP-REMOVED" | "APP-FAIL" => None,
        "PROV-OK" | "PROV-FAIL" => {
            let mut a = args.split_whitespace();
            Some(format!("PROV {} {}", a.next()?, a.next()?))
        }
        // The deploy pass: a capability's or a feature's verdict starts the next one.
        "CAP-OK" | "CAP-FAIL" | "CAP-SKIP" => Some(format!("CAP {}", first()?)),
        "FEATURE-OK" | "FEATURE-FAIL" => Some(format!("FEATURE {}", first()?)),
        _ => Some(rest.to_owned()),
    }
}

/// Sets the boot order on its own and reads it back. Changed together with a drive, PVE
/// rebuilds the order from the drives instead ("order=scsi0;sata3") - and a generalized
/// disk that boots when WinPE should is a spent sysprep: specialize and OOBE run, and
/// the bake is lost.
pub(crate) async fn set_boot(pve: &Pve, node: &str, vmid: u32, order: &str) -> Result<()> {
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
    iso_sha256: &str,
) -> Result<()> {
    let (pve, log) = (b.pve, b.log);
    let node = p.node.as_str();
    let upgrade = virtual_edition(&opt.edition_upgrade);
    let id = gold_image_id(img, &opt.edition_upgrade);
    let display = upgrade.map(|v| v.display.to_owned()).unwrap_or_else(|| img.name.clone());
    let client = img.installation_type == "Client";
    golds::check_node_memory(pve, log, node, p.memory_mb.max(4096)).await?;
    let mut pr = Progress::new(log, format!("Baking {display}"));
    pr.calibrate("WinPE pass 1").await;
    pr.stage(0.0, 2.0, "creating the bake VM");
    let mut made: Option<u32> = None;

    let result: Result<(u32, String, Option<String>)> = async {
        // ---- seeds: one per WinPE pass ----
        let working = golds::working_name(gold_id);
        let seed_for = |n: u8| format!("pvs-seed-{working}-pass{n}");
        let (s1, s2) = (seed_for(1), seed_for(2));
        // Seeds are small disks now (sata3), not ISOs: built here, attached once the VM exists.
        let pass1 = SeedDisk::build(
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

        // ---- the bake VM ----
        pve.ensure_pool(GOLD_POOL, "PVE VM Studio: golds (templates) and the bakes that make them").await?;
        let guard = pve.vmid_guard().await;
        let vmid = pve.free_vmid_in(GOLD_IDS).await?;
        let name = working.clone();
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
            ("efidisk0", format!("{}:1,efitype=4m,pre-enrolled-keys=1", p.disk_storage)),
            ("scsihw", "virtio-scsi-single"),
            ("scsi0", format!("{}:{},discard=on,iothread=1,ssd=1", p.disk_storage, opt.disk_gb())),
            ("sata0", format!("{winpe_volid},media=cdrom")),
            ("sata1", format!("{},media=cdrom", opt.iso)),
            ("sata2", format!("{virtio_volid},media=cdrom")),
            ("serial0", "socket"),
            ("net0", net0),
            // fstrim_cloned_disks: thin storage gets the clone's freed blocks back (PVE's qm guide).
            ("agent", "enabled=1,fstrim_cloned_disks=1"),
            // Windows expects a local-time RTC.
            ("localtime", 1),
            ("boot", "order=sata0"),
            ("tags", crate::tags::BAKE),
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
        seed::attach(pve, node, vmid, "sata3", &p.disk_storage, pass1, &s1).await.context("attaching the pass 1 seed disk")?;
        log.ok("Pass 1 seed attached as a disk (sata3)").await;
        pr.within(1.0, "created");

        // ---- WinPE pass 1: apply ----
        log.run("WinPE pass 1: partition, apply, drivers, boot files").await;
        pr.stage(2.0, 39.0, "WinPE pass 1");
        let m = run_pass(pve, log, &mut pr, node, vmid, "pass 1", 40, &pass1_units()).await?;
        if !m.iter().any(|l| l == "PVS-PASS1-OK") {
            bail!("pass 1 failed: {}", m.last().map(|l| crate::markers::text(l)).unwrap_or_else(|| "nothing on the serial console".into()));
        }
        // Asked now, before audit mode has cost twenty minutes: an index that cannot become
        // the edition will not become it after sysprep either.
        let targets: Vec<String> = m.iter().filter_map(|l| l.strip_prefix("PVS-TARGET ").map(|t| t.trim().to_owned())).collect();
        let edition_target = match upgrade {
            Some(v) => match virtual_target(v.key, &targets) {
                Some(t) => {
                    log.ok(format!("Index {} can become '{t}' - continuing", img.index)).await;
                    Some(t)
                }
                None => bail!(
                    "index {} cannot be changed to {} - DISM lists no matching target (can become: {}). {}",
                    img.index,
                    v.display,
                    if targets.is_empty() { "none".into() } else { targets.join(", ") },
                    v.hint
                ),
            },
            None => None,
        };

        // ---- audit boot: drivers, agent, generalize ----
        log.run("Audit mode: virtio drivers, guest agent, sysprep /generalize").await;
        pr.stage(39.0, 86.0, "audit mode and sysprep");
        set_boot(pve, node, vmid, "scsi0").await?;
        let m = run_pass(pve, log, &mut pr, node, vmid, "audit", 60, &audit_units()).await?;
        if !m.iter().any(|l| l == "PVS-SYSPREP-START") {
            bail!("audit mode did not reach sysprep: {}", m.last().cloned().unwrap_or_else(|| "no markers".into()));
        }

        // ---- WinPE pass 2: verify, customize, key ----
        log.run("WinPE pass 2: verify generalize, locale, time zone, policies, key").await;
        pr.stage(86.0, 98.0, "WinPE pass 2");
        // The pass 2 seed, now that the edition DISM will be handed is known; the VM is off
        // after sysprep, so the seed disks swap.
        let pass2 = SeedDisk::build(
            b.work,
            &s2,
            "PVSSEED",
            &[("pvs/pe.cmd", &pe2_cmd(img, &opt.region, &opt.features, edition_target.as_deref())), ("pvs/gold.xml", &gold_unattend())],
        )
        .await?;
        seed::detach(pve, node, vmid, "sata3").await?;
        seed::attach(pve, node, vmid, "sata3", &p.disk_storage, pass2, &s2).await.context("attaching the pass 2 seed disk")?;
        log.ok("Pass 2 seed attached as a disk (sata3)").await;
        set_boot(pve, node, vmid, "sata0").await?;
        let m = run_pass(pve, log, &mut pr, node, vmid, "pass 2", 30, &pass2_units()).await?;
        if !m.iter().any(|l| l == "PVS-PASS2-OK") {
            let why = m.iter().find(|l| l.starts_with("PVS-NO-SYSPREP-TAG") || l.starts_with("PVS-NOT-GENERALIZED") || l.starts_with("PVS-EDITION-NOT-CHANGED") || l.ends_with("FAILED")).cloned();
            bail!("pass 2 failed: {}", why.or_else(|| m.last().cloned()).map(|l| crate::markers::text(&l)).unwrap_or_else(|| "nothing on the serial console".into()));
        }

        // ---- make it a gold ----
        pr.stage(98.0, 100.0, "making it a template");
        pve.vm_set(
            node,
            vmid,
            form![("delete", "sata0,sata1,sata2"), ("net0", format!("virtio,bridge={}", p.bridge))],
        )
        .await?;
        seed::detach(pve, node, vmid, "sata3").await?;
        // Windows 11 Setup needed the TPM; the gold must not keep it. A clone copies the
        // state volume bit for bit - every VM would share one endorsement key and whatever the
        // bake sealed. Each VM gets its own at deploy (vms.rs), as Hyper-V gives each VM its own.
        if client {
            pve.vm_set(node, vmid, form![("delete", "tpmstate0"), ("force", 1)]).await?;
        }
        set_boot(pve, node, vmid, "scsi0").await?;
        let gold_name = golds::gold_name(gold_id);
        let notes = format!(
            "## Gold: {display}\n\nBaked by PVE VM Studio on {}. Do not start this template - clone it.\n\n\
             | | |\n|---|---|\n| Gold id | `{gold_id}` |\n| Image | `{id}` (index {} of `{}`) |\n| Build | {} |\n| Language | {} |\n| Region | {} / keyboard {} / {} |\n| virtio-win | {virtio_release} |\n| Policies | {} |\n| Key | {} |\n",
            Utc::now().format("%Y-%m-%d %H:%M UTC"),
            img.index,
            opt.iso,
            if img.version.is_empty() { &img.build } else { &img.version },
            img.language,
            opt.region.locale,
            opt.region.keyboard,
            opt.region.timezone,
            if opt.features.is_empty() { "none".into() } else { opt.features.join(", ") },
            if gvlk(edition_target.as_deref().unwrap_or(&img.edition_id), &img.build).is_some() { "KMS client (GVLK)" } else { "none" },
        );
        let build = if img.version.is_empty() { &img.build } else { &img.version };
        let tags = vec![crate::tags::GOLD.to_owned(), crate::tags::os("windows", &id, Some(build))];
        pve.vm_set(node, vmid, form![("name", &gold_name), ("tags", tags.join(";")), ("description", notes)]).await?;
        crate::tags::paint(pve, &tags).await;
        pve.run_task(&format!("/nodes/{}/qemu/{vmid}/template", enc(node)), vec![], |_| {}).await?;
        Ok((vmid, gold_name, edition_target))
    }
    .await;

    match result {
        Ok((vmid, gold_name, edition_target)) => {
            // New-Vhdx's New-WindowsGoldManifest, then the keys every gold shares.
            let has = |f: &str| opt.features.iter().any(|x| x == f);
            let mut bake_options = json!({ "rdp": has("rdp"), "ping": has("ping"), "blockSignInInputMethods": has("signinkeyboard"), "preferIPv4": has("preferipv4"), "edgeBaseline": has("edge") && img.installation_type != "Server Core" });
            if client {
                bake_options["preventDeviceEncryption"] = json!(has("noencrypt"));
                bake_options["vmPowerPlan"] = json!(has("power"));
                bake_options["suppressWelcomeExperience"] = json!(has("welcome"));
                bake_options["suppressFirstSignInAnimation"] = json!(has("firstlogon"));
            } else {
                bake_options["suppressServerManagerAtLogon"] = json!(has("svrmgr"));
            }
            let manifest = golds::complete_manifest(
                gold_id,
                json!({
                    "label": "",
                    "osFamily": "windows",
                    "imageId": id,
                    "displayName": display,
                    "build": if img.version.is_empty() { img.build.clone() } else { img.version.clone() },
                    "language": img.language,
                    "locale": opt.region.locale,
                    "keyboardLayout": opt.region.keyboard,
                    "inputLocale": input_locale(if opt.region.keyboard.is_empty() { &opt.region.locale } else { &opt.region.keyboard }),
                    "timeZone": opt.region.timezone,
                    "localeMode": "offline",
                    "imageName": img.name,
                    "imageIndex": img.index,
                    // The SKU it became, as DISM named it (ServerRdsh, ServerTurbineCor).
                    "editionId": edition_target.clone().unwrap_or_else(|| img.edition_id.clone()),
                    // DISM names an evaluation SKU ...Eval: 180 days, no KMS.
                    "evaluation": edition_target.as_deref().unwrap_or(&img.edition_id).ends_with("Eval"),
                    "generalized": true,
                    // [diff] Hyper-V has "avma" (host-based activation); PVE has no AVMA,
                    // so a gold carries the KMS client key or nothing.
                    "activation": if gvlk(edition_target.as_deref().unwrap_or(&img.edition_id), &img.build).is_some() { "kms-client" } else { "none" },
                    "requiresTpm": client,
                    "secureBootTemplate": "MicrosoftWindows",
                    "bakeOptions": bake_options,
                    "sourceMedia": opt.iso,
                    "sourceMediaSha256": iso_sha256,
                    "installationType": img.installation_type,
                    "virtio": virtio_release,
                }),
                node,
                &p.disk_storage,
                opt.disk_gb(),
            )
            .await;
            let mut manifest = manifest;
            if let (Some(v), Some(_)) = (upgrade, &edition_target) {
                // imageName and imageIndex describe the index that was applied; imageId and
                // displayName what it became. Both are true, so the sidecar says both.
                manifest["sourceEdition"] = json!(img.name);
                manifest["sourceEditionId"] = json!(img.edition_id);
                manifest["editionUpgrade"] = json!(v.manifest);
            }
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
    /// The answer file reaches specialize (written into Panther by the WinPE deploy pass):
    /// static addresses go into it (TCPIP / DNS-Client by MAC, as Build-Vms writes them)
    /// instead of SetupComplete.
    pub specialize: bool,
    /// A join done by the answer file in specialize (Microsoft-Windows-UnattendedJoin).
    pub join_specialize: Option<crate::guest::DomainJoin>,
    /// A product key from the Windows licenses blade - "" keeps the gold's KMS client key.
    pub product_key: String,
}

/// A Windows product key: five groups of five letters and digits.
pub fn product_key_ok(k: &str) -> bool {
    let g: Vec<&str> = k.split('-').collect();
    g.len() == 5 && g.iter().all(|x| x.len() == 5 && x.chars().all(|c| c.is_ascii_alphanumeric()))
}

/// "BC:24:11:AA:BB:CC" -> "BC-24-11-AA-BB-CC", the TCPIP / DNS-Client Identifier form
/// (Build-Vms' ConvertTo-UnattendMacAddress).
fn unattend_mac(mac: &str) -> String {
    let raw: String = mac.chars().filter(|c| c.is_ascii_hexdigit()).collect::<String>().to_uppercase();
    raw.as_bytes().chunks(2).map(|c| String::from_utf8_lossy(c).into_owned()).collect::<Vec<_>>().join("-")
}

/// The specialize components Build-Vms' Get-ServerUnattendContent writes after
/// <ComputerName>: TCPIP and DNS-Client per adapter with a static address (the primary one
/// first, with the route and the resolver; extra adapters neither - a second default route
/// is how a multi-homed guest becomes unreachable), then UnattendedJoin.
fn specialize_components(s: &WinVmSeed) -> String {
    let mut ifaces = Vec::new();
    if !s.ip.is_empty() {
        ifaces.push((unattend_mac(&s.mac), format!("{}/{}", s.ip, s.prefix), s.gateway.clone(), s.dns.clone()));
    }
    for (mac, addr, prefix) in &s.extra {
        ifaces.push((unattend_mac(mac), format!("{addr}/{prefix}"), String::new(), vec![]));
    }
    let mut out = String::new();
    if s.specialize && !ifaces.is_empty() {
        let tcpip: String = ifaces
            .iter()
            .map(|(id, cidr, gw, _)| {
                let routes = if gw.is_empty() {
                    String::new()
                } else {
                    format!(
                        "\n          <Routes>\n            <Route wcm:action=\"add\">\n              <Identifier>0</Identifier>\n              <Prefix>0.0.0.0/0</Prefix>\n              <NextHopAddress>{}</NextHopAddress>\n            </Route>\n          </Routes>",
                        xml_escape(gw)
                    )
                };
                format!(
                    "\n        <Interface wcm:action=\"add\">\n          <Ipv4Settings>\n            <DhcpEnabled>false</DhcpEnabled>\n          </Ipv4Settings>\n          <Ipv6Settings>\n            <DhcpEnabled>false</DhcpEnabled>\n          </Ipv6Settings>\n          <Identifier>{}</Identifier>\n          <UnicastIpAddresses>\n            <IpAddress wcm:action=\"add\" wcm:keyValue=\"1\">{}</IpAddress>\n          </UnicastIpAddresses>{routes}\n        </Interface>",
                    xml_escape(id),
                    xml_escape(cidr)
                )
            })
            .collect();
        out += &format!("\n    <component name=\"Microsoft-Windows-TCPIP\" {COMP}>\n      <Interfaces>{tcpip}\n      </Interfaces>\n    </component>");
        let dns: String = ifaces
            .iter()
            .filter(|(_, _, _, d)| !d.is_empty())
            .map(|(id, _, _, d)| {
                let entries: String = d
                    .iter()
                    .enumerate()
                    .map(|(i, x)| format!("\n            <IpAddress wcm:action=\"add\" wcm:keyValue=\"{}\">{}</IpAddress>", i + 1, xml_escape(x)))
                    .collect();
                format!(
                    "\n        <Interface wcm:action=\"add\">\n          <DNSServerSearchOrder>{entries}\n          </DNSServerSearchOrder>\n          <Identifier>{}</Identifier>\n        </Interface>",
                    xml_escape(id)
                )
            })
            .collect();
        if !dns.is_empty() {
            out += &format!("\n    <component name=\"Microsoft-Windows-DNS-Client\" {COMP}>\n      <Interfaces>{dns}\n      </Interfaces>\n    </component>");
        }
    }
    if let (true, Some(j)) = (s.specialize, &s.join_specialize) {
        // DOMAIN\user and user@domain both work; the bare name takes the joined domain.
        let (cred_domain, cred_user) = if let Some((d, u)) = j.user.split_once('\\') {
            (d.to_owned(), u.to_owned())
        } else if let Some((u, d)) = j.user.split_once('@') {
            (d.to_owned(), u.to_owned())
        } else {
            (j.domain.clone(), j.user.clone())
        };
        let ou = if j.ou.trim().is_empty() { String::new() } else { format!("\n        <MachineObjectOU>{}</MachineObjectOU>", xml_escape(j.ou.trim())) };
        out += &format!(
            "\n    <component name=\"Microsoft-Windows-UnattendedJoin\" {COMP}>\n      <Identification>\n        <Credentials>\n          <Domain>{}</Domain>\n          <Password>{}</Password>\n          <Username>{}</Username>\n        </Credentials>\n        <JoinDomain>{}</JoinDomain>{ou}\n      </Identification>\n    </component>",
            xml_escape(&cred_domain),
            xml_escape(&j.password),
            xml_escape(&cred_user),
            xml_escape(j.domain.trim())
        );
    }
    out
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

/// The VM's answer file: specialize names the machine (Build-Vms' Get-ServerUnattendContent),
/// oobeSystem does the rest. Written into Panther by the WinPE deploy pass it replaces the
/// gold's own file; on the seed-CD path the gold's firstboot.cmd points oobeSystem at it.
/// International-Core repeats the gold's locale: the region page has no hide flag and is
/// only skipped when this answers it.
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
    let computer = xml_escape(&s.name.to_uppercase());
    let specialize = specialize_components(s);
    format!(
        r#"<?xml version="1.0" encoding="utf-8"?>
<unattend {NS}>
  <settings pass="specialize">
    <component name="Microsoft-Windows-Shell-Setup" {COMP}>
      <ComputerName>{computer}</ComputerName>
    </component>{specialize}
  </settings>
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
    // With the answer file in specialize the addresses are set there already.
    if !s.ip.is_empty() && !s.specialize {
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
    for (mac, addr, prefix) in s.extra.iter().filter(|_| !s.specialize) {
        let mac = mac.replace(':', "-").to_uppercase();
        ip += &format!(
            "powershell -NoProfile -ExecutionPolicy Bypass -Command \"$a = Get-NetAdapter | Where-Object MacAddress -eq '{mac}'; Set-NetIPInterface -InterfaceIndex $a.ifIndex -Dhcp Disabled; New-NetIPAddress -InterfaceIndex $a.ifIndex -IPAddress {addr} -PrefixLength {prefix}\" >> C:\\Windows\\Temp\\pvs-firstboot.log 2>&1\n"
        );
    }
    // The licence from the Windows licenses blade: installed over the gold's KMS client key,
    // then activated (online - a failure is logged, the VM is not held up). The file deletes
    // itself, the seed disk goes after this boot.
    if product_key_ok(&s.product_key) {
        ip += &format!(
            "cscript //nologo %windir%\\system32\\slmgr.vbs /ipk {} >> C:\\Windows\\Temp\\pvs-firstboot.log 2>&1\ncscript //nologo %windir%\\system32\\slmgr.vbs /ato >> C:\\Windows\\Temp\\pvs-firstboot.log 2>&1\n",
            s.product_key.to_uppercase()
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
    // The last line deletes this file (Build-Vms' Set-OfflineGuestProvisionPayload):
    // "(goto) 2>nul" ends the batch before del runs, so cmd never reads on from a file
    // that is gone. GuestProvision removes its own folder after a successful run, so
    // nothing under Setup\Scripts runs again if the VM is ever sysprepped and captured.
    crlf(&format!(
        "@echo off\n{ip}{cds}{guest}if not exist C:\\ProgramData\\PVS mkdir C:\\ProgramData\\PVS\necho done> C:\\ProgramData\\PVS\\provisioned.txt\n(goto) 2>nul & del \"%~f0\"\n"
    ))
}

/// Waits until SetupComplete.cmd left its marker. The bar moves with the milestones of the
/// first boot: the agent answering, firstboot.cmd having run, the marker.
pub async fn follow_first_boot(pve: &Pve, log: &JobLog, pr: &mut Progress, node: &str, vmid: u32) -> Result<()> {
    let started = Instant::now();
    let mut agent = false;
    let mut first = false;
    loop {
        log.check_abort()?;
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
        // GuestProvision's own steps, once it runs ("<done> <total> <step>", weighted in
        // seconds): it is most of this boot - 5 of 6 minutes on vm-ws2025-02 (2026-10-06).
        let gp = if agent {
            pve.agent_read(node, vmid, r"C:\ProgramData\PVS\progress.txt", 0).await.and_then(|(t, _)| {
                let mut it = t.trim().splitn(3, ' ');
                let (d, n) = (it.next()?.parse::<f64>().ok()?, it.next()?.parse::<f64>().ok()?);
                Some((d / n.max(1.0), it.next().unwrap_or("").trim().to_owned()))
            })
        } else {
            None
        };
        match gp {
            Some((f, step)) => pr.within(0.2 + 0.8 * f, format!("GuestProvision: {step}")),
            None => pr.within(if first { 0.15 } else if agent { 0.1 } else { 0.0 }, if first { "OOBE" } else if agent { "specialize" } else { "booting" }),
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pass_plans_follow_the_scripts() {
        let src = include_str!("windows.rs");
        for (k, _) in pass1_units().iter().chain(&audit_units()).chain(&pass2_units()) {
            assert!(src.contains(&format!("echo PVS-{k}")), "no marker for {k}");
        }
        let caps = vec!["Rsat.Dns.Tools~~~~0.0.1.0".to_owned()];
        let feats = vec!["DNS".to_owned()];
        let apps = vec!["Microsoft.BingNews".to_owned()];
        let p = DeployPass { capabilities: &caps, fod_root: "", fod_marker: "x", client_features: &[], server_features: &feats, remove_apps: &apps };
        let u: Vec<String> = deploy_units(&p).into_iter().map(|(k, _)| k).collect();
        assert_eq!(u, vec!["DEPLOY-START", "DISK", "CAP Rsat.Dns.Tools~~~~0.0.1.0", "FEATURE DNS", "APPS-DONE", "ANSWERFILE"]);
        assert_eq!(unit_key("PVS-CAP-OK Rsat.Dns.Tools~~~~0.0.1.0").as_deref(), Some("CAP Rsat.Dns.Tools~~~~0.0.1.0"));
        assert_eq!(unit_key("PVS-FEATURE-FAIL DNS").as_deref(), Some("FEATURE DNS"));
        assert_eq!(unit_key("PVS-APP-REMOVED x"), None);
    }

    #[test]
    fn edge_search_engines_survive_cmd() {
        // The & of the suggest URL sits between two \" pairs - outside cmd's quoting.
        let d = cmd_reg_data(r#"[{"u": "a?x=1&q=2", "n": "G"}]"#);
        assert_eq!(d, r#""[{\"u\": \"a?x=1^&q=2\", \"n\": \"G\"}]""#);
        assert_eq!(cmd_reg_data("a?x=1&q=2"), r#""a?x=1&q=2""#);
        let core = pass2_policies(&["edge".into()], false, true);
        assert!(!core.contains("Edge"));
        let client = pass2_policies(&["edge".into()], true, false);
        assert!(client.contains("ManagedSearchEngines") && !client.contains("PreventDeviceEncryption"));
    }

    #[test]
    fn prefer_ipv4_is_bit_0x20() {
        let p = pass2_policies(&["preferipv4".into()], false, true);
        assert!(p.contains(r#"Tcpip6\Parameters" /v DisabledComponents /t REG_DWORD /d 32 "#));
    }

    #[test]
    fn old_options_keep_the_client_policies() {
        let mut o: WinBakeOptions = serde_json::from_str(r#"{"iso":"x","index":1,"region":{"locale":"en-US","keyboard":"","timezone":"UTC"},"features":["rdp"]}"#).unwrap();
        o.upgrade();
        assert_eq!(o.features, ["rdp", "noencrypt", "power"]);
        let mut n: WinBakeOptions = serde_json::from_str(r#"{"iso":"x","index":1,"region":{"locale":"en-US","keyboard":"","timezone":"UTC"},"features":[],"policies":1}"#).unwrap();
        n.upgrade();
        assert!(n.features.is_empty());
    }

    fn img(edition_id: &str, installation_type: &str, build: &str) -> WimImage {
        WimImage {
            index: 1,
            name: String::new(),
            edition_id: edition_id.into(),
            installation_type: installation_type.into(),
            language: "en-US".into(),
            build: build.into(),
            version: String::new(),
            total_bytes: 0,
        }
    }

    #[test]
    fn virtual_targets_match_the_whole_token() {
        let t = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(virtual_target("MultiSession", &t(&["Enterprise", "ServerRdsh"])).as_deref(), Some("ServerRdsh"));
        assert_eq!(virtual_target("AzureEdition", &t(&["ServerDatacenterCor", "ServerTurbineCor"])).as_deref(), Some("ServerTurbineCor"));
        assert_eq!(virtual_target("AzureEdition", &t(&["ServerDatacenter"])), None);
    }

    #[test]
    fn deploy_pass_script() {
        let caps = vec!["Rsat.Dns.Tools~~~~0.0.1.0".to_owned()];
        let feats = vec!["Microsoft-Hyper-V-Tools-All".to_owned()];
        let apps = vec!["Microsoft.BingNews".to_owned(), "Not.In.Catalog".to_owned()];
        let cmd = pe_deploy_cmd(&DeployPass {
            capabilities: &caps,
            fod_root: "LanguagesAndOptionalFeatures",
            fod_marker: "LanguagesAndOptionalFeatures/x-FoD-Package~31bf3856ad364e35~amd64~~.cab",
            client_features: &feats,
            server_features: &[],
            remove_apps: &apps,
        });
        assert!(cmd.contains("if exist %%d:\\LanguagesAndOptionalFeatures\\x-FoD-Package"));
        assert!(cmd.contains("call :cap Rsat.Dns.Tools~~~~0.0.1.0\r\n"));
        assert!(cmd.contains("/Source:%FOD%\\LanguagesAndOptionalFeatures /LimitAccess"));
        assert!(cmd.contains("/FeatureName:Microsoft-Hyper-V-Tools-All /All"));
        assert!(cmd.contains("if /i \"!p:~0,19!\"==\"Microsoft.BingNews_\" goto :rm"));
        assert!(!cmd.contains("Not.In.Catalog"));
        assert!(cmd.contains("W:\\Windows\\Panther\\unattend.xml"));
        // Nothing to do but the answer file: no FoD lookup, no app listing.
        let bare = pe_deploy_cmd(&DeployPass { capabilities: &[], fod_root: "", fod_marker: "", client_features: &[], server_features: &[], remove_apps: &[] });
        assert!(!bare.contains("Get-ProvisionedAppxPackages") && !bare.contains("set FOD=%%d:"));
    }

    #[test]
    fn specialize_join_and_address() {
        let mut seed = WinVmSeed {
            name: "dc-02".into(), user: "admin".into(), password: "P@ss".into(), builtin_admin_only: false, client: false,
            mac: "bc:24:11:aa:bb:cc".into(), ip: "10.0.0.12".into(), prefix: 24, gateway: "10.0.0.1".into(), dns: vec!["10.0.0.10".into()],
            extra: vec![], manifest: serde_json::json!({}), arc_secret: None, join_secret: None, specialize: true,
            join_specialize: Some(crate::guest::DomainJoin {
                domain: "ad.example.invalid".into(), user: "AD\\joiner".into(), password: "x<y".into(), ou: "OU=Servers,DC=ad".into(),
                sudo_groups: vec![], login_groups: vec![], mode: "specialize".into(),
            }),
            product_key: String::new(),
        };
        let xml = vm_unattend(&seed, &serde_json::json!({}));
        assert!(xml.contains("<ComputerName>DC-02</ComputerName>"));
        assert!(xml.contains("<Identifier>BC-24-11-AA-BB-CC</Identifier>"));
        assert!(xml.contains("<IpAddress wcm:action=\"add\" wcm:keyValue=\"1\">10.0.0.12/24</IpAddress>"));
        assert!(xml.contains("<NextHopAddress>10.0.0.1</NextHopAddress>"));
        assert!(xml.contains("Microsoft-Windows-DNS-Client"));
        assert!(xml.contains("<Domain>AD</Domain>") && xml.contains("<Username>joiner</Username>") && xml.contains("<Password>x&lt;y</Password>"));
        assert!(xml.contains("<MachineObjectOU>OU=Servers,DC=ad</MachineObjectOU>"));
        assert!(!setupcomplete_cmd(&seed).contains("New-NetIPAddress"));
        // The seed-CD path: nothing in specialize but the name, the address set by SetupComplete.
        seed.specialize = false;
        let xml = vm_unattend(&seed, &serde_json::json!({}));
        assert!(!xml.contains("UnattendedJoin") && !xml.contains("Microsoft-Windows-TCPIP"));
        assert!(setupcomplete_cmd(&seed).contains("New-NetIPAddress"));
        // A licence key: installed and activated by SetupComplete; a malformed one is not.
        assert!(!setupcomplete_cmd(&seed).contains("slmgr"));
        seed.product_key = "abcde-12345-fghij-67890-klmno".into();
        let sc = setupcomplete_cmd(&seed);
        assert!(sc.contains("cscript //nologo %windir%\\system32\\slmgr.vbs /ipk ABCDE-12345-FGHIJ-67890-KLMNO >> C:\\Windows\\Temp\\pvs-firstboot.log 2>&1\r\n"), "{sc}");
        assert!(sc.contains("slmgr.vbs /ato"));
        seed.product_key = "abcde-12345".into();
        assert!(!setupcomplete_cmd(&seed).contains("slmgr"));
    }

    #[test]
    fn server_feature_plan() {
        let plan = plan_server_features(
            &["AD-Domain-Services".to_owned(), "ADCS-Cert-Authority".to_owned(), "RDS-Web-Access".to_owned()],
            true,
            "10.0.26100.4061",
        );
        let (dism, online) = (plan.dism, plan.online);
        assert_eq!(plan.groups.len(), 2);
        assert!(plan.groups[0].1.contains(&"DirectoryServices-DomainController".to_owned()));
        // The role, what Install-WindowsFeature adds (RSAT-AD-PowerShell), the tools, the
        // role service's role.
        for want in ["DirectoryServices-DomainController", "ActiveDirectory-PowerShell", "CertificateServices", "ADCertificateServicesRole"] {
            assert!(dism.iter().any(|d| d == want), "{want} missing from {dism:?}");
        }
        assert_eq!(online, vec!["RDS-Web-Access".to_owned()]);
        let p = plan_server_features(&["DNS".to_owned()], true, "20348");
        assert!(p.dism.is_empty() && p.online == vec!["DNS".to_owned()]);
    }

    #[test]
    fn virtual_gold_ids() {
        let pro = img("Professional", "Client", "26200");
        assert!(virtual_edition_fits("MultiSession", &pro));
        assert_eq!(gold_image_id(&pro, "MultiSession"), "w11-enterprise-ms");
        let core = img("ServerDatacenter", "Server Core", "26100");
        assert!(virtual_edition_fits("AzureEdition", &core));
        assert_eq!(gold_image_id(&core, "AzureEdition"), "ws2025-datacenter-az-core");
        assert_eq!(gold_image_id(&core, ""), "ws2025-datacenter-core");
        assert!(!virtual_edition_fits("AzureEdition", &img("ServerDatacenter", "Server", "20348")));
    }
}
