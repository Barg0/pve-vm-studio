//! What can be baked: the Linux images (the same fourteen as Get-LinuxImageCatalog in
//! New-Vhdx.ps1 and kiln.sh, with the same URLs - the reasons each URL is the one it is
//! are written up there), the optional gold features, and the region data.

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct LinuxImage {
    pub id: &'static str,
    pub distro: &'static str,
    /// debian | rhel | suse | arch - decides package manager, admin group, network files.
    pub family: &'static str,
    pub version: &'static str,
    pub name: &'static str,
    pub url: &'static str,
    pub checksum_url: &'static str,
    pub algorithm: &'static str,
    /// For images whose checksum is published only on a web page (Oracle).
    pub pinned_checksum: Option<&'static str>,
    pub disk_gb: u32,
    pub packages: &'static [&'static str],
    /// Boots with Secure Boot on (a Microsoft-signed shim). Arch has none.
    pub secure_boot: bool,
    /// The Hyper-V studio's "noDomainJoin" / "noAzureArc" flags, carried for the designer.
    pub domain_join: bool,
    pub azure_arc: bool,
}

const QGA: &[&str] = &["qemu-guest-agent"];
/// Oracle keeps kernel-uek-modules, as on Hyper-V: fwupd asks for i2c_dev on every boot
/// and the template only has UEK's -core half.
const QGA_UEK: &[&str] = &["qemu-guest-agent", "kernel-uek-modules"];

macro_rules! img {
    ($id:expr, $distro:expr, $family:expr, $ver:expr, $name:expr, $url:expr, $sum:expr, $algo:expr,
     $pinned:expr, $disk:expr, $pk:expr, sb=$sb:expr, dj=$dj:expr, arc=$arc:expr) => {
        LinuxImage {
            id: $id, distro: $distro, family: $family, version: $ver, name: $name, url: $url,
            checksum_url: $sum, algorithm: $algo, pinned_checksum: $pinned, disk_gb: $disk,
            packages: $pk, secure_boot: $sb, domain_join: $dj, azure_arc: $arc,
        }
    };
}

pub static LINUX: &[LinuxImage] = &[
    img!("ubuntu2604", "ubuntu", "debian", "26.04", "Ubuntu 26.04 LTS (Resolute)",
        "https://cloud-images.ubuntu.com/releases/26.04/release/ubuntu-26.04-server-cloudimg-amd64.img",
        "https://cloud-images.ubuntu.com/releases/26.04/release/SHA256SUMS", "sha256", None, 32, QGA,
        sb = true, dj = true, arc = true),
    img!("ubuntu2404", "ubuntu", "debian", "24.04", "Ubuntu 24.04 LTS (Noble)",
        "https://cloud-images.ubuntu.com/releases/24.04/release/ubuntu-24.04-server-cloudimg-amd64.img",
        "https://cloud-images.ubuntu.com/releases/24.04/release/SHA256SUMS", "sha256", None, 32, QGA,
        sb = true, dj = true, arc = true),
    img!("debian13", "debian", "debian", "13", "Debian 13 (Trixie)",
        "https://cloud.debian.org/images/cloud/trixie/latest/debian-13-genericcloud-amd64.qcow2",
        "https://cloud.debian.org/images/cloud/trixie/latest/SHA512SUMS", "sha512", None, 32, QGA,
        sb = true, dj = true, arc = true),
    img!("debian12", "debian", "debian", "12", "Debian 12 (Bookworm)",
        "https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-genericcloud-amd64.qcow2",
        "https://cloud.debian.org/images/cloud/bookworm/latest/SHA512SUMS", "sha512", None, 32, QGA,
        sb = true, dj = true, arc = false),
    img!("fedora44", "fedora", "rhel", "44", "Fedora 44 (Cloud Base)",
        "https://download.fedoraproject.org/pub/fedora/linux/releases/44/Cloud/x86_64/images/Fedora-Cloud-Base-Generic-44-1.7.x86_64.qcow2",
        "https://download.fedoraproject.org/pub/fedora/linux/releases/44/Cloud/x86_64/images/Fedora-Cloud-44-1.7-x86_64-CHECKSUM",
        "sha256", None, 32, QGA, sb = true, dj = true, arc = false),
    img!("fedora43", "fedora", "rhel", "43", "Fedora 43 (Cloud Base)",
        "https://download.fedoraproject.org/pub/fedora/linux/releases/43/Cloud/x86_64/images/Fedora-Cloud-Base-Generic-43-1.6.x86_64.qcow2",
        "https://download.fedoraproject.org/pub/fedora/linux/releases/43/Cloud/x86_64/images/Fedora-Cloud-43-1.6-x86_64-CHECKSUM",
        "sha256", None, 32, QGA, sb = true, dj = true, arc = false),
    img!("rocky10", "rocky", "rhel", "10", "Rocky Linux 10 (GenericCloud)",
        "https://dl.rockylinux.org/pub/rocky/10/images/x86_64/Rocky-10-GenericCloud-Base.latest.x86_64.qcow2",
        "https://dl.rockylinux.org/pub/rocky/10/images/x86_64/Rocky-10-GenericCloud-Base.latest.x86_64.qcow2.CHECKSUM",
        "sha256", None, 32, QGA, sb = true, dj = true, arc = true),
    img!("rocky9", "rocky", "rhel", "9", "Rocky Linux 9 (GenericCloud)",
        "https://dl.rockylinux.org/pub/rocky/9/images/x86_64/Rocky-9-GenericCloud-Base.latest.x86_64.qcow2",
        "https://dl.rockylinux.org/pub/rocky/9/images/x86_64/Rocky-9-GenericCloud-Base.latest.x86_64.qcow2.CHECKSUM",
        "sha256", None, 32, QGA, sb = true, dj = true, arc = true),
    img!("alma10", "alma", "rhel", "10", "AlmaLinux 10 (GenericCloud)",
        "https://repo.almalinux.org/almalinux/10/cloud/x86_64/images/AlmaLinux-10-GenericCloud-latest.x86_64.qcow2",
        "https://repo.almalinux.org/almalinux/10/cloud/x86_64/images/CHECKSUM", "sha256", None, 32, QGA,
        sb = true, dj = true, arc = true),
    img!("alma9", "alma", "rhel", "9", "AlmaLinux 9 (GenericCloud)",
        "https://repo.almalinux.org/almalinux/9/cloud/x86_64/images/AlmaLinux-9-GenericCloud-latest.x86_64.qcow2",
        "https://repo.almalinux.org/almalinux/9/cloud/x86_64/images/CHECKSUM", "sha256", None, 32, QGA,
        sb = true, dj = true, arc = true),
    img!("oracle10", "oracle", "rhel", "10", "Oracle Linux 10 (KVM template)",
        "https://yum.oracle.com/templates/OracleLinux/OL10/u1/x86_64/OL10U1_x86_64-kvm-b291.qcow2",
        "https://yum.oracle.com/oracle-linux-templates.html", "sha256",
        Some("8e59326c4bf7cfa58a6cac404db8ed583fe3a5f4c460e2b73c64988785bb4f0f"), 40, QGA_UEK,
        sb = true, dj = true, arc = true),
    img!("oracle9", "oracle", "rhel", "9", "Oracle Linux 9 (KVM template)",
        "https://yum.oracle.com/templates/OracleLinux/OL9/u8/x86_64/OL9U8_x86_64-kvm-b293.qcow2",
        "https://yum.oracle.com/oracle-linux-templates.html", "sha256",
        Some("b12103391327abee8090686759c0d62dac9a7af2bf0f45fdf6b0d085a0fbb52b"), 40, QGA_UEK,
        sb = true, dj = true, arc = true),
    img!("leap16", "opensuse", "suse", "16.0", "openSUSE Leap 16.0 (Minimal VM, Cloud)",
        "https://download.opensuse.org/distribution/leap/16.0/appliances/Leap-16.0-Minimal-VM.x86_64-Cloud.qcow2",
        "https://download.opensuse.org/distribution/leap/16.0/appliances/Leap-16.0-Minimal-VM.x86_64-Cloud.qcow2.sha256",
        "sha256", None, 32, QGA, sb = true, dj = true, arc = false),
    img!("arch", "arch", "arch", "rolling", "Arch Linux (rolling)",
        "https://geo.mirror.pkgbuild.com/images/latest/Arch-Linux-x86_64-cloudimg.qcow2",
        "https://geo.mirror.pkgbuild.com/images/latest/Arch-Linux-x86_64-cloudimg.qcow2.SHA256",
        "sha256", None, 32, QGA, sb = false, dj = false, arc = false),
];

pub fn linux(id: &str) -> Option<&'static LinuxImage> {
    LINUX.iter().find(|i| i.id == id)
}

/// The optional gold features - Get-LinuxGoldFeatureCatalog, same ids, same labels.
#[derive(Debug, Clone, Serialize)]
pub struct Feature {
    pub id: &'static str,
    pub label: &'static str,
    /// Images it applies to; empty = all.
    pub images: &'static [&'static str],
}

pub static FEATURES: &[Feature] = &[
    Feature { id: "aliases", label: "Shell aliases", images: &[] },
    Feature { id: "prompt", label: "Coloured prompt", images: &[] },
    Feature { id: "fastfetch", label: "fastfetch at login", images: &[] },
    Feature {
        id: "quietmotd",
        label: "Quiet SSH login",
        images: &["ubuntu2604", "ubuntu2404", "debian13", "debian12", "rocky10", "rocky9"],
    },
    Feature { id: "yay", label: "yay (AUR helper)", images: &["arch"] },
    Feature { id: "ilovecandy", label: "Pac-Man progress bar and colour", images: &["arch"] },
];

pub fn feature_applies(feature: &str, image: &str) -> bool {
    FEATURES
        .iter()
        .find(|f| f.id == feature)
        .is_some_and(|f| f.images.is_empty() || f.images.contains(&image))
}

// ---- region data (from HyperV-Scripts/data) ----

pub static LINUX_REGION: &str = include_str!("../data/linux-region.json");
pub static TIMEZONES: &str = include_str!("../data/linux-timezones.json");
pub static LOCALES: &str = include_str!("../data/locales.json");

/// "de-DE" -> "de_DE.UTF-8"
pub fn posix_locale(tag: &str) -> String {
    format!("{}.UTF-8", tag.replace('-', "_"))
}

/// The keyboard a locale tag maps to: (XKB layout, XKB variant, console keymap candidates).
/// A tag not in the table falls back to its region part, lower case (de-DE -> de).
pub fn keyboard_for(tag: &str) -> (String, String, Vec<String>) {
    let table: serde_json::Value = serde_json::from_str(LINUX_REGION).unwrap_or_default();
    if let Some(k) = table["keyboards"].get(tag) {
        let x11 = k["x11"].as_str().unwrap_or("us").to_owned();
        let variant = k["x11Variant"].as_str().unwrap_or("").to_owned();
        let console = k["console"]
            .as_array()
            .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_owned)).collect())
            .unwrap_or_else(|| vec![x11.clone()]);
        return (x11, variant, console);
    }
    let region = tag.rsplit('-').next().unwrap_or("us").to_lowercase();
    (region.clone(), String::new(), vec![region])
}
