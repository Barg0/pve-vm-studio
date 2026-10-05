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
    /// What it does, for the (i) beside the toggle - what src/linux.rs actually bakes.
    pub tip: &'static str,
}

pub static FEATURES: &[Feature] = &[
    Feature {
        id: "aliases",
        label: "Shell aliases",
        images: &[],
        tip: "The same aliases on every distribution: ll (ls -la), la (ls -A), .. and cd.. (cd ..), and colour for ls and grep. In /etc/profile.d, loaded by every new user's .bashrc.",
    },
    Feature {
        id: "prompt",
        label: "Coloured prompt",
        images: &[],
        tip: "A short bash prompt: the current folder in bold blue, then a > that is green after a command that worked and red after one that failed. For every new user (/etc/skel/.bashrc).",
    },
    Feature {
        id: "fastfetch",
        label: "fastfetch at login",
        images: &[],
        tip: "Installs fastfetch and shows it when an interactive shell starts: the distribution's logo next to OS, kernel, uptime, packages, locale, CPU, memory and disk. Only in interactive shells, so scp and scripts are not disturbed.",
    },
    Feature {
        id: "pskeys",
        label: "PowerShell-style keys",
        images: &[],
        tip: "Readline keys as PowerShell has them: Ctrl+Left and Ctrl+Right jump a word, Ctrl+Backspace and Ctrl+Delete delete one, Home and End go to the start and end of the line. Added to /etc/inputrc for every user.",
    },
    Feature {
        id: "quietmotd",
        label: "Quiet SSH login",
        images: &["ubuntu2604", "ubuntu2404", "debian13", "debian12", "rocky10", "rocky9"],
        tip: "No message of the day at SSH login: a .hushlogin for root and every new user, and on Ubuntu the news, ESM, Landscape, update and help messages switched off.",
    },
    Feature {
        id: "yay",
        label: "yay (AUR helper)",
        images: &["arch"],
        tip: "Builds and installs yay-bin from the AUR, so packages from the Arch User Repository install with yay -S.",
    },
    Feature {
        id: "ilovecandy",
        label: "Pac-Man progress bar and colour",
        images: &["arch"],
        tip: "pacman's ILoveCandy and Color options: a Pac-Man eating dots as the progress bar, and coloured output.",
    },
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

/// Country package mirrors for the apt distributions (New-Vhdx's Get-AptMirrorCatalog): the
/// stock cloud image points at archive.ubuntu.com / deb.debian.org, and a badly routed one
/// turns a five-minute upgrade into a long wait. Every host was probed on 2026-09-22; an
/// empty one means that distribution has no country mirror there and keeps its default.
/// Ubuntu and Debian name them differently: gb.archive.ubuntu.com but ftp.uk.debian.org.
#[derive(Debug, Clone, Copy, serde::Serialize)]
pub struct AptMirror {
    pub code: &'static str,
    pub name: &'static str,
    pub ubuntu: &'static str,
    pub debian: &'static str,
}

macro_rules! m {
    ($c:expr, $n:expr, $u:expr, $d:expr) => {
        AptMirror { code: $c, name: $n, ubuntu: $u, debian: $d }
    };
}

pub static APT_MIRRORS: &[AptMirror] = &[
    m!("ar", "Argentina", "ar.archive.ubuntu.com", ""),
    m!("au", "Australia", "au.archive.ubuntu.com", "ftp.au.debian.org"),
    m!("at", "Austria", "at.archive.ubuntu.com", "ftp.at.debian.org"),
    m!("be", "Belgium", "be.archive.ubuntu.com", "ftp.be.debian.org"),
    m!("br", "Brazil", "br.archive.ubuntu.com", "ftp.br.debian.org"),
    m!("bg", "Bulgaria", "bg.archive.ubuntu.com", "ftp.bg.debian.org"),
    m!("ca", "Canada", "ca.archive.ubuntu.com", "ftp.ca.debian.org"),
    m!("cl", "Chile", "cl.archive.ubuntu.com", "ftp.cl.debian.org"),
    m!("cn", "China", "cn.archive.ubuntu.com", "ftp.cn.debian.org"),
    m!("hr", "Croatia", "hr.archive.ubuntu.com", "ftp.hr.debian.org"),
    m!("cz", "Czechia", "cz.archive.ubuntu.com", "ftp.cz.debian.org"),
    m!("dk", "Denmark", "", "ftp.dk.debian.org"),
    m!("ee", "Estonia", "ee.archive.ubuntu.com", "ftp.ee.debian.org"),
    m!("fi", "Finland", "fi.archive.ubuntu.com", "ftp.fi.debian.org"),
    m!("fr", "France", "fr.archive.ubuntu.com", "ftp.fr.debian.org"),
    m!("de", "Germany", "de.archive.ubuntu.com", "ftp.de.debian.org"),
    m!("gr", "Greece", "gr.archive.ubuntu.com", "ftp.gr.debian.org"),
    m!("hk", "Hong Kong", "hk.archive.ubuntu.com", "ftp.hk.debian.org"),
    m!("hu", "Hungary", "hu.archive.ubuntu.com", "ftp.hu.debian.org"),
    m!("is", "Iceland", "is.archive.ubuntu.com", "ftp.is.debian.org"),
    m!("in", "India", "in.archive.ubuntu.com", ""),
    m!("id", "Indonesia", "id.archive.ubuntu.com", ""),
    m!("ie", "Ireland", "ie.archive.ubuntu.com", "ftp.ie.debian.org"),
    m!("il", "Israel", "il.archive.ubuntu.com", ""),
    m!("it", "Italy", "it.archive.ubuntu.com", "ftp.it.debian.org"),
    m!("jp", "Japan", "jp.archive.ubuntu.com", "ftp.jp.debian.org"),
    m!("lv", "Latvia", "lv.archive.ubuntu.com", ""),
    m!("lt", "Lithuania", "lt.archive.ubuntu.com", "ftp.lt.debian.org"),
    m!("mx", "Mexico", "mx.archive.ubuntu.com", "ftp.mx.debian.org"),
    m!("nl", "Netherlands", "nl.archive.ubuntu.com", "ftp.nl.debian.org"),
    m!("nz", "New Zealand", "nz.archive.ubuntu.com", "ftp.nz.debian.org"),
    m!("no", "Norway", "no.archive.ubuntu.com", "ftp.no.debian.org"),
    m!("pl", "Poland", "pl.archive.ubuntu.com", "ftp.pl.debian.org"),
    m!("pt", "Portugal", "", "ftp.pt.debian.org"),
    m!("ro", "Romania", "ro.archive.ubuntu.com", "ftp.ro.debian.org"),
    m!("ru", "Russia", "ru.archive.ubuntu.com", "ftp.ru.debian.org"),
    m!("sg", "Singapore", "sg.archive.ubuntu.com", "ftp.sg.debian.org"),
    m!("sk", "Slovakia", "sk.archive.ubuntu.com", "ftp.sk.debian.org"),
    m!("si", "Slovenia", "si.archive.ubuntu.com", "ftp.si.debian.org"),
    m!("za", "South Africa", "za.archive.ubuntu.com", ""),
    m!("kr", "South Korea", "kr.archive.ubuntu.com", "ftp.kr.debian.org"),
    m!("es", "Spain", "es.archive.ubuntu.com", "ftp.es.debian.org"),
    m!("se", "Sweden", "se.archive.ubuntu.com", "ftp.se.debian.org"),
    m!("ch", "Switzerland", "ch.archive.ubuntu.com", "ftp.ch.debian.org"),
    m!("tw", "Taiwan", "tw.archive.ubuntu.com", "ftp.tw.debian.org"),
    m!("th", "Thailand", "th.archive.ubuntu.com", "ftp.th.debian.org"),
    m!("tr", "Turkey", "tr.archive.ubuntu.com", "ftp.tr.debian.org"),
    m!("ua", "Ukraine", "ua.archive.ubuntu.com", "ftp.ua.debian.org"),
    m!("gb", "United Kingdom", "gb.archive.ubuntu.com", "ftp.uk.debian.org"),
    m!("us", "United States", "us.archive.ubuntu.com", "ftp.us.debian.org"),
    m!("vn", "Vietnam", "vn.archive.ubuntu.com", ""),
];

/// The apt URI for a distribution in a country, None when there is none - the image then
/// keeps its own default rather than a host name that does not resolve.
pub fn apt_mirror_uri(distro: &str, code: &str) -> Option<String> {
    let m = APT_MIRRORS.iter().find(|m| m.code == code)?;
    match distro {
        "ubuntu" if !m.ubuntu.is_empty() => Some(format!("http://{}/ubuntu/", m.ubuntu)),
        "debian" if !m.debian.is_empty() => Some(format!("http://{}/debian/", m.debian)),
        _ => None,
    }
}

/// Where security updates come from once the primary mirror moved. It has to be said
/// whenever the primary is: cloud-init points security at the primary otherwise, and Debian's
/// country mirrors carry no -security suite (apt-get update exits 100, and the upgrade runs
/// without security updates). These are the distributions' own hosts.
pub fn apt_security_uri(distro: &str) -> Option<&'static str> {
    match distro {
        "ubuntu" => Some("http://security.ubuntu.com/ubuntu/"),
        "debian" => Some("https://deb.debian.org/debian-security/"),
        _ => None,
    }
}

/// The primary and security keys of a cloud-init apt block, unindented. Two callers - the
/// bake's own user-data and the drop-in that carries the mirror into every VM - and the two
/// must never disagree.
pub fn apt_mirror_yaml(distro: &str, uri: &str) -> Vec<String> {
    let mut y = vec!["primary:".to_owned(), "  - arches: [default]".to_owned(), format!("    uri: {uri}")];
    if let Some(s) = apt_security_uri(distro) {
        y.extend(["security:".to_owned(), "  - arches: [default]".to_owned(), format!("    uri: {s}")]);
    }
    y
}
