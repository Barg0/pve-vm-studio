//! Cloud-init for Linux golds and VMs - Get-BakeUserData and Get-CloudInitUserData from
//! the Hyper-V studio, by way of kiln.sh, adapted to PVE:
//!
//! - The bake reports through a file in /run that the studio reads over the guest agent
//!   (agent/file-read), not a serial log - the API has no serial log to read. /run is
//!   gone after the shutdown, so the report never reaches the gold.
//! - The bake does not power itself off: the studio reads the report first, then shuts
//!   the VM down through the API.

use serde::{Deserialize, Serialize};

use crate::catalog::{self, LinuxImage};

pub const REPORT: &str = "/run/pvs-bake.report";

/// What a bake is asked to put on the gold.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BakeOptions {
    #[serde(default)]
    pub features: Vec<String>,
    #[serde(default = "yes")]
    pub updates: bool,
    /// None keeps the image's own region (en_US, UTC, us keyboard as shipped).
    pub region: Option<Region>,
    /// The system disk in GiB (New-Vhdx's -VhdSizeGB); None = the catalog's size.
    #[serde(default)]
    pub disk_gb: Option<u32>,
    /// This bake's disk storage - its provisioning is the gold's thin or thick; None = the
    /// bake settings' storage.
    #[serde(default)]
    pub disk_storage: Option<String>,
    /// CIS hardening (docs/cis-benchmark.md); None or level 0 = off.
    #[serde(default)]
    pub cis: Option<crate::cis::CisOptions>,
}

impl BakeOptions {
    /// The CIS level this bake applies - 0 when off or the image has no benchmark.
    pub fn cis_level(&self, image: &str) -> u8 {
        match (&self.cis, crate::cis::benchmark_for(image)) {
            (Some(c), Some(_)) if (1..=2).contains(&c.level) => c.level,
            _ => 0,
        }
    }
}

/// The seed disk's slot on a Linux VM: virtio-scsi, which every cloud kernel has (Debian 12's
/// has no AHCI, so no SATA); the last SCSI slot, clear of the data disks (scsi1...).
pub const SEED_SLOT: &str = "scsi30";

/// Where the CIS bundle lives in the gold.
pub const CIS_LIB: &str = "/usr/local/lib/pvs-cis";
/// A CIS Level 2 gold's root partition; the rest of the disk is the LVM volumes.
pub const CIS_ROOT_GB: u32 = 12;

fn yes() -> bool {
    true
}

/// Locale tags as the studio's region data has them (de-DE), and an IANA time zone.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Region {
    pub language: String,
    #[serde(default)]
    pub format: String,
    #[serde(default)]
    pub keyboard: String,
    #[serde(default)]
    pub timezone: String,
}

/// The cloud-config being written, line by line.
struct Ud(Vec<String>);

impl Ud {
    fn line(&mut self, l: impl Into<String>) {
        self.0.push(l.into());
    }
    fn lines(&mut self, ls: &[&str]) {
        self.0.extend(ls.iter().map(|l| l.to_string()));
    }
    /// A shell command for runcmd/bootcmd.
    fn cmd(&mut self, c: &str) {
        self.0.push(format!("  - [ sh, -c, {} ]", sq(c)));
    }
    /// A command whose output is part of the bake's report.
    fn report(&mut self, c: &str) {
        self.cmd(&format!("{{ {c}; }} 2>&1 | tee -a {REPORT}"));
    }
    fn text(self) -> String {
        let mut s = self.0.join("\n");
        s.push('\n');
        s
    }
}

/// YAML single-quoted scalar.
pub fn sq(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

pub fn admin_group(family: &str) -> &'static str {
    if family == "debian" { "sudo" } else { "wheel" }
}

fn package_probe(family: &str, pkgs: &str) -> String {
    let test = match family {
        "debian" => r#"dpkg -s $p 2>/dev/null | grep -q "^Status: install ok installed""#,
        "arch" => "pacman -Q $p >/dev/null 2>&1",
        _ => "rpm -q $p >/dev/null 2>&1",
    };
    format!("for p in {pkgs}; do if {test}; then echo BAKE-PKG $p ok; else echo BAKE-PKG $p MISSING; fi; done")
}

/// The kernel the GOLD will boot, which after an upgrade is not the one the bake runs.
fn kernel_report(family: &str) -> &'static str {
    match family {
        "arch" => r#"k=$(pacman -Q linux 2>/dev/null | cut -d" " -f2); [ -n "$k" ] || k=$(uname -r); echo BAKE-KERNEL $k"#,
        "rhel" => r#"k=$(grubby --default-kernel 2>/dev/null); case "$k" in */vmlinuz-?*) k=${k##*/vmlinuz-} ;; *) k=$(uname -r) ;; esac; echo BAKE-KERNEL $k"#,
        _ => r#"v=$(readlink /boot/vmlinuz 2>/dev/null); case "$v" in vmlinuz-?*) v=${v#vmlinuz-} ;; *) v=$(uname -r) ;; esac; echo BAKE-KERNEL $v"#,
    }
}

/// What cloud-init rendered for the bake's network, which must not reach a VM.
fn network_artifacts(family: &str) -> &'static [&'static str] {
    match family {
        "arch" => &["/etc/netplan/50-cloud-init.yaml", "/etc/systemd/network/10-cloud-init-*.network"],
        "suse" => &[
            "/etc/NetworkManager/system-connections/cloud-init-*.nmconnection",
            "/etc/NetworkManager/conf.d/99-cloud-init.conf",
        ],
        "rhel" => &[
            "/etc/NetworkManager/system-connections/cloud-init-*.nmconnection",
            "/etc/NetworkManager/conf.d/99-cloud-init.conf",
            "/etc/sysconfig/network-scripts/ifcfg-*",
        ],
        _ => &["/etc/netplan/50-cloud-init.yaml"],
    }
}

/// The package a language needs to exist on the gold, or nothing. Ubuntu splits
/// translations into language-pack-*, the RHEL family has no locale-gen and needs the
/// glibc langpack, openSUSE has one package for all of them, Debian and Arch generate.
fn language_pack(img: &LinuxImage, posix: &str) -> Option<String> {
    let lang = posix.split(['_', '.']).next().unwrap_or("");
    if lang.is_empty() || matches!(lang, "en" | "C" | "POSIX") {
        return None;
    }
    match img.family {
        "rhel" => Some(format!("glibc-langpack-{lang}")),
        "suse" => Some("glibc-locale".into()),
        "debian" if img.distro == "ubuntu" => Some(format!("language-pack-{lang}")),
        _ => None,
    }
}

/// fastfetch: the title takes the logo's colour, and the logo is padded down to sit
/// centred on the box - the heights are the ones measured for New-Vhdx.ps1.
fn title_color(distro: &str) -> &'static str {
    match distro {
        "ubuntu" | "debian" | "oracle" => "1;31",
        "fedora" | "alma" => "1;34",
        "rocky" | "opensuse" => "1;32",
        "arch" => "1;36",
        _ => "1",
    }
}

fn logo_padding(distro: &str) -> u8 {
    match distro {
        "debian" => 3,
        "oracle" => 6,
        "ubuntu" | "alma" => 1,
        _ => 2,
    }
}

pub fn bake_user_data(img: &LinuxImage, opt: &BakeOptions) -> String {
    let has = |f: &str| opt.features.iter().any(|x| x == f) && catalog::feature_applies(f, img.id);
    let region = opt.region.as_ref().filter(|r| !r.language.is_empty());
    let (distro, family) = (img.distro, img.family);

    let lang = region.map(|r| catalog::posix_locale(&r.language));
    let fmt = region.map(|r| catalog::posix_locale(if r.format.is_empty() { &r.language } else { &r.format }));
    let keyboard = region.filter(|r| !r.keyboard.is_empty()).map(|r| catalog::keyboard_for(&r.keyboard));

    // Same list-building as Get-BakeUserData: the image's own packages, what the region
    // needs, what the ticked features need - one install, one probe.
    let mut packages: Vec<String> = img.packages.iter().map(|p| p.to_string()).collect();
    if region.is_some() {
        // Debian's genericcloud image has no keyboard machinery at all, so the keymap
        // would silently do nothing without these.
        if distro == "debian" && keyboard.is_some() {
            packages.extend(["kbd", "console-setup", "keyboard-configuration"].map(String::from));
        }
        for l in [&lang, &fmt].into_iter().flatten() {
            packages.extend(language_pack(img, l));
        }
    }
    // Debian 12 has fastfetch in no repository it can use - it comes from the GitHub
    // release in runcmd, and curl with it.
    let ff_github = has("fastfetch") && img.id == "debian12";
    if has("fastfetch") {
        packages.push(if ff_github { "curl" } else { "fastfetch" }.into());
    }
    if has("yay") {
        packages.extend(["git", "base-devel"].map(String::from));
    }
    let mut seen = std::collections::HashSet::new();
    packages.retain(|p| seen.insert(p.clone()));

    let mut ud = Ud(vec!["#cloud-config".into()]);

    // A console login for a bake that stalls (PVE console of the bake VM). Deleted at the
    // end of the bake - cloud-init clean does not remove users.
    ud.line("users:");
    ud.line("  - name: bake");
    ud.line(format!("    groups: [{}]", admin_group(family)));
    ud.lines(&[
        "    shell: /bin/bash",
        "    sudo: 'ALL=(ALL) NOPASSWD:ALL'",
        "    lock_passwd: false",
        "chpasswd:",
        "  expire: false",
        "  users:",
        "    - name: bake",
        "      password: 'bake'",
        "      type: text",
    ]);

    if family == "debian" {
        // Bounded apt timeouts, so a dead mirror costs minutes, not an hour.
        ud.lines(&[
            "apt:",
            "  conf: |",
            "    Acquire::http::Timeout \"20\";",
            "    Acquire::https::Timeout \"20\";",
            "    Acquire::Retries \"2\";",
        ]);
        // noble's archive never carried fastfetch; its author's PPA does.
        if has("fastfetch") && img.id == "ubuntu2404" {
            ud.lines(&["  sources:", "    fastfetch:", "      source: 'ppa:zhangsongcui3371/fastfetch'"]);
        }
    }

    ud.line("package_update: true");
    if opt.updates {
        ud.line("package_upgrade: true");
    }
    if !packages.is_empty() {
        ud.line("packages:");
        for p in &packages {
            ud.line(format!("  - {}", sq(p)));
        }
    }

    // Level 2 keeps cloud-init's growpart: the bake disk is ROOT_GB on the first boot, so the
    // root grows to ROOT_GB there - the image's own root (Ubuntu: 2.3 GB) is too small for the
    // upgrade. /etc/growroot-disabled (runcmd) stops it on the second boot, after the studio
    // grew the disk; the agent, which triggers that, answers only after cloud-init's init stage.
    let cis = opt.cis_level(img.id);

    // bootcmd: what has to be settled before the package module, which is the first
    // thing in the final stage.
    let mut boot: Vec<String> = Vec::new();
    // The guest agent before anything else: the studio follows the bake through it, and
    // images that do not ship one (Debian, Ubuntu, Arch) would otherwise only get it
    // with the package run - after the part worth following.
    // `systemctl start` must not wait here: the agent's unit is ordered after
    // cloud-init.service, which is the one running bootcmd - a plain start deadlocks. And
    // Debian's postinst would start it the same way, so policy-rc.d holds that off.
    boot.push(
        match family {
            "debian" => "if ! command -v qemu-ga >/dev/null; then printf '#!/bin/sh\\nexit 101\\n' > /usr/sbin/policy-rc.d; chmod 0755 /usr/sbin/policy-rc.d; apt-get update -q && DEBIAN_FRONTEND=noninteractive apt-get install -y -q qemu-guest-agent; rm -f /usr/sbin/policy-rc.d; fi; systemctl start --no-block qemu-guest-agent || true",
            "arch" => "pacman -Q qemu-guest-agent >/dev/null 2>&1 || pacman -Sy --noconfirm qemu-guest-agent; systemctl start --no-block qemu-guest-agent || true",
            "suse" => "rpm -q qemu-guest-agent >/dev/null 2>&1 || zypper -n install qemu-guest-agent; systemctl start --no-block qemu-guest-agent || true",
            _ => "rpm -q qemu-guest-agent >/dev/null 2>&1 || dnf -y install qemu-guest-agent; systemctl start --no-block qemu-guest-agent || true",
        }
        .into(),
    );
    if family == "rhel" {
        // The RHEL family ships the agent with file access and exec switched off
        // (/etc/sysconfig/qemu-ga). Opened here, at boot, so the studio can follow the
        // bake from the start - and put back as the distribution had it before the gold
        // is sealed.
        boot.push("if [ -f /etc/sysconfig/qemu-ga ] && [ ! -f /run/pvs-qemu-ga.orig ]; then cp -a /etc/sysconfig/qemu-ga /run/pvs-qemu-ga.orig; sed -i -e 's/^BLOCK_RPCS=.*/BLOCK_RPCS=/' -e 's/^FILTER_RPC_ARGS=.*/FILTER_RPC_ARGS=/' /etc/sysconfig/qemu-ga; systemctl restart --no-block qemu-guest-agent 2>/dev/null || true; fi".into());
    }
    if family == "suse" {
        // Hyper-V Studio's Leap finding: a getty taking ttyS0 hangs the port up and took
        // cloud-init's final stage down with it mid-zypper. Off for this boot only.
        boot.push("systemctl mask --runtime --now serial-getty@ttyS0.service 2>/dev/null || true".into());
    }
    if family == "rhel" || family == "suse" {
        // SELinux (EL; openSUSE Leap 16 enforcing too) confines the agent to its own files;
        // this boolean lets it read the report and cloud-init's log. Runtime only (no -P):
        // gone at the next boot, so the gold keeps the distribution's policy.
        boot.push("command -v setsebool >/dev/null && setsebool virt_qemu_ga_read_nonsecurity_files on 2>/dev/null || true".into());
    }
    if family == "rhel" {
        boot.push(r#"printf "\ntimeout=20\nretries=2\n" >> /etc/dnf/dnf.conf"#.into());
    }
    if cis > 0 {
        // The CIS bundle from the seed disk (pvs-cis/) into the image - once; bootcmd runs
        // on every boot.
        boot.push(format!(
            "if [ ! -x {CIS_LIB}/pvs-cis ]; then mkdir -p /run/pvs-seed && mount -o ro /dev/disk/by-label/CIDATA /run/pvs-seed && rm -rf {CIS_LIB} && cp -r /run/pvs-seed/pvs-cis {CIS_LIB}; umount /run/pvs-seed; chown -R root:root {CIS_LIB}; find {CIS_LIB} -type d -exec chmod 0755 {{}} +; find {CIS_LIB} -type f -exec chmod 0644 {{}} +; chmod 0755 {CIS_LIB}/pvs-cis {CIS_LIB}/layout.sh; ln -sf {CIS_LIB}/pvs-cis /usr/local/sbin/pvs-cis; mkdir -p /etc/pvs-cis; chmod 0700 /etc/pvs-cis; mv {CIS_LIB}/level {CIS_LIB}/exceptions /etc/pvs-cis/; echo BAKE-CIS-BUNDLE $(ls {CIS_LIB}/*/bench.conf | wc -l) benchmark >> /run/pvs-cis-boot.log; fi"
        ));
    }
    if distro == "oracle" {
        // Root is an LV, which growpart skips outright - partition, PV and LV grown here.
        boot.push(r#"[ -e /etc/growroot-disabled ] || root=$(findmnt -no SOURCE /); case "${root:-}" in /dev/mapper/*) pv=$(pvs --noheadings -o pv_name 2>/dev/null | head -n1 | tr -d " "); part=$(basename "$(readlink -f "$pv")"); disk=$(lsblk -dno PKNAME "/dev/$part"); num=$(cat "/sys/class/block/$part/partition"); growpart "/dev/$disk" "$num"; pvresize "$pv" && lvextend -r -l +100%FREE "$root"; echo BAKE-LVM-ROOT $(lvs --noheadings -o lv_size "$root" 2>/dev/null | tr -d " ") >> /run/pvs-bake.report ;; esac"#.into());
    }
    // fastfetch lives in EPEL on the EL rebuilds, and EPEL has to exist before the
    // package module runs.
    if has("fastfetch") {
        match distro {
            "rocky" | "alma" => boot.push("dnf install -y epel-release".into()),
            "oracle" => boot.push(format!("dnf install -y oracle-epel-release-el{}", img.version)),
            _ => {}
        }
    }
    if !boot.is_empty() {
        ud.line("bootcmd:");
        for b in &boot {
            ud.cmd(b);
        }
    }

    if let Some(r) = region.filter(|r| !r.timezone.is_empty()) {
        ud.line(format!("timezone: {}", r.timezone));
    }

    // One write_files key for all of them - a second one is a YAML error, not a merge.
    if region.is_some() || has("aliases") || has("fastfetch") || has("prompt") || has("pskeys") {
        ud.line("write_files:");
    }
    if region.is_some() {
        // The locale is the gold's; cloud-init's locale module would re-apply its own
        // idea of it on every VM's first boot.
        ud.lines(&[
            "  - path: /etc/cloud/cloud.cfg.d/91-pve-vm-studio-locale.cfg",
            "    permissions: '0644'",
            "    content: |",
            "      # Baked by PVE VM Studio: the locale is the gold's; cloud-init leaves it alone.",
            "      locale: 'false'",
        ]);
    }
    if has("aliases") {
        ud.lines(&[
            "  - path: /etc/profile.d/99-pve-vm-studio-aliases.sh",
            "    permissions: '0644'",
            "    content: |",
            "      # Baked by PVE VM Studio. Same aliases on every distribution.",
            "      alias ls='ls --color=auto'",
            "      alias grep='grep --color=auto'",
            "      alias ll='ls -la'",
            "      alias la='ls -A'",
            "      alias ..='cd ..'",
            "      alias cd..='cd ..'",
        ]);
    }
    if has("pskeys") {
        // Readline keys as PowerShell has them; included from /etc/inputrc (runcmd below), so
        // the distribution's own bindings stay and these come last.
        ud.lines(&[
            "  - path: /etc/inputrc.d/pvs-keys.inputrc",
            "    permissions: '0644'",
            "    content: |",
            "      # Baked by PVE VM Studio: PowerShell-style keys.",
            "      # Ctrl+Left / Ctrl+Right: a word back / forward",
            r#"      "\e[1;5D": backward-word"#,
            r#"      "\e[5D": backward-word"#,
            r#"      "\e[1;5C": forward-word"#,
            r#"      "\e[5C": forward-word"#,
            "      # Ctrl+Backspace / Ctrl+Delete: delete a word back / forward",
            r#"      "\C-h": backward-kill-word"#,
            r#"      "\e[127;5u": backward-kill-word"#,
            r#"      "\e[7;5~": backward-kill-word"#,
            r#"      "\e[3;5~": kill-word"#,
            "      # Home / End",
            r#"      "\e[H": beginning-of-line"#,
            r#"      "\e[F": end-of-line"#,
            r#"      "\eOH": beginning-of-line"#,
            r#"      "\eOF": end-of-line"#,
        ]);
    }
    if has("fastfetch") {
        let tc = title_color(distro);
        let logo_src = if distro == "opensuse" { "\"source\": \"opensuse\", " } else { "" };
        let bar = |n: usize| "─".repeat(n);
        ud.lines(&["  - path: /etc/skel/.config/fastfetch/config.jsonc", "    permissions: '0644'", "    content: |", "      {"]);
        ud.line(format!("        \"logo\": {{ {logo_src}\"padding\": {{ \"top\": {} }} }},", logo_padding(distro)));
        ud.line("        \"display\": { \"separator\": \"  \", \"key\": { \"width\": 16 } },");
        ud.line("        \"modules\": [");
        ud.line("          \"break\",");
        ud.line(format!("          {{ \"type\": \"title\", \"color\": {{ \"user\": \"{tc}\", \"at\": \"1\", \"host\": \"{tc}\" }} }},"));
        ud.line(format!("          {{ \"type\": \"custom\", \"format\": \"{{#90}}┌─{{#}} {{#1}}System{{#}} {{#90}}{}{{#}}\" }},", bar(33)));
        for (t, k) in [("os", "{#1;34}OS"), ("kernel", "{#1;34}Kernel"), ("host", "{#1;35}Platform"), ("uptime", "{#1;35}Uptime"), ("packages", "{#1;35}Packages"), ("shell", "{#1;36}Shell"), ("locale", "{#1;36}Locale")] {
            ud.line(format!("          {{ \"type\": \"{t}\", \"key\": \"{{#0;90}}│{{#0}}  {k}\" }},"));
        }
        ud.line("          { \"type\": \"datetime\", \"key\": \"{#0;90}│{#0}  {#1;36}Time\", \"format\": \"{year}-{month-pretty}-{day-pretty} {hour-pretty}:{minute-pretty}\" },");
        ud.line(format!("          {{ \"type\": \"custom\", \"format\": \"{{#90}}├─{{#}} {{#1}}Resources{{#}} {{#90}}{}{{#}}\" }},", bar(30)));
        ud.line("          { \"type\": \"cpu\", \"key\": \"{#0;90}│{#0}  {#1;32}CPU\" },");
        ud.line("          { \"type\": \"memory\", \"key\": \"{#0;90}│{#0}  {#1;33}Memory\" },");
        ud.line("          { \"type\": \"disk\", \"key\": \"{#0;90}│{#0}  {#1;33}Disk\", \"folders\": \"/\" },");
        ud.line(format!("          {{ \"type\": \"custom\", \"format\": \"{{#90}}├─{{#}} {{#1}}Network{{#}} {{#90}}{}{{#}}\" }},", bar(32)));
        ud.line("          { \"type\": \"localip\", \"key\": \"{#0;90}│{#0}  {#1;31}IP\" },");
        ud.line("          { \"type\": \"command\", \"key\": \"{#0;90}│{#0}  {#1;31}Gateway\", \"text\": \"ip route show default 2>/dev/null | awk '{print $3; exit}'\" },");
        ud.line("          { \"type\": \"dns\", \"key\": \"{#0;90}│{#0}  {#1;31}DNS\" },");
        ud.line(r#"          { "type": "command", "key": "{#0;90}│{#0}  {#1;31}Domain", "text": "d=$(PATH=\"$PATH:/usr/sbin:/sbin\" realm list --name-only 2>/dev/null | head -n 1); if [ -n \"$d\" ]; then printf '%s' \"$d\"; else printf '\\033[2;37mnone\\033[0m'; fi" },"#);
        ud.line(format!("          {{ \"type\": \"custom\", \"format\": \"{{#90}}└{}{{#}}\" }},", bar(43)));
        ud.lines(&["          \"break\",", "          { \"type\": \"colors\", \"paddingLeft\": 2 }", "        ]", "      }"]);
    }
    if has("prompt") {
        // Appended, so it is the last word on PS1 in skel's .bashrc.
        ud.lines(&[
            "  - path: /etc/skel/.bashrc",
            "    append: true",
            "    content: |",
            "      ",
            "      # Baked by PVE VM Studio. Bold blue path, then a >: green after a command that",
            "      # succeeded, red after one that did not.",
            "      __pvs_prompt() {",
            "          if [ $? -eq 0 ]; then",
            r#"              PS1="\[\e[1;38;2;122;162;247m\]\w\[\e[0m\] \[\e[1;38;2;158;206;106m\]>\[\e[0m\] ""#,
            "          else",
            r#"              PS1="\[\e[1;38;2;122;162;247m\]\w\[\e[0m\] \[\e[1;38;2;247;118;142m\]>\[\e[0m\] ""#,
            "          fi",
            "      }",
            "      case \"$PROMPT_COMMAND\" in",
            "          *__pvs_prompt*) ;;",
            "          \"\") PROMPT_COMMAND=__pvs_prompt ;;",
            "          *) PROMPT_COMMAND=\"$PROMPT_COMMAND; __pvs_prompt\" ;;",
            "      esac",
        ]);
    }

    ud.line("runcmd:");
    // The studio reads the report through the agent; the agent must be up for that.
    ud.cmd("systemctl enable qemu-guest-agent 2>/dev/null; systemctl restart qemu-guest-agent 2>/dev/null || true");
    if cis == 2 {
        // Level 2's volumes are made on the second boot, before the local filesystems mount
        // (pvs-cis-layout.service). Here growpart has taken the root to the ROOT_GB disk;
        // /etc/growroot-disabled stops it (and Debian's initramfs growroot) from then on, and
        // BAKE-GROW-READY tells the studio to grow the disk for the volumes. lvm2 now, while
        // there is network.
        // KIWI-built images (openSUSE Leap) grow the root to the whole disk in the initramfs at
        // EVERY boot (55kiwi-repart, no oem-resize-once): left out of the initramfs through
        // dracut's own configuration, before the studio grows the disk.
        ud.cmd(&format!(
            "if [ -d /usr/lib/dracut/modules.d/55kiwi-repart ]; then printf 'omit_dracutmodules+=\" kiwi-repart \"\\n' > /etc/dracut.conf.d/99-pvs-cis-no-repart.conf && dracut -f --regenerate-all >/dev/null 2>&1 && echo BAKE-KIWI-REPART-OFF >> {REPORT}; fi"
        ));
        ud.cmd(&format!(
            "touch /etc/growroot-disabled; {{ command -v pvcreate >/dev/null && command -v mkfs.ext4 >/dev/null; }} || {{ if command -v apt-get >/dev/null; then DEBIAN_FRONTEND=noninteractive apt-get install -y -q lvm2; elif command -v zypper >/dev/null; then zypper -n -q install --no-recommends lvm2 e2fsprogs; else dnf -y -q install lvm2 e2fsprogs; fi; }} >/dev/null 2>&1; mkdir -p /etc/pvs-cis && echo ROOT_GB={CIS_ROOT_GB} > /etc/pvs-cis/layout.wanted; echo BAKE-GROW-READY >> {REPORT}"
        ));
    }
    if let (Some(r), Some(lang), Some(fmt)) = (region, &lang, &fmt) {
        // LANG is the language, the nine LC_* format variables the format locale,
        // LC_MESSAGES left on LANG. How a locale comes to exist is per family.
        let mut assigns = format!("LANG={lang}");
        for v in ["LC_TIME", "LC_NUMERIC", "LC_MONETARY", "LC_PAPER", "LC_MEASUREMENT", "LC_ADDRESS", "LC_TELEPHONE", "LC_NAME", "LC_IDENTIFICATION"] {
            assigns.push_str(&format!(" {v}={fmt}"));
        }
        let wanted = if fmt != lang { format!("{lang} {fmt}") } else { lang.clone() };
        let generate = format!(
            r#"for l in {wanted}; do grep -q "^$l UTF-8" /etc/locale.gen || sed -i "s/^# *$l UTF-8/$l UTF-8/" /etc/locale.gen; grep -q "^$l UTF-8" /etc/locale.gen || echo "$l UTF-8" >> /etc/locale.gen; done; locale-gen {wanted}"#
        );
        let conf = format!(r#"localectl set-locale {assigns} || printf "%s\n" {assigns} > /etc/locale.conf"#);
        match family {
            "debian" => ud.cmd(&format!("{generate}; update-locale {assigns}")),
            "arch" => ud.cmd(&format!("{generate}; {conf}")),
            _ => ud.cmd(&conf),
        }
        if let Some((x11, variant, console)) = &keyboard {
            if family == "debian" {
                // /etc/default/keyboard is the one file on Debian and Ubuntu; localectl
                // there cannot set a console keymap.
                for (key, val) in [("XKBLAYOUT", x11.as_str()), ("XKBVARIANT", variant.as_str())] {
                    ud.cmd(&format!("if grep -q ^{key}= /etc/default/keyboard 2>/dev/null; then sed -i s/^{key}=.*/{key}={val}/ /etc/default/keyboard; else echo {key}={val} >> /etc/default/keyboard; fi"));
                }
            } else {
                // Console keymap names differ per image - the first one it has wins.
                let cands = console.join(" ");
                let names = console.join(",");
                ud.report(&format!(r#"k=""; for c in {cands}; do if localectl list-keymaps 2>/dev/null | grep -qx "$c"; then k=$c; break; fi; done; if [ -n "$k" ] && localectl set-keymap "$k"; then echo BAKE-KEYMAP $k; else echo BAKE-KEYMAP-MISSING {names}; fi"#));
            }
        }
        ud.report(&format!(r#"for l in {wanted}; do n=$(echo $l | sed s/UTF-8/utf8/); if locale -a | grep -qx $n; then echo BAKE-LOCALE $l ok; else echo BAKE-LOCALE $l MISSING; fi; done"#));
        let _ = r;
        ud.report(r#"echo BAKE-REGION $(grep -h -E "^(LANG|LC_TIME)=" /etc/default/locale /etc/locale.conf 2>/dev/null | sort -u | tr "\n" " ") TZ=$(readlink /etc/localtime | sed "s#.*zoneinfo/##") KEYMAP=$(sed -n "s/^XKBLAYOUT=//p" /etc/default/keyboard 2>/dev/null | tr -d \"; [ -f /etc/default/keyboard ] || localectl status 2>/dev/null | sed -n "s/.*VC Keymap: //p")"#);
    }
    ud.report(kernel_report(family));
    ud.report("echo BAKE-RUNNING-KERNEL $(uname -r)");
    if ff_github {
        ud.report("curl -fsSL -o /tmp/fastfetch.deb https://github.com/fastfetch-cli/fastfetch/releases/latest/download/fastfetch-linux-amd64.deb && DEBIAN_FRONTEND=noninteractive apt-get install -y /tmp/fastfetch.deb >/dev/null; rm -f /tmp/fastfetch.deb; if dpkg -s fastfetch >/dev/null 2>&1; then echo BAKE-PKG fastfetch ok; else echo BAKE-PKG fastfetch MISSING; fi");
    }
    if has("ilovecandy") {
        ud.cmd(r#"grep -q "^ILoveCandy" /etc/pacman.conf || sed -i "/^\[options\]/a ILoveCandy" /etc/pacman.conf; sed -i "s/^#Color$/Color/" /etc/pacman.conf"#);
    }
    if has("yay") {
        // As the bake account: makepkg will not build as root.
        ud.report(r#"runuser -l bake -c "git clone https://aur.archlinux.org/yay-bin.git && cd yay-bin && makepkg -si --noconfirm" >/dev/null 2>&1; if pacman -Q yay-bin >/dev/null 2>&1; then echo BAKE-PKG yay-bin ok; else echo BAKE-PKG yay-bin MISSING; fi"#);
    }
    if !packages.is_empty() {
        ud.report(&package_probe(family, &packages.join(" ")));
    }
    ud.cmd("systemctl enable --now ssh 2>/dev/null || systemctl enable --now sshd 2>/dev/null || true");
    if has("aliases") {
        ud.cmd(r#"grep -q 99-pve-vm-studio-aliases /etc/skel/.bashrc || echo ". /etc/profile.d/99-pve-vm-studio-aliases.sh" >> /etc/skel/.bashrc"#);
    }
    if has("fastfetch") {
        // Interactive shells only - a banner in a non-interactive one breaks scp.
        // cloud-init made /etc/skel/.config 0755 for the config file; a home's dot folders are
        // its user's (CIS 7.2.11 wants 0750 at most).
        ud.cmd("chmod 0750 /etc/skel/.config /etc/skel/.config/fastfetch 2>/dev/null || true");
        ud.cmd(r#"grep -q pvs-fastfetch /etc/skel/.bashrc || echo 'command -v fastfetch >/dev/null 2>&1 && case $- in *i*) fastfetch; printf "\n\n" ;; esac # pvs-fastfetch' >> /etc/skel/.bashrc"#);
    }
    if has("pskeys") {
        // openSUSE ships its inputrc in /usr/etc: the /etc copy then replaces it, so it starts
        // as that copy. A ~/.inputrc of a user's own replaces both - readline reads one file.
        ud.cmd(r#"[ -f /etc/inputrc ] || cp /usr/etc/inputrc /etc/inputrc 2>/dev/null || touch /etc/inputrc; grep -q pvs-keys.inputrc /etc/inputrc || printf '\n$include /etc/inputrc.d/pvs-keys.inputrc\n' >> /etc/inputrc"#);
    }
    if has("quietmotd") {
        if distro == "ubuntu" {
            ud.cmd("sed -i s/^ENABLED=1/ENABLED=0/ /etc/default/motd-news 2>/dev/null || true");
            ud.cmd("chmod -x /etc/update-motd.d/50-motd-news /etc/update-motd.d/91-contract-ua-esm-status /etc/update-motd.d/50-landscape-sysinfo /etc/update-motd.d/90-updates-available /etc/update-motd.d/95-hwe-eol /etc/update-motd.d/10-help-text 2>/dev/null || true");
        }
        ud.cmd("touch /etc/skel/.hushlogin /root/.hushlogin");
    }

    // Generalize: the gold must carry no identity of its own. (command, part of the report)
    let mut seal: Vec<(String, bool)> = vec![("cloud-init clean --logs --machine-id".into(), false), ("rm -f /etc/ssh/ssh_host_*".into(), false)];
    for p in network_artifacts(family) {
        seal.push((format!("rm -f {p}"), false));
    }
    // Rocky 9's ifcfg renderer keeps an existing resolv.conf's servers ahead of the
    // seed's. Emptied only when it is a plain file - on Fedora it is resolved's symlink.
    if family == "rhel" || family == "suse" {
        seal.push(("[ -L /etc/resolv.conf ] || : > /etc/resolv.conf".into(), false));
    }
    seal.push(("truncate -s 0 /etc/machine-id".into(), false));
    seal.push((": > /etc/hostname".into(), false));
    // The bake's journal sits under its machine-id and would read as the VM's own.
    seal.push(("journalctl --relinquish-var && rm -rf /var/log/journal/*".into(), false));
    if cis > 0 {
        // The bake's audit trail and any integrity database are the bake's, not a clone's.
        seal.push(("find /var/log/audit -type f -delete 2>/dev/null; rm -f /var/lib/aide/aide.db /var/lib/aide/aide.db.new /var/lib/aide/aide.db.gz /var/lib/aide/aide.db.new.gz".into(), false));
    }
    // Ubuntu 26.04's dracut initrd is hostonly and copied the bake's hostname and
    // machine-id into itself; rebuilt now both are empty.
    if distro == "ubuntu" {
        seal.push(("if dpkg -s dracut >/dev/null 2>&1; then update-initramfs -u -k all >/dev/null 2>&1 && echo BAKE-INITRD-REBUILT || echo BAKE-INITRD-FAILED; fi".into(), true));
    }
    // Fedora's btrfs mount points under the var/home subvolumes stay unlabeled_t forever
    // unless they are labelled from underneath.
    seal.push((r#"if command -v matchpathcon >/dev/null && selinuxenabled 2>/dev/null && [ "$(findmnt -no FSTYPE /)" = btrfs ]; then dev=$(findmnt -no SOURCE / | sed "s/\[.*//"); rs=$(findmnt -no FSROOT /); t=$(mktemp -d); if mount -o subvolid=5 "$dev" "$t"; then findmnt -rn -t btrfs -o TARGET | grep -vx / | while read -r m; do h="$t$rs$m"; [ -d "$h" ] || continue; want=$(matchpathcon -n "$m"); have=$(stat -c %C "$h"); if [ "$have" != "$want" ]; then chcon "$want" "$h" && echo "BAKE-RELABEL $m $have -> $want" || echo "BAKE-RELABEL-FAILED $m"; fi; done; umount "$t"; fi; rmdir "$t"; fi"#.into(), true));
    if family == "rhel" {
        // Back to the distribution's agent policy - after the next start, which is a VM's.
        seal.push(("[ -f /run/pvs-qemu-ga.orig ] && cp -a /run/pvs-qemu-ga.orig /etc/sysconfig/qemu-ga || true".into(), false));
    }
    // Last: the diagnostic account, once nothing can need it any more.
    seal.push(("userdel -f -r bake 2>/dev/null || true".into(), false));
    seal.push(("rm -f /etc/sudoers.d/90-cloud-init-users".into(), false));

    if cis > 0 {
        // CIS: harden now, reboot, and check the system as it then is - pvs-cis-finish.service
        // runs the check on the second boot, then this same generalize, then BAKE-OK.
        // What bootcmd noted (the bundle, the Level 2 volumes) joins the report here.
        ud.report("cat /run/pvs-cis-boot.log 2>/dev/null; [ -f /etc/pvs-cis/layout.failed ] && echo BAKE-LAYOUT-FAILED $(cat /etc/pvs-cis/layout.failed); true");
        if cis == 2 && distro == "ubuntu" {
            // Level 2 takes squashfs away (1.1.1.7): snaps could no longer mount.
            ud.report("if dpkg -s snapd >/dev/null 2>&1; then DEBIAN_FRONTEND=noninteractive apt-get purge -y -q snapd >/dev/null 2>&1 && echo BAKE-CIS-SNAPD-PURGED || echo BAKE-CIS-SNAPD-KEPT; fi; sed -i -E 's#:/snap/bin##g' /etc/environment");
        }
        ud.report(&format!("pvs-cis fix --level {cis} --exceptions /etc/pvs-cis/exceptions | tee /etc/pvs-cis/fix.log | grep -E '^(CIS-FIX-(FAILED|DONE)|  [|] )'"));
        // Later fixes install packages (auditd, aide, ufw...) that can pull in what chapter 2
        // removed, bring SUID programs the privileged-commands audit rule does not list yet, or (ufw on
        // Debian) bring their own sysctl file over chapter 3's network settings: those rules
        // once more, now that everything is in.
        ud.report(&format!(r#"pvs-cis fix --level {cis} --exceptions /etc/pvs-cis/exceptions --only $(pvs-cis list | awk -F'\t' '$1 ~ /^2\./ || $1 ~ /^3\.3\./ || $5 == "audit-use-of-suid-sgid-programs" {{ print $1 }}' | paste -sd,) | sed 's/^CIS-FIX-DONE/CIS-FIX-DONE second pass,/' | tee -a /etc/pvs-cis/fix.log | grep -E '^(CIS-FIX-(FAILED|DONE)|  [|] )'"#));
        ud.cmd("[ -f /run/pvs-cis/grub-password ] && install -m 0600 /run/pvs-cis/grub-password /root/.pvs-cis-grub-password || true");
        let script: String = std::iter::once("#!/bin/bash\n# PVE VM Studio: generalize the gold (CIS bake, second boot).\n".to_owned())
            .chain(seal.iter().map(|(c, report)| if *report { format!("{{ {c}; }} 2>&1 | tee -a {REPORT}\n") } else { format!("{c}\n") }))
            .collect();
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD.encode(script);
        ud.cmd(&format!("echo {b64} | base64 -d > {CIS_LIB}/generalize.sh && chmod 0700 {CIS_LIB}/generalize.sh"));
        let units = if cis == 2 { "pvs-cis-finish.service pvs-cis-layout.service" } else { "pvs-cis-finish.service" };
        // The units are for the next boot: some images start a unit enabled now in this boot
        // (Oracle Linux - cloud-final before multi-user.target); they compare this boot's id.
        ud.cmd("cat /proc/sys/kernel/random/boot_id > /etc/pvs-cis/boot1.id");
        ud.cmd(&format!("install -m 0644 {CIS_LIB}/bake/*.service {CIS_LIB}/units/*.service /etc/systemd/system/ && systemctl daemon-reload && systemctl enable {units}"));
        if cis == 2 {
            // The root partition before the reboot - Level 2's layout needs it at ROOT_GB.
            ud.cmd(&format!(r#"echo "BAKE-ROOT-SIZE root $(lsblk -bdno SIZE "$(findmnt -no SOURCE /)" | numfmt --to=iec) disk $(lsblk -bdno SIZE "/dev/$(lsblk -snlo NAME,TYPE "$(findmnt -no SOURCE /)" | awk '$2 == "disk" {{ print $1; exit }}')" | numfmt --to=iec) cloud-init: $(grep -h 'cc_growpart' /var/log/cloud-init.log 2>/dev/null | grep -Eo '(resized|changed|disabled|NOCHANGE|skip)[^,]*' | tr '
' ' ' | cut -c1-200)" >> {REPORT}"#));
        }
        ud.cmd(&format!("echo BAKE-CIS-REBOOT >> {REPORT}"));
        // This boot's report (kernel, packages, locales) outlives the reboot in /etc - the
        // second boot puts it back in front of its own, so the studio judges it as always.
        ud.cmd(&format!("cp {REPORT} /etc/pvs-cis/boot1.report && sync && echo PVS-BOOT1-SAVED $(wc -l < /etc/pvs-cis/boot1.report) lines"));
        // cloud-init reboots once its final stage is done.
        ud.lines(&["power_state:", "  mode: reboot", "  delay: now", "  message: 'PVE VM Studio: CIS - reboot into the hardened system for the check'", "  condition: true"]);
    } else {
        for (c, report) in &seal {
            if *report {
                ud.report(c);
            } else {
                ud.cmd(c);
            }
        }
        // The signal the studio waits for. It then shuts the VM down through the API.
        ud.cmd(&format!("sync; echo BAKE-OK >> {REPORT}"));
    }

    ud.text()
}

pub fn bake_meta_data(image: &str, stamp: &str) -> String {
    format!("instance-id: bake-{image}-{stamp}\nlocal-hostname: bake\n")
}

// ---- per-VM ----

/// One VM's first boot, the Linux half of Build-Vms (workgroup; domain join comes later).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmSeed {
    pub hostname: String,
    pub user: String,
    pub password: String,
    #[serde(default)]
    pub ssh_key: String,
    #[serde(default)]
    pub packages: Vec<String>,
    #[serde(default)]
    pub domain_join: Option<crate::guest::DomainJoin>,
    #[serde(default)]
    pub arc: Option<crate::guest::AzureArc>,
    /// Cloned from a CIS gold.
    #[serde(default)]
    pub cis: bool,
}

/// One network adapter of a VM, as the seed describes it: matched by its MAC, a static
/// address or DHCP. Gateway and DNS belong to the primary adapter only - a second default
/// route is the classic way to make a multi-homed guest unreachable (the Hyper-V studio's
/// rule).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NicCfg {
    pub mac: String,
    /// Empty = DHCP.
    pub address: String,
    pub prefix: u8,
    #[serde(default)]
    pub gateway: String,
    #[serde(default)]
    pub dns: Vec<String>,
    #[serde(default)]
    pub search: String,
}

pub fn vm_user_data(img: &LinuxImage, s: &VmSeed) -> String {
    let mut ud = Ud(vec!["#cloud-config".into()]);
    ud.line(format!("hostname: {}", s.hostname));
    ud.line("preserve_hostname: false");
    let dj = s.domain_join.as_ref().filter(|d| !d.domain.trim().is_empty());
    if let Some(d) = dj {
        // The FQDN in /etc/hosts before the join runs, and the domain as the time source -
        // a join before NTP has stepped the clock fails.
        let domain = d.domain.trim();
        ud.line(format!("fqdn: {}.{domain}", s.hostname));
        ud.lines(&["prefer_fqdn_over_hostname: true", "manage_etc_hosts: true", "ntp:", "  enabled: true"]);
        ud.line(format!("  servers: ['{domain}']"));
        if img.distro == "fedora" {
            ud.lines(&["  config:", "    service_name: chronyd"]);
        }
    }
    ud.line("users:");
    ud.line(format!("  - name: {}", s.user));
    ud.line(format!("    groups: [{}]", admin_group(img.family)));
    // A CIS gold asks for the password on sudo (5.2.4) - the studio always sets one.
    let sudo = if s.cis { "ALL=(ALL) ALL" } else { "ALL=(ALL) NOPASSWD:ALL" };
    ud.lines(&["    shell: /bin/bash", &format!("    sudo: '{sudo}'"), "    lock_passwd: false"]);
    if !s.ssh_key.trim().is_empty() {
        ud.line("    ssh_authorized_keys:");
        ud.line(format!("      - {}", sq(s.ssh_key.trim())));
    }
    // In clear, as on Hyper-V: the seed is detached and deleted after this boot, and the
    // scrub below takes cloud-init's own copies of it off the disk.
    if s.cis {
        // A CIS gold's PAM would judge the password (pwquality, enforce_for_root) and could
        // refuse it, leaving the admin without one: set as a hash, past PAM (runcmd below).
        ud.line("ssh_pwauth: true");
    } else {
        ud.lines(&["chpasswd:", "  expire: false", "  users:"]);
        ud.line(format!("    - name: {}", s.user));
        ud.line(format!("      password: {}", sq(&s.password)));
        ud.lines(&["      type: text", "ssh_pwauth: true"]);
    }
    if s.cis {
        // The gold's apt sources are CIS's (HTTPS, Signed-By); cloud-init would render its
        // own http:// ones for the new instance.
        ud.lines(&["apt:", "  preserve_sources_list: true"]);
    }
    let mut packages: Vec<String> = s.packages.clone();
    if dj.is_some() {
        packages.extend(crate::guest::join_packages(img.family).iter().map(|p| p.to_string()));
    }
    if s.arc.is_some() {
        packages.push("curl".into());
    }
    let mut seen = std::collections::HashSet::new();
    packages.retain(|p| seen.insert(p.clone()));
    if !packages.is_empty() {
        ud.line("packages:");
        for p in &packages {
            ud.line(format!("  - {}", sq(p)));
        }
    }
    ud.line("runcmd:");
    if s.cis {
        let shq = |v: &str| format!("'{}'", v.replace('\'', "'\\''"));
        ud.cmd(&format!(
            "h=$(printf '%s' {pw} | openssl passwd -6 -stdin) && usermod -p \"$h\" {user} && echo PVS-PASSWORD-SET || echo PVS-PASSWORD-FAILED",
            pw = shq(&s.password),
            user = shq(&s.user)
        ));
    }
    if let Some(d) = dj {
        for c in crate::guest::linux_join_commands(d, img.family) {
            ud.cmd(&c);
        }
    }
    if let Some(a) = &s.arc {
        for c in crate::guest::linux_arc_commands(a) {
            ud.cmd(&c);
        }
    }
    ud.cmd(r#"find /var/lib/cloud/instances -maxdepth 2 -type f \( -name 'user-data.txt*' -o -name 'cloud-config.txt' -o -name 'vendor-data.txt*' -o -name 'vendor-cloud-config.txt' -o -name 'obj.pkl' \) -delete 2>/dev/null; rm -f /run/cloud-init/instance-data-sensitive.json /var/lib/cloud/instance/scripts/runcmd; echo SEED-SCRUBBED"#);
    ud.lines(&["growpart:", "  mode: auto", "  devices: ['/']", "resize_rootfs: true"]);
    // Powered off when done: that is the signal to take the seed away.
    ud.lines(&["power_state:", "  mode: poweroff", "  timeout: 30", "  condition: true"]);
    ud.text()
}

pub fn vm_meta_data(hostname: &str, stamp: &str) -> String {
    // A fresh instance-id per build, so a rebuilt VM of the same name is provisioned.
    format!("instance-id: {hostname}-{stamp}\nlocal-hostname: {hostname}\n")
}

/// netplan v2, one entry per adapter matched by MAC (Get-CloudInitNetworkConfig, all
/// adapters). None when there is nothing cloud-init's own DHCP default would not do.
pub fn vm_network_config(nics: &[NicCfg]) -> Option<String> {
    if nics.len() <= 1 && nics.iter().all(|n| n.address.is_empty()) {
        return None;
    }
    let mut s = String::from("version: 2\nethernets:\n");
    for (i, n) in nics.iter().enumerate() {
        s += &format!("  nic{i}:\n    match:\n      macaddress: '{}'\n", n.mac.to_lowercase());
        if n.address.is_empty() {
            s += "    dhcp4: true\n";
            if i > 0 {
                // DHCP on an extra adapter must not take the default route away.
                s += "    dhcp4-overrides:\n      use-routes: false\n      use-dns: false\n";
            }
            continue;
        }
        s += &format!("    addresses: ['{}/{}']\n", n.address, n.prefix);
        if i > 0 {
            continue;
        }
        if !n.gateway.is_empty() {
            s += &format!("    routes:\n      - to: 0.0.0.0/0\n        via: '{}'\n", n.gateway);
        }
        if !n.dns.is_empty() || !n.search.is_empty() {
            s += "    nameservers:\n";
            if !n.dns.is_empty() {
                let list: Vec<String> = n.dns.iter().map(|d| format!("'{d}'")).collect();
                s += &format!("      addresses: [{}]\n", list.join(", "));
            }
            if !n.search.is_empty() {
                s += &format!("      search: ['{}']\n", n.search);
            }
        }
    }
    Some(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vm_user_data_with_join_and_arc() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("target/tmp/user-data");
        std::fs::create_dir_all(&dir).unwrap();
        for id in ["debian13", "rocky10", "leap16", "ubuntu2604"] {
            let img = catalog::linux(id).unwrap();
            let seed = VmSeed {
                hostname: "web-01".into(),
                user: "admin".into(),
                password: "it's a 'secret'".into(),
                ssh_key: "ssh-ed25519 AAAA test".into(),
                packages: vec!["nginx".into()],
                domain_join: Some(crate::guest::DomainJoin {
                    domain: "ad.example".into(),
                    user: "AD\\Join Svc".into(),
                    password: "p'w\"$x".into(),
                    ou: "OU=Linux,DC=ad,DC=example".into(),
                    sudo_groups: vec!["Domain Admins".into()],
                    login_groups: vec!["Linux Users".into()],
                    mode: String::new(),
            }),
                arc: Some(crate::guest::AzureArc {
                    auth_mode: "servicePrincipal".into(),
                    app_id: "app".into(),
                    secret: "s'e\"c".into(),
                    tenant_id: "t".into(),
                    subscription_id: "s".into(),
                    resource_group: "rg".into(),
                    location: "westeurope".into(),
                }),
                cis: false,
            };
            let ud = vm_user_data(img, &seed);
            assert!(ud.contains("realm join") && ud.contains("azcmagent connect"));
            std::fs::write(dir.join(format!("vm-{id}.yaml")), ud).unwrap();
        }
    }

    #[test]
    fn network_config_multi_nic() {
        let primary = NicCfg { mac: "BC:24:11:00:00:01".into(), address: "10.0.0.5".into(), prefix: 24, gateway: "10.0.0.1".into(), dns: vec!["10.0.0.1".into()], search: "lab.local".into() };
        let extra = NicCfg { mac: "BC:24:11:00:00:02".into(), address: String::new(), prefix: 24, gateway: String::new(), dns: vec![], search: String::new() };
        let y = vm_network_config(&[primary.clone(), extra]).unwrap();
        assert!(y.contains("nic0:") && y.contains("nic1:"));
        assert!(y.contains("via: '10.0.0.1'"));
        assert!(y.contains("use-routes: false"), "a DHCP extra adapter must not take the default route");
        // One DHCP adapter: cloud-init's own default does it.
        let dhcp = NicCfg { address: String::new(), ..primary };
        assert!(vm_network_config(&[dhcp]).is_none());
    }

    /// Writes every image's bake user-data (all features, a region) next to the build, for
    /// a YAML check outside Rust: `python3 -c 'import yaml,glob; ...'`.
    #[test]
    fn bake_user_data_for_every_image() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("target/tmp/user-data");
        std::fs::create_dir_all(&dir).unwrap();
        let opt = BakeOptions {
            features: catalog::FEATURES.iter().map(|f| f.id.to_string()).collect(),
            updates: true,
            region: Some(Region {
                language: "en-US".into(),
                format: "de-DE".into(),
                keyboard: "de-DE".into(),
                timezone: "Europe/Berlin".into(),
            }),
            disk_gb: None,
            disk_storage: None,
            cis: None,
        };
        for img in catalog::LINUX {
            let ud = bake_user_data(img, &opt);
            assert!(ud.starts_with("#cloud-config\n"));
            assert!(ud.contains("BAKE-OK"));
            assert!(ud.contains(r#""\e[1;5D": backward-word"#) && ud.contains("$include /etc/inputrc.d/pvs-keys.inputrc"));
            std::fs::write(dir.join(format!("{}.yaml", img.id)), ud).unwrap();
        }
        let plain = bake_user_data(catalog::linux("debian13").unwrap(), &BakeOptions { updates: true, ..Default::default() });
        std::fs::write(dir.join("debian13-plain.yaml"), plain).unwrap();

        // CIS: hardening, then a reboot - BAKE-OK comes from the second boot, not runcmd.
        let u = catalog::linux("ubuntu2604").unwrap();
        for level in [1u8, 2] {
            let cis_opt = BakeOptions { cis: Some(crate::cis::CisOptions { level, exceptions: vec![] }), ..opt.clone() };
            assert_eq!(cis_opt.cis_level(u.id), level);
            let ud = bake_user_data(u, &cis_opt);
            assert!(ud.contains("pvs-cis fix --level") && ud.contains("mode: reboot") && !ud.contains("echo BAKE-OK"));
            assert_eq!(ud.contains("/etc/pvs-cis/layout.wanted") && ud.contains("growroot-disabled"), level == 2);
            assert!(!ud.contains("growpart:"));
            std::fs::write(dir.join(format!("ubuntu2604-cis{level}.yaml")), ud).unwrap();
        }
        // No CIS benchmark for Fedora: the option is ignored. Debian 13 has Ubuntu 26.04's.
        let d = BakeOptions { cis: Some(crate::cis::CisOptions { level: 2, exceptions: vec![] }), ..opt.clone() };
        assert_eq!(d.cis_level("fedora44"), 0);
        assert!(bake_user_data(catalog::linux("fedora44").unwrap(), &d).contains("echo BAKE-OK"));
        // Enterprise Linux: lvm2 by dnf.
        assert_eq!(d.cis_level("rocky10"), 2);
        let el = bake_user_data(catalog::linux("rocky10").unwrap(), &d);
        assert!(el.contains("pvs-cis fix --level 2") && el.contains("dnf -y -q install lvm2 e2fsprogs") && !el.contains("snapd"));
        std::fs::write(dir.join("rocky10-cis2.yaml"), el).unwrap();
        assert_eq!(d.cis_level("debian13"), 2);
        let deb = bake_user_data(catalog::linux("debian13").unwrap(), &d);
        assert!(deb.contains("pvs-cis fix --level 2") && !deb.contains("snapd"));
        std::fs::write(dir.join("debian13-cis2.yaml"), deb).unwrap();
        let vm = VmSeed { hostname: "h".into(), user: "admin".into(), password: "it's".into(), ssh_key: String::new(), packages: vec![], domain_join: None, arc: None, cis: true };
        let ud = vm_user_data(u, &vm);
        assert!(ud.contains("ALL=(ALL) ALL'") && !ud.contains("chpasswd:") && ud.contains("openssl passwd -6") && ud.contains("preserve_sources_list"));
        std::fs::write(dir.join("vm-ubuntu2604-cis.yaml"), ud).unwrap();
    }
}
