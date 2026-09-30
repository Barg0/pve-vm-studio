#!/usr/bin/env bash
#
# kiln.sh - Linux golds and VMs on QEMU/KVM, baked and deployed in one go.
#
# The libvirt cousin of New-Vhdx.ps1 and Build-Vms.ps1 (HyperV-Scripts), for a Linux
# desktop instead of a Hyper-V host. Same catalog, same bake, same first-boot seed -
# ported rather than shared, so this file stands on its own and needs nothing but
# bash and the usual virtualisation tools:
#
#   virsh, virt-install, qemu-img, xorriso, curl, sha256sum/sha512sum
#
# Where it differs from the PowerShell pair, it differs because KVM is not Hyper-V:
#   - qemu-guest-agent instead of hyperv-daemons, and the distribution's own kernel
#     instead of linux-azure.
#   - The serial console stays. A libvirt VM HAS a serial port (virt-install gives it
#     a pty), so `virsh console` works and the cloud images' console=ttyS0 is right as
#     it is - the Hyper-V bake takes it out because a Hyper-V VM has nothing behind it.
#   - Secure Boot is off. The distribution OVMF on this kind of box ships no firmware
#     with Microsoft's keys enrolled, so there is nothing for a shim to validate against.
#   - No domain join, no Azure Arc: workgroup VMs only.
#
# The bake runs under qemu:///session - as you, on user-mode networking - so its
# serial log is a file you own and can grep for BAKE-OK. The VMs run under
# qemu:///system on a libvirt network, so they show up in Virtual Machine Manager
# and can reach each other.
#
# Golds are never replaced in place: a rebake writes a new, time-stamped file, and
# every VM keeps the gold it was built on. "Remove golds" only offers the ones no VM
# uses any more.
#
# Settings, from the environment:
#   KILN_VM_DIR    where VM disks go            (default ~/VMs)
#   KILN_GOLD_DIR  where golds go               (default $KILN_VM_DIR/golds)
#   KILN_CACHE     where cloud images are kept  (default <kiln>/media)
#   NO_COLOR          plain output
#
# Both VM directories must be reachable by the qemu user libvirt runs VMs as - under a
# home directory that is 0700 that means e.g. `setfacl -m u:libvirt-qemu:x ~`.

set -uo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)

VM_DIR=${KILN_VM_DIR:-$HOME/VMs}
GOLD_DIR=${KILN_GOLD_DIR:-$VM_DIR/golds}
CACHE_DIR=${KILN_CACHE:-$SCRIPT_DIR/media}
LOG_ROOT=$SCRIPT_DIR/logs

SYS=qemu:///system
SES=qemu:///session

# Three bakes at once. Each is a 3 GiB VM running a package manager flat out, and
# fourteen of them in parallel is how a desktop runs out of memory.
BAKE_SLOTS=3
BAKE_MEMORY_MB=3072
BAKE_TIMEOUT_MIN=60
FIRSTBOOT_TIMEOUT_MIN=20
IP_TIMEOUT_SEC=180

# Every lab VM carries this at the start of its libvirt description, followed by the
# image id and the gold it was built on. It is how "Remove VMs" knows which VMs are
# this script's, and how "Remove golds" knows which golds are still in use.
DESC_TAG=kiln

# ---------------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------------

if [[ -n ${NO_COLOR:-} || ! -t 1 ]]; then
    C_RESET="" C_BOLD="" C_DIM="" C_ACCENT="" C_OK="" C_WARN="" C_ERR="" C_INFO=""
else
    # The studio's palette (Tokyo Night), as exact colours so every terminal draws the
    # same thing.
    C_RESET=$'\e[0m' C_BOLD=$'\e[1m' C_DIM=$'\e[38;2;86;95;137m'
    C_ACCENT=$'\e[38;2;122;162;247m' C_OK=$'\e[38;2;158;206;106m'
    C_WARN=$'\e[38;2;224;175;104m' C_ERR=$'\e[38;2;247;118;142m' C_INFO=$'\e[38;2;187;154;247m'
fi

RUN_STAMP=$(date +%Y%m%d-%H%M%S)
RUN_LOG_DIR=$LOG_ROOT/$RUN_STAMP
MAIN_LOG=$RUN_LOG_DIR/kiln.log
# Set inside a job so its lines go to its own log as well as the run's, and so
# long steps can put their progress on the job's board line.
JOB_LOG=""
JOB=""

# Same layout as the PowerShell logs: time, a five-wide tag, the message.
log() {
    local tag=$1; shift
    local line
    line=$(printf '%s [ %-5s ] %s' "$(date '+%Y-%m-%d %H:%M:%S')" "$tag" "$*")
    [[ -d $RUN_LOG_DIR ]] && printf '%s\n' "$line" >>"$MAIN_LOG"
    [[ -n $JOB_LOG ]] && printf '%s\n' "$line" >>"$JOB_LOG"
    return 0
}

say()  { printf '  %s\n' "$*"; }
ok()   { printf '  %s✓%s %s\n' "$C_OK" "$C_RESET" "$*"; }
warn() { printf '  %s!%s %s\n' "$C_WARN" "$C_RESET" "$*"; }
fail() { printf '  %s✗%s %s\n' "$C_ERR" "$C_RESET" "$*" >&2; }
die()  { fail "$*"; exit 1; }

vs() { virsh -q -c "$SYS" "$@"; }
vu() { virsh -q -c "$SES" "$@"; }

repeat() { local s="" i; for ((i = 0; i < $2; i++)); do s+=$1; done; printf '%s' "$s"; }

# A YAML single-quoted scalar: the only escape it has is a doubled quote.
sq() { local s=${1//\'/\'\'}; printf "'%s'" "$s"; }

# ---------------------------------------------------------------------------------
# Catalog
# ---------------------------------------------------------------------------------
#
# The same fourteen images as Get-LinuxImageCatalog in New-Vhdx.ps1, with the same
# URLs - the reasons each URL is the one it is (genericcloud not nocloud, Base-Generic
# not UKI, GenericCloud-Base not LVM, cloudimg not basic) are written up there.
#
# imageid|distro|family|version|name|url|checksum url|algorithm|pinned checksum|disk GiB|osinfo candidates|bake packages
#
# Bake packages: qemu-guest-agent everywhere (some images carry it, and naming it then
# costs nothing). Oracle keeps kernel-uek-modules for the same reason as on Hyper-V:
# fwupd asks for i2c_dev on every boot and the template only has UEK's -core half.
CATALOG='
ubuntu2604|ubuntu|debian|26.04|Ubuntu 26.04 LTS (Resolute)|https://cloud-images.ubuntu.com/releases/26.04/release/ubuntu-26.04-server-cloudimg-amd64.img|https://cloud-images.ubuntu.com/releases/26.04/release/SHA256SUMS|sha256||32|ubuntu26.04 ubuntu24.04|qemu-guest-agent
ubuntu2404|ubuntu|debian|24.04|Ubuntu 24.04 LTS (Noble)|https://cloud-images.ubuntu.com/releases/24.04/release/ubuntu-24.04-server-cloudimg-amd64.img|https://cloud-images.ubuntu.com/releases/24.04/release/SHA256SUMS|sha256||32|ubuntu24.04|qemu-guest-agent
debian13|debian|debian|13|Debian 13 (Trixie)|https://cloud.debian.org/images/cloud/trixie/latest/debian-13-genericcloud-amd64.qcow2|https://cloud.debian.org/images/cloud/trixie/latest/SHA512SUMS|sha512||32|debian13|qemu-guest-agent
debian12|debian|debian|12|Debian 12 (Bookworm)|https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-genericcloud-amd64.qcow2|https://cloud.debian.org/images/cloud/bookworm/latest/SHA512SUMS|sha512||32|debian12|qemu-guest-agent
fedora44|fedora|rhel|44|Fedora 44 (Cloud Base)|https://download.fedoraproject.org/pub/fedora/linux/releases/44/Cloud/x86_64/images/Fedora-Cloud-Base-Generic-44-1.7.x86_64.qcow2|https://download.fedoraproject.org/pub/fedora/linux/releases/44/Cloud/x86_64/images/Fedora-Cloud-44-1.7-x86_64-CHECKSUM|sha256||32|fedora44 fedora43|qemu-guest-agent
fedora43|fedora|rhel|43|Fedora 43 (Cloud Base)|https://download.fedoraproject.org/pub/fedora/linux/releases/43/Cloud/x86_64/images/Fedora-Cloud-Base-Generic-43-1.6.x86_64.qcow2|https://download.fedoraproject.org/pub/fedora/linux/releases/43/Cloud/x86_64/images/Fedora-Cloud-43-1.6-x86_64-CHECKSUM|sha256||32|fedora43|qemu-guest-agent
rocky10|rocky|rhel|10|Rocky Linux 10 (GenericCloud)|https://dl.rockylinux.org/pub/rocky/10/images/x86_64/Rocky-10-GenericCloud-Base.latest.x86_64.qcow2|https://dl.rockylinux.org/pub/rocky/10/images/x86_64/Rocky-10-GenericCloud-Base.latest.x86_64.qcow2.CHECKSUM|sha256||32|rocky10 rocky9|qemu-guest-agent
rocky9|rocky|rhel|9|Rocky Linux 9 (GenericCloud)|https://dl.rockylinux.org/pub/rocky/9/images/x86_64/Rocky-9-GenericCloud-Base.latest.x86_64.qcow2|https://dl.rockylinux.org/pub/rocky/9/images/x86_64/Rocky-9-GenericCloud-Base.latest.x86_64.qcow2.CHECKSUM|sha256||32|rocky9|qemu-guest-agent
alma10|alma|rhel|10|AlmaLinux 10 (GenericCloud)|https://repo.almalinux.org/almalinux/10/cloud/x86_64/images/AlmaLinux-10-GenericCloud-latest.x86_64.qcow2|https://repo.almalinux.org/almalinux/10/cloud/x86_64/images/CHECKSUM|sha256||32|almalinux10 almalinux9|qemu-guest-agent
alma9|alma|rhel|9|AlmaLinux 9 (GenericCloud)|https://repo.almalinux.org/almalinux/9/cloud/x86_64/images/AlmaLinux-9-GenericCloud-latest.x86_64.qcow2|https://repo.almalinux.org/almalinux/9/cloud/x86_64/images/CHECKSUM|sha256||32|almalinux9|qemu-guest-agent
oracle10|oracle|rhel|10|Oracle Linux 10 (KVM template)|https://yum.oracle.com/templates/OracleLinux/OL10/u1/x86_64/OL10U1_x86_64-kvm-b291.qcow2|https://yum.oracle.com/oracle-linux-templates.html|sha256|8e59326c4bf7cfa58a6cac404db8ed583fe3a5f4c460e2b73c64988785bb4f0f|40|ol10.0 ol9.4|qemu-guest-agent kernel-uek-modules
oracle9|oracle|rhel|9|Oracle Linux 9 (KVM template)|https://yum.oracle.com/templates/OracleLinux/OL9/u8/x86_64/OL9U8_x86_64-kvm-b293.qcow2|https://yum.oracle.com/oracle-linux-templates.html|sha256|b12103391327abee8090686759c0d62dac9a7af2bf0f45fdf6b0d085a0fbb52b|40|ol9.4|qemu-guest-agent kernel-uek-modules
leap16|opensuse|suse|16.0|openSUSE Leap 16.0 (Minimal VM, Cloud)|https://download.opensuse.org/distribution/leap/16.0/appliances/Leap-16.0-Minimal-VM.x86_64-Cloud.qcow2|https://download.opensuse.org/distribution/leap/16.0/appliances/Leap-16.0-Minimal-VM.x86_64-Cloud.qcow2.sha256|sha256||32|opensuse16.0|qemu-guest-agent
arch|arch|arch|rolling|Arch Linux (rolling)|https://geo.mirror.pkgbuild.com/images/latest/Arch-Linux-x86_64-cloudimg.qcow2|https://geo.mirror.pkgbuild.com/images/latest/Arch-Linux-x86_64-cloudimg.qcow2.SHA256|sha256||32|archlinux|qemu-guest-agent
'

IMAGE_IDS=()
declare -A I_DISTRO I_FAMILY I_VERSION I_NAME I_URL I_SUMURL I_ALGO I_PINNED I_DISK I_OSINFO I_PACKAGES

load_catalog() {
    local id distro family version name url sumurl algo pinned disk osinfo packages
    while IFS='|' read -r id distro family version name url sumurl algo pinned disk osinfo packages; do
        [[ -z $id ]] && continue
        IMAGE_IDS+=("$id")
        I_DISTRO[$id]=$distro I_FAMILY[$id]=$family I_VERSION[$id]=$version I_NAME[$id]=$name
        I_URL[$id]=$url I_SUMURL[$id]=$sumurl I_ALGO[$id]=$algo I_PINNED[$id]=$pinned
        I_DISK[$id]=$disk I_OSINFO[$id]=$osinfo I_PACKAGES[$id]=$packages
    done <<<"$CATALOG"
}

# The optional gold features - Get-LinuxGoldFeatureCatalog, same ids, same labels.
# id|label|images it applies to (empty = all)
FEATURES='
aliases|Shell aliases|
prompt|Coloured prompt|
fastfetch|fastfetch at login|
quietmotd|Quiet SSH login|ubuntu2604 ubuntu2404 debian13 debian12 rocky10 rocky9
yay|yay (AUR helper)|arch
ilovecandy|Pac-Man progress bar and colour|arch
'
FEATURE_IDS=()
declare -A F_LABEL F_IMAGES
load_features() {
    local id label images
    while IFS='|' read -r id label images; do
        [[ -z $id ]] && continue
        FEATURE_IDS+=("$id"); F_LABEL[$id]=$label; F_IMAGES[$id]=$images
    done <<<"$FEATURES"
}

feature_applies() { # feature image
    local images=${F_IMAGES[$1]}
    [[ -z $images || " $images " == *" $2 "* ]]
}

# ---------------------------------------------------------------------------------
# Family profiles - Get-LinuxFamilyProfile, less what only Hyper-V needed
# ---------------------------------------------------------------------------------

admin_group() { [[ $1 == debian ]] && echo sudo || echo wheel; }

package_probe() { # family "pkg pkg"
    case $1 in
        debian) echo "for p in $2; do if dpkg -s \$p 2>/dev/null | grep -q \"^Status: install ok installed\"; then echo BAKE-PKG \$p ok; else echo BAKE-PKG \$p MISSING; fi; done" ;;
        arch)   echo "for p in $2; do if pacman -Q \$p >/dev/null 2>&1; then echo BAKE-PKG \$p ok; else echo BAKE-PKG \$p MISSING; fi; done" ;;
        *)      echo "for p in $2; do if rpm -q \$p >/dev/null 2>&1; then echo BAKE-PKG \$p ok; else echo BAKE-PKG \$p MISSING; fi; done" ;;
    esac
}

# The kernel the GOLD will boot, which after an upgrade is not the one the bake runs.
kernel_report() {
    case $1 in
        arch) cat <<'EOF'
k=$(pacman -Q linux 2>/dev/null | cut -d" " -f2); [ -n "$k" ] || k=$(uname -r); echo BAKE-KERNEL $k
EOF
        ;;
        rhel) cat <<'EOF'
k=$(grubby --default-kernel 2>/dev/null); case "$k" in */vmlinuz-?*) k=${k##*/vmlinuz-} ;; *) k=$(uname -r) ;; esac; echo BAKE-KERNEL $k
EOF
        ;;
        *) cat <<'EOF'
v=$(readlink /boot/vmlinuz 2>/dev/null); case "$v" in vmlinuz-?*) v=${v#vmlinuz-} ;; *) v=$(uname -r) ;; esac; echo BAKE-KERNEL $v
EOF
        ;;
    esac
}

# What cloud-init rendered for the bake's network, which must not reach a VM.
network_artifacts() {
    case $1 in
        arch) echo "/etc/netplan/50-cloud-init.yaml /etc/systemd/network/10-cloud-init-*.network" ;;
        suse) echo "/etc/NetworkManager/system-connections/cloud-init-*.nmconnection /etc/NetworkManager/conf.d/99-cloud-init.conf" ;;
        rhel) echo "/etc/NetworkManager/system-connections/cloud-init-*.nmconnection /etc/NetworkManager/conf.d/99-cloud-init.conf /etc/sysconfig/network-scripts/ifcfg-*" ;;
        *)    echo "/etc/netplan/50-cloud-init.yaml" ;;
    esac
}

# The package a language needs to exist on the gold, or nothing. Ubuntu splits
# translations into language-pack-*, the RHEL family has no locale-gen and needs the
# glibc langpack, openSUSE has one package for all of them, Debian and Arch generate.
language_pack() { # image "de_DE.UTF-8"
    local id=$1 lang=${2%%_*}
    lang=${lang%%.*}
    [[ -z $lang || $lang == en || $lang == C || $lang == POSIX ]] && return
    case ${I_FAMILY[$id]} in
        rhel) echo "glibc-langpack-$lang" ;;
        suse) echo "glibc-locale" ;;
        debian) [[ ${I_DISTRO[$id]} == ubuntu ]] && echo "language-pack-$lang" ;;
    esac
}

# fastfetch: the title takes the logo's colour, and the logo is padded down to sit
# centred on the box - the heights are the ones measured for New-Vhdx.ps1.
title_color() {
    case $1 in
        ubuntu|debian|oracle) echo "1;31" ;;
        fedora|alma) echo "1;34" ;;
        rocky|opensuse) echo "1;32" ;;
        arch) echo "1;36" ;;
        *) echo "1" ;;
    esac
}
logo_padding() {
    case $1 in
        debian) echo 3 ;; oracle) echo 6 ;; ubuntu|alma) echo 1 ;; *) echo 2 ;;
    esac
}

# ---------------------------------------------------------------------------------
# Bake cloud-config
# ---------------------------------------------------------------------------------

UD=()
ud() { UD+=("$@"); }
# A command for runcmd/bootcmd, read from stdin so it can be written as plain shell.
ud_cmd() { local c; c=$(cat); UD+=("  - [ sh, -c, $(sq "$c") ]"); }

# Settings the bake reads (set by the menus).
FEAT=()                 # ticked feature ids
APPLY_UPDATES=1
REGION_MODE=image       # image | host
R_LANG="" R_LOCALE="" R_KEYMAP="" R_VARIANT="" R_CONSOLE="" R_TZ=""

has_feature() { # feature image
    local f
    for f in "${FEAT[@]}"; do
        [[ $f == "$1" ]] && feature_applies "$1" "$2" && return 0
    done
    return 1
}

bake_user_data() { # image
    local id=$1
    local distro=${I_DISTRO[$id]} family=${I_FAMILY[$id]}
    local want_region=0 p
    [[ $REGION_MODE == host && -n $R_LANG ]] && want_region=1

    # Same list-building as Get-BakeUserData: the image's own packages, what the
    # region needs, what the ticked features need - one install, one probe.
    local packages=() ff_github=0
    for p in ${I_PACKAGES[$id]}; do packages+=("$p"); done
    if ((want_region)); then
        # Debian's genericcloud image has no keyboard machinery at all, so the
        # keymap would silently do nothing without these.
        [[ $distro == debian && -n $R_KEYMAP ]] && packages+=(kbd console-setup keyboard-configuration)
        p=$(language_pack "$id" "$R_LANG"); [[ -n $p ]] && packages+=("$p")
        p=$(language_pack "$id" "$R_LOCALE"); [[ -n $p ]] && packages+=("$p")
    fi
    if has_feature fastfetch "$id"; then
        # Debian 12 has fastfetch in no repository it can use - it comes from the
        # GitHub release in runcmd, and curl with it.
        if [[ $id == debian12 ]]; then ff_github=1; packages+=(curl); else packages+=(fastfetch); fi
    fi
    has_feature yay "$id" && packages+=(git base-devel)
    # Unique, order kept.
    local -A seen=(); local uniq=()
    for p in "${packages[@]}"; do [[ -n ${seen[$p]:-} ]] || { seen[$p]=1; uniq+=("$p"); }; done
    packages=("${uniq[@]}")

    UD=()
    ud "#cloud-config"
    # openSUSE puts console=tty0 last, so cloud-init's output never reaches ttyS0 -
    # and ttyS0 is the file this script greps for BAKE-OK.
    [[ $family == suse ]] && ud "output: {all: '| tee -a /var/log/cloud-init-output.log /dev/ttyS0'}"

    # A console login for a bake that stalls (`virsh -c qemu:///session console`).
    # Deleted at the end of the bake - cloud-init clean does not remove users.
    ud "users:" \
       "  - name: bake" \
       "    groups: [$(admin_group "$family")]" \
       "    shell: /bin/bash" \
       "    sudo: 'ALL=(ALL) NOPASSWD:ALL'" \
       "    lock_passwd: false" \
       "chpasswd:" \
       "  expire: false" \
       "  users:" \
       "    - name: bake" \
       "      password: 'bake'" \
       "      type: text"

    if [[ $family == debian ]]; then
        # Bounded apt timeouts, so a dead mirror costs minutes, not an hour.
        ud "apt:" \
           "  conf: |" \
           "    Acquire::http::Timeout \"20\";" \
           "    Acquire::https::Timeout \"20\";" \
           "    Acquire::Retries \"2\";"
        # noble's archive never carried fastfetch; its author's PPA does.
        if has_feature fastfetch "$id" && [[ $id == ubuntu2404 ]]; then
            ud "  sources:" \
               "    fastfetch:" \
               "      source: 'ppa:zhangsongcui3371/fastfetch'"
        fi
    fi

    ud "package_update: true"
    ((APPLY_UPDATES)) && ud "package_upgrade: true"
    if ((${#packages[@]})); then
        ud "packages:"
        for p in "${packages[@]}"; do ud "  - $(sq "$p")"; done
    fi

    # bootcmd: what has to be settled before the package module, which is the first
    # thing in the final stage.
    local boot=()
    case $family in
        rhel) boot+=('printf "\ntimeout=20\nretries=2\n" >> /etc/dnf/dnf.conf') ;;
        # The serial getty hangs ttyS0 up when it starts, and the tee above lost
        # cloud-init's output with it mid-zypper on Hyper-V. This boot only (--runtime);
        # the VMs keep their serial getty, since a KVM VM has a real port behind it.
        suse) boot+=('systemctl mask --runtime --now serial-getty@ttyS0.service') ;;
    esac
    if [[ $distro == oracle ]]; then
        # Root is an LV, which growpart skips outright - partition, PV and LV grown here.
        boot+=('root=$(findmnt -no SOURCE /); case "$root" in /dev/mapper/*) pv=$(pvs --noheadings -o pv_name 2>/dev/null | head -n1 | tr -d " "); part=$(basename "$(readlink -f "$pv")"); disk=$(lsblk -dno PKNAME "/dev/$part"); num=$(cat "/sys/class/block/$part/partition"); growpart "/dev/$disk" "$num"; pvresize "$pv" && lvextend -r -l +100%FREE "$root"; echo BAKE-LVM-ROOT $(lvs --noheadings -o lv_size "$root" 2>/dev/null | tr -d " ") ;; esac')
    fi
    # fastfetch lives in EPEL on the EL rebuilds, and EPEL has to exist before the
    # package module runs.
    if has_feature fastfetch "$id"; then
        case $distro in
            rocky|alma) boot+=('dnf install -y epel-release') ;;
            oracle) boot+=("dnf install -y oracle-epel-release-el${I_VERSION[$id]}") ;;
        esac
    fi
    if ((${#boot[@]})); then
        ud "bootcmd:"
        for p in "${boot[@]}"; do ud_cmd <<<"$p"; done
    fi

    ((want_region)) && [[ -n $R_TZ ]] && ud "timezone: $R_TZ"

    # One write_files key for all of them - a second one is a YAML error, not a merge.
    if ((want_region)) || has_feature aliases "$id" || has_feature fastfetch "$id" || has_feature prompt "$id"; then
        ud "write_files:"
    fi
    if ((want_region)); then
        # The locale is the gold's; cloud-init's locale module would re-apply its own
        # idea of it on every VM's first boot.
        ud "  - path: /etc/cloud/cloud.cfg.d/91-hv-studio-locale.cfg" \
           "    permissions: '0644'" \
           "    content: |" \
           "      # Baked by kiln: the locale is the gold's; cloud-init leaves it alone." \
           "      locale: 'false'"
    fi
    if has_feature aliases "$id"; then
        ud "  - path: /etc/profile.d/99-hv-studio-aliases.sh" \
           "    permissions: '0644'" \
           "    content: |" \
           "      # Baked by kiln. Same aliases on every distribution." \
           "      alias ls='ls --color=auto'" \
           "      alias grep='grep --color=auto'" \
           "      alias ll='ls -la'" \
           "      alias la='ls -A'" \
           "      alias ..='cd ..'" \
           "      alias cd..='cd ..'"
    fi
    if has_feature fastfetch "$id"; then
        local tc logo_src=""
        tc=$(title_color "$distro")
        [[ $distro == opensuse ]] && logo_src='"source": "opensuse", '
        ud "  - path: /etc/skel/.config/fastfetch/config.jsonc" \
           "    permissions: '0644'" \
           "    content: |" \
           '      {' \
           "        \"logo\": { ${logo_src}\"padding\": { \"top\": $(logo_padding "$distro") } }," \
           '        "display": { "separator": "  ", "key": { "width": 16 } },' \
           '        "modules": [' \
           '          "break",' \
           "          { \"type\": \"title\", \"color\": { \"user\": \"$tc\", \"at\": \"1\", \"host\": \"$tc\" } }," \
           '          { "type": "custom", "format": "{#90}┌─{#} {#1}System{#} {#90}'"$(repeat '─' 33)"'{#}" },' \
           '          { "type": "os", "key": "{#0;90}│{#0}  {#1;34}OS" },' \
           '          { "type": "kernel", "key": "{#0;90}│{#0}  {#1;34}Kernel" },' \
           '          { "type": "host", "key": "{#0;90}│{#0}  {#1;35}Platform" },' \
           '          { "type": "uptime", "key": "{#0;90}│{#0}  {#1;35}Uptime" },' \
           '          { "type": "packages", "key": "{#0;90}│{#0}  {#1;35}Packages" },' \
           '          { "type": "shell", "key": "{#0;90}│{#0}  {#1;36}Shell" },' \
           '          { "type": "locale", "key": "{#0;90}│{#0}  {#1;36}Locale" },' \
           '          { "type": "datetime", "key": "{#0;90}│{#0}  {#1;36}Time", "format": "{year}-{month-pretty}-{day-pretty} {hour-pretty}:{minute-pretty}" },' \
           '          { "type": "custom", "format": "{#90}├─{#} {#1}Resources{#} {#90}'"$(repeat '─' 30)"'{#}" },' \
           '          { "type": "cpu", "key": "{#0;90}│{#0}  {#1;32}CPU" },' \
           '          { "type": "memory", "key": "{#0;90}│{#0}  {#1;33}Memory" },' \
           '          { "type": "disk", "key": "{#0;90}│{#0}  {#1;33}Disk", "folders": "/" },' \
           '          { "type": "custom", "format": "{#90}├─{#} {#1}Network{#} {#90}'"$(repeat '─' 32)"'{#}" },' \
           '          { "type": "localip", "key": "{#0;90}│{#0}  {#1;31}IP" },' \
           "          { \"type\": \"command\", \"key\": \"{#0;90}│{#0}  {#1;31}Gateway\", \"text\": \"ip route show default 2>/dev/null | awk '{print \$3; exit}'\" }," \
           '          { "type": "dns", "key": "{#0;90}│{#0}  {#1;31}DNS" },' \
           "          { \"type\": \"command\", \"key\": \"{#0;90}│{#0}  {#1;31}Domain\", \"text\": \"d=\$(PATH=\\\"\$PATH:/usr/sbin:/sbin\\\" realm list --name-only 2>/dev/null | head -n 1); if [ -n \\\"\$d\\\" ]; then printf '%s' \\\"\$d\\\"; else printf '\\\\033[2;37mnone\\\\033[0m'; fi\" }," \
           '          { "type": "custom", "format": "{#90}└'"$(repeat '─' 43)"'{#}" },' \
           '          "break",' \
           '          { "type": "colors", "paddingLeft": 2 }' \
           '        ]' \
           '      }'
    fi
    if has_feature prompt "$id"; then
        # Appended, so it is the last word on PS1 in skel's .bashrc.
        ud "  - path: /etc/skel/.bashrc" \
           "    append: true" \
           "    content: |" \
           "      " \
           "      # Baked by kiln. Bold blue path, then a >: green after a command that" \
           "      # succeeded, red after one that did not." \
           '      __hv_prompt() {' \
           '          if [ $? -eq 0 ]; then' \
           '              PS1="\[\e[1;38;2;122;162;247m\]\w\[\e[0m\] \[\e[1;38;2;158;206;106m\]>\[\e[0m\] "' \
           '          else' \
           '              PS1="\[\e[1;38;2;122;162;247m\]\w\[\e[0m\] \[\e[1;38;2;247;118;142m\]>\[\e[0m\] "' \
           '          fi' \
           '      }' \
           '      case "$PROMPT_COMMAND" in' \
           '          *__hv_prompt*) ;;' \
           '          "") PROMPT_COMMAND=__hv_prompt ;;' \
           '          *) PROMPT_COMMAND="$PROMPT_COMMAND; __hv_prompt" ;;' \
           '      esac'
    fi

    ud "runcmd:"
    if ((want_region)); then
        # LANG is the language, the nine LC_* format variables the format locale,
        # LC_MESSAGES left on LANG. How a locale comes to exist is per family.
        local fmt=${R_LOCALE:-$R_LANG} v assigns wanted
        assigns="LANG=$R_LANG"
        for v in LC_TIME LC_NUMERIC LC_MONETARY LC_PAPER LC_MEASUREMENT LC_ADDRESS LC_TELEPHONE LC_NAME LC_IDENTIFICATION; do
            assigns+=" $v=$fmt"
        done
        wanted=$R_LANG; [[ $fmt != "$R_LANG" ]] && wanted+=" $fmt"
        local gen="for l in $wanted; do grep -q \"^\$l UTF-8\" /etc/locale.gen || sed -i \"s/^# *\$l UTF-8/\$l UTF-8/\" /etc/locale.gen; grep -q \"^\$l UTF-8\" /etc/locale.gen || echo \"\$l UTF-8\" >> /etc/locale.gen; done; locale-gen $wanted"
        local conf="localectl set-locale $assigns || printf \"%s\\n\" $assigns > /etc/locale.conf"
        case $family in
            debian) ud_cmd <<<"$gen; update-locale $assigns" ;;
            arch)   ud_cmd <<<"$gen; $conf" ;;
            *)      ud_cmd <<<"$conf" ;;
        esac
        if [[ -n $R_KEYMAP ]]; then
            if [[ $family == debian ]]; then
                # /etc/default/keyboard is the one file on Debian and Ubuntu; localectl
                # there cannot set a console keymap.
                local pair key val
                for pair in "XKBLAYOUT=$R_KEYMAP" "XKBVARIANT=$R_VARIANT"; do
                    key=${pair%%=*} val=${pair#*=}
                    ud_cmd <<<"if grep -q ^$key= /etc/default/keyboard 2>/dev/null; then sed -i s/^$key=.*/$key=$val/ /etc/default/keyboard; else echo $key=$val >> /etc/default/keyboard; fi"
                done
            else
                # Console keymap names differ per image - the first one it has wins.
                local cands=${R_CONSOLE:-$R_KEYMAP}
                ud_cmd <<EOF
k=""; for c in $cands; do if localectl list-keymaps 2>/dev/null | grep -qx "\$c"; then k=\$c; break; fi; done; if [ -n "\$k" ] && localectl set-keymap "\$k"; then echo BAKE-KEYMAP \$k; else echo BAKE-KEYMAP-MISSING ${cands// /,}; fi
EOF
            fi
        fi
        ud_cmd <<EOF
for l in $wanted; do n=\$(echo \$l | sed s/UTF-8/utf8/); if locale -a | grep -qx \$n; then echo BAKE-LOCALE \$l ok; else echo BAKE-LOCALE \$l MISSING; fi; done
EOF
        ud_cmd <<'EOF'
echo BAKE-REGION $(grep -h -E "^(LANG|LC_TIME)=" /etc/default/locale /etc/locale.conf 2>/dev/null | sort -u | tr "\n" " ") TZ=$(readlink /etc/localtime | sed "s#.*zoneinfo/##") KEYMAP=$(sed -n "s/^XKBLAYOUT=//p" /etc/default/keyboard 2>/dev/null | tr -d \"; [ -f /etc/default/keyboard ] || localectl status 2>/dev/null | sed -n "s/.*VC Keymap: //p")
EOF
    fi
    ud_cmd <<<"$(kernel_report "$family")"
    ud_cmd <<<'echo BAKE-RUNNING-KERNEL $(uname -r)'
    if ((ff_github)); then
        ud_cmd <<'EOF'
curl -fsSL -o /tmp/fastfetch.deb https://github.com/fastfetch-cli/fastfetch/releases/latest/download/fastfetch-linux-amd64.deb && DEBIAN_FRONTEND=noninteractive apt-get install -y /tmp/fastfetch.deb; rm -f /tmp/fastfetch.deb; if dpkg -s fastfetch >/dev/null 2>&1; then echo BAKE-PKG fastfetch ok; else echo BAKE-PKG fastfetch MISSING; fi
EOF
    fi
    if has_feature ilovecandy "$id"; then
        ud_cmd <<'EOF'
grep -q "^ILoveCandy" /etc/pacman.conf || sed -i "/^\[options\]/a ILoveCandy" /etc/pacman.conf; sed -i "s/^#Color$/Color/" /etc/pacman.conf
EOF
    fi
    if has_feature yay "$id"; then
        # As the bake account: makepkg will not build as root.
        ud_cmd <<'EOF'
runuser -l bake -c "git clone https://aur.archlinux.org/yay-bin.git && cd yay-bin && makepkg -si --noconfirm"; if pacman -Q yay-bin >/dev/null 2>&1; then echo BAKE-PKG yay-bin ok; else echo BAKE-PKG yay-bin MISSING; fi
EOF
    fi
    ((${#packages[@]})) && ud_cmd <<<"$(package_probe "$family" "${packages[*]}")"
    ud_cmd <<<'systemctl enable --now ssh 2>/dev/null || systemctl enable --now sshd 2>/dev/null || true'
    if has_feature aliases "$id"; then
        ud_cmd <<<'grep -q 99-hv-studio-aliases /etc/skel/.bashrc || echo ". /etc/profile.d/99-hv-studio-aliases.sh" >> /etc/skel/.bashrc'
    fi
    if has_feature fastfetch "$id"; then
        # Interactive shells only - a banner in a non-interactive one breaks scp.
        ud_cmd <<'EOF'
grep -q hv-studio-fastfetch /etc/skel/.bashrc || echo 'command -v fastfetch >/dev/null 2>&1 && case $- in *i*) fastfetch; printf "\n\n" ;; esac # hv-studio-fastfetch' >> /etc/skel/.bashrc
EOF
    fi
    if has_feature quietmotd "$id"; then
        if [[ $distro == ubuntu ]]; then
            ud_cmd <<<'sed -i s/^ENABLED=1/ENABLED=0/ /etc/default/motd-news 2>/dev/null || true'
            ud_cmd <<<'chmod -x /etc/update-motd.d/50-motd-news /etc/update-motd.d/91-contract-ua-esm-status /etc/update-motd.d/50-landscape-sysinfo /etc/update-motd.d/90-updates-available /etc/update-motd.d/95-hwe-eol /etc/update-motd.d/10-help-text 2>/dev/null || true'
        fi
        ud_cmd <<<'touch /etc/skel/.hushlogin /root/.hushlogin'
    fi

    # Generalize: the gold must carry no identity of its own.
    ud "  - [ cloud-init, clean, '--logs', '--machine-id' ]"
    ud_cmd <<<'rm -f /etc/ssh/ssh_host_*'
    for p in $(network_artifacts "$family"); do ud_cmd <<<"rm -f $p"; done
    # Rocky 9's ifcfg renderer keeps an existing resolv.conf's servers ahead of the
    # seed's. Emptied only when it is a plain file - on Fedora it is resolved's symlink.
    [[ $family == rhel || $family == suse ]] && ud_cmd <<<'[ -L /etc/resolv.conf ] || : > /etc/resolv.conf'
    ud_cmd <<<'truncate -s 0 /etc/machine-id'
    ud_cmd <<<': > /etc/hostname'
    # The bake's journal sits under its machine-id and would read as the VM's own.
    ud_cmd <<<'journalctl --relinquish-var && rm -rf /var/log/journal/*'
    # Ubuntu 26.04's dracut initrd is hostonly and copied the bake's hostname and
    # machine-id into itself; rebuilt now both are empty.
    if [[ $distro == ubuntu ]]; then
        ud_cmd <<<'if dpkg -s dracut >/dev/null 2>&1; then update-initramfs -u -k all && echo BAKE-INITRD-REBUILT || echo BAKE-INITRD-FAILED; fi'
    fi
    # Fedora's btrfs mount points under the var/home subvolumes stay unlabeled_t
    # forever unless they are labelled from underneath.
    ud_cmd <<'EOF'
if command -v matchpathcon >/dev/null && selinuxenabled 2>/dev/null && [ "$(findmnt -no FSTYPE /)" = btrfs ]; then dev=$(findmnt -no SOURCE / | sed "s/\[.*//"); rs=$(findmnt -no FSROOT /); t=$(mktemp -d); if mount -o subvolid=5 "$dev" "$t"; then findmnt -rn -t btrfs -o TARGET | grep -vx / | while read -r m; do h="$t$rs$m"; [ -d "$h" ] || continue; want=$(matchpathcon -n "$m"); have=$(stat -c %C "$h"); if [ "$have" != "$want" ]; then chcon "$want" "$h" && echo "BAKE-RELABEL $m $have -> $want" || echo "BAKE-RELABEL-FAILED $m"; fi; done; umount "$t"; fi; rmdir "$t"; fi
EOF
    # Last: the diagnostic account, once nothing can need it any more.
    ud_cmd <<<'userdel -f -r bake 2>/dev/null || true'
    ud_cmd <<<'rm -f /etc/sudoers.d/90-cloud-init-users'
    ud_cmd <<<'echo BAKE-OK > /dev/console'
    ud_cmd <<<'echo BAKE-OK > /dev/ttyS0 || true'
    ud "power_state:" "  mode: poweroff" "  timeout: 30" "  condition: true"

    printf '%s\n' "${UD[@]}"
}

# ---------------------------------------------------------------------------------
# Per-VM cloud-config - Get-CloudInitUserData, workgroup only
# ---------------------------------------------------------------------------------

VM_USER="" VM_PASSWORD="" VM_SSHKEY=""

vm_user_data() { # image hostname
    local family=${I_FAMILY[$1]} host=$2
    UD=()
    ud "#cloud-config" \
       "hostname: $host" \
       "preserve_hostname: false" \
       "users:" \
       "  - name: $VM_USER" \
       "    groups: [$(admin_group "$family")]" \
       "    shell: /bin/bash" \
       "    sudo: 'ALL=(ALL) NOPASSWD:ALL'" \
       "    lock_passwd: false"
    if [[ -n $VM_SSHKEY ]]; then
        ud "    ssh_authorized_keys:" "      - $(sq "$VM_SSHKEY")"
    fi
    # In clear, as on Hyper-V: the seed is detached and deleted after this boot, and
    # the scrub below takes cloud-init's own copies of it off the disk.
    ud "chpasswd:" \
       "  expire: false" \
       "  users:" \
       "    - name: $VM_USER" \
       "      password: $(sq "$VM_PASSWORD")" \
       "      type: text" \
       "ssh_pwauth: true" \
       "runcmd:"
    ud_cmd <<'EOF'
find /var/lib/cloud/instances -maxdepth 2 -type f \( -name 'user-data.txt*' -o -name 'cloud-config.txt' -o -name 'vendor-data.txt*' -o -name 'vendor-cloud-config.txt' -o -name 'obj.pkl' \) -delete 2>/dev/null; rm -f /run/cloud-init/instance-data-sensitive.json /var/lib/cloud/instance/scripts/runcmd; echo SEED-SCRUBBED
EOF
    ud "growpart:" "  mode: auto" "  devices: ['/']" "resize_rootfs: true"
    # Powered off when done: that is the signal to take the seed away.
    ud "power_state:" "  mode: poweroff" "  timeout: 30" "  condition: true"
    printf '%s\n' "${UD[@]}"
}

make_seed_iso() { # out.iso dir
    xorriso -as mkisofs -quiet -o "$1" -V cidata -J -r "$2" >/dev/null 2>&1
}

# ---------------------------------------------------------------------------------
# Golds and images
# ---------------------------------------------------------------------------------

# The newest finished gold for an image, or nothing.
current_gold() {
    local f newest=""
    for f in "$GOLD_DIR/$1"-[0-9]*.qcow2; do
        [[ -f $f ]] && newest=$f
    done
    printf '%s' "$newest"
}

# Golds are <image>-<yyyymmdd>-<hhmmss>.qcow2.
gold_date() { # path -> 2026-09-29
    local d=${1##*/}
    d=${d%.qcow2}; d=${d%-*}; d=${d##*-}
    printf '%s-%s-%s' "${d:0:4}" "${d:4:2}" "${d:6:2}"
}

# Pull one file's hash out of a published listing: coreutils `<hash>  <name>` or
# BSD `SHA256 (<name>) = <hash>` (Fedora wraps the latter in a PGP clearsign, whose
# lines match neither and fall through).
checksum_from_listing() { # filename < listing
    awk -v f="$1" '
        { sub(/\r$/, "") }
        /^[A-Za-z0-9]+ \(.*\) = [0-9A-Fa-f]+$/ {
            n = $0; sub(/^[A-Za-z0-9]+ \(/, "", n); sub(/\) = [0-9A-Fa-f]+$/, "", n)
            if (n == f) { print tolower($NF); exit }
            next
        }
        NF >= 2 { n = $2; sub(/^\*/, "", n); if (n == f) { print tolower($1); exit } }'
}

# pacman's ILoveCandy bar: the track he has eaten, him (mouth open on one tick,
# shut on the next), and the dots still ahead - [------C o o o o ].
pacman_bar() { # percent tick
    local width=24 eaten i bar="" c
    eaten=$(($1 * width / 100))
    ((eaten > width)) && eaten=$width
    bar+="$C_DIM$(repeat '-' "$eaten")$C_RESET"
    if ((eaten < width)); then
        (($2 % 2)) && c=c || c=C
        bar+="$C_WARN$c$C_RESET"
        for ((i = eaten + 1; i < width; i++)); do
            ((i % 2)) && bar+=' ' || bar+='o'
        done
    fi
    printf '[%s]' "$bar"
}

# curl in the background while the board line shows how far it got: a bar, the
# megabytes and the speed over the last second. The size comes from a HEAD request
# first (following redirects - Fedora's URL is a mirror redirector); a server that
# sends none just gets megabytes and speed, no bar.
download() { # url file
    local url=$1 out=$2 total pid rc size last=0 speed pct tick=0
    total=$(curl -fsSIL "$url" 2>/dev/null | tr -d '\r' | awk 'tolower($1) == "content-length:" {n = $2} END {print n + 0}')
    curl -fL --retry 3 --retry-delay 5 -sS -o "$out" "$url" 2>>"${JOB_LOG:-/dev/null}" &
    pid=$!
    while kill -0 "$pid" 2>/dev/null; do
        if [[ -n $JOB ]]; then
            size=$(stat -c %s "$out" 2>/dev/null || echo 0)
            speed=$(awk -v b=$((size - last)) 'BEGIN {printf "%.1f", b / 1048576}')
            last=$size
            if ((total > 0)); then
                pct=$((size * 100 / total))
                set_status "$JOB" run "$(printf '%s %3d%%  %d/%d MB  %s MB/s' "$(pacman_bar "$pct" "$tick")" "$pct" $((size / 1048576)) $((total / 1048576)) "$speed")"
            else
                set_status "$JOB" run "downloading $((size / 1048576)) MB  $speed MB/s"
            fi
        fi
        sleep 1; tick=$((tick + 1))
    done
    wait "$pid"; rc=$?
    return $rc
}

# Returns (stdout) the path of a verified copy of the image, downloading when needed.
fetch_image() { # image
    local id=$1 url=${I_URL[$1]} algo=${I_ALGO[$1]}
    local file=${url##*/} expected actual
    local path=$CACHE_DIR/$file
    mkdir -p "$CACHE_DIR"

    if [[ -n ${I_PINNED[$id]} ]]; then
        expected=${I_PINNED[$id]}
    else
        expected=$(curl -fsSL --retry 3 "${I_SUMURL[$id]}" 2>>"${JOB_LOG:-/dev/null}" | checksum_from_listing "$file")
        [[ -z $expected ]] && log warn "No published checksum for $file - the download goes unverified"
    fi

    if [[ -f $path ]]; then
        if [[ -z $expected ]]; then
            log warn "Re-using cached $file without a checksum to check it against"
            printf '%s' "$path"; return 0
        fi
        [[ -n $JOB ]] && set_status "$JOB" run "checking the cached image"
        actual=$("${algo}sum" "$path" | cut -d' ' -f1)
        if [[ $actual == "$expected" ]]; then
            log ok "Cached $file is current"
            printf '%s' "$path"; return 0
        fi
        log info "Cached $file is stale - fetching"
    fi

    # A part file of this process's own: two runs fetching the same image at once
    # would otherwise both write into one.
    local part=$path.part.$BASHPID
    log get "Downloading $url"
    if ! download "$url" "$part"; then
        log error "Download failed: $url"
        rm -f "$part"; return 1
    fi
    if [[ -n $expected ]]; then
        [[ -n $JOB ]] && set_status "$JOB" run "verifying $algo"
        actual=$("${algo}sum" "$part" | cut -d' ' -f1)
        if [[ $actual != "$expected" ]]; then
            log error "$file: checksum mismatch (expected $expected, got $actual)"
            rm -f "$part"; return 1
        fi
        log ok "$file: $algo matches the published checksum"
    fi
    mv -f "$part" "$path"
    printf '%s' "$path"
}

# First osinfo name this virt-install knows, or a generic Linux.
OSINFO_KNOWN=""
resolve_osinfo() {
    local c
    if [[ -z $OSINFO_KNOWN ]]; then
        OSINFO_KNOWN=" $(virt-install --osinfo list 2>/dev/null | tr ',' '\n' | awk '{print $1}' | tr '\n' ' ') "
    fi
    for c in ${I_OSINFO[$1]} linux2024 linux2022; do
        [[ $OSINFO_KNOWN == *" $c "* ]] && { printf '%s' "$c"; return; }
    done
    printf 'generic'
}

# Secure Boot off: no enrolled Microsoft keys on stock OVMF, and Arch has no shim.
UEFI_BOOT="uefi,firmware.feature0.name=secure-boot,firmware.feature0.enabled=no"

# ---------------------------------------------------------------------------------
# Jobs: status files the board reads
# ---------------------------------------------------------------------------------

RUN_DIR=""
set_status() { # job state detail   (state: wait|run|ok|warn|fail)
    local f=$RUN_DIR/status/$1
    [[ -f $f.start || $2 == wait ]] || date +%s >"$f.start"
    printf '%s\t%s\n' "$2" "$3" >"$f.tmp" && mv -f "$f.tmp" "$f"
}

acquire_slot() {
    local i
    while :; do
        for ((i = 1; i <= BAKE_SLOTS; i++)); do
            mkdir "$RUN_DIR/slot.$i" 2>/dev/null && { printf '%s' "$i"; return; }
        done
        sleep 2
    done
}
release_slot() { rmdir "$RUN_DIR/slot.$1" 2>/dev/null; }

bake_gold() { # image
    local id=$1 job="gold-$1"
    JOB_LOG=$RUN_LOG_DIR/$job.log JOB=$job
    local slot src stamp work seed_dir iso serial dom osinfo start state

    set_status "$job" wait "waiting for a bake slot"
    slot=$(acquire_slot)
    set_status "$job" run "fetching ${I_NAME[$id]}"
    if ! src=$(fetch_image "$id"); then
        set_status "$job" fail "download failed"; release_slot "$slot"; return 1
    fi

    stamp=$(date +%Y%m%d-%H%M%S)
    work=$GOLD_DIR/.$id-$stamp.baking.qcow2
    seed_dir=$RUN_DIR/seed-$job
    iso=$RUN_DIR/$job-seed.iso
    serial=$RUN_LOG_DIR/$job.serial.log
    dom=kiln-bake-$id-$stamp
    osinfo=$(resolve_osinfo "$id")

    set_status "$job" run "preparing disk"
    mkdir -p "$GOLD_DIR" "$seed_dir"
    # A full copy, not an overlay on the cache: the gold must outlive a cache cleanup.
    if ! qemu-img convert -O qcow2 "$src" "$work" >>"$JOB_LOG" 2>&1 ||
       ! qemu-img resize -q "$work" "${I_DISK[$id]}G" >>"$JOB_LOG" 2>&1; then
        set_status "$job" fail "qemu-img failed"; rm -f "$work"; release_slot "$slot"; return 1
    fi
    bake_user_data "$id" >"$seed_dir/user-data"
    printf 'instance-id: bake-%s-%s\nlocal-hostname: bake\n' "$id" "$stamp" >"$seed_dir/meta-data"
    cp "$seed_dir/user-data" "$RUN_LOG_DIR/$job.user-data"
    make_seed_iso "$iso" "$seed_dir"

    log run "Baking $id as $dom ($osinfo)"
    if ! virt-install --connect "$SES" --name "$dom" --osinfo "$osinfo" \
            --memory "$BAKE_MEMORY_MB" --vcpus 2 --boot "$UEFI_BOOT" --import \
            --disk "path=$work,bus=virtio" --disk "path=$iso,device=cdrom" \
            --network user,model=virtio --graphics none --serial "file,path=$serial" \
            --noautoconsole >>"$JOB_LOG" 2>&1; then
        set_status "$job" fail "virt-install failed"; rm -f "$work"; release_slot "$slot"; return 1
    fi

    start=$(date +%s)
    while :; do
        state=$(vu domstate "$dom" 2>/dev/null)
        [[ $state == "shut off" || -z $state ]] && break
        if (($(date +%s) - start > BAKE_TIMEOUT_MIN * 60)); then
            log error "$dom did not power off within $BAKE_TIMEOUT_MIN minutes"
            vu destroy "$dom" >/dev/null 2>&1
            break
        fi
        # A phase word from the console, so twenty silent minutes read as progress.
        if grep -aq 'BAKE-OK' "$serial" 2>/dev/null; then set_status "$job" run "powering off"
        elif grep -aq 'BAKE-KERNEL' "$serial" 2>/dev/null; then set_status "$job" run "generalizing"
        elif grep -aq 'modules:final' "$serial" 2>/dev/null; then set_status "$job" run "installing packages"
        elif grep -aq 'Cloud-init' "$serial" 2>/dev/null; then set_status "$job" run "cloud-init running"
        else set_status "$job" run "booting"
        fi
        sleep 5
    done
    vu undefine "$dom" --nvram >/dev/null 2>&1
    rm -rf "$seed_dir" "$iso"
    release_slot "$slot"

    # The BAKE-* lines are the bake's own report - copied into the job log so it can
    # be read without the rest of the console.
    grep -ao 'BAKE-[A-Z-]*.*' "$serial" 2>/dev/null | tr -d '\r' | sed 's/^/    /' >>"$JOB_LOG"

    if ! grep -aq 'BAKE-OK' "$serial" 2>/dev/null; then
        log error "No BAKE-OK on the console - the bake did not finish; see $serial"
        set_status "$job" fail "bake did not finish (serial log)"; rm -f "$work"; return 1
    fi
    if grep -aq 'BAKE-LOCALE .* MISSING' "$serial"; then
        log error "A locale is missing on the gold; see $serial"
        set_status "$job" fail "locale missing on gold"; rm -f "$work"; return 1
    fi

    local final=$GOLD_DIR/$id-$stamp.qcow2 missing kernel
    mv -f "$work" "$final"
    chmod 0444 "$final"
    missing=$(grep -aoE 'BAKE-PKG [^ ]+ MISSING' "$serial" | awk '{print $2}' | sort -u | tr '\n' ' ')
    kernel=$(grep -aoE 'BAKE-KERNEL [^ ]+' "$serial" | tail -n1 | awk '{print $2}' | tr -d '\r')
    {
        printf 'image=%s\nname=%s\nbaked=%s\nsource=%s\nkernel=%s\n' \
            "$id" "${I_NAME[$id]}" "$(date -Is)" "$(basename "$src")" "$kernel"
        printf 'features=%s\nregion=%s\nupdates=%s\n' "${FEAT[*]}" \
            "$([[ $REGION_MODE == host ]] && echo "$R_LANG $R_KEYMAP $R_TZ" || echo image)" "$APPLY_UPDATES"
    } >"$final.txt"
    log ok "Gold ready: $final (kernel $kernel)"
    if [[ -n $missing ]]; then
        log warn "Packages that did not arrive: $missing"
        set_status "$job" warn "gold ready, missing: $missing"
    else
        set_status "$job" ok "gold ready · kernel $kernel"
    fi
}

deploy_vm() { # name image gold
    local name=$1 id=$2 gold=$3 job="vm-$1"
    JOB_LOG=$RUN_LOG_DIR/$job.log JOB=$job
    local disk=$VM_DIR/$name.qcow2 seed=$VM_DIR/$name-seed.iso seed_dir=$RUN_DIR/seed-$job
    local osinfo start state target ip

    set_status "$job" run "creating disk"
    osinfo=$(resolve_osinfo "$id")
    if ! qemu-img create -q -f qcow2 -F qcow2 -b "$gold" "$disk" "${VM_DISK_GB[$id]}G" >>"$JOB_LOG" 2>&1; then
        set_status "$job" fail "qemu-img failed"; return 1
    fi
    mkdir -p "$seed_dir"
    vm_user_data "$id" "$name" >"$seed_dir/user-data"
    # A fresh instance-id per build, so a rebuilt VM of the same name is provisioned.
    printf 'instance-id: %s-%s\nlocal-hostname: %s\n' "$name" "$(date -u +%Y%m%d%H%M%S)" "$name" >"$seed_dir/meta-data"
    make_seed_iso "$seed" "$seed_dir"
    rm -rf "$seed_dir"

    set_status "$job" run "first boot"
    log run "Creating $name from $(basename "$gold") ($osinfo)"
    if ! virt-install --connect "$SYS" --name "$name" --osinfo "$osinfo" \
            --metadata "description=$DESC_TAG image=$id gold=$gold" \
            --memory "$VM_MEMORY_MB" --vcpus "$VM_VCPUS" --boot "$UEFI_BOOT" --import \
            --disk "path=$disk,bus=virtio,discard=unmap" --disk "path=$seed,device=cdrom" \
            --network "network=$VM_NETWORK,model=virtio" --graphics spice \
            --noautoconsole >>"$JOB_LOG" 2>&1; then
        set_status "$job" fail "virt-install failed (see log)"; rm -f "$disk" "$seed"; return 1
    fi

    start=$(date +%s)
    while :; do
        state=$(vs domstate "$name" 2>/dev/null)
        [[ $state == "shut off" ]] && break
        if (($(date +%s) - start > FIRSTBOOT_TIMEOUT_MIN * 60)); then
            log warn "$name did not power off within $FIRSTBOOT_TIMEOUT_MIN minutes; seed left attached at $seed - it holds the password in clear"
            set_status "$job" warn "provisioning did not finish - seed still attached"
            return 1
        fi
        sleep 3
    done

    # The seed holds the password in clear; a provisioned VM has no use for it.
    target=$(vs domblklist "$name" --details 2>/dev/null | awk '$2 == "cdrom" {print $3; exit}')
    if [[ -n $target ]] && vs detach-disk "$name" "$target" --config >>"$JOB_LOG" 2>&1; then
        rm -f "$seed"
        log run "Detached and deleted the seed of $name"
    else
        log warn "Could not detach the seed from $name - it is still at $seed"
    fi

    set_status "$job" run "starting"
    vs start "$name" >>"$JOB_LOG" 2>&1
    start=$(date +%s)
    while (($(date +%s) - start < IP_TIMEOUT_SEC)); do
        set_status "$job" run "waiting for an address"
        ip=$(vs domifaddr "$name" --source lease 2>/dev/null | awk '$3 == "ipv4" {sub(/\/.*/, "", $4); print $4; exit}')
        [[ -z $ip ]] && ip=$(vs domifaddr "$name" --source agent 2>/dev/null | awk '$3 == "ipv4" && $4 !~ /^127\./ {sub(/\/.*/, "", $4); print $4; exit}')
        [[ -n $ip ]] && break
        sleep 3
    done
    printf '%s' "$ip" >"$RUN_DIR/ip-$name"
    if [[ -n $ip ]]; then
        log ok "$name is up at $ip"
        set_status "$job" ok "$ip"
    else
        log warn "$name is running but reported no address"
        set_status "$job" warn "running, no address yet"
    fi
}

# One image: its gold (baked first when it has none, or when a rebake was asked for),
# then its VMs, all at once.
image_chain() { # image bake(0|1) vm...
    local id=$1 bake=$2; shift 2
    local gold vm
    if ((bake)); then
        if ! bake_gold "$id"; then
            for vm in "$@"; do set_status "vm-$vm" fail "no gold"; done
            return 1
        fi
    fi
    gold=$(current_gold "$id")
    for vm in "$@"; do
        if [[ ${I_FAMILY[$id]} == windows ]]; then deploy_windows_vm "$vm" "$id" "$gold" &
        else deploy_vm "$vm" "$id" "$gold" &
        fi
    done
    wait
}

# ---------------------------------------------------------------------------------
# Windows golds
# ---------------------------------------------------------------------------------
#
# New-Vhdx.ps1's pipeline, in the same order, with a WinPE helper VM standing in for
# the Hyper-V host's own DISM (docs/windows-provisioning.md has the why of each step):
#
#   pass 1 (WinPE)  diskpart, DISM apply, bcdboot, the audit-mode answer file
#   audit boot      virtio drivers + guest agent, then sysprep /generalize
#   pass 2 (WinPE)  prove generalize worked, then locale, time zone, policies and the
#                   product key - offline, after generalize, as on Hyper-V
#
# The WinPE is the Setup environment from the ISO's own boot.wim (index 2), started
# into our startnet.cmd instead of setup.exe. It has to be index 2: the bare WinPE at
# index 1 applies images but cannot host DISM's offline servicing session (every
# /Image: call fails with 0x80004002).
#
# WinPE has no way to talk to the host, so each helper VM gets a small raw disk that
# WinPE formats NTFS and writes its log to; the host reads it back with ntfscat.

WIN_PE_TIMEOUT_MIN=30
WIN_AUDIT_TIMEOUT_MIN=45
WIN_FIRSTBOOT_TIMEOUT_MIN=30
WIN_GOLD_GB=64
WIN_BAKE_MEMORY_MB=4096

WIN_IDS=()
declare -A I_SHORT I_LOCALE I_LANGID I_KLID I_TZ

# The KMS client (GVLK) keys Microsoft publishes. AVMA - what the Hyper-V golds carry -
# only activates against a Hyper-V Datacenter host; a GVLK activates against a KMS
# when there is one. Either way the key is what keeps OOBE off its product key page.
# /Set-ProductKey refuses a key from another version, so an unknown pair gets none.
gvlk_key() { # year editionid
    case "$1-$2" in
        2025-ServerDatacenter) echo D764K-2NDRG-47T6Q-P8T8W-YP6DF ;;
        2025-ServerStandard)   echo TVRH6-WHNXV-R9WG3-9XRFY-MY832 ;;
        2022-ServerDatacenter) echo WX4NM-KYWYW-QJJR4-XV3QB-6VM33 ;;
        2022-ServerStandard)   echo VDYBN-27WPP-V4HQT-9VMD4-VMK7H ;;
        2019-ServerDatacenter) echo WMDGN-G9PQG-XVVXX-R3X43-63DFG ;;
        2019-ServerStandard)   echo N69G4-B89J2-4G8F4-WWYCC-J464C ;;
        2016-ServerDatacenter) echo CB7KF-BWN84-R7R2Y-793K2-8XDDG ;;
        2016-ServerStandard)   echo WC2BQ-8NRM3-FDDYY-2BFGV-KHKQY ;;
    esac
}

server_year() { # build
    case $1 in 26100) echo 2025 ;; 20348) echo 2022 ;; 17763) echo 2019 ;; 14393) echo 2016 ;; esac
}

# This machine's region in Windows terms. Small tables on purpose - the common
# cases, with en-US / US / UTC as the fallback the menu shows before anything is
# baked. HyperV-Scripts' data/locales.json has the full catalog.
win_locale() { # de_DE.UTF-8 -> "de-DE 0407"
    local l=${1%%.*}
    l=${l/_/-}
    case $l in
        en-US) echo "en-US 0409" ;; en-GB) echo "en-GB 0809" ;; de-DE) echo "de-DE 0407" ;;
        de-AT) echo "de-AT 0c07" ;; de-CH) echo "de-CH 0807" ;; fr-FR) echo "fr-FR 040c" ;;
        fr-CH) echo "fr-CH 100c" ;; es-ES) echo "es-ES 0c0a" ;; it-IT) echo "it-IT 0410" ;;
        nl-NL) echo "nl-NL 0413" ;; sv-SE) echo "sv-SE 041d" ;; nb-NO) echo "nb-NO 0414" ;;
        da-DK) echo "da-DK 0406" ;; fi-FI) echo "fi-FI 040b" ;; pl-PL) echo "pl-PL 0415" ;;
        pt-PT) echo "pt-PT 0816" ;; pt-BR) echo "pt-BR 0416" ;; cs-CZ) echo "cs-CZ 0405" ;;
        ja-JP) echo "ja-JP 0411" ;;
        *) echo "en-US 0409" ;;
    esac
}

win_keyboard() { # xkb layout, variant -> KLID
    case $1 in
        de|at) echo 00000407 ;; gb) echo 00000809 ;; fr) echo 0000040c ;;
        ch) [[ $2 == fr ]] && echo 0000100c || echo 00000807 ;;
        es) echo 0000040a ;; it) echo 00000410 ;; se) echo 0000041d ;; no) echo 00000414 ;;
        dk) echo 00000406 ;; fi) echo 0000040b ;; pl) echo 00000415 ;; pt) echo 00000816 ;;
        br) echo 00000416 ;; be) echo 0000080c ;; cz) echo 00000405 ;; nl) echo 00020409 ;;
        jp) echo 00000411 ;;
        *) echo 00000409 ;;
    esac
}

win_timezone() { # IANA -> Windows id
    case $1 in
        Europe/Berlin|Europe/Amsterdam|Europe/Vienna|Europe/Zurich|Europe/Rome|Europe/Stockholm|Europe/Oslo|Europe/Luxembourg)
            echo "W. Europe Standard Time" ;;
        Europe/Paris|Europe/Madrid|Europe/Brussels|Europe/Copenhagen) echo "Romance Standard Time" ;;
        Europe/Warsaw|Europe/Zagreb|Europe/Sarajevo) echo "Central European Standard Time" ;;
        Europe/Prague|Europe/Budapest|Europe/Belgrade|Europe/Bratislava) echo "Central Europe Standard Time" ;;
        Europe/London|Europe/Dublin|Europe/Lisbon) echo "GMT Standard Time" ;;
        Europe/Helsinki|Europe/Kiev|Europe/Kyiv|Europe/Riga|Europe/Tallinn|Europe/Vilnius) echo "FLE Standard Time" ;;
        America/New_York) echo "Eastern Standard Time" ;; America/Chicago) echo "Central Standard Time" ;;
        America/Denver) echo "Mountain Standard Time" ;; America/Los_Angeles) echo "Pacific Standard Time" ;;
        Asia/Tokyo) echo "Tokyo Standard Time" ;;
        *) echo "UTC" ;;
    esac
}

# Settings the Windows bake reads (set by the menus).
W_LOCALE=en-US W_LANGID=0409 W_KLID=00000409 W_TZ=UTC
W_FEAT=(rdp ping)
W_ISO="" W_VIRTIO=""
W_INDEXES=()                          # "index|name|edition|type|lang|build" rows picked
declare -A W_ROW                      # index -> the same row, for every index on the ISO

# Every finished Windows gold, from the manifests beside them.
load_windows_golds() {
    local f id k v
    WIN_IDS=()
    for f in "$GOLD_DIR"/*.qcow2.txt; do
        [[ -f $f ]] && grep -qx 'os=windows' "$f" || continue
        id=$(sed -n 's/^image=//p' "$f")
        [[ " ${WIN_IDS[*]} " == *" $id "* ]] || WIN_IDS+=("$id")
        while IFS='=' read -r k v; do
            case $k in
                name) I_NAME[$id]=$v ;; osinfo) I_OSINFO[$id]=$v ;; short) I_SHORT[$id]=$v ;;
                disk) I_DISK[$id]=$v ;; locale) I_LOCALE[$id]=$v ;; langid) I_LANGID[$id]=$v ;;
                klid) I_KLID[$id]=$v ;; tz) I_TZ[$id]=$v ;;
            esac
        done <"$f"
        I_FAMILY[$id]=windows I_DISTRO[$id]=windows
    done
}

# ISOs are loop-mounted through udisks - polkit lets the desktop user do that without
# root - to read install.wim's image list and copy WinPE's boot files.
ISO_DEV="" ISO_MNT=""
iso_mount() { # iso
    local out
    out=$(udisksctl loop-setup -r -f "$1" 2>&1) || { log error "loop-setup $1: $out"; return 1; }
    ISO_DEV=$(sed -n 's/.* as \(\/dev\/loop[0-9]*\)\.$/\1/p' <<<"$out")
    [[ -n $ISO_DEV ]] || return 1
    sleep 1
    # A desktop may auto-mount it first; findmnt answers either way.
    ISO_MNT=$(findmnt -no TARGET "$ISO_DEV" 2>/dev/null | head -n1)
    if [[ -z $ISO_MNT ]]; then
        udisksctl mount -b "$ISO_DEV" >/dev/null 2>&1
        ISO_MNT=$(findmnt -no TARGET "$ISO_DEV" 2>/dev/null | head -n1)
    fi
    [[ -n $ISO_MNT ]]
}
iso_unmount() {
    [[ -n $ISO_DEV ]] || return 0
    udisksctl unmount -b "$ISO_DEV" >/dev/null 2>&1
    udisksctl loop-delete -b "$ISO_DEV" >/dev/null 2>&1
    ISO_DEV="" ISO_MNT=""
}

# install.wim's images as "index|name|editionid|installation type|language|build".
wim_images() { # wim
    wimlib-imagex info "$1" 2>/dev/null | awk -F': *' '
        /^Index:/ { if (i) print i "|" n "|" e "|" t "|" l "|" b; i = $2; n = e = t = l = b = "" }
        /^Name:/ { n = $2 } /^Edition ID:/ { e = $2 } /^Installation Type:/ { t = $2 }
        /^Languages:/ { l = $2; sub(/ +$/, "", l) } /^Build:/ { b = $2 }
        END { if (i) print i "|" n "|" e "|" t "|" l "|" b }'
}

# The gold's id, named the way the Hyper-V studio names it (ws2025-datacenter-core)
# plus the image language, and the short tag VM names use - a Windows computer name
# has fifteen characters, and lab-ws2025-datacenter-desktop-01 is not one.
win_image_id() { # editionid type build lang
    local ed=${1#Server} year kind
    ed=${ed,,}; year=$(server_year "$3")
    [[ $2 == "Server Core" ]] && kind=core || kind=desktop
    printf 'ws%s-%s-%s-%s' "$year" "$ed" "$kind" "${4//-/}" | tr 'A-Z' 'a-z'
}
win_short() { # editionid type build
    local ed year
    case $1 in ServerDatacenter) ed=dc ;; ServerStandard) ed=std ;; *) ed=srv ;; esac
    year=$(server_year "$3")
    printf 'ws%s%s%s' "${year:2}" "$ed" "$([[ $2 == "Server Core" ]] && echo c)"
}

newest_virtio() {
    local d f best=""
    for d in "$CACHE_DIR" "$HOME/ISOs" "$HOME/Downloads"; do
        for f in "$d"/virtio-win*.iso; do [[ -f $f ]] && best+="$f"$'\n'; done
    done
    # Newest by version, whichever folder it is in.
    printf '%s' "$best" | sed '/^$/d' | awk -F/ '{print $NF "\t" $0}' | sort -V | tail -n1 | cut -f2
}

crlf() { sed 's/$/\r/' >"$1"; }

# The WinPE boot ISO for one Windows ISO: its boot files, boot.wim index 2 with our
# startnet.cmd and a winpeshl.ini that runs it instead of Setup, and the ISO's own
# efisys_noprompt.bin so there is no "Press any key to boot from CD". Built once and
# kept beside the cloud images.
winpe_iso() { # mountpoint iso -> path (stdout)
    local out=$CACHE_DIR/winpe-$(basename "$2" .iso).iso d t
    [[ -f $out ]] && { printf '%s' "$out"; return 0; }
    d=$(mktemp -d "$GOLD_DIR/.winpe.XXXXXX") t=$(mktemp -d "$GOLD_DIR/.winpe-files.XXXXXX")
    cp -r "$1/bootmgr" "$1/bootmgr.efi" "$1/boot" "$1/efi" "$d/" && chmod -R u+w "$d" && mkdir -p "$d/sources" || return 1
    crlf "$t/startnet.cmd" <<'EOF'
@echo off
wpeinit
for %%d in (C D E F G H I J K M N O P Q R T U V Y Z) do if exist %%d:\kiln\pe.cmd call %%d:\kiln\pe.cmd %%d: & goto :done
echo kiln: no seed CD found
:done
rem winpeshl restarts WinPE whenever this script ends - a pass that stopped early
rem must power off, not loop.
wpeutil shutdown
EOF
    crlf "$t/winpeshl.ini" <<'EOF'
[LaunchApps]
%SYSTEMROOT%\System32\cmd.exe, /c %SYSTEMROOT%\System32\startnet.cmd
EOF
    if ! wimlib-imagex export "$1/sources/boot.wim" 2 "$d/sources/boot.wim" --boot >/dev/null ||
       ! printf 'add %s /Windows/System32/startnet.cmd\nadd %s /Windows/System32/winpeshl.ini\n' \
            "$t/startnet.cmd" "$t/winpeshl.ini" | wimlib-imagex update "$d/sources/boot.wim" 1 >/dev/null ||
       ! xorriso -as mkisofs -quiet -o "$out.part" -iso-level 3 -J -joliet-long -R -V KILNPE \
            -e efi/microsoft/boot/efisys_noprompt.bin -no-emul-boot "$d" >/dev/null 2>&1; then
        rm -rf "$d" "$t" "$out.part"; return 1
    fi
    rm -rf "$d" "$t"
    mv -f "$out.part" "$out"
    printf '%s' "$out"
}

# The log disk: a raw image the WinPE formats; the host reads files back from it.
logdisk_cat() { # img file [raw]
    local start tmp
    start=$(sfdisk -d "$1" 2>/dev/null | sed -n 's/.*start= *\([0-9]*\).*/\1/p' | head -n1)
    [[ -n $start ]] || return 1
    tmp=$(mktemp "$(dirname "$1")/.logpart.XXXXXX")
    dd if="$1" of="$tmp" bs=512 skip="$start" status=none
    if [[ -n ${3:-} ]]; then ntfscat "$tmp" "$2" 2>/dev/null
    else ntfscat "$tmp" "$2" 2>/dev/null | tr -d '\r'; fi
    rm -f "$tmp"
}

# The files every Windows bake puts on its seed CD. pass is 1 or 2.
win_seed() { # dir pass index key
    local dir=$1/kiln f
    mkdir -p "$dir"
    # The gold's own answer file, written into Panther by pass 2. Its specialize pass
    # runs firstboot.cmd, which hands oobeSystem to the VM's file on the VM's CD -
    # Setup never searches a CD for one after generalize.
        cat >"$dir/gold.xml" <<'EOF'
<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
  <settings pass="specialize">
    <component name="Microsoft-Windows-Deployment" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <RunSynchronous>
        <RunSynchronousCommand wcm:action="add">
          <Order>1</Order>
          <Path>cmd /c C:\Windows\Kiln\firstboot.cmd</Path>
          <Description>Kiln: name the VM, hand oobeSystem to its own answer file</Description>
        </RunSynchronousCommand>
      </RunSynchronous>
    </component>
  </settings>
</unattend>
EOF
    if [[ $2 == 1 ]]; then
        crlf "$dir/pe.cmd" <<EOF
@echo off
rem Kiln WinPE pass 1: partition, apply, boot files, the audit-mode answer file.
rem Disk 0 is the gold, disk 1 the log disk the host reads back.
setlocal
set SEED=%1
set SRC=
for %%d in (C D E F G H I J K M N O P Q R T U V Y Z) do (
    if exist %%d:\\sources\\install.wim set SRC=%%d:\\sources\\install.wim
    if exist %%d:\\sources\\install.esd set SRC=%%d:\\sources\\install.esd
)
(
echo select disk 1
echo clean
echo create partition primary
echo format quick fs=ntfs label=KILNLOG
echo assign letter=L
) > X:\\dp-log.txt
diskpart /s X:\\dp-log.txt > X:\\dp-log.out
if not exist L:\\ goto :eof
set LOG=L:\\pass1.log
echo KILN-PASS1-START %DATE% %TIME% SRC=%SRC% INDEX=$3 >> %LOG%
(
echo select disk 0
echo clean
echo convert gpt
echo create partition efi size=200
echo format quick fs=fat32 label=System
echo assign letter=S
echo create partition msr size=128
echo create partition primary
echo format quick fs=ntfs label=Windows
echo assign letter=W
) > X:\\dp.txt
diskpart /s X:\\dp.txt >> %LOG% 2>&1 || goto :fail
dism /English /Apply-Image /ImageFile:%SRC% /Index:$3 /ApplyDir:W:\\ >> %LOG% 2>&1 || goto :fail
echo KILN-APPLIED %TIME% >> %LOG%
bcdboot W:\\Windows /s S: /f UEFI >> %LOG% 2>&1
rem Judged by the loader being there, not by the exit code - a bcdboot that did
rem nothing once shipped a gold that could not boot.
if not exist S:\\EFI\\Microsoft\\Boot\\bootmgfw.efi goto :fail
echo KILN-BCDBOOT >> %LOG%
rem install.wim can ship this tag, and pass 2 reads it as proof sysprep worked.
if exist W:\\Windows\\System32\\Sysprep\\Sysprep_succeeded.tag del /f /q W:\\Windows\\System32\\Sysprep\\Sysprep_succeeded.tag
mkdir W:\\Windows\\Panther
copy /y %SEED%\\kiln\\audit.xml W:\\Windows\\Panther\\unattend.xml >> %LOG% 2>&1 || goto :fail
echo KILN-PASS1-OK %TIME% >> %LOG%
wpeutil shutdown
goto :eof
:fail
echo KILN-PASS1-FAILED %TIME% >> %LOG%
wpeutil shutdown
EOF
        cat >"$dir/audit.xml" <<'EOF'
<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
  <settings pass="oobeSystem">
    <component name="Microsoft-Windows-Deployment" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <Reseal>
        <Mode>Audit</Mode>
      </Reseal>
    </component>
  </settings>
  <settings pass="auditUser">
    <component name="Microsoft-Windows-Deployment" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <RunSynchronous>
        <RunSynchronousCommand wcm:action="add">
          <Order>1</Order>
          <Path>cmd /c for %d in (D E F G H I J K L M N O P Q R S T U V W Y Z) do @if exist %d:\kiln\audit.cmd %d:\kiln\audit.cmd</Path>
          <Description>Kiln audit step: virtio drivers, guest agent, then generalize</Description>
        </RunSynchronousCommand>
      </RunSynchronous>
    </component>
  </settings>
</unattend>
EOF
        crlf "$dir/audit.cmd" <<'EOF'
@echo off
rem Kiln, audit mode: the gold's first boot, on SATA, with a scratch virtio disk, a
rem virtio NIC (link down - nothing may update between boot and sysprep) and the
rem virtio serial channel attached. Installing the drivers here binds each one to a
rem real device, so viostor ends up a boot-start service and the VMs boot from
rem virtio. auditUser runs once: nothing here may ask for a reboot.
setlocal
set LOG=C:\Windows\Temp\kiln-audit.log
set VIO=
set SEED=
for %%d in (D E F G H I J K L M N O P Q R S T U V W Y Z) do (
    if exist %%d:\pass1.log set LOG=%%d:\audit.log
    if exist %%d:\virtio-win_license.txt set VIO=%%d:
    if exist %%d:\kiln\firstboot.cmd set SEED=%%d:
)
echo KILN-AUDIT-START %DATE% %TIME% VIO=%VIO% SEED=%SEED% >> %LOG%
msiexec /i %VIO%\virtio-win-gt-x64.msi /qn /norestart /l*v C:\Windows\Temp\virtio-win-gt.log
echo KILN-VIRTIO %ERRORLEVEL% >> %LOG%
msiexec /i %VIO%\guest-agent\qemu-ga-x86_64.msi /qn /norestart /l*v C:\Windows\Temp\qemu-ga.log
echo KILN-QGA %ERRORLEVEL% >> %LOG%
sc qc viostor >> %LOG%
mkdir C:\Windows\Kiln
copy /y %SEED%\kiln\firstboot.cmd C:\Windows\Kiln\firstboot.cmd >> %LOG%
echo KILN-SYSPREP-START %TIME% >> %LOG%
rem No /unattend, as in New-Vhdx: a cached answer file that is in use is not replaced
rem by one, so the audit-mode file would survive into the gold. Pass 2 writes the
rem gold's answer file offline instead.
C:\Windows\System32\Sysprep\Sysprep.exe /generalize /oobe /mode:vm /shutdown
EOF
        crlf "$dir/firstboot.cmd" <<'EOF'
@echo off
rem Kiln, a VM's first boot (specialize). Finds the VM's CD, names the machine, points
rem Setup at the VM's own answer file for oobeSystem, and leaves a SetupComplete.cmd
rem whose marker file tells the host provisioning is over.
setlocal
set LOG=C:\Windows\Temp\kiln-firstboot.log
set VM=
for %%d in (D E F G H I J K L M N O P Q R S T U V W Y Z) do if exist %%d:\kiln-vm\unattend.xml set VM=%%d:\kiln-vm
echo KILN-FIRSTBOOT %DATE% %TIME% VM=%VM% >> %LOG%
rem No CD: leave the pointer alone rather than point it at a file that is not there.
if "%VM%"=="" exit /b 0
call %VM%\vm.cmd
reg add "HKLM\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName" /v ComputerName /t REG_SZ /d %KILN_NAME% /f >> %LOG% 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v Hostname /t REG_SZ /d %KILN_NAME% /f >> %LOG% 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "NV Hostname" /t REG_SZ /d %KILN_NAME% /f >> %LOG% 2>&1
rem The file first, then the pointer to it.
copy /y %VM%\unattend.xml C:\Windows\Panther\kiln-vm.xml >> %LOG% 2>&1 || exit /b 0
reg add "HKLM\SYSTEM\Setup" /v UnattendFile /t REG_SZ /d C:\Windows\Panther\kiln-vm.xml /f >> %LOG% 2>&1
if not exist C:\Windows\Setup\Scripts mkdir C:\Windows\Setup\Scripts
(
echo @echo off
echo if not exist C:\ProgramData\Kiln mkdir C:\ProgramData\Kiln
echo echo done^> C:\ProgramData\Kiln\provisioned.txt
) > C:\Windows\Setup\Scripts\SetupComplete.cmd
echo KILN-FIRSTBOOT-OK %KILN_NAME% >> %LOG%
EOF
        return 0
    fi

    # Pass 2: the generalized gold. Everything New-Vhdx does offline after generalize.
    local policies="" fw='HKLM\KSYS\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules'
    for f in "${W_FEAT[@]}"; do
        case $f in
            rdp) policies+="reg add \"HKLM\\KSYS\\ControlSet001\\Control\\Terminal Server\" /v fDenyTSConnections /t REG_DWORD /d 0 /f >> %LOG% 2>&1
reg add \"HKLM\\KSYS\\ControlSet001\\Control\\Terminal Server\\WinStations\\RDP-Tcp\" /v UserAuthentication /t REG_DWORD /d 1 /f >> %LOG% 2>&1
reg add \"$fw\" /v Baked-RDP-TCP-In /t REG_SZ /d \"v2.31|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=3389|Name=Remote Desktop (TCP-In)|Desc=Allow inbound RDP over TCP|EmbedCtxt=Remote Desktop|\" /f >> %LOG% 2>&1
reg add \"$fw\" /v Baked-RDP-UDP-In /t REG_SZ /d \"v2.31|Action=Allow|Active=TRUE|Dir=In|Protocol=17|LPort=3389|Name=Remote Desktop (UDP-In)|Desc=Allow inbound RDP over UDP|EmbedCtxt=Remote Desktop|\" /f >> %LOG% 2>&1
echo KILN-POLICY rdp >> %LOG%
" ;;
            ping) policies+="reg add \"$fw\" /v Baked-ICMPv4-Echo-In /t REG_SZ /d \"v2.31|Action=Allow|Active=TRUE|Dir=In|Protocol=1|ICMP4=8:*|Name=Allow ICMPv4 Echo Request (ping)|Desc=Allow inbound ping IPv4|EmbedCtxt=Ping|\" /f >> %LOG% 2>&1
reg add \"$fw\" /v Baked-ICMPv6-Echo-In /t REG_SZ /d \"v2.31|Action=Allow|Active=TRUE|Dir=In|Protocol=58|ICMP6=128:*|Name=Allow ICMPv6 Echo Request (ping)|Desc=Allow inbound ping IPv6|EmbedCtxt=Ping|\" /f >> %LOG% 2>&1
echo KILN-POLICY ping >> %LOG%
" ;;
            svrmgr) policies+="reg add \"HKLM\\KSOFT\\Policies\\Microsoft\\Windows\\Server\\ServerManager\" /v DoNotOpenAtLogon /t REG_DWORD /d 1 /f >> %LOG% 2>&1
echo KILN-POLICY svrmgr >> %LOG%
" ;;
        esac
    done
    local keyline="echo KILN-NO-KEY >> %LOG%"
    [[ -n $4 ]] && keyline="call :dism /Image:W:\\ /Set-ProductKey:$4 || goto :fail
echo KILN-KEY >> %LOG%"
    crlf "$dir/pe.cmd" <<EOF
@echo off
rem Kiln WinPE pass 2, on the generalized gold: prove generalize worked, then locale,
rem time zone, policies and the product key - offline, after generalize, in the order
rem New-Vhdx.ps1 does them (the key last, once the edition is final).
setlocal
set SEED=%1
(
echo select disk 1
echo clean
echo create partition primary
echo format quick fs=ntfs label=KILNLOG
echo assign letter=L
echo select disk 0
echo select partition 3
echo assign letter=W
) > X:\\dp.txt
diskpart /s X:\\dp.txt > X:\\dp.out
set LOG=L:\\pass2.log
echo KILN-PASS2-START %DATE% %TIME% >> %LOG%
dir W:\\Windows\\System32\\Sysprep >> %LOG% 2>&1
type W:\\Windows\\Setup\\State\\State.ini >> %LOG% 2>&1
rem Sysprep can exit 0 and still fail; the tag and the image state are the proof.
if not exist W:\\Windows\\System32\\Sysprep\\Sysprep_succeeded.tag (echo KILN-NO-SYSPREP-TAG >> %LOG% & goto :fail)
rem ImageState read by cmd itself: this WinPE has no findstr.exe.
set IMGSTATE=
for /f "usebackq tokens=1,* delims==" %%a in ("W:\\Windows\\Setup\\State\\State.ini") do if /i "%%a"=="ImageState" set IMGSTATE=%%b
if /i not "%IMGSTATE%"=="IMAGE_STATE_GENERALIZE_RESEAL_TO_OOBE" (echo KILN-NOT-GENERALIZED %IMGSTATE% >> %LOG% & goto :fail)
echo KILN-GENERALIZED >> %LOG%
call :dism /Image:W:\\ /Set-UserLocale:$W_LOCALE /Set-SysLocale:$W_LOCALE /Set-InputLocale:$W_LANGID:$W_KLID || goto :fail
echo KILN-LOCALE $W_LOCALE $W_LANGID:$W_KLID >> %LOG%
call :dism /Image:W:\\ /Set-TimeZone:"$W_TZ" || goto :fail
echo KILN-TIMEZONE $W_TZ >> %LOG%
reg load HKLM\\KSYS W:\\Windows\\System32\\config\\SYSTEM >> %LOG% 2>&1 || goto :fail
reg load HKLM\\KSOFT W:\\Windows\\System32\\config\\SOFTWARE >> %LOG% 2>&1 || goto :fail
${policies}rem The answer file: whatever audit mode left cached goes, the pointer Setup
rem searches first goes, and the gold's own file takes Panther's place.
reg delete "HKLM\\KSYS\\Setup" /v UnattendFile /f >nul 2>&1
reg unload HKLM\\KSOFT >> %LOG% 2>&1
reg unload HKLM\\KSYS >> %LOG% 2>&1
if exist W:\\Windows\\Panther\\Unattend rmdir /s /q W:\\Windows\\Panther\\Unattend
copy /y %SEED%\\kiln\\gold.xml W:\\Windows\\Panther\\unattend.xml >> %LOG% 2>&1 || goto :fail
if not exist W:\\Windows\\Kiln\\firstboot.cmd (echo KILN-NO-FIRSTBOOT >> %LOG% & goto :fail)
echo KILN-ANSWERFILE >> %LOG%
$keyline
echo KILN-PASS2-OK %TIME% >> %LOG%
wpeutil shutdown
goto :eof
:fail
copy /y W:\\Windows\\System32\\Sysprep\\Panther\\setuperr.log L:\\sysprep-setuperr.log >nul 2>&1
copy /y W:\\Windows\\System32\\Sysprep\\Panther\\setupact.log L:\\sysprep-setupact.log >nul 2>&1
echo KILN-PASS2-FAILED %TIME% >> %LOG%
wpeutil shutdown
goto :eof
:dism
rem Back-to-back DISM sessions can collide on the image's still-mapped hives (exit 87,
rem nothing applied) - two retries, ten seconds apart.
for /l %%i in (1,1,3) do (
    dism /English %* >> %LOG% 2>&1 && exit /b 0
    ping -n 11 127.0.0.1 >nul
)
exit /b 1
EOF
}

# A helper VM under qemu:///session, until it powers off or the timeout runs out.
# The status line shows how far a pass got, from the gold disk's growth.
win_helper_vm() { # job name timeout_min label disk -- virt-install args...
    local job=$1 dom=$2 timeout=$3 label=$4 disk=$5 start state size
    shift 6
    if ! virt-install --connect "$SES" --name "$dom" --osinfo win2k25 \
            --memory "$WIN_BAKE_MEMORY_MB" --vcpus 4 --boot "$UEFI_BOOT" --clock offset=localtime \
            "$@" --graphics vnc --noautoconsole >>"$JOB_LOG" 2>&1; then
        log error "virt-install $dom failed"; return 1
    fi
    start=$(date +%s)
    while :; do
        state=$(vu domstate "$dom" 2>/dev/null)
        [[ $state == "shut off" || -z $state ]] && break
        if (($(date +%s) - start > timeout * 60)); then
            log error "$dom did not power off within $timeout minutes"
            vu destroy "$dom" >/dev/null 2>&1
            vu undefine "$dom" --nvram >/dev/null 2>&1
            return 1
        fi
        size=$(du -BG "$disk" 2>/dev/null | cut -f1)
        set_status "$job" run "$label · gold ${size:-?}"
        sleep 5
    done
    vu undefine "$dom" --nvram >/dev/null 2>&1
    return 0
}

bake_windows_gold() { # iso row pe_iso virtio
    local iso=$1 row=$2 pe=$3 virtio=$4
    local index name ed type lang build id short key year stamp work disk logimg scratch dom slot
    IFS='|' read -r index name ed type lang build <<<"$row"
    id=$(win_image_id "$ed" "$type" "$build" "$lang")
    short=$(win_short "$ed" "$type" "$build")
    year=$(server_year "$build")
    key=$(gvlk_key "$year" "$ed")
    local job="gold-$id"
    JOB_LOG=$RUN_LOG_DIR/$job.log JOB=$job

    set_status "$job" wait "waiting for a bake slot"
    slot=$(acquire_slot)

    # A disk that got through sysprep is kept when pass 2 fails - pass 2 only writes
    # settings, so the next bake of the same image picks it up and starts at pass 2
    # rather than applying and generalizing all over again.
    local resume="" d
    for d in "$GOLD_DIR/.work-$id-"*; do [[ -f $d/generalized ]] && resume=$d; done
    if [[ -n $resume ]]; then
        work=$resume stamp=${resume##*-$id-}
    else
        stamp=$(date +%Y%m%d-%H%M%S)
        work=$GOLD_DIR/.work-$id-$stamp
    fi
    disk=$work/gold.qcow2 logimg=$work/log.img scratch=$work/scratch.qcow2
    dom=kiln-bake-$id-$(date +%Y%m%d-%H%M%S)
    mkdir -p "$work"
    log run "Windows gold $id from $(basename "$iso") index $index ($name, build $build); key: ${key:+GVLK}${key:-none}"

    local sata="bus=sata"
    finish_fail() { # message logfile keep
        [[ -n ${2:-} ]] && logdisk_cat "$logimg" "$2" >"$RUN_LOG_DIR/$job.$2"
        log error "$1"; set_status "$job" fail "$1"
        if [[ -n ${3:-} ]]; then log info "Kept the generalized disk in $work - the next bake of $id resumes at pass 2"
        else rm -rf "$work"; fi
        release_slot "$slot"
    }

    rm -rf "$work/seed2" "$work/seed2.iso"
    win_seed "$work/seed2" 2 "$index" "$key" && make_seed_iso "$work/seed2.iso" "$work/seed2"
    if [[ -n $resume ]]; then
        [[ -f $logimg ]] || qemu-img create -q -f raw "$logimg" 64M
        log info "Resuming at pass 2 with the generalized disk in $work"
    else
    qemu-img create -q -f qcow2 "$disk" "${WIN_GOLD_GB}G" && qemu-img create -q -f raw "$logimg" 64M &&
        qemu-img create -q -f qcow2 "$scratch" 1G || { finish_fail "qemu-img failed"; return 1; }
    win_seed "$work/seed1" 1 "$index" "$key" && make_seed_iso "$work/seed1.iso" "$work/seed1"

    # Pass 1: apply.
    win_helper_vm "$job" "$dom-pe1" "$WIN_PE_TIMEOUT_MIN" "pass 1: apply" "$disk" -- \
        --disk "path=$disk,$sata,boot.order=2" --disk "path=$logimg,format=raw,$sata" \
        --disk "path=$pe,device=cdrom,$sata,boot.order=1" --disk "path=$iso,device=cdrom,$sata" \
        --disk "path=$work/seed1.iso,device=cdrom,$sata" --network none \
        || { finish_fail "pass 1 timed out" pass1.log; return 1; }
    logdisk_cat "$logimg" pass1.log >"$RUN_LOG_DIR/$job.pass1.log"
    grep -q KILN-PASS1-OK "$RUN_LOG_DIR/$job.pass1.log" || { finish_fail "pass 1 failed (apply/bcdboot)"; return 1; }

    # Audit boot: drivers, agent, generalize.
    win_helper_vm "$job" "$dom-audit" "$WIN_AUDIT_TIMEOUT_MIN" "audit: drivers, agent, sysprep" "$disk" -- \
        --disk "path=$disk,$sata,boot.order=1" --disk "path=$logimg,format=raw,$sata" \
        --disk "path=$scratch,bus=virtio" \
        --disk "path=$virtio,device=cdrom,$sata" --disk "path=$work/seed1.iso,device=cdrom,$sata" \
        --network user,model=virtio,link.state=down \
        --channel unix,target.type=virtio,name=org.qemu.guest_agent.0 \
        || { finish_fail "audit boot / sysprep timed out" audit.log; return 1; }
    logdisk_cat "$logimg" audit.log >"$RUN_LOG_DIR/$job.audit.log"
    grep -q KILN-SYSPREP-START "$RUN_LOG_DIR/$job.audit.log" || { finish_fail "audit step did not reach sysprep"; return 1; }
    touch "$work/generalized"
    fi

    # Pass 2: verify, customize, key.
    win_helper_vm "$job" "$dom-pe2" "$WIN_PE_TIMEOUT_MIN" "pass 2: verify, locale, policies, key" "$disk" -- \
        --disk "path=$disk,$sata,boot.order=2" --disk "path=$logimg,format=raw,$sata" \
        --disk "path=$pe,device=cdrom,$sata,boot.order=1" --disk "path=$work/seed2.iso,device=cdrom,$sata" \
        --network none \
        || { finish_fail "pass 2 timed out" pass2.log keep; return 1; }
    logdisk_cat "$logimg" pass2.log >"$RUN_LOG_DIR/$job.pass2.log"
    if ! grep -q KILN-PASS2-OK "$RUN_LOG_DIR/$job.pass2.log"; then
        logdisk_cat "$logimg" sysprep-setuperr.log >"$RUN_LOG_DIR/$job.sysprep-setuperr.log"
        logdisk_cat "$logimg" State.ini raw | iconv -f UTF-16 -t UTF-8 >"$RUN_LOG_DIR/$job.State.ini" 2>/dev/null
        finish_fail "pass 2 failed: $(grep -oE 'KILN-(NO-SYSPREP-TAG|NOT-GENERALIZED|PASS2-FAILED)' "$RUN_LOG_DIR/$job.pass2.log" | head -n1)" "" keep
        return 1
    fi

    local final=$GOLD_DIR/$id-$stamp.qcow2
    mv -f "$disk" "$final" && chmod 0444 "$final"
    local display="Windows Server $year ${ed#Server}$([[ $type == "Server Core" ]] && echo " Core") ($lang)"
    {
        printf 'os=windows\nimage=%s\nname=%s\nshort=%s\nosinfo=win2k%s\ndisk=%s\n' \
            "$id" "$display" "$short" "${year:2}" "$WIN_GOLD_GB"
        printf 'locale=%s\nlangid=%s\nklid=%s\ntz=%s\n' "$W_LOCALE" "$W_LANGID" "$W_KLID" "$W_TZ"
        printf 'source=%s\nindex=%s\nedition=%s\ntype=%s\nbuild=%s\nkey=%s\npolicies=%s\nbaked=%s\n' \
            "$(basename "$iso")" "$index" "$ed" "$type" "$build" "${key:+gvlk}" "${W_FEAT[*]}" "$(date -Is)"
    } >"$final.txt"
    rm -rf "$work"
    release_slot "$slot"
    log ok "Gold ready: $final"
    set_status "$job" ok "gold ready · $W_LOCALE · $W_TZ${key:+ · GVLK}"
}

# ---------------------------------------------------------------------------------
# Windows VMs
# ---------------------------------------------------------------------------------

# base64(UTF-16LE(password + element name)) - what Setup wants for PlainText=false.
win_password() { printf '%s' "$1$2" | iconv -t UTF-16LE | base64 -w0; }
xml_escape() { local s=$1; s=${s//&/&amp;}; s=${s//</&lt;}; s=${s//>/&gt;}; printf '%s' "$s"; }

# The VM's oobeSystem answer file. International-Core echoes the gold's own locale -
# the region page has no hide flag and is only skipped when this answers it.
win_vm_unattend() { # image
    local id=$1 input="${I_LANGID[$1]}:${I_KLID[$1]}" user accounts=""
    user=$(xml_escape "$VM_USER")
    # Built-in Administrator only when that is the name asked for.
    if [[ ${VM_USER,,} != administrator ]]; then
        accounts="
        <LocalAccounts>
          <LocalAccount wcm:action=\"add\">
            <Password>
              <Value>$(win_password "$VM_PASSWORD" Password)</Value>
              <PlainText>false</PlainText>
            </Password>
            <Description>Provisioned local admin</Description>
            <DisplayName>$user</DisplayName>
            <Group>Administrators</Group>
            <Name>$user</Name>
          </LocalAccount>
        </LocalAccounts>"
    fi
    cat <<EOF
<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
  <settings pass="oobeSystem">
    <component name="Microsoft-Windows-International-Core" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <InputLocale>$input</InputLocale>
      <SystemLocale>${I_LOCALE[$id]}</SystemLocale>
      <UserLocale>${I_LOCALE[$id]}</UserLocale>
    </component>
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <TimeZone>${I_TZ[$id]}</TimeZone>
      <UserAccounts>
        <AdministratorPassword>
          <Value>$(win_password "$VM_PASSWORD" AdministratorPassword)</Value>
          <PlainText>false</PlainText>
        </AdministratorPassword>$accounts
      </UserAccounts>
      <OOBE>
        <HideEULAPage>true</HideEULAPage>
        <HideWirelessSetupInOOBE>true</HideWirelessSetupInOOBE>
        <ProtectYourPC>3</ProtectYourPC>
        <VMModeOptimizations>
          <SkipAdministratorProfileRemoval>true</SkipAdministratorProfileRemoval>
          <SkipNotifyUILanguageChange>true</SkipNotifyUILanguageChange>
        </VMModeOptimizations>
      </OOBE>
    </component>
  </settings>
</unattend>
EOF
}

# Does a file exist in the guest? Asked through qemu-guest-agent.
agent_file_exists() { # domain windows-path
    local path=${2//\\/\\\\} r h
    r=$(vs qemu-agent-command "$1" "{\"execute\":\"guest-file-open\",\"arguments\":{\"path\":\"$path\",\"mode\":\"r\"}}" 2>/dev/null) || return 1
    h=$(sed -n 's/.*"return":\([0-9]*\).*/\1/p' <<<"$r")
    [[ -n $h ]] || return 1
    vs qemu-agent-command "$1" "{\"execute\":\"guest-file-close\",\"arguments\":{\"handle\":$h}}" >/dev/null 2>&1
    return 0
}

deploy_windows_vm() { # name image gold
    local name=$1 id=$2 gold=$3 job="vm-$1"
    JOB_LOG=$RUN_LOG_DIR/$job.log JOB=$job
    local disk=$VM_DIR/$name.qcow2 seed=$VM_DIR/$name-seed.iso seed_dir=$RUN_DIR/seed-$job
    local start target ip

    set_status "$job" run "creating disk"
    if ! qemu-img create -q -f qcow2 -F qcow2 -b "$gold" "$disk" "${VM_DISK_GB[$id]}G" >>"$JOB_LOG" 2>&1; then
        set_status "$job" fail "qemu-img failed"; return 1
    fi
    mkdir -p "$seed_dir/kiln-vm"
    win_vm_unattend "$id" >"$seed_dir/kiln-vm/unattend.xml"
    if command -v xmllint >/dev/null && ! xmllint --noout "$seed_dir/kiln-vm/unattend.xml" 2>>"$JOB_LOG"; then
        set_status "$job" fail "answer file is not valid XML"; rm -rf "$seed_dir" "$disk"; return 1
    fi
    printf 'set KILN_NAME=%s\r\n' "$name" >"$seed_dir/kiln-vm/vm.cmd"
    make_seed_iso "$seed" "$seed_dir"
    rm -rf "$seed_dir"

    set_status "$job" run "specialize + OOBE"
    log run "Creating $name from $(basename "$gold")"
    if ! virt-install --connect "$SYS" --name "$name" --osinfo "${I_OSINFO[$id]}" \
            --metadata "description=$DESC_TAG image=$id gold=$gold" \
            --memory "$VM_MEMORY_MB" --vcpus "$VM_VCPUS" --boot "$UEFI_BOOT" --import \
            --clock offset=localtime \
            --disk "path=$disk,bus=virtio,discard=unmap" --disk "path=$seed,device=cdrom" \
            --network "network=$VM_NETWORK,model=virtio" \
            --channel unix,target.type=virtio,name=org.qemu.guest_agent.0 \
            --graphics spice --noautoconsole >>"$JOB_LOG" 2>&1; then
        set_status "$job" fail "virt-install failed (see log)"; rm -f "$disk" "$seed"; return 1
    fi

    # SetupComplete.cmd leaves the marker once Setup is done - the moment the CD, which
    # carries the passwords, can go.
    start=$(date +%s)
    until agent_file_exists "$name" 'C:\ProgramData\Kiln\provisioned.txt'; do
        if (($(date +%s) - start > WIN_FIRSTBOOT_TIMEOUT_MIN * 60)); then
            log warn "$name did not finish provisioning within $WIN_FIRSTBOOT_TIMEOUT_MIN minutes; its CD is still attached at $seed and holds the password"
            set_status "$job" warn "provisioning did not finish - CD still attached"
            return 1
        fi
        sleep 10
    done
    target=$(vs domblklist "$name" --details 2>/dev/null | awk '$2 == "cdrom" {print $3; exit}')
    if [[ -n $target ]] && vs change-media "$name" "$target" --eject --live --config >>"$JOB_LOG" 2>&1; then
        rm -f "$seed"
        log run "Ejected and deleted the CD of $name"
    else
        log warn "Could not eject the CD of $name - it is still at $seed"
    fi

    set_status "$job" run "waiting for an address"
    start=$(date +%s)
    while (($(date +%s) - start < IP_TIMEOUT_SEC)); do
        ip=$(vs domifaddr "$name" --source agent 2>/dev/null | awk '$3 == "ipv4" && $4 !~ /^(127|169\.254)\./ {sub(/\/.*/, "", $4); print $4; exit}')
        [[ -z $ip ]] && ip=$(vs domifaddr "$name" --source lease 2>/dev/null | awk '$3 == "ipv4" {sub(/\/.*/, "", $4); print $4; exit}')
        [[ -n $ip ]] && break
        sleep 3
    done
    printf '%s' "$ip" >"$RUN_DIR/ip-$name"
    if [[ -n $ip ]]; then log ok "$name is up at $ip"; set_status "$job" ok "$ip"
    else log warn "$name is running but reported no address"; set_status "$job" warn "running, no address yet"; fi
}

# ---------------------------------------------------------------------------------
# Board
# ---------------------------------------------------------------------------------

BOARD_JOBS=()
SPIN=(⠋ ⠙ ⠹ ⠸ ⠼ ⠴ ⠦ ⠧ ⠇ ⠏)

board_line() { # job tick
    local job=$1 f=$RUN_DIR/status/$1 state="wait" detail="" icon color el="" s
    [[ -f $f ]] && IFS=$'\t' read -r state detail <"$f"
    if [[ -f $f.start ]]; then
        read -r s <"$f.start"; s=$(($(date +%s) - s))
        el=$(printf '%d:%02d' $((s / 60)) $((s % 60)))
    fi
    case $state in
        run)  icon=${SPIN[$2 % ${#SPIN[@]}]} color=$C_ACCENT ;;
        ok)   icon="✓" color=$C_OK ;;
        warn) icon="!" color=$C_WARN ;;
        fail) icon="✗" color=$C_ERR ;;
        *)    icon="·" color=$C_DIM ;;
    esac
    printf '\e[2K  %s%s%s %-26s %s%6s%s  %s\n' "$color" "$icon" "$C_RESET" "$job" "$C_DIM" "$el" "$C_RESET" "$detail"
}

run_board() { # pid...
    local tick=0 job n=${#BOARD_JOBS[@]} alive pid
    printf '\e[?25l'
    while :; do
        for job in "${BOARD_JOBS[@]}"; do board_line "$job" "$tick"; done
        alive=0
        for pid in "$@"; do kill -0 "$pid" 2>/dev/null && alive=1; done
        ((alive)) || break
        sleep 1; tick=$((tick + 1))
        printf '\e[%dA' "$n"
    done
    printf '\e[?25h'
}

start_run() {
    mkdir -p "$RUN_LOG_DIR"
    RUN_DIR=$(mktemp -d "${XDG_RUNTIME_DIR:-/tmp}/kiln.XXXXXX")
    mkdir -p "$RUN_DIR/status"
    log start "kiln run $RUN_STAMP"
}

cleanup() {
    iso_unmount
    printf '\e[?25h'
    [[ -n $RUN_DIR && -d $RUN_DIR ]] && rm -rf "$RUN_DIR"
}
on_interrupt() {
    printf '\e[?25h\n'
    warn "Interrupted - VMs already created are left as they are; a bake still running"
    warn "is in: virsh -c $SES list"
    # Background jobs of a script ignore SIGINT, so the whole group is told.
    trap '' TERM
    kill -- -$$ 2>/dev/null
    exit 130
}

# ---------------------------------------------------------------------------------
# Menus
# ---------------------------------------------------------------------------------

KEY=""
read_key() {
    local k rest
    IFS= read -rsn1 k </dev/tty || { KEY=quit; return; }
    if [[ $k == $'\e' ]]; then
        IFS= read -rsn2 -t 0.05 rest </dev/tty
        k+=$rest
    fi
    case $k in
        $'\e[A'|k) KEY=up ;;
        $'\e[B'|j) KEY=down ;;
        '') KEY=enter ;;
        ' ') KEY=space ;;
        $'\x7f'|$'\b'|$'\e') KEY=back ;;
        q) KEY=quit ;;
        a) KEY=all ;;
        *) KEY=other ;;
    esac
}

LEGEND_ONE="↑↓ move · Enter pick · Backspace back · q quit"
LEGEND_MANY="↑↓ move · Space tick · a all · Enter confirm · Backspace back"

# Options are "label" or "label|detail". Sets PICK. Returns 1 for back, exits on q.
PICK=0
menu_one() { # title default option...
    local title=$1 cur=$2; shift 2
    local opts=("$@") n=$# i label detail first=1
    printf '\n  %s%s%s\n\n' "$C_BOLD" "$title" "$C_RESET"
    printf '\e[?25l'
    while :; do
        ((first)) || printf '\e[%dA' $((n + 2))
        first=0
        for ((i = 0; i < n; i++)); do
            label=${opts[i]%%|*} detail=""
            [[ ${opts[i]} == *"|"* ]] && detail=${opts[i]#*|}
            if ((i == cur)); then
                printf '\e[2K  %s❯ %s%s  %s%s%s\n' "$C_ACCENT" "$label" "$C_RESET" "$C_DIM" "$detail" "$C_RESET"
            else
                printf '\e[2K    %s  %s%s%s\n' "$label" "$C_DIM" "$detail" "$C_RESET"
            fi
        done
        printf '\e[2K\n\e[2K  %s%s%s\n' "$C_DIM" "$LEGEND_ONE" "$C_RESET"
        read_key
        case $KEY in
            up) cur=$(((cur - 1 + n) % n)) ;;
            down) cur=$(((cur + 1) % n)) ;;
            enter) PICK=$cur; printf '\e[?25h'; return 0 ;;
            back) printf '\e[?25h'; return 1 ;;
            quit) printf '\e[?25h'; exit 0 ;;
        esac
    done
}

# Sets PICKS (indexes). Rows whose label starts with "-" are shown but cannot be ticked.
PICKS=()
menu_many() { # title "preticked indexes" option...
    local title=$1 pre=$2; shift 2
    local opts=("$@") n=$# i cur=0 label detail mark first=1 any
    local -a on=()
    for ((i = 0; i < n; i++)); do on[i]=0; done
    for i in $pre; do on[i]=1; done
    printf '\n  %s%s%s\n\n' "$C_BOLD" "$title" "$C_RESET"
    printf '\e[?25l'
    while :; do
        ((first)) || printf '\e[%dA' $((n + 2))
        first=0
        for ((i = 0; i < n; i++)); do
            label=${opts[i]%%|*} detail=""
            [[ ${opts[i]} == *"|"* ]] && detail=${opts[i]#*|}
            ((on[i])) && mark="${C_OK}[x]${C_RESET}" || mark="[ ]"
            if ((i == cur)); then
                printf '\e[2K  %s❯%s %s %s%s%s  %s%s%s\n' "$C_ACCENT" "$C_RESET" "$mark" "$C_ACCENT" "$label" "$C_RESET" "$C_DIM" "$detail" "$C_RESET"
            else
                printf '\e[2K    %s %s  %s%s%s\n' "$mark" "$label" "$C_DIM" "$detail" "$C_RESET"
            fi
        done
        printf '\e[2K\n\e[2K  %s%s%s\n' "$C_DIM" "$LEGEND_MANY" "$C_RESET"
        read_key
        case $KEY in
            up) cur=$(((cur - 1 + n) % n)) ;;
            down) cur=$(((cur + 1) % n)) ;;
            space) on[cur]=$((1 - on[cur])) ;;
            all)
                any=0; for ((i = 0; i < n; i++)); do ((on[i])) || any=1; done
                for ((i = 0; i < n; i++)); do on[i]=$any; done ;;
            enter)
                PICKS=()
                for ((i = 0; i < n; i++)); do ((on[i])) && PICKS+=("$i"); done
                printf '\e[?25h'; return 0 ;;
            back) printf '\e[?25h'; return 1 ;;
            quit) printf '\e[?25h'; exit 0 ;;
        esac
    done
}

# A line of text. Typing < goes back. Sets TEXT.
TEXT=""
ask_text() { # prompt default
    printf '\n  %s%s%s  %s(Enter keeps the default · < goes back)%s\n' "$C_BOLD" "$1" "$C_RESET" "$C_DIM" "$C_RESET"
    IFS= read -e -r -p "  › " -i "$2" TEXT </dev/tty || exit 0
    [[ $TEXT == "<" ]] && return 1
    return 0
}

declare -A ANS
ANS_ORDER=()
declare -A STEP_LABEL=(
    [step_images]=Images [step_count]=Count [step_size]=Size [step_disk]=Disk
    [step_network]=Network [step_prefix]=Names [step_user]=User [step_password]=Password
    [step_sshkey]="SSH key" [step_features]=Features [step_region]=Region [step_updates]=Updates
    [step_win_iso]=ISO [step_win_indexes]=Editions [step_win_region]=Region [step_win_features]=Features
)
header() {
    local s k
    printf '\e[H\e[2J\n  %sKiln%s  %sLinux golds and VMs on QEMU/KVM%s\n' "$C_BOLD$C_ACCENT" "$C_RESET" "$C_DIM" "$C_RESET"
    printf '  %s%s%s\n' "$C_DIM" "────────────────────────────────────────────" "$C_RESET"
    for s in "${ANS_ORDER[@]}"; do
        k=${STEP_LABEL[$s]:-}
        [[ -n $k && -n ${ANS[$k]:-} ]] && printf '  %s%-10s%s %s\n' "$C_DIM" "$k" "$C_RESET" "${ANS[$k]}"
    done
}

# Runs step functions in order. 0 = next, 1 = back, 3 = does not apply (skipped in
# whichever direction we are going), 4 = input not accepted, ask again.
run_steps() {
    local steps=("$@") i=0 rc dir=1
    ANS_ORDER=()
    while ((i < ${#steps[@]})); do
        ANS_ORDER=("${steps[@]:0:i}")
        header
        "${steps[i]}"; rc=$?
        case $rc in
            0) dir=1; i=$((i + 1)) ;;
            3) i=$((i + dir)) ;;
            4) ;;
            *) dir=-1; i=$((i - 1)) ;;
        esac
        ((i < 0)) && return 1
    done
    return 0
}

# ---------------------------------------------------------------------------------
# Steps
# ---------------------------------------------------------------------------------

SEL_IMAGES=()
NEEDS_BAKE=()
FORCE_BAKE=0
VM_COUNT=1 VM_VCPUS=2 VM_MEMORY_MB=4096 VM_NETWORK=default VM_PREFIX=lab
declare -A VM_DISK_GB

# What the deploy picker offers: the Linux catalog (baked on demand) and every
# Windows gold there is (baked from an ISO, through "Bake Windows golds").
all_ids() { printf '%s\n' "${IMAGE_IDS[@]}" "${WIN_IDS[@]}"; }

image_options() {
    local id g opts=()
    for id in $(all_ids); do
        g=$(current_gold "$id")
        if [[ -n $g ]]; then opts+=("${I_NAME[$id]}|gold $(gold_date "$g")")
        else opts+=("${I_NAME[$id]}|no gold yet - bakes first"); fi
    done
    printf '%s\n' "${opts[@]}"
}

step_images() {
    local opts pre="" i id names=()
    local ids
    mapfile -t opts < <(image_options)
    mapfile -t ids < <(all_ids)
    for ((i = 0; i < ${#ids[@]}; i++)); do
        [[ " ${SEL_IMAGES[*]} " == *" ${ids[i]} "* ]] && pre+=" $i"
    done
    local title="Which images?"
    ((FORCE_BAKE)) && title="Which golds to bake?"
    menu_many "$title" "$pre" "${opts[@]}" || return 1
    ((${#PICKS[@]})) || return 1
    SEL_IMAGES=()
    for i in "${PICKS[@]}"; do SEL_IMAGES+=("${ids[i]}"); names+=("${I_NAME[${ids[i]}]%% (*}"); done
    NEEDS_BAKE=()
    for id in "${SEL_IMAGES[@]}"; do
        [[ ${I_FAMILY[$id]} == windows ]] && continue
        if ((FORCE_BAKE)) || [[ -z $(current_gold "$id") ]]; then NEEDS_BAKE+=("$id"); fi
    done
    ANS[Images]=$(IFS=,; echo "${names[*]}" | sed 's/,/, /g')
}

step_count() {
    menu_one "How many VMs of each?" $((VM_COUNT - 1)) 1 2 3 4 5 6 || return 1
    VM_COUNT=$((PICK + 1))
    ANS[Count]="$VM_COUNT per image"
}

step_size() {
    local cur=1
    case "$VM_VCPUS/$VM_MEMORY_MB" in 1/2048) cur=0 ;; 4/8192) cur=2 ;; 8/16384) cur=3 ;; esac
    menu_one "Size" "$cur" "Small|1 vCPU · 2 GiB" "Medium|2 vCPU · 4 GiB" "Large|4 vCPU · 8 GiB" "X-Large|8 vCPU · 16 GiB" || return 1
    case $PICK in
        0) VM_VCPUS=1 VM_MEMORY_MB=2048 ;;
        1) VM_VCPUS=2 VM_MEMORY_MB=4096 ;;
        2) VM_VCPUS=4 VM_MEMORY_MB=8192 ;;
        3) VM_VCPUS=8 VM_MEMORY_MB=16384 ;;
    esac
    ANS[Size]="$VM_VCPUS vCPU · $((VM_MEMORY_MB / 1024)) GiB"
}

step_disk() {
    local id min=0
    for id in "${SEL_IMAGES[@]}"; do ((I_DISK[$id] > min)) && min=${I_DISK[$id]}; done
    ask_text "Disk size in GiB (at least the gold's own, $min for these)" "${VM_DISK:-$min}" || return 1
    [[ $TEXT =~ ^[0-9]+$ ]] || return 4
    VM_DISK=$TEXT
    # Never smaller than the gold: a qcow2 overlay cannot shrink what it sits on.
    for id in "${SEL_IMAGES[@]}"; do
        VM_DISK_GB[$id]=$VM_DISK
        ((VM_DISK < I_DISK[$id])) && VM_DISK_GB[$id]=${I_DISK[$id]}
    done
    ANS[Disk]="$VM_DISK GiB"
}

step_network() {
    local nets=() n cur=0 i
    mapfile -t nets < <(vs net-list --name 2>/dev/null | sed '/^$/d')
    ((${#nets[@]})) || { warn "No active libvirt network - start one (virsh net-start default)"; exit 1; }
    for ((i = 0; i < ${#nets[@]}; i++)); do [[ ${nets[i]} == "$VM_NETWORK" ]] && cur=$i; done
    local opts=()
    for n in "${nets[@]}"; do
        opts+=("$n|$(vs net-dumpxml "$n" 2>/dev/null | sed -n "s/.*<ip address='\([^']*\)'.*/\1/p" | head -n1)")
    done
    menu_one "Network" "$cur" "${opts[@]}" || return 1
    VM_NETWORK=${nets[PICK]}
    ANS[Network]=$VM_NETWORK
}

step_prefix() {
    ask_text "Name prefix (VMs become <prefix>-<image>-01)" "$VM_PREFIX" || return 1
    [[ $TEXT =~ ^[a-z0-9][a-z0-9-]*$ ]] || return 4
    VM_PREFIX=$TEXT
    ANS[Names]="$VM_PREFIX-<image>-NN"
}

step_user() {
    ask_text "Local user" "${VM_USER:-$USER}" || return 1
    [[ $TEXT =~ ^[a-z_][a-z0-9_-]*$ ]] || return 4
    VM_USER=$TEXT
    ANS[User]=$VM_USER
}

step_password() {
    local gen=""
    # Always upper, lower and a digit - Windows refuses a password without all three.
    until [[ $gen =~ [A-Z] && $gen =~ [a-z] && $gen =~ [0-9] ]]; do
        gen=$(tr -dc 'A-Za-z0-9' </dev/urandom 2>/dev/null | head -c 16)
    done
    ask_text "Password for $VM_USER (the default is a fresh random one)" "${VM_PASSWORD:-$gen}" || return 1
    [[ -n $TEXT ]] || return 4
    VM_PASSWORD=$TEXT
    ANS[Password]="${VM_PASSWORD:0:2}$(printf '%*s' $((${#VM_PASSWORD} - 2)) '' | tr ' ' '*')"
}

step_sshkey() {
    local keys=() k opts=()
    for k in "$HOME"/.ssh/*.pub; do [[ -f $k ]] && keys+=("$k"); done
    for k in "${keys[@]}"; do opts+=("${k/#$HOME/\~}|$(cut -d' ' -f1 "$k")"); done
    opts+=("No key|password only")
    menu_one "SSH key for $VM_USER" 0 "${opts[@]}" || return 1
    if ((PICK < ${#keys[@]})); then
        VM_SSHKEY=$(head -n1 "${keys[PICK]}")
        ANS["SSH key"]=${keys[PICK]/#$HOME/\~}
    else
        VM_SSHKEY=""; ANS["SSH key"]="none"
    fi
}

step_features() {
    ((${#NEEDS_BAKE[@]})) || return 3
    local f opts=() pre="" i=0 id where
    for f in "${FEATURE_IDS[@]}"; do
        where=""
        [[ -n ${F_IMAGES[$f]} ]] && where=$(for id in ${F_IMAGES[$f]}; do printf '%s ' "$id"; done)
        opts+=("${F_LABEL[$f]}|${where:+only on ${where% }}")
        [[ " ${FEAT[*]} " == *" $f "* ]] && pre+=" $i"
        i=$((i + 1))
    done
    menu_many "Gold features (baked into ${#NEEDS_BAKE[@]} new gold(s))" "$pre" "${opts[@]}" || return 1
    FEAT=()
    for i in "${PICKS[@]}"; do FEAT+=("${FEATURE_IDS[i]}"); done
    ANS[Features]=${FEAT[*]:-none}
}

read_host_region() {
    R_LANG=$(localectl status 2>/dev/null | sed -n 's/.*LANG=\([^ ]*\).*/\1/p' | head -n1)
    R_LOCALE=$(sed -n 's/^LC_TIME=//p' /etc/locale.conf 2>/dev/null | tr -d '"')
    R_KEYMAP=$(localectl status 2>/dev/null | sed -n 's/.*X11 Layout: //p' | cut -d, -f1)
    R_VARIANT=$(localectl status 2>/dev/null | sed -n 's/.*X11 Variant: //p' | cut -d, -f1)
    local vc; vc=$(localectl status 2>/dev/null | sed -n 's/.*VC Keymap: //p')
    [[ $vc == "(unset)" || $vc == n/a ]] && vc=""
    R_CONSOLE=$(printf '%s %s' "$vc" "$R_KEYMAP" | xargs -n1 2>/dev/null | awk '!s[$0]++' | xargs)
    R_TZ=$(timedatectl show -p Timezone --value 2>/dev/null)
    [[ -z $R_TZ && -L /etc/localtime ]] && R_TZ=$(readlink /etc/localtime | sed 's#.*zoneinfo/##')
}

step_region() {
    ((${#NEEDS_BAKE[@]})) || return 3
    read_host_region
    local cur=0; [[ $REGION_MODE == image ]] && cur=1
    menu_one "Region of the new gold(s)" "$cur" \
        "This machine's|${R_LANG:-?} · keyboard ${R_KEYMAP:-?}${R_VARIANT:+ ($R_VARIANT)} · ${R_TZ:-?}" \
        "The image's own|usually en_US, us, UTC" || return 1
    if ((PICK == 0)); then REGION_MODE=host; ANS[Region]="$R_LANG · $R_KEYMAP · $R_TZ"
    else REGION_MODE=image; ANS[Region]="image defaults"; fi
}

step_updates() {
    ((${#NEEDS_BAKE[@]})) || return 3
    menu_one "Updates during the bake" $((1 - APPLY_UPDATES)) \
        "Apply all updates|the gold starts current (slower bake)" \
        "Packages only|what the image shipped, plus the bake's packages" || return 1
    APPLY_UPDATES=$((1 - PICK))
    ((APPLY_UPDATES)) && ANS[Updates]="all" || ANS[Updates]="packages only"
}


# ---- Windows bake steps -------------------------------------------------------------

# Every ISO in the usual places that is not a virtio driver disc.
win_iso_candidates() {
    local d f
    for d in "$CACHE_DIR" "$HOME/ISOs" "$HOME/Downloads"; do
        for f in "$d"/*.iso; do
            [[ -f $f ]] || continue
            case ${f##*/} in virtio-win*|winpe-*) continue ;; esac
            printf '%s\n' "$f"
        done
    done
}

step_win_iso() {
    local isos=() f opts=() cur=0 i
    mapfile -t isos < <(win_iso_candidates)
    ((${#isos[@]})) || { warn "No ISO in ${CACHE_DIR/#$HOME/\~}, ~/ISOs or ~/Downloads"; pause; return 1; }
    for ((i = 0; i < ${#isos[@]}; i++)); do
        opts+=("${isos[i]##*/}|$(du -h "${isos[i]}" | cut -f1) · ${isos[i]%/*}")
        [[ ${isos[i]} == "$W_ISO" ]] && cur=$i
    done
    menu_one "Which Windows ISO?" "$cur" "${opts[@]}" || return 1
    iso_unmount
    W_ISO=${isos[PICK]}
    printf '\n  %sReading %s…%s\n' "$C_DIM" "${W_ISO##*/}" "$C_RESET"
    if ! iso_mount "$W_ISO" || [[ ! -f $ISO_MNT/sources/install.wim && ! -f $ISO_MNT/sources/install.esd ]]; then
        iso_unmount; warn "${W_ISO##*/} is not Windows install media"; pause; return 4
    fi
    local wim=$ISO_MNT/sources/install.wim row
    [[ -f $wim ]] || wim=$ISO_MNT/sources/install.esd
    W_ROW=()
    while IFS= read -r row; do W_ROW[${row%%|*}]=$row; done < <(wim_images "$wim")
    ANS[ISO]=${W_ISO##*/}
}

step_win_indexes() {
    local idx rows=() opts=() row name ed type lang build pre=""
    for idx in $(printf '%s\n' "${!W_ROW[@]}" | sort -n); do
        IFS='|' read -r _ name ed type lang build <<<"${W_ROW[$idx]}"
        # Servers only for now: clients need their own OOBE handling and a TPM.
        [[ $type == Server || $type == "Server Core" ]] || continue
        [[ -n $(server_year "$build") ]] || continue
        rows+=("${W_ROW[$idx]}")
        opts+=("$name|index $idx · $lang · $(win_image_id "$ed" "$type" "$build" "$lang")$([[ -n $(current_gold "$(win_image_id "$ed" "$type" "$build" "$lang")") ]] && echo " · has a gold")")
    done
    ((${#rows[@]})) || { warn "No Windows Server index on this ISO"; pause; return 1; }
    menu_many "Which editions?" "" "${opts[@]}" || return 1
    ((${#PICKS[@]})) || return 4
    W_INDEXES=()
    for idx in "${PICKS[@]}"; do W_INDEXES+=("${rows[idx]}"); done
    ANS[Editions]="${#W_INDEXES[@]} picked"
}

step_win_region() {
    read_host_region
    local hl hk ht
    read -r hl _ <<<"$(win_locale "$R_LANG")"
    hk=$(win_keyboard "$R_KEYMAP" "$R_VARIANT"); ht=$(win_timezone "$R_TZ")
    menu_one "Region of the new gold(s)" 0 \
        "This machine's|$hl · keyboard ${R_KEYMAP:-us} ($hk) · $ht" \
        "US defaults|en-US · US keyboard · UTC" || return 1
    if ((PICK == 0)); then
        read -r W_LOCALE W_LANGID <<<"$(win_locale "$R_LANG")"
        W_KLID=$hk W_TZ=$ht
    else
        W_LOCALE=en-US W_LANGID=0409 W_KLID=00000409 W_TZ=UTC
    fi
    ANS[Region]="$W_LOCALE · $W_LANGID:$W_KLID · $W_TZ"
}

WIN_FEATURES=("rdp|Remote Desktop|on, NLA" "ping|Answer ping|ICMPv4 + v6" "svrmgr|Server Manager stays closed at logon|policy")
step_win_features() {
    local opts=() pre="" i f
    for ((i = 0; i < ${#WIN_FEATURES[@]}; i++)); do
        f=${WIN_FEATURES[i]}
        opts+=("${f#*|}")
        [[ " ${W_FEAT[*]} " == *" ${f%%|*} "* ]] && pre+=" $i"
    done
    menu_many "Baked into the gold(s)" "$pre" "${opts[@]}" || return 1
    W_FEAT=()
    for i in "${PICKS[@]}"; do W_FEAT+=("${WIN_FEATURES[i]%%|*}"); done
    ANS[Features]=${W_FEAT[*]:-none}
}

step_win_confirm() {
    W_VIRTIO=$(newest_virtio)
    if [[ -z $W_VIRTIO ]]; then
        warn "No virtio-win ISO in ${CACHE_DIR/#$HOME/\~}, ~/ISOs or ~/Downloads."
        say "Get it from https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/stable-virtio/virtio-win.iso"
        pause; return 1
    fi
    local row ed type build lang
    printf '\n  %sWill bake%s\n' "$C_BOLD" "$C_RESET"
    for row in "${W_INDEXES[@]}"; do
        IFS='|' read -r _ _ ed type lang build <<<"$row"
        printf '    %s  %s%s%s\n' "$(win_image_id "$ed" "$type" "$build" "$lang")" "$C_DIM" \
            "$([[ -n $(gvlk_key "$(server_year "$build")" "$ed") ]] && echo "GVLK" || echo "no key")" "$C_RESET"
    done
    printf '\n  %sDrivers:%s %s\n' "$C_DIM" "$C_RESET" "${W_VIRTIO##*/}"
    menu_one "Go?" 0 "Bake|${#W_INDEXES[@]} gold(s), ~10 min each" "Back" "Cancel" || return 1
    case $PICK in 0) return 0 ;; 1) return 1 ;; *) iso_unmount; exit 0 ;; esac
}

# VM names: <prefix>-<image>-NN, skipping any name libvirt or the disk folder has.
PLAN_VMS=()
declare -A PLAN_IMAGE
plan_names() {
    local id n k name taken
    taken=" $(vs list --all --name 2>/dev/null | tr '\n' ' ') "
    PLAN_VMS=(); PLAN_IMAGE=()
    for id in "${SEL_IMAGES[@]}"; do
        n=1
        for ((k = 0; k < VM_COUNT; k++)); do
            while :; do
                name=$(printf '%s-%s-%02d' "$VM_PREFIX" "${I_SHORT[$id]:-$id}" "$n")
                n=$((n + 1))
                [[ $taken == *" $name "* || -e $VM_DIR/$name.qcow2 ]] || break
            done
            PLAN_VMS+=("$name"); PLAN_IMAGE[$name]=$id
        done
    done
}

step_confirm_deploy() {
    plan_names
    local long
    for long in "${PLAN_VMS[@]}"; do
        if [[ ${I_FAMILY[${PLAN_IMAGE[$long]}]} == windows && ${#long} -gt 15 ]]; then
            warn "$long is longer than a Windows computer name may be (15) - use a shorter prefix"
            pause; return 1
        fi
    done
    local lines=() name
    ((${#NEEDS_BAKE[@]})) && lines+=("Bake first: ${NEEDS_BAKE[*]}")
    printf '\n  %sWill create%s\n' "$C_BOLD" "$C_RESET"
    for name in "${PLAN_VMS[@]}"; do
        printf '    %s  %s%s%s\n' "$name" "$C_DIM" "${I_NAME[${PLAN_IMAGE[$name]}]}" "$C_RESET"
    done
    ((${#NEEDS_BAKE[@]})) && printf '\n  %sBakes first:%s %s\n' "$C_WARN" "$C_RESET" "${NEEDS_BAKE[*]}"
    menu_one "Go?" 0 "Build|${#PLAN_VMS[@]} VM(s)" "Back" "Cancel" || return 1
    case $PICK in 0) return 0 ;; 1) return 1 ;; *) exit 0 ;; esac
}

step_confirm_bake() {
    menu_one "Bake ${#NEEDS_BAKE[@]} gold(s)?" 0 "Bake|${NEEDS_BAKE[*]}" "Back" "Cancel" || return 1
    case $PICK in 0) return 0 ;; 1) return 1 ;; *) exit 0 ;; esac
}

# ---------------------------------------------------------------------------------
# Flows
# ---------------------------------------------------------------------------------

flow_deploy() {
    FORCE_BAKE=0
    load_windows_golds
    run_steps step_images step_count step_size step_disk step_network step_prefix \
              step_user step_password step_sshkey step_features step_region step_updates \
              step_confirm_deploy || return

    start_run
    log info "Deploy: ${PLAN_VMS[*]} on $VM_NETWORK; bake: ${NEEDS_BAKE[*]:-none}; features: ${FEAT[*]:-none}"
    local id bake vms name pids=()
    BOARD_JOBS=()
    for id in "${SEL_IMAGES[@]}"; do
        bake=0; [[ " ${NEEDS_BAKE[*]} " == *" $id "* ]] && bake=1
        vms=()
        for name in "${PLAN_VMS[@]}"; do [[ ${PLAN_IMAGE[$name]} == "$id" ]] && vms+=("$name"); done
        ((bake)) && { BOARD_JOBS+=("gold-$id"); set_status "gold-$id" wait "queued"; }
        for name in "${vms[@]}"; do
            BOARD_JOBS+=("vm-$name")
            set_status "vm-$name" wait "$( ((bake)) && echo "waiting for its gold" || echo queued)"
        done
        image_chain "$id" "$bake" "${vms[@]}" &
        pids+=($!)
    done
    header
    printf '\n'
    run_board "${pids[@]}"
    wait
    summary_deploy
}

flow_bake_windows() {
    run_steps step_win_iso step_win_indexes step_win_region step_win_features step_win_confirm || { iso_unmount; return; }
    start_run
    local pe row pids=() id
    header
    printf '\n  %sPreparing WinPE from %s…%s\n' "$C_DIM" "${W_ISO##*/}" "$C_RESET"
    if ! pe=$(winpe_iso "$ISO_MNT" "$W_ISO"); then
        iso_unmount; fail "Could not build the WinPE boot ISO"; pause; return
    fi
    iso_unmount
    log info "Windows bake from ${W_ISO##*/}: ${#W_INDEXES[@]} gold(s); $W_LOCALE $W_LANGID:$W_KLID $W_TZ; ${W_FEAT[*]}; ${W_VIRTIO##*/}"
    BOARD_JOBS=()
    for row in "${W_INDEXES[@]}"; do
        IFS='|' read -r _ _ ed type lang build <<<"$row"
        id=$(win_image_id "$ed" "$type" "$build" "$lang")
        BOARD_JOBS+=("gold-$id"); set_status "gold-$id" wait "queued"
        bake_windows_gold "$W_ISO" "$row" "$pe" "$W_VIRTIO" &
        pids+=($!)
    done
    header
    printf '\n'
    run_board "${pids[@]}"
    wait
    load_windows_golds
    printf '\n'
    say "Logs: ${RUN_LOG_DIR/#$HOME/\~}"
    pause
}

flow_bake() {
    FORCE_BAKE=1
    run_steps step_images step_features step_region step_updates step_confirm_bake || return
    start_run
    log info "Bake: ${NEEDS_BAKE[*]}; features: ${FEAT[*]:-none}"
    local id pids=()
    BOARD_JOBS=()
    for id in "${NEEDS_BAKE[@]}"; do
        BOARD_JOBS+=("gold-$id"); set_status "gold-$id" wait "queued"
        bake_gold "$id" &
        pids+=($!)
    done
    header
    printf '\n'
    run_board "${pids[@]}"
    wait
    printf '\n'
    say "Logs: ${RUN_LOG_DIR/#$HOME/\~}"
    pause
}

summary_deploy() {
    local name ip state detail any_ok=0
    printf '\n  %sReady%s\n\n' "$C_BOLD" "$C_RESET"
    for name in "${PLAN_VMS[@]}"; do
        ip=""; [[ -f $RUN_DIR/ip-$name ]] && ip=$(<"$RUN_DIR/ip-$name")
        IFS=$'\t' read -r state detail <"$RUN_DIR/status/vm-$name"
        if [[ -n $ip ]]; then
            any_ok=1
            if [[ ${I_FAMILY[${PLAN_IMAGE[$name]}]} == windows ]]; then
                printf '    %s%-24s%s RDP %s  (%s)\n' "$C_OK" "$name" "$C_RESET" "$ip" "$VM_USER"
            else
                printf '    %s%-24s%s ssh %s@%s\n' "$C_OK" "$name" "$C_RESET" "$VM_USER" "$ip"
            fi
        else
            printf '    %s%-24s%s %s\n' "$C_ERR" "$name" "$C_RESET" "$detail"
        fi
    done
    ((any_ok)) && printf '\n  Password for %s: %s%s%s\n' "$VM_USER" "$C_BOLD" "$VM_PASSWORD" "$C_RESET"
    printf '  Consoles: virt-manager, or virsh -c %s console <name>\n' "$SYS"
    say "Logs: ${RUN_LOG_DIR/#$HOME/\~}"
    refresh_pool
    pause
}

# Let virt-manager's storage view see new disks, when the VM folder is a pool.
refresh_pool() {
    local p path
    for p in $(vs pool-list --name 2>/dev/null); do
        path=$(vs pool-dumpxml "$p" 2>/dev/null | sed -n 's:.*<path>\(.*\)</path>.*:\1:p')
        [[ $path == "$VM_DIR" ]] && vs pool-refresh "$p" >/dev/null 2>&1
    done
}

pause() { printf '\n  %sPress any key%s' "$C_DIM" "$C_RESET"; read_key; }

# The lab's VMs: name<TAB>gold, from the description every one of them carries.
lab_vms() {
    local name desc
    for name in $(vs list --all --name 2>/dev/null); do
        desc=$(vs desc "$name" 2>/dev/null)
        [[ $desc == "$DESC_TAG "* ]] || continue
        printf '%s\t%s\n' "$name" "$(sed -n 's/.* gold=//p' <<<"$desc")"
    done
}

flow_remove_vms() {
    ANS_ORDER=(); header
    local rows=() names=() opts=() r name gold state i
    mapfile -t rows < <(lab_vms)
    ((${#rows[@]})) || { say "No lab VMs."; pause; return; }
    for r in "${rows[@]}"; do
        name=${r%%$'\t'*}; gold=${r#*$'\t'}
        state=$(vs domstate "$name" 2>/dev/null)
        names+=("$name"); opts+=("$name|$state · $(basename "$gold")")
    done
    menu_many "Remove which VMs? (disks are deleted)" "" "${opts[@]}" || return
    ((${#PICKS[@]})) || return
    menu_one "Delete ${#PICKS[@]} VM(s) and their disks? This cannot be undone." 1 "Delete" "Cancel" || return
    ((PICK == 0)) || return
    printf '\n'
    local disks d
    for i in "${PICKS[@]}"; do
        name=${names[i]}
        mapfile -t disks < <(vs domblklist "$name" --details 2>/dev/null | awk '$2 == "disk" || $2 == "cdrom" {print $4}')
        [[ $(vs domstate "$name" 2>/dev/null) == "shut off" ]] || vs destroy "$name" >/dev/null 2>&1
        if vs undefine "$name" --nvram >/dev/null 2>&1; then
            # Only files in the VM folder - never a gold, never anything else a disk
            # list might point at.
            for d in "${disks[@]}"; do [[ $d == "$VM_DIR"/* && -f $d ]] && rm -f "$d"; done
            ok "$name removed"
        else
            fail "$name: undefine failed"
        fi
    done
    refresh_pool
    pause
}

flow_remove_golds() {
    ANS_ORDER=(); header
    local used golds=() opts=() g i
    used=$(lab_vms | cut -f2)
    for g in "$GOLD_DIR"/*-[0-9]*.qcow2; do
        [[ -f $g ]] || continue
        grep -qxF "$g" <<<"$used" && continue
        golds+=("$g"); opts+=("$(basename "$g")|$(du -h "$g" | cut -f1)")
    done
    ((${#golds[@]})) || { say "No unused golds - every gold has a VM built on it."; pause; return; }
    menu_many "Remove which unused golds?" "" "${opts[@]}" || return
    ((${#PICKS[@]})) || return
    printf '\n'
    for i in "${PICKS[@]}"; do
        rm -f "${golds[i]}" "${golds[i]}.txt" && ok "$(basename "${golds[i]}") removed"
    done
    pause
}

# ---------------------------------------------------------------------------------
# Preflight and main
# ---------------------------------------------------------------------------------

preflight() {
    local t missing=()
    for t in virsh virt-install qemu-img xorriso curl sha256sum sha512sum awk wimlib-imagex ntfscat udisksctl sfdisk iconv; do
        command -v "$t" >/dev/null || missing+=("$t")
    done
    ((${#missing[@]})) && die "Missing: ${missing[*]}"
    [[ -r /dev/kvm && -w /dev/kvm ]] || die "/dev/kvm is not usable - is KVM enabled, and are you in the kvm group?"
    vs uri >/dev/null 2>&1 || die "Cannot reach $SYS - is libvirtd running, and are you in the libvirt group?"
    vu uri >/dev/null 2>&1 || die "Cannot reach $SES"
    [[ -t 0 && -t 1 ]] || die "Run this in a terminal - the menus need one."
    mkdir -p "$VM_DIR" "$GOLD_DIR" "$CACHE_DIR" || die "Cannot create $VM_DIR / $GOLD_DIR"
}

main() {
    trap cleanup EXIT
    trap on_interrupt INT TERM
    load_catalog
    load_features
    preflight
    load_windows_golds
    while :; do
        ANS_ORDER=(); header
        local golds=0 g
        for g in "$GOLD_DIR"/*-[0-9]*.qcow2; do [[ -f $g ]] && golds=$((golds + 1)); done
        menu_one "What now?" 0 \
            "Deploy VMs|bakes any gold that is missing first" \
            "Bake golds|new Linux golds; existing VMs keep theirs" \
            "Bake Windows golds|from a Windows Server ISO" \
            "Remove VMs|lab VMs and their disks" \
            "Remove golds|$golds gold(s) in ${GOLD_DIR/#$HOME/\~}" \
            "Quit" || exit 0
        case $PICK in
            0) flow_deploy ;;
            1) flow_bake ;;
            2) flow_bake_windows ;;
            3) flow_remove_vms ;;
            4) flow_remove_golds ;;
            *) exit 0 ;;
        esac
        # A fresh run directory and log for the next thing done from this menu.
        [[ -n $RUN_DIR && -d $RUN_DIR ]] && rm -rf "$RUN_DIR"
        RUN_DIR="" RUN_STAMP=$(date +%Y%m%d-%H%M%S) RUN_LOG_DIR=$LOG_ROOT/$RUN_STAMP MAIN_LOG=$RUN_LOG_DIR/kiln.log
    done
}

# Sourcing the file (tests, or reading the generated seeds) defines everything and
# runs nothing.
if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    main "$@"
fi
