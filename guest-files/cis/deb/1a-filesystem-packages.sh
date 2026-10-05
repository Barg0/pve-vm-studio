# shellcheck shell=bash
# CIS Ubuntu 26.04 LTS v1.0.0 - chapter 1 (part a): filesystem kernel modules, /tmp and
# /dev/shm, the separate partitions and their mount options, APT configuration and updates.
# Rules: our own titles; see ../README.md.
#
# Decisions
# - 1.1.1.x: a module built into the kernel (no .ko for it) counts as not available, as the
#   benchmark's audit does. Modules are denied by underscore name in
#   /etc/modprobe.d/pvs-cis-<module>.conf (install /bin/false + blacklist).
# - 1.1.1.6 overlay / 1.1.1.7 squashfs (L2): disabled per CIS. Containers (Docker, LXD, podman)
#   and snaps stop working on L2 clones; snapd's mounts fail (boot is unaffected).
# - 1.1.1.8 udf (L2): disabled. The studio's seeds are FAT disks (vfat) on PVE; a NoCloud ISO
#   (Hyper-V) is iso9660, which stays loadable.
# - 1.1.1.11 (manual): every module under kernel/fs of the installed kernels is denied in
#   /etc/modprobe.d/pvs-cis-unused-fs.conf EXCEPT: root/data fs (ext4 jbd2 mbcache xfs btrfs),
#   seed media (fat vfat isofs), fuse/cuse/virtiofs (PVE virtiofs shares), autofs4,
#   binfmt_misc, quota modules, pstore/efivarfs/configfs, nls, the ones owned by 1.1.1.1-8,
#   anything mounted or loaded at fix time, and PVS_CIS_FS_KEEP (env, space separated). So NFS,
#   CIFS/SMB, ceph, 9p, exfat, ntfs3 ... are off on clones. Check: evidence + review (3).
# - 1.1.2.1.x /tmp: tmpfs via fstab (defaults,rw,nosuid,nodev,noexec,relatime,size=2G,
#   mode=1777); tmp.mount unmasked. Not mounted/remounted during the bake (would hide or
#   noexec files the bake may be using) - effective after the reboot. An existing /tmp fstab
#   entry is kept and only gets the options added. RISK: noexec /tmp breaks installers that
#   execute from /tmp.
# - 1.1.2.2.x /dev/shm: fstab line "tmpfs /dev/shm tmpfs defaults,rw,nosuid,nodev,noexec,relatime
#   0 0"; remounted live (systemd-remount-fs applies it at boot).
# - 1.1.2.3-7 .1 separate partitions (L2): check only, the bake creates the LVM volumes.
#   Mount-option rules: n/a (rc 2) when the path is not its own mount; the fix adds the option
#   to the fstab entry (no entry: nothing to do, rc 0). Live remount for nodev/nosuid only;
#   noexec on /var/tmp waits for the reboot.
# - 1.2.1.1 (manual): verifiable - 0 when every deb line / deb822 stanza has Signed-By, else
#   review with the offending entries. No fix (the Ubuntu sources ship Signed-By).
# - 1.2.1.2 (L2) -> /etc/apt/apt.conf.d/99-pvs-cis-weak-deps; 1.2.1.12-15 ->
#   /etc/apt/apt.conf.d/99-pvs-cis-repositories. Checks read `apt-config dump`.
# - 1.2.1.10/11 https: http:// URIs switched to https:// host by host, each kept only if
#   `apt-get update` then fetches from that host (country mirrors are http only - the studio
#   does not offer them with CIS)
#   (no Err:/E: lines); otherwise the files are restored and the fix fails.
#   RISK: cloud-init regenerates the deb822 sources on a clone's first boot (new instance id)
#   from its template with http:// mirrors - the studio must send `apt: preserve_sources_list:
#   true` (or https primary/security mirrors) in the clone's user-data, or 1.2.1.11 fails there.
# - 1.2.1.3: also covers Signed-By key files outside the standard keyring dirs (multiple keys
#   per option and the trailing "]" of one-line sources are handled; embedded keys skipped).
# - 1.2.2.1 (manual): fix = apt-get update + dist-upgrade (confold). Check runs apt-get update
#   (best effort), 0 when nothing is pending and no reboot is required, else review.
#   1.1.1.11's deny list is computed before this upgrade: a new kernel's extra fs modules (if
#   any) are not covered until the fix runs again.

# ---- chapter helpers ----

# A kernel module is not available: no .ko in the running kernel (built in counts as not
# available, like the benchmark's audit), else denied and not loaded (mod_unavailable).
c1a_mod_check() {
    local m=$1 n=${1//-/_} kver
    kver=$(uname -r)
    if ! find /lib/modules/*/ -type f \( -name "$m.ko*" -o -name "$n.ko*" \) 2>/dev/null | grep -q .; then
        if grep -Eq "/(${m}|${n})\.ko" "/lib/modules/$kver/modules.builtin" 2>/dev/null; then
            ev "$m: built into kernel $kver (not a loadable module)"
        else
            ev "$m: no module in any installed kernel"
        fi
        return 0
    fi
    mod_unavailable "$m"
}

# Deny by the underscore name (what modprobe matches), unload if loaded.
c1a_mod_off() { mod_disable "${1//-/_}"; }

# 0 when fstab has an active entry for MOUNTPOINT.
c1a_fstab_has() {
    awk -v mp="$1" '$1 !~ /^#/ && $2 == mp { f = 1 } END { exit !f }' /etc/fstab 2>/dev/null
}

# Adds OPTs to MOUNTPOINT's fstab entry. No entry: nothing to do (0). Remounts live unless
# REMOUNT=0.
c1a_opts() {
    local mp=$1 o
    shift
    if ! c1a_fstab_has "$mp"; then
        ev "$mp: no fstab entry - not a separate mount, nothing to do"
        return 0
    fi
    for o in "$@"; do
        awk -v mp="$mp" -v o="$o" 'BEGIN { OFS = "\t" }
            $1 !~ /^#/ && $2 == mp { n = split($4, a, ","); h = 0; for (i = 1; i <= n; i++) if (a[i] == o) h = 1; if (!h) $4 = $4 "," o }
            { print }' /etc/fstab > /etc/fstab.pvs-cis || return 1
        cat /etc/fstab.pvs-cis > /etc/fstab && rm -f /etc/fstab.pvs-cis || return 1
    done
    systemctl daemon-reload 2>/dev/null
    if [ "${REMOUNT:-1}" = 1 ] && findmnt -kn "$mp" >/dev/null 2>&1; then
        mount -o remount "$mp" 2>/dev/null
    fi
    return 0
}

# Separate partition: MOUNTPOINT is a mount of its own.
c1a_separate() {
    local line
    line=$(findmnt -kn "$1" 2>/dev/null)
    if [ -n "$line" ]; then
        ev "$line"
        return 0
    fi
    ev "$1: not a separate mount"
    return 1
}

# Effective value of an APT option (apt-config dump), "" when unset.
c1a_apt_val() {
    apt-config dump 2>/dev/null | awk -v k="$1" 'tolower($1) == tolower(k) { v = $2 } END { print v }' \
        | sed -E 's/;$//; s/^"//; s/"$//'
}

# KEY's effective value is one of the |-separated WANT values.
c1a_apt_is() {
    local k=$1 want=$2 have
    have=$(c1a_apt_val "$k")
    ev "$k: ${have:-unset}"
    [ -n "$have" ] && [[ "${have,,}" =~ ^(${want})$ ]]
}

# KEY "VALUE"; into FILE (one line per key).
c1a_apt_set() {
    local f=$1 k=$2 v=$3
    mkdir -p /etc/apt/apt.conf.d
    touch "$f"
    chmod 0644 "$f"
    sed -i "/^[[:space:]]*${k}[[:space:]]/Id" "$f"
    printf '%s "%s";\n' "$k" "$v" >> "$f"
}

C1A_APT_REPO=/etc/apt/apt.conf.d/99-pvs-cis-repositories
C1A_APT_WEAK=/etc/apt/apt.conf.d/99-pvs-cis-weak-deps

# Repository lines still on plain http:// in FILES (.list one-line or .sources deb822).
c1a_http_lines() {
    local f
    for f in "$@"; do
        [ -f "$f" ] || continue
        case $f in
            *.sources) grep -HniE '^[[:space:]]*URIs:.*http://' "$f" ;;
            *) grep -HniE '^[[:space:]]*deb(-src)?[[:space:]]+(\[[^]]*\][[:space:]]+)?http://' "$f" ;;
        esac
    done
    return 0
}

# Switch FILES to https host by host, keeping each switch only if apt-get update fetches from
# that host over https. One host without https (Ubuntu's and Debian's country mirrors serve
# http only) stays on http - and keeps the rule failing - without taking the others back.
c1a_https_fix() {
    local f hosts h out failed=0 esc
    hosts=$(for f in "$@"; do [ -f "$f" ] && c1a_http_lines "$f"; done \
        | grep -oE 'http://[^/[:space:]]+' | sed 's#http://##' | sort -u)
    [ -n "$hosts" ] || return 0
    for h in $hosts; do
        esc=${h//./\\.}
        for f in "$@"; do
            [ -f "$f" ] || continue
            case $f in
                *.sources) sed -i -E "/^[[:space:]]*URIs:/I s#http://${esc}([/[:space:]]|\$)#https://${h}\\1#g" "$f" ;;
                *) sed -i -E "s#^([[:space:]]*deb(-src)?[[:space:]]+(\\[[^]]*\\][[:space:]]+)?)http://${esc}([/[:space:]]|\$)#\\1https://${h}\\4#" "$f" ;;
            esac
        done
        out=$(apt-get update -q 2>&1)
        if grep -E '^(Err|E):' <<<"$out" | grep -qF "$h"; then
            for f in "$@"; do
                [ -f "$f" ] && sed -i -E "s#https://${esc}([/[:space:]]|\$)#http://${h}\\1#g" "$f"
            done
            ev "$h: no https (apt-get update failed) - left on http"
            failed=1
        else
            ev "$h: switched to https"
        fi
    done
    apt-get update -q >/dev/null 2>&1
    return $failed
}

# Signed-By key files named in the source files (absolute, existing), one per line.
c1a_signed_by_files() {
    local tok k
    grep -PRhoi -- '\bSigned-By\b\s*[=:]\s*\K\S+' /etc/apt/sources.list /etc/apt/sources.list.d/*.list \
        /etc/apt/sources.list.d/*.sources 2>/dev/null | sed 's/\]$//' | tr ',' '\n' | sort -u \
        | while IFS= read -r tok; do
            k=$(readlink -e "$tok" 2>/dev/null) || continue
            [ -f "$k" ] && echo "$k"
        done
}

# Key files with more than 0644 or not root:root.
c1a_bad_keys() {
    local k
    find -L /usr/share/keyrings/ /etc/apt/trusted.gpg.d/ -xdev -type f -name '*gpg' \
        \( ! -user root -o ! -group root -o -perm /133 \) 2>/dev/null
    c1a_signed_by_files | while IFS= read -r k; do
        case $k in /usr/share/keyrings/* | /etc/apt/trusted.gpg.d/*) continue ;; esac
        [ "$(stat -Lc '%U:%G' "$k")" = root:root ] && (( (8#$(stat -Lc '%a' "$k") & 8#133) == 0 )) || echo "$k"
    done
}

# Files in DIR beyond MAXMODE or not root:root (-> 1). No files: 0.
c1a_dir_files_ok() {
    local d=$1 max=$2 f bad=0 n=0
    while IFS= read -r -d '' f; do
        n=$((n + 1))
        perm_ok "$f" "$max" root root || bad=1
    done < <(find -L "$d" -mindepth 1 -maxdepth 1 -type f -print0 2>/dev/null)
    [ $n -gt 0 ] || ev "$d: no files"
    return $bad
}

c1a_dir_files_set() {
    local d=$1 max=$2 f
    while IFS= read -r -d '' f; do
        perm_set "$f" "$max" root root
    done < <(find -L "$d" -mindepth 1 -maxdepth 1 -type f -print0 2>/dev/null)
    return 0
}

# ---- 1.1.1 filesystem kernel modules ----

rule kmod-cramfs-unavailable "kmod cramfs unavailable"
check_kmod_cramfs_unavailable() { c1a_mod_check cramfs; }
fix_kmod_cramfs_unavailable() { c1a_mod_off cramfs; }

rule kmod-freevxfs-unavailable "kmod freevxfs unavailable"
check_kmod_freevxfs_unavailable() { c1a_mod_check freevxfs; }
fix_kmod_freevxfs_unavailable() { c1a_mod_off freevxfs; }

rule kmod-hfs-unavailable "kmod hfs unavailable"
check_kmod_hfs_unavailable() { c1a_mod_check hfs; }
fix_kmod_hfs_unavailable() { c1a_mod_off hfs; }

rule kmod-hfsplus-unavailable "kmod hfsplus unavailable"
check_kmod_hfsplus_unavailable() { c1a_mod_check hfsplus; }
fix_kmod_hfsplus_unavailable() { c1a_mod_off hfsplus; }

rule kmod-jffs2-unavailable "kmod jffs2 unavailable"
check_kmod_jffs2_unavailable() { c1a_mod_check jffs2; }
fix_kmod_jffs2_unavailable() { c1a_mod_off jffs2; }

rule kmod-overlay-unavailable "kmod overlay unavailable"
check_kmod_overlay_unavailable() { c1a_mod_check overlay; }
fix_kmod_overlay_unavailable() { c1a_mod_off overlay; }

rule kmod-squashfs-unavailable "kmod squashfs unavailable"
check_kmod_squashfs_unavailable() { c1a_mod_check squashfs; }
fix_kmod_squashfs_unavailable() { c1a_mod_off squashfs; }

rule kmod-udf-unavailable "kmod udf unavailable"
check_kmod_udf_unavailable() { c1a_mod_check udf; }
fix_kmod_udf_unavailable() { c1a_mod_off udf; }

rule kmod-firewire-core-unavailable "kmod firewire-core unavailable"
check_kmod_firewire_core_unavailable() { c1a_mod_check firewire-core; }
fix_kmod_firewire_core_unavailable() { c1a_mod_off firewire-core; }

rule kmod-usb-storage-unavailable "kmod usb-storage unavailable"
check_kmod_usb_storage_unavailable() { c1a_mod_check usb-storage; }
fix_kmod_usb_storage_unavailable() { c1a_mod_off usb-storage; }

C1A_FS_CONF=/etc/modprobe.d/pvs-cis-unused-fs.conf
# Filesystem modules that stay loadable (1.1.1.11), besides mounted/loaded ones.
C1A_FS_KEEP="ext4 jbd2 mbcache xfs btrfs fat vfat isofs fuse cuse virtiofs autofs4 autofs
binfmt_misc quota_v1 quota_v2 quota_tree pstore efivarfs configfs
cramfs freevxfs hfs hfsplus jffs2 overlay squashfs"

# Filesystem module names under kernel/fs (not nls) of KERNEL dirs given.
c1a_fs_modules() {
    local d
    for d in "$@"; do
        [ -d "$d/kernel/fs" ] || continue
        find "$d/kernel/fs" -mindepth 2 -type f -name '*.ko*' ! -path '*/kernel/fs/nls/*' -printf '%f\n' 2>/dev/null
    done | sed -E 's/\.ko(\.[a-z0-9]+)?$//' | tr '-' '_' | sort -u
}

rule unused-filesystem-kmods-unavailable "Unused filesystem kmods unavailable"
check_unused_filesystem_kmods_unavailable() {
    local m mounted loaded conf keep
    local -a inuse=() load=() open=() off=() kept=()
    keep=" $(xargs <<<"$C1A_FS_KEEP ${PVS_CIS_FS_KEEP:-}" | tr '-' '_') "
    mounted=$(findmnt -Dkerno fstype 2>/dev/null | sort -u | xargs)
    loaded=$(lsmod 2>/dev/null | awk 'NR > 1 { print $1 }')
    conf=$(modprobe --showconfig 2>/dev/null | grep -Ei '^[[:space:]]*(blacklist|install)[[:space:]]')
    while IFS= read -r m; do
        [ -n "$m" ] || continue
        if grep -qw -- "$m" <<<"$mounted"; then
            inuse+=("$m")
        elif grep -qx -- "$m" <<<"$loaded"; then
            load+=("$m")
        elif grep -Eq "^install[[:space:]]+${m}[[:space:]]+[^[:space:]]" <<<"$conf" \
            && grep -Eq "^blacklist[[:space:]]+${m}([[:space:]]|$)" <<<"$conf"; then
            off+=("$m")
        elif [[ "$keep" == *" $m "* ]]; then
            kept+=("$m")
        else
            open+=("$m")
        fi
    done < <(c1a_fs_modules "/lib/modules/$(uname -r)")
    ev "mounted fs types: ${mounted:-none}"
    ev "fs modules mounted: ${inuse[*]:-none}"
    ev "fs modules loaded (not mounted): ${load[*]:-none}"
    ev "fs modules loadable by decision: ${kept[*]:-none}"
    ev "fs modules loadable (not decided): ${open[*]:-none}"
    ev "fs modules disabled: ${#off[@]}"
    ev "decision: all other fs modules denied (pvs-cis-unused-fs.conf); keep list + PVS_CIS_FS_KEEP + in use stay"
    return 3
}
fix_unused_filesystem_kmods_unavailable() {
    local m mounted loaded keep tmp
    mounted=$(findmnt -Dkerno fstype 2>/dev/null | sort -u | xargs)
    loaded=$(lsmod 2>/dev/null | awk 'NR > 1 { print $1 }')
    keep=" $(xargs <<<"$C1A_FS_KEEP ${PVS_CIS_FS_KEEP:-}" | tr '-' '_') "
    tmp=$(mktemp) || return 1
    echo "# pvs-cis 1.1.1.11: filesystem modules the studio does not use" > "$tmp"
    while IFS= read -r m; do
        [ -n "$m" ] || continue
        [[ "$keep" == *" $m "* ]] && continue
        if grep -qw -- "$m" <<<"$mounted" || grep -qx -- "$m" <<<"$loaded"; then
            ev "$m: in use, left loadable"
            continue
        fi
        printf 'install %s /bin/false\nblacklist %s\n' "$m" "$m" >> "$tmp"
    done < <(c1a_fs_modules /lib/modules/*)
    cat "$tmp" > "$C1A_FS_CONF" && chmod 0644 "$C1A_FS_CONF"
    rm -f "$tmp"
    return 0
}

# ---- 1.1.2.1 /tmp ----

C1A_TMP_LINE="tmpfs	/tmp	tmpfs	defaults,rw,nosuid,nodev,noexec,relatime,size=2G,mode=1777	0	0"

rule tmp-is-its-own-mount "/tmp is its own mount"
check_tmp_is_its_own_mount() {
    local st rc=0
    c1a_separate /tmp || rc=1
    st=$(systemctl is-enabled tmp.mount 2>/dev/null)
    ev "tmp.mount: ${st:-not found}"
    case $st in "" | masked* | disabled) rc=1 ;; esac
    return $rc
}
fix_tmp_is_its_own_mount() {
    systemctl unmask tmp.mount >/dev/null 2>&1
    c1a_fstab_has /tmp || printf '%s\n' "$C1A_TMP_LINE" >> /etc/fstab
    systemctl daemon-reload 2>/dev/null
    return 0
}

rule tmp-mounted-nodev "/tmp mounted nodev"
check_tmp_mounted_nodev() { mount_has /tmp nodev; }
fix_tmp_mounted_nodev() { REMOUNT=0 c1a_opts /tmp nodev; }

rule tmp-mounted-nosuid "/tmp mounted nosuid"
check_tmp_mounted_nosuid() { mount_has /tmp nosuid; }
fix_tmp_mounted_nosuid() { REMOUNT=0 c1a_opts /tmp nosuid; }

rule tmp-mounted-noexec "/tmp mounted noexec"
check_tmp_mounted_noexec() { mount_has /tmp noexec; }
fix_tmp_mounted_noexec() { REMOUNT=0 c1a_opts /tmp noexec; }

# ---- 1.1.2.2 /dev/shm ----

rule dev-shm-is-its-own-mount "/dev/shm is its own mount"
check_dev_shm_is_its_own_mount() { c1a_separate /dev/shm; }
fix_dev_shm_is_its_own_mount() {
    c1a_fstab_has /dev/shm || printf 'tmpfs\t/dev/shm\ttmpfs\tdefaults,rw,nosuid,nodev,noexec,relatime\t0\t0\n' >> /etc/fstab
    systemctl daemon-reload 2>/dev/null
    return 0
}

rule dev-shm-mounted-nodev "/dev/shm mounted nodev"
check_dev_shm_mounted_nodev() { mount_has /dev/shm nodev; }
fix_dev_shm_mounted_nodev() { c1a_opts /dev/shm nodev; }

rule dev-shm-mounted-nosuid "/dev/shm mounted nosuid"
check_dev_shm_mounted_nosuid() { mount_has /dev/shm nosuid; }
fix_dev_shm_mounted_nosuid() { c1a_opts /dev/shm nosuid; }

rule dev-shm-mounted-noexec "/dev/shm mounted noexec"
check_dev_shm_mounted_noexec() { mount_has /dev/shm noexec; }
fix_dev_shm_mounted_noexec() { c1a_opts /dev/shm noexec; }

# ---- 1.1.2.3 /home ----

rule home-on-its-own-partition "/home on its own partition"
check_home_on_its_own_partition() { c1a_separate /home; }

rule home-mounted-nodev "/home mounted nodev"
check_home_mounted_nodev() { mount_has /home nodev; }
fix_home_mounted_nodev() { c1a_opts /home nodev; }

rule home-mounted-nosuid "/home mounted nosuid"
check_home_mounted_nosuid() { mount_has /home nosuid; }
fix_home_mounted_nosuid() { c1a_opts /home nosuid; }

# ---- 1.1.2.4 /var ----

rule var-on-its-own-partition "/var on its own partition"
check_var_on_its_own_partition() { c1a_separate /var; }

rule var-mounted-nodev "/var mounted nodev"
check_var_mounted_nodev() { mount_has /var nodev; }
fix_var_mounted_nodev() { c1a_opts /var nodev; }

rule var-mounted-nosuid "/var mounted nosuid"
check_var_mounted_nosuid() { mount_has /var nosuid; }
fix_var_mounted_nosuid() { c1a_opts /var nosuid; }

# ---- 1.1.2.5 /var/tmp ----

rule var-tmp-on-its-own-partition "/var/tmp on its own partition"
check_var_tmp_on_its_own_partition() { c1a_separate /var/tmp; }

rule var-tmp-mounted-nodev "/var/tmp mounted nodev"
check_var_tmp_mounted_nodev() { mount_has /var/tmp nodev; }
fix_var_tmp_mounted_nodev() { c1a_opts /var/tmp nodev; }

rule var-tmp-mounted-nosuid "/var/tmp mounted nosuid"
check_var_tmp_mounted_nosuid() { mount_has /var/tmp nosuid; }
fix_var_tmp_mounted_nosuid() { c1a_opts /var/tmp nosuid; }

rule var-tmp-mounted-noexec "/var/tmp mounted noexec"
check_var_tmp_mounted_noexec() { mount_has /var/tmp noexec; }
fix_var_tmp_mounted_noexec() { REMOUNT=0 c1a_opts /var/tmp noexec; }

# ---- 1.1.2.6 /var/log ----

rule var-log-on-its-own-partition "/var/log on its own partition"
check_var_log_on_its_own_partition() { c1a_separate /var/log; }

rule var-log-mounted-nodev "/var/log mounted nodev"
check_var_log_mounted_nodev() { mount_has /var/log nodev; }
fix_var_log_mounted_nodev() { c1a_opts /var/log nodev; }

rule var-log-mounted-nosuid "/var/log mounted nosuid"
check_var_log_mounted_nosuid() { mount_has /var/log nosuid; }
fix_var_log_mounted_nosuid() { c1a_opts /var/log nosuid; }

rule var-log-mounted-noexec "/var/log mounted noexec"
check_var_log_mounted_noexec() { mount_has /var/log noexec; }
fix_var_log_mounted_noexec() { c1a_opts /var/log noexec; }

# ---- 1.1.2.7 /var/log/audit ----

rule var-log-audit-on-its-own-partition "/var/log/audit on its own partition"
check_var_log_audit_on_its_own_partition() { c1a_separate /var/log/audit; }

rule var-log-audit-mounted-nodev "/var/log/audit mounted nodev"
check_var_log_audit_mounted_nodev() { mount_has /var/log/audit nodev; }
fix_var_log_audit_mounted_nodev() { c1a_opts /var/log/audit nodev; }

rule var-log-audit-mounted-nosuid "/var/log/audit mounted nosuid"
check_var_log_audit_mounted_nosuid() { mount_has /var/log/audit nosuid; }
fix_var_log_audit_mounted_nosuid() { c1a_opts /var/log/audit nosuid; }

rule var-log-audit-mounted-noexec "/var/log/audit mounted noexec"
check_var_log_audit_mounted_noexec() { mount_has /var/log/audit noexec; }
fix_var_log_audit_mounted_noexec() { c1a_opts /var/log/audit noexec; }

# ---- 1.2.1 APT configuration ----

rule apt-sources-pin-their-keys-signed-by "APT sources pin their keys (Signed-By)"
check_apt_sources_pin_their_keys_signed_by() {
    local list stanzas
    shopt -s nullglob
    list=$(grep -PHn -- '^\h*(deb(-src)?)\h+(\[(?![^\]]*\b[Ss]igned-[Bb]y\b)[^\]]*\]|[^\[])' \
        /etc/apt/sources.list /etc/apt/sources.list.d/*.list 2>/dev/null)
    stanzas=$(for f in /etc/apt/sources.list.d/*.sources; do
        awk 'BEGIN { u = 0; s = 0 }
            /^[[:blank:]]*$/ { if (u && !s) print FILENAME ":" NR ": stanza without Signed-By"; u = 0; s = 0; next }
            tolower($0) ~ /^[[:blank:]]*uris:[[:blank:]]*[^[:blank:]]/ { u = 1 }
            tolower($0) ~ /^[[:blank:]]*signed-by:[[:blank:]]*[^[:blank:]]/ { s = 1 }
            END { if (u && !s) print FILENAME ": last stanza without Signed-By" }' "$f"
    done)
    if [ -z "$list$stanzas" ]; then
        ev "every source entry has Signed-By"
        return 0
    fi
    [ -n "$list" ] && head -n 10 <<<"$list"
    [ -n "$stanzas" ] && head -n 10 <<<"$stanzas"
    ev "decision: review - sources without Signed-By (not added by the studio)"
    return 3
}

rule apt-no-recommends-suggests "APT: no Recommends/Suggests"
check_apt_no_recommends_suggests() {
    local rc=0
    c1a_apt_is APT::Install-Recommends '0|false|no' || rc=1
    c1a_apt_is APT::Install-Suggests '0|false|no' || rc=1
    return $rc
}
fix_apt_no_recommends_suggests() {
    c1a_apt_set "$C1A_APT_WEAK" APT::Install-Recommends 0
    c1a_apt_set "$C1A_APT_WEAK" APT::Install-Suggests 0
}

rule apt-key-files-0644-root-root "APT key files 0644 root:root"
check_apt_key_files_0644_root_root() {
    local bad
    bad=$(c1a_bad_keys | sort -u)
    if [ -z "$bad" ]; then
        ev "keyrings and Signed-By keys: all <=0644 root:root"
        return 0
    fi
    while IFS= read -r f; do stat -Lc '%n %a %U:%G' "$f"; done <<<"$bad" | head -n 20
    return 1
}
fix_apt_key_files_0644_root_root() {
    local f
    while IFS= read -r f; do
        [ -n "$f" ] || continue
        chown root:root "$f" && chmod u-x,go-wx "$f" || return 1
    done < <(c1a_bad_keys | sort -u)
    return 0
}

rule etc-apt-trusted-gpg-d-0755-root-root "/etc/apt/trusted.gpg.d 0755 root:root"
check_etc_apt_trusted_gpg_d_0755_root_root() { OPTIONAL=1 perm_ok /etc/apt/trusted.gpg.d 0755 root root; }
fix_etc_apt_trusted_gpg_d_0755_root_root() { perm_set /etc/apt/trusted.gpg.d 0755 root root; }

rule etc-apt-auth-conf-d-0755-root-root "/etc/apt/auth.conf.d 0755 root:root"
check_etc_apt_auth_conf_d_0755_root_root() { OPTIONAL=1 perm_ok /etc/apt/auth.conf.d 0755 root root; }
fix_etc_apt_auth_conf_d_0755_root_root() { perm_set /etc/apt/auth.conf.d 0755 root root; }

rule apt-auth-files-0640-root-root "APT auth files 0640 root:root"
check_apt_auth_files_0640_root_root() { c1a_dir_files_ok /etc/apt/auth.conf.d 0640; }
fix_apt_auth_files_0640_root_root() { c1a_dir_files_set /etc/apt/auth.conf.d 0640; }

rule usr-share-keyrings-0755-root-root "/usr/share/keyrings 0755 root:root"
check_usr_share_keyrings_0755_root_root() { OPTIONAL=1 perm_ok /usr/share/keyrings 0755 root root; }
fix_usr_share_keyrings_0755_root_root() { perm_set /usr/share/keyrings 0755 root root; }

rule etc-apt-sources-list-d-0755-root-root "/etc/apt/sources.list.d 0755 root:root"
check_etc_apt_sources_list_d_0755_root_root() { OPTIONAL=1 perm_ok /etc/apt/sources.list.d 0755 root root; }
fix_etc_apt_sources_list_d_0755_root_root() { perm_set /etc/apt/sources.list.d 0755 root root; }

rule apt-source-files-0644-root-root "APT source files 0644 root:root"
check_apt_source_files_0644_root_root() { c1a_dir_files_ok /etc/apt/sources.list.d 0644; }
fix_apt_source_files_0644_root_root() { c1a_dir_files_set /etc/apt/sources.list.d 0644; }

rule sources-list-https-repositories "sources.list: https repositories"
check_sources_list_https_repositories() {
    local hits
    if [ ! -f /etc/apt/sources.list ]; then
        ev "/etc/apt/sources.list: missing"
        return 0
    fi
    hits=$(c1a_http_lines /etc/apt/sources.list)
    [ -z "$hits" ] && { ev "/etc/apt/sources.list: no http:// repositories"; return 0; }
    head -n 10 <<<"$hits"
    return 1
}
fix_sources_list_https_repositories() { c1a_https_fix /etc/apt/sources.list; }

rule sources-list-d-https-repositories "sources.list.d: https repositories"
check_sources_list_d_https_repositories() {
    local hits
    shopt -s nullglob
    hits=$(c1a_http_lines /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources)
    [ -z "$hits" ] && { ev "/etc/apt/sources.list.d: no http:// repositories"; return 0; }
    head -n 10 <<<"$hits"
    return 1
}
fix_sources_list_d_https_repositories() {
    shopt -s nullglob
    c1a_https_fix /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources
}

rule apt-no-unsigned-repositories "APT: no unsigned repositories"
check_apt_no_unsigned_repositories() { c1a_apt_is Acquire::AllowInsecureRepositories '0|false|no'; }
fix_apt_no_unsigned_repositories() { c1a_apt_set "$C1A_APT_REPO" Acquire::AllowInsecureRepositories 0; }

rule apt-no-weakly-signed-repositories "APT: no weakly signed repositories"
check_apt_no_weakly_signed_repositories() { c1a_apt_is Acquire::AllowWeakRepositories '0|false|no'; }
fix_apt_no_weakly_signed_repositories() { c1a_apt_set "$C1A_APT_REPO" Acquire::AllowWeakRepositories 0; }

rule apt-no-downgrade-to-insecure-repos "APT: no downgrade to insecure repos"
check_apt_no_downgrade_to_insecure_repos() { c1a_apt_is Acquire::AllowDowngradeToInsecureRepositories '0|false|no'; }
fix_apt_no_downgrade_to_insecure_repos() { c1a_apt_set "$C1A_APT_REPO" Acquire::AllowDowngradeToInsecureRepositories 0; }

rule apt-release-date-checked "APT: Release date checked"
check_apt_release_date_checked() { c1a_apt_is Acquire::Check-Date 'true|1|yes'; }
fix_apt_release_date_checked() { c1a_apt_set "$C1A_APT_REPO" Acquire::Check-Date true; }

# ---- 1.2.2 updates ----

rule all-package-updates-installed "All package updates installed"
check_all_package_updates_installed() {
    local pend n rc=0
    local fresh=1
    if timeout 300 apt-get update -q >/dev/null 2>&1; then
        ev "apt-get update: ok"
    else
        ev "apt-get update: failed - the package lists may be old, so this cannot pass"
        fresh=0
    fi
    pend=$(apt-get -s -q -o Debug::NoLocking=1 dist-upgrade 2>/dev/null | awk '/^Inst / { print $2 }')
    n=$(grep -c . <<<"$pend")
    ev "pending upgrades: $n"
    [ "$n" -gt 0 ] && { head -n 15 <<<"$pend" | xargs; rc=3; }
    if [ -f /var/run/reboot-required ]; then
        ev "reboot required: $(xargs < /var/run/reboot-required.pkgs 2>/dev/null)"
        rc=3
    else
        ev "no reboot required"
    fi
    [ $fresh = 0 ] && rc=3
    [ $rc = 3 ] && ev "decision: the bake installs all updates; clones patch per site policy"
    return $rc
}
fix_all_package_updates_installed() {
    apt-get update -q >/dev/null || return 1
    DEBIAN_FRONTEND=noninteractive apt-get dist-upgrade -y -q \
        -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold >/dev/null
}
