# shellcheck shell=bash
# CIS Ubuntu 26.04 LTS v1.0.0 - chapter 1 (part b): AppArmor, bootloader, process hardening,
# banners, GDM (1.3.1.1 - 1.7.7). Rules: our own titles; see ../README.md.
#
# Decisions
# - 1.3.1.2: kernel cmdline gets "apparmor=1 security=apparmor" from
#   /etc/default/grub.d/99-pvs-cis.cfg (sorts after the cloud image's 50-cloudimg-settings.cfg
#   and appends to GRUB_CMDLINE_LINUX); any apparmor=0 is removed from /etc/default/grub{,.d}.
#   security= only deselects the other legacy major LSMs (none on Ubuntu); yama/landlock stay.
# - 1.3.1.3 (L2): every /etc/apparmor.d profile is put in enforce mode (aa-enforce, plus
#   complain/unconfined flags dropped from the profile header). EXCEPTION: "stub" profiles
#   (name-only, flags=(unconfined)) whose program IS installed are left alone - enforcing a
#   rule-less profile denies all file access and breaks the program (e.g. busybox). They keep
#   the check failing and are listed in its evidence; the studio needs an exception per gold.
#   cloud-init, qemu-guest-agent and sshd have no shipped profile (run unconfined, not counted).
#   rsyslogd's profile (shipped disabled) gets enabled + enforced if rsyslog is installed.
#   Snap profiles (/var/lib/snapd/apparmor) are snapd's; a devmode snap would fail the check.
# - 1.4.1: GRUB superuser is "root" (GRUB-only name). Random 24-char password, pbkdf2 hash
#   (600000 iterations, 64-byte salt) in /etc/grub.d/01_pvs-cis; the clear text goes ONLY to
#   /run/pvs-cis/grub-password (0600, dir 0700) - the studio must collect it before reboot.
#   A re-run keeps the password while that /run file exists, else generates a new one.
#   --unrestricted is added to CLASS= in /etc/grub.d/10_linux (a grub-common conffile: an
#   upgrade that replaces it would make every boot ask for the password - apt keeps ours with
#   --force-confold). All clones of a gold share the same GRUB password.
# - 1.4.2: grub.cfg 0600 root:root. grub-mkconfig keeps 0600 while a password is set; an apt
#   DPkg::Post-Invoke hook (/etc/apt/apt.conf.d/99-pvs-cis-grub-perms) re-applies it anyway.
# - 1.5.3: ptrace_scope = 2 (admin-only attach; the benchmark accepts 1-3, its note prefers 2
#   for CVE-2026-46333). Non-root gdb/strace -p stop working. 1.5.8: kptr_restrict = 2.
# - 1.5.7: apport is disabled (enabled=0) and apport.service masked, not purged.
# - 1.5.10: "* hard core 0" in /etc/security/limits.d/60-pvs-cis.conf; other hard core > 0
#   lines are commented out. 1.5.11/1.5.12: systemd-coredump not installed = pass (benchmark);
#   the drop-in /etc/systemd/coredump.conf.d/60-pvs-cis.conf is written regardless.
# - 1.6.x banners: our text in /etc/motd, /etc/issue, /etc/issue.net; sshd Banner
#   /etc/issue.net (00-pvs-cis.conf). Lines naming the OS or \m \r \s \v are deleted from
#   /etc/motd.d/* and /etc/issue.d/*; files under /usr/lib are package-owned and only reported.
# - 1.6.4/1.6.6: the dynamic MOTD is switched off: every /etc/update-motd.d/* script made
#   0644 (pam_motd's run-parts skips them), pinned by dpkg-statoverride so upgrades keep it.
#   Logins lose the "updates available"/news lines; /run/motd.dynamic becomes empty.
# - 1.6.11/1.6.12: update-notifier-motd service+timer masked (pass when not installed).
# - 1.7.x: no GDM in the server image: checks return n/a without gdm3/gdm; when GDM exists they
#   read gsettings/gdm config. No fixes (the studio does not install desktops).

C1B_BANNER="Authorized use only. Activity on this system is monitored and recorded."
C1B_GRUB_DROPIN=/etc/default/grub.d/99-pvs-cis.cfg
C1B_GRUB_USERS=/etc/grub.d/01_pvs-cis
C1B_GRUB_PWDIR=/run/pvs-cis
C1B_GRUB_CFG=/boot/grub/grub.cfg
C1B_COREDUMP=/etc/systemd/coredump.conf.d/60-pvs-cis.conf
C1B_STUB_MARK="This profile exist only to give a name"

# ---- chapter helpers ----

# The paths matching the given glob patterns that exist (unquoted expansion is on purpose).
c1b_glob() {
    local p f
    for p in "$@"; do
        # shellcheck disable=SC2086
        for f in $p; do [ -e "$f" ] && printf '%s\n' "$f"; done
    done
    return 0
}

c1b_osid() { (. /etc/os-release 2>/dev/null; echo "${ID:-ubuntu}"); }

# Prints "file:line" for every line that shows OS information (\m \r \s \v escapes or the
# distro id as a word); 0 when something was found.
c1b_osinfo() {
    local id
    id=$(c1b_osid)
    [ $# -gt 0 ] || return 1
    grep -HPsi -- "(\\\\v|\\\\r|\\\\m|\\\\s|\\b${id}\\b)" "$@" 2>/dev/null
}

# Deletes the OS-information lines from FILEs.
c1b_osinfo_strip() {
    local id f
    id=$(c1b_osid)
    for f in "$@"; do
        [ -f "$f" ] && sed -i -E "/(\\\\[vrms]|\\b${id}\\b)/Id" "$f"
    done
    return 0
}

# Replaces FILE (a symlink too) with the banner, 0644 root:root.
c1b_banner_write() {
    local f=$1
    [ -L "$f" ] && rm -f "$f"
    printf '%s\n' "$C1B_BANNER" > "$f" || return 1
    chown root:root "$f"
    chmod 0644 "$f"
}

# Each existing PATH: at most MAXMODE, root:root. Missing paths are skipped.
c1b_perm_all() {
    local max=$1 p bad=0 n=0
    shift
    for p in "$@"; do
        [ -e "$p" ] || continue
        n=$((n + 1))
        perm_ok "$p" "$max" root root || bad=1
    done
    [ $n -gt 0 ] || ev "no such files"
    return $bad
}

c1b_update_grub() {
    command -v update-grub >/dev/null 2>&1 || { ev "update-grub: missing"; return 1; }
    update-grub >/dev/null 2>&1 || { ev "update-grub failed"; return 1; }
}

# Running and configured sysctl both match the regex.
c1b_sysctl_in() {
    local k=$1 re=$2 run conf
    run=$(sysctl -n "$k" 2>/dev/null | xargs)
    conf=$(sysctl_conf "$k")
    ev "$k: running '${run}', configured '${conf:-unset}'"
    [[ "$run" =~ ^($re)$ ]] && [[ "$conf" =~ ^($re)$ ]]
}

# aa-status output (apparmor_status in /usr/sbin).
c1b_aa_status() {
    local b
    for b in /usr/sbin/apparmor_status /usr/sbin/aa-status; do
        [ -x "$b" ] && { "$b" 2>/dev/null; return; }
    done
    return 1
}

# The count in the aa-status line matching "N <PHRASE>", "" when absent.
c1b_aa_count() { grep -Eo "^[[:space:]]*[0-9]+ $1" <<<"$2" | head -n 1 | awk '{print $1}'; }

# The program a profile attaches to ("profile NAME /path", "profile /path" or "/path" header),
# "" if none.
c1b_aa_attach() {
    sed -n -E \
        -e 's/^[[:space:]]*profile[[:space:]]+[^/[:space:]][^[:space:]]*[[:space:]]+(\/[^[:space:]]+)[[:space:]].*/\1/p' \
        -e 's/^[[:space:]]*profile[[:space:]]+(\/[^[:space:]]+)[[:space:]].*/\1/p' \
        -e 's/^[[:space:]]*(\/[^[:space:]]+)[[:space:]]+.*\{[[:space:]]*$/\1/p' "$1" | head -n 1
}

# Drops complain / unconfined from the flags of profile headers in FILE.
c1b_aa_clear_flags() {
    sed -i -E '/^[[:space:]]*(profile[[:space:]]|\/)/{
        s/(flags=\([^)]*)\b(complain|unconfined)\b[[:space:]]*,?[[:space:]]*/\1/g
        s/,[[:space:]]*\)/)/
        s/[[:space:]]*flags=\([[:space:]]*\)//
    }' "$1"
}

# Is a stub profile's program installed? (no attachment path: treat as not installed)
c1b_aa_stub_live() {
    local a
    a=$(c1b_aa_attach "$1")
    [ -n "$a" ] || return 1
    # AppArmor alternations/variables ({,usr/}, @{bin}) become a shell glob.
    a=$(sed -E 's/@?\{[^}]*\}/*/g; s/\*\*+/*/g' <<<"$a")
    [ -n "$(c1b_glob "$a")" ]
}

# Effective value of KEY in [Coredump] (last assignment in systemd's read order), "" if unset.
c1b_coredump_val() {
    systemd-analyze cat-config systemd/coredump.conf 2>/dev/null | awk -v k="$1" '
        /^# \// { sec = 0; next }
        /^[[:space:]]*\[/ { sec = ($0 ~ /^[[:space:]]*\[Coredump\]/); next }
        sec && $0 ~ "^[[:space:]]*" k "[[:space:]]*=" { sub(/^[^=]*=[[:space:]]*/, ""); sub(/[[:space:]]+$/, ""); v = $0 }
        END { print v }'
}

c1b_coredump_is() {
    local k=$1 want=$2 have
    if ! pkg_installed systemd-coredump; then
        ev "systemd-coredump: not installed"
        return 0
    fi
    have=$(c1b_coredump_val "$k")
    ev "coredump $k: ${have:-default}"
    [ "$have" = "$want" ]
}

c1b_coredump_set() {
    local k=$1 v=$2 f
    for f in /etc/systemd/coredump.conf /etc/systemd/coredump.conf.d/*.conf; do
        [ -f "$f" ] && [ "$f" != "$C1B_COREDUMP" ] || continue
        sed -i -E "/^[[:space:]]*${k}[[:space:]]*=/{/=[[:space:]]*${v}[[:space:]]*$/!s/^/# /}" "$f"
    done
    mkdir -p "${C1B_COREDUMP%/*}"
    [ -f "$C1B_COREDUMP" ] || printf '[Coredump]\n' > "$C1B_COREDUMP"
    sed -i -E "/^[[:space:]]*${k}[[:space:]]*=/d" "$C1B_COREDUMP"
    printf '%s=%s\n' "$k" "$v" >> "$C1B_COREDUMP"
    chmod 0644 "$C1B_COREDUMP"
    systemctl reload-or-restart systemd-coredump.socket >/dev/null 2>&1
    return 0
}

# MOTD scripts that pam_motd runs at login: made non-executable (0644 at most, root:root),
# pinned with dpkg-statoverride so package upgrades keep the mode.
c1b_motd_scripts_off() {
    local f t m
    while IFS= read -r f; do
        t=$(readlink -e "$f") || continue
        [ -f "$t" ] || continue
        perm_set "$t" 644 root root
        m=$(stat -c '%a' "$t")
        if dpkg-statoverride --list "$t" >/dev/null 2>&1; then
            dpkg-statoverride --remove "$t" >/dev/null 2>&1
        fi
        dpkg-statoverride --add root root "$m" "$t" >/dev/null 2>&1
    done < <(c1b_glob '/etc/update-motd.d/*')
    return 0
}

# motd= paths of pam_motd in /etc/pam.d.
c1b_pam_motd_paths() { grep -hPo 'motd=\K\S+' /etc/pam.d/* 2>/dev/null | tr -d "\"'" | sort -u; }

# The sshd Banner file, "" when none.
c1b_sshd_banner() {
    local b
    b=$(sshd_val banner)
    [ -n "$b" ] && [ "${b,,}" != none ] && printf '%s\n' "$b"
}

# GDM installed? (else the 1.7 rules do not apply)
c1b_gdm() {
    if pkg_installed gdm3 || pkg_installed gdm; then return 0; fi
    ev "gdm3: not installed"
    return 1
}

# gsettings KEY is locked (not writable) and its value matches the regex.
c1b_gs() {
    local schema=$1 key=$2 re=$3 v w
    v=$(gsettings get "$schema" "$key" 2>/dev/null)
    w=$(gsettings writable "$schema" "$key" 2>/dev/null)
    ev "$schema $key: ${v:-unset} (writable: ${w:-unknown})"
    [ "$w" = false ] && [[ "$v" =~ ^($re)$ ]]
}

c1b_gdm_files() { c1b_glob /etc/gdm3/custom.conf /etc/gdm3/daemon.conf /etc/gdm/custom.conf /etc/gdm/daemon.conf; }

# ---- 1.3.1 AppArmor ----

rule apparmor-and-its-tools-installed "AppArmor and its tools installed"
check_apparmor_and_its_tools_installed() {
    local p bad=0
    for p in apparmor apparmor-utils; do
        if pkg_installed "$p"; then ev "$p: installed"; else ev "$p: not installed"; bad=1; fi
    done
    return $bad
}
fix_apparmor_and_its_tools_installed() { pkg_install apparmor apparmor-utils; }

rule apparmor-on-at-boot-and-running "AppArmor on at boot and running"
check_apparmor_on_at_boot_and_running() {
    local bad=0 st n
    if grep -E '^[[:space:]]*linux' "$C1B_GRUB_CFG" 2>/dev/null | grep -q 'apparmor=0'; then
        ev "$C1B_GRUB_CFG: apparmor=0 on a linux line"; bad=1
    fi
    if grep -qs 'apparmor=0' /etc/default/grub.d/apparmor.cfg; then
        ev "/etc/default/grub.d/apparmor.cfg: apparmor=0"; bad=1
    fi
    grep -qw 'apparmor=0' /proc/cmdline && { ev "running kernel: apparmor=0"; bad=1; }
    ev "apparmor.service: $(systemctl is-enabled apparmor.service 2>/dev/null || true) / $(systemctl is-active apparmor.service 2>/dev/null || true)"
    svc_enabled apparmor.service && svc_active apparmor.service || bad=1
    st=$(c1b_aa_status) || { ev "apparmor_status: not available"; return 1; }
    n=$(c1b_aa_count 'profiles are loaded' "$st")
    ev "profiles loaded: ${n:-0}"
    [ "${n:-0}" -gt 0 ] || bad=1
    return $bad
}
fix_apparmor_on_at_boot_and_running() {
    local f
    for f in /etc/default/grub /etc/default/grub.d/*.cfg; do
        [ -f "$f" ] && [ "$f" != "$C1B_GRUB_DROPIN" ] || continue
        sed -i -E 's/(^|[[:space:]"'\''])apparmor=0([[:space:]"'\'']|$)/\1\2/g' "$f"
    done
    mkdir -p /etc/default/grub.d
    cat > "$C1B_GRUB_DROPIN" <<'EOF'
# pvs-cis (CIS 1.3.1.2): AppArmor on. Sorts after the cloud image's settings file.
GRUB_CMDLINE_LINUX="${GRUB_CMDLINE_LINUX:-} apparmor=1 security=apparmor"
EOF
    chmod 0644 "$C1B_GRUB_DROPIN"
    systemctl unmask apparmor.service >/dev/null 2>&1
    systemctl enable apparmor.service >/dev/null 2>&1 || return 1
    systemctl start apparmor.service >/dev/null 2>&1
    c1b_update_grub
}

rule apparmor-every-profile-enforcing "AppArmor: every profile enforcing"
check_apparmor_every_profile_enforcing() {
    local st n e c bad=0 mode
    st=$(c1b_aa_status) || { ev "apparmor_status: not available"; return 1; }
    n=$(c1b_aa_count 'profiles are loaded' "$st")
    e=$(c1b_aa_count 'profiles are in enforce mode' "$st")
    ev "profiles: ${n:-0} loaded, ${e:-0} enforce"
    [ "${n:-0}" -gt 0 ] && [ "${n:-0}" = "${e:-0}" ] || bad=1
    for mode in complain prompt kill unconfined; do
        c=$(c1b_aa_count "profiles are in $mode mode" "$st")
        if [ "${c:-0}" -gt 0 ]; then
            ev "$mode: $c - $(awk -v m="profiles are in $mode mode" '
                index($0, m) { f = 1; next } f && /^[[:space:]]+[^[:space:]]/ && !/ (profiles|processes) / { printf "%s ", $1; if (++k >= 12) exit; next } f { exit }' <<<"$st")"
            bad=1
        fi
    done
    c=$(c1b_aa_count 'processes are unconfined but have a profile defined' "$st")
    ev "processes unconfined with a profile: ${c:-0}"
    [ "${c:-0}" -eq 0 ] || bad=1
    local stubs
    stubs=$(grep -rl "$C1B_STUB_MARK" /etc/apparmor.d/ 2>/dev/null | while IFS= read -r f; do
        c1b_aa_stub_live "$f" && printf '%s ' "${f##*/}"; done)
    [ -n "$stubs" ] && ev "stub profiles of installed programs (left unenforced): $stubs"
    return $bad
}
fix_apparmor_every_profile_enforcing() {
    local f list=() skipped=()
    command -v aa-enforce >/dev/null 2>&1 || { ev "aa-enforce missing (apparmor-utils)"; return 1; }
    for f in /etc/apparmor.d/*; do
        [ -f "$f" ] || continue
        if grep -q "$C1B_STUB_MARK" "$f" 2>/dev/null && c1b_aa_stub_live "$f"; then
            skipped+=("${f##*/}")
            continue
        fi
        list+=("$f")
    done
    [ ${#list[@]} -gt 0 ] || return 0
    if ! aa-enforce "${list[@]}" >/dev/null 2>&1; then
        for f in "${list[@]}"; do aa-enforce "$f" >/dev/null 2>&1 || ev "aa-enforce failed: ${f##*/}"; done
    fi
    # aa-enforce may leave an explicit flags=(unconfined); take it out on the same set.
    for f in "${list[@]}"; do c1b_aa_clear_flags "$f"; done
    [ ${#skipped[@]} -gt 0 ] && ev "stub profiles of installed programs not enforced: ${skipped[*]}"
    systemctl reload apparmor.service >/dev/null 2>&1 || systemctl restart apparmor.service >/dev/null 2>&1
    return 0
}

rule unconfined-unprivileged-change-profile-off "Unconfined unprivileged change_profile off"
# An Ubuntu kernel setting (23.10 on): Debian's kernel does not have it.
check_unconfined_unprivileged_change_profile_off() {
    if [ ! -e /proc/sys/kernel/apparmor_restrict_unprivileged_unconfined ]; then
        ev "kernel $(uname -r) has no kernel.apparmor_restrict_unprivileged_unconfined"
        return 2
    fi
    sysctl_is kernel.apparmor_restrict_unprivileged_unconfined 1
}
fix_unconfined_unprivileged_change_profile_off() {
    [ -e /proc/sys/kernel/apparmor_restrict_unprivileged_unconfined ] || return 0
    sysctl_set kernel.apparmor_restrict_unprivileged_unconfined 1
}

# ---- 1.4 bootloader ----

rule grub-superuser-password "GRUB superuser password"
check_grub_superuser_password() {
    local su pw bad=0
    [ -f "$C1B_GRUB_CFG" ] || { ev "$C1B_GRUB_CFG: missing"; return 1; }
    su=$(grep -E '^set superusers' "$C1B_GRUB_CFG" | head -n 1)
    pw=$(awk -F. '/^[[:space:]]*password/ { print $1 "." $2 "." $3; exit }' "$C1B_GRUB_CFG")
    ev "superusers: ${su:-none}"
    ev "password: ${pw:-none}"
    [ -n "$su" ] || bad=1
    [[ "$pw" =~ ^[[:space:]]*password_pbkdf2[[:space:]]+[^[:space:]]+[[:space:]]+grub\.pbkdf2\.sha512$ ]] || bad=1
    grep -q -- '--unrestricted' "$C1B_GRUB_CFG" && ev "menu entries: --unrestricted"
    return $bad
}
fix_grub_superuser_password() {
    local user=root pw hash
    command -v grub-mkpasswd-pbkdf2 >/dev/null 2>&1 || { ev "grub-mkpasswd-pbkdf2 missing"; return 1; }
    if ! { [ -s "$C1B_GRUB_PWDIR/grub-password" ] && grep -q '^password_pbkdf2 ' "$C1B_GRUB_USERS" 2>/dev/null; }; then
        pw=$(head -c 1024 /dev/urandom | tr -dc 'A-Za-z0-9' | head -c 24)
        [ "${#pw}" -eq 24 ] || { ev "password generation failed"; return 1; }
        hash=$(printf '%s\n%s\n' "$pw" "$pw" | grub-mkpasswd-pbkdf2 --iteration-count=600000 --salt=64 2>/dev/null \
            | grep -o 'grub\.pbkdf2\.sha512\.[^[:space:]]*' | head -n 1)
        [ -n "$hash" ] || { ev "grub-mkpasswd-pbkdf2 gave no hash"; return 1; }
        mkdir -p "$C1B_GRUB_PWDIR"
        chmod 0700 "$C1B_GRUB_PWDIR"
        (umask 077; printf '%s\n' "$pw" > "$C1B_GRUB_PWDIR/grub-password") || return 1
        chmod 0600 "$C1B_GRUB_PWDIR/grub-password"
        cat > "$C1B_GRUB_USERS" <<EOF
#!/bin/sh
# pvs-cis (CIS 1.4.1): GRUB superuser; menu entries are --unrestricted (10_linux).
cat <<'GRUBEOF'
set superusers="$user"
password_pbkdf2 $user $hash
GRUBEOF
EOF
        chown root:root "$C1B_GRUB_USERS"
        chmod 0755 "$C1B_GRUB_USERS"
    fi
    if [ -f /etc/grub.d/10_linux ]; then
        sed -i -E '/^CLASS="/{/--unrestricted/!s/"[[:space:]]*$/ --unrestricted"/}' /etc/grub.d/10_linux
        grep -Eq '^CLASS=".*--unrestricted' /etc/grub.d/10_linux || { ev "10_linux: CLASS not patched"; return 1; }
    fi
    c1b_update_grub
}

rule grub-cfg-0600-root-root "grub.cfg 0600 root:root"
check_grub_cfg_0600_root_root() { perm_ok "$C1B_GRUB_CFG" 600 root root; }
fix_grub_cfg_0600_root_root() {
    [ -f "$C1B_GRUB_CFG" ] || return 1
    perm_set "$C1B_GRUB_CFG" 600 root root
    chmod u-x "$C1B_GRUB_CFG"
    # update-grub from later package runs: put the mode back.
    printf '%s\n' '// pvs-cis (CIS 1.4.2): grub.cfg stays 0600 root:root' \
        'DPkg::Post-Invoke { "if [ -f /boot/grub/grub.cfg ]; then chown root:root /boot/grub/grub.cfg; chmod 0600 /boot/grub/grub.cfg; fi"; };' \
        > /etc/apt/apt.conf.d/99-pvs-cis-grub-perms
    chmod 0644 /etc/apt/apt.conf.d/99-pvs-cis-grub-perms
}

# ---- 1.5 process hardening ----

rule hardlink-protection-on "Hardlink protection on"
check_hardlink_protection_on() { sysctl_is fs.protected_hardlinks 1; }
fix_hardlink_protection_on() { sysctl_set fs.protected_hardlinks 1; }

rule symlink-protection-on "Symlink protection on"
check_symlink_protection_on() { sysctl_is fs.protected_symlinks 1; }
fix_symlink_protection_on() { sysctl_set fs.protected_symlinks 1; }

rule ptrace-restricted-yama "ptrace restricted (yama)"
check_ptrace_restricted_yama() { c1b_sysctl_in kernel.yama.ptrace_scope '1|2|3'; }
fix_ptrace_restricted_yama() { sysctl_set kernel.yama.ptrace_scope 2; }

rule no-core-dumps-from-setuid-programs "No core dumps from setuid programs"
check_no_core_dumps_from_setuid_programs() { sysctl_is fs.suid_dumpable 0; }
fix_no_core_dumps_from_setuid_programs() { sysctl_set fs.suid_dumpable 0; }

rule kernel-log-readable-by-root-only "Kernel log readable by root only"
check_kernel_log_readable_by_root_only() { sysctl_is kernel.dmesg_restrict 1; }
fix_kernel_log_readable_by_root_only() { sysctl_set kernel.dmesg_restrict 1; }

rule prelink-absent "prelink absent"
check_prelink_absent() {
    if pkg_installed prelink; then ev "prelink: installed"; return 1; fi
    ev "prelink: not installed"
}
fix_prelink_absent() {
    pkg_installed prelink || return 0
    command -v prelink >/dev/null 2>&1 && prelink -ua >/dev/null 2>&1
    pkg_purge prelink
}

rule apport-crash-reporting-off "apport crash reporting off"
check_apport_crash_reporting_off() {
    local bad=0 en
    if pkg_installed apport; then
        en=$(kv_get /etc/default/apport enabled)
        ev "/etc/default/apport enabled=${en:-unset}"
        grep -Psiq '^\h*enabled\h*=\h*[^0]\b' /etc/default/apport 2>/dev/null && bad=1
    else
        ev "apport: not installed"
    fi
    if svc_active apport.service; then ev "apport.service: active"; bad=1; else ev "apport.service: not active"; fi
    return $bad
}
fix_apport_crash_reporting_off() {
    pkg_installed apport || svc_exists apport.service || return 0
    [ -f /etc/default/apport ] && kv_set /etc/default/apport enabled 0 =
    svc_off apport.service
}

rule kernel-pointers-hidden "Kernel pointers hidden"
check_kernel_pointers_hidden() { c1b_sysctl_in kernel.kptr_restrict '1|2'; }
fix_kernel_pointers_hidden() { sysctl_set kernel.kptr_restrict 2; }

rule full-aslr "Full ASLR"
check_full_aslr() { sysctl_is kernel.randomize_va_space 2; }
fix_full_aslr() { sysctl_set kernel.randomize_va_space 2; }

rule hard-core-size-limit-0-for-all "Hard core size limit 0 for all"
check_hard_core_size_limit_0_for_all() {
    local lines bad=0 l v
    lines=$(grep -HPsi -- '^\h*\*\h+hard\h+core\b' /etc/security/limits.conf $(c1b_glob '/etc/security/limits.d/*') 2>/dev/null)
    [ -n "$lines" ] || { ev "no '* hard core' limit"; return 1; }
    while IFS= read -r l; do
        ev "$l"
        v=$(awk '{print $4}' <<<"${l#*:}")
        [ "$v" = 0 ] || bad=1
    done <<<"$lines"
    return $bad
}
fix_hard_core_size_limit_0_for_all() {
    local f
    for f in /etc/security/limits.conf $(c1b_glob '/etc/security/limits.d/*'); do
        [ -f "$f" ] && [ "$f" != /etc/security/limits.d/60-pvs-cis.conf ] || continue
        sed -ri '/^\s*[^#[:space:]]+\s+hard\s+core\s+([1-9][0-9]*|unlimited|infinity)\b/s/^/# /' "$f"
    done
    mkdir -p /etc/security/limits.d
    printf '%s\n' '# pvs-cis (CIS 1.5.10)' '* hard core 0' > /etc/security/limits.d/60-pvs-cis.conf
    chmod 0644 /etc/security/limits.d/60-pvs-cis.conf
}

rule systemd-coredump-no-processing "systemd-coredump: no processing"
check_systemd_coredump_no_processing() { c1b_coredump_is ProcessSizeMax 0; }
fix_systemd_coredump_no_processing() { c1b_coredump_set ProcessSizeMax 0; }

rule systemd-coredump-nothing-stored "systemd-coredump: nothing stored"
check_systemd_coredump_nothing_stored() { c1b_coredump_is Storage none; }
fix_systemd_coredump_nothing_stored() { c1b_coredump_set Storage none; }

# ---- 1.6 banners ----

rule motd-shows-no-os-details "MOTD shows no OS details"
check_motd_shows_no_os_details() {
    local files hits
    mapfile -t files < <(c1b_glob /etc/motd '/etc/motd.d/*')
    [ ${#files[@]} -gt 0 ] || { ev "no motd files"; return 0; }
    hits=$(c1b_osinfo "${files[@]}")
    if [ -n "$hits" ]; then ev "$hits"; return 1; fi
    ev "${files[*]}: no OS information"
}
fix_motd_shows_no_os_details() {
    c1b_banner_write /etc/motd || return 1
    c1b_osinfo_strip $(c1b_glob '/etc/motd.d/*')
}

rule local-login-banner-shows-no-os-details "Local login banner shows no OS details"
check_local_login_banner_shows_no_os_details() {
    local files hits
    mapfile -t files < <(c1b_glob /etc/issue '/usr/lib/issue.d/*' '/etc/issue.d/*' '/run/issue.d/*')
    [ ${#files[@]} -gt 0 ] || { ev "/etc/issue: missing"; return 1; }
    hits=$(c1b_osinfo "${files[@]}")
    if [ -n "$hits" ]; then ev "$hits"; return 1; fi
    ev "${files[*]}: no OS information"
}
fix_local_login_banner_shows_no_os_details() {
    c1b_banner_write /etc/issue || return 1
    c1b_osinfo_strip $(c1b_glob '/etc/issue.d/*')
}

rule remote-login-banner-shows-no-os-details "Remote login banner shows no OS details"
check_remote_login_banner_shows_no_os_details() {
    local hits
    [ -f /etc/issue.net ] || { ev "/etc/issue.net: missing"; return 1; }
    hits=$(c1b_osinfo /etc/issue.net)
    if [ -n "$hits" ]; then ev "$hits"; return 1; fi
    ev "/etc/issue.net: $(head -c 120 /etc/issue.net | tr '\n' ' ')"
}
fix_remote_login_banner_shows_no_os_details() { c1b_banner_write /etc/issue.net; }

rule pam-motd-files-show-no-os-details "pam_motd files show no OS details"
check_pam_motd_files_show_no_os_details() {
    local svc file line p bad=0 n=0 hits
    for svc in sshd login su gdm-password; do
        if [ -f "/etc/pam.d/$svc" ]; then file=/etc/pam.d/$svc
        elif [ -f "/usr/lib/pam.d/$svc" ]; then file=/usr/lib/pam.d/$svc
        else continue; fi
        while IFS= read -r line; do
            while IFS= read -r p; do
                p=${p//\"/}; p=${p//\'/}
                [ -r "$p" ] || { ev "$file: motd=$p (not present)"; continue; }
                n=$((n + 1))
                hits=$(c1b_osinfo "$p")
                if [ -n "$hits" ]; then ev "$file: $hits"; bad=1; else ev "$file: motd=$p clean"; fi
            done < <(grep -oP '\bmotd=\K\S+' <<<"$line")
        done < <(grep -Pi '^\h*session\h+(required|optional)\h+pam_motd\.so\b.*\bmotd=' "$file" 2>/dev/null)
    done
    [ $n -gt 0 ] || ev "no readable pam_motd motd= file"
    return $bad
}
fix_pam_motd_files_show_no_os_details() {
    local p
    # The login-time generator (/etc/update-motd.d) is what writes the OS name into
    # /run/motd.dynamic; it is switched off (see also 1.6.6).
    c1b_motd_scripts_off
    while IFS= read -r p; do
        [ -f "$p" ] || continue
        c1b_osinfo "$p" >/dev/null || continue
        case $p in
            /run/*) : > "$p" ;;
            *) c1b_banner_write "$p" ;;
        esac
    done < <(c1b_pam_motd_paths)
    return 0
}

rule sshd-shows-the-warning-banner "sshd shows the warning banner"
check_sshd_shows_the_warning_banner() {
    local b hits
    b=$(c1b_sshd_banner)
    ev "sshd banner: ${b:-none}"
    [ -n "$b" ] && [ -f "$b" ] || return 1
    hits=$(c1b_osinfo "$b")
    if [ -n "$hits" ]; then ev "$hits"; return 1; fi
    return 0
}
fix_sshd_shows_the_warning_banner() {
    [ -f /etc/issue.net ] || c1b_banner_write /etc/issue.net || return 1
    sshd_set Banner /etc/issue.net
    if ! sshd -t >/dev/null 2>&1; then
        sed -i -E '/^[[:space:]]*Banner[[:space:]]/Id' "$SSHD_FILE"
        ev "sshd -t failed; Banner taken out again"
        return 1
    fi
    systemctl reload ssh.service >/dev/null 2>&1 || true
}

rule motd-files-0644-root-root "MOTD files 0644 root:root"
check_motd_files_0644_root_root() {
    local files
    mapfile -t files < <(c1b_glob /etc/motd /run/motd /usr/lib/motd '/etc/motd.d/*' '/run/motd.d/*' '/usr/lib/motd.d/*' '/etc/update-motd.d/*')
    [ ${#files[@]} -gt 0 ] || { ev "no motd files"; return 0; }
    c1b_perm_all 644 "${files[@]}"
}
fix_motd_files_0644_root_root() {
    local f
    c1b_motd_scripts_off
    while IFS= read -r f; do
        perm_set "$(readlink -e "$f")" 644 root root
    done < <(c1b_glob /etc/motd /run/motd /usr/lib/motd '/etc/motd.d/*' '/run/motd.d/*' '/usr/lib/motd.d/*')
    return 0
}

rule etc-issue-0644-root-root "/etc/issue 0644 root:root"
check_etc_issue_0644_root_root() {
    local files
    mapfile -t files < <(c1b_glob /etc/issue '/usr/lib/issue.d/*' '/etc/issue.d/*' '/run/issue.d/*')
    [ -e /etc/issue ] || { ev "/etc/issue: missing"; return 1; }
    c1b_perm_all 644 "${files[@]}"
}
fix_etc_issue_0644_root_root() {
    local f
    while IFS= read -r f; do
        perm_set "$(readlink -e "$f")" 644 root root
    done < <(c1b_glob /etc/issue '/usr/lib/issue.d/*' '/etc/issue.d/*' '/run/issue.d/*')
    return 0
}

rule etc-issue-net-0644-root-root "/etc/issue.net 0644 root:root"
check_etc_issue_net_0644_root_root() { perm_ok /etc/issue.net 644 root root; }
fix_etc_issue_net_0644_root_root() { [ -e /etc/issue.net ] || return 1; perm_set "$(readlink -e /etc/issue.net)" 644 root root; }

rule pam-motd-files-0644-root-root "pam_motd files 0644 root:root"
check_pam_motd_files_0644_root_root() {
    local p bad=0 n=0
    while IFS= read -r p; do
        if [ -e "$p" ]; then
            n=$((n + 1))
            perm_ok "$p" 644 root root || bad=1
        else
            ev "$p: not present now"
        fi
    done < <(c1b_pam_motd_paths)
    [ $n -gt 0 ] || ev "no pam_motd motd= file present"
    return $bad
}
fix_pam_motd_files_0644_root_root() {
    local p
    while IFS= read -r p; do
        [ -e "$p" ] && perm_set "$(readlink -e "$p")" 644 root root
    done < <(c1b_pam_motd_paths)
    return 0
}

rule sshd-banner-file-0644-root-root "sshd banner file 0644 root:root"
check_sshd_banner_file_0644_root_root() {
    local b
    b=$(c1b_sshd_banner)
    [ -n "$b" ] || { ev "sshd banner: none (see 1.6.5)"; return 0; }
    perm_ok "$b" 644 root root
}
fix_sshd_banner_file_0644_root_root() {
    local b
    b=$(c1b_sshd_banner)
    [ -n "$b" ] && [ -e "$b" ] || return 0
    perm_set "$(readlink -e "$b")" 644 root root
}

rule update-notifier-motd-service-off "update-notifier MOTD service off"
check_update_notifier_motd_service_off() {
    local u=update-notifier-motd.service
    svc_exists "$u" || { ev "$u: not installed"; return 0; }
    ev "$u: $(systemctl is-enabled "$u" 2>/dev/null || true) / $(systemctl is-active "$u" 2>/dev/null || true)"
    ! svc_enabled "$u" && ! svc_active "$u"
}
fix_update_notifier_motd_service_off() { svc_exists update-notifier-motd.service || return 0; svc_off update-notifier-motd.service; }

rule update-notifier-motd-timer-off "update-notifier MOTD timer off"
check_update_notifier_motd_timer_off() {
    local u=update-notifier-motd.timer
    svc_exists "$u" || { ev "$u: not installed"; return 0; }
    ev "$u: $(systemctl is-enabled "$u" 2>/dev/null || true) / $(systemctl is-active "$u" 2>/dev/null || true)"
    ! svc_enabled "$u" && ! svc_active "$u"
}
fix_update_notifier_motd_timer_off() { svc_exists update-notifier-motd.timer || return 0; svc_off update-notifier-motd.timer; }

# ---- 1.7 GDM (not in the server image: n/a; no fixes) ----

rule gdm-login-banner-on-and-locked "GDM: login banner on and locked"
check_gdm_login_banner_on_and_locked() {
    c1b_gdm || return 2
    local bad=0
    c1b_gs org.gnome.login-screen banner-message-enable true || bad=1
    c1b_gs org.gnome.login-screen banner-message-text "'.+'" || bad=1
    return $bad
}

rule gdm-no-user-list-locked "GDM: no user list, locked"
check_gdm_no_user_list_locked() {
    c1b_gdm || return 2
    c1b_gs org.gnome.login-screen disable-user-list true
}

rule gdm-screen-lock-delays-locked "GDM: screen lock delays, locked"
check_gdm_screen_lock_delays_locked() {
    c1b_gdm || return 2
    local bad=0 v
    c1b_gs org.gnome.desktop.session idle-delay 'uint32 [0-9]+' || bad=1
    v=$(gsettings get org.gnome.desktop.session idle-delay 2>/dev/null | awk '{print $NF}')
    [[ "$v" =~ ^[0-9]+$ ]] && [ "$v" -gt 0 ] && [ "$v" -le 900 ] || bad=1
    c1b_gs org.gnome.desktop.screensaver lock-delay 'uint32 [0-5]' || bad=1
    return $bad
}

rule gdm-removable-media-automount-off "GDM: removable media automount off"
check_gdm_removable_media_automount_off() {
    c1b_gdm || return 2
    local bad=0
    c1b_gs org.gnome.desktop.media-handling automount false || bad=1
    c1b_gs org.gnome.desktop.media-handling automount-open false || bad=1
    return $bad
}

rule gdm-autorun-never "GDM: autorun never"
check_gdm_autorun_never() {
    c1b_gdm || return 2
    c1b_gs org.gnome.desktop.media-handling autorun-never true
}

rule gdm-xdmcp-off "GDM: XDMCP off"
check_gdm_xdmcp_off() {
    c1b_gdm || return 2
    local f out bad=0
    while IFS= read -r f; do
        out=$(awk '/\[xdmcp\]/ { f = 1; next } /\[/ { f = 0 } f && /^[[:space:]]*Enable[[:space:]]*=[[:space:]]*true/ { print FILENAME ": [xdmcp] " $0 }' "$f")
        if [ -n "$out" ]; then ev "$out"; bad=1; fi
    done < <(c1b_gdm_files)
    [ $bad -eq 1 ] || ev "xdmcp: not enabled"
    return $bad
}

rule gdm-wayland-off-no-xwayland "GDM: Wayland off (no Xwayland)"
check_gdm_wayland_off_no_xwayland() {
    c1b_gdm || return 2
    local f hit=1
    while IFS= read -r f; do
        if grep -Piq '^\h*WaylandEnable\h*=\h*false\b' "$f"; then ev "$f: WaylandEnable=false"; hit=0; fi
    done < <(c1b_gdm_files)
    [ $hit -eq 0 ] || ev "WaylandEnable=false: not set"
    return $hit
}
