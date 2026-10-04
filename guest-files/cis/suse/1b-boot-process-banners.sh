# shellcheck shell=bash
# CIS SUSE Linux Enterprise 16 v1.0.0 on openSUSE Leap 16.0 - chapter 1 (part b): builds on
# deb/ and el/1b-boot-process-banners.sh, sourced after both. SELinux 1.3.1.3-1.3.1.8, the
# process hardening (1.5), crypto policy 1.6.2/1.6.6/1.6.7 and the banner/GDM rules not named
# below stay on el/deb. Redefined here: the SUSE package and boot names (libselinux1, classic
# GRUB at /boot/grub2 without grubby, BLS or 01_users), the crypto policy rules that differ,
# the vendor banner fragments under /usr/lib, sshd.service.
# Rules: our own titles; see ../README.md.
#
# Decisions
# - SELinux mode: getenforce (selinux-tools) when present, else /sys/fs/selinux/enforce - the
#   image has no selinux-tools; 1.3.1.1's fix installs it.
# - 1.3.1.2: selinux=0/enforcing=0 removed from /etc/default/grub and /etc/kernel/cmdline;
#   GRUB_CMDLINE_LINUX_DEFAULT keeps (or gets) "security=selinux selinux=1" - a different
#   security= is left alone and reported. grub.cfg is regenerated (grub2-mkconfig). The fix
#   refuses (fails) while SELinux is disabled at runtime: no relabel from a fix.
# - 1.4.1: GRUB superuser "root", random 24-char password, pbkdf2 hash (600000 iterations,
#   64-byte salt) in /etc/grub.d/01_pvs-cis (not package-owned, so grub2 updates keep it);
#   the clear text ONLY in /run/pvs-cis/grub-password (0600, dir 0700) for the studio. A
#   re-run keeps the password while that /run file exists. Normal boots stay prompt-free with
#   SUSE's own switch (what YaST's "protect entry modification only" writes):
#   `set unrestricted_menu="y"` exported next to the superuser - no package script (10_linux)
#   is patched. The fix refuses when no GRUB module or image knows unrestricted_menu, and
#   runs grub2-mkconfig into a scratch file first: the real grub.cfg is written only when
#   the scratch one carries the superuser and the switch (so grub2-mkconfig reads /etc/grub.d
#   wherever the vendor scripts live). All clones of a gold share the GRUB password.
# - 1.4.2: /boot/grub2/grub.cfg only (the benchmark's scope): 0600 root:root. grub2-mkconfig
#   keeps 0600 while the config holds a password (1.4.1), so no hook.
# - 1.6.1 (new): crypto-policies-scripts installed (absent from the image); first in the map
#   order, before every update-crypto-policies call.
# - 1.6.3 (new): no uncommented CRYPTO_POLICY= in /etc/sysconfig/ssh (a missing file passes);
#   the fix comments it out and reloads sshd.service. Evidence: whether sshd's configuration
#   includes the crypto-policies back-end.
# - 1.6.4 + decision 3: the fix sets NO-SHA1 (hash/sign, certs) AND our PVS-NO-SHA1-MAC:
#   `mac = -*-128` plus `mac@!kerberos = -HMAC-SHA1` (HMAC-SHA1 off everywhere but Kerberos:
#   Active Directory signs Kerberos with aes*-cts-hmac-sha1-96). If that scope syntax is
#   refused, per-scope lines (tls, ssh, ipsec) instead. Verified on the back-ends: openssh
#   without hmac-sha1, krb5 still with the AES-SHA1 enctypes.
# - 1.6.5: listed in leap16/exceptions.default (its fix is skipped). The check stays as strict
#   as the benchmark: no -128 MAC in the global list and no HMAC-SHA1 anywhere in
#   CURRENT.pol; the evidence says when only the Kerberos scope keeps it. The fix (only when
#   the exception is removed) is the benchmark's global NO-WEAKMAC (`-*-128 -HMAC-SHA1`).
# - 1.7.1/1.7.2 (decision 5): vendor fragments are overridden under /etc, never deleted:
#   every /usr/lib/motd.d file (and /run/motd.d files that name the OS) gets an empty file of
#   the same name in /etc/motd.d; the banner is /etc/motd (which also hides /run/motd and
#   /usr/lib/motd). issue.d fragments that name the OS (\S \r \m \v, ID or NAME) get an empty
#   /etc/issue.d override; with issue-generator (/etc/issue -> /run/issue) the banner is
#   /etc/issue.d/00-pvs-cis and /run/issue is regenerated, else /etc/issue is the banner.
#   Checks read what is shown: /etc beats /run beats /usr/lib per file name; the shadowed
#   vendor files are listed as evidence (the benchmark's literal grep of /usr/lib would still
#   see them).
# - 1.7.4: pam_motd motd= paths from /etc/pam.d and /usr/lib/pam.d; a path under /usr is
#   reported, never written.
# - 1.7.5: Banner /etc/issue.net in 00-pvs-cis.conf; sshd.service reloaded; the fix fails when
#   sshd's effective Banner is not ours (sshd_config.d not included).

S1_GRUB_CFG=/boot/grub2/grub.cfg
S1_GRUB_USERS=/etc/grub.d/01_pvs-cis
S1_GRUB_PWDIR=/run/pvs-cis
S1_CP_MACMOD=PVS-NO-SHA1-MAC
S1_ISSUE_BANNER=/etc/issue.d/00-pvs-cis

# ---- chapter helpers ----

# Puts the policy's file context on PATHs we created (SELinux), where restorecon exists.
s1_restorecon() { command -v restorecon >/dev/null 2>&1 && restorecon -F "$@" >/dev/null 2>&1; return 0; }

# SELinux mode without selinux-tools: the selinuxfs flag.
e1_se_mode() {
    local v
    if command -v getenforce >/dev/null 2>&1; then getenforce 2>/dev/null && return 0; fi
    if [ -r /sys/fs/selinux/enforce ]; then
        v=$(cat /sys/fs/selinux/enforce 2>/dev/null)
        case $v in 1) echo Enforcing ;; 0) echo Permissive ;; *) echo unknown ;; esac
    else
        echo Disabled
    fi
}

s1_mkconfig() {
    local out=${1:-$S1_GRUB_CFG}
    command -v grub2-mkconfig >/dev/null 2>&1 || { ev "grub2-mkconfig: missing"; return 1; }
    grub2-mkconfig -o "$out" >/dev/null 2>&1 || { ev "grub2-mkconfig -o $out failed"; return 1; }
}

# Appends TOKEN to VAR="..." in /etc/default/grub unless the word is there.
s1_grub_default_add() {
    local var=$1 tok=$2 f=/etc/default/grub
    grep -Eq "^[[:space:]]*${var}=" "$f" || printf '%s=""\n' "$var" >> "$f"
    grep -E "^[[:space:]]*${var}=" "$f" | grep -Eq "[\"'[:space:]=]${tok}([\"'[:space:]]|$)" && return 0
    sed -i -E "s/^([[:space:]]*${var}=\"[^\"]*)\"/\1 ${tok}\"/" "$f"
}

# The GRUB in this system knows SUSE's unrestricted_menu switch (a module or a monolithic
# EFI image carries the name).
s1_grub_unrestricted_ok() {
    local f
    while IFS= read -r f; do
        if grep -aq unrestricted_menu "$f" 2>/dev/null; then
            ev "unrestricted_menu: known to $f"
            return 0
        fi
    done < <(find /boot/grub2 /usr/share/grub2 /usr/lib/grub2 /boot/efi/EFI /usr/share/efi -type f \
        \( -name '*.mod' -o -name '*.efi' \) 2>/dev/null)
    ev "unrestricted_menu: not found in any GRUB module or EFI image"
    return 1
}

# Where the grub2 package keeps its grub.d scripts (evidence).
s1_grubd_vendor() { rpm -ql grub2 2>/dev/null | grep -E '/grub\.d/[0-9]' | xargs -r -n1 dirname | sort -u | xargs; }

# The OS name of os-release (e.g. "openSUSE Leap").
s1_osname() { (. /etc/os-release 2>/dev/null; echo "${NAME:-}"); }

# FILE shows OS information: the benchmark's pattern, or the os-release NAME.
s1_shows_os() {
    local n
    c1b_osinfo "$1" >/dev/null && return 0
    n=$(s1_osname)
    [ -n "$n" ] && grep -qiF -- "$n" "$1" 2>/dev/null
}

# The files of a drop-in directory (motd.d, issue.d) that are in effect: per name, /etc beats
# /run beats /usr/lib.
s1_dropins() {
    local d=$1 n
    for n in $(c1b_glob "/usr/lib/$d/*" "/run/$d/*" "/etc/$d/*" | sed 's|.*/||' | sort -u); do
        if [ -e "/etc/$d/$n" ]; then echo "/etc/$d/$n"
        elif [ -e "/run/$d/$n" ]; then echo "/run/$d/$n"
        else echo "/usr/lib/$d/$n"; fi
    done
}

# Evidence: the vendor files of a drop-in directory hidden by an /etc file of the same name.
s1_shadowed() {
    local d=$1 f l=""
    for f in $(c1b_glob "/usr/lib/$d/*" "/run/$d/*"); do
        [ -e "/etc/$d/${f##*/}" ] && l+="$f "
    done
    [ -n "$l" ] && ev "overridden in /etc/$d: $l"
    return 0
}

# An empty /etc/<dir>/<name> that hides the vendor fragment of that name.
s1_override_empty() {
    local t=$1
    mkdir -p "${t%/*}"
    [ -L "$t" ] && rm -f "$t"
    : > "$t" || return 1
    chown root:root "$t"
    chmod 0644 "$t"
    s1_restorecon "$t"
}

# ---- 1.3.1 SELinux ----

rule selinux-installed "SELinux installed"
check_selinux_installed() {
    if pkg_installed libselinux1; then ev "libselinux1: $(rpm -q libselinux1)"; return 0; fi
    ev "libselinux1: not installed"
    return 1
}
fix_selinux_installed() {
    pkg_installed libselinux1 || pkg_install libselinux1 || return 1
    # getenforce/setenforce for the mode rules.
    pkg_installed selinux-tools || pkg_install selinux-tools || ev "selinux-tools: install failed"
    return 0
}

fix_selinux_not_disabled_at_boot() {
    local f=/etc/default/grub before sec tok
    [ -f "$f" ] || { ev "$f: missing"; return 1; }
    if [ "$(e1_se_mode)" = Disabled ]; then
        ev "SELinux disabled at runtime: boot options left alone (needs a full relabel - the bake decides)"
        return 1
    fi
    before=$(cat "$f" /etc/kernel/cmdline 2>/dev/null | md5sum)
    for tok in selinux=0 enforcing=0; do
        e1_cmdline_strip_file "$f" "$tok"
        e1_cmdline_strip_file /etc/kernel/cmdline "$tok"
    done
    sec=$(grep -E '^[[:space:]]*GRUB_CMDLINE_LINUX(_DEFAULT)?=' "$f" | grep -Eo 'security=[^[:space:]"]+' | head -n 1)
    if [ -z "$sec" ] || [ "$sec" = security=selinux ]; then
        s1_grub_default_add GRUB_CMDLINE_LINUX_DEFAULT security=selinux
    else
        ev "$f: $sec kept (another LSM chosen - not switched)"
    fi
    grep -E '^[[:space:]]*GRUB_CMDLINE_LINUX(_DEFAULT)?=' "$f" | grep -Eq '(^|[[:space:]"])selinux=' \
        || s1_grub_default_add GRUB_CMDLINE_LINUX_DEFAULT selinux=1
    if [ "$before" != "$(cat "$f" /etc/kernel/cmdline 2>/dev/null | md5sum)" ] \
        || grep -Eqs '^[[:space:]]*linux.*[[:space:]](selinux|enforcing)=0([[:space:]]|$)' "$S1_GRUB_CFG"; then
        s1_mkconfig || return 1
    fi
    return 0
}

# ---- 1.4 bootloader (classic GRUB 2 at /boot/grub2) ----

rule grub-superuser-password "GRUB superuser password"
check_grub_superuser_password() {
    local su pw bad=0
    [ -f "$S1_GRUB_CFG" ] || { ev "$S1_GRUB_CFG: missing"; return 1; }
    su=$(grep -E '^[[:space:]]*set superusers' "$S1_GRUB_CFG" | head -n 1 | sed -E 's/^[[:space:]]+//')
    pw=$(awk -F. '/^[[:space:]]*password/ { print $1 "." $2 "." $3; exit }' "$S1_GRUB_CFG" | sed -E 's/^[[:space:]]+//')
    ev "superusers: ${su:-none}"
    ev "password: ${pw:-none}"
    [ -n "$su" ] || bad=1
    [[ "$pw" =~ ^password_pbkdf2[[:space:]]+[^[:space:]]+[[:space:]]+grub\.pbkdf2\.sha512$ ]] || bad=1
    if grep -Eq '^[[:space:]]*set unrestricted_menu="?y' "$S1_GRUB_CFG"; then
        ev "menu entries: unrestricted (unrestricted_menu=y)"
    elif grep -q -- '--unrestricted' "$S1_GRUB_CFG"; then
        ev "menu entries: --unrestricted"
    else
        ev "menu entries: restricted - every boot asks for the password"
    fi
    return $bad
}
fix_grub_superuser_password() {
    local user=root pw hash tmp ok=0
    command -v grub2-mkpasswd-pbkdf2 >/dev/null 2>&1 || { ev "grub2-mkpasswd-pbkdf2 missing"; return 1; }
    command -v grub2-mkconfig >/dev/null 2>&1 || { ev "grub2-mkconfig missing"; return 1; }
    # Without the switch, a superuser makes every boot wait at a password prompt.
    s1_grub_unrestricted_ok || { ev "no GRUB password set"; return 1; }
    if ! { [ -s "$S1_GRUB_PWDIR/grub-password" ] && grep -q '^password_pbkdf2 ' "$S1_GRUB_USERS" 2>/dev/null; }; then
        pw=$(head -c 1024 /dev/urandom | tr -dc 'A-Za-z0-9' | head -c 24)
        [ "${#pw}" -eq 24 ] || { ev "password generation failed"; return 1; }
        hash=$(printf '%s\n%s\n' "$pw" "$pw" | grub2-mkpasswd-pbkdf2 --iteration-count=600000 --salt=64 2>/dev/null \
            | grep -o 'grub\.pbkdf2\.sha512\.[^[:space:]]*' | head -n 1)
        [ -n "$hash" ] || { ev "grub2-mkpasswd-pbkdf2 gave no hash"; return 1; }
        mkdir -p "$S1_GRUB_PWDIR"
        chmod 0700 "$S1_GRUB_PWDIR"
        (umask 077; printf '%s\n' "$pw" > "$S1_GRUB_PWDIR/grub-password") || return 1
        chmod 0600 "$S1_GRUB_PWDIR/grub-password"
        mkdir -p "${S1_GRUB_USERS%/*}"
        cat > "$S1_GRUB_USERS" <<EOF
#!/bin/sh
# pvs-cis (CIS 1.4.1): GRUB superuser; menu entries stay bootable without it (unrestricted_menu).
cat <<'GRUBEOF'
set superusers="$user"
password_pbkdf2 $user $hash
export superusers
set unrestricted_menu="y"
export unrestricted_menu
GRUBEOF
EOF
        chown root:root "$S1_GRUB_USERS"
        chmod 0755 "$S1_GRUB_USERS"
        s1_restorecon "$S1_GRUB_USERS"
    fi
    # A scratch run first: the real grub.cfg changes only when the script is read.
    tmp=$(mktemp -d) || return 1
    if s1_mkconfig "$tmp/grub.cfg" && grep -q '^set superusers=' "$tmp/grub.cfg" \
        && grep -q '^set unrestricted_menu="y"' "$tmp/grub.cfg"; then
        ok=1
    fi
    rm -rf "$tmp"
    if [ $ok = 0 ]; then
        ev "grub2-mkconfig does not read $S1_GRUB_USERS (vendor scripts: $(s1_grubd_vendor)) - removed again"
        rm -f "$S1_GRUB_USERS"
        return 1
    fi
    s1_mkconfig || return 1
    perm_set "$S1_GRUB_CFG" 600 root root
}

rule grub-cfg-0600-root-root "grub.cfg 0600 root:root"
check_grub_cfg_0600_root_root() { perm_ok "$S1_GRUB_CFG" 600 root root; }
fix_grub_cfg_0600_root_root() {
    [ -f "$S1_GRUB_CFG" ] || { ev "$S1_GRUB_CFG: missing"; return 1; }
    perm_set "$S1_GRUB_CFG" 600 root root
    chmod u-x "$S1_GRUB_CFG"
}

# ---- 1.6 system-wide crypto policy ----

rule crypto-policies-scripts-installed "crypto-policies-scripts installed"
check_crypto_policies_scripts_installed() {
    if pkg_installed crypto-policies-scripts; then ev "$(rpm -q crypto-policies-scripts)"; return 0; fi
    ev "crypto-policies-scripts: not installed"
    return 1
}
fix_crypto_policies_scripts_installed() { pkg_installed crypto-policies-scripts || pkg_install crypto-policies-scripts; }

rule sshd-crypto-policy-not-overridden "sshd: crypto policy not overridden (CRYPTO_POLICY)"
check_sshd_crypto_policy_not_overridden() {
    local f=/etc/sysconfig/ssh hits inc
    inc=$(grep -rlsi 'crypto-policies' /etc/ssh/sshd_config /etc/ssh/sshd_config.d /usr/etc/ssh/sshd_config /usr/etc/ssh/sshd_config.d 2>/dev/null | xargs)
    ev "crypto policy back-end included by: ${inc:-nothing found}"
    [ -f "$f" ] || { ev "$f: missing"; return 0; }
    hits=$(grep -Pi -- '^\h*CRYPTO_POLICY\h*=' "$f")
    if [ -n "$hits" ]; then ev "$f: $hits"; return 1; fi
    ev "$f: no CRYPTO_POLICY"
}
fix_sshd_crypto_policy_not_overridden() {
    local f=/etc/sysconfig/ssh
    [ -f "$f" ] || return 0
    grep -Piq -- '^\h*CRYPTO_POLICY\h*=' "$f" || return 0
    sed -ri '/^\s*(CRYPTO_POLICY\s*=)/Is/^/# /' "$f"
    systemctl reload sshd.service >/dev/null 2>&1 || true
}

# The back-ends follow decision 3: openssh without HMAC-SHA1, Kerberos with its AES-SHA1.
s1_cp_verify_macs() {
    local f bad=0 be=/etc/crypto-policies/back-ends
    command -v update-crypto-policies >/dev/null 2>&1 && ev "update-crypto-policies --check: $(update-crypto-policies --check 2>&1 | tail -n 1)"
    for f in "$be/opensshserver.config" "$be/openssh.config"; do
        [ -f "$f" ] || { ev "$f: missing"; continue; }
        if grep -qi 'hmac-sha1' "$f"; then ev "$f: still offers hmac-sha1"; bad=1; else ev "$f: no hmac-sha1"; fi
    done
    if grep -qi 'hmac-sha1' "$be/krb5.config" 2>/dev/null; then
        ev "krb5: AES-SHA1 enctypes kept (Active Directory)"
    else
        ev "krb5: no hmac-sha1 enctype - AD joins may fail"
    fi
    grep -Piq -- '^\h*mac\h*=\h*([^#\n\r]+)?-128\b' "$E1_CP_POL" 2>/dev/null && { ev "global mac list still has -128"; bad=1; }
    return $bad
}

fix_crypto_policy_no_sha1() {
    command -v update-crypto-policies >/dev/null 2>&1 || { ev "update-crypto-policies missing (1.6.1)"; return 1; }
    e1_cp_module NO-SHA1 'hash = -SHA1' 'sign = -*-SHA1' 'sha1_in_certs = 0'
    # Decision 3: HMAC-SHA1 off for all but Kerberos (1.6.5 is a studio exception).
    e1_cp_module "$S1_CP_MACMOD" 'mac = -*-128' 'mac@!kerberos = -HMAC-SHA1'
    if ! e1_cp_add NO-SHA1 "$S1_CP_MACMOD"; then
        ev "scope negation refused - per-scope lines"
        e1_cp_module "$S1_CP_MACMOD" 'mac = -*-128' 'mac@tls = -HMAC-SHA1' 'mac@ssh = -HMAC-SHA1' 'mac@ipsec = -HMAC-SHA1'
        e1_cp_add NO-SHA1 "$S1_CP_MACMOD" || return 1
    fi
    s1_cp_verify_macs
}

rule crypto-policy-no-weak-macs "Crypto policy: no weak MACs (-128, HMAC-SHA1)"
check_crypto_policy_no_weak_macs() {
    local hits rest
    [ -f "$E1_CP_POL" ] || { ev "$E1_CP_POL: missing"; return 1; }
    ev "crypto policy: $(e1_cp_show)"
    hits=$(grep -Pi -- '(^\h*mac\h*=\h*([^#\n\r]+)?-128\b|hmac-sha1)' "$E1_CP_POL")
    if [ -z "$hits" ]; then ev "no -128 MAC and no HMAC-SHA1 in $E1_CP_POL"; return 0; fi
    ev "$(cut -c1-200 <<<"$hits")"
    rest=$(grep -Piv -- '^\h*mac@(kerberos|krb5)\h*=' <<<"$hits")
    [ -z "$rest" ] && ev "HMAC-SHA1 only in the Kerberos scope"
    return 1
}
fix_crypto_policy_no_weak_macs() {
    e1_cp_module NO-WEAKMAC 'mac = -*-128 -HMAC-SHA1'
    e1_cp_add NO-WEAKMAC
}

# ---- 1.7 banners ----

rule motd-shows-no-os-details "MOTD shows no OS details"
check_motd_shows_no_os_details() {
    local files=() m hits
    for m in /etc/motd /run/motd /usr/lib/motd; do
        [ -e "$m" ] && { files+=("$m"); break; }
    done
    mapfile -t -O "${#files[@]}" files < <(s1_dropins motd.d)
    s1_shadowed motd.d
    [ ${#files[@]} -gt 0 ] || { ev "no motd files"; return 0; }
    hits=$(c1b_osinfo "${files[@]}")
    if [ -n "$hits" ]; then ev "$hits"; return 1; fi
    ev "${files[*]}: no OS information"
}
fix_motd_shows_no_os_details() {
    local f
    c1b_banner_write /etc/motd || return 1
    s1_restorecon /etc/motd
    for f in $(c1b_glob '/usr/lib/motd.d/*' '/run/motd.d/*'); do
        [ -f "$f" ] || continue
        case $f in /run/*) s1_shows_os "$f" || continue ;; esac
        s1_override_empty "/etc/motd.d/${f##*/}" || return 1
    done
    c1b_osinfo_strip $(c1b_glob '/etc/motd.d/*')
}

rule local-login-banner-shows-no-os-details "Local login banner shows no OS details"
check_local_login_banner_shows_no_os_details() {
    local files hits
    [ -e /etc/issue ] || { ev "/etc/issue: missing"; return 1; }
    mapfile -t files < <(echo /etc/issue; s1_dropins issue.d)
    s1_shadowed issue.d
    hits=$(c1b_osinfo "${files[@]}")
    if [ -n "$hits" ]; then ev "$hits"; return 1; fi
    ev "${files[*]}: no OS information"
}
fix_local_login_banner_shows_no_os_details() {
    local f gen=0
    [ -L /etc/issue ] && [ "$(readlink -f /etc/issue)" = /run/issue ] && command -v issue-generator >/dev/null 2>&1 && gen=1
    for f in $(c1b_glob '/usr/lib/issue.d/*' '/run/issue.d/*'); do
        [ -f "$f" ] && s1_shows_os "$f" || continue
        [ -e "/etc/issue.d/${f##*/}" ] && continue
        s1_override_empty "/etc/issue.d/${f##*/}" || return 1
    done
    c1b_osinfo_strip $(c1b_glob '/etc/issue.d/*')
    if [ $gen = 1 ]; then
        mkdir -p "${S1_ISSUE_BANNER%/*}"
        c1b_banner_write "$S1_ISSUE_BANNER" || return 1
        s1_restorecon "$S1_ISSUE_BANNER"
        systemctl restart issue-generator.service >/dev/null 2>&1 || issue-generator >/dev/null 2>&1
        [ -s /run/issue ] || { ev "/run/issue not regenerated"; return 1; }
    else
        c1b_banner_write /etc/issue || return 1
        s1_restorecon /etc/issue
    fi
    return 0
}

# motd= paths of pam_motd in the PAM files in effect (/etc/pam.d beats /usr/lib/pam.d).
c1b_pam_motd_paths() {
    local n f
    for n in $(c1b_glob '/usr/lib/pam.d/*' '/etc/pam.d/*' | sed 's|.*/||' | sort -u); do
        if [ -f "/etc/pam.d/$n" ]; then f=/etc/pam.d/$n; else f=/usr/lib/pam.d/$n; fi
        grep -hPo 'motd=\K\S+' "$f" 2>/dev/null
    done | tr -d "\"'" | sort -u
}

fix_pam_motd_files_show_no_os_details() {
    local p
    while IFS= read -r p; do
        [ -f "$p" ] || continue
        c1b_osinfo "$p" >/dev/null || continue
        case $p in
            /usr/*) ev "$p: vendor file names the OS - not written (override it in /etc)" ;;
            /run/*) : > "$p" ;;
            *) c1b_banner_write "$p" ;;
        esac
    done < <(c1b_pam_motd_paths)
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
    [ "$(c1b_sshd_banner)" = /etc/issue.net ] || { ev "sshd banner: $(c1b_sshd_banner) - $SSHD_FILE not read?"; return 1; }
    systemctl reload sshd.service >/dev/null 2>&1 || true
}
