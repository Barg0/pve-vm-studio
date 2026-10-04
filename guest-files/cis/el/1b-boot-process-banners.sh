# shellcheck shell=bash
# CIS AlmaLinux/Oracle/Rocky Linux 9 v3.0.0 and 10 v1.0.0 - chapter 1 (part b): builds on
# deb/1b-boot-process-banners.sh. Adds SELinux (1.3.1), the EL boot rules (1.4.3-1.4.5), the
# system-wide crypto policy (1.6) and GDM Wayland (EL9 1.8.7); redefines the GRUB rules for
# grub2/BLS and the systemd-coredump checks. Process hardening sysctls, core limits, banners
# and the other GDM checks stay on the deb implementation (sysctl.d, limits.d, /etc/issue*,
# /etc/motd*, gsettings - nothing Debian-specific; c1b_gdm knows the EL package "gdm").
# Rules: our own titles; see ../README.md.
#
# Decisions
# - 1.3.1.x: SELinux enforcing with the targeted policy (the cloud images already are). A
#   fix never relabels: when SELinux is disabled at runtime the mode fixes refuse (fail) and
#   say so - switching it on without a relabel would make the clone unusable; the bake
#   decides. selinux=0/enforcing=0 are removed from every BLS entry (grubby), from
#   /etc/default/grub, /etc/kernel/cmdline and a grubenv kernelopts.
# - 1.3.1.6 (manual): processes in unconfined_service_t are listed; pvs-cis's own session is
#   left out (the scan service runs from /usr/local, which systemd starts unconfined).
#   0 when none, else review.
# - 1.4.1: GRUB superuser "root" (what grub2-setpassword writes): random 24-char password,
#   pbkdf2 hash (600000 iterations, 64-byte salt) as GRUB2_PASSWORD= in /boot/grub2/user.cfg
#   (0600); the clear text ONLY in /run/pvs-cis/grub-password (0600, dir 0700) - the studio
#   collects it before the reboot. A re-run keeps the password while that /run file exists.
#   Normal boots stay prompt-free: BLS entries carry "grub_arg --unrestricted" (the EL
#   default; added to an entry that lacks it). grub.cfg is regenerated only when it does not
#   source user.cfg. All clones of a gold share the GRUB password.
# - 1.4.2: every top-level file of /boot/grub2 plus grub*/user.cfg under /boot: 0600
#   root:root; under /boot/efi (vfat) 0700 root:root via fstab fmask=0077,uid=0,gid=0 (after
#   the reboot). A kernel-install plugin (/etc/kernel/install.d/99-pvs-cis-grub-perms.install)
#   puts the modes back after kernel updates.
# - 1.4.3/1.4.4 (EL9, L2): rescue/emergency already run systemd-sulogin-shell; a drop-in is
#   written only when they do not. Cloud images lock root: sulogin then refuses the shell and
#   recovery needs the PVE console with boot media - the benchmark's own trade-off.
# - 1.4.5: systemd.confirm_spawn removed like selinux=0 (grubby, default/grub, kernel/cmdline).
# - 1.5.9/1.5.10: systemd-coredump is part of the systemd package on EL, so the deb check's
#   "not installed = pass" never applies; the drop-in is checked when the helper exists.
# - 1.6: `update-crypto-policies --set <base>:<modules>`; each fix adds its module to what is
#   set (other modules stay), LEGACY becomes DEFAULT. Our modules in
#   /etc/crypto-policies/policies/modules: NO-SHA1 (hash/sign SHA1 off, no SHA1 in certs),
#   NO-WEAKMAC (EL9: *-64 MACs; EL10: *-128 MACs, as each text asks), NO-SSHCBC (CBC off for
#   SSH only - TLS and Kerberos keep their CBC suites; a global CBC line is evidence, not a
#   failure). SSH logins from OpenSSH >= 8 keep working (AES-GCM/CTR, chacha20, sha2 MACs).
#   1.6.5/1.6.6 (EL9, manual): chacha20 and EtM stay on. n/a (rc 2) when openssh carries the
#   Terrapin fix (CVE-2023-48795 in its changelog or version >= 9.6), else review.
#   1.6.7 (EL9, L2): PQ added when the release ships the PQ module; n/a without it.
#   Effective after the reboot (services read the back-ends at start).
# - 1.8.7 (EL9): GDM must not force Xorg. No GDM in the server image: n/a. With GDM, the fix
#   comments out WaylandEnable=false.

E1_GRUB_DIR=/boot/grub2
E1_GRUB_CFG=/boot/grub2/grub.cfg
E1_GRUB_USERCFG=/boot/grub2/user.cfg
E1_GRUB_PWDIR=/run/pvs-cis
E1_GRUB_HOOK=/etc/kernel/install.d/99-pvs-cis-grub-perms.install
E1_CP_POL=/etc/crypto-policies/state/CURRENT.pol
E1_CP_MODS=/etc/crypto-policies/policies/modules

# ---- chapter helpers ----

# The whole-word tokens on stdin matching the regex (PCRE), one per line, unique.
e1_tokens() { grep -Po "(?<=^|[\\s\"'=])$1(?=[\\s\"']|$)" | sort -u; }

# Kernel command line tokens matching the ERE TOKEN (whole words) in the boot entries, the
# GRUB defaults, /etc/kernel/cmdline, grubenv kernelopts and grub.cfg kernelopts; one
# "where: token" per line.
e1_cmdline_find() {
    local re=$1 f
    command -v grubby >/dev/null 2>&1 &&
        grubby --info=ALL 2>/dev/null | grep -E '^args=' | e1_tokens "$re" | sed 's/^/grubby: /'
    for f in /etc/default/grub /etc/kernel/cmdline; do
        [ -f "$f" ] || continue
        grep -E '^[[:space:]]*[^#]' "$f" | e1_tokens "$re" | sed "s|^|$f: |"
    done
    grep -Prs -- '^\h*([^#\n\r]+\h+)?kernelopts=' /boot/grub2 /boot/efi 2>/dev/null \
        | grep -E "[=[:space:]\"]${re}([[:space:]\"']|$)" | cut -d: -f1 | sort -u | sed 's/$/: kernelopts/'
    return 0
}

# Removes the literal TOKEN from a kernel command line file (whole words only).
e1_cmdline_strip_file() {
    local f=$1 tok=$2 esc i
    [ -f "$f" ] || return 0
    esc=$(sed 's/[.[\*^$/]/\\&/g' <<<"$tok")
    for i in 1 2; do
        sed -i -E "s/(^|[[:space:]\"'])${esc}([[:space:]\"']|$)/\1\2/g" "$f"
    done
}

# Removes every token matching the ERE from all the places e1_cmdline_find looks at.
e1_cmdline_drop() {
    local re=$1 tok f v nv
    while IFS= read -r tok; do
        [ -n "$tok" ] || continue
        grubby --update-kernel=ALL --remove-args="$tok" >/dev/null 2>&1 || ev "grubby: could not remove $tok"
        for f in /etc/default/grub /etc/kernel/cmdline; do e1_cmdline_strip_file "$f" "$tok"; done
    done < <({
        command -v grubby >/dev/null 2>&1 && grubby --info=ALL 2>/dev/null | grep -E '^args='
        cat /etc/default/grub /etc/kernel/cmdline 2>/dev/null
    } | grep -Ev '^[[:space:]]*#' | e1_tokens "$re")
    # grubenv kernelopts (older layouts).
    if command -v grub2-editenv >/dev/null 2>&1; then
        v=$(grub2-editenv - list 2>/dev/null | sed -n 's/^kernelopts=//p')
        if [ -n "$v" ] && grep -Eq "(^|[[:space:]])${re}([[:space:]]|$)" <<<"$v"; then
            nv=$(tr ' ' '\n' <<<"$v" | grep -Ev "^${re}$" | xargs)
            grub2-editenv - set "kernelopts=$nv" || ev "grub2-editenv failed"
        fi
    fi
    # A grub.cfg that still sets them itself is regenerated.
    if grep -Pqs -- '^\h*([^#\n\r]+\h+)?kernelopts=' "$E1_GRUB_CFG" \
        && grep -Eq "kernelopts=.*[=[:space:]\"]${re}([[:space:]\"']|$)" "$E1_GRUB_CFG"; then
        grub2-mkconfig -o "$E1_GRUB_CFG" >/dev/null 2>&1 || ev "grub2-mkconfig failed"
    fi
    return 0
}

e1_se_mode() { getenforce 2>/dev/null || echo "unknown"; }
e1_se_conf() { kv_get /etc/selinux/config "$1"; }

# SELINUX=VALUE in /etc/selinux/config (the line replaced in place, appended when missing).
e1_se_conf_set() {
    local k=$1 v=$2 f=/etc/selinux/config
    [ -f "$f" ] || printf '# pvs-cis\n' > "$f"
    if grep -Eq "^[[:space:]]*${k}[[:space:]]*=" "$f"; then
        sed -i -E "s/^[[:space:]]*${k}[[:space:]]*=.*/${k}=${v}/" "$f"
    else
        printf '%s=%s\n' "$k" "$v" >> "$f"
    fi
}

# GRUB files: "path maxmode" per line (/boot/grub2 top level and grub*/user.cfg: 600; on the
# EFI system partition: 700).
e1_grub_files() {
    {
        find -L "$E1_GRUB_DIR" -mindepth 1 -maxdepth 1 -type f 2>/dev/null
        find /boot -type f \( -name 'grub*' -o -name 'user.cfg' \) 2>/dev/null
    } | sort -u | while IFS= read -r f; do
        case $f in /boot/efi/*) echo "$f 700" ;; *) echo "$f 600" ;; esac
    done
}

# systemd-coredump present (on EL it ships inside systemd)?
e1_coredump_present() {
    [ -x /usr/lib/systemd/systemd-coredump ] || pkg_installed systemd-coredump
}

e1_coredump_is() {
    local k=$1 want=$2 have
    if ! e1_coredump_present; then
        ev "systemd-coredump: not present"
        return 0
    fi
    have=$(c1b_coredump_val "$k")
    ev "coredump $k: ${have:-default}"
    [ "$have" = "$want" ]
}

# Unit's ExecStart runs sulogin.
e1_sulogin() {
    local u=$1 v
    v=$(systemctl show -p ExecStart --value "$u" 2>/dev/null)
    ev "$u: $(grep -Eo 'argv\[\]=[^;]*' <<<"$v" | head -n 1 | sed 's/argv\[\]=//; s/[[:space:]]*$//')"
    grep -q sulogin <<<"$v"
}

e1_sulogin_set() {
    local u=$1 arg=$2 d
    e1_sulogin "$u" >/dev/null && return 0
    d=/etc/systemd/system/$u.d
    mkdir -p "$d"
    printf '%s\n' '# pvs-cis: the maintenance shell asks for the root password' '[Service]' 'ExecStart=' \
        "ExecStart=-/usr/lib/systemd/systemd-sulogin-shell $arg" > "$d/00-pvs-cis-require-auth.conf"
    chmod 0644 "$d/00-pvs-cis-require-auth.conf"
    systemctl daemon-reload
}

# ---- crypto policy helpers ----

e1_cp_show() {
    update-crypto-policies --show 2>/dev/null || sed -n '1{s/[[:space:]]//g;p}' /etc/crypto-policies/config 2>/dev/null
}

# The policy has subpolicy MOD (exact name, colon separated).
e1_cp_has() { [[ ":$(e1_cp_show):" == *":$1:"* ]]; }

# Writes our module NAME with the given lines.
e1_cp_module() {
    local name=$1
    shift
    mkdir -p "$E1_CP_MODS"
    printf '%s\n' "# pvs-cis: subpolicy $name" "$@" > "$E1_CP_MODS/$name.pmod"
    chmod 0644 "$E1_CP_MODS/$name.pmod"
}

# Sets the policy to its base (LEGACY -> DEFAULT) with its modules plus MODs.
e1_cp_add() {
    local cur base mods m
    cur=$(e1_cp_show)
    [ -n "$cur" ] || cur=DEFAULT
    base=${cur%%:*}
    mods=${cur#"$base"}
    [ "$base" = LEGACY ] && base=DEFAULT
    for m in "$@"; do
        [[ "$mods:" == *":$m:"* ]] || mods="$mods:$m"
    done
    # Always re-applied: our module files may have changed under an unchanged name.
    update-crypto-policies --set "$base$mods" >/dev/null 2>&1 || { ev "update-crypto-policies --set $base$mods failed"; return 1; }
    ev "crypto policy: $base$mods"
}

# The CURRENT.pol lines for the SSH cipher (scoped ones, or the global line when none).
e1_cp_ssh_ciphers() {
    local s
    s=$(grep -Pi -- '^\h*cipher@(lib|open)ssh(-server|-client)?\h*=' "$E1_CP_POL" 2>/dev/null)
    [ -n "$s" ] || s=$(grep -Pi -- '^\h*cipher\h*=' "$E1_CP_POL" 2>/dev/null)
    printf '%s\n' "$s"
}

# openssh carries the Terrapin fix (strict key exchange)?
e1_terrapin_fixed() {
    local v
    v=$(ssh -V 2>&1 | grep -Eo 'OpenSSH_[0-9]+\.[0-9]+' | head -n 1 | cut -d_ -f2)
    ev "openssh: ${v:-unknown}"
    if rpm -q --changelog openssh 2>/dev/null | grep -q 'CVE-2023-48795'; then
        ev "openssh changelog: CVE-2023-48795 fixed"
        return 0
    fi
    [ -n "$v" ] && [ "$(printf '%s\n9.6\n' "$v" | sort -V | head -n 1)" = 9.6 ]
}

# ---- 1.3.1 SELinux ----

rule selinux-installed "SELinux installed"
check_selinux_installed() {
    if pkg_installed libselinux; then ev "libselinux: $(rpm -q libselinux)"; return 0; fi
    ev "libselinux: not installed"
    return 1
}
fix_selinux_installed() { pkg_installed libselinux || pkg_install libselinux; }

rule selinux-not-disabled-at-boot "SELinux not disabled on the kernel cmdline"
check_selinux_not_disabled_at_boot() {
    local hits
    hits=$(e1_cmdline_find '(selinux|enforcing)=0')
    grep -Eqw '(selinux|enforcing)=0' /proc/cmdline && hits+=$'\n'"running kernel: $(grep -Eow '(selinux|enforcing)=0' /proc/cmdline | xargs)"
    hits=$(sed '/^$/d' <<<"$hits")
    if [ -n "$hits" ]; then ev "$hits"; return 1; fi
    ev "no selinux=0 / enforcing=0 in boot entries, GRUB defaults or the running kernel"
}
fix_selinux_not_disabled_at_boot() { e1_cmdline_drop '(selinux|enforcing)=0'; }

rule selinux-policy-targeted "SELinux policy targeted (or mls)"
check_selinux_policy_targeted() {
    local t
    t=$(e1_se_conf SELINUXTYPE)
    ev "/etc/selinux/config SELINUXTYPE=${t:-unset}"
    command -v sestatus >/dev/null 2>&1 && ev "$(sestatus 2>/dev/null | grep -i 'loaded policy name' | xargs)"
    [[ "$t" =~ ^(targeted|mls)$ ]]
}
fix_selinux_policy_targeted() {
    [[ "$(e1_se_conf SELINUXTYPE)" =~ ^(targeted|mls)$ ]] && return 0
    pkg_installed selinux-policy-targeted || pkg_install selinux-policy-targeted || return 1
    e1_se_conf_set SELINUXTYPE targeted
}

rule selinux-not-disabled "SELinux not disabled"
check_selinux_not_disabled() {
    local c r bad=0
    c=$(e1_se_conf SELINUX)
    r=$(e1_se_mode)
    ev "configured: ${c:-unset}, running: $r"
    [[ "${c,,}" =~ ^(enforcing|permissive)$ ]] || bad=1
    [[ "$r" =~ ^(Enforcing|Permissive)$ ]] || bad=1
    return $bad
}
fix_selinux_not_disabled() {
    [[ "$(e1_se_conf SELINUX)" =~ ^(enforcing|permissive)$ ]] && return 0
    if [ "$(e1_se_mode)" = Disabled ]; then
        ev "SELinux disabled at runtime: not switched on (needs a full relabel - the bake decides)"
        return 1
    fi
    e1_se_conf_set SELINUX enforcing
}

rule selinux-enforcing "SELinux enforcing"
check_selinux_enforcing() {
    local c r
    c=$(e1_se_conf SELINUX)
    r=$(e1_se_mode)
    ev "configured: ${c:-unset}, running: $r"
    [ "${c,,}" = enforcing ] && [ "$r" = Enforcing ]
}
fix_selinux_enforcing() {
    case $(e1_se_mode) in
        Disabled)
            ev "SELinux disabled at runtime: not switched on (needs a full relabel - the bake decides)"
            return 1
            ;;
        Permissive) setenforce 1 || return 1 ;;
    esac
    e1_se_conf_set SELINUX enforcing
}

rule selinux-unconfined-services-reviewed "SELinux: unconfined services reviewed"
check_selinux_unconfined_services_reviewed() {
    local sid list
    sid=$(ps -o sid= -p $$ 2>/dev/null | xargs)
    list=$(ps -e -o label=,pid=,sid=,comm= 2>/dev/null | awk -v s="$sid" '$1 ~ /:unconfined_service_t:/ && $3 != s { print $4 "(" $2 ")" }')
    if [ -z "$list" ]; then
        ev "no process in unconfined_service_t"
        return 0
    fi
    ev "unconfined_service_t: $(head -n 20 <<<"$list" | xargs)"
    ev "decision: review - left as they are (no custom policy from the studio)"
    return 3
}

rule mcstrans-removed "mcstrans not installed"
check_mcstrans_removed() {
    if pkg_installed mcstrans; then ev "mcstrans: installed"; return 1; fi
    ev "mcstrans: not installed"
}
fix_mcstrans_removed() { pkg_purge mcstrans; }

rule setroubleshoot-removed "setroubleshoot not installed"
check_setroubleshoot_removed() {
    if pkg_installed setroubleshoot; then ev "setroubleshoot: installed"; return 1; fi
    ev "setroubleshoot: not installed"
}
fix_setroubleshoot_removed() { pkg_purge setroubleshoot; }

# ---- 1.4 bootloader (grub2, BLS) ----

rule grub-superuser-password "GRUB superuser password"
check_grub_superuser_password() {
    local hits e n=0 r=0
    hits=$(find /boot -type f -name 'user.cfg' ! -empty -exec grep -HE '^[[:space:]]*GRUB2?_PASSWORD=' {} + 2>/dev/null \
        | sed -E 's/(grub\.pbkdf2\.sha512)\..*/\1/')
    ev "password: ${hits:-none}"
    grep -q 'GRUB2\{0,1\}_PASSWORD=grub\.pbkdf2\.sha512$' <<<"$hits" || return 1
    if grep -qs 'user\.cfg' "$E1_GRUB_CFG"; then ev "$E1_GRUB_CFG: reads user.cfg"; else ev "$E1_GRUB_CFG: does not read user.cfg"; r=1; fi
    for e in /boot/loader/entries/*.conf; do
        [ -f "$e" ] || continue
        grep -Eq '^[[:space:]]*grub_arg[[:space:]].*--unrestricted' "$e" || n=$((n + 1))
    done
    ev "boot entries without --unrestricted: $n"
    return $r
}
fix_grub_superuser_password() {
    local pw hash e
    command -v grub2-mkpasswd-pbkdf2 >/dev/null 2>&1 || { ev "grub2-mkpasswd-pbkdf2 missing"; return 1; }
    if ! { [ -s "$E1_GRUB_PWDIR/grub-password" ] && grep -q '^GRUB2_PASSWORD=grub\.pbkdf2\.sha512\.' "$E1_GRUB_USERCFG" 2>/dev/null; }; then
        pw=$(head -c 1024 /dev/urandom | tr -dc 'A-Za-z0-9' | head -c 24)
        [ "${#pw}" -eq 24 ] || { ev "password generation failed"; return 1; }
        hash=$(printf '%s\n%s\n' "$pw" "$pw" | grub2-mkpasswd-pbkdf2 --iteration-count=600000 --salt=64 2>/dev/null \
            | grep -o 'grub\.pbkdf2\.sha512\.[^[:space:]]*' | head -n 1)
        [ -n "$hash" ] || { ev "grub2-mkpasswd-pbkdf2 gave no hash"; return 1; }
        mkdir -p "$E1_GRUB_PWDIR"
        chmod 0700 "$E1_GRUB_PWDIR"
        (umask 077; printf '%s\n' "$pw" > "$E1_GRUB_PWDIR/grub-password") || return 1
        chmod 0600 "$E1_GRUB_PWDIR/grub-password"
        (umask 077; printf 'GRUB2_PASSWORD=%s\n' "$hash" > "$E1_GRUB_USERCFG") || return 1
        chown root:root "$E1_GRUB_USERCFG"
        chmod 0600 "$E1_GRUB_USERCFG"
    fi
    # Boot entries stay bootable without the password; only editing and the console need it.
    for e in /boot/loader/entries/*.conf; do
        [ -f "$e" ] || continue
        grep -Eq '^[[:space:]]*grub_arg[[:space:]].*--unrestricted' "$e" || printf 'grub_arg --unrestricted\n' >> "$e"
    done
    if ! grep -qs 'user\.cfg' "$E1_GRUB_CFG"; then
        grub2-mkconfig -o "$E1_GRUB_CFG" >/dev/null 2>&1 || { ev "grub2-mkconfig failed"; return 1; }
    fi
    return 0
}

rule grub-cfg-0600-root-root "GRUB files 0600 root:root"
check_grub_cfg_0600_root_root() {
    local f max bad=0 n=0
    while read -r f max; do
        n=$((n + 1))
        perm_ok "$f" "$max" root root || bad=1
    done < <(e1_grub_files)
    [ $n -gt 0 ] || { ev "no GRUB files under /boot"; return 1; }
    return $bad
}
fix_grub_cfg_0600_root_root() {
    local f max efi=0
    while read -r f max; do
        case $f in
            /boot/efi/*) perm_ok "$f" "$max" root root >/dev/null || efi=1 ;;
            *) perm_set "$f" "$max" root root ;;
        esac
    done < <(e1_grub_files)
    # vfat has no per-file modes: the mount options set them (next mount).
    [ $efi = 1 ] && c1a_opts /boot/efi fmask=0077 uid=0 gid=0
    mkdir -p "${E1_GRUB_HOOK%/*}"
    cat > "$E1_GRUB_HOOK" <<'EOF'
#!/bin/sh
# pvs-cis (CIS 1.4.2): GRUB files stay 0600 root:root after kernel installs and removals.
find -L /boot/grub2 -mindepth 1 -maxdepth 1 -type f -exec chown root:root {} + -exec chmod u-x,go-rwx {} + 2>/dev/null
exit 0
EOF
    chmod 0755 "$E1_GRUB_HOOK"
    return 0
}

rule rescue-mode-auth "Rescue mode asks for the root password"
check_rescue_mode_auth() { e1_sulogin rescue.service; }
fix_rescue_mode_auth() { e1_sulogin_set rescue.service rescue; }

rule emergency-mode-auth "Emergency mode asks for the root password"
check_emergency_mode_auth() { e1_sulogin emergency.service; }
fix_emergency_mode_auth() { e1_sulogin_set emergency.service emergency; }

rule systemd-interactive-boot-off "No interactive boot (systemd.confirm_spawn)"
check_systemd_interactive_boot_off() {
    local hits
    hits=$(e1_cmdline_find 'systemd\.confirm_spawn(=[^[:space:]"]*)?')
    if [ -n "$hits" ]; then ev "$hits"; return 1; fi
    ev "systemd.confirm_spawn: not set"
}
fix_systemd_interactive_boot_off() { e1_cmdline_drop 'systemd\.confirm_spawn(=[^[:space:]"]*)?'; }

# ---- 1.5 process hardening (systemd-coredump ships with systemd on EL) ----

check_systemd_coredump_no_processing() { e1_coredump_is ProcessSizeMax 0; }
check_systemd_coredump_nothing_stored() { e1_coredump_is Storage none; }

# ---- 1.6 system-wide crypto policy ----

rule crypto-policy-not-legacy "Crypto policy not LEGACY"
check_crypto_policy_not_legacy() {
    ev "crypto policy: $(e1_cp_show)"
    ! grep -Piq '^\h*LEGACY\b' /etc/crypto-policies/config 2>/dev/null
}
fix_crypto_policy_not_legacy() {
    grep -Piq '^\h*LEGACY\b' /etc/crypto-policies/config 2>/dev/null || return 0
    e1_cp_add
}

rule crypto-policy-no-sha1 "Crypto policy: no SHA1 hashes or signatures"
check_crypto_policy_no_sha1() {
    local g s c bad=0
    [ -f "$E1_CP_POL" ] || { ev "$E1_CP_POL: missing"; return 1; }
    ev "crypto policy: $(e1_cp_show)"
    g=$(grep -Pi -- '^\h*(hash|sign)\h*=.*SHA-?1\b' "$E1_CP_POL")
    [ -n "$g" ] && { ev "$(cut -c1-200 <<<"$g")"; bad=1; }
    # Scopes that keep SHA1 to verify existing artifacts are allowed.
    s=$(grep -Pi -- '^\h*(hash|sign)@\S+\h*=.*SHA-?1\b' "$E1_CP_POL" | grep -Piv -- '^\h*(hash|sign)@\S*(rpm|dnssec|smime|pkcs12)\S*\h*=')
    [ -n "$s" ] && { ev "$(cut -c1-200 <<<"$s")"; bad=1; }
    c=$(grep -Pi -- '^\h*sha1_in_certs\h*=' "$E1_CP_POL" | tail -n 1 | cut -d= -f2 | xargs)
    ev "sha1_in_certs: ${c:-unset (0)}"
    [ -z "$c" ] || [ "$c" = 0 ] || bad=1
    [ $bad = 0 ] && ev "no SHA1 in the global hash/sign sets"
    return $bad
}
fix_crypto_policy_no_sha1() {
    e1_cp_module NO-SHA1 'hash = -SHA1' 'sign = -*-SHA1' 'sha1_in_certs = 0'
    e1_cp_add NO-SHA1
}

# The weak MAC suffix each text names: EL9 the 64-bit ones, EL10 the 128-bit UMAC.
e1_weak_mac() { if [ "$(e1_el)" -ge 10 ]; then echo 128; else echo 64; fi; }

rule crypto-policy-no-weak-macs "Crypto policy: no weak MACs"
check_crypto_policy_no_weak_macs() {
    local w hits
    [ -f "$E1_CP_POL" ] || { ev "$E1_CP_POL: missing"; return 1; }
    w=$(e1_weak_mac)
    hits=$(grep -Pi -- "^\\h*mac(@[^=\\h]+)?\\h*=\\h*([^#\\n\\r]+)?-${w}\\b" "$E1_CP_POL")
    if [ -n "$hits" ]; then ev "$(cut -c1-200 <<<"$hits")"; return 1; fi
    ev "no *-$w MAC in $E1_CP_POL"
}
fix_crypto_policy_no_weak_macs() {
    e1_cp_module NO-WEAKMAC "mac = -*-$(e1_weak_mac)"
    e1_cp_add NO-WEAKMAC
}

rule crypto-policy-ssh-no-cbc "Crypto policy: no CBC ciphers for SSH"
check_crypto_policy_ssh_no_cbc() {
    local s f bad=0
    [ -f "$E1_CP_POL" ] || { ev "$E1_CP_POL: missing"; return 1; }
    s=$(e1_cp_ssh_ciphers)
    if grep -qi -- '-CBC\b' <<<"$s"; then
        ev "$(grep -i -- '-CBC' <<<"$s" | cut -c1-200)"
        bad=1
    else
        ev "SSH ciphers: no CBC"
    fi
    grep -Piq -- '^\h*cipher\h*=.*-CBC\b' "$E1_CP_POL" && ev "global cipher list keeps CBC (TLS, Kerberos) - by decision"
    for f in /etc/crypto-policies/back-ends/opensshserver.config /etc/crypto-policies/back-ends/openssh.config; do
        [ -f "$f" ] || continue
        if grep -Eiq -- '-cbc' "$f"; then ev "$f: CBC cipher"; bad=1; fi
    done
    return $bad
}
fix_crypto_policy_ssh_no_cbc() {
    e1_cp_module NO-SSHCBC 'cipher@SSH = -*-CBC'
    e1_cp_add NO-SSHCBC
}

rule crypto-policy-ssh-chacha-reviewed "Crypto policy: SSH chacha20 reviewed"
check_crypto_policy_ssh_chacha_reviewed() {
    local s
    s=$(e1_cp_ssh_ciphers)
    if ! grep -qi 'CHACHA20-POLY1305' <<<"$s"; then
        ev "SSH ciphers: no chacha20-poly1305"
        return 0
    fi
    ev "SSH ciphers include chacha20-poly1305"
    e1_terrapin_fixed && { ev "Terrapin fixed (strict key exchange): does not apply"; return 2; }
    ev "decision: review - chacha20-poly1305 kept; update openssh to get the Terrapin fix"
    return 3
}

rule crypto-policy-ssh-etm-reviewed "Crypto policy: SSH EtM reviewed"
check_crypto_policy_ssh_etm_reviewed() {
    local e
    e=$(grep -Psi -- '^\h*etm\b' "$E1_CP_POL" 2>/dev/null)
    if [ -n "$e" ] && ! grep -vqi 'DISABLE_ETM' <<<"$e"; then
        ev "$(xargs <<<"$e")"
        return 0
    fi
    ev "EtM: $(xargs <<<"${e:-not disabled}")"
    e1_terrapin_fixed && { ev "Terrapin fixed (strict key exchange): does not apply"; return 2; }
    ev "decision: review - EtM kept; update openssh to get the Terrapin fix"
    return 3
}

e1_pq_available() {
    [ -f /usr/share/crypto-policies/policies/modules/PQ.pmod ] || [ -f "$E1_CP_MODS/PQ.pmod" ]
}

rule crypto-policy-post-quantum "Crypto policy: post-quantum (PQ) on"
check_crypto_policy_post_quantum() {
    e1_pq_available || { ev "PQ subpolicy: not shipped on this release"; return 2; }
    ev "crypto policy: $(e1_cp_show)"
    e1_cp_has PQ
}
fix_crypto_policy_post_quantum() {
    e1_pq_available || return 0
    e1_cp_add PQ
}

# ---- 1.8 GDM ----

rule gdm-wayland-on "GDM: Wayland not switched off"
check_gdm_wayland_on() {
    c1b_gdm || return 2
    local f hits=""
    for f in /etc/gdm/custom.conf /etc/gdm3/custom.conf; do
        [ -f "$f" ] || continue
        hits+=$(grep -PHsi -- '^\h*WaylandEnable\h*=\h*false\b' "$f")
    done
    if [ -n "$hits" ]; then ev "$hits"; return 1; fi
    ev "WaylandEnable=false: not set"
}
fix_gdm_wayland_on() {
    local f
    for f in /etc/gdm/custom.conf /etc/gdm3/custom.conf; do
        [ -f "$f" ] && sed -ri 's/^(\s*WaylandEnable\s*=\s*false)/# \1/I' "$f"
    done
    return 0
}
