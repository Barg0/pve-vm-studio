# shellcheck shell=bash
# CIS AlmaLinux/Oracle/Rocky Linux 9 v3.0.0 and 10 v1.0.0 - chapter 5: SSH server, sudo / su,
# PAM through authselect, shadow password suite, accounts. Builds on deb/5-access.sh (sourced
# first): new keys are defined here, Debian-specific checks/fixes and helpers are redefined.
# Rules: our own titles; see ../README.md.
#
# Decisions
# - sshd: same drop-in as Debian, /etc/ssh/sshd_config.d/00-pvs-cis.conf (first value wins;
#   it sorts before 50-redhat.conf, which includes the crypto-policy back-end, and before
#   cloud-init's 50-cloud-init.conf). Reload is sshd.service (never a restart).
# - Ciphers / KexAlgorithms / MACs belong to the system crypto policy (chapter 1, our .pmod
#   modules): the fix writes nothing when the effective list is clean. Only when it is not, an
#   explicit list = the effective list minus the weak names goes into 00-pvs-cis.conf (validated
#   with sshd -t) - it then pins sshd's list ahead of the policy. Weak lists per benchmark:
#   EL10 also counts hmac-sha1-etm and umac-128-etm as weak MACs, EL9 does not. chacha20 is
#   evidence only (EL backports strict KEX).
# - Host private keys: root:root <= 0600, or root:ssh_keys <= 0640 (EL's sshd-keygen and
#   cloud-init use ssh_keys) - the fix keeps the group it finds.
# - AllowGroups wheel pvs-ssh (pvs-ssh created empty). The clone admin from cloud-init is in
#   wheel; other SSH users (domain users too) must join pvs-ssh.
# - sudo is classic sudo: /etc/sudoers.d/10-pvs-cis (deb helpers). pwfeedback / visiblepw /
#   timestamp_type=global are removed from the Defaults lines that set them (other options on
#   the line stay); every change is validated with visudo -c and reverted on failure.
#   timestamp_timeout unset passes (sudo's default is 5 minutes); the fix still sets 15.
# - PAM: authselect owns /etc/pam.d/{system,password}-auth - never edited by hand. The studio
#   profile is custom/pvs-cis, created from the profile in use (none selected: local on EL10 when
#   it exists, else sssd when pam_sss is installed, else minimal), selected with the features
#   it had plus with-faillock with-pwhistory without-nullok (those the profile knows). A missing
#   pam_pwhistory / pam_pwquality line is added to the custom templates. Module arguments are
#   edited in the custom templates only, then `authselect apply-changes`. After every select or
#   apply both files must still call pam_unix in auth/account/password/session, otherwise the
#   previous templates/profile come back and the fix fails (no lock-out).
# - Options live in /etc/security/{faillock,pwhistory}.conf and pwquality.conf.d/50-pvs-cis.conf
#   (deb values: deny 5, unlock_time 900, even_deny_root, difok 2, minlen 14, minclass 3,
#   maxrepeat 3, maxsequence 3, enforce_for_root, remember 24). use_authtok stays on the
#   pam_pwhistory and pam_unix module lines (EL audits read the module lines).
# - Password hash: SHA512 (EL default, FIPS-approved) in login.defs, libuser.conf and on
#   pam_unix; an existing yescrypt is kept (both pass).
# - Package rules: the benchmark's minimum versions decide (pam >= 1.5.1-14, authselect >=
#   1.2.6-1, libpwquality >= 1.4.4-8); a pending upgrade in dnf's cache is evidence; the fix
#   upgrades the package.
# - umask: weak umask lines in /etc/profile, /etc/bashrc, profile.d are rewritten to 027 in
#   place (EL wraps them in if/else - commenting them out would break the syntax); root's
#   effective login umask is checked (su - root), the fix adds umask 027 to root's dotfiles.
# - STUDIO: `realm join` / ipa-client-install select their own authselect profile (sssd) and
#   drop custom/pvs-cis - the PAM rules then fail until the profile is re-selected.

# ---- helpers ----

e5_major() { local v=${VERSION_ID:-9}; echo "${v%%.*}"; }

c5_sshd_reload() {
    if systemctl is-active --quiet sshd.service 2>/dev/null; then
        systemctl reload sshd.service 2>/dev/null || true
    fi
    return 0
}

E5_WEAK_MACS9="hmac-md5,hmac-md5-96,hmac-ripemd160,hmac-sha1-96,umac-64@openssh.com,hmac-md5-etm@openssh.com,hmac-md5-96-etm@openssh.com,hmac-ripemd160-etm@openssh.com,hmac-sha1-96-etm@openssh.com,umac-64-etm@openssh.com"
e5_weak_macs() {
    if [ "$(e5_major)" -ge 10 ]; then
        echo "$E5_WEAK_MACS9,hmac-sha1-etm@openssh.com,umac-128-etm@openssh.com"
    else
        echo "$E5_WEAK_MACS9"
    fi
}

# Effective sshd list KEY without the names in WEAK (comma lists); "" when nothing is left.
e5_sshd_clean_list() {
    local have a out=""
    have=$(sshd_val "$1")
    IFS=, read -ra _have <<<"$have"
    for a in "${_have[@]}"; do
        [[ ",$2," == *",$a,"* ]] && continue
        out="$out,$a"
    done
    echo "${out#,}"
}

# Fix for a crypto list: nothing when CHECK passes (the crypto policy did it), else an explicit
# clean list in our drop-in.
e5_sshd_crypto_fix() {
    local key=$1 weak=$2 chk=$3 list
    c5_ssh_here >/dev/null || return 0
    "$chk" >/dev/null && return 0
    list=$(e5_sshd_clean_list "${key,,}" "$weak")
    [ -n "$list" ] || { echo "sshd $key: nothing left without the weak names"; return 1; }
    c5_sshd "$key" "$list"
}

# ---- sudo ----

# Removes the Defaults options matching ERE (one option, trimmed: "pwfeedback") from every
# sudoers file; a Defaults line left empty becomes a comment. visudo -c or everything reverts.
e5_sudoers_drop_opt() {
    local re=$1 f d i=0 changed=0
    d=$(mktemp -d)
    for f in /etc/sudoers /etc/sudoers.d/*; do
        [ -f "$f" ] || continue
        awk -v re="$re" '
            function trim(s) { sub(/^[ \t]+/, "", s); sub(/[ \t]+$/, "", s); return s }
            {
                if (match($0, /^[ \t]*Defaults([:@!>][^ \t]*)?[ \t]+/)) {
                    head = substr($0, 1, RLENGTH); rest = substr($0, RLENGTH + 1)
                    n = split(rest, a, ","); out = ""; drop = 0
                    for (j = 1; j <= n; j++) {
                        t = trim(a[j])
                        if (t ~ re) { drop = 1; continue }
                        out = out (out == "" ? "" : ", ") t
                    }
                    if (drop) {
                        if (out == "") print "# pvs-cis: Defaults line removed"; else print head out
                        next
                    }
                }
                print
            }' "$f" > "$d/new" || continue
        cmp -s "$f" "$d/new" && continue
        i=$((i + 1))
        cp -p "$f" "$d/orig.$i"
        printf '%s\t%s\n' "$i" "$f" >> "$d/list"
        cat "$d/new" > "$f"
        changed=1
    done
    if [ $changed -eq 1 ] && ! visudo -c >/dev/null 2>&1; then
        while IFS=$'\t' read -r i f; do cat "$d/orig.$i" > "$f"; done < "$d/list"
        rm -rf "$d"
        echo "visudo rejected the change - reverted"
        return 1
    fi
    rm -rf "$d"
    return 0
}

# ---- packages ----

e5_rpm_ver() { rpm -q --qf '%{VERSION}-%{RELEASE}\n' "$1" 2>/dev/null | sort -V | tail -n 1; }

# 0 when version-release A >= B.
e5_ver_ge() {
    local r
    r=$(rpm --eval "%{lua: print(rpm.vercmp('$1', '$2'))}" 2>/dev/null)
    if [[ "$r" =~ ^-?[0-9]+$ ]]; then
        [ "$r" -ge 0 ]
    else
        [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -n 1)" = "$2" ]
    fi
}

# PKG installed at MIN or later; a newer one in dnf's cache is shown.
e5_pkg_min() {
    local p=$1 min=$2 v up
    pkg_installed "$p" || { ev "$p: not installed"; return 1; }
    v=$(e5_rpm_ver "$p")
    up=$(dnf -q --cacheonly list --upgrades "$p" 2>/dev/null | awk -v p="$p" 'index($1, p ".") == 1 { print $2; exit }')
    ev "$p: $v (minimum $min)${up:+ - upgrade available: $up}"
    e5_ver_ge "$v" "$min"
}

e5_pkg_upgrade() {
    if pkg_installed "$1"; then
        dnf -y -q upgrade "$1" >/dev/null
    else
        pkg_install "$1"
    fi
}

# ---- PAM via authselect ----

E5_AS_NAME=pvs-cis
E5_AS_ID=custom/pvs-cis
E5_AS_DIR=/etc/authselect/custom/pvs-cis
E5_AS_SAVE=/var/lib/pvs-cis/authselect-saved
E5_AS_FEATURES="with-faillock with-pwhistory without-nullok"
E5_PAM_FILES="/etc/pam.d/system-auth /etc/pam.d/password-auth"

# "profile feature..." of the configuration in use, "" when authselect manages nothing.
# Without one, authselect says "No existing configuration detected." - on stdout.
e5_as_raw() {
    local o
    o=$(authselect current --raw 2>/dev/null) || return 0
    case $o in "" | No\ *) return 0 ;; esac
    head -n 1 <<<"$o"
}

# Both effective files call pam_unix in every stack.
e5_pam_sane() {
    local f t
    for f in $E5_PAM_FILES; do
        for t in auth account password session; do
            grep -Pq -- "^\h*-?${t}\h+.*\bpam_unix\.so\b" "$f" 2>/dev/null || return 1
        done
    done
    return 0
}

# The profile to copy: the one in use, else the platform default.
e5_as_base() {
    local p
    p=$(e5_as_raw)
    p=${p%% *}
    if [ -n "$p" ] && [ "$p" != "$E5_AS_ID" ]; then echo "$p"; return 0; fi
    if [ "$(e5_major)" -ge 10 ] && [ -d /usr/share/authselect/default/local ]; then
        echo local
    elif [ -d /usr/share/authselect/default/sssd ] && ls /usr/lib*/security/pam_sss.so >/dev/null 2>&1; then
        echo sssd
    elif [ -d /usr/share/authselect/default/local ]; then
        echo local
    else
        echo minimal
    fi
}

# Copies the custom templates once, before the first edit of a fix.
e5_tpl_save() {
    [ -f "$E5_AS_SAVE/system-auth" ] && return 0
    mkdir -p "$E5_AS_SAVE"
    cp -p "$E5_AS_DIR/system-auth" "$E5_AS_DIR/password-auth" "$E5_AS_SAVE/" 2>/dev/null
}

# sed -E -i SCRIPT on both custom templates; 0 when one changed.
e5_tpl_sed() {
    local f s changed=1
    for f in "$E5_AS_DIR/system-auth" "$E5_AS_DIR/password-auth"; do
        [ -f "$f" ] || continue
        s=$(cksum <"$f")
        sed -E -i "$1" "$f"
        [ "$(cksum <"$f")" = "$s" ] || changed=0
    done
    return $changed
}

# apply-changes; on a broken result the saved templates come back.
e5_as_apply() {
    if authselect apply-changes >/dev/null 2>&1 && e5_pam_sane; then
        rm -rf "$E5_AS_SAVE"
        return 0
    fi
    if [ -f "$E5_AS_SAVE/system-auth" ]; then
        cp -p "$E5_AS_SAVE/system-auth" "$E5_AS_SAVE/password-auth" "$E5_AS_DIR/"
        authselect apply-changes >/dev/null 2>&1
    fi
    rm -rf "$E5_AS_SAVE"
    echo "authselect apply-changes left PAM without pam_unix - templates restored"
    return 1
}

# custom/pvs-cis exists, is selected with our features, and its templates have the pam_pwquality
# and pam_pwhistory lines (idempotent).
e5_as_ensure() {
    local prev cur sup f bk ins=1
    local -a have=() want=()
    pkg_installed authselect || pkg_install authselect || { echo "authselect: install failed"; return 1; }
    prev=$(e5_as_raw)
    read -ra have <<<"$prev"
    cur=${have[0]:-}
    if [ ! -d "$E5_AS_DIR" ]; then
        f=$(e5_as_base)
        authselect create-profile "$E5_AS_NAME" -b "$f" >/dev/null 2>&1 \
            || { echo "authselect create-profile $E5_AS_NAME -b $f failed"; return 1; }
    fi
    sup=$(authselect list-features "$E5_AS_ID" 2>/dev/null)
    for f in "${have[@]:1}" $E5_AS_FEATURES; do
        grep -qx -- "$f" <<<"$sup" || continue
        [[ " ${want[*]} " == *" $f "* ]] || want+=("$f")
    done
    local need=0
    [ "$cur" = "$E5_AS_ID" ] || need=1
    for f in "${want[@]}"; do [[ " ${have[*]:1} " == *" $f "* ]] || need=1; done
    if [ $need -eq 1 ]; then
        bk=pvs-cis-$(date +%Y%m%d%H%M%S)
        authselect select "$E5_AS_ID" "${want[@]}" --backup="$bk" --force >/dev/null 2>&1
        if [ "$(e5_as_raw | cut -d' ' -f1)" != "$E5_AS_ID" ] || ! e5_pam_sane; then
            authselect backup-restore "$bk" >/dev/null 2>&1
            # shellcheck disable=SC2086
            [ -n "$prev" ] && authselect select $prev --force >/dev/null 2>&1
            echo "authselect select $E5_AS_ID ${want[*]} failed or broke pam_unix - restored"
            return 1
        fi
    fi
    # Module lines the base profile may lack (an authselect without with-pwhistory, a custom base).
    for f in "$E5_AS_DIR/system-auth" "$E5_AS_DIR/password-auth"; do
        [ -f "$f" ] || continue
        if ! grep -Pq '^\h*password\h+.*\bpam_pwquality\.so\b' "$f"; then
            e5_tpl_save
            sed -E -i '0,/^[[:space:]]*password[[:space:]]/s//password    requisite                                    pam_pwquality.so local_users_only\n&/' "$f"
            ins=0
        fi
        if ! grep -Pq '^\h*password\h+.*\bpam_pwhistory\.so\b' "$f"; then
            e5_tpl_save
            if grep -Pq '^\h*password\h+.*\bpam_pwquality\.so\b' "$f"; then
                sed -E -i '/^[[:space:]]*password[[:space:]].*pam_pwquality\.so/a password    required                                     pam_pwhistory.so use_authtok' "$f"
            else
                sed -E -i '0,/^[[:space:]]*password[[:space:]].*pam_unix\.so/s//password    required                                     pam_pwhistory.so use_authtok\n&/' "$f"
            fi
            ins=0
        fi
    done
    if [ $ins -eq 0 ]; then e5_as_apply || return 1; fi
    return 0
}

# Evidence: the profile in use and authselect check; 0 when one is selected and valid.
e5_as_valid() {
    local r
    r=$(e5_as_raw)
    [ -n "$r" ] || { ev "authselect: no profile selected"; return 1; }
    ev "authselect: $r"
    if authselect check >/dev/null 2>&1; then ev "authselect check: valid"; return 0; fi
    ev "authselect check: not valid (PAM changed outside authselect)"
    return 1
}

# Lines of TYPE calling MODULE in both effective files (with file names).
e5_pam_lines() { grep -PHs -- "^\h*${1}\h+.*\b${2//./\\.}\b" $E5_PAM_FILES; }

# 0 when every effective file has a TYPE line for MODULE matching the extra PCRE (may be "").
e5_pam_each() {
    local type=$1 mod=${2//./\\.} extra=${3:-} f rc=0 l
    for f in $E5_PAM_FILES; do
        l=$(grep -Ps -- "^\h*${type}\h+.*\b${mod}\b${extra}" "$f" | head -n 1)
        ev "${f##*/}: ${l:-no $type $2${3:+ ($3)}}"
        [ -n "$l" ] || rc=1
    done
    return $rc
}

# Debian helper names, authselect semantics: the deb fixes for faillock/pwquality/pwhistory
# options call these. Drop MODULE's ARG (key, key=value) from the custom templates; 0 when one
# changed (then c5_pam_update applies).
c5_profile_drop_arg() {
    local mod=${1//./\\.} arg=$2 fresh=0
    e5_as_ensure >/dev/null || return 1
    [ -f "$E5_AS_SAVE/system-auth" ] || fresh=1
    e5_tpl_save
    if e5_tpl_sed "/${mod}/ s/[[:space:]]+${arg}([[:space:]]*=[[:space:]]*[^[:space:]{}]+)?([[:space:]]|\$)/\\2/g"; then
        return 0
    fi
    [ $fresh -eq 1 ] && rm -rf "$E5_AS_SAVE"
    return 1
}

c5_pam_update() {
    e5_as_ensure >/dev/null || return 1
    e5_as_apply
}

# Adds ARG to TYPE lines of MODULE in the custom templates that lack it, then applies.
e5_tpl_add_arg() {
    local type=$1 mod=${2//./\\.} arg=$3
    e5_as_ensure || return 1
    [ -f "$E5_AS_SAVE/system-auth" ] && { e5_as_apply || return 1; }
    e5_tpl_save
    if e5_tpl_sed "/^[[:space:]]*${type}[[:space:]].*${mod}/ { /[[:space:]]${arg}([[:space:]]|\$)/! s/(${mod})([[:space:]]|\$)/\\1 ${arg}\\2/ }"; then
        e5_as_apply
    else
        rm -rf "$E5_AS_SAVE"
        return 0
    fi
}

# Effective pwquality KEY: module argument (either file) > pwquality.conf > conf.d.
c5_pwq_get() {
    local k=$1 v f w src=""
    for f in $E5_PAM_FILES; do
        v=$(c5_pam_arg "$f" password pam_pwquality.so "$k")
        if [ -n "$v" ]; then printf '%s\t%s\n' "$v" "${f##*/}"; return 0; fi
    done
    v=$(kv_get /etc/security/pwquality.conf "$k")
    if [ -n "$v" ]; then printf '%s\t/etc/security/pwquality.conf\n' "$v"; return 0; fi
    for f in $(ls /etc/security/pwquality.conf.d/*.conf 2>/dev/null | LC_ALL=C sort); do
        w=$(kv_get "$f" "$k")
        if [ -n "$w" ]; then v=$w; src=$f; fi
    done
    [ -n "$v" ] && printf '%s\t%s\n' "$v" "$src"
    return 0
}

# ---- umask ----

E5_UMASK_FILES="/etc/profile /etc/bashrc /etc/bash.bashrc /etc/profile.d/sh.local"

e5_umask_files() {
    local f
    for f in $E5_UMASK_FILES /etc/profile.d/*.sh; do [ -f "$f" ] && echo "$f"; done | sort -u
}

# Rewrites the weak umask lines c5_weak_umask reports in FILEs to 027, in place.
e5_umask_tighten() {
    local l f n
    while IFS= read -r l; do
        f=${l%%:*}; n=${l#*:}; n=${n%%:*}
        [[ "$n" =~ ^[0-9]+$ ]] || continue
        sed -i -E "${n}s/(umask[[:space:]]+)[^[:space:];#]+/\\1027/I" "$f"
    done < <(c5_weak_umask "$@")
    return 0
}

# ======================================================================================
# 5.1 SSH server
# ======================================================================================

check_sshd_config_files_0600_root() {
    local rc=0 f
    c5_ssh_here || return 2
    perm_ok /etc/ssh/sshd_config 600 root root || rc=1
    while IFS= read -r -d '' f; do
        ev "$f: $(stat -Lc '%a %U:%G' "$f")"
        rc=1
    done < <(find /etc/ssh/sshd_config.d/ -xdev -type f -name '*.conf' \( -perm /177 -o ! -user root -o ! -group root \) -print0 2>/dev/null)
    return $rc
}

check_sshd_private_host_keys_0600_root() {
    local rc=0 f n=0 m o g mask
    c5_ssh_here || return 2
    while IFS= read -r f; do
        ssh-keygen -lf "$f" >/dev/null 2>&1 || continue
        n=$((n + 1))
        read -r m o g < <(stat -Lc '%a %U %G' "$f")
        ev "$f: $m $o:$g"
        if [ "$g" = ssh_keys ]; then mask=137; else mask=177; fi
        if (( (8#$m & 8#$mask) != 0 )) || [ "$o" != root ] || { [ "$g" != root ] && [ "$g" != ssh_keys ]; }; then rc=1; fi
    done < <(c5_sshd_vals hostkey)
    [ $n -gt 0 ] || ev "no host key found"
    return $rc
}
fix_sshd_private_host_keys_0600_root() {
    local f
    c5_ssh_here >/dev/null || return 0
    while IFS= read -r f; do
        [ -f "$f" ] || continue
        if [ "$(stat -Lc '%G' "$f")" = ssh_keys ]; then
            chown root:ssh_keys "$f"
            chmod u-x,g-wx,o-rwx "$f"
        else
            chown root:root "$f"
            chmod u-x,go-rwx "$f"
        fi
    done < <(c5_sshd_vals hostkey)
    return 0
}

fix_sshd_login_limited_to_allowed_groups() {
    getent group pvs-ssh >/dev/null || groupadd -r pvs-ssh || return 1
    c5_sshd AllowGroups wheel pvs-ssh
}

check_sshd_no_weak_ciphers() {
    local c v
    c5_ssh_here || return 2
    c=$(sshd_val ciphers)
    ev "sshd ciphers: ${c:-unset}"
    [ -n "$c" ] || return 1
    if [[ ",$c," == *",chacha20-poly1305@openssh.com,"* ]]; then
        v=$(c5_ssh_version)
        ev "chacha20-poly1305 offered, OpenSSH ${v:-unknown} (advisory: strict KEX is in EL's OpenSSH)"
    fi
    c5_list_without "$c" "$C5_WEAK_CIPHERS"
}
fix_sshd_no_weak_ciphers() { e5_sshd_crypto_fix Ciphers "$C5_WEAK_CIPHERS" check_sshd_no_weak_ciphers; }

fix_sshd_no_weak_key_exchange() { e5_sshd_crypto_fix KexAlgorithms "$C5_WEAK_KEX" check_sshd_no_weak_key_exchange; }

check_sshd_no_weak_macs() {
    local m
    c5_ssh_here || return 2
    m=$(sshd_val macs)
    ev "sshd macs: ${m:-unset}"
    [ -n "$m" ] || return 1
    c5_list_without "$m" "$(e5_weak_macs)"
}
fix_sshd_no_weak_macs() { e5_sshd_crypto_fix MACs "$(e5_weak_macs)" check_sshd_no_weak_macs; }

# ======================================================================================
# 5.2 Privilege escalation
# ======================================================================================

check_sudo_installed() {
    pkg_installed sudo && { ev "sudo: $(e5_rpm_ver sudo)"; return 0; }
    ev "sudo: not installed"
    return 1
}
fix_sudo_installed() { pkg_installed sudo || pkg_install sudo; }

rule sudoers-files-access "sudoers files 0440 root"
check_sudoers_files_access() {
    local out
    [ -e /etc/sudoers ] || { ev "/etc/sudoers: missing"; return 1; }
    out=$(find /etc/sudoers /etc/sudoers.d/ -type f \( -perm /0337 -o ! -user root -o ! -group root \) -printf '%p: %m %u:%g\n' 2>/dev/null)
    [ -n "$out" ] && { ev "$out"; return 1; }
    ev "/etc/sudoers, /etc/sudoers.d/*: 0440 or stricter, root:root"
    return 0
}
fix_sudoers_files_access() {
    [ -e /etc/sudoers ] || return 0
    chown root:root /etc/sudoers
    chmod u-wx,g-wx,o-rwx /etc/sudoers
    find /etc/sudoers.d/ -type f -exec chown root:root {} + -exec chmod u-wx,g-wx,o-rwx {} + 2>/dev/null
    return 0
}

rule sudoers-d-dir-access "sudoers.d directory 0750 root"
check_sudoers_d_dir_access() {
    [ -d /etc/sudoers.d ] || { ev "/etc/sudoers.d: missing"; return 2; }
    perm_ok /etc/sudoers.d 750 root root
}
fix_sudoers_d_dir_access() {
    [ -d /etc/sudoers.d ] || return 0
    chown root:root /etc/sudoers.d
    chmod g-w,o-rwx /etc/sudoers.d
}

# Classic sudo: a logfile is the EL requirement (journal capture does not count here).
check_sudo_events_logged() {
    local lf
    [ -n "$(c5_sudo_impl)" ] || { ev "sudo: not installed"; return 2; }
    lf=$(c5_sudoers_grep "^\h*Defaults\h+([^#]+,\h*)?logfile\h*=\h*(\"|')?\H+(\"|')?(,\h*\H+\h*)*\h*(#.*)?$")
    [ -n "$lf" ] || { ev "sudo logfile: not set"; return 1; }
    ev "$lf"
    return 0
}
fix_sudo_events_logged() {
    [ -n "$(c5_sudo_impl)" ] || return 0
    c5_sudoers_add 'Defaults logfile="/var/log/sudo.log"'
}

rule sudo-pwfeedback-off "sudo: password feedback off"
check_sudo_pwfeedback_off() {
    local out
    [ -n "$(c5_sudo_impl)" ] || { ev "sudo: not installed"; return 2; }
    out=$(c5_sudoers_grep '^\h*Defaults\h+([^#\n\r]+,\h*)?pwfeedback\b')
    [ -n "$out" ] && { ev "$out"; return 1; }
    ev "pwfeedback: not enabled"
    return 0
}
fix_sudo_pwfeedback_off() { e5_sudoers_drop_opt '^pwfeedback$'; }

rule sudo-visiblepw-off "sudo: visible password prompt off"
check_sudo_visiblepw_off() {
    local out
    [ -n "$(c5_sudo_impl)" ] || { ev "sudo: not installed"; return 2; }
    out=$(c5_sudoers_grep '^\h*Defaults\h+([^#\n\r]+,\h*)?visiblepw\b')
    [ -n "$out" ] && { ev "$out"; return 1; }
    ev "visiblepw: not enabled"
    return 0
}
fix_sudo_visiblepw_off() { e5_sudoers_drop_opt '^visiblepw$'; }

check_sudo_credential_cache_15_min_or_less() {
    local out v rc=0
    [ -n "$(c5_sudo_impl)" ] || { ev "sudo: not installed"; return 2; }
    out=$(c5_sudoers_grep '^\h*Defaults\h+([^#\n\r]+,\h*)?timestamp_timeout\h*=\h*[-0-9]+')
    [ -n "$out" ] || { ev "timestamp_timeout: not set (sudo default: 5 minutes)"; return 0; }
    ev "$out"
    while read -r v; do
        { [ "$v" -lt 0 ] || [ "$v" -gt 15 ]; } && rc=1
    done < <(grep -oP 'timestamp_timeout\h*=\h*\K-?[0-9]+' <<<"$out")
    return $rc
}

rule sudo-timestamp-type "sudo: credential cache not global"
check_sudo_timestamp_type() {
    local out
    [ -n "$(c5_sudo_impl)" ] || { ev "sudo: not installed"; return 2; }
    out=$(c5_sudoers_grep '^\h*[^#\s][^#\n\r]*\btimestamp_type\h*=\h*"?global\b')
    [ -n "$out" ] && { ev "$out"; return 1; }
    ev "timestamp_type: not global"
    return 0
}
fix_sudo_timestamp_type() { e5_sudoers_drop_opt '^timestamp_type[ \t]*=[ \t]*"?global"?$'; }

# ======================================================================================
# 5.3 PAM (authselect)
# ======================================================================================

rule pam-runtime-installed-and-current "pam package installed and current"
check_pam_runtime_installed_and_current() { e5_pkg_min pam 1.5.1-14; }
fix_pam_runtime_installed_and_current() { e5_pkg_upgrade pam; }

rule authselect-installed-and-current "authselect installed and current"
check_authselect_installed_and_current() { e5_pkg_min authselect 1.2.6-1; }
fix_authselect_installed_and_current() { e5_pkg_upgrade authselect; }

rule pwquality-module-installed-and-current "libpwquality installed and current"
check_pwquality_module_installed_and_current() { e5_pkg_min libpwquality 1.4.4-8; }
fix_pwquality_module_installed_and_current() { e5_pkg_upgrade libpwquality; }

rule authselect-profile-active "authselect: profile active and valid"
check_authselect_profile_active() { e5_as_valid; }
fix_authselect_profile_active() { e5_as_ensure && e5_as_valid >/dev/null; }

rule authselect-profile-pam-modules "authselect: profile has the CIS PAM modules"
check_authselect_profile_pam_modules() {
    local p d f m rc=0
    p=$(head -n 1 /etc/authselect/authselect.conf 2>/dev/null)
    ev "authselect.conf: ${p:-missing}"
    [ -n "$p" ] || return 1
    d=/etc/authselect/$p
    [[ "$p" == custom/* ]] && [ -d "$d" ] || { ev "$p: not a custom profile"; return 1; }
    for f in system-auth password-auth; do
        for m in pam_pwquality pam_pwhistory pam_faillock pam_unix; do
            grep -Pq -- "\b${m}\.so\b" "$d/$f" 2>/dev/null || { ev "$d/$f: no $m"; rc=1; }
        done
    done
    [ $rc -eq 0 ] && ev "$d: pam_pwquality, pam_pwhistory, pam_faillock, pam_unix in both templates"
    return $rc
}
fix_authselect_profile_pam_modules() { e5_as_ensure; }

check_pam_pam_faillock_enabled() {
    local rc=0
    e5_as_valid || rc=1
    e5_pam_each auth pam_faillock.so '\h+([^#\n\r]+\h+)?preauth\b' || rc=1
    e5_pam_each auth pam_faillock.so '\h+([^#\n\r]+\h+)?authfail\b' || rc=1
    e5_pam_each account pam_faillock.so || rc=1
    return $rc
}
fix_pam_pam_faillock_enabled() { e5_as_ensure; }

check_pam_pam_pwquality_enabled() {
    local rc=0
    e5_as_valid || rc=1
    e5_pam_each password pam_pwquality.so || rc=1
    return $rc
}
fix_pam_pam_pwquality_enabled() {
    pkg_installed libpwquality || pkg_install libpwquality || return 1
    e5_as_ensure
}

check_pam_pam_pwhistory_enabled() {
    local rc=0
    e5_as_valid || rc=1
    e5_pam_each password pam_pwhistory.so || rc=1
    return $rc
}
fix_pam_pam_pwhistory_enabled() { e5_as_ensure; }

check_pam_pam_unix_enabled() {
    local rc=0 t
    e5_as_valid || rc=1
    for t in auth account password session; do e5_pam_each "$t" pam_unix.so || rc=1; done
    return $rc
}
fix_pam_pam_unix_enabled() { e5_as_ensure && e5_pam_sane; }

# ---- faillock (options in /etc/security/faillock.conf; deb fixes, EL file names) ----

check_faillock_lock_after_5_failures() {
    local v bad
    v=$(kv_get /etc/security/faillock.conf deny)
    ev "faillock.conf deny: ${v:-unset}"
    bad=$(grep -PHsi -- '^\h*auth\h+(requisite|required|sufficient)\h+pam_faillock\.so\h+([^#\n\r]+\h+)?deny\h*=\h*(0|[6-9]|[1-9][0-9]+)\b' $E5_PAM_FILES)
    [ -n "$bad" ] && ev "$bad"
    [[ "$v" =~ ^[1-5]$ ]] && [ -z "$bad" ]
}

check_faillock_unlock_after_15_min() {
    local v bad
    v=$(kv_get /etc/security/faillock.conf unlock_time)
    ev "faillock.conf unlock_time: ${v:-unset}"
    bad=$(grep -PHsi -- '^\h*auth\h+(requisite|required|sufficient)\h+pam_faillock\.so\h+([^#\n\r]+\h+)?unlock_time\h*=\h*([1-9]|[1-9][0-9]|[1-8][0-9][0-9])\b' $E5_PAM_FILES)
    [ -n "$bad" ] && ev "$bad"
    [[ "$v" =~ ^[0-9]+$ ]] && { [ "$v" -eq 0 ] || [ "$v" -ge 900 ]; } && [ -z "$bad" ]
}

check_faillock_root_is_locked_too() {
    local l bad rc=0
    l=$(grep -Pi -- '^\h*(even_deny_root|root_unlock_time\h*=\h*\d+)\b' /etc/security/faillock.conf 2>/dev/null)
    ev "faillock.conf: ${l:-no even_deny_root / root_unlock_time}"
    [ -n "$l" ] || rc=1
    bad=$(grep -Pi -- '^\h*root_unlock_time\h*=\h*([1-9]|[1-5][0-9])\b' /etc/security/faillock.conf 2>/dev/null)
    [ -n "$bad" ] && { ev "too short: $bad"; rc=1; }
    bad=$(grep -PHsi -- '^\h*auth\h+([^#\n\r]+\h+)pam_faillock\.so\h+([^#\n\r]+\h+)?root_unlock_time\h*=\h*([1-9]|[1-5][0-9])\b' $E5_PAM_FILES)
    [ -n "$bad" ] && { ev "$bad"; rc=1; }
    return $rc
}

# ---- pwquality (values via c5_pwq_get/c5_pwq_set; module lines in the EL files) ----

check_pwquality_character_classes_policy_3() {
    local k got v rc=0 neg=0 mc=0 ov
    for k in minclass dcredit ucredit lcredit ocredit; do
        got=$(c5_pwq_get "$k")
        v=${got%%$'\t'*}
        ev "pwquality $k: ${v:-unset}${got:+ (${got#*$'\t'})}"
        [ -n "$v" ] || continue
        if [ "$k" = minclass ]; then mc=$v; continue; fi
        [[ "$v" =~ ^-?[0-9]+$ ]] || { rc=1; continue; }
        [ "$v" -gt 0 ] && rc=1
        [ "$v" -lt 0 ] && neg=$((neg + 1))
    done
    ov=$(grep -PHsi -- '^\h*password\h+(requisite|required|sufficient)\h+pam_pwquality\.so\h+([^#\n\r]+\h+)?(minclass=\d*|[dulo]credit=-?\d*)\b' $E5_PAM_FILES)
    [ -n "$ov" ] && { ev "module overrides: $ov"; rc=1; }
    ev "studio policy: minclass 3"
    [[ "$mc" =~ ^[0-9]+$ ]] || mc=0
    { [ "$mc" -ge 3 ] || [ $neg -ge 3 ]; } || rc=1
    return $rc
}

check_pwquality_dictionary_check_on() {
    local out
    out=$(grep -PHsi -- '^\h*dictcheck\h*=\h*0\b' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf 2>/dev/null)
    out="$out$(grep -PHsi -- '^\h*password\h+(requisite|required|sufficient)\h+pam_pwquality\.so\h+([^#\n\r]+\h+)?dictcheck\h*=\h*0\b' $E5_PAM_FILES)"
    [ -n "$out" ] && { ev "$out"; return 1; }
    ev "dictcheck: not disabled"
    return 0
}

# ---- pwhistory (remember / enforce_for_root in pwhistory.conf, use_authtok on the line) ----

check_pwhistory_remember_24_passwords() {
    local c bad
    c=$(kv_get "$C5_PWH" remember)
    ev "pwhistory.conf remember: ${c:-unset}"
    bad=$(grep -PHsi -- '^\h*password\h+(requisite|required|sufficient)\h+pam_pwhistory\.so\h+([^#\n\r]+\h+)?remember=(2[0-3]|1[0-9]|[0-9])\b' $E5_PAM_FILES)
    [ -n "$bad" ] && ev "$bad"
    [[ "$c" =~ ^[0-9]+$ ]] && [ "$c" -ge 24 ] && [ -z "$bad" ]
}

check_pwhistory_enforced_for_root() {
    local l
    l=$(grep -Pi -- '^\h*enforce_for_root\b' "$C5_PWH" 2>/dev/null)
    ev "pwhistory.conf: ${l:-no enforce_for_root}"
    [ -n "$l" ]
}
fix_pwhistory_enforced_for_root() { c5_add_flag "$C5_PWH" enforce_for_root; }

check_pwhistory_uses_the_token_already_given() {
    e5_pam_each password pam_pwhistory.so '\h+([^#\n\r]+\h+)?use_authtok\b'
}
fix_pwhistory_uses_the_token_already_given() {
    e5_as_ensure || return 1
    [ -f "$C5_PWH" ] && sed -ri 's/^\s*use_authtok\b/# pvs-cis: &/' "$C5_PWH"
    e5_tpl_add_arg password pam_pwhistory.so use_authtok || return 1
    check_pwhistory_uses_the_token_already_given >/dev/null
}

# ---- pam_unix ----

check_pam_unix_no_empty_passwords_nullok() {
    local out
    out=$(grep -PHs -- '^\h*[^#\n\r]+\h+pam_unix\.so\h+([^#\n\r]+\h+)?nullok\b' $E5_PAM_FILES)
    [ -n "$out" ] && { ev "$out"; return 1; }
    ev "pam_unix: no nullok"
    return 0
}
fix_pam_unix_no_empty_passwords_nullok() {
    e5_as_ensure || return 1
    # without-nullok handles the template's {if not "without-nullok":nullok}; a bare nullok goes.
    e5_tpl_save
    if e5_tpl_sed '/pam_unix\.so/ s/[[:space:]]+nullok(_secure)?([[:space:]]|$)/\2/g'; then
        e5_as_apply || return 1
    else
        rm -rf "$E5_AS_SAVE"
    fi
    check_pam_unix_no_empty_passwords_nullok >/dev/null
}

check_pam_unix_no_remember_option() {
    local out
    out=$(grep -PHs -- '^\h*[^#\n\r]+\h+pam_unix\.so\h+([^#\n\r]+\h+)?remember=\d+\b' $E5_PAM_FILES)
    [ -n "$out" ] && { ev "$out"; return 1; }
    ev "pam_unix: no remember="
    return 0
}
fix_pam_unix_no_remember_option() {
    if c5_profile_drop_arg pam_unix.so remember; then c5_pam_update || return 1; fi
    check_pam_unix_no_remember_option >/dev/null
}

check_pam_unix_strong_password_hash() {
    e5_pam_each password pam_unix.so '\h+([^#\n\r]+\h+)?(sha512|yescrypt)\b'
}
fix_pam_unix_strong_password_hash() {
    e5_as_ensure || return 1
    e5_tpl_save
    e5_tpl_sed '/^[[:space:]]*password[[:space:]].*pam_unix\.so/ s/[[:space:]](md5|bigcrypt|sha256|blowfish)([[:space:]]|$)/ sha512\2/'
    e5_tpl_sed '/^[[:space:]]*password[[:space:]].*pam_unix\.so/ { /[[:space:]](sha512|yescrypt)([[:space:]]|$)/! s/(pam_unix\.so)([[:space:]]|$)/\1 sha512\2/ }'
    e5_as_apply || return 1
    check_pam_unix_strong_password_hash >/dev/null
}

check_pam_unix_uses_the_token_already_given() {
    e5_pam_each password pam_unix.so '\h+([^#\n\r]+\h+)?use_authtok\b'
}
fix_pam_unix_uses_the_token_already_given() {
    e5_tpl_add_arg password pam_unix.so use_authtok || return 1
    check_pam_unix_uses_the_token_already_given >/dev/null
}

# ======================================================================================
# 5.4 User accounts and environment
# ======================================================================================

fix_login_defs_strong_password_hash() {
    local v
    v=$(kv_get /etc/login.defs ENCRYPT_METHOD)
    [[ "${v^^}" == SHA512 || "${v^^}" == YESCRYPT ]] || kv_set /etc/login.defs ENCRYPT_METHOD SHA512
    if [ -f /etc/libuser.conf ] && ! grep -Pqi '^\h*crypt_style\h*=\h*(sha512|yescrypt)\b' /etc/libuser.conf; then
        sed -ri 's/^\s*crypt_style\s*=.*/crypt_style = sha512/' /etc/libuser.conf
    fi
    return 0
}

check_root_umask_027_or_stricter() {
    local u out rc=0
    u=$(su - root -s /bin/bash -c umask 2>/dev/null </dev/null | tail -n 1)
    ev "root login umask: ${u:-unknown}"
    { [[ "$u" =~ ^[0-7]{3,4}$ ]] && (( (8#$u & 8#027) == 8#027 )); } || rc=1
    out=$(c5_weak_umask /root/.bash_profile /root/.bashrc /root/.profile)
    [ -n "$out" ] && { ev "$out"; rc=1; }
    return $rc
}
fix_root_umask_027_or_stricter() {
    local f
    e5_umask_tighten /root/.bash_profile /root/.bashrc /root/.profile
    for f in /root/.bash_profile /root/.bashrc; do
        [ -f "$f" ] || continue
        grep -Pq '^\h*umask\h+0?[0-7]?[2367]7\b' "$f" || printf '%s\n' 'umask 027' >> "$f"
    done
    return 0
}

rule login-defs-umask "login.defs: UMASK 027 or stricter"
check_login_defs_umask() {
    local v
    v=$(kv_get /etc/login.defs UMASK)
    ev "login.defs UMASK: ${v:-unset}"
    [[ "$v" =~ ^[0-7]{3,4}$ ]] && (( (8#$v & 8#027) == 8#027 ))
}
fix_login_defs_umask() { kv_set /etc/login.defs UMASK 027; }

# EL9: no shell init file sets a weaker umask. EL10 also wants a profile.d umask and login.defs.
check_default_umask_027() {
    local out good v rc=0
    # shellcheck disable=SC2046
    out=$(c5_weak_umask $(e5_umask_files))
    [ -n "$out" ] && { ev "$out"; rc=1; }
    [ -z "$out" ] && ev "no umask weaker than 027 in /etc/profile, /etc/bashrc, profile.d"
    if [ "$(e5_major)" -ge 10 ]; then
        good=$(grep -PHsi -- '^\h*umask\h+0?[0-7]?[2367]7\b' /etc/profile.d/*.sh 2>/dev/null | head -n 1)
        ev "${good:-no umask 027 in /etc/profile.d}"
        [ -n "$good" ] || rc=1
        v=$(kv_get /etc/login.defs UMASK)
        ev "login.defs UMASK: ${v:-unset}"
        { [[ "$v" =~ ^[0-7]{3,4}$ ]] && (( (8#$v & 8#027) == 8#027 )); } || rc=1
    fi
    return $rc
}
fix_default_umask_027() {
    # shellcheck disable=SC2046
    e5_umask_tighten $(e5_umask_files | grep -vxF "$C5_UMASK")
    printf '%s\n' '# pvs-cis: default umask' 'umask 027' > "$C5_UMASK"
    chmod 0644 "$C5_UMASK"
    kv_set /etc/login.defs UMASK 027
}
