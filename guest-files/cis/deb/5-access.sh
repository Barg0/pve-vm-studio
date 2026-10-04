# shellcheck shell=bash
# CIS Ubuntu 26.04 LTS v1.0.0 - chapter 5: SSH server, privilege escalation (sudo / su), PAM,
# shadow password suite, accounts and their environment. Rules: our own titles; see ../README.md.
#
# Decisions
# - sshd: every setting goes to /etc/ssh/sshd_config.d/00-pvs-cis.conf (sshd_set). Each fix
#   runs `sshd -t` and restores the previous file when the test fails, then reloads ssh.service
#   if it runs (never a restart). /run/sshd is created before sshd -t/-T (socket activation
#   may not have created it yet, and both refuse to run without it).
# - 5.1.1/5.1.2: sshd_config and every drop-in 0600 root:root, sshd_config.d 0700. cloud-init
#   writes 50-cloud-init.conf on the clone's first boot - its mode is cloud-init's.
# - 5.1.5: AllowGroups sudo pvs-ssh (group pvs-ssh created empty). Users outside sudo who need
#   SSH must join pvs-ssh - this includes domain users/groups after a domain join.
# - 5.1.6: Banner /etc/issue.net; the file gets the studio wording when it has escapes or the
#   OS id in it (chapter 1 writes the same text).
# - 5.1.7/5.1.13/5.1.17: subtractive lists ("-weak,...") as the benchmark remediates; sshd does
#   not validate removed names, so the full lists are used. chacha20: passes when OpenSSH is
#   >= 9.6 (strict KEX, CVE-2023-48795 fixed). The conditional ETM MAC removal is not applied.
# - 5.1.14 (manual): verified from sshd -T (sntrup761 always, mlkem768 on >= 9.9) -> pass/fail.
#   Fix only when they are missing: an explicit KexAlgorithms list (PQC first, then the
#   effective list minus the weak ones), limited to `ssh -Q kex`.
# - 5.1.8 ClientAlive 15/3, 5.1.15 LoginGraceTime 60, 5.1.16 LogLevel VERBOSE, 5.1.18
#   MaxAuthTries 4, 5.1.19 MaxSessions 10, 5.1.20 MaxStartups 10:30:60.
# - 5.2.x: sudo-rs is the 26.04 default. Our sudoers drop-in is /etc/sudoers.d/10-pvs-cis
#   (0440, validated with visudo -c when visudo can check): Defaults use_pty,
#   timestamp_timeout=15, and logfile=/var/log/sudo.log only for classic sudo (sudo-rs ignores
#   it). 5.2.3 on sudo-rs: journald capture (method A); the check runs `sudo -n true` as root
#   and looks for the event in the journal. No rsyslog file (its PrivDrop user could not write
#   a root:adm 0640 log).
# - 5.2.4 (L2): the fix comments out NOPASSWD everywhere EXCEPT 90-cloud-init-users (the bake
#   removes it). STUDIO: clones get `sudo: ALL=(ALL) NOPASSWD:ALL` from user-data -> L2 fails
#   on every clone unless the studio drops that line for CIS L2 golds (group sudo suffices).
# - 5.2.7: empty group pvs-su; `auth required pam_wheel.so use_uid group=pvs-su` after
#   pam_rootok in /etc/pam.d/su - nobody but root can su; admins use sudo.
# - 5.3.1.x: "latest" = no upgrade pending in the apt cache the bake left (apt-get update must
#   have run before the fixes); fix = apt install (upgrades to the candidate).
# - PAM: only pam-auth-update profiles in /usr/share/pam-configs, never hand edits of common-*.
#   New profiles: faillock, faillock_notify, pwhistory (benchmark names) and pvs-cis-unix: a
#   copy of the shipped `unix` profile without nullok/remember=, with use_authtok (Password:)
#   and yescrypt; `unix` is then disabled (--disable) so a libpam-runtime upgrade cannot bring
#   nullok back. After every pam-auth-update the four common-* files must still call pam_unix,
#   otherwise `unix` is re-enabled and the fix fails (no lock-out).
# - faillock.conf: deny = 5, unlock_time = 900, even_deny_root (L2 rule). Key logins do not go
#   through PAM auth; password guessing can lock the admin for 15 min (intended).
# - pwquality (/etc/security/pwquality.conf.d/50-pvs-cis.conf): difok 2, minlen 14, minclass 3
#   (5.3.3.2.3 is manual: our policy, verified -> pass/fail), maxrepeat 3, maxsequence 3,
#   enforce_for_root; dictcheck/enforcing left at their defaults (=0 lines commented out).
#   STUDIO: user-data sets the admin password with `chpasswd` type: text, which goes through
#   PAM (common-password) - a password that fails this policy is REJECTED (enforce_for_root)
#   and the admin has no password. Use `type: hash` (chpasswd -e skips PAM) or enforce the
#   policy in the studio UI (>= 14 chars, 3 classes, no 4 repeats/sequences, no dictionary word).
# - pwhistory: profile line carries no options; remember = 24, enforce_for_root, use_authtok in
#   /etc/security/pwhistory.conf (the benchmark's preferred single location).
# - login.defs: PASS_MAX_DAYS 365, PASS_MIN_DAYS 1 (5.4.1.2 manual, verified), PASS_WARN_AGE 7,
#   ENCRYPT_METHOD YESCRYPT, UMASK 027; useradd -D INACTIVE 45. Existing users with a password
#   get the same via chage. cloud-init creates the clone admin with useradd at first boot and
#   chpasswd sets the date to that day, so aging starts fresh (expires after 365 days).
# - 5.4.1.6: fix resets a future change date to today.
# - 5.4.2.1-3: check only (renumbering accounts is a human decision).
# - 5.4.2.4: root stays locked (cloud image); the fix locks it only when it has no password.
# - 5.4.2.5: fix takes group/other write off root-PATH directories and chowns them to root;
#   missing directories are reported, not created.
# - 5.4.3.2: TMOUT=900 readonly+export in /etc/profile.d/50-pvs-cis-tmout.sh, POSIX form
#   (dash sources profile.d too, `typeset` would error there); TMOUT lines elsewhere commented.
# - 5.4.3.3: umask 027 in /etc/profile.d/60-pvs-cis-umask.sh and UMASK 027 in login.defs;
#   weaker umask lines in /etc/profile and profile.d are commented out.

# ---- chapter helpers ----

C5_SUDOERS=/etc/sudoers.d/10-pvs-cis
C5_PWQ=/etc/security/pwquality.conf.d/50-pvs-cis.conf
C5_PAMCFG=/usr/share/pam-configs

c5_sshd_bin() { readlink -e /usr/sbin/sshd 2>/dev/null || readlink -e /sbin/sshd 2>/dev/null; }

# 0 when sshd is installed; prints the n/a evidence otherwise.
c5_ssh_here() {
    if [ -z "$(c5_sshd_bin)" ]; then
        ev "openssh-server: not installed"
        return 1
    fi
    mkdir -p /run/sshd 2>/dev/null && chmod 0755 /run/sshd 2>/dev/null
    return 0
}

# Every effective value of KEY (lower case), one per line.
c5_sshd_vals() {
    sshd -T -C user=root -C host="$(hostname)" -C addr=127.0.0.1 2>/dev/null \
        | awk -v k="${1,,}" 'tolower($1) == k { $1 = ""; sub(/^ /, ""); print }'
}

c5_sshd_reload() {
    if systemctl is-active --quiet ssh.service 2>/dev/null; then
        systemctl reload ssh.service 2>/dev/null || true
    fi
    return 0
}

# sshd_set KEY VALUE..., validated: the previous drop-in comes back when sshd -t fails.
c5_sshd() {
    local bak had=0
    c5_ssh_here >/dev/null || return 0
    bak=$(mktemp)
    if [ -f "$SSHD_FILE" ]; then cp -p "$SSHD_FILE" "$bak"; had=1; fi
    sshd_set "$@"
    if ! sshd -t 2>&1; then
        if [ $had -eq 1 ]; then cat "$bak" > "$SSHD_FILE"; else rm -f "$SSHD_FILE"; fi
        rm -f "$bak"
        echo "sshd -t failed after '$*' - reverted"
        return 1
    fi
    rm -f "$bak"
    c5_sshd_reload
}

# Effective VALUE of a numeric sshd KEY is within MIN..MAX.
c5_sshd_range() {
    local k=$1 min=$2 max=$3 v
    c5_ssh_here || return 2
    v=$(sshd_val "$k")
    ev "sshd $k: ${v:-unset}"
    [[ "$v" =~ ^[0-9]+$ ]] && [ "$v" -ge "$min" ] && [ "$v" -le "$max" ]
}

# A comma list (sshd -T) contains none of the names in the second comma list.
c5_list_without() {
    local have=$1 bad=$2 n rc=0
    IFS=, read -ra _bad <<<"$bad"
    for n in "${_bad[@]}"; do
        if [[ ",$have," == *",$n,"* ]]; then ev "weak: $n"; rc=1; fi
    done
    return $rc
}

c5_ssh_version() { ssh -V 2>&1 | grep -oE 'OpenSSH_[0-9]+\.[0-9]+' | head -n 1 | cut -d_ -f2; }

# 0 when version A >= B (major.minor).
c5_ver_ge() { [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -n 1)" = "$2" ]; }

C5_WEAK_CIPHERS="3des-cbc,blowfish-cbc,cast128-cbc,aes128-cbc,aes192-cbc,aes256-cbc,arcfour,arcfour128,arcfour256,rijndael-cbc@lysator.liu.se"
C5_WEAK_KEX="diffie-hellman-group1-sha1,diffie-hellman-group14-sha1,diffie-hellman-group-exchange-sha1"
C5_WEAK_MACS="hmac-md5,hmac-md5-96,hmac-ripemd160,hmac-sha1-96,umac-64@openssh.com,hmac-md5-etm@openssh.com,hmac-md5-96-etm@openssh.com,hmac-ripemd160-etm@openssh.com,hmac-sha1-96-etm@openssh.com,umac-64-etm@openssh.com,umac-128-etm@openssh.com"

# ---- sudo ----

# "sudo-rs" or "sudo" (classic) - the implementation `sudo` runs, "" when none.
c5_sudo_impl() {
    local v
    command -v sudo >/dev/null 2>&1 || { echo ""; return 0; }
    v=$(sudo -V 2>/dev/null | head -n 1)
    if [[ "$v" == *sudo-rs* ]] || [[ "$(readlink -f "$(command -v sudo)")" == *sudo-rs* ]]; then
        echo sudo-rs
    else
        echo sudo
    fi
}

# Uncommented sudoers lines matching a PCRE (case-insensitive), with file names.
c5_sudoers_grep() { grep -rPHsi -- "$1" /etc/sudoers /etc/sudoers.d/ 2>/dev/null; }

# Adds LINE to our sudoers drop-in unless it is there; validated with visudo when it can check.
c5_sudoers_add() {
    local line=$1 bak had=0
    mkdir -p /etc/sudoers.d
    bak=$(mktemp)
    if [ -f "$C5_SUDOERS" ]; then cp -p "$C5_SUDOERS" "$bak"; had=1; fi
    touch "$C5_SUDOERS"
    grep -qxF -- "$line" "$C5_SUDOERS" || printf '%s\n' "$line" >> "$C5_SUDOERS"
    chown root:root "$C5_SUDOERS"
    chmod 0440 "$C5_SUDOERS"
    if command -v visudo >/dev/null 2>&1 && visudo -c -f /etc/sudoers >/dev/null 2>&1; then
        if ! visudo -c -f "$C5_SUDOERS" >/dev/null 2>&1; then
            if [ $had -eq 1 ]; then cat "$bak" > "$C5_SUDOERS"; else rm -f "$C5_SUDOERS"; fi
            rm -f "$bak"
            echo "visudo rejected '$line' - reverted"
            return 1
        fi
    fi
    rm -f "$bak"
    return 0
}

# Comments out sudoers lines matching a PCRE, in every file but cloud-init's (the bake owns it).
c5_sudoers_comment() {
    local re=$1 f
    for f in /etc/sudoers /etc/sudoers.d/*; do
        [ -f "$f" ] || continue
        [ "$f" = /etc/sudoers.d/90-cloud-init-users ] && continue
        if grep -Pqi -- "$re" "$f"; then
            # sed has no PCRE: comment out the lines grep -P finds, by number.
            grep -Pni -- "$re" "$f" | cut -d: -f1 | sort -rn | while read -r n; do
                sed -i "${n}s/^/# pvs-cis: /" "$f"
            done
        fi
    done
    return 0
}

# ---- PAM ----

# The common-* files still have pam_unix in every stack (a broken stack locks everyone out).
c5_pam_sane() {
    grep -Pq '^\h*auth\h+.*\bpam_unix\.so\b' /etc/pam.d/common-auth 2>/dev/null \
        && grep -Pq '^\h*account\h+.*\bpam_unix\.so\b' /etc/pam.d/common-account 2>/dev/null \
        && grep -Pq '^\h*password\h+.*\bpam_unix\.so\b' /etc/pam.d/common-password 2>/dev/null \
        && grep -Pq '^\h*session\h+.*\bpam_unix\.so\b' /etc/pam.d/common-session 2>/dev/null
}

# pam-auth-update ARGS..., then the sanity check; on a broken result `unix` is re-enabled.
c5_pam_update() {
    DEBIAN_FRONTEND=noninteractive pam-auth-update "$@" </dev/null >/dev/null 2>&1
    if ! c5_pam_sane; then
        echo "pam_unix missing after pam-auth-update $* - re-enabling unix"
        DEBIAN_FRONTEND=noninteractive pam-auth-update --enable unix </dev/null >/dev/null 2>&1
        return 1
    fi
    return 0
}

# The profile that provides pam_unix: ours when it exists, else the shipped one.
c5_unix_profile() { if [ -f "$C5_PAMCFG/pvs-cis-unix" ]; then echo pvs-cis-unix; else echo unix; fi; }

# Writes the pvs-cis-unix profile from the shipped `unix` one: no nullok / remember=, the
# Password: line with use_authtok, both password lines with a strong hash.
c5_unix_profile_write() {
    local src=$C5_PAMCFG/unix
    [ -f "$src" ] || src=$C5_PAMCFG/pvs-cis-unix
    [ -f "$src" ] || { echo "no unix pam-auth-update profile"; return 1; }
    awk '
        /^Name:/ { print "Name: Unix authentication (pvs-cis)"; next }
        /^[A-Za-z-]+:/ { sec = $1 }
        /pam_unix\.so/ {
            line = $0
            gsub(/[ \t]+nullok(_secure)?/, "", line)
            gsub(/[ \t]+remember=[0-9]+/, "", line)
            if (sec == "Password:" || sec == "Password-Initial:") {
                if (line !~ /(sha512|yescrypt)/) line = line " yescrypt"
                if (sec == "Password:" && line !~ /use_authtok/) line = line " use_authtok"
            }
            print line; next
        }
        { print }' "$src" > "$C5_PAMCFG/pvs-cis-unix.new" || return 1
    mv -f "$C5_PAMCFG/pvs-cis-unix.new" "$C5_PAMCFG/pvs-cis-unix"
    chmod 0644 "$C5_PAMCFG/pvs-cis-unix"
}

# Switches pam_unix to our profile (idempotent).
c5_unix_profile_use() {
    c5_unix_profile_write || return 1
    c5_pam_update --enable pvs-cis-unix || return 1
    if grep -qx 'unix' /var/lib/pam/seen 2>/dev/null || [ -f "$C5_PAMCFG/unix" ]; then
        c5_pam_update --disable unix || return 1
    fi
    return 0
}

# Removes MODULE's ARG (key or key=value) from every pam-auth-update profile; 0 when one changed.
c5_profile_drop_arg() {
    local mod=$1 arg=$2 f changed=1
    for f in "$C5_PAMCFG"/*; do
        [ -f "$f" ] || continue
        if grep -Pq -- "\b${mod//./\\.}\h+([^#\n\r]+\h+)?${arg}\b" "$f"; then
            sed -Ei "/${mod//./\\.}/s/[[:space:]]+${arg}(=[^[:space:]]*)?([[:space:]]|$)/\2/g" "$f"
            changed=0
        fi
    done
    return $changed
}

# Value of KEY=... on MODULE's uncommented lines of type TYPE in a pam.d FILE (last one).
c5_pam_arg() {
    local file=$1 type=$2 mod=$3 k=$4
    grep -P -- "^\h*${type}\h+.*\b${mod//./\\.}\b" "$file" 2>/dev/null \
        | grep -oP -- "(?<=\h)${k}=\S+" | tail -n 1 | cut -d= -f2-
}

# A flag (no value) on MODULE's lines.
c5_pam_flag() {
    grep -Pq -- "^\h*${2}\h+.*\b${3//./\\.}\h+([^#\n\r]+\h+)?${4}\b" "$1" 2>/dev/null
}

# Effective pwquality value of KEY: "value<TAB>where" (module argument > pwquality.conf >
# the last pwquality.conf.d file that sets it). Nothing when unset.
c5_pwq_get() {
    local k=$1 v f src=""
    v=$(c5_pam_arg /etc/pam.d/common-password password pam_pwquality.so "$k")
    if [ -n "$v" ]; then printf '%s\tcommon-password\n' "$v"; return 0; fi
    v=$(kv_get /etc/security/pwquality.conf "$k")
    if [ -n "$v" ]; then printf '%s\t/etc/security/pwquality.conf\n' "$v"; return 0; fi
    for f in $(ls /etc/security/pwquality.conf.d/*.conf 2>/dev/null | LC_ALL=C sort); do
        local w
        w=$(kv_get "$f" "$k")
        if [ -n "$w" ]; then v=$w; src=$f; fi
    done
    [ -n "$v" ] && printf '%s\t%s\n' "$v" "$src"
    return 0
}

# KEY = VALUE in our pwquality drop-in; the key commented out in pwquality.conf and removed
# from pam_pwquality's profile lines (then common-password is regenerated).
c5_pwq_set() {
    local k=$1 v=$2
    mkdir -p /etc/security/pwquality.conf.d
    [ -f /etc/security/pwquality.conf ] && sed -ri "s/^\s*${k}\s*=/# &/" /etc/security/pwquality.conf
    kv_set "$C5_PWQ" "$k" "$v" " = "
    chmod 0644 "$C5_PWQ"
    if c5_profile_drop_arg pam_pwquality.so "$k"; then c5_pam_update --package || return 1; fi
    return 0
}

# Prints the check line for a numeric pwquality KEY and tests it with a bash condition on $v.
c5_pwq_check() {
    local k=$1 cond=$2 got v where
    got=$(c5_pwq_get "$k")
    v=${got%%$'\t'*}
    where=${got#*$'\t'}
    ev "pwquality $k: ${v:-unset}${got:+ ($where)}"
    [[ "$v" =~ ^-?[0-9]+$ ]] || return 1
    eval "$cond"
}

# Flag line present (uncommented) in FILE.
c5_has_flag() { grep -Pq -- "^\h*${2}\b" "$1" 2>/dev/null; }

c5_add_flag() {
    touch "$1"
    c5_has_flag "$1" "$2" || printf '%s\n' "$2" >> "$1"
}

# ---- accounts ----

# Users with a real password hash in /etc/shadow.
c5_pw_users() { awk -F: '$2 ~ /^\$.+\$/ { print $1 }' /etc/shadow 2>/dev/null; }

# The shells that count as valid login shells (an ERE alternation).
c5_valid_shells() {
    awk -F/ '$NF != "nologin" && /^\// { print }' /etc/shells 2>/dev/null \
        | sed -E 's/[.[\*^$()+?{|]/\\&/g' | paste -s -d '|' -
}

# ======================================================================================
# 5.1 SSH server
# ======================================================================================

rule sshd-config-files-0600-root "sshd: config files 0600 root"
check_sshd_config_files_0600_root() {
    local rc=0 f
    c5_ssh_here || return 2
    perm_ok /etc/ssh/sshd_config 600 root root || rc=1
    while IFS= read -r -d '' f; do
        ev "$f: $(stat -Lc '%a %U:%G' "$f")"
        rc=1
    done < <(find /etc/ssh/sshd_config.d/ -xdev -type f -name '*.conf' \( -perm /077 -o ! -user root -o ! -group root \) -print0 2>/dev/null)
    return $rc
}
fix_sshd_config_files_0600_root() {
    local f
    [ -f /etc/ssh/sshd_config ] || return 0
    chmod u-x,og-rwx /etc/ssh/sshd_config
    chown root:root /etc/ssh/sshd_config
    while IFS= read -r -d '' f; do
        chmod u-x,og-rwx "$f"
        chown root:root "$f"
    done < <(find /etc/ssh/sshd_config.d -type f -print0 2>/dev/null)
    return 0
}

rule sshd-drop-in-directory-0700-root "sshd: drop-in directory 0700 root"
check_sshd_drop_in_directory_0700_root() {
    c5_ssh_here || return 2
    [ -d /etc/ssh/sshd_config.d ] || { ev "/etc/ssh/sshd_config.d: missing"; return 0; }
    perm_ok /etc/ssh/sshd_config.d 700 root root
}
fix_sshd_drop_in_directory_0700_root() {
    [ -d /etc/ssh/sshd_config.d ] || return 0
    chown root:root /etc/ssh/sshd_config.d
    chmod 0700 /etc/ssh/sshd_config.d
}

rule sshd-private-host-keys-0600-root "sshd: private host keys 0600 root"
check_sshd_private_host_keys_0600_root() {
    local rc=0 f n=0
    c5_ssh_here || return 2
    while IFS= read -r f; do
        ssh-keygen -lf "$f" >/dev/null 2>&1 || continue
        n=$((n + 1))
        perm_ok "$f" 600 root root || rc=1
    done < <(c5_sshd_vals hostkey)
    [ $n -gt 0 ] || ev "no host key found"
    return $rc
}
fix_sshd_private_host_keys_0600_root() {
    local f
    c5_ssh_here >/dev/null || return 0
    while IFS= read -r f; do
        [ -f "$f" ] || continue
        chown root:root "$f"
        chmod 0600 "$f"
    done < <(c5_sshd_vals hostkey)
    return 0
}

rule sshd-public-host-keys-0644-root "sshd: public host keys 0644 root"
check_sshd_public_host_keys_0644_root() {
    local rc=0 f n=0
    c5_ssh_here || return 2
    while IFS= read -r f; do
        f="$f.pub"
        ssh-keygen -lf "$f" >/dev/null 2>&1 || continue
        n=$((n + 1))
        perm_ok "$f" 644 root root || rc=1
    done < <(c5_sshd_vals hostkey)
    [ $n -gt 0 ] || ev "no public host key found"
    return $rc
}
fix_sshd_public_host_keys_0644_root() {
    local f
    c5_ssh_here >/dev/null || return 0
    while IFS= read -r f; do
        [ -f "$f.pub" ] || continue
        chown root:root "$f.pub"
        chmod 0644 "$f.pub"
    done < <(c5_sshd_vals hostkey)
    return 0
}

rule sshd-login-limited-to-allowed-groups "sshd: login limited to allowed groups"
check_sshd_login_limited_to_allowed_groups() {
    local out
    c5_ssh_here || return 2
    out=$(sshd -T -C user=root -C host="$(hostname)" -C addr=127.0.0.1 2>/dev/null | grep -Pi '^\h*(allow|deny)(users|groups)\h+\H+')
    if [ -z "$out" ]; then ev "no AllowUsers/AllowGroups/DenyUsers/DenyGroups"; return 1; fi
    ev "$out"
    return 0
}
fix_sshd_login_limited_to_allowed_groups() {
    getent group pvs-ssh >/dev/null || groupadd -r pvs-ssh || return 1
    c5_sshd AllowGroups sudo pvs-ssh
}

rule sshd-warning-banner-before-login "sshd: warning banner before login"
check_sshd_warning_banner_before_login() {
    local b id
    c5_ssh_here || return 2
    b=$(sshd_val banner)
    ev "sshd banner: ${b:-unset}"
    [[ "$b" == /* ]] || return 1
    [ -f "$b" ] || { ev "$b: missing"; return 1; }
    id=$(. /etc/os-release && echo "${ID:-ubuntu}")
    if grep -Psi -- "(\\\\v|\\\\r|\\\\m|\\\\s|\\b${id}\\b)" "$b"; then
        ev "$b: OS information in the banner"
        return 1
    fi
    return 0
}
fix_sshd_warning_banner_before_login() {
    local id
    id=$(. /etc/os-release && echo "${ID:-ubuntu}")
    if [ ! -s /etc/issue.net ] || grep -Psqi -- "(\\\\v|\\\\r|\\\\m|\\\\s|\\b${id}\\b)" /etc/issue.net; then
        printf '%s\n' "Authorized use only. Activity on this system is monitored and recorded." > /etc/issue.net
        chown root:root /etc/issue.net
        chmod 0644 /etc/issue.net
    fi
    c5_sshd Banner /etc/issue.net
}

rule sshd-no-weak-ciphers "sshd: no weak ciphers"
check_sshd_no_weak_ciphers() {
    local c v rc=0
    c5_ssh_here || return 2
    c=$(sshd_val ciphers)
    ev "sshd ciphers: ${c:-unset}"
    [ -n "$c" ] || return 1
    c5_list_without "$c" "$C5_WEAK_CIPHERS" || rc=1
    if [[ ",$c," == *",chacha20-poly1305@openssh.com,"* ]]; then
        v=$(c5_ssh_version)
        # Debian backports strict KEX (Terrapin) into older OpenSSH (12: 9.2p1-2+deb12u2).
        if zcat /usr/share/doc/openssh-server/changelog.Debian.gz 2>/dev/null | grep -q 'CVE-2023-48795'; then
            ev "chacha20-poly1305 offered, OpenSSH ${v:-unknown} - strict KEX backported (CVE-2023-48795 in the changelog)"
        else
            ev "chacha20-poly1305 offered, OpenSSH ${v:-unknown} (strict KEX from 9.6)"
            { [ -n "$v" ] && c5_ver_ge "$v" 9.6; } || rc=1
        fi
    fi
    return $rc
}
fix_sshd_no_weak_ciphers() { c5_sshd Ciphers "-$C5_WEAK_CIPHERS"; }

rule sshd-client-alive-interval-and-count "sshd: client alive interval and count"
check_sshd_client_alive_interval_and_count() {
    local i n
    c5_ssh_here || return 2
    i=$(sshd_val clientaliveinterval)
    n=$(sshd_val clientalivecountmax)
    ev "sshd clientaliveinterval: ${i:-unset}, clientalivecountmax: ${n:-unset}"
    [[ "$i" =~ ^[0-9]+$ ]] && [[ "$n" =~ ^[0-9]+$ ]] && [ "$i" -gt 0 ] && [ "$n" -gt 0 ]
}
fix_sshd_client_alive_interval_and_count() { c5_sshd ClientAliveInterval 15 && c5_sshd ClientAliveCountMax 3; }

rule sshd-all-forwarding-off "sshd: all forwarding off"
check_sshd_all_forwarding_off() { c5_ssh_here || return 2; sshd_is disableforwarding yes; }
fix_sshd_all_forwarding_off() { c5_sshd DisableForwarding yes; }

rule sshd-gssapi-authentication-off "sshd: GSSAPI authentication off"
check_sshd_gssapi_authentication_off() { c5_ssh_here || return 2; sshd_is gssapiauthentication no; }
fix_sshd_gssapi_authentication_off() { c5_sshd GSSAPIAuthentication no; }

rule sshd-host-based-authentication-off "sshd: host-based authentication off"
check_sshd_host_based_authentication_off() { c5_ssh_here || return 2; sshd_is hostbasedauthentication no; }
fix_sshd_host_based_authentication_off() { c5_sshd HostbasedAuthentication no; }

rule sshd-rhosts-files-ignored "sshd: rhosts files ignored"
check_sshd_rhosts_files_ignored() { c5_ssh_here || return 2; sshd_is ignorerhosts yes; }
fix_sshd_rhosts_files_ignored() { c5_sshd IgnoreRhosts yes; }

rule sshd-no-weak-key-exchange "sshd: no weak key exchange"
check_sshd_no_weak_key_exchange() {
    local k
    c5_ssh_here || return 2
    k=$(sshd_val kexalgorithms)
    ev "sshd kexalgorithms: ${k:-unset}"
    [ -n "$k" ] || return 1
    c5_list_without "$k" "$C5_WEAK_KEX"
}
fix_sshd_no_weak_key_exchange() {
    # An explicit list written by 5.1.14 already leaves the weak ones out.
    if grep -Eq '^[[:space:]]*KexAlgorithms[[:space:]]+[^-]' "$SSHD_FILE" 2>/dev/null; then
        check_sshd_no_weak_key_exchange >/dev/null && return 0
    fi
    c5_sshd KexAlgorithms "-$C5_WEAK_KEX"
}

rule sshd-post-quantum-key-exchange-offered "sshd: post-quantum key exchange offered"
check_sshd_post_quantum_key_exchange_offered() {
    local k v rc=0
    c5_ssh_here || return 2
    v=$("$(c5_sshd_bin)" -V 2>&1 | grep -Psio 'openssh_\d+\.\d+' | head -n 1 | cut -d_ -f2)
    k=$(sshd_val kexalgorithms)
    ev "OpenSSH ${v:-unknown}; kexalgorithms: ${k:-unset}"
    [[ ",$k," == *",sntrup761x25519-sha512"* ]] || { ev "missing: sntrup761x25519-sha512"; rc=1; }
    if [ -n "$v" ] && c5_ver_ge "$v" 9.9; then
        [[ ",$k," == *",mlkem768x25519-sha256,"* ]] || { ev "missing: mlkem768x25519-sha256"; rc=1; }
    fi
    return $rc
}
fix_sshd_post_quantum_key_exchange_offered() {
    local k pq="" a list="" sup
    c5_ssh_here >/dev/null || return 0
    check_sshd_post_quantum_key_exchange_offered >/dev/null && return 0
    sup=$(ssh -Q kex 2>/dev/null | paste -s -d, -)
    for a in mlkem768x25519-sha256 sntrup761x25519-sha512 sntrup761x25519-sha512@openssh.com; do
        [[ ",$sup," == *",$a,"* ]] && pq="$pq,$a"
    done
    k=$(sshd_val kexalgorithms)
    IFS=, read -ra _k <<<"$k"
    for a in "${_k[@]}"; do
        [[ ",$C5_WEAK_KEX,$pq," == *",$a,"* ]] && continue
        list="$list,$a"
    done
    list="${pq#,}${list}"
    list=${list#,}
    [ -n "$list" ] || return 1
    c5_sshd KexAlgorithms "$list"
}

rule sshd-login-grace-time-60s-or-less "sshd: login grace time 60s or less"
check_sshd_login_grace_time_60s_or_less() { c5_sshd_range logingracetime 1 60; }
fix_sshd_login_grace_time_60s_or_less() { c5_sshd LoginGraceTime 60; }

rule sshd-log-level-info-or-verbose "sshd: log level INFO or VERBOSE"
check_sshd_log_level_info_or_verbose() {
    local v
    c5_ssh_here || return 2
    v=$(sshd_val loglevel)
    ev "sshd loglevel: ${v:-unset}"
    [[ "${v^^}" == VERBOSE || "${v^^}" == INFO ]]
}
fix_sshd_log_level_info_or_verbose() { c5_sshd LogLevel VERBOSE; }

rule sshd-no-weak-macs "sshd: no weak MACs"
check_sshd_no_weak_macs() {
    local m
    c5_ssh_here || return 2
    m=$(sshd_val macs)
    ev "sshd macs: ${m:-unset}"
    [ -n "$m" ] || return 1
    c5_list_without "$m" "$C5_WEAK_MACS"
}
fix_sshd_no_weak_macs() { c5_sshd MACs "-$C5_WEAK_MACS"; }

rule sshd-at-most-4-auth-tries "sshd: at most 4 auth tries"
check_sshd_at_most_4_auth_tries() { c5_sshd_range maxauthtries 1 4; }
fix_sshd_at_most_4_auth_tries() { c5_sshd MaxAuthTries 4; }

rule sshd-at-most-10-sessions "sshd: at most 10 sessions"
check_sshd_at_most_10_sessions() {
    local rc=0 l
    c5_sshd_range maxsessions 1 10 || rc=$?
    [ $rc -eq 2 ] && return 2
    l=$(grep -Psi -- '^\h*MaxSessions\h+"?(1[1-9]|[2-9][0-9]|[1-9][0-9][0-9]+)\b' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null)
    [ -n "$l" ] && { ev "$l"; rc=1; }
    return $rc
}
fix_sshd_at_most_10_sessions() {
    local f
    for f in /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf; do
        [ -f "$f" ] && [ "$f" != "$SSHD_FILE" ] || continue
        sed -ri 's/^\s*MaxSessions\s+"?(1[1-9]|[2-9][0-9]|[1-9][0-9][0-9]+)\b/# pvs-cis: &/I' "$f"
    done
    c5_sshd MaxSessions 10
}

rule sshd-max-startups-10-30-60 "sshd: max startups 10:30:60"
check_sshd_max_startups_10_30_60() {
    local v a b c
    c5_ssh_here || return 2
    v=$(sshd_val maxstartups)
    ev "sshd maxstartups: ${v:-unset}"
    IFS=: read -r a b c <<<"$v"
    [[ "$a" =~ ^[0-9]+$ && "$b" =~ ^[0-9]+$ && "$c" =~ ^[0-9]+$ ]] || return 1
    [ "$a" -le 10 ] && [ "$b" -le 30 ] && [ "$c" -le 60 ]
}
fix_sshd_max_startups_10_30_60() { c5_sshd MaxStartups 10:30:60; }

rule sshd-empty-passwords-refused "sshd: empty passwords refused"
check_sshd_empty_passwords_refused() { c5_ssh_here || return 2; sshd_is permitemptypasswords no; }
fix_sshd_empty_passwords_refused() { c5_sshd PermitEmptyPasswords no; }

rule sshd-root-login-off "sshd: root login off"
check_sshd_root_login_off() { c5_ssh_here || return 2; sshd_is permitrootlogin no; }
fix_sshd_root_login_off() { c5_sshd PermitRootLogin no; }

rule sshd-user-environment-files-off "sshd: user environment files off"
check_sshd_user_environment_files_off() { c5_ssh_here || return 2; sshd_is permituserenvironment no; }
fix_sshd_user_environment_files_off() { c5_sshd PermitUserEnvironment no; }

rule sshd-pam-on "sshd: PAM on"
check_sshd_pam_on() { c5_ssh_here || return 2; sshd_is usepam yes; }
fix_sshd_pam_on() { c5_sshd UsePAM yes; }

# Ubuntu 24.04 / Debian 12 only. The address is the clone's, known at deploy (DHCP or the
# studio's static IP) - a template cannot name it; binding to a wrong one locks SSH out.
rule sshd-listen-address "sshd: listen address"
check_sshd_listen_address() {
    c5_ssh_here || return 2
    ev "sshd listenaddress: $(sshd_val listenaddress | paste -sd' ')"
    ev "decision: a template has no address of its own yet; bind it per clone where wanted"
    return 3
}

# ======================================================================================
# 5.2 Privilege escalation
# ======================================================================================

rule sudo-installed "sudo installed"
check_sudo_installed() {
    local p out=""
    for p in sudo-rs sudo; do pkg_installed "$p" && out="$out $p"; done
    ev "installed:${out:- none}"
    [ -n "$out" ]
}
fix_sudo_installed() {
    pkg_installed sudo-rs || pkg_installed sudo || pkg_install sudo-rs
}

rule sudo-commands-run-in-a-pty "sudo: commands run in a pty"
check_sudo_commands_run_in_a_pty() {
    local neg pos
    [ -n "$(c5_sudo_impl)" ] || { ev "sudo: not installed"; return 2; }
    neg=$(c5_sudoers_grep '^\h*Defaults\h+([^#\n\r]+,\h*)?!use_pty\b')
    pos=$(c5_sudoers_grep '^\h*Defaults\h+([^#\n\r]+,\h*)?use_pty\b')
    [ -n "$neg" ] && ev "$neg"
    ev "${pos:-use_pty: not set}"
    [ -z "$neg" ] && [ -n "$pos" ]
}
fix_sudo_commands_run_in_a_pty() {
    c5_sudoers_comment '^\h*Defaults\h+([^#\n\r]+,\h*)?!use_pty\b'
    c5_sudoers_add 'Defaults use_pty'
}

rule sudo-events-logged "sudo: events logged"
check_sudo_events_logged() {
    local impl lf j
    impl=$(c5_sudo_impl)
    [ -n "$impl" ] || { ev "sudo: not installed"; return 2; }
    ev "implementation: $impl"
    if [ "$impl" = sudo ]; then
        lf=$(c5_sudoers_grep "^\h*Defaults\h+([^#]+,\h*)?logfile\h*=\h*(\"|')?\H+(\"|')?(,\h*\H+\h*)*\h*(#.*)?$")
        if [ -n "$lf" ]; then ev "$lf"; return 0; fi
    fi
    # Method A: a fresh event must reach the journal.
    timeout 20 sudo -n true >/dev/null 2>&1
    j=$(journalctl -t sudo -t sudo-rs --since=-5min --no-pager -q 2>/dev/null | tail -n 3)
    if [ -n "$j" ]; then ev "journal: $j"; return 0; fi
    ev "no sudo event in the journal"
    return 1
}
fix_sudo_events_logged() {
    local impl
    impl=$(c5_sudo_impl)
    [ -n "$impl" ] || return 0
    if [ "$impl" = sudo ]; then
        c5_sudoers_add 'Defaults logfile="/var/log/sudo.log"' || return 1
    fi
    # sudo-rs (and classic sudo too) log to syslog; journald keeps them.
    systemctl is-active --quiet systemd-journald 2>/dev/null || systemctl start systemd-journald
}

rule sudo-password-required-no-nopasswd "sudo: password required (no NOPASSWD)"
check_sudo_password_required_no_nopasswd() {
    local out
    out=$(c5_sudoers_grep '^\s*[^#].*\bNOPASSWD\s*:')
    [ -n "$out" ] && { ev "$out"; return 1; }
    ev "no NOPASSWD"
    return 0
}
fix_sudo_password_required_no_nopasswd() { c5_sudoers_comment '^\s*[^#].*\bNOPASSWD\s*:'; }

rule sudo-re-authentication-not-disabled "sudo: re-authentication not disabled"
check_sudo_re_authentication_not_disabled() {
    local out
    out=$(c5_sudoers_grep '^\s*[^#].*!authenticate\b')
    [ -n "$out" ] && { ev "$out"; return 1; }
    ev "no !authenticate"
    return 0
}
fix_sudo_re_authentication_not_disabled() { c5_sudoers_comment '^\s*[^#].*!authenticate\b'; }

rule sudo-credential-cache-15-min-or-less "sudo: credential cache 15 min or less"
check_sudo_credential_cache_15_min_or_less() {
    local out v rc=0
    [ -n "$(c5_sudo_impl)" ] || { ev "sudo: not installed"; return 2; }
    out=$(c5_sudoers_grep '^\h*Defaults\h+([^#\n\r]+,\h*)?timestamp_timeout\h*=\h*[-0-9]+')
    [ -n "$out" ] || { ev "timestamp_timeout: not set"; return 1; }
    ev "$out"
    while read -r v; do
        [ "$v" -lt 0 ] || [ "$v" -gt 15 ] && rc=1
    done < <(grep -oP 'timestamp_timeout\h*=\h*\K-?[0-9]+' <<<"$out")
    return $rc
}
fix_sudo_credential_cache_15_min_or_less() {
    c5_sudoers_comment '^\h*Defaults\h+([^#\n\r]+,\h*)?timestamp_timeout\h*=\h*(-[0-9]+|1[6-9]|[2-9][0-9]|[0-9]{3,})\b'
    c5_sudoers_add 'Defaults timestamp_timeout=15'
}

rule su-limited-to-an-empty-group "su limited to an empty group"
check_su_limited_to_an_empty_group() {
    local l g m
    l=$(grep -Pi '^\s*auth\s+(?:required|requisite)\s+pam_wheel\.so(?=.*\buse_uid\b)(?=.*\bgroup=\S+).*' /etc/pam.d/su 2>/dev/null | head -n 1)
    [ -n "$l" ] || { ev "/etc/pam.d/su: no pam_wheel use_uid group="; return 1; }
    ev "$l"
    g=$(grep -oP '\bgroup=\K\S+' <<<"$l")
    m=$(getent group "$g")
    ev "${m:-group $g: missing}"
    [ -n "$m" ] && [ -z "$(cut -d: -f4 <<<"$m")" ]
}
fix_su_limited_to_an_empty_group() {
    local f=/etc/pam.d/su line='auth       required   pam_wheel.so use_uid group=pvs-su'
    getent group pvs-su >/dev/null || groupadd -r pvs-su || return 1
    # empty it (nobody may su)
    gpasswd -M '' pvs-su >/dev/null 2>&1
    [ -f "$f" ] || return 1
    check_su_limited_to_an_empty_group >/dev/null && return 0
    sed -i '/^[[:space:]]*auth[[:space:]].*pam_wheel\.so.*pvs-su/d' "$f"
    if grep -Eq '^[[:space:]]*auth[[:space:]]+sufficient[[:space:]]+pam_rootok\.so' "$f"; then
        sed -i "0,/^[[:space:]]*auth[[:space:]]\+sufficient[[:space:]]\+pam_rootok\.so.*/s//&\n${line}/" "$f"
    else
        sed -i "1i ${line}" "$f"
    fi
    check_su_limited_to_an_empty_group >/dev/null
}

# ======================================================================================
# 5.3 PAM
# ======================================================================================

# Installed, and the apt cache has no newer version.
c5_pkg_latest() {
    local p=$1 up
    pkg_installed "$p" || { ev "$p: not installed"; return 1; }
    up=$(apt list --upgradable 2>/dev/null | grep -P "^${p}/")
    ev "$p: $(dpkg-query -W -f='${Version}' "$p" 2>/dev/null)${up:+ - upgradable: $up}"
    [ -z "$up" ]
}

rule pam-runtime-installed-and-current "PAM runtime installed and current"
check_pam_runtime_installed_and_current() { c5_pkg_latest libpam-runtime; }
fix_pam_runtime_installed_and_current() { pkg_install libpam-runtime; }

rule pam-modules-installed-and-current "PAM modules installed and current"
check_pam_modules_installed_and_current() { c5_pkg_latest libpam-modules; }
fix_pam_modules_installed_and_current() { pkg_install libpam-modules; }

rule pwquality-module-installed-and-current "pwquality module installed and current"
check_pwquality_module_installed_and_current() { c5_pkg_latest libpam-pwquality; }
fix_pwquality_module_installed_and_current() { pkg_install libpam-pwquality; }

rule cracklib-runtime-installed-and-current "cracklib runtime installed and current"
check_cracklib_runtime_installed_and_current() { c5_pkg_latest cracklib-runtime; }
fix_cracklib_runtime_installed_and_current() { pkg_install cracklib-runtime; }

rule pam-pam-unix-enabled "PAM: pam_unix enabled"
check_pam_pam_unix_enabled() {
    local f rc=0 l
    for f in account auth password session session-noninteractive; do
        l=$(grep -P -- '\bpam_unix\.so\b' "/etc/pam.d/common-$f" 2>/dev/null | grep -v '^\s*#' | head -n 1)
        ev "common-$f: ${l:-no pam_unix}"
        [ -n "$l" ] || rc=1
    done
    return $rc
}
fix_pam_pam_unix_enabled() {
    if [ -f "$C5_PAMCFG/pvs-cis-unix" ]; then
        c5_unix_profile_use || return 1
    else
        c5_pam_update --enable unix || return 1
    fi
    check_pam_pam_unix_enabled >/dev/null
}

rule pam-pam-faillock-enabled "PAM: pam_faillock enabled"
check_pam_pam_faillock_enabled() {
    local rc=0
    grep -Pq '^\h*auth\h+\S+.*\bpam_faillock\.so\h+([^#\n\r]+\h+)?preauth\b' /etc/pam.d/common-auth 2>/dev/null \
        && ev "common-auth: faillock preauth" || { ev "common-auth: no faillock preauth"; rc=1; }
    grep -Pq '^\h*auth\h+\S+.*\bpam_faillock\.so\h+([^#\n\r]+\h+)?authfail\b' /etc/pam.d/common-auth 2>/dev/null \
        && ev "common-auth: faillock authfail" || { ev "common-auth: no faillock authfail"; rc=1; }
    grep -Pq '^\h*account\h+\S+.*\bpam_faillock\.so\b' /etc/pam.d/common-account 2>/dev/null \
        && ev "common-account: faillock" || { ev "common-account: no faillock"; rc=1; }
    return $rc
}
fix_pam_pam_faillock_enabled() {
    printf '%s\n' 'Name: Enable pam_faillock to deny access' 'Default: yes' 'Priority: 0' \
        'Auth-Type: Primary' 'Auth:' '	[default=die]	pam_faillock.so authfail' > "$C5_PAMCFG/faillock"
    printf '%s\n' 'Name: Notify of failed login attempts and reset count upon success' 'Default: yes' \
        'Priority: 1024' 'Auth-Type: Primary' 'Auth:' '	requisite	pam_faillock.so preauth' \
        'Account-Type: Primary' 'Account:' '	required	pam_faillock.so' > "$C5_PAMCFG/faillock_notify"
    chmod 0644 "$C5_PAMCFG/faillock" "$C5_PAMCFG/faillock_notify"
    c5_pam_update --enable faillock faillock_notify || return 1
    check_pam_pam_faillock_enabled >/dev/null
}

rule pam-pam-pwquality-enabled "PAM: pam_pwquality enabled"
check_pam_pam_pwquality_enabled() {
    local l
    l=$(grep -P -- '^\h*password\h+.*\bpam_pwquality\.so\b' /etc/pam.d/common-password 2>/dev/null)
    ev "common-password: ${l:-no pam_pwquality}"
    [ -n "$l" ]
}
fix_pam_pam_pwquality_enabled() {
    local p
    pkg_installed libpam-pwquality || pkg_install libpam-pwquality || return 1
    p=$(grep -Pl -- '\bpam_pwquality\.so\b' "$C5_PAMCFG"/* 2>/dev/null | head -n 1)
    if [ -z "$p" ]; then
        printf '%s\n' 'Name: Pwquality password strength checking' 'Default: yes' 'Priority: 1024' \
            'Conflicts: cracklib' 'Password-Type: Primary' 'Password:' '	requisite	pam_pwquality.so retry=3' \
            > "$C5_PAMCFG/pwquality"
        chmod 0644 "$C5_PAMCFG/pwquality"
        p=$C5_PAMCFG/pwquality
    fi
    c5_pam_update --enable "$(basename "$p")" || return 1
    check_pam_pam_pwquality_enabled >/dev/null
}

rule pam-pam-pwhistory-enabled "PAM: pam_pwhistory enabled"
check_pam_pam_pwhistory_enabled() {
    local l
    l=$(grep -P -- '^\h*password\h+.*\bpam_pwhistory\.so\b' /etc/pam.d/common-password 2>/dev/null)
    ev "common-password: ${l:-no pam_pwhistory}"
    [ -n "$l" ]
}
fix_pam_pam_pwhistory_enabled() {
    # Options live in /etc/security/pwhistory.conf (5.3.3.3.x), not on the module line.
    printf '%s\n' 'Name: pwhistory password history checking' 'Default: yes' 'Priority: 1024' \
        'Password-Type: Primary' 'Password:' '	requisite	pam_pwhistory.so' > "$C5_PAMCFG/pwhistory"
    chmod 0644 "$C5_PAMCFG/pwhistory"
    c5_pam_update --enable pwhistory || return 1
    check_pam_pam_pwhistory_enabled >/dev/null
}

# ---- 5.3.3.1 faillock ----

rule faillock-lock-after-5-failures "faillock: lock after 5 failures"
check_faillock_lock_after_5_failures() {
    local v bad
    v=$(kv_get /etc/security/faillock.conf deny)
    ev "faillock.conf deny: ${v:-unset}"
    bad=$(grep -Pi -- '^\h*auth\h+(requisite|required|sufficient)\h+pam_faillock\.so\h+([^#\n\r]+\h+)?deny\h*=\h*(0|[6-9]|[1-9][0-9]+)\b' /etc/pam.d/common-auth 2>/dev/null)
    [ -n "$bad" ] && ev "common-auth: $bad"
    [[ "$v" =~ ^[1-5]$ ]] && [ -z "$bad" ]
}
fix_faillock_lock_after_5_failures() {
    kv_set /etc/security/faillock.conf deny 5 " = "
    if c5_profile_drop_arg pam_faillock.so deny; then c5_pam_update --package || return 1; fi
    return 0
}

rule faillock-unlock-after-15-min "faillock: unlock after 15 min"
check_faillock_unlock_after_15_min() {
    local v bad
    v=$(kv_get /etc/security/faillock.conf unlock_time)
    ev "faillock.conf unlock_time: ${v:-unset}"
    bad=$(grep -Pi -- '^\h*auth\h+(requisite|required|sufficient)\h+pam_faillock\.so\h+([^#\n\r]+\h+)?unlock_time\h*=\h*([1-9]|[1-9][0-9]|[1-8][0-9][0-9])\b' /etc/pam.d/common-auth 2>/dev/null)
    [ -n "$bad" ] && ev "common-auth: $bad"
    [[ "$v" =~ ^[0-9]+$ ]] && { [ "$v" -eq 0 ] || [ "$v" -ge 900 ]; } && [ -z "$bad" ]
}
fix_faillock_unlock_after_15_min() {
    kv_set /etc/security/faillock.conf unlock_time 900 " = "
    if c5_profile_drop_arg pam_faillock.so unlock_time; then c5_pam_update --package || return 1; fi
    return 0
}

rule faillock-root-is-locked-too "faillock: root is locked too"
check_faillock_root_is_locked_too() {
    local l bad rc=0
    l=$(grep -Pi -- '^\h*(even_deny_root|root_unlock_time\h*=\h*\d+)\b' /etc/security/faillock.conf 2>/dev/null)
    ev "faillock.conf: ${l:-no even_deny_root / root_unlock_time}"
    [ -n "$l" ] || rc=1
    bad=$(grep -Pi -- '^\h*root_unlock_time\h*=\h*([1-9]|[1-5][0-9])\b' /etc/security/faillock.conf 2>/dev/null)
    [ -n "$bad" ] && { ev "too short: $bad"; rc=1; }
    bad=$(grep -Pi -- '^\h*auth\h+([^#\n\r]+\h+)pam_faillock\.so\h+([^#\n\r]+\h+)?root_unlock_time\h*=\h*([1-9]|[1-5][0-9])\b' /etc/pam.d/common-auth 2>/dev/null)
    [ -n "$bad" ] && { ev "common-auth: $bad"; rc=1; }
    return $rc
}
fix_faillock_root_is_locked_too() {
    local f=/etc/security/faillock.conf ch=1
    touch "$f"
    sed -ri 's/^\s*root_unlock_time\s*=\s*([1-9]|[1-5][0-9])\b/# pvs-cis: &/' "$f"
    c5_add_flag "$f" even_deny_root
    c5_profile_drop_arg pam_faillock.so even_deny_root && ch=0
    c5_profile_drop_arg pam_faillock.so root_unlock_time && ch=0
    if [ $ch -eq 0 ]; then c5_pam_update --package || return 1; fi
    return 0
}

# ---- 5.3.3.2 pwquality ----

rule pwquality-at-least-2-changed-characters "pwquality: at least 2 changed characters"
check_pwquality_at_least_2_changed_characters() { c5_pwq_check difok '[ "$v" -ge 2 ]'; }
fix_pwquality_at_least_2_changed_characters() { c5_pwq_set difok 2; }

rule pwquality-minimum-length-14 "pwquality: minimum length 14"
check_pwquality_minimum_length_14() { c5_pwq_check minlen '[ "$v" -ge 14 ]'; }
fix_pwquality_minimum_length_14() { c5_pwq_set minlen 14; }

rule pwquality-character-classes-policy-3 "pwquality: character classes (policy: 3)"
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
    ov=$(grep -Psi -- '^\h*password\h+(requisite|required|sufficient)\h+pam_pwquality\.so\h+([^#\n\r]+\h+)?(minclass=\d*|[dulo]credit=-?\d*)\b' /etc/pam.d/common-password 2>/dev/null)
    [ -n "$ov" ] && { ev "common-password overrides: $ov"; rc=1; }
    ev "studio policy: minclass 3"
    [[ "$mc" =~ ^[0-9]+$ ]] || mc=0
    { [ "$mc" -ge 3 ] || [ $neg -ge 3 ]; } || rc=1
    return $rc
}
fix_pwquality_character_classes_policy_3() {
    local k ch=1
    [ -f /etc/security/pwquality.conf ] && sed -ri 's/^\s*(minclass|[dulo]credit)\s*=/# &/' /etc/security/pwquality.conf
    for k in minclass dcredit ucredit lcredit ocredit; do
        c5_profile_drop_arg pam_pwquality.so "$k" && ch=0
    done
    [ $ch -eq 0 ] && { c5_pam_update --package || return 1; }
    c5_pwq_set minclass 3
}

rule pwquality-at-most-3-repeated-characters "pwquality: at most 3 repeated characters"
check_pwquality_at_most_3_repeated_characters() { c5_pwq_check maxrepeat '[ "$v" -ge 1 ] && [ "$v" -le 3 ]'; }
fix_pwquality_at_most_3_repeated_characters() { c5_pwq_set maxrepeat 3; }

rule pwquality-at-most-3-sequential-characters "pwquality: at most 3 sequential characters"
check_pwquality_at_most_3_sequential_characters() { c5_pwq_check maxsequence '[ "$v" -ge 1 ] && [ "$v" -le 3 ]'; }
fix_pwquality_at_most_3_sequential_characters() { c5_pwq_set maxsequence 3; }

rule pwquality-dictionary-check-on "pwquality: dictionary check on"
check_pwquality_dictionary_check_on() {
    local out
    out=$(grep -PHsi -- '^\h*dictcheck\h*=\h*0\b' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf 2>/dev/null)
    out="$out$(grep -Psi -- '^\h*password\h+(requisite|required|sufficient)\h+pam_pwquality\.so\h+([^#\n\r]+\h+)?dictcheck\h*=\h*0\b' /etc/pam.d/common-password 2>/dev/null)"
    [ -n "$out" ] && { ev "$out"; return 1; }
    ev "dictcheck: not disabled"
    return 0
}
fix_pwquality_dictionary_check_on() {
    local f
    for f in /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf; do
        [ -f "$f" ] && sed -ri 's/^\s*dictcheck\s*=/# &/' "$f"
    done
    if c5_profile_drop_arg pam_pwquality.so dictcheck; then c5_pam_update --package || return 1; fi
    return 0
}

rule pwquality-checks-enforced "pwquality: checks enforced"
check_pwquality_checks_enforced() {
    local out
    out=$(grep -PHsi -- '^\h*enforcing\h*=\h*0\b' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf 2>/dev/null)
    out="$out$(grep -PHsi -- '^\h*password\h+[^#\n\r]+\h+pam_pwquality\.so\h+([^#\n\r]+\h+)?enforcing=0\b' /etc/pam.d/common-password 2>/dev/null)"
    [ -n "$out" ] && { ev "$out"; return 1; }
    ev "enforcing: not disabled"
    return 0
}
fix_pwquality_checks_enforced() {
    local f
    for f in /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf; do
        [ -f "$f" ] && sed -ri 's/^\s*enforcing\s*=\s*0/# &/' "$f"
    done
    if c5_profile_drop_arg pam_pwquality.so 'enforcing=0'; then c5_pam_update --package || return 1; fi
    return 0
}

rule pwquality-enforced-for-root "pwquality: enforced for root"
check_pwquality_enforced_for_root() {
    local out
    out=$(grep -PHsi -- '^\h*enforce_for_root\b' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf 2>/dev/null)
    ev "${out:-enforce_for_root: not set}"
    [ -n "$out" ]
}
fix_pwquality_enforced_for_root() {
    mkdir -p /etc/security/pwquality.conf.d
    c5_add_flag "$C5_PWQ" enforce_for_root
    chmod 0644 "$C5_PWQ"
}

# ---- 5.3.3.3 pwhistory ----

C5_PWH=/etc/security/pwhistory.conf

# The pwhistory line(s) of common-password.
c5_pwh_line() { grep -P -- '^\h*password\h+.*\bpam_pwhistory\.so\b' /etc/pam.d/common-password 2>/dev/null; }

rule pwhistory-remember-24-passwords "pwhistory: remember 24 passwords"
check_pwhistory_remember_24_passwords() {
    local c m
    c=$(kv_get "$C5_PWH" remember)
    m=$(c5_pam_arg /etc/pam.d/common-password password pam_pwhistory.so remember)
    ev "pwhistory.conf remember: ${c:-unset}; module argument: ${m:-unset}"
    if [ -n "$c" ] && [ -n "$m" ]; then ev "set in both places"; return 1; fi
    c=${c:-$m}
    [[ "$c" =~ ^[0-9]+$ ]] && [ "$c" -ge 24 ]
}
fix_pwhistory_remember_24_passwords() {
    kv_set "$C5_PWH" remember 24 " = "
    if c5_profile_drop_arg pam_pwhistory.so remember; then c5_pam_update --package || return 1; fi
    return 0
}

rule pwhistory-enforced-for-root "pwhistory: enforced for root"
check_pwhistory_enforced_for_root() {
    local c=0 m=0
    c5_has_flag "$C5_PWH" enforce_for_root && c=1
    c5_pam_flag /etc/pam.d/common-password password pam_pwhistory.so enforce_for_root && m=1
    ev "pwhistory.conf enforce_for_root: $c; module argument: $m"
    [ $((c + m)) -eq 1 ]
}
fix_pwhistory_enforced_for_root() {
    c5_add_flag "$C5_PWH" enforce_for_root
    if c5_profile_drop_arg pam_pwhistory.so enforce_for_root; then c5_pam_update --package || return 1; fi
    return 0
}

rule pwhistory-uses-the-token-already-given "pwhistory: uses the token already given"
check_pwhistory_uses_the_token_already_given() {
    local c=0 m=0
    c5_has_flag "$C5_PWH" use_authtok && c=1
    c5_pam_flag /etc/pam.d/common-password password pam_pwhistory.so use_authtok && m=1
    ev "pwhistory.conf use_authtok: $c; module argument: $m"
    [ $((c + m)) -eq 1 ]
}
fix_pwhistory_uses_the_token_already_given() {
    c5_add_flag "$C5_PWH" use_authtok
    if c5_profile_drop_arg pam_pwhistory.so use_authtok; then c5_pam_update --package || return 1; fi
    return 0
}

# ---- 5.3.3.4 pam_unix ----

rule pam-unix-no-empty-passwords-nullok "pam_unix: no empty passwords (nullok)"
check_pam_unix_no_empty_passwords_nullok() {
    local out
    out=$(grep -PHs -- '^\h*[^#\n\r]+\h+pam_unix\.so\h+([^#\n\r]+\h+)?nullok\b' /etc/pam.d/common-{password,auth,account,session,session-noninteractive} 2>/dev/null)
    [ -n "$out" ] && { ev "$out"; return 1; }
    ev "pam_unix: no nullok"
    return 0
}
fix_pam_unix_no_empty_passwords_nullok() { c5_unix_profile_use && check_pam_unix_no_empty_passwords_nullok >/dev/null; }

rule pam-unix-no-remember-option "pam_unix: no remember option"
check_pam_unix_no_remember_option() {
    local out
    out=$(grep -PHs -- '^\h*[^#\n\r]+\h+pam_unix\.so\h+([^#\n\r]+\h+)?remember=\d+\b' /etc/pam.d/common-{password,auth,account,session,session-noninteractive} 2>/dev/null)
    [ -n "$out" ] && { ev "$out"; return 1; }
    ev "pam_unix: no remember="
    return 0
}
fix_pam_unix_no_remember_option() { c5_unix_profile_use && check_pam_unix_no_remember_option >/dev/null; }

rule pam-unix-strong-password-hash "pam_unix: strong password hash"
check_pam_unix_strong_password_hash() {
    local out
    out=$(grep -PH -- '^\h*password\h+([^#\n\r]+)\h+pam_unix\.so\h+([^#\n\r]+\h+)?(sha512|yescrypt)\b' /etc/pam.d/common-password 2>/dev/null)
    ev "${out:-pam_unix password line: no sha512/yescrypt}"
    [ -n "$out" ]
}
fix_pam_unix_strong_password_hash() { c5_unix_profile_use && check_pam_unix_strong_password_hash >/dev/null; }

rule pam-unix-uses-the-token-already-given "pam_unix: uses the token already given"
check_pam_unix_uses_the_token_already_given() {
    local out
    out=$(grep -PH -- '^\h*password\h+([^#\n\r]+)\h+pam_unix\.so\h+([^#\n\r]+\h+)?use_authtok\b' /etc/pam.d/common-password 2>/dev/null)
    ev "${out:-pam_unix password line: no use_authtok}"
    [ -n "$out" ]
}
fix_pam_unix_uses_the_token_already_given() { c5_unix_profile_use && check_pam_unix_uses_the_token_already_given >/dev/null; }

# ======================================================================================
# 5.4 User accounts and environment
# ======================================================================================

# Shadow field N (4 min, 5 max, 6 warn, 7 inactive) of every password user failing AWK-COND
# on $f ("" counts as failing unless the condition says otherwise).
c5_shadow_bad() {
    awk -F: -v n="$1" '($2 ~ /^\$.+\$/) { f = $n; if ('"$2"') print "user " $1 ": " f }' /etc/shadow 2>/dev/null
}

rule passwords-expire-within-365-days "passwords expire within 365 days"
check_passwords_expire_within_365_days() {
    local v bad
    v=$(kv_get /etc/login.defs PASS_MAX_DAYS)
    ev "login.defs PASS_MAX_DAYS: ${v:-unset}"
    bad=$(c5_shadow_bad 5 'f == "" || f > 365 || f < 1')
    [ -n "$bad" ] && ev "$bad"
    [[ "$v" =~ ^[0-9]+$ ]] && [ "$v" -ge 1 ] && [ "$v" -le 365 ] && [ -z "$bad" ]
}
fix_passwords_expire_within_365_days() {
    local u
    kv_set /etc/login.defs PASS_MAX_DAYS 365
    for u in $(c5_pw_users); do
        # a password without a change date would expire at once: date it today first
        [ -z "$(awk -F: -v u="$u" '$1 == u { print $3 }' /etc/shadow)" ] && chage -d "$(date +%Y-%m-%d)" "$u"
        awk -F: -v u="$u" '$1 == u && ($5 == "" || $5 > 365 || $5 < 1) { found = 1 } END { exit !found }' /etc/shadow \
            && chage --maxdays 365 "$u"
    done
    return 0
}

rule passwords-kept-at-least-1-day "passwords kept at least 1 day"
check_passwords_kept_at_least_1_day() {
    local v bad
    v=$(kv_get /etc/login.defs PASS_MIN_DAYS)
    ev "login.defs PASS_MIN_DAYS: ${v:-unset} (studio policy: 1)"
    bad=$(c5_shadow_bad 4 'f == "" || f < 1')
    [ -n "$bad" ] && ev "$bad"
    [[ "$v" =~ ^[0-9]+$ ]] && [ "$v" -ge 1 ] && [ -z "$bad" ]
}
fix_passwords_kept_at_least_1_day() {
    local u
    kv_set /etc/login.defs PASS_MIN_DAYS 1
    for u in $(c5_pw_users); do
        awk -F: -v u="$u" '$1 == u && ($4 == "" || $4 < 1) { found = 1 } END { exit !found }' /etc/shadow \
            && chage --mindays 1 "$u"
    done
    return 0
}

rule expiry-warning-7-days-ahead "expiry warning 7 days ahead"
check_expiry_warning_7_days_ahead() {
    local v bad
    v=$(kv_get /etc/login.defs PASS_WARN_AGE)
    ev "login.defs PASS_WARN_AGE: ${v:-unset}"
    bad=$(c5_shadow_bad 6 'f == "" || f < 7')
    [ -n "$bad" ] && ev "$bad"
    [[ "$v" =~ ^[0-9]+$ ]] && [ "$v" -ge 7 ] && [ -z "$bad" ]
}
fix_expiry_warning_7_days_ahead() {
    local u
    kv_set /etc/login.defs PASS_WARN_AGE 7
    for u in $(c5_pw_users); do
        awk -F: -v u="$u" '$1 == u && ($6 == "" || $6 < 7) { found = 1 } END { exit !found }' /etc/shadow \
            && chage --warndays 7 "$u"
    done
    return 0
}

rule login-defs-strong-password-hash "login.defs: strong password hash"
check_login_defs_strong_password_hash() {
    local v
    v=$(kv_get /etc/login.defs ENCRYPT_METHOD)
    ev "login.defs ENCRYPT_METHOD: ${v:-unset}"
    [[ "${v^^}" == SHA512 || "${v^^}" == YESCRYPT ]]
}
fix_login_defs_strong_password_hash() { kv_set /etc/login.defs ENCRYPT_METHOD YESCRYPT; }

rule inactive-accounts-locked-after-45-days "inactive accounts locked after 45 days"
check_inactive_accounts_locked_after_45_days() {
    local v bad
    v=$(useradd -D 2>/dev/null | awk -F= '$1 == "INACTIVE" { print $2 }')
    ev "useradd INACTIVE: ${v:-unset}"
    bad=$(c5_shadow_bad 7 'f == "" || f > 45 || f < 0')
    [ -n "$bad" ] && ev "$bad"
    [[ "$v" =~ ^[0-9]+$ ]] && [ "$v" -le 45 ] && [ -z "$bad" ]
}
fix_inactive_accounts_locked_after_45_days() {
    local u
    useradd -D -f 45 || return 1
    for u in $(c5_pw_users); do
        awk -F: -v u="$u" '$1 == u && ($7 == "" || $7 > 45 || $7 < 0) { found = 1 } END { exit !found }' /etc/shadow \
            && chage --inactive 45 "$u"
    done
    return 0
}

rule no-password-change-dates-in-the-future "no password change dates in the future"
check_no_password_change_dates_in_the_future() {
    local u d now rc=0
    now=$(( $(date +%s) / 86400 ))
    while IFS=: read -r u d; do
        [[ "$d" =~ ^[0-9]+$ ]] || continue
        if [ "$d" -gt "$now" ]; then ev "user $u: last change $(date -u -d "@$((d * 86400))" +%F)"; rc=1; fi
    done < <(awk -F: '$2 ~ /^\$.+\$/ { print $1 ":" $3 }' /etc/shadow 2>/dev/null)
    [ $rc -eq 0 ] && ev "no future change dates"
    return $rc
}
fix_no_password_change_dates_in_the_future() {
    local u d now
    now=$(( $(date +%s) / 86400 ))
    while IFS=: read -r u d; do
        [[ "$d" =~ ^[0-9]+$ ]] && [ "$d" -gt "$now" ] && chage -d "$(date +%Y-%m-%d)" "$u"
    done < <(awk -F: '$2 ~ /^\$.+\$/ { print $1 ":" $3 }' /etc/shadow 2>/dev/null)
    return 0
}

rule only-root-has-uid-0 "only root has UID 0"
check_only_root_has_uid_0() {
    local out
    out=$(awk -F: '$3 == 0 { print $1 }' /etc/passwd | paste -s -d' ' -)
    ev "UID 0: ${out:-none}"
    [ "$out" = root ]
}

rule only-root-has-primary-gid-0 "only root has primary GID 0"
check_only_root_has_primary_gid_0() {
    local out
    out=$(awk -F: '$1 !~ /^(sync|shutdown|halt|operator)/ && $4 == "0" { print $1 ":" $4 }' /etc/passwd | paste -s -d' ' -)
    ev "primary GID 0: ${out:-none}"
    [ "$out" = root:0 ]
}

rule only-group-root-has-gid-0 "only group root has GID 0"
check_only_group_root_has_gid_0() {
    local out
    out=$(awk -F: '$3 == "0" { print $1 ":" $3 }' /etc/group | paste -s -d' ' -)
    ev "GID 0 groups: ${out:-none}"
    [ "$out" = root:0 ]
}

rule root-has-a-password-or-is-locked "root has a password or is locked"
check_root_has_a_password_or_is_locked() {
    local s
    s=$(passwd -S root 2>/dev/null | awk '{ print $2 }')
    ev "root password status: ${s:-unknown}"
    [[ "$s" == P* || "$s" == L* ]]
}
fix_root_has_a_password_or_is_locked() {
    check_root_has_a_password_or_is_locked >/dev/null && return 0
    usermod -L root
}

# root's login PATH (what `su - root` gives).
c5_root_path() { su - root -s /bin/bash -c 'printf "%s\n" "$PATH"' 2>/dev/null </dev/null | tail -n 1; }

rule root-path-has-only-safe-directories "root PATH has only safe directories"
check_root_path_has_only_safe_directories() {
    local p d m o rc=0
    p=$(c5_root_path)
    ev "root PATH: ${p:-unknown}"
    [ -n "$p" ] || return 1
    [[ "$p" == *::* ]] && { ev "empty entry (::)"; rc=1; }
    [[ "$p" =~ :[[:space:]]*$ ]] && { ev "trailing :"; rc=1; }
    [[ "$p" =~ (^|:)\.(:|$) ]] && { ev "current directory (.)"; rc=1; }
    IFS=: read -ra _p <<<"$p"
    for d in "${_p[@]}"; do
        [ -n "$d" ] || continue
        if [ ! -d "$d" ]; then ev "$d: not a directory"; rc=1; continue; fi
        read -r m o < <(stat -Lc '%a %U' "$d")
        [ "$o" = root ] || { ev "$d: owner $o"; rc=1; }
        (( (8#$m & 8#022) == 0 )) || { ev "$d: mode $m"; rc=1; }
    done
    return $rc
}
fix_root_path_has_only_safe_directories() {
    local p d
    p=$(c5_root_path)
    IFS=: read -ra _p <<<"$p"
    for d in "${_p[@]}"; do
        [ -n "$d" ] && [ "$d" != . ] || continue
        # Enterprise Linux's /root/.bashrc puts ~/.local/bin and ~/bin in front, made or not.
        if [ ! -e "$d" ] && [[ "$d" == /root/* ]]; then
            mkdir -p -m 0700 "$d"
        fi
        [ -d "$d" ] || continue
        chown root "$d"
        chmod go-w "$d"
    done
    return 0
}

# umask lines in FILEs that are weaker than 027 (octal or symbolic).
c5_weak_umask() {
    local f n l v
    for f in "$@"; do
        [ -f "$f" ] || continue
        while IFS=: read -r n l; do
            v=$(sed -E 's/^[[:space:]]*umask[[:space:]]+//I; s/[[:space:];#].*$//' <<<"$l")
            if [[ "$v" =~ ^[0-7]{1,4}$ ]]; then
                (( (8#$v & 8#027) == 8#027 )) && continue
            elif [[ "$v" =~ ^[ugoa=,rwx]+$ ]]; then
                # symbolic: group must not get w, other must get nothing
                local g o
                g=$(grep -oE 'g=[rwx]*' <<<"$v" | tail -n 1)
                o=$(grep -oE 'o=[rwx]*' <<<"$v" | tail -n 1)
                [[ "$g" != *w* ]] && [ "$o" = "o=" ] && continue
            fi
            echo "$f:$n: $l"
        done < <(grep -nEi '^[[:space:]]*umask[[:space:]]+' "$f" 2>/dev/null)
    done
}

rule root-umask-027-or-stricter "root umask 027 or stricter"
check_root_umask_027_or_stricter() {
    local out
    out=$(c5_weak_umask /root/.profile /root/.bashrc)
    [ -n "$out" ] && { ev "$out"; return 1; }
    ev "/root/.profile, /root/.bashrc: no weak umask"
    return 0
}
fix_root_umask_027_or_stricter() {
    local l f n
    while IFS= read -r l; do
        f=${l%%:*}; n=${l#*:}; n=${n%%:*}
        sed -i "${n}s/^/# pvs-cis: /" "$f"
    done < <(c5_weak_umask /root/.profile /root/.bashrc)
    return 0
}

# System accounts (below UID_MIN or 65534, not root/halt/sync/shutdown/nfsnobody) with a
# valid shell: "user:shell".
c5_sys_shell_users() {
    local pat min
    pat="^($(c5_valid_shells))$"
    min=$(uid_min)
    awk -v pat="$pat" -v min="${min:-1000}" -F: '($1 !~ /^(root|halt|sync|shutdown|nfsnobody)$/ && ($3 < min || $3 == 65534) && $NF ~ pat) { print $1 ":" $NF }' /etc/passwd
}

rule system-accounts-have-no-login-shell "system accounts have no login shell"
check_system_accounts_have_no_login_shell() {
    local out
    out=$(c5_sys_shell_users)
    [ -n "$out" ] && { ev "$out"; return 1; }
    ev "no system account with a login shell"
    return 0
}
fix_system_accounts_have_no_login_shell() {
    local u nl
    nl=$(command -v nologin || echo /usr/sbin/nologin)
    for u in $(c5_sys_shell_users | cut -d: -f1); do usermod -s "$nl" "$u"; done
    return 0
}

# Non-root accounts with no valid shell that are not locked.
c5_noshell_unlocked() {
    local pat u
    pat="^($(c5_valid_shells))$"
    while IFS= read -r u; do
        passwd -S "$u" 2>/dev/null | awk '$2 !~ /^L/ { print $1 }'
    done < <(awk -v pat="$pat" -F: '($1 != "root" && $NF !~ pat) { print $1 }' /etc/passwd)
}

rule accounts-without-a-login-shell-are-locked "accounts without a login shell are locked"
check_accounts_without_a_login_shell_are_locked() {
    local out
    out=$(c5_noshell_unlocked | paste -s -d' ' -)
    [ -n "$out" ] && { ev "not locked: $out"; return 1; }
    ev "all locked"
    return 0
}
fix_accounts_without_a_login_shell_are_locked() {
    local u
    for u in $(c5_noshell_unlocked); do usermod -L "$u"; done
    return 0
}

rule nologin-not-listed-as-a-shell "nologin not listed as a shell"
check_nologin_not_listed_as_a_shell() {
    local out
    out=$(grep -Ps '^\h*([^#\n\r]+)?\/nologin\b' /etc/shells)
    [ -n "$out" ] && { ev "/etc/shells: $out"; return 1; }
    ev "/etc/shells: no nologin"
    return 0
}
fix_nologin_not_listed_as_a_shell() { [ -f /etc/shells ] && sed -ri '/^\s*([^#]+)?\/nologin\b/d' /etc/shells; return 0; }

C5_TMOUT=/etc/profile.d/50-pvs-cis-tmout.sh

rule shell-timeout-900s-read-only "shell timeout 900s, read-only"
check_shell_timeout_900s_read_only() {
    local f v n=0 rc=0
    while IFS= read -r f; do
        n=$((n + 1))
        v=$(grep -Po -- '^([^#\n\r]+)?\bTMOUT=\d+\b' "$f" | awk -F= '{ print $NF }' | tail -n 1)
        ev "$f: TMOUT=${v:-unset}"
        if [ -z "$v" ] || [ "$v" -le 0 ] || [ "$v" -gt 900 ]; then rc=1; fi
        grep -Pq -- '^\h*(typeset\h-xr\hTMOUT=\d+|([^#\n\r]+)?\breadonly\h+TMOUT\b)' "$f" || { ev "$f: not readonly"; rc=1; }
        grep -Pq -- '^\h*(typeset\h-xr\hTMOUT=\d+|([^#\n\r]+)?\bexport\b([^#\n\r]+\b)?TMOUT\b)' "$f" || { ev "$f: not exported"; rc=1; }
    done < <(grep -Pls -- '^([^#\n\r]+)?\bTMOUT\b' /etc/*bashrc /etc/profile /etc/profile.d/*.sh)
    [ $n -gt 0 ] || { ev "TMOUT: not configured"; return 1; }
    return $rc
}
fix_shell_timeout_900s_read_only() {
    local f
    while IFS= read -r f; do
        [ "$f" = "$C5_TMOUT" ] && continue
        sed -ri 's/^([^#]*\bTMOUT\b)/# pvs-cis: \1/' "$f"
    done < <(grep -Pls -- '^([^#\n\r]+)?\bTMOUT\b' /etc/*bashrc /etc/profile /etc/profile.d/*.sh)
    printf '%s\n' '# pvs-cis: idle shells end after 15 minutes' 'TMOUT=900' 'readonly TMOUT' 'export TMOUT' > "$C5_TMOUT"
    chmod 0644 "$C5_TMOUT"
}

C5_UMASK=/etc/profile.d/60-pvs-cis-umask.sh

rule default-umask-027 "default umask 027"
check_default_umask_027() {
    local out good rc=0 v
    out=$(grep -PHsi -- '^\h*umask\h+(?!0?[02367]7\b)' /etc/profile /etc/profile.d/*.sh 2>/dev/null)
    [ -n "$out" ] && { ev "$out"; rc=1; }
    good=$(grep -PHsi -- '^\h*umask\h+0?[02367]7\b' /etc/profile /etc/profile.d/*.sh 2>/dev/null | head -n 1)
    ev "${good:-no umask 027 in /etc/profile or profile.d}"
    [ -n "$good" ] || rc=1
    v=$(kv_get /etc/login.defs UMASK)
    ev "login.defs UMASK: ${v:-unset}"
    grep -Pq '^0?[02367]7$' <<<"$v" || rc=1
    return $rc
}
fix_default_umask_027() {
    local f
    for f in /etc/profile /etc/profile.d/*.sh; do
        [ -f "$f" ] && [ "$f" != "$C5_UMASK" ] || continue
        grep -Pq '^\h*umask\h+(?!0?[02367]7\b)' "$f" || continue
        # comment out the lines grep -P flags (sed has no lookahead)
        grep -Pn '^\h*umask\h+(?!0?[02367]7\b)' "$f" | cut -d: -f1 | sort -rn | while read -r n; do
            sed -i "${n}s/^/# pvs-cis: /" "$f"
        done
    done
    printf '%s\n' '# pvs-cis: default umask' 'umask 027' > "$C5_UMASK"
    chmod 0644 "$C5_UMASK"
    kv_set /etc/login.defs UMASK 027
}
