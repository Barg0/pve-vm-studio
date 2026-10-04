# shellcheck shell=bash
# suse/5-access.sh - openSUSE Leap 16.0 (CIS SLE 16 v1.0.0) chapter 5: what differs from deb/
# and el/. Sourced after both: SSH, sudo, su, PAM through pam-config, login.defs, accounts.
#
# Decisions
# - Vendor files: openSUSE keeps sshd_config, sudoers, pam.d/{su,sshd,login}, login.defs,
#   shells, faillock.conf, pwhistory.conf in /usr/etc or /usr/lib; an /etc file REPLACES the
#   vendor one. Nothing here writes under /usr: before the first edit the vendor file is copied
#   to /etc (vendor_copy, SELinux label restored), checks read the file in effect.
# - 5.1.1: /etc/ssh/sshd_config is created as a copy of the vendor file (0600). cloud-init
#   (ssh_pwauth) writes a bare /etc/ssh/sshd_config when none exists - that would drop the
#   Include of sshd_config.d and every studio setting. The copy is kept only when `sshd -T`
#   gives the same configuration as before. Vendor drop-ins in /usr/etc/ssh/sshd_config.d with
#   other modes are reported, not changed (package files).
# - 5.1.15: SLE's weak MAC list is Debian's (umac-128-etm weak, hmac-sha1-etm not) - not EL10's.
# - sudo (studio decision 4): stock sudoers has `Defaults targetpw` + `ALL ALL=(ALL) ALL`; the
#   CIS admin (wheel, `ALL=(ALL) ALL` without NOPASSWD from cloud-init) would be asked for the
#   locked root password. Before any sudoers edit, /etc/sudoers (a vendor copy) gets the stock
#   `ALL ALL` rule commented out and `Defaults:%wheel !targetpw` - one write, `visudo -c`, the
#   previous state back on failure. The global targetpw stays (never dropped while ALL ALL is
#   active). Every sudoers change is validated with plain `visudo -c` and reverted on failure.
#   5.2.5's check also fails while the stock rule is active or wheel still has targetpw.
# - 5.2.7: /etc/pam.d/su from /usr/lib/pam.d/su; pam_wheel group=pvs-su after pam_rootok. su-l
#   gets the line too when it does not include su.
# - PAM: pam-config owns /etc/pam.d/common-*-pc (common-* are its symlinks). Every change is
#   one `pam-config -a|-d` run: common-*, postlogin-* and their -pc saved first; afterwards
#   pam_unix must be in auth/account/password/session, common-* must still be symlinks to
#   -pc (else pam-config's change is inert), pam_sss must stay when it was there, and sshd /
#   login must still reach common-auth - or everything comes back and the fix fails.
# - faillock (studio decision 1): deny 5, unlock_time 900, even_deny_root (L2) in
#   /etc/security/faillock.conf. pam-config has no faillock module and common-auth is never
#   touched (a domain join's `pam-config -a --sss` rewrites it): /etc/pam.d/sshd and login
#   (vendor copies) get `auth required preauth` / `[success=1 default=bad] substack
#   common-auth` / `[default=die] authfail` / `sufficient authsucc` and `account required
#   pam_faillock.so` first in account - a successful login is never counted. Applied by the
#   5.3.2.1.1 fix, checked there (structure, order, module present), restored on any doubt.
# - pwhistory: remember=24, enforce_for_root, use_authtok on the module line (pam-config
#   --pwhistory-*; SLE audits the line). The same keys in pwhistory.conf are commented out.
#   pam-config loses use_authtok on its next rewrite, so c5_pam_update puts it back (the
#   studio's domain join does the same after its pam-config --add --sss).
# - pam_unix: `-d --unix-nullok`, `-d --unix-remember`, `-a --unix --unix-sha512` (pam-config
#   has no yescrypt). use_authtok comes from pam-config itself while pam_pwquality is enabled:
#   the fix installs pam_pwquality and runs `-a --pwquality` (values stay in conf.d).
# - login.defs: kv_set copies the vendor file first (lib.sh). ENCRYPT_METHOD SHA512, the same
#   hash pam_unix uses.
# - 5.4.2.7/5.4.2.8: valid shells = /etc/shells (or its vendor copy) minus */nologin and
#   */false, as SLE counts them. An empty list makes the check fail and the fix refuse - it would
#   otherwise lock every account, the admin included.
# - 5.4.3.2: TMOUT also looked for in /usr/etc/profile(.d) and bash.bashrc (reported, not
#   edited).
# - STUDIO: the bake cannot test a password login or sudo for the clone admin (it does not exist
#   yet); a clone-time check should run `sudo -l -U <admin>` and one password SSH login.

# ---- helpers ----

# vendor_copy plus the SELinux label of the /etc path (cp -a keeps the /usr one); 1 when there
# is neither an /etc file nor a vendor copy.
s5_vendor_copy() {
    local f=$1
    [ -e "$f" ] && return 0
    vendor_copy "$f" || return 1
    [ -e "$f" ] || return 1
    command -v restorecon >/dev/null 2>&1 && restorecon -F "$f" 2>/dev/null
    return 0
}

# Restores FILE from BAK, or removes it when CREATED=1 (the vendor file is in effect again).
s5_restore() {
    local f=$1 bak=$2 created=$3
    if [ "$created" -eq 1 ]; then rm -f "$f"; else cat "$bak" > "$f"; fi
    rm -f "$bak"
}

# The full sshd configuration as sshd sees it (for a before/after comparison).
s5_sshd_dump() { sshd -T -C user=root -C host="$(hostname)" -C addr=127.0.0.1 2>/dev/null | LC_ALL=C sort; }

# SLE's weak MAC list is Debian's (EL10 also counts hmac-sha1-etm).
e5_weak_macs() { echo "$C5_WEAK_MACS"; }

# ---- sudo ----

# Uncommented lines matching a PCRE in the sudoers in effect and both drop-in directories.
c5_sudoers_grep() {
    local d=""
    [ -d /usr/etc/sudoers.d ] && d=/usr/etc/sudoers.d/
    # shellcheck disable=SC2086
    grep -rPHsi -- "$1" "$(effective_file /etc/sudoers)" /etc/sudoers.d/ $d 2>/dev/null
}

# Evidence of the stock policy; 0 when the `ALL ALL` rule is off and wheel is not asked for
# the target's (root's) password.
s5_sudo_policy() {
    local f a t w rc=0
    f=$(effective_file /etc/sudoers)
    a=$(grep -Ps -- '^\h*ALL\h+ALL\h*=' "$f")
    t=$(c5_sudoers_grep '^\h*Defaults\h+([^#\n\r]+,\h*)?targetpw\b')
    w=$(c5_sudoers_grep '^\h*Defaults:%wheel\h+([^#\n\r]+,\h*)?!targetpw\b')
    if [ -n "$a" ]; then ev "$f: stock rule active: $a"; rc=1; else ev "$f: no ALL ALL rule"; fi
    if [ -n "$t" ]; then
        ev "targetpw: $t"
        if [ -n "$w" ]; then ev "wheel: $w"; else ev "wheel: no !targetpw (admin would need root's password)"; rc=1; fi
    else
        ev "targetpw: not set"
    fi
    return $rc
}

# /etc/sudoers (vendor copy) with the stock `ALL ALL` rule commented out and wheel exempt from
# targetpw - one write, validated with visudo -c, the previous state back on failure.
s5_sudo_wheel_self() {
    local f=/etc/sudoers created=0 bak tmp
    pkg_installed sudo || return 0
    command -v visudo >/dev/null 2>&1 || { echo "visudo: missing"; return 1; }
    [ -e "$f" ] || created=1
    bak=$(mktemp)
    [ $created -eq 0 ] && cp -p "$f" "$bak"
    if ! s5_vendor_copy "$f" || [ ! -f "$f" ]; then
        rm -f "$bak"
        echo "no /etc/sudoers and no vendor copy"
        return 1
    fi
    tmp=$(mktemp)
    awk '/^[[:space:]]*ALL[[:space:]]+ALL[[:space:]]*=/ { print "# pvs-cis: " $0; next } { print }' "$f" > "$tmp"
    grep -Pq '^\h*Defaults:%wheel\h+([^#\n\r]+,\h*)?!targetpw\b' "$tmp" \
        || printf '%s\n' '# pvs-cis: wheel authenticates with its own password' 'Defaults:%wheel !targetpw' >> "$tmp"
    if cmp -s "$tmp" "$f" && [ $created -eq 0 ]; then
        rm -f "$tmp" "$bak"
        return 0
    fi
    cat "$tmp" > "$f"
    rm -f "$tmp"
    chown root:root "$f"
    chmod 0440 "$f"
    if ! visudo -c >/dev/null 2>&1; then
        s5_restore "$f" "$bak" $created
        echo "visudo -c failed after the wheel/targetpw change - reverted"
        return 1
    fi
    rm -f "$bak"
    return 0
}

# Adds LINE to our sudoers drop-in unless it is there; the whole configuration validated.
c5_sudoers_add() {
    local line=$1 bak had=0
    s5_sudo_wheel_self || return 1
    mkdir -p /etc/sudoers.d
    bak=$(mktemp)
    if [ -f "$C5_SUDOERS" ]; then cp -p "$C5_SUDOERS" "$bak"; had=1; fi
    touch "$C5_SUDOERS"
    grep -qxF -- "$line" "$C5_SUDOERS" || printf '%s\n' "$line" >> "$C5_SUDOERS"
    chown root:root "$C5_SUDOERS"
    chmod 0440 "$C5_SUDOERS"
    if command -v visudo >/dev/null 2>&1 && ! visudo -c >/dev/null 2>&1; then
        if [ $had -eq 1 ]; then cat "$bak" > "$C5_SUDOERS"; else rm -f "$C5_SUDOERS"; fi
        rm -f "$bak"
        echo "visudo rejected '$line' - reverted"
        return 1
    fi
    rm -f "$bak"
    return 0
}

# Comments out lines matching a PCRE in /etc/sudoers and /etc/sudoers.d (not cloud-init's);
# visudo -c or every file comes back.
c5_sudoers_comment() {
    local re=$1 f d i=0 n
    s5_sudo_wheel_self || return 1
    d=$(mktemp -d)
    for f in /etc/sudoers /etc/sudoers.d/*; do
        [ -f "$f" ] || continue
        [ "$f" = /etc/sudoers.d/90-cloud-init-users ] && continue
        grep -Pqi -- "$re" "$f" || continue
        i=$((i + 1))
        cp -p "$f" "$d/orig.$i"
        printf '%s\t%s\n' "$i" "$f" >> "$d/list"
        grep -Pni -- "$re" "$f" | cut -d: -f1 | sort -rn | while read -r n; do
            sed -i "${n}s/^/# pvs-cis: /" "$f"
        done
    done
    if [ $i -gt 0 ] && command -v visudo >/dev/null 2>&1 && ! visudo -c >/dev/null 2>&1; then
        while IFS=$'\t' read -r i f; do cat "$d/orig.$i" > "$f"; done < "$d/list"
        rm -rf "$d"
        echo "visudo rejected the change - reverted"
        return 1
    fi
    rm -rf "$d"
    return 0
}

# ---- PAM (pam-config) ----

S5_PAM_NAMES="common-account common-auth common-password common-session common-session-nonlogin postlogin-account postlogin-auth postlogin-password postlogin-session"
S5_FL_SVCS="sshd login"

s5_pam_eff() { effective_file "/etc/pam.d/$1"; }

# The common-* files in effect that exist.
s5_pam_common() {
    local n f
    for n in common-password common-auth common-account common-session common-session-nonlogin; do
        f=$(s5_pam_eff "$n")
        [ -f "$f" ] && echo "$f"
    done
}

# A PAM module is on disk (a missing `required` module fails every login).
s5_pam_mod() {
    local d
    for d in /usr/lib64/security /usr/lib/security /lib64/security /lib/security; do
        [ -f "$d/$1" ] && return 0
    done
    return 1
}

# The service FILE still authenticates through common-auth and accounts through common-account.
s5_svc_sane() {
    grep -Pq '^\h*auth\h+.*\b(include|substack)\h+common-auth\b' "$1" 2>/dev/null \
        && grep -Pq '^\h*account\h+.*\b(include|substack)\h+common-account\b' "$1" 2>/dev/null
}

# pam_unix in all four stacks in effect; sshd and login (when they exist) still reach them.
c5_pam_sane() {
    local t f s
    for t in auth account password session; do
        f=$(s5_pam_eff "common-$t")
        grep -Pq -- "^\h*-?${t}\h+.*\bpam_unix\.so\b" "$f" 2>/dev/null || { echo "$f: no $t pam_unix"; return 1; }
    done
    for s in $S5_FL_SVCS; do
        f=$(s5_pam_eff "$s")
        [ -f "$f" ] || continue
        s5_svc_sane "$f" || { echo "$f: does not reach common-auth/common-account"; return 1; }
    done
    return 0
}

# common-{account,auth,password,session} are pam-config's symlinks (else its edits are inert).
s5_pam_linked() {
    local n rc=0
    for n in common-account common-auth common-password common-session; do
        if [ "$(basename "$(readlink "/etc/pam.d/$n" 2>/dev/null)")" != "$n-pc" ]; then
            echo "/etc/pam.d/$n: not a symlink to $n-pc (self-managed - pam-config changes are not in effect)"
            rc=1
        fi
    done
    return $rc
}

s5_pam_has_sss() { grep -Pq '^\h*auth\h+.*\bpam_sss\.so\b' "$(s5_pam_eff common-auth)" 2>/dev/null; }

# State of every pam-config file in /etc/pam.d into DIR: missing, symlink (target) or a copy.
s5_pam_save() {
    local d=$1 n p
    for n in $S5_PAM_NAMES; do
        for p in "$n" "$n-pc"; do
            if [ -L "/etc/pam.d/$p" ]; then
                printf '%s\tlink\t%s\n' "$p" "$(readlink "/etc/pam.d/$p")" >> "$d/state"
            elif [ -f "/etc/pam.d/$p" ]; then
                cp -p "/etc/pam.d/$p" "$d/$p"
                printf '%s\tfile\t-\n' "$p" >> "$d/state"
            else
                printf '%s\tnone\t-\n' "$p" >> "$d/state"
            fi
        done
    done
}

s5_pam_restore() {
    local d=$1 p kind tgt
    while IFS=$'\t' read -r p kind tgt; do
        rm -f "/etc/pam.d/$p"
        case $kind in
            link) ln -s "$tgt" "/etc/pam.d/$p" ;;
            file) cp -p "$d/$p" "/etc/pam.d/$p" ;;
        esac
    done < "$d/state"
    command -v restorecon >/dev/null 2>&1 && restorecon -RF /etc/pam.d 2>/dev/null
    return 0
}

# `pam-config ARGS`, validated; everything comes back when the result is not sane. With no
# argument or --package (the Debian fixes' "regenerate"): only the sanity check, and a failure
# a c5_profile_drop_arg call recorded.
S5_PAM_ERR=0
c5_pam_update() {
    local d out rc sss=0
    case ${1:-} in
        '' | --package)
            [ "$S5_PAM_ERR" -eq 0 ] || { echo "an earlier pam-config change failed"; return 1; }
            c5_pam_sane
            return
            ;;
    esac
    command -v pam-config >/dev/null 2>&1 || { echo "pam-config: not installed"; return 1; }
    s5_pam_has_sss && sss=1
    d=$(mktemp -d)
    s5_pam_save "$d"
    out=$(pam-config "$@" 2>&1)
    rc=$?
    if [ $rc -ne 0 ] || ! c5_pam_sane || ! s5_pam_linked || { [ $sss -eq 1 ] && ! s5_pam_has_sss; }; then
        s5_pam_restore "$d"
        rm -rf "$d"
        echo "pam-config $* (rc=$rc${out:+: $(tail -n 2 <<<"$out" | paste -sd' ')}) - PAM files restored"
        return 1
    fi
    rm -rf "$d"
    s5_pwh_authtok
    return 0
}

# pam-config writes use_authtok on the pam_pwhistory line but does not read it back: its
# next rewrite (any -a or -d) drops it. Put back after every call, when the line is there.
s5_pwh_authtok() {
    local f
    f=$(s5_pam_eff common-password)
    grep -Pq '^\h*password\h+.*\bpam_pwhistory\.so\b' "$f" 2>/dev/null || return 0
    grep -Pq '^\h*password\h+.*\bpam_pwhistory\.so\b.*\buse_authtok\b' "$f" && return 0
    pam-config -a --pwhistory --pwhistory-use_authtok >/dev/null 2>&1
}

# MODULE's ARG (key or key=value) off its pam-config line: `pam-config -d --<mod>-<key>`.
# 0 when the argument was there (the caller then runs c5_pam_update --package).
c5_profile_drop_arg() {
    local mod=$1 arg=${2%%=*} opt f hit=0
    case $mod in
        pam_pwquality.so) opt=pwquality ;;
        pam_pwhistory.so) opt=pwhistory ;;
        pam_unix.so) opt=unix ;;
        *) return 1 ;;    # pam_faillock: our sshd/login lines carry no arguments
    esac
    while IFS= read -r f; do
        grep -Pq -- "^\h*[a-z]+\h+.*\b${mod//./\\.}\h+([^#\n\r]+\h+)?${arg}\b" "$f" && hit=1
    done < <(s5_pam_common)
    [ $hit -eq 1 ] || return 1
    c5_pam_update -d "--$opt-$arg" || S5_PAM_ERR=1
    return 0
}

# pam_pwquality installed and enabled (pam-config then writes use_authtok on pam_unix).
s5_pwquality_on() {
    s5_pam_mod pam_pwquality.so || pkg_install pam_pwquality || { echo "pam_pwquality: install failed"; return 1; }
    grep -Pq '^\h*password\h+.*\bpam_pwquality\.so\b' "$(s5_pam_eff common-password)" 2>/dev/null && return 0
    c5_pam_update -a --pwquality
}

# Effective pwquality KEY: module argument > pwquality.conf (or the vendor one) > conf.d.
c5_pwq_get() {
    local k=$1 v f w src=""
    v=$(c5_pam_arg "$(s5_pam_eff common-password)" password pam_pwquality.so "$k")
    if [ -n "$v" ]; then printf '%s\tcommon-password\n' "$v"; return 0; fi
    v=$(kv_get /etc/security/pwquality.conf "$k")
    if [ -n "$v" ]; then printf '%s\t%s\n' "$v" "$(effective_file /etc/security/pwquality.conf)"; return 0; fi
    for f in $(ls /etc/security/pwquality.conf.d/*.conf 2>/dev/null | LC_ALL=C sort); do
        w=$(kv_get "$f" "$k")
        if [ -n "$w" ]; then v=$w; src=$f; fi
    done
    [ -n "$v" ] && printf '%s\t%s\n' "$v" "$src"
    return 0
}

# The key in our conf.d file; a vendor pwquality.conf that sets it is copied to /etc first and
# the key commented out there.
c5_pwq_set() {
    local k=$1 v=$2 vf
    mkdir -p /etc/security/pwquality.conf.d
    if [ ! -e /etc/security/pwquality.conf ] && vf=$(vendor_of /etc/security/pwquality.conf) \
        && grep -Pq "^\h*${k}\h*=" "$vf"; then
        s5_vendor_copy /etc/security/pwquality.conf
    fi
    [ -f /etc/security/pwquality.conf ] && sed -ri "s/^\s*${k}\s*=/# &/" /etc/security/pwquality.conf
    kv_set "$C5_PWQ" "$k" "$v" " = "
    chmod 0644 "$C5_PWQ"
    if c5_profile_drop_arg pam_pwquality.so "$k"; then c5_pam_update --package || return 1; fi
    return 0
}

# The pam.d files el's checks grep for module-line overrides: the SUSE ones in effect.
E5_PAM_FILES="$(s5_pam_eff common-auth) $(s5_pam_eff common-password) $(s5_pam_eff sshd) $(s5_pam_eff login)"

# ---- faillock in sshd / login ----

S5_FL_AUTH=$'auth\trequired\tpam_faillock.so preauth\nauth\t[success=1 default=bad]\tsubstack common-auth\nauth\t[default=die]\tpam_faillock.so authfail\nauth\tsufficient\tpam_faillock.so authsucc'

# 0 when FILE has exactly the studio's faillock pattern: preauth, then the substack line
# directly followed by authfail and authsucc (success=1 skips exactly one line), no other
# common-auth include, and account pam_faillock before the other account lines.
s5_fl_wired() {
    [ -f "$1" ] || return 1
    awk '
        /^[[:space:]]*(#|$)/ { next }
        { $1 = $1; n++; l[n] = $0 }
        END {
            pre = 0; sub_ = 0; acc = 0; other = 0; firstacc = 0
            for (i = 1; i <= n; i++) {
                if (l[i] == "auth required pam_faillock.so preauth" && !sub_) pre = i
                if (l[i] == "auth [success=1 default=bad] substack common-auth") {
                    if (pre && l[i + 1] == "auth [default=die] pam_faillock.so authfail" \
                        && l[i + 2] == "auth sufficient pam_faillock.so authsucc") sub_ = i
                } else if (l[i] ~ /^auth .*(include|substack) common-auth( |$)/) other = 1
                if (l[i] ~ /^account / && !firstacc) {
                    firstacc = i
                    if (l[i] == "account required pam_faillock.so") acc = 1
                }
            }
            exit !(pre && sub_ && acc && !other)
        }' "$1"
}

# Puts the faillock pattern into /etc/pam.d/SVC (a vendor copy first); restored on any doubt.
s5_fl_wire() {
    local svc=$1 f=/etc/pam.d/$1 created=0 bak tmp
    if [ ! -e "$f" ] && ! vendor_of "$f" >/dev/null; then
        [ "$svc" = sshd ] && ! c5_ssh_here >/dev/null && return 0
        [ "$svc" = login ] && return 0
        echo "pam.d/$svc: missing"
        return 1
    fi
    s5_fl_wired "$(effective_file "$f")" && return 0
    if grep -Pq '^\h*[a-z]+\h+.*\bpam_faillock\.so\b' "$(effective_file "$f")"; then
        echo "$(effective_file "$f"): pam_faillock lines of another layout - not touched"
        return 1
    fi
    [ -e "$f" ] || created=1
    bak=$(mktemp)
    [ $created -eq 0 ] && cp -p "$f" "$bak"
    s5_vendor_copy "$f" || { rm -f "$bak"; echo "pam.d/$svc: vendor copy failed"; return 1; }
    tmp=$(mktemp)
    if ! awk -v fl="$S5_FL_AUTH" '
        !a && /^[[:space:]]*auth[[:space:]]+(include|substack)[[:space:]]+common-auth([[:space:]]|$)/ { print fl; a = 1; next }
        !c && /^[[:space:]]*account[[:space:]]/ { print "account\trequired\tpam_faillock.so"; c = 1 }
        { print }
        END { exit !(a && c) }' "$f" > "$tmp"; then
        rm -f "$tmp"
        s5_restore "$f" "$bak" $created
        echo "$f: no 'auth include common-auth' or no account line - not changed"
        return 1
    fi
    cat "$tmp" > "$f"
    rm -f "$tmp"
    if ! s5_fl_wired "$f" || ! s5_svc_sane "$f" || ! c5_pam_sane >/dev/null; then
        s5_restore "$f" "$bak" $created
        echo "$f: faillock pattern did not validate - restored"
        return 1
    fi
    rm -f "$bak"
    return 0
}

# ---- accounts ----

# Valid login shells (ERE alternation): /etc/shells in effect minus */nologin and */false.
c5_valid_shells() {
    awk -F/ '$NF != "nologin" && $NF != "false" && /^\// { print }' "$(effective_file /etc/shells)" 2>/dev/null \
        | sed -E 's/[.[\*^$()+?{|]/\\&/g' | paste -s -d '|' -
}

# ======================================================================================
# 5.1 SSH server
# ======================================================================================

check_sshd_config_files_0600_root() {
    local rc=0 f
    c5_ssh_here || return 2
    perm_ok "$(effective_file /etc/ssh/sshd_config)" 600 root root || rc=1
    while IFS= read -r -d '' f; do
        ev "$f: $(stat -Lc '%a %U:%G' "$f")"
        rc=1
    done < <(find /etc/ssh/sshd_config.d/ /usr/etc/ssh/sshd_config.d/ -xdev -type f -name '*.conf' \( -perm /177 -o ! -user root -o ! -group root \) -print0 2>/dev/null)
    return $rc
}
fix_sshd_config_files_0600_root() {
    local f before rc=0
    c5_ssh_here >/dev/null || return 0
    if [ ! -e /etc/ssh/sshd_config ]; then
        before=$(s5_sshd_dump)
        s5_vendor_copy /etc/ssh/sshd_config || { echo "no vendor sshd_config"; return 1; }
        chown root:root /etc/ssh/sshd_config
        chmod 0600 /etc/ssh/sshd_config
        if ! sshd -t >/dev/null 2>&1 || [ "$(s5_sshd_dump)" != "$before" ]; then
            rm -f /etc/ssh/sshd_config
            echo "/etc/ssh/sshd_config copy changed sshd's configuration - removed"
            return 1
        fi
    fi
    chmod u-x,og-rwx /etc/ssh/sshd_config
    chown root:root /etc/ssh/sshd_config
    while IFS= read -r -d '' f; do
        chmod u-x,og-rwx "$f"
        chown root:root "$f"
    done < <(find /etc/ssh/sshd_config.d -type f -print0 2>/dev/null)
    while IFS= read -r -d '' f; do
        echo "$f: $(stat -Lc '%a %U:%G' "$f") - vendor file, not changed"
        rc=1
    done < <(find /usr/etc/ssh/sshd_config.d/ -xdev -type f -name '*.conf' \( -perm /177 -o ! -user root -o ! -group root \) -print0 2>/dev/null)
    return $rc
}

# ======================================================================================
# 5.2 Privilege escalation
# ======================================================================================

check_sudo_password_required_no_nopasswd() {
    local out rc=0
    out=$(c5_sudoers_grep '^\s*[^#].*\bNOPASSWD\s*:')
    if [ -n "$out" ]; then ev "$out"; rc=1; else ev "no NOPASSWD"; fi
    s5_sudo_policy >/dev/null && ev "stock policy: ALL ALL off, wheel without targetpw"
    return $rc
}

check_sudo_re_authentication_not_disabled() {
    local out rc=0
    out=$(c5_sudoers_grep '^\s*[^#].*!authenticate\b')
    if [ -n "$out" ]; then ev "$out"; rc=1; else ev "no !authenticate"; fi
    s5_sudo_policy || rc=1
    return $rc
}
fix_sudo_re_authentication_not_disabled() {
    s5_sudo_wheel_self || return 1
    c5_sudoers_comment '^\s*[^#].*!authenticate\b'
}

check_su_limited_to_an_empty_group() {
    local f l g m rc=0 sl
    f=$(effective_file /etc/pam.d/su)
    l=$(grep -Pi '^\s*auth\s+(?:required|requisite)\s+pam_wheel\.so(?=.*\buse_uid\b)(?=.*\bgroup=\S+).*' "$f" 2>/dev/null | head -n 1)
    [ -n "$l" ] || { ev "$f: no pam_wheel use_uid group="; return 1; }
    ev "$f: $l"
    g=$(grep -oP '\bgroup=\K\S+' <<<"$l")
    m=$(getent group "$g")
    ev "${m:-group $g: missing}"
    { [ -n "$m" ] && [ -z "$(cut -d: -f4 <<<"$m")" ]; } || rc=1
    sl=$(effective_file /etc/pam.d/su-l)
    if [ -f "$sl" ] && ! grep -Pq '^\h*auth\h+include\h+su\b' "$sl"; then
        if grep -Pqi '^\s*auth\s+(?:required|requisite)\s+pam_wheel\.so(?=.*\buse_uid\b)(?=.*\bgroup=\S+)' "$sl"; then
            ev "$sl: pam_wheel"
        else
            ev "$sl: does not include su and has no pam_wheel"
            rc=1
        fi
    fi
    return $rc
}

# pam_wheel group=pvs-su after pam_rootok in /etc/pam.d/SVC (vendor copy first).
s5_su_wheel() {
    local f=/etc/pam.d/$1 created=0 bak line='auth       required   pam_wheel.so use_uid group=pvs-su'
    grep -Pqi '^\s*auth\s+(?:required|requisite)\s+pam_wheel\.so(?=.*\buse_uid\b)(?=.*\bgroup=pvs-su\b)' "$(effective_file "$f")" 2>/dev/null && return 0
    [ -e "$f" ] || created=1
    bak=$(mktemp)
    [ $created -eq 0 ] && cp -p "$f" "$bak"
    s5_vendor_copy "$f" || { rm -f "$bak"; echo "pam.d/$1: missing"; return 1; }
    sed -i '/^[[:space:]]*auth[[:space:]].*pam_wheel\.so/s/^/# pvs-cis: /' "$f"
    if grep -Eq '^[[:space:]]*auth[[:space:]]+sufficient[[:space:]]+pam_rootok\.so' "$f"; then
        sed -i "0,/^[[:space:]]*auth[[:space:]]\+sufficient[[:space:]]\+pam_rootok\.so.*/s//&\n${line}/" "$f"
    else
        sed -i "0,/^[[:space:]]*auth[[:space:]]/s//${line}\n&/" "$f"
    fi
    if ! grep -qF "$line" "$f" || ! grep -Pq '^\h*auth\h+' "$f"; then
        s5_restore "$f" "$bak" $created
        echo "$f: pam_wheel line not placed - restored"
        return 1
    fi
    rm -f "$bak"
    return 0
}
fix_su_limited_to_an_empty_group() {
    local sl
    getent group pvs-su >/dev/null || groupadd -r pvs-su || return 1
    gpasswd -M '' pvs-su >/dev/null 2>&1
    s5_su_wheel su || return 1
    sl=$(effective_file /etc/pam.d/su-l)
    if [ -f "$sl" ] && ! grep -Pq '^\h*auth\h+include\h+su\b' "$sl"; then
        s5_su_wheel su-l || return 1
    fi
    check_su_limited_to_an_empty_group >/dev/null
}

# ======================================================================================
# 5.3 PAM
# ======================================================================================

check_pam_runtime_installed_and_current() {
    local up
    pkg_installed pam || { ev "pam: not installed"; return 1; }
    up=$(zypper -n --no-refresh lu 2>/dev/null | awk -F'|' '{ n = $3; gsub(/[[:space:]]/, "", n); if (n == "pam") { v = $5; gsub(/^[[:space:]]+|[[:space:]]+$/, "", v); print v; exit } }')
    ev "pam: $(e5_rpm_ver pam)${up:+ - update available: $up}"
    [ -z "$up" ]
}
fix_pam_runtime_installed_and_current() {
    if pkg_installed pam; then zypper -n -q update pam >/dev/null; else pkg_install pam; fi
}

# root's login environment without su (Leap minimal has none): the check runs as root, so a
# login shell started directly reads the same profile files.
c5_root_login() { env -i HOME=/root USER=root LOGNAME=root SHELL=/bin/bash TERM=dumb bash -l -c "$1" 2>/dev/null </dev/null; }
c5_root_path() { c5_root_login 'printf "%s\n" "$PATH"' | tail -n 1; }

# ---- faillock ----

check_faillock_lock_after_5_failures() {
    local v rc=0 s f bad
    v=$(kv_get /etc/security/faillock.conf deny)
    ev "faillock.conf deny: ${v:-unset} ($(effective_file /etc/security/faillock.conf))"
    [[ "$v" =~ ^[1-5]$ ]] || rc=1
    for s in $S5_FL_SVCS; do
        f=$(s5_pam_eff "$s")
        if [ ! -f "$f" ]; then
            ev "pam.d/$s: none"
            [ "$s" = sshd ] && c5_ssh_here >/dev/null && rc=1
            continue
        fi
        if s5_fl_wired "$f"; then
            ev "$f: pam_faillock in the stack"
        else
            # Studio decision (option A): faillock.conf only, as the SLE 16 audit checks.
            # pam-config has no faillock switch, and a pattern around Leap's `substack
            # common-auth` cannot tell success from failure - so nothing is locked yet.
            ev "$f: pam_faillock NOT in the auth stack - faillock.conf is set, logins are not locked (studio decision: domain join first)"
        fi
    done
    s5_pam_mod pam_faillock.so || { ev "pam_faillock.so: not installed"; rc=1; }
    # shellcheck disable=SC2086
    bad=$(grep -PHsi -- '^\h*auth\h+\S+\h+pam_faillock\.so\h+([^#\n\r]+\h+)?deny\h*=\h*(0|[6-9]|[1-9][0-9]+)\b' $E5_PAM_FILES)
    [ -n "$bad" ] && { ev "$bad"; rc=1; }
    return $rc
}
fix_faillock_lock_after_5_failures() {
    s5_pam_mod pam_faillock.so || { echo "pam_faillock.so: not installed"; return 1; }
    kv_set /etc/security/faillock.conf deny 5 " = "
    command -v restorecon >/dev/null 2>&1 && restorecon -F /etc/security/faillock.conf 2>/dev/null
    # sshd / login are not rewired (option A, see the check).
    return 0
}

# ---- pwquality ----

check_pwquality_dictionary_check_on() {
    local out
    # shellcheck disable=SC2046
    out=$(grep -PHsi -- '^\h*dictcheck\h*=\h*0\b' "$(effective_file /etc/security/pwquality.conf)" /etc/security/pwquality.conf.d/*.conf 2>/dev/null)
    out="$out$(grep -PHsi -- '^\h*password\h+(requisite|required|sufficient)\h+pam_pwquality\.so\h+([^#\n\r]+\h+)?dictcheck\h*=\h*0\b' "$(s5_pam_eff common-password)" 2>/dev/null)"
    [ -n "$out" ] && { ev "$out"; return 1; }
    ev "dictcheck: not disabled"
    return 0
}
fix_pwquality_dictionary_check_on() {
    local f vf
    if [ ! -e /etc/security/pwquality.conf ] && vf=$(vendor_of /etc/security/pwquality.conf) \
        && grep -Pqi '^\h*dictcheck\h*=\h*0\b' "$vf"; then
        s5_vendor_copy /etc/security/pwquality.conf
    fi
    for f in /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf; do
        [ -f "$f" ] && sed -ri 's/^\s*dictcheck\s*=/# &/' "$f"
    done
    if c5_profile_drop_arg pam_pwquality.so dictcheck; then c5_pam_update --package || return 1; fi
    return 0
}

# ---- pwhistory (module line via pam-config; pwhistory.conf keys commented out) ----

# Comments KEY out of /etc/security/pwhistory.conf (when it exists): one place only.
s5_pwh_conf_off() {
    [ -f "$C5_PWH" ] && sed -ri "s/^\s*${1}\b/# pvs-cis: on the pam_pwhistory line - &/" "$C5_PWH"
    return 0
}

check_pwhistory_remember_24_passwords() {
    local m c
    m=$(c5_pam_arg "$(s5_pam_eff common-password)" password pam_pwhistory.so remember)
    c=$(kv_get "$C5_PWH" remember)
    ev "pam_pwhistory remember: ${m:-unset}${c:+ (pwhistory.conf: $c)}"
    [[ "$m" =~ ^[0-9]+$ ]] && [ "$m" -ge 24 ]
}
fix_pwhistory_remember_24_passwords() {
    s5_pwh_conf_off remember
    c5_pam_update -a --pwhistory --pwhistory-remember=24 --pwhistory-enforce_for_root --pwhistory-use_authtok || return 1
    check_pwhistory_remember_24_passwords >/dev/null
}

check_pwhistory_enforced_for_root() {
    local l
    l=$(grep -P -- '^\h*password\h+.*\bpam_pwhistory\.so\b' "$(s5_pam_eff common-password)" 2>/dev/null | head -n 1)
    ev "pam_pwhistory: ${l:-not in common-password}"
    c5_pam_flag "$(s5_pam_eff common-password)" password pam_pwhistory.so enforce_for_root
}
fix_pwhistory_enforced_for_root() {
    s5_pwh_conf_off enforce_for_root
    c5_pam_update -a --pwhistory --pwhistory-remember=24 --pwhistory-enforce_for_root --pwhistory-use_authtok || return 1
    check_pwhistory_enforced_for_root >/dev/null
}

check_pwhistory_uses_the_token_already_given() {
    local l
    l=$(grep -P -- '^\h*password\h+.*\bpam_pwhistory\.so\b' "$(s5_pam_eff common-password)" 2>/dev/null | head -n 1)
    ev "pam_pwhistory: ${l:-not in common-password}"
    c5_pam_flag "$(s5_pam_eff common-password)" password pam_pwhistory.so use_authtok
}
fix_pwhistory_uses_the_token_already_given() {
    # use_authtok needs a module before it that asks for the new password: pam_pwquality.
    s5_pwquality_on || return 1
    s5_pwh_conf_off use_authtok
    c5_pam_update -a --pwhistory --pwhistory-remember=24 --pwhistory-enforce_for_root --pwhistory-use_authtok || return 1
    check_pwhistory_uses_the_token_already_given >/dev/null
}

# ---- pam_unix ----

check_pam_unix_no_empty_passwords_nullok() {
    local out
    out=$(s5_pam_common | xargs -r grep -PHs -- '^\h*[^#\n\r]+\h+pam_unix\.so\h+([^#\n\r]+\h+)?nullok\b')
    [ -n "$out" ] && { ev "$out"; return 1; }
    ev "pam_unix: no nullok"
    return 0
}
fix_pam_unix_no_empty_passwords_nullok() {
    check_pam_unix_no_empty_passwords_nullok >/dev/null && return 0
    c5_pam_update -d --unix-nullok || return 1
    check_pam_unix_no_empty_passwords_nullok >/dev/null
}

check_pam_unix_no_remember_option() {
    local out
    out=$(s5_pam_common | xargs -r grep -PHs -- '^\h*[^#\n\r]+\h+pam_unix\.so\h+([^#\n\r]+\h+)?remember=\d+\b')
    [ -n "$out" ] && { ev "$out"; return 1; }
    ev "pam_unix: no remember="
    return 0
}
fix_pam_unix_no_remember_option() {
    check_pam_unix_no_remember_option >/dev/null && return 0
    c5_pam_update -d --unix-remember || return 1
    check_pam_unix_no_remember_option >/dev/null
}

check_pam_unix_strong_password_hash() {
    local f out
    f=$(s5_pam_eff common-password)
    out=$(grep -PH -- '^\h*password\h+([^#\n\r]+)\h+pam_unix\.so\h+([^#\n\r]+\h+)?(sha512|yescrypt)\b' "$f" 2>/dev/null)
    ev "${out:-$f: pam_unix password line without sha512/yescrypt}"
    [ -n "$out" ]
}
fix_pam_unix_strong_password_hash() {
    local h
    for h in md5 bigcrypt sha256 blowfish; do
        grep -Pq "^\h*password\h+.*\bpam_unix\.so\h+([^#\n\r]+\h+)?${h}\b" "$(s5_pam_eff common-password)" 2>/dev/null \
            && { c5_pam_update -d "--unix-$h" || return 1; }
    done
    check_pam_unix_strong_password_hash >/dev/null && return 0
    c5_pam_update -a --unix --unix-sha512 || return 1
    check_pam_unix_strong_password_hash >/dev/null
}

check_pam_unix_uses_the_token_already_given() {
    local f out
    f=$(s5_pam_eff common-password)
    out=$(grep -PH -- '^\h*password\h+([^#\n\r]+)\h+pam_unix\.so\h+([^#\n\r]+\h+)?use_authtok\b' "$f" 2>/dev/null)
    ev "${out:-$f: pam_unix password line without use_authtok}"
    [ -n "$out" ]
}
# pam-config writes use_authtok on pam_unix's password line itself while pam_pwquality is on.
fix_pam_unix_uses_the_token_already_given() {
    s5_pwquality_on || return 1
    check_pam_unix_uses_the_token_already_given >/dev/null
}

# ======================================================================================
# 5.4 User accounts and environment
# ======================================================================================

fix_login_defs_strong_password_hash() {
    local v
    v=$(kv_get /etc/login.defs ENCRYPT_METHOD)
    [ "${v^^}" = SHA512 ] || kv_set /etc/login.defs ENCRYPT_METHOD SHA512
    return 0
}

check_system_accounts_have_no_login_shell() {
    local out
    [ -n "$(c5_valid_shells)" ] || { ev "$(effective_file /etc/shells): no valid login shell listed"; return 1; }
    out=$(c5_sys_shell_users)
    [ -n "$out" ] && { ev "$out"; return 1; }
    ev "no system account with a login shell"
    return 0
}
fix_system_accounts_have_no_login_shell() {
    local u nl
    [ -n "$(c5_valid_shells)" ] || { echo "no valid login shell in /etc/shells - nothing changed"; return 1; }
    nl=$(command -v nologin || echo /usr/sbin/nologin)
    for u in $(c5_sys_shell_users | cut -d: -f1); do usermod -s "$nl" "$u"; done
    return 0
}

check_accounts_without_a_login_shell_are_locked() {
    local out
    [ -n "$(c5_valid_shells)" ] || { ev "$(effective_file /etc/shells): no valid login shell listed"; return 1; }
    out=$(c5_noshell_unlocked | paste -s -d' ' -)
    [ -n "$out" ] && { ev "not locked: $out"; return 1; }
    ev "all locked"
    return 0
}
fix_accounts_without_a_login_shell_are_locked() {
    local u
    # An empty list would make every account "without a login shell" - the admin included.
    [ -n "$(c5_valid_shells)" ] || { echo "no valid login shell in /etc/shells - nothing locked"; return 1; }
    for u in $(c5_noshell_unlocked); do usermod -L "$u"; done
    return 0
}

check_nologin_not_listed_as_a_shell() {
    local f out
    f=$(effective_file /etc/shells)
    out=$(grep -Ps '^\h*([^#\n\r]+)?\/nologin\b' "$f")
    [ -n "$out" ] && { ev "$f: $out"; return 1; }
    ev "$f: no nologin"
    return 0
}
fix_nologin_not_listed_as_a_shell() {
    local f=/etc/shells created=0 bak
    check_nologin_not_listed_as_a_shell >/dev/null && return 0
    [ -e "$f" ] || created=1
    bak=$(mktemp)
    [ $created -eq 0 ] && cp -p "$f" "$bak"
    s5_vendor_copy "$f" || { rm -f "$bak"; echo "no /etc/shells"; return 1; }
    sed -ri '/^\s*([^#]+)?\/nologin\b/d' "$f"
    if [ -z "$(c5_valid_shells)" ]; then
        s5_restore "$f" "$bak" $created
        echo "/etc/shells would list no login shell - restored"
        return 1
    fi
    rm -f "$bak"
    return 0
}

# Shell init files that mention TMOUT, the vendor ones in /usr/etc included.
s5_tmout_files() {
    grep -Pls -- '^([^#\n\r]+)?\bTMOUT\b' /etc/*bashrc /etc/profile /etc/profile.d/*.sh \
        /usr/etc/*bashrc /usr/etc/profile /usr/etc/profile.d/*.sh 2>/dev/null
}

check_shell_timeout_900s_read_only() {
    local f v n=0 rc=0
    while IFS= read -r f; do
        n=$((n + 1))
        v=$(grep -Po -- '^([^#\n\r]+)?\bTMOUT=\d+\b' "$f" | awk -F= '{ print $NF }' | tail -n 1)
        ev "$f: TMOUT=${v:-unset}"
        if [ -z "$v" ] || [ "$v" -le 0 ] || [ "$v" -gt 900 ]; then rc=1; fi
        grep -Pq -- '^\h*(typeset\h-xr\hTMOUT=\d+|([^#\n\r]+)?\breadonly\h+TMOUT\b)' "$f" || { ev "$f: not readonly"; rc=1; }
        grep -Pq -- '^\h*(typeset\h-xr\hTMOUT=\d+|([^#\n\r]+)?\bexport\b([^#\n\r]+\b)?TMOUT\b)' "$f" || { ev "$f: not exported"; rc=1; }
    done < <(s5_tmout_files)
    [ $n -gt 0 ] || { ev "TMOUT: not configured"; return 1; }
    return $rc
}
fix_shell_timeout_900s_read_only() {
    local f
    while IFS= read -r f; do
        [ "$f" = "$C5_TMOUT" ] && continue
        case $f in
            /usr/*) echo "$f: sets TMOUT - vendor file, not changed" ;;
            *) sed -ri 's/^([^#]*\bTMOUT\b)/# pvs-cis: \1/' "$f" ;;
        esac
    done < <(s5_tmout_files)
    printf '%s\n' '# pvs-cis: idle shells end after 15 minutes' 'TMOUT=900' 'readonly TMOUT' 'export TMOUT' > "$C5_TMOUT"
    chmod 0644 "$C5_TMOUT"
    check_shell_timeout_900s_read_only >/dev/null
}

# 5.4.2.6 without su (Leap minimal has none): el's check, the login shell started directly.
check_root_umask_027_or_stricter() {
    local u out rc=0
    u=$(c5_root_login umask | tail -n 1)
    ev "root login umask: ${u:-unknown}"
    { [[ "$u" =~ ^[0-7]{3,4}$ ]] && (( (8#$u & 8#027) == 8#027 )); } || rc=1
    out=$(c5_weak_umask /root/.bash_profile /root/.bashrc /root/.profile)
    [ -n "$out" ] && { ev "$out"; rc=1; }
    return $rc
}
