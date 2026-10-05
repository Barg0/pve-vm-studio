# lib.sh - helpers for pvs-cis rules. Sourced by the engine (bash, `set -u`).
# Checks print evidence and return 0 (pass) / 1 (fail) / 2 (does not apply); fixes return 0
# when they did their part. See README.md.

# Evidence: one line of what a check found.
ev() { printf '%s\n' "$*"; }

# ---- packages (dpkg/apt, rpm/dnf, rpm/zypper) ----

if command -v dpkg-query >/dev/null 2>&1; then PKG_TOOL=deb
elif command -v zypper >/dev/null 2>&1; then PKG_TOOL=zypper
else PKG_TOOL=rpm; fi

pkg_installed() {
    if [ "$PKG_TOOL" = deb ]; then
        dpkg-query -W -f='${db:Status-Status}' "$1" 2>/dev/null | grep -qx installed
    else
        rpm -q --quiet "$1" 2>/dev/null
    fi
}

pkg_install() {
    case $PKG_TOOL in
        deb) DEBIAN_FRONTEND=noninteractive apt-get install -y -q -o Dpkg::Options::=--force-confold "$@" >/dev/null ;;
        zypper) zypper -n -q install --no-recommends "$@" >/dev/null ;;
        *) dnf -y -q install "$@" >/dev/null ;;
    esac
}

# Purges the ones that are installed; the others are fine as they are.
pkg_purge() {
    local p
    for p in "$@"; do
        pkg_installed "$p" || continue
        case $PKG_TOOL in
            deb) DEBIAN_FRONTEND=noninteractive apt-get purge -y -q "$p" >/dev/null || return 1 ;;
            # --no-clean-deps: zypper would otherwise take what only this package pulled in.
            zypper) zypper -n -q remove --no-clean-deps "$p" >/dev/null || return 1 ;;
            # noautoremove: dnf would otherwise take what only this package pulled in.
            *) dnf -y -q remove --setopt=clean_requirements_on_remove=False "$p" >/dev/null || return 1 ;;
        esac
    done
    return 0
}

# ---- vendor files (openSUSE: /usr/etc, /usr/lib) ----

# Where the distribution keeps the vendor copy of an /etc file, "" when it keeps none. openSUSE
# moved many out of /etc (login.defs, sshd_config, sudoers, pam.d/su...); an /etc file then
# REPLACES the vendor one completely.
vendor_of() {
    local rel=${1#/etc/} c
    for c in "/usr/etc/$rel" "/usr/lib/$rel"; do
        [ -e "$c" ] && { echo "$c"; return 0; }
    done
    return 1
}

# Before the first edit of an /etc file that does not exist yet: the vendor copy, so a one-line
# edit never stands in for the whole vendor file. A no-op where /etc has it (Debian, EL).
vendor_copy() {
    local f=$1 v
    [ -e "$f" ] && return 0
    v=$(vendor_of "$f") || return 0
    mkdir -p "$(dirname "$f")"
    cp -a "$v" "$f"
}

# The file that is in effect: /etc's, else the vendor copy.
effective_file() {
    if [ -e "$1" ]; then echo "$1"; else vendor_of "$1" || echo "$1"; fi
}

# ---- services (systemd) ----

svc_exists() { [ -n "$(systemctl list-unit-files "$1" --no-legend 2>/dev/null)" ]; }
svc_enabled() { [ "$(systemctl is-enabled "$1" 2>/dev/null)" = enabled ]; }
svc_active() { systemctl is-active --quiet "$1" 2>/dev/null; }

# Stopped and masked - nothing can start it again by dependency.
svc_off() {
    local u
    for u in "$@"; do
        systemctl stop "$u" 2>/dev/null
        systemctl mask "$u" 2>/dev/null
    done
    return 0
}

# ---- kernel modules ----

# A module is unavailable when the running kernel cannot load it: no module file at all, or
# `install <m> /bin/false|/bin/true` plus `blacklist <m>` in modprobe's configuration, and
# not loaded now.
mod_unavailable() {
    local m=$1 n=${1//-/_} kver conf
    kver=$(uname -r)
    # Every installed kernel, not only the running one: the next boot may be another (the
    # benchmark's audit walks /usr/lib/modules/** too). modprobe.d holds for all of them.
    if ! find /lib/modules/*/ -type f \( -name "$m.ko*" -o -name "$n.ko*" \) 2>/dev/null | grep -q .; then
        if grep -Eq "/(${m}|${n})\.ko" "/lib/modules/$kver/modules.builtin" 2>/dev/null; then
            ev "$m: built into the kernel"
            return 1
        fi
        ev "$m: no module in any installed kernel"
        return 0
    fi
    local bad=0
    if lsmod | awk '{print $1}' | grep -qx "$n"; then ev "$m: loaded"; bad=1; fi
    conf=$(modprobe --showconfig 2>/dev/null)
    if grep -Eq "^install[[:space:]]+${n}[[:space:]]+(/usr)?/bin/(false|true)\b" <<<"$conf"; then
        ev "$m: install -> /bin/false"
    else
        ev "$m: loadable (no install /bin/false)"; bad=1
    fi
    if grep -Eq "^blacklist[[:space:]]+${n}\b" <<<"$conf"; then ev "$m: blacklisted"; else ev "$m: not blacklisted"; bad=1; fi
    return $bad
}

mod_disable() {
    local m=$1
    printf 'install %s /bin/false\nblacklist %s\n' "$m" "$m" > "/etc/modprobe.d/pvs-cis-$m.conf"
    chmod 0644 "/etc/modprobe.d/pvs-cis-$m.conf"
    modprobe -r "$m" 2>/dev/null || rmmod "$m" 2>/dev/null
    return 0
}

# ---- sysctl ----

SYSCTL_FILE=/etc/sysctl.d/60-pvs-cis.conf

# The value the configuration files leave for KEY (the last assignment, in the order
# systemd-sysctl reads them), "" when none sets it.
sysctl_conf() {
    local k=$1 re
    re="^[[:space:]]*${k//./[./]}[[:space:]]*="
    systemd-analyze cat-config sysctl.d 2>/dev/null | grep -E "$re" | tail -n 1 | cut -d= -f2- | xargs
}

# UFW's own sysctl file (IPT_SYSCTL in /etc/default/ufw), when it exists. ufw applies it on
# start, after systemd-sysctl - the benchmark's audit reads it first.
sysctl_ufw_file() {
    local f
    [ -f /etc/default/ufw ] || return 0
    f=$(awk -F= '/^[[:space:]]*IPT_SYSCTL=/ { print $2 }' /etc/default/ufw | tail -n 1 | tr -d "\"' ")
    [ -n "$f" ] && [ -f "$f" ] && echo "$f"
    return 0
}

# Running and configured both equal VAL (whitespace normalized - "1 0" vs "1	0"), and no
# active line in UFW's sysctl file says otherwise.
sysctl_is() {
    local k=$1 want run conf f have
    want=$(xargs <<<"$2")
    run=$(sysctl -n "$k" 2>/dev/null | xargs)
    conf=$(sysctl_conf "$k")
    ev "$k: running '${run}', configured '${conf:-unset}'"
    f=$(sysctl_ufw_file)
    if [ -n "$f" ]; then
        have=$(grep -E "^[[:space:]]*${k//./[./]}[[:space:]]*=" "$f" 2>/dev/null | tail -n 1 | cut -d= -f2- | xargs)
        if [ -n "$have" ]; then
            ev "$f: $k = $have"
            [ "$have" = "$want" ] || return 1
        fi
    fi
    [ "$run" = "$want" ] && [ "$conf" = "$want" ]
}

# Writes KEY = VAL into the studio's file, comments it out in every other file under /etc
# that sets it differently, and sets it now.
sysctl_set() {
    local k=$1 v=$2 re f
    re="^[[:space:]]*${k//./[./]}[[:space:]]*="
    touch "$SYSCTL_FILE"
    sed -i -E "/${re}/d" "$SYSCTL_FILE"
    printf '%s = %s\n' "$k" "$v" >> "$SYSCTL_FILE"
    for f in /etc/sysctl.conf /etc/sysctl.d/*.conf /etc/ufw/sysctl.conf; do
        [ -f "$f" ] && [ "$f" != "$SYSCTL_FILE" ] || continue
        # 99-sysctl.conf -> ../sysctl.conf: the target is in the list itself, and sed -i
        # would replace the link with a copy.
        [ -L "$f" ] && continue
        sed -i -E "s|${re}|# pvs-cis: set in ${SYSCTL_FILE} - &|" "$f"
    done
    sysctl -q -w "$k=$v" >/dev/null 2>&1
    return 0
}

# ---- sshd ----

SSHD_FILE=/etc/ssh/sshd_config.d/00-pvs-cis.conf

# sshd's effective value of KEY (lower case key), for a root login from localhost.
sshd_val() { sshd_val_for root 127.0.0.1 "$1"; }

# sshd's effective value of KEY for USER connecting from ADDR.
sshd_val_for() {
    sshd -T -C user="$1" -C host="$(hostname)" -C addr="$2" 2>/dev/null \
        | awk -v k="${3,,}" 'tolower($1) == k { $1 = ""; sub(/^ /, ""); print; exit }'
}

# The connections to evaluate, "user addr" per line: root from localhost, and - when the
# configuration has Match blocks - the users, groups' members and addresses they name (the
# benchmark evaluates sshd -T for those as well). Patterns (*, ?, !) are not expanded.
sshd_contexts() {
    echo "root 127.0.0.1"
    local m kind vals v
    m=$(grep -hiE '^[[:space:]]*Match[[:space:]]' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null) || return 0
    while read -r _ kind vals _; do
        for v in ${vals//,/ }; do
            case $v in *'*'* | *'?'* | '!'*) continue ;; esac
            case ${kind,,} in
                user) echo "$v 127.0.0.1" ;;
                group) getent group "$v" | awk -F: '{ n = split($4, u, ","); if (n) print u[1] " 127.0.0.1" }' ;;
                address) echo "root ${v%/*}" ;;
            esac
        done
    done <<<"$m"
}

sshd_is() {
    local have u a rc=0 ctx
    have=$(sshd_val "$1")
    ev "sshd $1: ${have:-unset}"
    [ "${have,,}" = "${2,,}" ] || rc=1
    while read -r u a; do
        [ "$u $a" = "root 127.0.0.1" ] && continue
        ctx=$(sshd_val_for "$u" "$a" "$1")
        if [ "${ctx,,}" != "${2,,}" ]; then ev "sshd $1 for $u from $a (Match): ${ctx:-unset}"; rc=1; fi
    done < <(sshd_contexts)
    return $rc
}

# Our drop-in comes first (00-), and sshd keeps the first value it reads.
sshd_set() {
    local k=$1
    shift
    mkdir -p /etc/ssh/sshd_config.d
    touch "$SSHD_FILE"
    chmod 0600 "$SSHD_FILE"
    sed -i -E "/^[[:space:]]*${k}[[:space:]]/Id" "$SSHD_FILE"
    printf '%s %s\n' "$k" "$*" >> "$SSHD_FILE"
    return 0
}

# ---- key/value configuration files (login.defs "KEY value", or "KEY=value") ----

# The last uncommented value of KEY.
kv_get() {
    local file k=$2
    file=$(effective_file "$1")
    [ -f "$file" ] || return 0
    # Key, then blanks (spaces or tabs - login.defs uses both) or "=".
    sed -n -E "s/^[[:space:]]*${k}([[:space:]]+|[[:space:]]*=[[:space:]]*)//p" "$file" | tail -n 1 | sed -E 's/[[:space:]]+#.*$//; s/[[:space:]]+$//'
}

# KEY set to VALUE - every uncommented KEY line removed, one appended. SEP defaults to a space.
kv_set() {
    local file=$1 k=$2 v=$3 sep=${4:- }
    vendor_copy "$file"
    touch "$file"
    sed -i -E "/^[[:space:]]*${k}([[:space:]]|=)/d" "$file"
    printf '%s%s%s\n' "$k" "$sep" "$v" >> "$file"
}

# ---- file permissions ----

# PATH has no permission bits beyond MAXMODE (octal) and the owner/group asked for. OWNER
# and GROUP may be alternatives: "root|shadow". A missing file passes when OPTIONAL=1.
perm_ok() {
    local path=$1 max=$2 owner=$3 group=$4 mode o g bad=0
    if [ ! -e "$path" ]; then
        ev "$path: missing"
        [ "${OPTIONAL:-0}" = 1 ] && return 2
        return 1
    fi
    read -r mode o g < <(stat -Lc '%a %U %G' "$path")
    ev "$path: $mode $o:$g"
    (( (8#$mode & ~8#$max) == 0 )) || bad=1
    [[ "$o" =~ ^($owner)$ ]] || bad=1
    [[ "$g" =~ ^($group)$ ]] || bad=1
    return $bad
}

# Takes away the bits beyond MAXMODE, sets owner and group (the first alternative).
perm_set() {
    local path=$1 max=$2 owner=${3%%|*} group=${4%%|*} mode
    [ -e "$path" ] || return 0
    mode=$(stat -Lc '%a' "$path")
    chmod "$(printf '%o' $(( 8#$mode & 8#$max )))" "$path"
    chown "$owner:$group" "$path"
}

# ---- mounts ----

# 0 when MOUNTPOINT is mounted with OPT, 1 when mounted without it, 2 when it is not a
# mount of its own (the rule does not apply).
mount_has() {
    local mp=$1 opt=$2 opts
    opts=$(findmnt -kn -o OPTIONS --target "$mp" 2>/dev/null)
    if ! findmnt -kn "$mp" >/dev/null 2>&1; then
        ev "$mp: not a separate mount"
        return 2
    fi
    ev "$mp: $opts"
    [[ ",$opts," == *",$opt,"* ]]
}

# Adds OPTs to MOUNTPOINT's fstab entry (effective at the next mount or boot). 1 when fstab
# has no entry for it.
fstab_opts() {
    local mp=$1 o
    shift
    awk -v mp="$mp" '$1 !~ /^#/ && $2 == mp { f = 1 } END { exit !f }' /etc/fstab || return 1
    for o in "$@"; do
        awk -v mp="$mp" -v o="$o" 'BEGIN { OFS = "\t" }
            $1 !~ /^#/ && $2 == mp { n = split($4, a, ","); h = 0; for (i = 1; i <= n; i++) if (a[i] == o) h = 1; if (!h) $4 = $4 "," o }
            { print }' /etc/fstab > /etc/fstab.pvs && cat /etc/fstab.pvs > /etc/fstab && rm -f /etc/fstab.pvs
    done
    mount -o remount "$mp" 2>/dev/null
    return 0
}

# ---- accounts ----

uid_min() { awk '/^[[:space:]]*UID_MIN/ { print $2 }' /etc/login.defs 2>/dev/null | tail -n 1; }

# ---- audit ----

AUDIT_FILE=/etc/audit/rules.d/50-pvs-cis.rules

# Appends LINE to the studio's audit rules unless it is there already (loaded after
# augenrules runs, at the next boot at the latest).
audit_add() {
    mkdir -p /etc/audit/rules.d
    touch "$AUDIT_FILE"
    chmod 0640 "$AUDIT_FILE"
    grep -qxF -- "$*" "$AUDIT_FILE" || printf '%s\n' "$*" >> "$AUDIT_FILE"
}
