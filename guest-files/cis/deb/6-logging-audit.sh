# CIS Ubuntu 26.04 - chapter 6: logging (journald / rsyslog / log files), auditd, AIDE.
#
# Decisions
# - Logger: journald is the studio's method (LOGGER in bench.conf, default journald). The
#   benchmark wants exactly one and says of 6.1.1.1.3 and all of 6.1.2: "do not apply if
#   systemd-journald is used". So 6.1.1.1.3's fix purges rsyslog (Ubuntu server installs it)
#   and its check FAILS while rsyslog is installed - two loggers is not "journald chosen".
#   With rsyslog gone the 6.1.2.x rules are na, on the benchmark's own word. LOGGER=rsyslog
#   would keep it and harden it instead (then 6.1.2.5/9/10 need a remote log host).
# - 6.1.1.1.4 (manual): the tmpfiles check is run; nothing too open -> pass, else review.
#   Decision: systemd's tmpfiles defaults are kept (utmp-group files stay 0664/0660).
# - 6.1.1.1.5 (manual): drop-in sets SystemMaxUse=1G, SystemKeepFree=500M, RuntimeMaxUse=200M,
#   RuntimeKeepFree=50M, MaxFileSec=1month (the benchmark's example); check reviews values.
# - journald settings go to /etc/systemd/journald.conf.d/60-pvs-cis.conf.
# - 6.1.2.5 / 6.1.2.10 (manual) and 6.1.2.9: no central log host is configured by the studio;
#   with no forwarding configured 6.1.2.9/6.1.2.10 are na, 6.1.2.5 is review (or na w/o rsyslog).
# - 6.1.2.4 / 6.1.2.7 (manual): distro rsyslog selectors and logrotate policy kept; review.
# - 6.1.3.1: anchored owner/group matching (CIS's is a substring match - stricter here).
#   The fix also makes new files compliant, not only the ones there now (the benchmark's
#   "permanent fix"): "create 644" -> "create 0640" in /etc/logrotate.d/*, and sysstat's own
#   UMASK=0027 in /etc/sysstat/sysstat - sa1/sa2 start a new /var/log/sysstat/saDD every day
#   with that umask (0022 shipped = 0644 files, failing again from day two).
# - auditd/aide are installed with --no-install-recommends (no MTA pulled in).
# - 6.2.1.3/6.2.1.4: audit=1 and audit_backlog_limit=8192 appended to GRUB_CMDLINE_LINUX in
#   /etc/default/grub.d/60-pvs-cis-audit*.cfg, then update-grub. Effective after reboot.
# - 6.2.2.1: max_log_file kept when set (Ubuntu default 8 MB), else set to 8.
# - 6.2.2.3: disk_full_action = halt, disk_error_action = halt (L2: own audit volume).
# - 6.2.2.4: space_left_action = exec /usr/local/sbin/pvs-cis-audit-space-left (logs a
#   warning; "email" needs an MTA we do not install), admin_space_left_action = single.
# - Audit rules: /etc/audit/rules.d/50-pvs-cis.rules (audit_add), exactly the benchmark's
#   rules incl. its b64/b32 split; auid>= from UID_MIN. Checks compare rule CONTENT
#   (action, arch, syscall set, fields; key ignored; auid unset/-1, perm order, a0 hex,
#   -C operand order normalized) on disk (rules.d) AND running (auditctl -l).
# - Path/dir watch rules are only added/required when the watched dir (dir=) or the parent
#   dir (path=) exists - a missing one cannot be loaded (benchmark: absent = passing).
# - 6.2.3.3: decided by the sudo actually in use (c5_sudo_impl), not by what is installed.
#   Classic sudo: the fix sets Defaults logfile="/var/log/sudo.log" and watches it. sudo-rs
#   (26.04's default) has no logfile option at all, so the rule FAILS there - and the
#   benchmark's exceptions.default declares that deviation with its reason (sudo events go to
#   the persistent journal, which 5.2.3 accepts). No sudo at all: na.
# - 6.2.3.10: privileged-command rules are generated from the SUID/SGID files found AT FIX
#   TIME (/etc/audit/rules.d/55-pvs-cis-privileged.rules). Software installed later is not
#   covered until the fix runs again; the check then fails. /snap mounts are skipped.
# - Rules are loaded once by the 6.2.3.36 fix (augenrules --load, after -c in
#   01-pvs-cis-initialize.rules and -e 2 in 99-finalize.rules); the immutable flag then holds
#   until the reboot. 6.2.3.35's check requires the last -e on disk AND running to be 2.
# - Rule syscalls assume amd64 (open/creat/chmod etc. do not exist on arm64).
# - AIDE: installed + configured, dailyaidecheck.timer enabled (fallback units created if
#   aide-common has none). NO database is built in the bake; the clone runs aideinit on its
#   first boot. No check here needs the database (evidence says whether it exists).
# - 6.3.3: audit-tool lines appended to /etc/aide/aide.conf; checked with `aide -p`.

C6_JOURNALD=/etc/systemd/journald.conf.d/60-pvs-cis.conf
C6_AUDITD=/etc/audit/auditd.conf
C6_PRIV_RULES=/etc/audit/rules.d/55-pvs-cis-privileged.rules
C6_INIT_RULES=/etc/audit/rules.d/01-pvs-cis-initialize.rules
C6_FINAL_RULES=/etc/audit/rules.d/99-finalize.rules
C6_SPACE_SCRIPT=/usr/local/sbin/pvs-cis-audit-space-left
C6_AIDE_CONF=/etc/aide/aide.conf
C6_LOGGER=${LOGGER:-journald}

# ---- chapter helpers: logging ----

# rsyslog is "in use" when its package is installed.
c6_rsyslog_used() { pkg_installed rsyslog; }

c6_rsyslog_files() { ls /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null; }

# Uncommented lines of the rsyslog configuration matching a PCRE (case-insensitive).
c6_rsyslog_grep() {
    local f
    f=$(c6_rsyslog_files)
    [ -n "$f" ] || return 1
    # shellcheck disable=SC2086
    grep -Psi -- "$1" $f 2>/dev/null
}

# A remote forwarding target configured in rsyslog (basic @/@@ or omfwd target=).
c6_rsyslog_fwd() {
    c6_rsyslog_grep '^\h*\*\.\*\h+@{1,2}\H+'
    c6_rsyslog_grep '^\h*([^#]+\h+)?action\(([^#]+\h+)?\btarget=\"?[^#\"]+\"?\b'
}

# journald's effective value for KEY ([Journal] section, last file wins). Empty when unset.
c6_journald_get() {
    systemd-analyze cat-config systemd/journald.conf 2>/dev/null | awk -v k="$1" '
        /^[[:space:]]*\[/ { sec = ($0 ~ /^[[:space:]]*\[Journal\]/); next }
        sec && $0 ~ ("^[[:space:]]*" k "[[:space:]]*=") { v = $0; sub(/^[^=]*=[[:space:]]*/, "", v); sub(/[[:space:]]+$/, "", v) }
        END { print v }'
}

# The commented default of KEY in the main journald.conf ("#Compress=yes").
c6_journald_default() {
    local f
    f=$(readlink -e /etc/systemd/journald.conf || readlink -e /usr/lib/systemd/journald.conf)
    [ -n "$f" ] || return 0
    sed -n -E "s/^[[:space:]]*#[[:space:]]*$1[[:space:]]*=[[:space:]]*([^[:space:]]+).*/\1/p" "$f" | head -n 1
}

c6_journald_set() {
    local k=$1 v=$2
    mkdir -p "${C6_JOURNALD%/*}"
    [ -f "$C6_JOURNALD" ] || printf '[Journal]\n' > "$C6_JOURNALD"
    grep -q '^\[Journal\]' "$C6_JOURNALD" || sed -i '1i [Journal]' "$C6_JOURNALD"
    sed -i -E "/^[[:space:]]*${k}[[:space:]]*=/d" "$C6_JOURNALD"
    printf '%s=%s\n' "$k" "$v" >> "$C6_JOURNALD"
    chmod 0644 "$C6_JOURNALD"
}

c6_journald_reload() { systemctl reload-or-restart systemd-journald.service 2>/dev/null; return 0; }

# KEY's effective journald value is VAL (case-insensitive).
c6_journald_is() {
    local k=$1 want=$2 have
    have=$(c6_journald_get "$k")
    if [ -n "$have" ]; then
        ev "journald $k=$have"
    else
        have=$(c6_journald_default "$k")
        ev "journald $k unset (default ${have:-unknown})"
    fi
    [ "${have,,}" = "${want,,}" ]
}

# Scans /var/log like the benchmark: FIX=1 also corrects mode/owner/group.
c6_logfiles() {
    local fix=${1:-0} file mode user group name mask rperm aus agr shell bad=0 n=0 out=()
    while IFS= read -r -d '' file; do
        read -r mode user group < <(stat -Lc '%a %U %G' "$file" 2>/dev/null) || continue
        name=${file##*/}
        if [[ "${file%/*}" =~ /apt$ ]]; then
            mask=0133 rperm=u-x,go-wx aus=root agr='root|adm'
        else
            case $name in
                lastlog | lastlog.* | wtmp | wtmp.* | wtmp-* | btmp | btmp.* | btmp-* | README)
                    mask=0113 rperm=ug-x,o-wx aus=root agr='root|utmp' ;;
                cloud-init.log* | localmessages* | waagent.log*)
                    mask=0133 rperm=u-x,go-wx aus='root|syslog' agr='root|adm' ;;
                secure | secure*.* | secure.* | secure-* | auth.log | syslog | messages)
                    mask=0137 rperm=u-x,g-wx,o-rwx aus='root|syslog' agr='root|adm' ;;
                SSSD | sssd)
                    mask=0117 rperm=ug-x,o-rwx aus='root|SSSD' agr='root|SSSD' ;;
                gdm | gdm3)
                    mask=0117 rperm=ug-x,o-rwx aus=root agr='root|gdm|gdm3' ;;
                *.journal | *.journal~)
                    mask=0137 rperm=u-x,g-wx,o-rwx aus=root agr='root|systemd-journal' ;;
                *)
                    mask=0137 rperm=u-x,g-wx,o-rwx aus='root|syslog' agr='root|adm'
                    # A service account (no login shell) may own its own log.
                    shell=$(awk -F: -v u="$user" '$1 == u { print $7 }' /etc/passwd)
                    if [ "$user" = root ] || [ -z "$shell" ] || ! grep -qxF -- "$shell" <(sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//' /etc/shells); then
                        [[ "$user" =~ ^($aus)$ ]] || aus="$aus|$user"
                        [[ "$group" =~ ^($agr)$ ]] || agr="$agr|$group"
                    fi ;;
            esac
        fi
        local issue=""
        (( (8#$mode & 8#$mask) == 0 )) || { issue+=" mode $mode"; [ "$fix" = 1 ] && chmod "$rperm" "$file"; }
        [[ "$user" =~ ^($aus)$ ]] || { issue+=" owner $user"; [ "$fix" = 1 ] && chown root "$file"; }
        [[ "$group" =~ ^($agr)$ ]] || { issue+=" group $group"; [ "$fix" = 1 ] && chgrp root "$file"; }
        if [ -n "$issue" ]; then
            bad=1
            n=$((n + 1))
            [ ${#out[@]} -lt 25 ] && out+=("$file:$issue")
        fi
    done < <(find -L /var/log -type f \( -perm /0137 -o ! -user root -o ! -group root \) -print0 2>/dev/null)
    if [ $bad -eq 0 ]; then
        ev "/var/log: all files within limits"
    else
        [ ${#out[@]} -gt 0 ] && printf '%s\n' "${out[@]}"
        ev "$n file(s) outside the limits$([ "$fix" = 1 ] && echo ' - corrected')"
    fi
    return $bad
}

# ---- chapter helpers: auditd ----

c6_uid_min() { local u; u=$(uid_min); echo "${u:-1000}"; }

# The audit log directory from auditd.conf.
c6_audit_logdir() {
    local f
    f=$(awk -F= '/^[[:space:]]*log_file[[:space:]]*=/ { print $2 }' "$C6_AUDITD" 2>/dev/null | xargs)
    [ -n "$f" ] || f=/var/log/audit/audit.log
    dirname "$f"
}

# awk functions: a rule line -> "action|arch|syscalls|fields" with the key dropped and
# auditctl -l spellings normalized (auid=-1 -> unset, perm letters sorted, a0..a3 hex,
# -C operands ordered, trailing slashes of path/dir dropped, -S all -> all).
C6_AWK_NORM='
function srt(s, sep,   a, n, i, j, t, out) {
    n = split(s, a, sep)
    for (i = 2; i <= n; i++) { t = a[i]; j = i - 1; while (j > 0 && a[j] > t) { a[j + 1] = a[j]; j-- } a[j + 1] = t }
    out = ""
    for (i = 1; i <= n; i++) if (a[i] != "") out = out (out == "" ? "" : sep) a[i]
    return out
}
function hexnorm(v,   n, i, c, d) {
    v = tolower(v)
    if (v ~ /^0x[0-9a-f]+$/) {
        n = 0
        for (i = 3; i <= length(v); i++) { c = substr(v, i, 1); d = index("0123456789abcdef", c) - 1; n = n * 16 + d }
    } else if (v ~ /^[0-9]+$/) n = v + 0
    else return v
    return sprintf("%x", n)
}
function norm(line,   t, n, i, j, act, arch, sc, f, x, nm, op, val, ch, k, c) {
    n = split(line, t, /[ \t]+/)
    act = ""; arch = ""; sc = ""; f = ""
    for (i = 1; i <= n; i++) {
        if (t[i] == "-a" || t[i] == "-A") { act = srt(t[++i], ","); continue }
        if (t[i] == "-S") { sc = sc "," t[++i]; continue }
        if (t[i] == "-k") { i++; continue }
        if (t[i] == "-F" || t[i] == "-C") {
            c = (t[i] == "-C"); x = t[++i]
            if (!match(x, /(!=|>=|<=|&=|=|>|<|&)/)) continue
            nm = substr(x, 1, RSTART - 1); op = substr(x, RSTART, RLENGTH); val = substr(x, RSTART + RLENGTH)
            if (c) {
                if ((op == "=" || op == "!=") && nm > val) { k = nm; nm = val; val = k }
                f = f " C:" nm op val; continue
            }
            if (nm == "key") continue
            if (nm == "arch") { arch = val; continue }
            if (nm ~ /^(auid|uid|euid|suid|fsuid|loginuid|ouid)$/ && (val == "-1" || val == "4294967295" || val == "unset")) val = "unset"
            if (nm ~ /^a[0-3]$/) val = hexnorm(val)
            if (nm == "perm") { k = split(val, ch, ""); val = ""; for (j = 1; j <= k; j++) val = val " " ch[j]; val = srt(val, " "); gsub(/ /, "", val) }
            if ((nm == "path" || nm == "dir") && val != "/") sub(/\/+$/, "", val)
            f = f " " nm op val
        }
    }
    sc = srt(sc, ",")
    if (("," sc ",") ~ /,all,/) sc = "all"
    # A watch (path=/dir= with perm=): auditctl -l prints it with the arch and the kernel
    # whole list of syscalls for that permission; the benchmark writes it without -S. Both
    # are the same rule - compared without arch and syscalls.
    if (f ~ /(^| )(path|dir)=/ && f ~ /(^| )perm=/) { arch = ""; sc = "" }
    return act "|" arch "|" sc "|" srt(f, " ")
}
function covers(r, l,   R, L, rs, ls, n, i, have) {
    split(r, R, "|"); split(l, L, "|")
    if (R[1] != L[1] || R[2] != L[2] || R[4] != L[4]) return 0
    if (R[3] == "") return (L[3] == "" || L[3] == "all")
    if (L[3] == "all") return 1
    n = split(L[3], ls, ","); for (i = 1; i <= n; i++) have[ls[i]] = 1
    n = split(R[3], rs, ","); for (i = 1; i <= n; i++) if (!(rs[i] in have)) return 0
    return 1
}'

# 0 when a line on stdin covers RULE (same content, key ignored).
c6_rule_in() {
    awk -v req="$1" "$C6_AWK_NORM"'
        BEGIN { R = norm(req) }
        /^[ \t]*-[aA][ \t]/ { if (covers(R, norm($0))) { found = 1; exit } }
        END { exit !found }'
}

c6_disk_rules() { cat /etc/audit/rules.d/*.rules 2>/dev/null | grep -Ev '^[[:space:]]*(#|$)'; }
c6_run_rules() { auditctl -l 2>/dev/null; }

# A watch rule can only be loaded when its directory (dir=) or parent (path=) exists. Only the
# network configuration watches may be skipped when absent - the benchmark allows that for
# 6.2.3.8/6.2.3.9 (ifupdown, NetworkManager: one of them is not there). Any other watch on a
# missing target is required anyway, so its check fails rather than passing unseen.
c6_target_ok() {
    local p t
    p=$(grep -oE -- '-F (path|dir)=[^ ]+' <<<"$1" | head -n 1)
    [ -n "$p" ] || return 0
    case $p in
        *dir=*) t=${p#*dir=}; t=${t%/} ;;
        *) t=${p#*path=}; t=${t%/*} ;;
    esac
    [ -d "$t" ] && return 0
    case $t in /etc/network | /etc/network/* | /etc/networks | /etc/netplan | /etc/NetworkManager | /etc/NetworkManager/*) return 1 ;; esac
    return 0
}

# Every RULE present on disk (rules.d) and in the running configuration.
c6_audit_check() {
    local disk run r d s bad=0
    if ! command -v auditctl >/dev/null 2>&1; then ev "auditctl: not installed"; return 1; fi
    disk=$(c6_disk_rules)
    run=$(c6_run_rules)
    for r in "$@"; do
        if ! c6_target_ok "$r"; then ev "target absent, not loadable: $r"; continue; fi
        d=missing s=missing
        c6_rule_in "$r" <<<"$disk" && d=ok
        c6_rule_in "$r" <<<"$run" && s=ok
        ev "disk:$d run:$s  $r"
        [ "$d" = ok ] && [ "$s" = ok ] || bad=1
    done
    return $bad
}

# Adds the RULEs not on disk yet to the studio's rules file (loaded by 6.2.3.36 / at boot).
c6_audit_fix() {
    local r disk
    [ -d /etc/audit ] || { echo "auditd not installed"; return 1; }
    disk=$(c6_disk_rules)
    for r in "$@"; do
        c6_target_ok "$r" || continue
        c6_rule_in "$r" <<<"$disk" || audit_add "$r"
    done
    return 0
}

c6_audit_locked() { auditctl -s 2>/dev/null | grep -Eq '^enabled[[:space:]]+2'; }

# auditd.conf KEY's first word is one of ALT (regex alternatives).
c6_auditd_is() {
    local k=$1 alt=$2 v
    if [ ! -f "$C6_AUDITD" ]; then ev "$C6_AUDITD: missing"; return 1; fi
    v=$(kv_get "$C6_AUDITD" "$k")
    ev "$k = ${v:-unset}"
    [[ "${v%% *}" =~ ^($alt)$ ]]
}

c6_auditd_set() {
    [ -f "$C6_AUDITD" ] || { echo "$C6_AUDITD missing"; return 1; }
    kv_set "$C6_AUDITD" "$1" "$2" " = "
}

c6_auditd_reload() { pkill -HUP -x auditd 2>/dev/null; return 0; }

# grub.cfg: every linux line matches the PCRE.
c6_grub_has() {
    local lines bad
    lines=$(find /boot -type f -name grub.cfg -exec grep -Ph '^\h*linux' {} + 2>/dev/null)
    ev "running: $(grep -oE "$2[^ ]*" /proc/cmdline 2>/dev/null || echo "no $2")"
    if [ -z "$lines" ]; then ev "no linux entries in /boot/**/grub.cfg"; return 1; fi
    bad=$(grep -Pv -- "$1" <<<"$lines")
    if [ -n "$bad" ]; then
        ev "grub.cfg: $(wc -l <<<"$bad") of $(wc -l <<<"$lines") linux entries without $2"
        return 1
    fi
    ev "grub.cfg: all $(wc -l <<<"$lines") linux entries have $2"
}

c6_grub_add() {
    local p=$1 f=/etc/default/grub.d/$2
    mkdir -p /etc/default/grub.d
    # shellcheck disable=SC2016
    printf '# pvs-cis: kernel parameter for auditd\nGRUB_CMDLINE_LINUX="${GRUB_CMDLINE_LINUX:-} %s"\n' "$p" > "$f"
    chmod 0644 "$f"
    update-grub >/dev/null 2>&1
}

C6_AUDIT_TOOLS="/sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/auditd /sbin/augenrules"

# Mounts the privileged-command scan walks (benchmark: real filesystems without
# noexec/nosuid; /snap revisions skipped).
c6_priv_mounts() {
    findmnt -n -l -k -it "$(awk '/nodev/ { print $2 }' /proc/filesystems | paste -sd,)" 2>/dev/null \
        | grep -Pv 'noexec|nosuid' | awk '{ print $1 }' | grep -Ev '^/snap(/|$)'
}

c6_priv_files() {
    local m
    for m in $(c6_priv_mounts); do
        find "$m" -xdev -perm /6000 -type f 2>/dev/null
    done | sort -u
}

# 0 when a line on stdin has the token path=FILE.
c6_has_path() { awk -v p="path=$1" '{ for (i = 1; i <= NF; i++) if ($i == p) { f = 1; exit } } END { exit !f }'; }

# ---- 6.1.1 journald ----

rule journald-service-active "journald service active"
check_journald_service_active() {
    local s
    s=$(systemctl is-active systemd-journald.service 2>/dev/null)
    ev "systemd-journald: ${s:-unknown}"
    [ "$s" = active ]
}
fix_journald_service_active() {
    systemctl unmask systemd-journald.service 2>/dev/null
    systemctl --now enable systemd-journald.service 2>/dev/null
    systemctl is-active --quiet systemd-journald.service
}

rule journal-remote-receiver-not-in-use "journal-remote receiver not in use"
check_journal_remote_receiver_not_in_use() {
    local u e a bad=0
    for u in systemd-journal-remote.socket systemd-journal-remote.service; do
        e=$(systemctl is-enabled "$u" 2>/dev/null)
        a=$(systemctl is-active "$u" 2>/dev/null)
        ev "$u: ${e:-not-found} / ${a:-inactive}"
        [ "$e" = enabled ] && bad=1
        [ "$a" = active ] && bad=1
    done
    return $bad
}
fix_journal_remote_receiver_not_in_use() {
    if svc_exists systemd-journal-remote.socket || svc_exists systemd-journal-remote.service; then
        svc_off systemd-journal-remote.socket systemd-journal-remote.service
    fi
    return 0
}

rule journald-forwards-to-rsyslog-if-rsyslog "journald forwards to rsyslog (if rsyslog)"
check_journald_forwards_to_rsyslog_if_rsyslog() {
    if [ "$C6_LOGGER" = journald ]; then
        if c6_rsyslog_used; then
            ev "journald is the chosen logger, but rsyslog is installed - two loggers"
            return 1
        fi
        ev "journald is the chosen logger, rsyslog not installed - the benchmark: do not apply"
        return 2
    fi
    if ! c6_rsyslog_used; then ev "rsyslog is the chosen logger but not installed"; return 1; fi
    local bad=0
    if systemd-analyze cat-config systemd/journald.conf 2>/dev/null | grep -Piq '^\h*ForwardToSyslog\h*=\h*yes\b'; then
        ev "ForwardToSyslog=yes"
    else
        ev "ForwardToSyslog=yes not set"; bad=1
    fi
    svc_active rsyslog.service && ev "rsyslog: active" || { ev "rsyslog: not active"; bad=1; }
    svc_active systemd-journald.service && ev "systemd-journald: active" || { ev "systemd-journald: not active"; bad=1; }
    return $bad
}
fix_journald_forwards_to_rsyslog_if_rsyslog() {
    if [ "$C6_LOGGER" = journald ]; then
        local inst
        inst=$(c2_installed rsyslog rsyslog-gnutls rsyslog-gssapi rsyslog-relp)
        systemctl stop rsyslog.service syslog.socket 2>/dev/null
        # shellcheck disable=SC2086
        [ -z "$inst" ] || c2_apt purge $inst || return 1
        c6_journald_set ForwardToSyslog no
        c6_journald_reload
        return 0
    fi
    pkg_installed rsyslog || pkg_install rsyslog
    c6_journald_set ForwardToSyslog yes
    c6_journald_reload
}

rule journald-log-file-modes-reviewed "journald log file modes reviewed"
check_journald_log_file_modes_reviewed() {
    local f type path perm _ actual n=0
    for f in /etc/tmpfiles.d/systemd.conf /usr/lib/tmpfiles.d/systemd.conf; do
        [ -f "$f" ] || continue
        ev "config: $f"
        while read -r type path perm _; do
            if [[ "$type" == f && "$perm" =~ ^0?[0-7]{3,4}$ && -f "$path" ]]; then
                actual=$(stat -c '%a' "$path" 2>/dev/null)
                if [ -n "$actual" ] && (( (8#$actual & 8#0137) != 0 )); then
                    ev "$path: $actual (from $f)"
                    n=$((n + 1))
                fi
            fi
        done < "$f"
    done
    if [ $n -eq 0 ]; then ev "no tmpfiles-defined log file above 0640"; return 0; fi
    ev "decision: systemd tmpfiles defaults kept"
    return 3
}

rule journald-rotation-limits-set "journald rotation limits set"
check_journald_rotation_limits_set() {
    local k v miss=0
    for k in SystemMaxUse SystemKeepFree RuntimeMaxUse RuntimeKeepFree MaxFileSec; do
        v=$(c6_journald_get "$k")
        ev "$k=${v:-unset}"
        [ -n "$v" ] || miss=1
    done
    [ $miss -eq 0 ] && return 0
    return 3
}
fix_journald_rotation_limits_set() {
    c6_journald_set SystemMaxUse 1G
    c6_journald_set SystemKeepFree 500M
    c6_journald_set RuntimeMaxUse 200M
    c6_journald_set RuntimeKeepFree 50M
    c6_journald_set MaxFileSec 1month
    c6_journald_reload
}

rule journald-storage-persistent "journald storage persistent"
check_journald_storage_persistent() { c6_journald_is Storage persistent; }
fix_journald_storage_persistent() {
    c6_journald_set Storage persistent
    c6_journald_reload
}

rule journald-compression-on "journald compression on"
check_journald_compression_on() { c6_journald_is Compress yes; }
fix_journald_compression_on() {
    c6_journald_set Compress yes
    c6_journald_reload
}

# ---- 6.1.2 rsyslog (only when installed) ----

rule rsyslog-present-if-chosen "rsyslog present (if chosen)"
check_rsyslog_present_if_chosen() {
    if c6_rsyslog_used; then ev "rsyslog: installed"; return 0; fi
    ev "rsyslog: not installed - journald is the logger"
    return 2
}

rule rsyslog-enabled-and-running "rsyslog enabled and running"
check_rsyslog_enabled_and_running() {
    c6_rsyslog_used || { ev "rsyslog: not installed"; return 2; }
    local e a
    e=$(systemctl is-enabled rsyslog.service 2>/dev/null)
    a=$(systemctl is-active rsyslog.service 2>/dev/null)
    ev "rsyslog: ${e:-unknown} / ${a:-unknown}"
    [ "$e" = enabled ] && [ "$a" = active ]
}
fix_rsyslog_enabled_and_running() {
    c6_rsyslog_used || return 0
    systemctl unmask rsyslog.service 2>/dev/null
    systemctl enable rsyslog.service 2>/dev/null
    systemctl start rsyslog.service 2>/dev/null
    svc_active rsyslog.service
}

rule rsyslog-creates-files-0640 "rsyslog creates files 0640"
check_rsyslog_creates_files_0640() {
    c6_rsyslog_used || { ev "rsyslog: not installed"; return 2; }
    local lines v bad=0
    lines=$(c6_rsyslog_grep '^\h*\$FileCreateMode\h+0[0-7]{3}\b')
    if [ -z "$lines" ]; then ev "\$FileCreateMode: not set (default 0644)"; return 1; fi
    while read -r v; do
        ev "\$FileCreateMode $v"
        (( (8#$v & 8#0137) == 0 )) || bad=1
    done < <(awk '{ print $2 }' <<<"$lines")
    return $bad
}
fix_rsyslog_creates_files_0640() {
    c6_rsyslog_used || return 0
    local f v
    for f in $(c6_rsyslog_files); do
        while read -r v; do
            [ -n "$v" ] || continue
            (( (8#$v & 8#0137) == 0 )) || sed -i -E "s/^([[:space:]]*\\\$FileCreateMode[[:space:]]+)${v}\b/\10640/I" "$f"
        done < <(grep -Pio '^\h*\$FileCreateMode\h+\K0[0-7]{3}\b' "$f" 2>/dev/null)
    done
    if [ -z "$(c6_rsyslog_grep '^\h*\$FileCreateMode\h+0[0-7]{3}\b')" ]; then
        printf '# pvs-cis: new log files 0640\n$FileCreateMode 0640\n' > /etc/rsyslog.d/00-pvs-cis.conf
        chmod 0644 /etc/rsyslog.d/00-pvs-cis.conf
    fi
    systemctl restart rsyslog.service 2>/dev/null
    return 0
}

rule rsyslog-selectors-reviewed "rsyslog selectors reviewed"
check_rsyslog_selectors_reviewed() {
    c6_rsyslog_used || { ev "rsyslog: not installed"; return 2; }
    c6_rsyslog_grep '^\h*[a-z*][^#$(]*\h+[-:/]' | head -n 15
    ev "logs: $(find /var/log -maxdepth 1 -type f -newermt '-1 day' 2>/dev/null | wc -l) files written in the last day"
    ev "decision: Ubuntu's default rsyslog selectors kept"
    return 3
}

rule remote-log-host-reviewed "Remote log host reviewed"
check_remote_log_host_reviewed() {
    c6_rsyslog_used || { ev "rsyslog: not installed"; return 2; }
    local fwd
    fwd=$(c6_rsyslog_fwd)
    if [ -n "$fwd" ]; then ev "$fwd"; else ev "no forwarding configured"; fi
    ev "decision: no central log host configured by the studio"
    return 3
}

rule rsyslog-does-not-accept-remote-logs "rsyslog does not accept remote logs"
check_rsyslog_does_not_accept_remote_logs() {
    c6_rsyslog_used || { ev "rsyslog: not installed"; return 2; }
    local hits
    hits=$(c6_rsyslog_grep '^\h*(module\(load=\"?im(tcp|udp)\"?\)|input\(type=\"?im(tcp|udp)\"?\b|\$ModLoad\h+im(tcp|udp)\b|\$InputTCPServerRun\b|\$UDPServerRun\b)')
    if [ -n "$hits" ]; then ev "$hits"; return 1; fi
    ev "no imtcp/imudp listener configured"
}
fix_rsyslog_does_not_accept_remote_logs() {
    c6_rsyslog_used || return 0
    local f
    for f in $(c6_rsyslog_files); do
        sed -i -E 's/^([[:space:]]*(module\(load="?im(tcp|udp)"?\)|input\(type="?im(tcp|udp)"?|\$ModLoad[[:space:]]+im(tcp|udp)|\$InputTCPServerRun|\$UDPServerRun))/# pvs-cis: &/I' "$f"
    done
    systemctl restart rsyslog.service 2>/dev/null
    return 0
}

rule logrotate-policy-reviewed "logrotate policy reviewed"
check_logrotate_policy_reviewed() {
    if ! pkg_installed logrotate; then ev "logrotate: not installed"; else ev "logrotate: installed"; fi
    ev "logrotate.conf: $(grep -Ev '^[[:space:]]*(#|$)' /etc/logrotate.conf 2>/dev/null | grep -Ev '^[[:space:]]*include' | xargs)"
    ev "logrotate.d: $(ls /etc/logrotate.d 2>/dev/null | xargs)"
    if grep -rqsE '^[[:space:]]*maxage' /etc/logrotate.conf /etc/logrotate.d; then ev "maxage: set"; else ev "maxage: not set"; fi
    ev "decision: distro rotation policy kept"
    return 3
}

rule rsyslog-tls-module-present "rsyslog TLS module present"
check_rsyslog_tls_module_present() {
    c6_rsyslog_used || { ev "rsyslog: not installed"; return 2; }
    local p
    for p in rsyslog-gnutls rsyslog-openssl; do
        if pkg_installed "$p"; then ev "$p: installed"; return 0; fi
    done
    ev "rsyslog-gnutls: not installed"
    return 1
}
fix_rsyslog_tls_module_present() {
    c6_rsyslog_used || return 0
    pkg_installed rsyslog-gnutls || pkg_installed rsyslog-openssl || pkg_install --no-install-recommends rsyslog-gnutls
}

rule rsyslog-forwarding-over-tls "rsyslog forwarding over TLS"
check_rsyslog_forwarding_over_tls() {
    c6_rsyslog_used || { ev "rsyslog: not installed"; return 2; }
    if [ -z "$(c6_rsyslog_fwd)" ]; then ev "no remote forwarding configured"; return 2; fi
    local hits
    hits=$(c6_rsyslog_grep '^[^#]*StreamDriver\s*=\s*"?(gtls|ossl)"?')
    if [ -n "$hits" ]; then ev "$hits"; return 0; fi
    ev "forwarding without a TLS stream driver"
    return 1
}

rule rsyslog-tls-ca-reviewed "rsyslog TLS CA reviewed"
check_rsyslog_tls_ca_reviewed() {
    c6_rsyslog_used || { ev "rsyslog: not installed"; return 2; }
    if [ -z "$(c6_rsyslog_fwd)" ]; then ev "no remote forwarding configured"; return 2; fi
    local hits
    hits=$(c6_rsyslog_grep '(DefaultNetstreamDriverCAFile|StreamDriver\.CAFile)\s*=')
    ev "${hits:-no CA file configured}"
    ev "decision: no central log host configured by the studio"
    return 3
}

# ---- 6.1.3 log files ----

rule log-files-in-var-log-restricted "Log files in /var/log restricted"
check_log_files_in_var_log_restricted() { c6_logfiles 0; }
fix_log_files_in_var_log_restricted() {
    local f
    for f in /etc/logrotate.d/*; do
        [ -f "$f" ] || continue
        sed -i -E 's/^([[:space:]]*create[[:space:]]+)0?644([[:space:]])/\10640\2/' "$f"
    done
    # sysstat's collector writes a new saDD (and sarDD) every day with ITS umask, set in its
    # own config file (a dpkg conffile, kept on upgrade).
    if [ -f /etc/sysstat/sysstat ]; then
        if grep -Eq '^[[:space:]]*UMASK=' /etc/sysstat/sysstat; then
            sed -i -E 's/^[[:space:]]*UMASK=.*/UMASK=0027/' /etc/sysstat/sysstat
        else
            echo 'UMASK=0027' >> /etc/sysstat/sysstat
        fi
    fi
    c6_logfiles 1 >/dev/null
    # apt's daily runs create /var/log/apt files with the default umask (0644) on clones.
    local u
    for u in apt-daily.service apt-daily-upgrade.service; do
        mkdir -p "/etc/systemd/system/$u.d"
        printf '[Service]\nUMask=0027\n' > "/etc/systemd/system/$u.d/50-pvs-cis-umask.conf"
    done
    systemctl daemon-reload 2>/dev/null
    return 0
}

# ---- 6.2.1 auditd ----

rule auditd-installed "auditd installed"
check_auditd_installed() {
    local p bad=0
    for p in auditd audispd-plugins; do
        if pkg_installed "$p"; then ev "$p: installed"; else ev "$p: not installed"; bad=1; fi
    done
    return $bad
}
fix_auditd_installed() { pkg_install --no-install-recommends auditd audispd-plugins; }

rule auditd-enabled-and-running "auditd enabled and running"
check_auditd_enabled_and_running() {
    local e a
    e=$(systemctl is-enabled auditd 2>/dev/null)
    a=$(systemctl is-active auditd 2>/dev/null)
    ev "auditd: ${e:-not-found} / ${a:-inactive}"
    [ "$e" = enabled ] && [ "$a" = active ]
}
fix_auditd_enabled_and_running() {
    systemctl unmask auditd 2>/dev/null
    systemctl enable auditd 2>/dev/null
    systemctl start auditd 2>/dev/null
    svc_active auditd
}

rule audit-early-boot-processes-audit-1 "Audit early boot processes (audit=1)"
check_audit_early_boot_processes_audit_1() { c6_grub_has '\baudit=1\b' 'audit='; }
fix_audit_early_boot_processes_audit_1() { c6_grub_add audit=1 60-pvs-cis-audit.cfg; }

rule audit-backlog-limit-on-cmdline "Audit backlog limit on cmdline"
check_audit_backlog_limit_on_cmdline() { c6_grub_has 'audit_backlog_limit=\d+\b' 'audit_backlog_limit='; }
fix_audit_backlog_limit_on_cmdline() { c6_grub_add audit_backlog_limit=8192 61-pvs-cis-audit-backlog.cfg; }

# ---- 6.2.2 auditd data retention ----

rule audit-log-file-size-set "Audit log file size set"
check_audit_log_file_size_set() {
    [ -f "$C6_AUDITD" ] || { ev "$C6_AUDITD: missing"; return 1; }
    local l
    l=$(grep -Po '^\h*max_log_file\h*=\h*\d+\b' "$C6_AUDITD")
    ev "${l:-max_log_file not set}"
    [ -n "$l" ]
}
fix_audit_log_file_size_set() {
    [ -f "$C6_AUDITD" ] || return 1
    grep -Pq '^\h*max_log_file\h*=\h*\d+\b' "$C6_AUDITD" && return 0
    c6_auditd_set max_log_file 8
    c6_auditd_reload
}

rule audit-logs-kept-never-deleted "Audit logs kept, never deleted"
check_audit_logs_kept_never_deleted() { c6_auditd_is max_log_file_action keep_logs; }
fix_audit_logs_kept_never_deleted() { c6_auditd_set max_log_file_action keep_logs && c6_auditd_reload; }

rule halt-when-audit-volume-is-full "Halt when audit volume is full"
check_halt_when_audit_volume_is_full() {
    local bad=0
    c6_auditd_is disk_full_action 'halt|single' || bad=1
    c6_auditd_is disk_error_action 'syslog|single|halt' || bad=1
    return $bad
}
fix_halt_when_audit_volume_is_full() {
    c6_auditd_set disk_full_action halt || return 1
    c6_auditd_set disk_error_action halt
    c6_auditd_reload
}

rule warn-when-audit-volume-runs-low "Warn when audit volume runs low"
check_warn_when_audit_volume_runs_low() {
    local bad=0
    c6_auditd_is space_left_action 'email|exec|single|halt' || bad=1
    c6_auditd_is admin_space_left_action 'single|halt' || bad=1
    return $bad
}
fix_warn_when_audit_volume_runs_low() {
    [ -f "$C6_AUDITD" ] || return 1
    mkdir -p "${C6_SPACE_SCRIPT%/*}"
    cat > "$C6_SPACE_SCRIPT" <<'EOF'
#!/bin/sh
# pvs-cis: auditd space_left_action - the audit log volume is running low.
logger -p authpriv.warning -t auditd "audit log volume is low on free space"
exit 0
EOF
    chown root:root "$C6_SPACE_SCRIPT"
    chmod 0750 "$C6_SPACE_SCRIPT"
    c6_auditd_set space_left_action "exec $C6_SPACE_SCRIPT"
    c6_auditd_set admin_space_left_action single
    c6_auditd_reload
}

# ---- 6.2.3 audit rules ----

C6_UID=$(c6_uid_min)

C6_R_6_2_3_1=(
    "-a always,exit -F arch=b64 -F path=/etc/sudoers -F perm=wa -k scope"
    "-a always,exit -F arch=b64 -F dir=/etc/sudoers.d -F perm=wa -k scope"
)
rule audit-sudoers-changes "Audit sudoers changes"
check_audit_sudoers_changes() { c6_audit_check "${C6_R_6_2_3_1[@]}"; }
fix_audit_sudoers_changes() { c6_audit_fix "${C6_R_6_2_3_1[@]}"; }

C6_R_6_2_3_2=(
    "-a always,exit -F arch=b32 -C euid!=uid -F auid!=unset -S execve -k user_emulation"
    "-a always,exit -F arch=b64 -C euid!=uid -F auid!=unset -S execve -k user_emulation"
)
rule audit-actions-run-as-another-user "Audit actions run as another user"
check_audit_actions_run_as_another_user() { c6_audit_check "${C6_R_6_2_3_2[@]}"; }
fix_audit_actions_run_as_another_user() { c6_audit_fix "${C6_R_6_2_3_2[@]}"; }

# The sudo log file configured in sudoers ("Defaults logfile="), empty when none.
c6_sudo_logfile() {
    grep -rPsih '^\h*Defaults\h+([^#]+,\h*)?logfile\h*=\h*(\"|\x27)?\H+(\"|\x27)?(,\h*\H+\h*)*\h*(#.*)?$' /etc/sudoers /etc/sudoers.d 2>/dev/null \
        | grep -Pio 'logfile\h*=\h*(\"|\x27)?\K[^\"\x27,\s]+' | tail -n 1
}
c6_sudo_rule() { echo "-a always,exit -F arch=b64 -F path=$1 -F perm=wa -k sudo_log_file"; }
rule audit-sudo-log-file-changes "Audit sudo log file changes"
check_audit_sudo_log_file_changes() {
    local f impl
    impl=$(c5_sudo_impl)
    f=$(c6_sudo_logfile)
    if [ -z "$impl" ]; then ev "sudo: not installed"; return 2; fi
    ev "sudo in use: $impl"
    if [ -z "$f" ]; then
        if [ "$impl" = sudo-rs ]; then ev "sudo-rs has no logfile option - no sudo log file to watch"; else ev "no Defaults logfile= configured"; fi
        return 1
    fi
    ev "sudo logfile: $f"
    c6_audit_check "$(c6_sudo_rule "$f")"
}
fix_audit_sudo_log_file_changes() {
    local f
    f=$(c6_sudo_logfile)
    if [ -z "$f" ]; then
        # sudo-rs has nothing to set; classic sudo gets its log file.
        [ "$(c5_sudo_impl)" = sudo ] || return 0
        c5_sudoers_add 'Defaults logfile="/var/log/sudo.log"' || return 1
        f=/var/log/sudo.log
    fi
    c6_audit_fix "$(c6_sudo_rule "$f")"
}

C6_R_6_2_3_4=(
    "-a always,exit -F arch=b64 -S adjtimex,settimeofday -k time-change"
    "-a always,exit -F arch=b64 -S clock_settime -F a0=0x0 -k time-change"
    "-a always,exit -F arch=b64 -F path=/etc/localtime -F perm=wa -k localtime-change"
)
rule audit-date-and-time-changes "Audit date and time changes"
check_audit_date_and_time_changes() { c6_audit_check "${C6_R_6_2_3_4[@]}"; }
fix_audit_date_and_time_changes() { c6_audit_fix "${C6_R_6_2_3_4[@]}"; }

C6_R_6_2_3_5=(
    "-a always,exit -F arch=b32 -S sethostname,setdomainname -k system-locale"
    "-a always,exit -F arch=b64 -S sethostname,setdomainname -k system-locale"
)
rule audit-host-domain-name-syscalls "Audit host/domain name syscalls"
check_audit_host_domain_name_syscalls() { c6_audit_check "${C6_R_6_2_3_5[@]}"; }
fix_audit_host_domain_name_syscalls() { c6_audit_fix "${C6_R_6_2_3_5[@]}"; }

C6_R_6_2_3_6=(
    "-a always,exit -F arch=b64 -F path=/etc/issue -F perm=wa -k system-locale"
    "-a always,exit -F arch=b64 -F path=/etc/issue.net -F perm=wa -k system-locale"
)
rule audit-login-banner-file-changes "Audit login banner file changes"
check_audit_login_banner_file_changes() { c6_audit_check "${C6_R_6_2_3_6[@]}"; }
fix_audit_login_banner_file_changes() { c6_audit_fix "${C6_R_6_2_3_6[@]}"; }

C6_R_6_2_3_7=(
    "-a always,exit -F arch=b64 -F path=/etc/hosts -F perm=wa -k system-locale"
    "-a always,exit -F arch=b64 -F path=/etc/hostname -F perm=wa -k system-locale"
)
rule audit-hosts-hostname-file-changes "Audit hosts/hostname file changes"
check_audit_hosts_hostname_file_changes() { c6_audit_check "${C6_R_6_2_3_7[@]}"; }
fix_audit_hosts_hostname_file_changes() { c6_audit_fix "${C6_R_6_2_3_7[@]}"; }

C6_R_6_2_3_8=(
    "-a always,exit -F arch=b64 -F path=/etc/network/interfaces -F perm=wa -k system-locale"
    "-a always,exit -F arch=b64 -F dir=/etc/network/interfaces.d -F perm=wa -k system-locale"
    "-a always,exit -F arch=b64 -F dir=/etc/netplan/ -F perm=wa -k system-locale"
)
rule audit-network-config-changes "Audit network config changes"
check_audit_network_config_changes() { c6_audit_check "${C6_R_6_2_3_8[@]}"; }
fix_audit_network_config_changes() { c6_audit_fix "${C6_R_6_2_3_8[@]}"; }

C6_R_6_2_3_9=(
    "-a always,exit -F arch=b64 -F dir=/etc/NetworkManager/ -F perm=wa -k system-locale"
)
rule audit-networkmanager-config-changes "Audit NetworkManager config changes"
check_audit_networkmanager_config_changes() { c6_audit_check "${C6_R_6_2_3_9[@]}"; }
fix_audit_networkmanager_config_changes() { c6_audit_fix "${C6_R_6_2_3_9[@]}"; }

# Ubuntu 24.04 / Debian 12 cut the network files differently: /etc/network and
# /etc/networks in one recommendation, /etc/netplan in another.
C6_R_NET_ETC=(
    "-a always,exit -F arch=b64 -F dir=/etc/network -F perm=wa -k system-locale"
    "-a always,exit -F arch=b64 -F path=/etc/networks -F perm=wa -k system-locale"
)
rule audit-etc-network-changes "Audit /etc/network and /etc/networks changes"
check_audit_etc_network_changes() { c6_audit_check "${C6_R_NET_ETC[@]}"; }
fix_audit_etc_network_changes() { c6_audit_fix "${C6_R_NET_ETC[@]}"; }

C6_R_NETPLAN=("-a always,exit -F arch=b64 -F dir=/etc/netplan -F perm=wa -k system-locale")
rule audit-netplan-changes "Audit netplan changes"
check_audit_netplan_changes() { c6_audit_check "${C6_R_NETPLAN[@]}"; }
fix_audit_netplan_changes() { c6_audit_fix "${C6_R_NETPLAN[@]}"; }

rule audit-use-of-suid-sgid-programs "Audit use of SUID/SGID programs"
check_audit_use_of_suid_sgid_programs() {
    command -v auditctl >/dev/null 2>&1 || { ev "auditctl: not installed"; return 1; }
    local disk run f n=0 miss=0
    disk=$(c6_disk_rules)
    run=$(c6_run_rules)
    while IFS= read -r f; do
        [ -n "$f" ] || continue
        n=$((n + 1))
        local d=ok s=ok
        c6_has_path "$f" <<<"$disk" || d=missing
        c6_has_path "$f" <<<"$run" || s=missing
        if [ "$d" != ok ] || [ "$s" != ok ]; then
            miss=$((miss + 1))
            [ $miss -le 20 ] && ev "disk:$d run:$s  $f"
        fi
    done < <(c6_priv_files)
    ev "$n SUID/SGID file(s) on $(c6_priv_mounts | xargs), $miss not audited"
    [ $miss -eq 0 ]
}
fix_audit_use_of_suid_sgid_programs() {
    [ -d /etc/audit ] || { echo "auditd not installed"; return 1; }
    local uid tmp
    uid=$(c6_uid_min)
    tmp=$(mktemp)
    {
        grep -Ev '^[[:space:]]*(#|$)' "$C6_PRIV_RULES" 2>/dev/null
        c6_priv_files | awk -v u="$uid" '{ print "-a always,exit -F arch=b64 -S all -F path=" $0 " -F perm=x -F auid>=" u " -F auid!=unset -k privileged" }'
    } | sort -u > "$tmp"
    cat "$tmp" > "$C6_PRIV_RULES"
    rm -f "$tmp"
    chown root:root "$C6_PRIV_RULES"
    chmod 0640 "$C6_PRIV_RULES"
    return 0
}

C6_R_6_2_3_11=(
    "-a always,exit -F arch=b32 -S creat,open,openat,truncate,ftruncate -F exit=-EACCES -F auid>=$C6_UID -F auid!=unset -k access"
    "-a always,exit -F arch=b32 -S creat,open,openat,truncate,ftruncate -F exit=-EPERM -F auid>=$C6_UID -F auid!=unset -k access"
    "-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-EACCES -F auid>=$C6_UID -F auid!=unset -k access"
    "-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-EPERM -F auid>=$C6_UID -F auid!=unset -k access"
)
rule audit-failed-file-access "Audit failed file access"
check_audit_failed_file_access() { ev "UID_MIN: $C6_UID"; c6_audit_check "${C6_R_6_2_3_11[@]}"; }
fix_audit_failed_file_access() { c6_audit_fix "${C6_R_6_2_3_11[@]}"; }

C6_R_6_2_3_12=("-a always,exit -F arch=b64 -F path=/etc/group -F perm=wa -k identity")
rule audit-etc-group-changes "Audit /etc/group changes"
check_audit_etc_group_changes() { c6_audit_check "${C6_R_6_2_3_12[@]}"; }
fix_audit_etc_group_changes() { c6_audit_fix "${C6_R_6_2_3_12[@]}"; }

C6_R_6_2_3_13=("-a always,exit -F arch=b64 -F path=/etc/passwd -F perm=wa -k identity")
rule audit-etc-passwd-changes "Audit /etc/passwd changes"
check_audit_etc_passwd_changes() { c6_audit_check "${C6_R_6_2_3_13[@]}"; }
fix_audit_etc_passwd_changes() { c6_audit_fix "${C6_R_6_2_3_13[@]}"; }

C6_R_6_2_3_14=(
    "-a always,exit -F arch=b64 -F path=/etc/gshadow -F perm=wa -k identity"
    "-a always,exit -F arch=b64 -F path=/etc/shadow -F perm=wa -k identity"
)
rule audit-shadow-gshadow-changes "Audit shadow/gshadow changes"
check_audit_shadow_gshadow_changes() { c6_audit_check "${C6_R_6_2_3_14[@]}"; }
fix_audit_shadow_gshadow_changes() { c6_audit_fix "${C6_R_6_2_3_14[@]}"; }

C6_R_6_2_3_15=("-a always,exit -F arch=b64 -F path=/etc/security/opasswd -F perm=wa -k identity")
rule audit-old-password-store-changes "Audit old-password store changes"
check_audit_old_password_store_changes() { c6_audit_check "${C6_R_6_2_3_15[@]}"; }
fix_audit_old_password_store_changes() { c6_audit_fix "${C6_R_6_2_3_15[@]}"; }

C6_R_6_2_3_16=("-a always,exit -F arch=b64 -F path=/etc/nsswitch.conf -F perm=wa -k identity")
rule audit-nsswitch-conf-changes "Audit nsswitch.conf changes"
check_audit_nsswitch_conf_changes() { c6_audit_check "${C6_R_6_2_3_16[@]}"; }
fix_audit_nsswitch_conf_changes() { c6_audit_fix "${C6_R_6_2_3_16[@]}"; }

C6_R_6_2_3_17=(
    "-a always,exit -F arch=b64 -F path=/etc/pam.conf -F perm=wa -k identity"
    "-a always,exit -F arch=b64 -F dir=/etc/pam.d -F perm=wa -k identity"
)
rule audit-pam-config-changes "Audit PAM config changes"
check_audit_pam_config_changes() { c6_audit_check "${C6_R_6_2_3_17[@]}"; }
fix_audit_pam_config_changes() { c6_audit_fix "${C6_R_6_2_3_17[@]}"; }

# fchmodat2 exists from kernel 6.6 (Debian 12 runs 6.1): a rule naming a syscall the kernel
# or auditctl does not know fails to load, and takes the rest of the file with it.
c6_chmod_rules() {
    local sc=chmod,fchmod,fchmodat kv
    kv=$(uname -r | cut -d- -f1)
    if [ "$(printf '%s\n6.6\n' "$kv" | sort -V | head -n 1)" = 6.6 ] && ausyscall x86_64 fchmodat2 >/dev/null 2>&1; then
        sc=$sc,fchmodat2
    fi
    C6_R_CHMOD=(
        "-a always,exit -F arch=b32 -S $sc -F auid>=$C6_UID -F auid!=unset -k perm_mod"
        "-a always,exit -F arch=b64 -S $sc -F auid>=$C6_UID -F auid!=unset -k perm_mod"
    )
}
rule audit-chmod-family-syscalls "Audit chmod-family syscalls"
check_audit_chmod_family_syscalls() { c6_chmod_rules; c6_audit_check "${C6_R_CHMOD[@]}"; }
fix_audit_chmod_family_syscalls() { c6_chmod_rules; c6_audit_fix "${C6_R_CHMOD[@]}"; }

C6_R_6_2_3_19=(
    "-a always,exit -F arch=b32 -S chown,fchown,lchown,fchownat -F auid>=$C6_UID -F auid!=unset -k perm_mod"
    "-a always,exit -F arch=b64 -S chown,fchown,lchown,fchownat -F auid>=$C6_UID -F auid!=unset -k perm_mod"
)
rule audit-chown-family-syscalls "Audit chown-family syscalls"
check_audit_chown_family_syscalls() { c6_audit_check "${C6_R_6_2_3_19[@]}"; }
fix_audit_chown_family_syscalls() { c6_audit_fix "${C6_R_6_2_3_19[@]}"; }

C6_R_6_2_3_20=(
    "-a always,exit -F arch=b32 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=$C6_UID -F auid!=unset -k perm_mod"
    "-a always,exit -F arch=b64 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=$C6_UID -F auid!=unset -k perm_mod"
)
rule audit-xattr-changes "Audit xattr changes"
check_audit_xattr_changes() { c6_audit_check "${C6_R_6_2_3_20[@]}"; }
fix_audit_xattr_changes() { c6_audit_fix "${C6_R_6_2_3_20[@]}"; }

C6_R_6_2_3_21=(
    "-a always,exit -F arch=b32 -S mount -F auid>=$C6_UID -F auid!=unset -k mounts"
    "-a always,exit -F arch=b64 -S mount -F auid>=$C6_UID -F auid!=unset -k mounts"
)
rule audit-mounts-by-users "Audit mounts by users"
check_audit_mounts_by_users() { c6_audit_check "${C6_R_6_2_3_21[@]}"; }
fix_audit_mounts_by_users() { c6_audit_fix "${C6_R_6_2_3_21[@]}"; }

C6_R_6_2_3_22=(
    "-a always,exit -F arch=b64 -F path=/var/run/utmp -F perm=wa -k session"
    "-a always,exit -F arch=b64 -F path=/var/log/wtmp -F perm=wa -k session"
    "-a always,exit -F arch=b64 -F path=/var/log/btmp -F perm=wa -k session"
)
rule audit-session-records "Audit session records"
check_audit_session_records() { c6_audit_check "${C6_R_6_2_3_22[@]}"; }
fix_audit_session_records() { c6_audit_fix "${C6_R_6_2_3_22[@]}"; }

C6_R_6_2_3_23=(
    "-a always,exit -F arch=b64 -F path=/var/log/lastlog -F perm=wa -k logins"
    "-a always,exit -F arch=b64 -F path=/var/run/faillock -F perm=wa -k logins"
)
rule audit-login-logout-records "Audit login/logout records"
check_audit_login_logout_records() { c6_audit_check "${C6_R_6_2_3_23[@]}"; }
fix_audit_login_logout_records() { c6_audit_fix "${C6_R_6_2_3_23[@]}"; }

C6_R_6_2_3_24=(
    "-a always,exit -F arch=b32 -S unlink,unlinkat -F auid>=$C6_UID -F auid!=unset -k delete"
    "-a always,exit -F arch=b64 -S unlink,unlinkat -F auid>=$C6_UID -F auid!=unset -k delete"
)
rule audit-file-deletion-by-users "Audit file deletion by users"
check_audit_file_deletion_by_users() { c6_audit_check "${C6_R_6_2_3_24[@]}"; }
fix_audit_file_deletion_by_users() { c6_audit_fix "${C6_R_6_2_3_24[@]}"; }

C6_R_6_2_3_25=(
    "-a always,exit -F arch=b32 -S rename,renameat,renameat2 -F auid>=$C6_UID -F auid!=unset -k delete"
    "-a always,exit -F arch=b64 -S rename,renameat,renameat2 -F auid>=$C6_UID -F auid!=unset -k delete"
)
rule audit-file-renames-by-users "Audit file renames by users"
check_audit_file_renames_by_users() { c6_audit_check "${C6_R_6_2_3_25[@]}"; }
fix_audit_file_renames_by_users() { c6_audit_fix "${C6_R_6_2_3_25[@]}"; }

# Ubuntu 24.04 / Debian 12 keep these as one recommendation each.
rule audit-dac-permission-changes "Audit permission, owner and xattr changes"
check_audit_dac_permission_changes() {
    local bad=0
    check_audit_chmod_family_syscalls || bad=1
    check_audit_chown_family_syscalls || bad=1
    check_audit_xattr_changes || bad=1
    return $bad
}
fix_audit_dac_permission_changes() {
    fix_audit_chmod_family_syscalls && fix_audit_chown_family_syscalls && fix_audit_xattr_changes
}

rule audit-file-deletion-and-renames "Audit file deletion and renames by users"
check_audit_file_deletion_and_renames() {
    local bad=0
    check_audit_file_deletion_by_users || bad=1
    check_audit_file_renames_by_users || bad=1
    return $bad
}
fix_audit_file_deletion_and_renames() { fix_audit_file_deletion_by_users && fix_audit_file_renames_by_users; }

C6_R_6_2_3_26=(
    "-a always,exit -F arch=b64 -F dir=/etc/apparmor -F perm=wa -k MAC-policy"
    "-a always,exit -F arch=b64 -F dir=/etc/apparmor.d -F perm=wa -k MAC-policy"
)
rule audit-apparmor-policy-changes "Audit AppArmor policy changes"
check_audit_apparmor_policy_changes() { c6_audit_check "${C6_R_6_2_3_26[@]}"; }
fix_audit_apparmor_policy_changes() { c6_audit_fix "${C6_R_6_2_3_26[@]}"; }

# 6.2.3.27: on Ubuntu 26.04 /usr/bin/chcon is a symlink into rust-coreutils' multi-call binary
# (one inode, 100+ names). The rule is the benchmark's and passes its audit, but a path watch
# does not follow the symlink, so running chcon is not recorded by THIS rule. What chcon does -
# set the security.selinux xattr - is recorded by 6.2.3.9's setxattr/lsetxattr/fsetxattr
# rules for every user. Watching the multi-call binary instead would log every coreutils
# command; switching the gold to GNU coreutils (coreutils-from-gnu) only for this was judged
# out of proportion.
C6_R_6_2_3_27=("-a always,exit -F arch=b64 -F path=/usr/bin/chcon -F perm=x -F auid>=$C6_UID -F auid!=unset -k perm_chng")
rule audit-chcon-use "Audit chcon use"
check_audit_chcon_use() { c6_audit_check "${C6_R_6_2_3_27[@]}"; }
fix_audit_chcon_use() { c6_audit_fix "${C6_R_6_2_3_27[@]}"; }

C6_R_6_2_3_28=("-a always,exit -F arch=b64 -F path=/usr/bin/setfacl -F perm=x -F auid>=$C6_UID -F auid!=unset -k perm_chng")
rule audit-setfacl-use "Audit setfacl use"
check_audit_setfacl_use() { c6_audit_check "${C6_R_6_2_3_28[@]}"; }
fix_audit_setfacl_use() { c6_audit_fix "${C6_R_6_2_3_28[@]}"; }

C6_R_6_2_3_29=("-a always,exit -F arch=b64 -F path=/usr/bin/chacl -F perm=x -F auid>=$C6_UID -F auid!=unset -k perm_chng")
rule audit-chacl-use "Audit chacl use"
check_audit_chacl_use() { c6_audit_check "${C6_R_6_2_3_29[@]}"; }
fix_audit_chacl_use() { c6_audit_fix "${C6_R_6_2_3_29[@]}"; }

C6_R_6_2_3_30=("-a always,exit -F arch=b64 -F path=/usr/sbin/usermod -F perm=x -F auid>=$C6_UID -F auid!=unset -k usermod")
rule audit-usermod-use "Audit usermod use"
check_audit_usermod_use() { c6_audit_check "${C6_R_6_2_3_30[@]}"; }
fix_audit_usermod_use() { c6_audit_fix "${C6_R_6_2_3_30[@]}"; }

C6_R_6_2_3_31=("-a always,exit -F arch=b64 -F path=/usr/bin/kmod -F perm=x -F auid>=$C6_UID -F auid!=unset -k kernel_modules")
rule audit-kmod-use "Audit kmod use"
check_audit_kmod_use() {
    local bad=0 f k
    c6_audit_check "${C6_R_6_2_3_31[@]}" || bad=1
    k=$(readlink -f /bin/kmod)
    for f in /usr/sbin/lsmod /usr/sbin/rmmod /usr/sbin/insmod /usr/sbin/modinfo /usr/sbin/modprobe /usr/sbin/depmod; do
        [ -e "$f" ] || [ -L "$f" ] || { ev "$f: missing"; bad=1; continue; }
        if [ "$(readlink -f "$f")" = "$k" ]; then ev "$f -> kmod"; else ev "$f -> $(readlink -f "$f") (not kmod)"; bad=1; fi
    done
    return $bad
}
fix_audit_kmod_use() { c6_audit_fix "${C6_R_6_2_3_31[@]}"; }

C6_R_6_2_3_32=(
    "-a always,exit -F arch=b32 -S init_module,finit_module -F auid>=$C6_UID -F auid!=unset -k kernel_modules"
    "-a always,exit -F arch=b64 -S init_module,finit_module -F auid>=$C6_UID -F auid!=unset -k kernel_modules"
)
rule audit-module-load-syscalls "Audit module load syscalls"
check_audit_module_load_syscalls() { c6_audit_check "${C6_R_6_2_3_32[@]}"; }
fix_audit_module_load_syscalls() { c6_audit_fix "${C6_R_6_2_3_32[@]}"; }

C6_R_6_2_3_33=(
    "-a always,exit -F arch=b32 -S delete_module -F auid>=$C6_UID -F auid!=unset -k kernel_modules"
    "-a always,exit -F arch=b64 -S delete_module -F auid>=$C6_UID -F auid!=unset -k kernel_modules"
)
rule audit-module-unload-syscall "Audit module unload syscall"
check_audit_module_unload_syscall() { c6_audit_check "${C6_R_6_2_3_33[@]}"; }
fix_audit_module_unload_syscall() { c6_audit_fix "${C6_R_6_2_3_33[@]}"; }

rule audit-rules-load-past-errors-c "Audit rules load past errors (-c)"
check_audit_rules_load_past_errors_c() {
    local l
    l=$(grep -Ph -- '^\h*-c\b' /etc/audit/rules.d/*.rules 2>/dev/null | tail -n 1 | xargs)
    ev "${l:-no -c in rules.d}"
    [ "$l" = "-c" ]
}
fix_audit_rules_load_past_errors_c() {
    [ -d /etc/audit/rules.d ] || { echo "auditd not installed"; return 1; }
    grep -Phq -- '^\h*-c\b' /etc/audit/rules.d/*.rules 2>/dev/null && return 0
    printf '%s\n' "-c" > "$C6_INIT_RULES"
    chown root:root "$C6_INIT_RULES"
    chmod 0640 "$C6_INIT_RULES"
}

rule audit-configuration-immutable "Audit configuration immutable"
check_audit_configuration_immutable() {
    local l e bad=0
    # augenrules keeps the last -e of all files (in its file order).
    l=$(ls -1v /etc/audit/rules.d/*.rules 2>/dev/null | while IFS= read -r f; do grep -Ph -- '^\h*-e\h+\d' "$f"; done | tail -n 1 | sed -E 's/^[[:space:]]+|[[:space:]]+$//g; s/[[:space:]]+/ /g')
    ev "rules.d last -e: ${l:-none}"
    [ "$l" = "-e 2" ] || bad=1
    e=$(auditctl -s 2>/dev/null | awk '$1 == "enabled" { print $2 }')
    ev "running: enabled ${e:-unknown}"
    [ "$e" = 2 ] || bad=1
    return $bad
}
fix_audit_configuration_immutable() {
    [ -d /etc/audit/rules.d ] || { echo "auditd not installed"; return 1; }
    local f
    # Another -e after ours would win: drop -e 0/1 lines elsewhere in rules.d.
    for f in /etc/audit/rules.d/*.rules; do
        [ -f "$f" ] && [ "$f" != "$C6_FINAL_RULES" ] || continue
        sed -i -E 's/^([[:space:]]*-e[[:space:]]+[01]\b)/# pvs-cis: \1/' "$f"
    done
    printf '%s\n' "-e 2" > "$C6_FINAL_RULES"
    chown root:root "$C6_FINAL_RULES"
    chmod 0640 "$C6_FINAL_RULES"
}

rule running-and-on-disk-audit-rules-agree "Running and on-disk audit rules agree"
check_running_and_on_disk_audit_rules_agree() {
    command -v augenrules >/dev/null 2>&1 || { ev "augenrules: not installed"; return 1; }
    local out
    out=$(augenrules --check 2>&1)
    ev "$out"
    grep -q 'No change' <<<"$out" && return 0
    return 3
}
fix_running_and_on_disk_audit_rules_agree() {
    command -v augenrules >/dev/null 2>&1 || { echo "augenrules not installed"; return 1; }
    if c6_audit_locked; then
        echo "audit rules locked (-e 2): they load at the next boot"
        augenrules >/dev/null 2>&1
        return 0
    fi
    augenrules --load
}

# ---- 6.2.4 audit file access ----

rule audit-log-files-0640-or-tighter "Audit log files 0640 or tighter"
check_audit_log_files_0640_or_tighter() {
    [ -f "$C6_AUDITD" ] || { ev "$C6_AUDITD: missing"; return 1; }
    local d bad
    d=$(c6_audit_logdir)
    [ -d "$d" ] || { ev "$d: missing"; return 1; }
    bad=$(find "$d" -maxdepth 1 -type f -perm /0137 -printf '%p %m\n' 2>/dev/null)
    if [ -n "$bad" ]; then ev "$bad"; return 1; fi
    ev "$d: all log files 0640 or tighter"
}
fix_audit_log_files_0640_or_tighter() {
    [ -f "$C6_AUDITD" ] || return 1
    find "$(c6_audit_logdir)" -type f -perm /0137 -exec chmod u-x,g-wx,o-rwx {} + 2>/dev/null
    return 0
}

rule audit-log-files-owned-by-root "Audit log files owned by root"
check_audit_log_files_owned_by_root() {
    [ -f "$C6_AUDITD" ] || { ev "$C6_AUDITD: missing"; return 1; }
    local d bad
    d=$(c6_audit_logdir)
    [ -d "$d" ] || { ev "$d: missing"; return 1; }
    bad=$(find "$d" -maxdepth 1 -type f ! -user root -printf '%p %u\n' 2>/dev/null)
    if [ -n "$bad" ]; then ev "$bad"; return 1; fi
    ev "$d: all log files owned by root"
}
fix_audit_log_files_owned_by_root() {
    [ -f "$C6_AUDITD" ] || return 1
    find "$(c6_audit_logdir)" -type f ! -user root -exec chown root {} + 2>/dev/null
    return 0
}

rule audit-log-files-group-adm-or-root "Audit log files group adm or root"
check_audit_log_files_group_adm_or_root() {
    [ -f "$C6_AUDITD" ] || { ev "$C6_AUDITD: missing"; return 1; }
    local d g bad=0 files
    g=$(grep -Piws -- '^\h*log_group\h*=\h*\H+\b' "$C6_AUDITD")
    ev "${g:-log_group not set (root)}"
    [ -n "$g" ] && ! grep -Piq 'adm' <<<"$g" && bad=1
    d=$(c6_audit_logdir)
    files=$(find -L "$d" -not -path "$d/lost+found" -type f \( ! -group root -a ! -group adm \) -printf '%p %g\n' 2>/dev/null)
    if [ -n "$files" ]; then ev "$files"; bad=1; else ev "$d: files group root/adm"; fi
    return $bad
}
fix_audit_log_files_group_adm_or_root() {
    [ -f "$C6_AUDITD" ] || return 1
    find "$(c6_audit_logdir)" -type f \( ! -group adm -a ! -group root \) -exec chgrp adm {} + 2>/dev/null
    if grep -Eq '^[[:space:]]*#?[[:space:]]*log_group[[:space:]]*=' "$C6_AUDITD"; then
        sed -ri 's/^\s*#?\s*log_group\s*=\s*\S+(\s*#.*)?.*$/log_group = adm\1/' "$C6_AUDITD"
    else
        printf 'log_group = adm\n' >> "$C6_AUDITD"
    fi
    c6_auditd_reload
}

rule audit-log-directory-0750-or-tighter "Audit log directory 0750 or tighter"
check_audit_log_directory_0750_or_tighter() {
    [ -f "$C6_AUDITD" ] || { ev "$C6_AUDITD: missing"; return 1; }
    local d m
    d=$(c6_audit_logdir)
    [ -d "$d" ] || { ev "$d: missing"; return 1; }
    m=$(stat -Lc '%a' "$d")
    ev "$d: $m"
    (( (8#$m & 8#0027) == 0 ))
}
fix_audit_log_directory_0750_or_tighter() {
    [ -f "$C6_AUDITD" ] || return 1
    chmod g-w,o-rwx "$(c6_audit_logdir)"
}

rule audit-config-files-0640-or-tighter "Audit config files 0640 or tighter"
check_audit_config_files_0640_or_tighter() {
    [ -d /etc/audit ] || { ev "/etc/audit: missing"; return 1; }
    local bad
    bad=$(find /etc/audit/ -type f \( -name '*.conf' -o -name '*.rules' \) -perm /0137 -printf '%p %m\n' 2>/dev/null)
    if [ -n "$bad" ]; then ev "$bad"; return 1; fi
    ev "/etc/audit: config files 0640 or tighter"
}
fix_audit_config_files_0640_or_tighter() {
    [ -d /etc/audit ] || return 1
    find /etc/audit/ -type f \( -name '*.conf' -o -name '*.rules' \) -exec chmod u-x,g-wx,o-rwx {} +
}

rule audit-config-files-owned-by-root "Audit config files owned by root"
check_audit_config_files_owned_by_root() {
    [ -d /etc/audit ] || { ev "/etc/audit: missing"; return 1; }
    local bad
    bad=$(find /etc/audit/ -type f \( -name '*.conf' -o -name '*.rules' \) ! -user root -printf '%p %u\n' 2>/dev/null)
    if [ -n "$bad" ]; then ev "$bad"; return 1; fi
    ev "/etc/audit: config files owned by root"
}
fix_audit_config_files_owned_by_root() {
    [ -d /etc/audit ] || return 1
    find /etc/audit/ -type f \( -name '*.conf' -o -name '*.rules' \) ! -user root -exec chown root {} +
}

rule audit-config-files-group-root "Audit config files group root"
check_audit_config_files_group_root() {
    [ -d /etc/audit ] || { ev "/etc/audit: missing"; return 1; }
    local bad
    bad=$(find /etc/audit/ -type f \( -name '*.conf' -o -name '*.rules' \) ! -group root -printf '%p %g\n' 2>/dev/null)
    if [ -n "$bad" ]; then ev "$bad"; return 1; fi
    ev "/etc/audit: config files group root"
}
fix_audit_config_files_group_root() {
    [ -d /etc/audit ] || return 1
    find /etc/audit/ -type f \( -name '*.conf' -o -name '*.rules' \) ! -group root -exec chgrp root {} +
}

rule audit-tools-0755-or-tighter "Audit tools 0755 or tighter"
check_audit_tools_0755_or_tighter() {
    local t m bad=0
    for t in $C6_AUDIT_TOOLS; do
        if [ ! -e "$t" ]; then ev "$t: missing"; bad=1; continue; fi
        m=$(stat -Lc '%a' "$t")
        ev "$t: $m"
        (( (8#$m & 8#0022) == 0 )) || bad=1
    done
    return $bad
}
fix_audit_tools_0755_or_tighter() {
    local t
    for t in $C6_AUDIT_TOOLS; do [ -e "$t" ] && chmod go-w "$t"; done
    return 0
}

rule audit-tools-owned-by-root "Audit tools owned by root"
check_audit_tools_owned_by_root() {
    local t o bad=0
    for t in $C6_AUDIT_TOOLS; do
        if [ ! -e "$t" ]; then ev "$t: missing"; bad=1; continue; fi
        o=$(stat -Lc '%U' "$t")
        ev "$t: $o"
        [ "$o" = root ] || bad=1
    done
    return $bad
}
fix_audit_tools_owned_by_root() {
    local t
    for t in $C6_AUDIT_TOOLS; do [ -e "$t" ] && chown root "$t"; done
    return 0
}

rule audit-tools-group-root "Audit tools group root"
check_audit_tools_group_root() {
    local t g bad=0
    for t in $C6_AUDIT_TOOLS; do
        if [ ! -e "$t" ]; then ev "$t: missing"; bad=1; continue; fi
        g=$(stat -Lc '%G' "$t")
        ev "$t: $g"
        [ "$g" = root ] || bad=1
    done
    return $bad
}
fix_audit_tools_group_root() {
    local t
    for t in $C6_AUDIT_TOOLS; do [ -e "$t" ] && chgrp root "$t"; done
    return 0
}

# ---- 6.3 integrity checking ----

c6_aide_db() {
    if [ -s /var/lib/aide/aide.db ]; then ev "aide database: present"; else ev "aide database: absent (built by aideinit on the clone's first boot)"; fi
}

rule aide-installed "AIDE installed"
check_aide_installed() {
    local p bad=0
    for p in aide aide-common; do
        if pkg_installed "$p"; then ev "$p: installed"; else ev "$p: not installed"; bad=1; fi
    done
    c6_aide_db
    return $bad
}
fix_aide_installed() {
    # Never build the database in the bake.
    echo "aide-common aide/aideinit boolean false" | debconf-set-selections 2>/dev/null
    pkg_install --no-install-recommends aide aide-common
}

rule daily-aide-check-scheduled "Daily AIDE check scheduled"
check_daily_aide_check_scheduled() {
    local t s a
    t=$(systemctl list-unit-files dailyaidecheck.timer --no-legend 2>/dev/null | awk '{ print $2 }')
    s=$(systemctl list-unit-files dailyaidecheck.service --no-legend 2>/dev/null | awk '{ print $2 }')
    a=$(systemctl is-active dailyaidecheck.timer 2>/dev/null)
    ev "dailyaidecheck.timer: ${t:-missing} / ${a:-inactive}"
    ev "dailyaidecheck.service: ${s:-missing}"
    c6_aide_db
    [ "$t" = enabled ] && [ "$a" = active ] && [[ "$s" =~ ^(static|enabled)$ ]]
}
fix_daily_aide_check_scheduled() {
    if ! svc_exists dailyaidecheck.timer; then
        # aide-common without its timer: our own, daily at 05:00.
        cat > /etc/systemd/system/dailyaidecheck.service <<'EOF'
[Unit]
Description=Daily AIDE file integrity check (pvs-cis)
ConditionPathExists=/var/lib/aide/aide.db

[Service]
Type=oneshot
ExecStart=/usr/bin/aide.wrapper --check
EOF
        cat > /etc/systemd/system/dailyaidecheck.timer <<'EOF'
[Unit]
Description=Daily AIDE file integrity check (pvs-cis)

[Timer]
OnCalendar=*-*-* 05:00:00
Persistent=true

[Install]
WantedBy=timers.target
EOF
        chmod 0644 /etc/systemd/system/dailyaidecheck.service /etc/systemd/system/dailyaidecheck.timer
        systemctl daemon-reload
    fi
    systemctl unmask dailyaidecheck.timer dailyaidecheck.service 2>/dev/null
    systemctl --now enable dailyaidecheck.timer 2>/dev/null
    svc_active dailyaidecheck.timer
}

C6_AIDE_ATTRS="p+i+n+u+g+s+b+acl+xattrs+sha512"
c6_aide_tools() {
    local t
    for t in auditctl auditd ausearch aureport augenrules; do echo "$(readlink -f /sbin)/$t"; done
}

rule aide-protects-audit-tools "AIDE protects audit tools"
check_aide_protects_audit_tools() {
    local aide conf t out item bad=0 miss
    aide=$(command -v aide)
    [ -n "$aide" ] || { ev "aide: not installed"; return 1; }
    conf=$(find -L /etc -type f -name aide.conf 2>/dev/null | head -n 1)
    [ -n "$conf" ] || { ev "aide.conf: not found"; return 1; }
    for t in $(c6_aide_tools); do
        [ -f "$t" ] || { ev "$t: missing"; continue; }
        out=$("$aide" --config "$conf" -p "f:$t" 2>/dev/null) || out=""
        if [ -z "$out" ]; then
            # aide could not evaluate the config: fall back to the selection line itself.
            out=$(grep -E "^[[:space:]]*${t//./\\.}[[:space:]]" "$conf" 2>/dev/null | tail -n 1)
            [ -n "$out" ] && ev "$t: aide -p failed, using the config line"
        fi
        miss=""
        for item in p i n u g s b acl xattrs sha512; do
            tr ' \t+' '\n\n\n' <<<"$out" | grep -qx -- "$item" || miss+=" $item"
        done
        if [ -n "$miss" ]; then ev "$t: missing$miss"; bad=1; else ev "$t: $C6_AIDE_ATTRS"; fi
    done
    return $bad
}
fix_aide_protects_audit_tools() {
    [ -f "$C6_AIDE_CONF" ] || { echo "$C6_AIDE_CONF missing"; return 1; }
    local t
    for t in $(c6_aide_tools); do
        sed -i -E "\\#^[[:space:]]*${t//./\\.}[[:space:]]#d" "$C6_AIDE_CONF"
    done
    grep -q '^# pvs-cis: audit tools' "$C6_AIDE_CONF" || printf '\n# pvs-cis: audit tools\n' >> "$C6_AIDE_CONF"
    for t in $(c6_aide_tools); do
        printf '%s %s\n' "$t" "$C6_AIDE_ATTRS" >> "$C6_AIDE_CONF"
    done
    return 0
}
