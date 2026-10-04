# suse/6-logging-audit.sh - openSUSE Leap 16.0 (CIS SLE 16): what differs from deb/ and el/. Sourced after both.
#
# Decisions
# - Logger: journald (Leap has no rsyslog; nothing installs it). The rsyslog rules stay na;
#   the TLS module, if rsyslog ever comes, is SUSE's rsyslog-module-gtls (or -ossl).
# - Audit package: `audit` (SUSE has no audit-libs; libaudit1 comes with it). augenrules and
#   rules.d are what auditd.service loads (ExecStartPost augenrules --load).
#   auditd.conf: when the package keeps it only under /usr, the whole vendor copy goes to /etc
#   before the first edit.
# - Kernel parameters audit=1 / audit_backlog_limit (a value already set stays, else 8192):
#   GRUB_CMDLINE_LINUX in /etc/default/grub (never _DEFAULT, which holds SELinux's
#   parameters), then grub2-mkconfig into a temporary file. The new grub.cfg replaces the old
#   one only when it has boot entries and all of them carry the parameter; otherwise the
#   existing grub.cfg's linux lines get the parameter (the next regeneration - kernel update -
#   keeps it via GRUB_CMDLINE_LINUX). No package script is touched.
# - Audit rules: deb/el's sets (b32 lines kept), plus create_module/query_module (6.2.3.32)
#   and /usr/lib/pam.d next to /etc/pam.d (Leap's vendor PAM files live there).
# - Audit log group: root (SLE allows root or audit, not adm); log_group must be set.
# - AIDE: /usr/bin/aide, config /etc/aide.conf, database uncompressed (database_in /
#   database_out from aide.conf, default /var/lib/aide/aide.db and aide.db.new). The bake
#   builds none: the clone's pvs-cis-aide-init.service (drop-in) runs aide --init and moves
#   the new database in place. Daily check: aidecheck.timer/.service at 05:00.

S6_GRUB_DEFAULT=/etc/default/grub
S6_GRUB_CFG=/boot/grub2/grub.cfg
S6_AIDE_DROPIN=/etc/systemd/system/pvs-cis-aide-init.service.d/50-pvs-cis-suse.conf

# ---- 6.1.2 rsyslog TLS (SUSE package names) ----

check_rsyslog_tls_module_present() {
    c6_rsyslog_used || { ev "rsyslog: not installed"; return 2; }
    local p
    for p in rsyslog-module-gtls rsyslog-module-ossl; do
        if pkg_installed "$p"; then ev "$p: installed"; return 0; fi
    done
    ev "rsyslog-module-gtls, rsyslog-module-ossl: not installed"
    return 1
}
fix_rsyslog_tls_module_present() {
    c6_rsyslog_used || return 0
    pkg_installed rsyslog-module-gtls || pkg_installed rsyslog-module-ossl || pkg_install rsyslog-module-gtls
}

# ---- 6.2.1 auditd ----

check_auditd_installed() {
    local bad=0
    if pkg_installed audit; then ev "audit: installed"; else ev "audit: not installed"; bad=1; fi
    if command -v augenrules >/dev/null 2>&1; then ev "augenrules: $(command -v augenrules)"; else ev "augenrules: missing"; fi
    return $bad
}
fix_auditd_installed() {
    pkg_installed audit || pkg_install audit || return 1
    # augenrules in a subpackage on some builds: best effort, the rules rules need it.
    command -v augenrules >/dev/null 2>&1 || pkg_install audit-rules >/dev/null 2>&1
    vendor_copy "$C6_AUDITD"
    return 0
}

# auditd.conf: the vendor copy in /etc before the first edit.
c6_auditd_set() {
    vendor_copy "$C6_AUDITD"
    [ -f "$C6_AUDITD" ] || { echo "$C6_AUDITD missing"; return 1; }
    kv_set "$C6_AUDITD" "$1" "$2" " = "
}

# GRUB_CMDLINE_LINUX's value (unquoted) from /etc/default/grub.
s6_cmdline_linux() {
    sed -n -E 's/^[[:space:]]*GRUB_CMDLINE_LINUX=["'\'']?([^"'\'']*)["'\'']?[[:space:]]*$/\1/p' "$S6_GRUB_DEFAULT" 2>/dev/null | tail -n 1
}
s6_cmdline_default() {
    sed -n -E 's/^[[:space:]]*GRUB_CMDLINE_LINUX_DEFAULT=["'\'']?([^"'\'']*)["'\'']?[[:space:]]*$/\1/p' "$S6_GRUB_DEFAULT" 2>/dev/null | tail -n 1
}

# RE (PCRE, e.g. 'audit=1') in GRUB_CMDLINE_LINUX and on every linux line of grub.cfg; WHAT
# (e.g. 'audit=') names it in the evidence. A different WHAT value in _DEFAULT (read after
# GRUB_CMDLINE_LINUX on the kernel line, so it would win) fails.
s6_kargs_has() {
    local re=$1 what=$2 v d bad=0
    v=$(s6_cmdline_linux)
    if grep -Pq -- "(^|\\h)$re(\\h|\$)" <<<"$v"; then
        ev "$S6_GRUB_DEFAULT: GRUB_CMDLINE_LINUX has $(grep -oE "(^| )${what}[^ ]*" <<<"$v" | xargs)"
    else
        ev "$S6_GRUB_DEFAULT: GRUB_CMDLINE_LINUX=\"$v\" without $what"; bad=1
    fi
    d=$(s6_cmdline_default)
    if grep -Eq "(^| )${what}" <<<"$d" && ! grep -Pq -- "(^|\\h)$re(\\h|\$)" <<<"$d"; then
        ev "$S6_GRUB_DEFAULT: GRUB_CMDLINE_LINUX_DEFAULT overrides: $(grep -oE "(^| )${what}[^ ]*" <<<"$d" | xargs)"; bad=1
    fi
    c6_grub_has "\\b$re\\b" "$what" || bad=1
    return $bad
}

# Linux lines of a grub.cfg all match RE, and there is at least one.
s6_cfg_ok() {
    local f=$1 re=$2 lines
    lines=$(grep -P '^\h*linux(efi)?\h' "$f" 2>/dev/null)
    [ -n "$lines" ] || return 1
    ! grep -Pvq -- "\\b$re\\b" <<<"$lines"
}

# KEY=VALUE into GRUB_CMDLINE_LINUX (an older KEY= value replaced), then grub.cfg.
s6_kargs_set() {
    local p=$1 k=${1%%=*} re=$2 tmp
    [ -f "$S6_GRUB_DEFAULT" ] || { echo "$S6_GRUB_DEFAULT missing"; return 1; }
    cp -a "$S6_GRUB_DEFAULT" "$S6_GRUB_DEFAULT.pvs-cis.tmp"
    if grep -Eq '^[[:space:]]*GRUB_CMDLINE_LINUX=' "$S6_GRUB_DEFAULT"; then
        sed -i -E "/^[[:space:]]*GRUB_CMDLINE_LINUX=/{s/([\"' ])${k}=[^\"' ]*/\\1/g; s/^([[:space:]]*GRUB_CMDLINE_LINUX=)([\"'])(.*)[\"'][[:space:]]*\$/\\1\\2\\3 ${p}\\2/; s/^([[:space:]]*GRUB_CMDLINE_LINUX=)\$/\\1\"${p}\"/; s/=([\"']) +/=\\1/; s/ {2,}/ /g}" "$S6_GRUB_DEFAULT"
    else
        printf 'GRUB_CMDLINE_LINUX="%s"\n' "$p" >> "$S6_GRUB_DEFAULT"
    fi
    if ! grep -Pq -- "(^|\\h)$re(\\h|\$)" <<<"$(s6_cmdline_linux)"; then
        mv -f "$S6_GRUB_DEFAULT.pvs-cis.tmp" "$S6_GRUB_DEFAULT"
        echo "GRUB_CMDLINE_LINUX edit did not take: restored"
        return 1
    fi
    rm -f "$S6_GRUB_DEFAULT.pvs-cis.tmp"
    [ -f "$S6_GRUB_CFG" ] || { echo "$S6_GRUB_CFG missing"; return 1; }
    s6_cfg_ok "$S6_GRUB_CFG" "$re" && return 0
    cp -a "$S6_GRUB_CFG" "$S6_GRUB_CFG.pvs-cis.bak"
    tmp=$(mktemp "${S6_GRUB_CFG%/*}/.grub.cfg.pvs-cis.XXXXXX") || return 1
    if command -v grub2-mkconfig >/dev/null 2>&1 && grub2-mkconfig -o "$tmp" >/dev/null 2>&1 && s6_cfg_ok "$tmp" "$re"; then
        # Same file (inode, SELinux label), new content.
        cat "$tmp" > "$S6_GRUB_CFG"
        rm -f "$tmp"
        echo "grub.cfg regenerated by grub2-mkconfig"
        return 0
    fi
    echo "grub2-mkconfig gave no usable grub.cfg (no entries or no $k=): the parameter goes onto the existing linux lines"
    # Lines that have KEY= keep their value; the others get KEY=VALUE at the end.
    sed -E "/^[[:space:]]*linux(efi)?[[:space:]]/{/[[:space:]]${k}=/!s/[[:space:]]*\$/ ${p}/}" "$S6_GRUB_CFG" > "$tmp"
    if s6_cfg_ok "$tmp" "$re"; then
        cat "$tmp" > "$S6_GRUB_CFG"
        rm -f "$tmp"
        return 0
    fi
    rm -f "$tmp"
    echo "grub.cfg left unchanged (no linux entries)"
    return 1
}

check_audit_early_boot_processes_audit_1() { s6_kargs_has 'audit=1' audit=; }
fix_audit_early_boot_processes_audit_1() { s6_kargs_set audit=1 'audit=1'; }

check_audit_backlog_limit_on_cmdline() { s6_kargs_has 'audit_backlog_limit=\d+' audit_backlog_limit=; }
fix_audit_backlog_limit_on_cmdline() {
    # A value already configured (or running) stays; the benchmark's example otherwise.
    local cur
    cur=$(grep -oE '(^| )audit_backlog_limit=[0-9]+' <<<"$(s6_cmdline_linux)" | tail -n 1 | xargs)
    [ -n "$cur" ] || cur=$(grep -oE '(^| )audit_backlog_limit=[0-9]+' /proc/cmdline 2>/dev/null | tail -n 1 | xargs)
    s6_kargs_set "${cur:-audit_backlog_limit=8192}" 'audit_backlog_limit=\d+'
}

# ---- 6.2.3 audit rules ----

# PAM: /etc/pam.d and the vendor files in /usr/lib/pam.d.
C6_R_6_2_3_17=(
    "-a always,exit -F arch=b64 -F path=/etc/pam.conf -F perm=wa -k identity"
    "-a always,exit -F arch=b64 -F dir=/etc/pam.d -F perm=wa -k identity"
    "-a always,exit -F arch=b64 -F dir=/usr/lib/pam.d -F perm=wa -k identity"
)

S6_R_CREATE_QUERY_MODULE=("-a always,exit -F arch=b64 -S create_module,query_module -F auid>=$C6_UID -F auid!=unset -k kernel_modules")
rule audit-create-query-module-syscalls "Audit create_module/query_module syscalls"
check_audit_create_query_module_syscalls() {
    local s
    for s in create_module query_module; do
        ausyscall x86_64 "$s" >/dev/null 2>&1 || { ev "$s: unknown to ausyscall here"; return 1; }
    done
    c6_audit_check "${S6_R_CREATE_QUERY_MODULE[@]}"
}
fix_audit_create_query_module_syscalls() {
    local s
    for s in create_module query_module; do
        ausyscall x86_64 "$s" >/dev/null 2>&1 || { echo "$s unknown to ausyscall"; return 1; }
    done
    c6_audit_fix "${S6_R_CREATE_QUERY_MODULE[@]}"
}

# ---- 6.2.4 audit file access ----

s6_log_group() { awk -F= '/^[[:space:]]*log_group[[:space:]]*=/ { print $2 }' "$C6_AUDITD" 2>/dev/null | tail -n 1 | xargs; }

rule audit-log-files-group-adm-or-root "Audit log files group root (or audit)"
check_audit_log_files_group_adm_or_root() {
    [ -f "$C6_AUDITD" ] || { ev "$C6_AUDITD: missing"; return 1; }
    local d g dg bad=0 files
    g=$(s6_log_group)
    ev "log_group = ${g:-unset}"
    [[ "$g" =~ ^(root|audit)$ ]] || bad=1
    d=$(c6_audit_logdir)
    [ -d "$d" ] || { ev "$d: missing"; return 1; }
    dg=$(stat -Lc '%G' "$d")
    ev "$d: group $dg"
    [[ "$dg" =~ ^(root|audit)$ ]] || bad=1
    files=$(find -L "$d" -maxdepth 1 -type f \( ! -group root -a ! -group audit \) -printf '%p %g\n' 2>/dev/null)
    if [ -n "$files" ]; then ev "$files"; bad=1; else ev "$d: files group root/audit"; fi
    return $bad
}
fix_audit_log_files_group_adm_or_root() {
    vendor_copy "$C6_AUDITD"
    [ -f "$C6_AUDITD" ] || return 1
    local d g
    d=$(c6_audit_logdir)
    if [ -d "$d" ]; then
        find "$d" -type f \( ! -group root -a ! -group audit \) -exec chgrp root {} + 2>/dev/null
        [[ "$(stat -Lc '%G' "$d")" =~ ^(root|audit)$ ]] || chgrp root "$d"
    fi
    g=$(s6_log_group)
    if ! [[ "$g" =~ ^(root|audit)$ ]]; then
        c6_auditd_set log_group root
        c6_auditd_reload
    fi
    return 0
}

# ---- 6.3 AIDE ----

# aide.conf's database path for KEY (database_in / database_out), @@{VAR} defines expanded.
s6_aide_dbpath() {
    local key=$1 conf v
    conf=$(effective_file "$C6_AIDE_CONF")
    [ -f "$conf" ] && v=$(awk -v k="$key" '
        /^[[:space:]]*@@define[[:space:]]/ { def[$2] = $3; next }
        $0 ~ "^[[:space:]]*" k "[[:space:]]*=" { sub(/^[^=]*=[[:space:]]*/, ""); sub(/[[:space:]].*$/, ""); val = $0 }
        END { for (d in def) gsub("@@\\{" d "\\}", def[d], val); print val }' "$conf")
    v=${v#file:}
    case $key in
        database_in) echo "${v:-/var/lib/aide/aide.db}" ;;
        *) echo "${v:-/var/lib/aide/aide.db.new}" ;;
    esac
}

c6_aide_db() {
    local db
    db=$(s6_aide_dbpath database_in)
    if [ -s "$db" ]; then ev "aide database: $db present"; else ev "aide database: $db absent (built by aide --init on the clone's first boot)"; fi
}

s6_aide_bin() { command -v aide 2>/dev/null || echo /usr/bin/aide; }

check_aide_installed() {
    local bad=0
    if pkg_installed aide; then ev "aide: installed ($(s6_aide_bin))"; else ev "aide: not installed"; bad=1; fi
    c6_aide_db
    return $bad
}
fix_aide_installed() {
    pkg_installed aide || pkg_install aide || return 1
    vendor_copy "$C6_AIDE_CONF"
    local aide db new
    aide=$(s6_aide_bin)
    db=$(s6_aide_dbpath database_in)
    new=$(s6_aide_dbpath database_out)
    # The clone's first boot builds the database (SUSE: aide --init, then the new db in place).
    mkdir -p "${S6_AIDE_DROPIN%/*}"
    cat > "$S6_AIDE_DROPIN" <<EOF
# pvs-cis: SUSE has no aideinit; aide in /usr/bin, database uncompressed
[Unit]
ConditionPathExists=
ConditionPathExists=!$db
ConditionPathExists=$aide

[Service]
ExecStart=
ExecStart=$aide --init
ExecStart=/usr/bin/mv -f $new $db
EOF
    chmod 0644 "$S6_AIDE_DROPIN"
    rm -f /etc/systemd/system/pvs-cis-aide-init.service.d/50-pvs-cis-el.conf
    systemctl daemon-reload 2>/dev/null
    return 0
}

fix_daily_aide_check_scheduled() {
    local aide db
    aide=$(s6_aide_bin)
    db=$(s6_aide_dbpath database_in)
    cat > /etc/systemd/system/aidecheck.service <<EOF
[Unit]
Description=AIDE file integrity check (pvs-cis)
ConditionPathExists=$db

[Service]
Type=oneshot
Nice=19
IOSchedulingClass=idle
ExecStart=$aide --check
EOF
    cat > /etc/systemd/system/aidecheck.timer <<'EOF'
[Unit]
Description=Daily AIDE file integrity check (pvs-cis)

[Timer]
OnCalendar=*-*-* 05:00:00
Persistent=true
Unit=aidecheck.service

[Install]
WantedBy=timers.target
EOF
    chown root:root /etc/systemd/system/aidecheck.service /etc/systemd/system/aidecheck.timer
    chmod 0644 /etc/systemd/system/aidecheck.service /etc/systemd/system/aidecheck.timer
    systemctl daemon-reload
    systemctl unmask aidecheck.timer aidecheck.service 2>/dev/null
    systemctl --now enable aidecheck.timer 2>/dev/null
    svc_active aidecheck.timer
}

fix_aide_protects_audit_tools() {
    vendor_copy "$C6_AIDE_CONF"
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

# 6.3.3 on Leap: the attributes aide itself applies to each tool (`aide -p`, its "selective
# rule: '<path> (none) <attrs>'" line), not the config text. Leap's aide is built without
# xattrs (`aide --version`: "xattrs: no") and drops it with a warning; then xattrs counts
# when the config line asks for it - there is nothing more the system can do.
check_aide_protects_audit_tools() {
    local aide conf t out rule line item bad=0 miss noxattrs=0
    aide=$(command -v aide)
    [ -n "$aide" ] || { ev "aide: not installed"; return 1; }
    conf=$(effective_file /etc/aide.conf)
    [ -f "$conf" ] || { ev "aide.conf: not found"; return 1; }
    "$aide" --version 2>&1 | grep -Eq '^\s*xattrs:\s*no' && noxattrs=1
    for t in $(c6_aide_tools); do
        [ -f "$t" ] || { ev "$t: missing"; continue; }
        out=$("$aide" --config "$conf" -p "f:$t" 2>/dev/null) || true
        rule=$(sed -nE "s/.*selective rule: '[^']*\(none\) ([^']*)'.*/\1/p" <<<"$out" | head -n 1)
        line=$(grep -E "^[[:space:]]*${t//./\\.}[[:space:]]" "$conf" | tail -n 1)
        miss=""
        for item in p i n u g s b acl xattrs sha512; do
            tr '+' '\n' <<<"$rule" | grep -qx -- "$item" && continue
            if [ "$item" = xattrs ] && [ "$noxattrs" = 1 ] && tr ' \t+' '\n\n\n' <<<"$line" | grep -qx xattrs; then continue; fi
            miss+=" $item"
        done
        if [ -n "$miss" ]; then
            ev "$t: missing$miss (aide applies: ${rule:-nothing})"
            bad=1
        else
            ev "$t: ${rule}$([ "$noxattrs" = 1 ] && echo ' (xattrs in aide.conf; this aide is built without it)')"
        fi
    done
    return $bad
}
