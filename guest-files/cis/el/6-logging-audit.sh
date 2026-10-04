# CIS AlmaLinux/Oracle/Rocky Linux 9 v3.0.0 and 10 v1.0.0 - chapter 6: logging, auditd, AIDE.
# Builds on deb/6-logging-audit.sh (sourced first): the rules that are the same on Enterprise
# Linux stay there; this file adds the EL-only rules and redefines what is Debian-specific.
#
# Decisions
# - Logger: EL9 = rsyslog (its benchmark covers rsyslog only; the rsyslog rule installs it if
#   the image lacks it). EL10 = rsyslog when the image ships it (kept), else journald alone.
#   With rsyslog the journald-only rules (journal-remote/upload, ForwardToSyslog off) are na;
#   with journald the rsyslog rules are na (deb's c6_rsyslog_used = package installed).
#   journald Compress/Storage (EL10) are set either way - harmless with rsyslog too.
# - journal-upload (EL10, journald only): the studio configures no central log host, so with
#   no URL the upload service cannot run: the rule fails until a URL is set (exception).
# - Kernel parameters audit=1 / audit_backlog_limit=8192: grubby on every boot entry, plus
#   GRUB_CMDLINE_LINUX in /etc/default/grub and /etc/kernel/cmdline (when present) so new
#   kernels and grub2-mkconfig keep them. Effective after the reboot.
# - Packages audit + audit-libs; AIDE package aide, config /etc/aide.conf.
# - Audit rules: deb's rule sets, plus what EL adds - execveat with execve, the b32 time
#   rules, /etc/sysconfig/network + NetworkManager/system-connections, SELinux policy dirs
#   (dir= watches; path= accepted too), query_module (EL10).
# - Audit log group root (log_group = root); EL has no use for adm.
# - /var/log: the EL9 table lets package-manager logs (dnf, hawkey) be 0644; EL10's does not
#   - the fix tightens them and runs dnf-makecache with UMask 0027 so new ones stay 0640.
# - AIDE: no database in the bake. The clone builds it on first boot: a drop-in turns
#   pvs-cis-aide-init.service into `aide --init` + move to /var/lib/aide/aide.db.gz.
#   Daily check: aidecheck.timer/.service (05:00, aide --check). Report also to syslog
#   (report_url=syslog:LOG_LOCAL0).

C6_AIDE_CONF=/etc/aide.conf
E6_AIDE_DB=/var/lib/aide/aide.db.gz
E6_EL=${VERSION_ID:-0}; E6_EL=${E6_EL%%.*}

# EL9: rsyslog is the logger, installed or not (its absence is a failure, not na).
c6_rsyslog_used() {
    [ "$E6_EL" = 9 ] && return 0
    pkg_installed rsyslog
}

# Which logger this system uses (EL10's single-logger choice).
e6_logger() { if c6_rsyslog_used; then echo rsyslog; else echo journald; fi; }

# ---- 6.1.1 / 6.2.1-6.2.2 journald ----

rule journald-forwards-to-rsyslog-if-rsyslog "journald forwards to rsyslog (if rsyslog)"
check_journald_forwards_to_rsyslog_if_rsyslog() {
    if ! c6_rsyslog_used; then ev "rsyslog not installed - journald is the logger"; return 2; fi
    local v bad=0
    v=$(c6_journald_get ForwardToSyslog)
    ev "journald ForwardToSyslog=${v:-unset}"
    [ "${v,,}" = yes ] || bad=1
    svc_active rsyslog.service && ev "rsyslog: active" || { ev "rsyslog: not active"; bad=1; }
    return $bad
}
fix_journald_forwards_to_rsyslog_if_rsyslog() {
    c6_rsyslog_used || return 0
    local f
    # One place only: other files that set it lose their line.
    for f in /etc/systemd/journald.conf /etc/systemd/journald.conf.d/*.conf; do
        [ -f "$f" ] && [ "$f" != "$C6_JOURNALD" ] || continue
        sed -i -E 's/^([[:space:]]*ForwardToSyslog[[:space:]]*=)/# pvs-cis: \1/I' "$f"
    done
    c6_journald_set ForwardToSyslog yes
    c6_journald_reload
}

rule one-logging-system "One logging system in use"
check_one_logging_system() {
    if pkg_installed rsyslog; then
        if svc_active rsyslog.service; then ev "rsyslog: installed and active - rsyslog is the logger"; return 0; fi
        ev "rsyslog: installed but not active"
        return 1
    fi
    if svc_active systemd-journald.service; then ev "rsyslog: not installed; journald active - journald is the logger"; return 0; fi
    ev "neither rsyslog nor journald active"
    return 1
}
fix_one_logging_system() {
    if pkg_installed rsyslog; then
        systemctl unmask rsyslog.service 2>/dev/null
        systemctl --now enable rsyslog.service 2>/dev/null
        svc_active rsyslog.service
    else
        systemctl unmask systemd-journald.service 2>/dev/null
        systemctl start systemd-journald.service 2>/dev/null
        svc_active systemd-journald.service
    fi
}

rule journal-remote-installed "systemd-journal-remote installed (journald)"
check_journal_remote_installed() {
    if c6_rsyslog_used; then ev "rsyslog is the logger"; return 2; fi
    if pkg_installed systemd-journal-remote; then ev "systemd-journal-remote: installed"; return 0; fi
    ev "systemd-journal-remote: not installed"
    return 1
}
fix_journal_remote_installed() {
    c6_rsyslog_used && return 0
    pkg_installed systemd-journal-remote || pkg_install systemd-journal-remote
}

# journal-upload.conf's [Upload] KEY=value lines, all files in systemd's order.
e6_upload_conf() {
    systemd-analyze cat-config systemd/journal-upload.conf 2>/dev/null | awk '
        /^[[:space:]]*\[/ { sec = ($0 ~ /^[[:space:]]*\[Upload\]/); next }
        sec && /^[[:space:]]*(URL|ServerKeyFile|ServerCertificateFile|TrustedCertificateFile)[[:space:]]*=/ { gsub(/[[:space:]]/, ""); print }'
}

rule journal-upload-auth-reviewed "journal-upload URL and certificates reviewed"
check_journal_upload_auth_reviewed() {
    if c6_rsyslog_used; then ev "rsyslog is the logger"; return 2; fi
    local c
    c=$(e6_upload_conf)
    ev "${c:-journal-upload: no URL or certificates configured}"
    ev "decision: no central log host configured by the studio"
    return 3
}

rule journal-upload-active "systemd-journal-upload enabled and active"
check_journal_upload_active() {
    if c6_rsyslog_used; then ev "rsyslog is the logger"; return 2; fi
    local e a bad=0
    grep -q '^URL=.' <<<"$(e6_upload_conf)" || { ev "journal-upload: no URL configured (no central log host)"; bad=1; }
    e=$(systemctl is-enabled systemd-journal-upload.service 2>/dev/null)
    a=$(systemctl is-active systemd-journal-upload.service 2>/dev/null)
    ev "systemd-journal-upload: ${e:-not-found} / ${a:-inactive}"
    [ "$e" = enabled ] && [ "$a" = active ] || bad=1
    return $bad
}
fix_journal_upload_active() {
    c6_rsyslog_used && return 0
    # Without a log host there is nothing to upload to: leave it for the site to configure.
    grep -q '^URL=.' <<<"$(e6_upload_conf)" || { echo "no journal-upload URL configured"; return 1; }
    systemctl unmask systemd-journal-upload.service 2>/dev/null
    systemctl --now enable systemd-journal-upload.service 2>/dev/null
    svc_active systemd-journal-upload.service
}

rule journald-forward-to-syslog-off "journald ForwardToSyslog off (journald)"
check_journald_forward_to_syslog_off() {
    if c6_rsyslog_used; then ev "rsyslog is the logger - forwarding wanted"; return 2; fi
    local v
    v=$(c6_journald_get ForwardToSyslog)
    [ -n "$v" ] || v=$(c6_journald_default ForwardToSyslog)
    ev "journald ForwardToSyslog=${v:-unset (default no)}"
    [ "${v,,}" != yes ]
}
fix_journald_forward_to_syslog_off() {
    c6_rsyslog_used && return 0
    c6_journald_set ForwardToSyslog no
    c6_journald_reload
}

# ---- 6.1.2 / 6.2.3 rsyslog ----

rule rsyslog-present-if-chosen "rsyslog installed (if the logger)"
check_rsyslog_present_if_chosen() {
    if pkg_installed rsyslog; then ev "rsyslog: installed"; return 0; fi
    if [ "$E6_EL" = 9 ]; then ev "rsyslog: not installed"; return 1; fi
    ev "rsyslog: not installed - journald is the logger"
    return 2
}
fix_rsyslog_present_if_chosen() {
    [ "$E6_EL" = 9 ] || return 0
    pkg_installed rsyslog || pkg_install rsyslog
}

rule rsyslog-creates-files-0640 "rsyslog creates files 0640"
check_rsyslog_creates_files_0640() {
    c6_rsyslog_used || { ev "rsyslog: not installed"; return 2; }
    local lines v bad=0
    lines=$(c6_rsyslog_grep '^\h*(\$FileCreateMode\h+|.*\bfileCreateMode\h*=\h*"?)0[0-7]{3}')
    if [ -z "$lines" ]; then ev "file creation mode: not set (default 0644)"; return 1; fi
    ev "$lines"
    while read -r v; do
        (( (8#$v & 8#0137) == 0 )) || bad=1
    done < <(grep -Pio '(\$FileCreateMode\h+|fileCreateMode\h*=\h*"?)\K0[0-7]{3}' <<<"$lines")
    return $bad
}
fix_rsyslog_creates_files_0640() {
    c6_rsyslog_used || return 0
    pkg_installed rsyslog || return 1
    local f v
    # Only the values that are too open (a stricter one stays).
    for f in $(c6_rsyslog_files); do
        while read -r v; do
            [ -n "$v" ] || continue
            (( (8#$v & 8#0137) == 0 )) && continue
            sed -i -E "s/^([[:space:]]*\\\$FileCreateMode[[:space:]]+)${v}\\b/\\10640/I; s/(fileCreateMode[[:space:]]*=[[:space:]]*\"?)${v}\\b/\\10640/I" "$f"
        done < <(grep -Pio '(\$FileCreateMode\h+|fileCreateMode\h*=\h*"?)\K0[0-7]{3}' "$f" 2>/dev/null | sort -u)
    done
    if [ -z "$(c6_rsyslog_grep '^\h*(\$FileCreateMode\h+|.*\bfileCreateMode\h*=\h*"?)0[0-7]{3}')" ]; then
        mkdir -p /etc/rsyslog.d
        printf '# pvs-cis: new log files 0640\n$FileCreateMode 0640\n' > /etc/rsyslog.d/00-pvs-cis.conf
        chown root:root /etc/rsyslog.d/00-pvs-cis.conf
        chmod 0640 /etc/rsyslog.d/00-pvs-cis.conf
    fi
    systemctl restart rsyslog.service 2>/dev/null
    return 0
}

rule rsyslog-conf-files-access "rsyslog config files 640 root:root"
check_rsyslog_conf_files_access() {
    c6_rsyslog_used || { ev "rsyslog: not installed"; return 2; }
    local bad
    [ -e /etc/rsyslog.conf ] || { ev "/etc/rsyslog.conf: missing"; return 1; }
    bad=$( { find /etc/rsyslog.conf -not -type l \( ! -user root -o ! -group root -o -perm /0137 \) -printf '%p %m %u:%g\n'
             find /etc/rsyslog.d/ -type f -name '*.conf' \( ! -user root -o ! -group root -o -perm /0137 \) -printf '%p %m %u:%g\n'; } 2>/dev/null)
    if [ -n "$bad" ]; then ev "$bad"; return 1; fi
    ev "/etc/rsyslog.conf, /etc/rsyslog.d/*.conf: 0640 or tighter, root:root"
}
fix_rsyslog_conf_files_access() {
    c6_rsyslog_used || return 0
    [ -e /etc/rsyslog.conf ] || return 0
    chown root:root /etc/rsyslog.conf && chmod u-x,g-wx,o-rwx /etc/rsyslog.conf
    [ -d /etc/rsyslog.d ] || return 0
    find /etc/rsyslog.d/ -type f -name '*.conf' -exec chown root:root {} + -exec chmod u-x,g-wx,o-rwx {} +
}

rule rsyslog-d-dir-access "/etc/rsyslog.d 755 root:root"
check_rsyslog_d_dir_access() {
    c6_rsyslog_used || { ev "rsyslog: not installed"; return 2; }
    [ -d /etc/rsyslog.d ] || { ev "/etc/rsyslog.d: missing"; return 2; }
    perm_ok /etc/rsyslog.d 0755 root root
}
fix_rsyslog_d_dir_access() {
    c6_rsyslog_used || return 0
    [ -d /etc/rsyslog.d ] || return 0
    chown root:root /etc/rsyslog.d && chmod g-w,o-w /etc/rsyslog.d
}

# rsyslog's work directory (the last one configured), default /var/lib/rsyslog.
e6_rsyslog_workdir() {
    local d
    d=$(c6_rsyslog_grep '^[^#]*workDirectory\h*[= ]' | grep -Pio 'workDirectory\h*[= ]\h*"?\K[^"\s)]+' | tail -n 1)
    echo "${d:-/var/lib/rsyslog}"
}

rule rsyslog-workdir-access "rsyslog work directory 700 root:root"
check_rsyslog_workdir_access() {
    c6_rsyslog_used || { ev "rsyslog: not installed"; return 2; }
    local d
    d=$(e6_rsyslog_workdir)
    [ -d "$d" ] || { ev "$d: missing"; return 2; }
    perm_ok "$d" 0700 root root
}
fix_rsyslog_workdir_access() {
    c6_rsyslog_used || return 0
    local d
    d=$(e6_rsyslog_workdir)
    [ -d "$d" ] || return 0
    chown root:root "$d" && chmod go-rwx "$d"
}

# Remote-input modules and listeners (log server configuration), both syntaxes.
E6_RSYSLOG_LISTEN='^\h*(module\(load="?im(tcp|udp|ptcp|relp)"?\)|input\(type="?im(tcp|udp|ptcp|relp)"?\b|\$ModLoad\h+im(tcp|udp|ptcp|relp)\b|\$(InputTCPServerRun|UDPServerRun|InputPTCPServerRun|InputRELPServerRun)\b)'

e6_rsyslog_listen_check() {
    c6_rsyslog_used || { ev "rsyslog: not installed"; return 2; }
    local hits
    hits=$(c6_rsyslog_grep "$E6_RSYSLOG_LISTEN")
    if [ -n "$hits" ]; then ev "$hits"; return 1; fi
    ev "no imtcp/imudp/imptcp/imrelp listener configured"
}
e6_rsyslog_listen_fix() {
    c6_rsyslog_used || return 0
    local f
    for f in $(c6_rsyslog_files); do
        sed -i -E 's/^([[:space:]]*(module\(load="?im(tcp|udp|ptcp|relp)"?\)|input\(type="?im(tcp|udp|ptcp|relp)"?|\$ModLoad[[:space:]]+im(tcp|udp|ptcp|relp)|\$(InputTCPServerRun|UDPServerRun|InputPTCPServerRun|InputRELPServerRun)))/# pvs-cis: \1/I' "$f"
    done
    systemctl restart rsyslog.service 2>/dev/null
    return 0
}

rule rsyslog-not-a-log-server "rsyslog not a log server"
check_rsyslog_not_a_log_server() { e6_rsyslog_listen_check; }
fix_rsyslog_not_a_log_server() { e6_rsyslog_listen_fix; }

check_rsyslog_does_not_accept_remote_logs() { e6_rsyslog_listen_check; }
fix_rsyslog_does_not_accept_remote_logs() { e6_rsyslog_listen_fix; }

check_rsyslog_selectors_reviewed() {
    c6_rsyslog_used || { ev "rsyslog: not installed"; return 2; }
    c6_rsyslog_grep '^\h*[a-z*][^#$(]*\h+[-:/]' | head -n 15
    ev "logs: $(find /var/log -maxdepth 1 -type f -newermt '-1 day' 2>/dev/null | wc -l) files written in the last day"
    ev "decision: the distribution's default rsyslog selectors kept"
    return 3
}

rule rsyslog-tls-driver-installed "rsyslog TLS driver installed"
check_rsyslog_tls_driver_installed() {
    c6_rsyslog_used || { ev "rsyslog: not installed"; return 2; }
    local p
    for p in rsyslog-gnutls rsyslog-openssl; do
        if pkg_installed "$p"; then ev "$p: installed"; return 0; fi
    done
    ev "rsyslog-gnutls, rsyslog-openssl: not installed"
    return 1
}
fix_rsyslog_tls_driver_installed() {
    c6_rsyslog_used || return 0
    pkg_installed rsyslog-gnutls || pkg_installed rsyslog-openssl || pkg_install rsyslog-gnutls
}

# Forwarding over TLS: driver gtls/ossl, mode 1, an auth mode and port 6514 all configured.
check_rsyslog_forwarding_over_tls() {
    c6_rsyslog_used || { ev "rsyslog: not installed"; return 2; }
    if [ -z "$(c6_rsyslog_fwd)" ]; then ev "no remote forwarding configured"; return 2; fi
    local bad=0 re n
    for re in '^[^#]*(StreamDriver|DefaultNetstreamDriver)(\.Name)?\s*[= ]\s*"?(gtls|ossl)"?' \
              '^[^#]*(StreamDriverMode\s*=\s*"?1"?|ActionSendStreamDriverMode\s+1)' \
              '^[^#]*(StreamDriverAuthMode\s*=\s*"?(x509/name|x509/certvalid|x509/fingerprint|anon)"?|ActionSendStreamDriverAuthMode\s+(x509/name|x509/certvalid|x509/fingerprint|anon))' \
              '^[^#]*(port\s*=\s*"?6514"?|:6514)'; do
        n=$(c6_rsyslog_grep "$re" | head -n 1)
        if [ -n "$n" ]; then ev "$n"; else ev "missing: $re"; bad=1; fi
    done
    return $bad
}

rule rsyslog-tls-client-cert-reviewed "rsyslog TLS client certificate reviewed"
check_rsyslog_tls_client_cert_reviewed() {
    c6_rsyslog_used || { ev "rsyslog: not installed"; return 2; }
    if [ -z "$(c6_rsyslog_fwd)" ]; then ev "no remote forwarding configured"; return 2; fi
    local hits
    hits=$(c6_rsyslog_grep '(DefaultNetstreamDriver(Cert|Key)File|StreamDriver\.(Cert|Key)File)\h*[= ]')
    ev "${hits:-no client certificate or key configured}"
    ev "decision: no central log host configured by the studio"
    return 3
}

# ---- 6.1.3 / 6.2.4 log files ----

# deb's scan with the EL9 package-manager class (dnf/hawkey/yum logs may stay 0644).
c6_logfiles() {
    local fix=${1:-0} file mode user group name mask rperm aus agr shell bad=0 n=0 out=()
    while IFS= read -r -d '' file; do
        read -r mode user group < <(stat -Lc '%a %U %G' "$file" 2>/dev/null) || continue
        name=${file##*/}
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
                if [ "$E6_EL" = 9 ] && [[ "$name" =~ ^(dnf\..*|dnf5\.log.*|hawkey\.log.*|yum\.log.*)$ ]] && [ "${file%/*}" = /var/log ]; then
                    mask=0133 rperm=u-x,go-wx aus=root agr='root|adm'
                else
                    shell=$(awk -F: -v u="$user" '$1 == u { print $7 }' /etc/passwd)
                    if [ "$user" = root ] || [ -z "$shell" ] || ! grep -qxF -- "$shell" <(sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//' /etc/shells); then
                        [[ "$user" =~ ^($aus)$ ]] || aus="$aus|$user"
                        [[ "$group" =~ ^($agr)$ ]] || agr="$agr|$group"
                    fi
                fi ;;
        esac
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

fix_log_files_in_var_log_restricted() {
    local f u
    for f in /etc/logrotate.d/*; do
        [ -f "$f" ] || continue
        sed -i -E 's/^([[:space:]]*create[[:space:]]+)0?644([[:space:]])/\10640\2/' "$f"
    done
    c6_logfiles 1 >/dev/null
    # dnf's own log rotation on clones (makecache timer) creates files with the unit's umask.
    for u in dnf-makecache.service; do
        mkdir -p "/etc/systemd/system/$u.d"
        printf '[Service]\nUMask=0027\n' > "/etc/systemd/system/$u.d/50-pvs-cis-umask.conf"
        chmod 0644 "/etc/systemd/system/$u.d/50-pvs-cis-umask.conf"
    done
    systemctl daemon-reload 2>/dev/null
    return 0
}

# ---- 6.2.1 / 6.3.1 auditd ----

rule auditd-installed "audit packages installed"
# audit 4 (EL10) moved augenrules and /etc/audit/rules.d into audit-rules.
e6_audit_pkgs() { if [ "$E6_EL" -ge 10 ]; then echo audit audit-libs audit-rules; else echo audit audit-libs; fi; }
check_auditd_installed() {
    local p bad=0
    for p in $(e6_audit_pkgs); do
        if pkg_installed "$p"; then ev "$p: installed"; else ev "$p: not installed"; bad=1; fi
    done
    return $bad
}
fix_auditd_installed() {
    local p
    for p in $(e6_audit_pkgs); do
        pkg_installed "$p" || pkg_install "$p" || return 1
    done
}

# Every grubby boot entry and GRUB_CMDLINE_LINUX carry the kernel parameter (PCRE).
e6_kargs_has() {
    local re=$1 what=$2 args n miss bad=0
    ev "running: $(grep -oE "(^| )${what}[^ ]*" /proc/cmdline 2>/dev/null | xargs || true)"
    command -v grubby >/dev/null 2>&1 || { ev "grubby: not installed"; return 1; }
    args=$(grubby --info=ALL 2>/dev/null | sed -n 's/^args=//p')
    n=$(grep -c . <<<"$args")
    if [ "$n" -eq 0 ]; then ev "grubby: no boot entries"; return 1; fi
    miss=$(grep -Pvc -- "\\b$re\\b" <<<"$args")
    if [ "$miss" -gt 0 ]; then ev "grubby: $miss of $n entries without $what"; bad=1; else ev "grubby: all $n entries have $what"; fi
    if grep -Psq -- "^\\h*GRUB_CMDLINE_LINUX=\"([^#\\n\\r]+\\h+)?$re\\b" /etc/default/grub; then
        ev "/etc/default/grub: GRUB_CMDLINE_LINUX has $what"
    else
        ev "/etc/default/grub: GRUB_CMDLINE_LINUX without $what"; bad=1
    fi
    return $bad
}

# KEY=VALUE on every boot entry, in GRUB_CMDLINE_LINUX and in /etc/kernel/cmdline; an
# older value of KEY is replaced. Effective at the next boot.
e6_kargs_set() {
    local p=$1 k=${1%%=*}
    command -v grubby >/dev/null 2>&1 || { echo "grubby not installed"; return 1; }
    grubby --update-kernel=ALL --args="$p" || return 1
    touch /etc/default/grub
    if grep -Eq '^[[:space:]]*GRUB_CMDLINE_LINUX=' /etc/default/grub; then
        sed -i -E "/^[[:space:]]*GRUB_CMDLINE_LINUX=/{s/([\" ])${k}=[^\" ]*/\\1/g; s/^([[:space:]]*GRUB_CMDLINE_LINUX=\")(.*)\"[[:space:]]*\$/\\1\\2 ${p}\"/; s/=\" +/=\"/; s/ {2,}/ /g}" /etc/default/grub
    else
        printf 'GRUB_CMDLINE_LINUX="%s"\n' "$p" >> /etc/default/grub
    fi
    if [ -f /etc/kernel/cmdline ]; then
        sed -i -E "s/(^| )${k}=[^ ]*//g; s/[[:space:]]*\$/ ${p}/; s/^ +//; s/ {2,}/ /g" /etc/kernel/cmdline
    fi
    return 0
}

check_audit_early_boot_processes_audit_1() { e6_kargs_has 'audit=1' audit=; }
fix_audit_early_boot_processes_audit_1() { e6_kargs_set audit=1; }

check_audit_backlog_limit_on_cmdline() { e6_kargs_has 'audit_backlog_limit=\d+' audit_backlog_limit=; }
fix_audit_backlog_limit_on_cmdline() {
    # A value already configured stays; the benchmark's example otherwise.
    local cur
    cur=$(grubby --info=DEFAULT 2>/dev/null | grep -oE 'audit_backlog_limit=[0-9]+' | head -n 1)
    e6_kargs_set "${cur:-audit_backlog_limit=8192}"
}

# auditd.conf values are case-insensitive (EL ships SUSPEND, ROTATE, SYSLOG).
c6_auditd_is() {
    local k=$1 alt=$2 v
    if [ ! -f "$C6_AUDITD" ]; then ev "$C6_AUDITD: missing"; return 1; fi
    v=$(kv_get "$C6_AUDITD" "$k")
    ev "$k = ${v:-unset}"
    v=${v%% *}
    [[ "${v,,}" =~ ^($alt)$ ]]
}

# ---- 6.2.3 / 6.3.3 audit rules (EL rule sets) ----

C6_R_6_2_3_2=(
    "-a always,exit -F arch=b32 -C euid!=uid -F auid!=unset -S execve,execveat -k user_emulation"
    "-a always,exit -F arch=b64 -C euid!=uid -F auid!=unset -S execve,execveat -k user_emulation"
)

C6_R_6_2_3_4=(
    "-a always,exit -F arch=b64 -S adjtimex,settimeofday -k time-change"
    "-a always,exit -F arch=b32 -S adjtimex,settimeofday -k time-change"
    "-a always,exit -F arch=b64 -S clock_settime -F a0=0x0 -k time-change"
    "-a always,exit -F arch=b32 -S clock_settime -F a0=0x0 -k time-change"
    "-a always,exit -F arch=b64 -F path=/etc/localtime -F perm=wa -k time-change"
)

E6_R_NET=(
    "-a always,exit -F arch=b64 -F path=/etc/sysconfig/network -F perm=wa -k system-locale"
    "-a always,exit -F arch=b64 -F dir=/etc/NetworkManager/system-connections -F perm=wa -k system-locale"
)
rule audit-el-network-config-changes "Audit sysconfig/network and NM connection changes"
check_audit_el_network_config_changes() { c6_audit_check "${E6_R_NET[@]}"; }
fix_audit_el_network_config_changes() { c6_audit_fix "${E6_R_NET[@]}"; }

# A directory watched with dir= (preferred, recursive) or path=: one of them on disk and
# running is enough.
e6_watch_check() {
    local key=$1 t out out2 bad=0
    shift
    for t in "$@"; do
        if out=$(c6_audit_check "-a always,exit -F arch=b64 -F dir=$t -F perm=wa -k $key"); then
            printf '%s\n' "$out"; continue
        fi
        if out2=$(c6_audit_check "-a always,exit -F arch=b64 -F path=$t -F perm=wa -k $key"); then
            printf '%s\n' "$out2"; continue
        fi
        printf '%s\n' "$out"
        bad=1
    done
    return $bad
}

E6_MAC_DIRS="/etc/selinux /usr/share/selinux /var/lib/selinux"
rule audit-apparmor-policy-changes "Audit SELinux policy changes"
check_audit_apparmor_policy_changes() {
    # shellcheck disable=SC2086
    e6_watch_check MAC-policy $E6_MAC_DIRS
}
fix_audit_apparmor_policy_changes() {
    local t r=()
    for t in $E6_MAC_DIRS; do
        # Already watched with path=: leave it.
        c6_audit_check "-a always,exit -F arch=b64 -F path=$t -F perm=wa -k MAC-policy" >/dev/null 2>&1 && continue
        r+=("-a always,exit -F arch=b64 -F dir=$t -F perm=wa -k MAC-policy")
    done
    [ ${#r[@]} -eq 0 ] || c6_audit_fix "${r[@]}"
}

E6_R_QUERY_MODULE=("-a always,exit -F arch=b64 -S query_module -F auid>=$C6_UID -F auid!=unset -k kernel_modules")
rule audit-query-module-syscall "Audit query_module syscall"
check_audit_query_module_syscall() {
    if ! ausyscall x86_64 query_module >/dev/null 2>&1; then ev "query_module: unknown to auditctl here"; return 1; fi
    c6_audit_check "${E6_R_QUERY_MODULE[@]}"
}
fix_audit_query_module_syscall() {
    ausyscall x86_64 query_module >/dev/null 2>&1 || { echo "query_module unknown to auditctl"; return 1; }
    c6_audit_fix "${E6_R_QUERY_MODULE[@]}"
}

# ---- 6.2.4 / 6.3.4 audit file access ----

rule audit-log-files-group-adm-or-root "Audit log files group root (or adm)"
check_audit_log_files_group_adm_or_root() {
    [ -f "$C6_AUDITD" ] || { ev "$C6_AUDITD: missing"; return 1; }
    local d g bad=0 files
    g=$(awk -F= '/^[[:space:]]*log_group[[:space:]]*=/ { print $2 }' "$C6_AUDITD" | xargs)
    ev "log_group = ${g:-unset (root)}"
    [ -z "$g" ] || [[ "$g" =~ ^(root|adm)$ ]] || bad=1
    d=$(c6_audit_logdir)
    files=$(find -L "$d" -maxdepth 1 -type f \( ! -group root -a ! -group adm \) -printf '%p %g\n' 2>/dev/null)
    if [ -n "$files" ]; then ev "$files"; bad=1; else ev "$d: files group root/adm"; fi
    return $bad
}
fix_audit_log_files_group_adm_or_root() {
    [ -f "$C6_AUDITD" ] || return 1
    find "$(c6_audit_logdir)" -maxdepth 1 -type f \( ! -group adm -a ! -group root \) -exec chgrp root {} + 2>/dev/null
    local g
    g=$(awk -F= '/^[[:space:]]*log_group[[:space:]]*=/ { print $2 }' "$C6_AUDITD" | xargs)
    if [ -z "$g" ] || ! [[ "$g" =~ ^(root|adm)$ ]]; then
        c6_auditd_set log_group root
        c6_auditd_reload
    fi
    return 0
}

# EL ships autrace with the other audit tools.
C6_AUDIT_TOOLS="/sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/auditd /sbin/augenrules"
[ -e /sbin/autrace ] && C6_AUDIT_TOOLS="$C6_AUDIT_TOOLS /sbin/autrace"

# ---- 6.3 / 6.1 AIDE ----

c6_aide_db() {
    if [ -s "$E6_AIDE_DB" ]; then ev "aide database: present"; else ev "aide database: absent (built by aide --init on the clone's first boot)"; fi
}

c6_aide_tools() {
    local t d
    d=$(readlink -f /sbin)
    for t in auditctl auditd ausearch aureport autrace augenrules; do
        [ "$t" = autrace ] && [ ! -e "$d/$t" ] && continue
        echo "$d/$t"
    done
}

E6_AIDE_DROPIN=/etc/systemd/system/pvs-cis-aide-init.service.d/50-pvs-cis-el.conf

rule aide-installed "AIDE installed"
check_aide_installed() {
    local bad=0
    if pkg_installed aide; then ev "aide: installed"; else ev "aide: not installed"; bad=1; fi
    c6_aide_db
    return $bad
}
fix_aide_installed() {
    pkg_installed aide || pkg_install aide || return 1
    # The clone's first boot builds the database (EL: aide --init, then the new db in place).
    mkdir -p "${E6_AIDE_DROPIN%/*}"
    cat > "$E6_AIDE_DROPIN" <<EOF
# pvs-cis: Enterprise Linux has no aideinit
[Unit]
ConditionPathExists=
ConditionPathExists=!$E6_AIDE_DB
ConditionPathExists=/usr/sbin/aide

[Service]
ExecStart=
ExecStart=/usr/sbin/aide --init
ExecStart=/bin/mv -f /var/lib/aide/aide.db.new.gz $E6_AIDE_DB
EOF
    chmod 0644 "$E6_AIDE_DROPIN"
    systemctl daemon-reload 2>/dev/null
    return 0
}

# A periodic aide --check/--update: from cron, or from an enabled/active timer.
check_daily_aide_check_scheduled() {
    local cron t en ac s found=""
    cron=$(grep -rEis 'aide[[:space:]]+(--check|--update|-C|-u)\b' /var/spool/cron/ /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null)
    [ -n "$cron" ] && { ev "$cron"; found=1; }
    for t in $(systemctl list-unit-files --type=timer --no-legend 2>/dev/null | awk '{ print $1 }'); do
        en=$(systemctl is-enabled "$t" 2>/dev/null)
        ac=$(systemctl is-active "$t" 2>/dev/null)
        [ "$en" = enabled ] || [ "$ac" = active ] || continue
        s=$(systemctl show -p Unit --value "$t" 2>/dev/null)
        [ -n "$s" ] || s=${t%.timer}.service
        if systemctl cat "$s" 2>/dev/null | grep -Eq 'ExecStart=.*aide[[:space:]]+(--check|--update)'; then
            ev "$t ($en/$ac) -> $s"
            found=1
        fi
    done
    [ -n "$found" ] || ev "no scheduled aide check (cron or timer)"
    c6_aide_db
    [ -n "$found" ]
}
fix_daily_aide_check_scheduled() {
    cat > /etc/systemd/system/aidecheck.service <<EOF
[Unit]
Description=AIDE file integrity check (pvs-cis)
ConditionPathExists=$E6_AIDE_DB

[Service]
Type=oneshot
Nice=19
IOSchedulingClass=idle
ExecStart=/usr/sbin/aide --check
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

# aide.conf and the files it includes (@@include / @@x_include of a file or a directory).
e6_aide_conf_files() {
    local inc d
    [ -f "$C6_AIDE_CONF" ] || return 0
    echo "$C6_AIDE_CONF"
    while read -r inc d; do
        if [ -d "$inc" ]; then find "$inc" -maxdepth 1 -type f 2>/dev/null; elif [ -f "$inc" ]; then echo "$inc"; fi
    done < <(sed -n -E 's/^[[:space:]]*@@x?_?include[[:space:]]+([^[:space:]]+)([[:space:]]+(.*))?$/\1 \3/p' "$C6_AIDE_CONF")
}

rule aide-report-url-reviewed "AIDE report goes to syslog"
check_aide_report_url_reviewed() {
    [ -f "$C6_AIDE_CONF" ] || { ev "$C6_AIDE_CONF: missing"; return 1; }
    local hits
    # shellcheck disable=SC2046
    hits=$(grep -Phs '^\h*report_url\h*=' $(e6_aide_conf_files))
    ev "${hits:-no report_url configured}"
    grep -Pq '^\h*report_url\h*=\h*syslog:' <<<"$hits"
}
fix_aide_report_url_reviewed() {
    [ -f "$C6_AIDE_CONF" ] || { echo "$C6_AIDE_CONF missing"; return 1; }
    grep -Pq '^\h*report_url\h*=\h*syslog:' "$C6_AIDE_CONF" && return 0
    printf '\n# pvs-cis: integrity reports also to the system log\nreport_url=syslog:LOG_LOCAL0\n' >> "$C6_AIDE_CONF"
}
