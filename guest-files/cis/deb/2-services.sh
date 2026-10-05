# CIS Ubuntu 26.04 chapter 2 - services, clients, time sync, job schedulers.
# shellcheck shell=bash
#
# Decisions
# - 2.1.x servers: purge the package (apt-get purge, simulated first). If the simulation would
#   remove a protected package (sshd, cloud-init, qemu-guest-agent, systemd, netplan, ufw,
#   sudo, snapd, unattended-upgrades, kernel/grub, ...), the purge is refused and the units are
#   stopped + masked instead (the benchmark's "required as a dependency" branch).
# - If a purge takes an ubuntu-* metapackage with it, that metapackage's installed deps are
#   marked manual first, so a later autoremove cannot gut the system. Never autoremove.
# - 2.1.13 rsync: purged like every other server package. The benchmark accepts "installed but
#   not in use" only when another installed package needs it; nothing in the image does, and
#   the bake copies with tar.
# - "installed, units off" passes only when an installed package depends on it (the evidence
#   names it); an installed server package nothing needs is a fail, whatever its units say.
# - 2.1.3 kea: every installed package named kea* counts (the benchmark matches on "kea").
# - 2.1.22 MTA: none in the cloud image. Fix handles postfix (loopback-only) and exim4
#   (127.0.0.1 ; ::1); sendmail is only checked.
# - 2.1.23 manual: lists listening sockets, returns review. Studio decision: sshd on 22 only,
#   plus loopback-only resolver/time daemons.
# - 2.2.x clients: purge only (no service to mask), same protected-package guard.
# - 2.3 time: systemd-timesyncd (benchmark allows either). 2.3.1.1's fix installs
#   systemd-timesyncd and purges chrony (Ubuntu 25.10+ images ship chrony by default - this
#   swap is expected). Server = ${PVS_CIS_NTP:-ntp.ubuntu.com} as NTP= in
#   /etc/systemd/timesyncd.conf.d/60-pvs-cis.conf; FallbackNTP left at the compiled default.
# - 2.3.3.x chrony: checks only (n/a when chrony is absent or timesyncd is the one in use);
#   no fix - chrony is removed by 2.3.1.1.
# - 2.4.1.x cron: n/a when no cron(d).service. Missing cron.hourly/daily/weekly/monthly/d are
#   created 0700; a missing cron.yearly passes (the benchmark says so) and is not created.
# - 2.4.1.9 / 2.4.2.1: empty /etc/cron.allow and /etc/at.allow are created -> only root may use
#   crontab/at. Admin users run them through sudo. at: n/a unless the package is installed.

c2_PROTECT='(openssh-server|openssh-client|openssh-sftp-server|cloud-init|cloud-guest-utils|qemu-guest-agent|systemd|systemd-sysv|systemd-timesyncd|systemd-resolved|udev|dbus|netplan\.io|netplan-generator|ufw|sudo|sudo-rs|snapd|unattended-upgrades|apt|dpkg|libc6|e2fsprogs|lvm2|cron|linux-image-.*|linux-generic.*|linux-virtual.*|linux-kvm.*|grub-.*|shim-signed|initramfs-tools.*|ubuntu-minimal)'

# The installed ones of the packages given.
c2_installed() {
    local p out=""
    for p in "$@"; do
        pkg_installed "$p" && out="$out $p"
    done
    echo "${out# }"
}

# apt-get ARGS... after a simulation: refuses when a protected package would be removed, and
# pins the deps of any ubuntu-* metapackage it would remove (apt-mark manual).
c2_apt() {
    local sim rm bad m deps
    sim=$(apt-get -s "$@" 2>&1) || { printf '%s\n' "$sim" | tail -n 3; return 1; }
    rm=$(awk '/^(Remv|Purg) / { sub(/:.*/, "", $2); print $2 }' <<<"$sim" | sort -u)
    bad=$(grep -Ex "$c2_PROTECT" <<<"$rm" | xargs)
    if [ -n "$bad" ]; then
        echo "refused: apt-get $* would remove $bad"
        return 1
    fi
    for m in $(grep -E '^ubuntu-' <<<"$rm"); do
        deps=$(apt-cache depends --installed "$m" 2>/dev/null \
            | awk '$1 ~ /^\|?(PreDepends|Depends|Recommends):$/ && $2 !~ /^</ { print $2 }' | sort -u)
        deps=$(comm -23 <(printf '%s\n' "$deps" | sed '/^$/d') <(printf '%s\n' "$rm" | sed '/^$/d') | xargs)
        # shellcheck disable=SC2086
        [ -n "$deps" ] && apt-mark manual $deps >/dev/null 2>&1
    done
    DEBIAN_FRONTEND=noninteractive apt-get -y -q -o Dpkg::Options::=--force-confold "$@" >/dev/null
}

c2_unit_line() {
    local u=$1 st act
    st=$(systemctl is-enabled "$u" 2>/dev/null | head -n 1)
    act=$(systemctl is-active "$u" 2>/dev/null | head -n 1)
    echo "$u: ${st:-none}, ${act:-none}"
}

# The installed packages that depend on PKG (Depends/PreDepends), empty when none.
c2_needed_by() {
    apt-cache rdepends --installed --no-recommends --no-suggests --no-enhances --no-conflicts \
        --no-breaks --no-replaces "$1" 2>/dev/null | awk 'NR > 2 { gsub(/^[ |]+/, ""); print }' | sort -u | xargs
}

# Pass when no package of PKGS is installed, or when (UNITS given) each installed one is needed
# by another installed package and none of UNITS is enabled or active - the benchmark's
# "required as a dependency" branch, and only that.
c2_off_check() {
    local pkgs=$1 units=${2:-} inst u st bad=0 p need
    # shellcheck disable=SC2086
    inst=$(c2_installed $pkgs)
    if [ -z "$inst" ]; then
        ev "not installed: $pkgs"
        return 0
    fi
    ev "installed: $inst"
    [ -n "$units" ] || return 1
    for p in $inst; do
        need=$(c2_needed_by "$p")
        if [ -n "$need" ]; then
            ev "$p needed by: $need"
        else
            ev "$p: no installed package needs it - it should be removed"
            bad=1
        fi
    done
    for u in $units; do
        ev "$(c2_unit_line "$u")"
        st=$(systemctl is-enabled "$u" 2>/dev/null | head -n 1)
        case $st in enabled*) bad=1 ;; esac
        systemctl is-active --quiet "$u" 2>/dev/null && bad=1
    done
    return $bad
}

# Stop UNITS and purge the installed PKGS; when the purge is refused, mask UNITS instead.
c2_off_fix() {
    local pkgs=$1 units=${2:-} inst
    # shellcheck disable=SC2086
    inst=$(c2_installed $pkgs)
    [ -n "$inst" ] || return 0
    # shellcheck disable=SC2086
    [ -n "$units" ] && systemctl stop $units 2>/dev/null
    # shellcheck disable=SC2086
    c2_apt purge $inst && return 0
    [ -n "$units" ] || return 1
    # shellcheck disable=SC2086
    svc_off $units
}

# ---- 2.1 server services ----

rule autofs-removed "autofs removed"
check_autofs_removed() { c2_off_check autofs autofs.service; }
fix_autofs_removed() { c2_off_fix autofs autofs.service; }

rule avahi-daemon-removed "avahi daemon removed"
check_avahi_daemon_removed() { c2_off_check avahi-daemon "avahi-daemon.socket avahi-daemon.service"; }
fix_avahi_daemon_removed() { c2_off_fix avahi-daemon "avahi-daemon.socket avahi-daemon.service"; }

c2_KEA_UNITS="kea-dhcp-ddns-server.service kea-dhcp4-server.service kea-dhcp6-server.service"
c2_kea_pkgs() { dpkg-query -W -f='${Package} ${db:Status-Status}\n' 'kea*' 2>/dev/null | awk '$2 == "installed" { print $1 }' | xargs; }

rule dhcp-server-kea-removed "DHCP server (kea) removed"
check_dhcp_server_kea_removed() {
    local p
    p=$(c2_kea_pkgs)
    [ -n "$p" ] || { ev "not installed: kea*"; return 0; }
    c2_off_check "$p" "$c2_KEA_UNITS"
}
fix_dhcp_server_kea_removed() {
    local p
    p=$(c2_kea_pkgs)
    [ -n "$p" ] || return 0
    c2_off_fix "$p" "$c2_KEA_UNITS"
}

rule dns-server-bind9-removed "DNS server (bind9) removed"
check_dns_server_bind9_removed() { c2_off_check bind9 named.service; }
fix_dns_server_bind9_removed() { c2_off_fix bind9 named.service; }

rule dnsmasq-removed "dnsmasq removed"
check_dnsmasq_removed() { c2_off_check dnsmasq dnsmasq.service; }
fix_dnsmasq_removed() { c2_off_fix dnsmasq dnsmasq.service; }

rule ftp-server-vsftpd-removed "FTP server (vsftpd) removed"
check_ftp_server_vsftpd_removed() { c2_off_check vsftpd vsftpd.service; }
fix_ftp_server_vsftpd_removed() { c2_off_fix vsftpd vsftpd.service; }

rule ldap-server-slapd-removed "LDAP server (slapd) removed"
check_ldap_server_slapd_removed() { c2_off_check slapd slapd.service; }
fix_ldap_server_slapd_removed() { c2_off_fix slapd slapd.service; }

rule imap-pop3-server-dovecot-removed "IMAP/POP3 server (dovecot) removed"
check_imap_pop3_server_dovecot_removed() { c2_off_check "dovecot-imapd dovecot-pop3d" "dovecot.socket dovecot.service"; }
fix_imap_pop3_server_dovecot_removed() { c2_off_fix "dovecot-imapd dovecot-pop3d" "dovecot.socket dovecot.service"; }

rule nfs-server-removed "NFS server removed"
check_nfs_server_removed() { c2_off_check nfs-kernel-server nfs-server.service; }
fix_nfs_server_removed() { c2_off_fix nfs-kernel-server nfs-server.service; }

rule nis-server-ypserv-removed "NIS server (ypserv) removed"
check_nis_server_ypserv_removed() { c2_off_check ypserv ypserv.service; }
fix_nis_server_ypserv_removed() { c2_off_fix ypserv ypserv.service; }

rule print-server-cups-removed "print server (cups) removed"
check_print_server_cups_removed() { c2_off_check cups "cups.socket cups.service"; }
fix_print_server_cups_removed() { c2_off_fix cups "cups.socket cups.service"; }

rule rpcbind-removed "rpcbind removed"
check_rpcbind_removed() { c2_off_check rpcbind "rpcbind.socket rpcbind.service"; }
fix_rpcbind_removed() { c2_off_fix rpcbind "rpcbind.socket rpcbind.service"; }

rule rsync-removed "rsync removed"
check_rsync_removed() { c2_off_check rsync rsync.service; }
fix_rsync_removed() { c2_off_fix rsync rsync.service; }

rule samba-removed "samba removed"
check_samba_removed() { c2_off_check samba smbd.service; }
fix_samba_removed() { c2_off_fix samba smbd.service; }

rule snmp-daemon-removed "SNMP daemon removed"
check_snmp_daemon_removed() { c2_off_check snmpd snmpd.service; }
fix_snmp_daemon_removed() { c2_off_fix snmpd snmpd.service; }

rule telnet-server-removed "telnet server removed"
check_telnet_server_removed() { c2_off_check "telnetd telnetd-ssl" inetutils-inetd.service; }
fix_telnet_server_removed() { c2_off_fix "telnetd telnetd-ssl" inetutils-inetd.service; }

rule tftp-server-removed "TFTP server removed"
check_tftp_server_removed() { c2_off_check tftpd-hpa tftpd-hpa.service; }
fix_tftp_server_removed() { c2_off_fix tftpd-hpa tftpd-hpa.service; }

rule web-proxy-squid-removed "web proxy (squid) removed"
check_web_proxy_squid_removed() { c2_off_check squid squid.service; }
fix_web_proxy_squid_removed() { c2_off_fix squid squid.service; }

rule web-servers-apache2-nginx-removed "web servers (apache2, nginx) removed"
check_web_servers_apache2_nginx_removed() {
    local bad=0
    c2_off_check apache2 "apache2.socket apache2.service" || bad=1
    c2_off_check nginx nginx.service || bad=1
    return $bad
}
fix_web_servers_apache2_nginx_removed() {
    c2_off_fix apache2 "apache2.socket apache2.service" || return 1
    c2_off_fix nginx nginx.service
}

rule xinetd-removed "xinetd removed"
check_xinetd_removed() { c2_off_check xinetd xinetd.service; }
fix_xinetd_removed() { c2_off_fix xinetd xinetd.service; }

rule x-server-removed "X server removed"
check_x_server_removed() { c2_off_check xserver-common; }
fix_x_server_removed() { c2_off_fix xserver-common; }

rule mta-listens-on-loopback-only "MTA listens on loopback only"
check_mta_listens_on_loopback_only() {
    local bad=0 port l ifs=""
    for port in 25 465 587; do
        l=$(ss -Hlntu 2>/dev/null | awk -v p="$port" '{ n = split($5, a, ":"); if (a[n] == p) print $5 }' \
            | grep -Ev '^(127\.0\.0\.1|\[?::1\]?|\[::ffff:127\.0\.0\.1\]):' | xargs)
        if [ -n "$l" ]; then ev "port $port: listening on $l"; bad=1; else ev "port $port: no non-loopback listener"; fi
    done
    if command -v postconf >/dev/null 2>&1; then
        ifs=$(postconf -h inet_interfaces 2>/dev/null)
        ev "postfix inet_interfaces: ${ifs:-unset}"
    elif command -v exim >/dev/null 2>&1; then
        ifs=$(exim -bP local_interfaces 2>/dev/null)
        ev "exim ${ifs:-local_interfaces unset}"
    elif command -v sendmail >/dev/null 2>&1 && [ -f /etc/mail/sendmail.cf ]; then
        ifs=$(grep -i '^O DaemonPortOptions=' /etc/mail/sendmail.cf | grep -oP '(?<=Addr=)[^,+]+' | grep -v '^127\.0\.0\.1$' | xargs)
        ev "sendmail non-loopback Addr: ${ifs:-none}"
    else
        ev "MTA: none"
        return $bad
    fi
    if [ -n "$ifs" ]; then
        if grep -Eqi '\ball\b' <<<"$ifs"; then
            bad=1
        elif ! grep -Eqi '(0\.0\.0\.0|::1|127\.0\.0\.1|loopback-only|localhost)' <<<"$ifs"; then
            bad=1
        fi
    fi
    return $bad
}
fix_mta_listens_on_loopback_only() {
    local f=/etc/exim4/update-exim4.conf.conf
    if command -v postconf >/dev/null 2>&1; then
        postconf -e 'inet_interfaces = loopback-only' || return 1
        systemctl is-active --quiet postfix 2>/dev/null && systemctl restart postfix
    fi
    if [ -f "$f" ]; then
        kv_set "$f" dc_local_interfaces "'127.0.0.1 ; ::1'" =
        command -v update-exim4.conf >/dev/null 2>&1 && update-exim4.conf
        systemctl is-active --quiet exim4 2>/dev/null && systemctl restart exim4
    fi
    return 0
}

rule listening-services-reviewed "listening services reviewed"
check_listening_services_reviewed() {
    ss -Hplntu 2>/dev/null | awk '{ p = $7; sub(/^users:\(\("/, "", p); sub(/".*/, "", p); print $1, $5, p }' | sort -u
    ev "decision: only sshd (22/tcp) expected on a non-loopback address; resolver and time daemons loopback-only"
    return 3
}

# ---- 2.2 clients ----

rule nis-client-removed "NIS client removed"
check_nis_client_removed() { c2_off_check nis; }
fix_nis_client_removed() { c2_off_fix nis; }

rule rsh-client-removed "rsh client removed"
check_rsh_client_removed() { c2_off_check rsh-client; }
fix_rsh_client_removed() { c2_off_fix rsh-client; }

rule talk-client-removed "talk client removed"
check_talk_client_removed() { c2_off_check talk; }
fix_talk_client_removed() { c2_off_fix talk; }

rule telnet-clients-removed "telnet clients removed"
check_telnet_clients_removed() { c2_off_check "telnet inetutils-telnet telnet-ssl"; }
fix_telnet_clients_removed() { c2_off_fix "telnet inetutils-telnet telnet-ssl"; }

rule ldap-client-tools-removed "LDAP client tools removed"
check_ldap_client_tools_removed() { c2_off_check ldap-utils; }
fix_ldap_client_tools_removed() { c2_off_fix ldap-utils; }

rule ftp-clients-removed "FTP clients removed"
check_ftp_clients_removed() { c2_off_check "ftp tnftp atftp inetutils-ftp ftp-ssl"; }
# ubuntu-standard depends on "ftp | tnftp | ftp-ssl": purging the installed one makes apt
# install the next. All of them in one purge, so apt drops the metapackage instead (c2_apt
# keeps its other dependencies).
fix_ftp_clients_removed() {
    [ -n "$(c2_installed ftp tnftp atftp inetutils-ftp ftp-ssl)" ] || return 0
    c2_apt purge ftp tnftp atftp inetutils-ftp ftp-ssl
}

# ---- 2.3 time synchronization ----

# Enabled (any enabled* state) or active.
c2_inuse() {
    case $(systemctl is-enabled "$1" 2>/dev/null | head -n 1) in enabled*) return 0 ;; esac
    systemctl is-active --quiet "$1" 2>/dev/null
}

# n/a for the timesyncd section when chrony is the daemon in use.
c2_tsd_na() {
    if ! c2_inuse systemd-timesyncd.service && c2_inuse chrony.service; then
        ev "chrony in use, systemd-timesyncd not"
        return 0
    fi
    return 1
}

# n/a for the chrony section when chrony is absent or timesyncd is the daemon in use.
c2_chrony_na() {
    if ! pkg_installed chrony; then ev "chrony: not installed"; return 0; fi
    if ! c2_inuse chrony.service && c2_inuse systemd-timesyncd.service; then
        ev "systemd-timesyncd in use, chrony not"
        return 0
    fi
    return 1
}

rule exactly-one-time-sync-daemon "exactly one time sync daemon"
check_exactly_one_time_sync_daemon() {
    local n=0
    ev "$(c2_unit_line systemd-timesyncd.service)"
    ev "$(c2_unit_line chrony.service)"
    c2_inuse systemd-timesyncd.service && n=$((n + 1))
    c2_inuse chrony.service && n=$((n + 1))
    [ "$n" -eq 1 ]
}
fix_exactly_one_time_sync_daemon() {
    local args=()
    pkg_installed systemd-timesyncd || args+=(systemd-timesyncd)
    pkg_installed chrony && args+=(chrony-)
    if [ "${#args[@]}" -gt 0 ]; then
        c2_apt install --purge "${args[@]}" || return 1
    fi
    systemctl unmask systemd-timesyncd.service 2>/dev/null
    systemctl enable --now systemd-timesyncd.service >/dev/null 2>&1
    c2_inuse systemd-timesyncd.service
}

rule timesyncd-time-server-set "timesyncd: time server set"
check_timesyncd_time_server_set() {
    local cfg ntp fb
    c2_tsd_na && return 2
    cfg=$(systemd-analyze cat-config systemd/timesyncd.conf 2>/dev/null)
    ntp=$(grep -E '^[[:space:]]*NTP=' <<<"$cfg" | tail -n 1 | cut -d= -f2- | sed 's/#.*//' | xargs)
    fb=$(grep -E '^[[:space:]]*FallbackNTP=' <<<"$cfg" | tail -n 1 | cut -d= -f2- | sed 's/#.*//' | xargs)
    ev "NTP=${ntp}"
    ev "FallbackNTP=${fb:-<compiled default>}"
    [ -n "$ntp" ] || [ -n "$fb" ]
}
fix_timesyncd_time_server_set() {
    local srv d=/etc/systemd/timesyncd.conf.d
    srv=$(printf '%s' "${PVS_CIS_NTP:-ntp.ubuntu.com}" | tr -cd 'A-Za-z0-9.:_ -' | xargs)
    [ -n "$srv" ] || srv=ntp.ubuntu.com
    mkdir -p "$d"
    printf '# pvs-cis: authorized time server(s)\n[Time]\nNTP=%s\n' "$srv" > "$d/60-pvs-cis.conf"
    chmod 0644 "$d/60-pvs-cis.conf"
    systemctl reload-or-restart systemd-timesyncd.service 2>/dev/null
    return 0
}

rule timesyncd-enabled-and-running "timesyncd enabled and running"
check_timesyncd_enabled_and_running() {
    c2_tsd_na && return 2
    ev "$(c2_unit_line systemd-timesyncd.service)"
    [ "$(systemctl is-enabled systemd-timesyncd.service 2>/dev/null)" = enabled ] \
        && systemctl is-active --quiet systemd-timesyncd.service
}
fix_timesyncd_enabled_and_running() {
    c2_tsd_na && return 0
    systemctl unmask systemd-timesyncd.service 2>/dev/null
    systemctl enable --now systemd-timesyncd.service >/dev/null 2>&1
}

rule chrony-time-server-set "chrony: time server set"
check_chrony_time_server_set() {
    local files=() f d hits=""
    c2_chrony_na && return 2
    [ -f /etc/chrony/chrony.conf ] && files+=(/etc/chrony/chrony.conf)
    for d in $(awk '$1 ~ /^(confdir|sourcedir)$/ { for (i = 2; i <= NF; i++) print $i }' /etc/chrony/chrony.conf 2>/dev/null); do
        for f in "$d"/*.conf "$d"/*.sources; do
            [ -f "$f" ] && files+=("$f")
        done
    done
    [ "${#files[@]}" -gt 0 ] || { ev "chrony: no configuration files"; return 1; }
    hits=$(grep -HEi '^[[:space:]]*(server|pool)[[:space:]:]+[^[:space:]]' "${files[@]}" 2>/dev/null)
    if [ -n "$hits" ]; then ev "$hits"; return 0; fi
    ev "chrony: no server/pool line in ${files[*]}"
    return 1
}

rule chrony-runs-as-chrony "chrony runs as _chrony"
check_chrony_runs_as_chrony() {
    local procs
    c2_chrony_na && return 2
    procs=$(ps -eo user:32=,comm= 2>/dev/null | awk '$2 == "chronyd" { print $1 }' | sort -u | xargs)
    ev "chronyd users: ${procs:-not running}"
    [ -z "$(tr ' ' '\n' <<<"$procs" | grep -vx '_chrony' | grep .)" ]
}

rule chrony-enabled-and-running "chrony enabled and running"
check_chrony_enabled_and_running() {
    c2_chrony_na && return 2
    ev "$(c2_unit_line chrony.service)"
    [ "$(systemctl is-enabled chrony.service 2>/dev/null)" = enabled ] && systemctl is-active --quiet chrony.service
}

# ---- 2.4 job schedulers ----

c2_cron_unit() { systemctl list-unit-files --no-legend 2>/dev/null | awk '$1 ~ /^crond?\.service$/ { print $1; exit }'; }

# rc 2 (with evidence) when cron is not installed.
c2_need_cron() {
    [ -n "$(c2_cron_unit)" ] && return 0
    ev "cron: not installed"
    return 2
}

rule cron-enabled-and-active "cron enabled and active"
check_cron_enabled_and_active() {
    local u
    c2_need_cron || return
    u=$(c2_cron_unit)
    ev "$(c2_unit_line "$u")"
    [ "$(systemctl is-enabled "$u" 2>/dev/null)" = enabled ] && systemctl is-active --quiet "$u"
}
fix_cron_enabled_and_active() {
    local u
    u=$(c2_cron_unit)
    [ -n "$u" ] || return 0
    systemctl unmask "$u" 2>/dev/null
    systemctl enable --now "$u" >/dev/null 2>&1
}

rule etc-crontab-root-only "/etc/crontab root-only"
check_etc_crontab_root_only() { c2_need_cron || return; perm_ok /etc/crontab 600 root root; }
fix_etc_crontab_root_only() { [ -n "$(c2_cron_unit)" ] || return 0; perm_set /etc/crontab 600 root root; }

# A cron directory: 0700 root:root. OPT=1: a missing directory passes and is not created.
c2_crondir_check() {
    c2_need_cron || return
    if [ ! -e "$1" ] && [ "${2:-0}" = 1 ]; then ev "$1: absent"; return 0; fi
    perm_ok "$1" 700 root root
}
c2_crondir_fix() {
    [ -n "$(c2_cron_unit)" ] || return 0
    if [ ! -e "$1" ]; then
        [ "${2:-0}" = 1 ] && return 0
        mkdir -m 0700 "$1" || return 1
    fi
    perm_set "$1" 700 root root
}

rule etc-cron-hourly-root-only "/etc/cron.hourly root-only"
check_etc_cron_hourly_root_only() { c2_crondir_check /etc/cron.hourly; }
fix_etc_cron_hourly_root_only() { c2_crondir_fix /etc/cron.hourly; }

rule etc-cron-daily-root-only "/etc/cron.daily root-only"
check_etc_cron_daily_root_only() { c2_crondir_check /etc/cron.daily; }
fix_etc_cron_daily_root_only() { c2_crondir_fix /etc/cron.daily; }

rule etc-cron-weekly-root-only "/etc/cron.weekly root-only"
check_etc_cron_weekly_root_only() { c2_crondir_check /etc/cron.weekly; }
fix_etc_cron_weekly_root_only() { c2_crondir_fix /etc/cron.weekly; }

rule etc-cron-monthly-root-only "/etc/cron.monthly root-only"
check_etc_cron_monthly_root_only() { c2_crondir_check /etc/cron.monthly; }
fix_etc_cron_monthly_root_only() { c2_crondir_fix /etc/cron.monthly; }

rule etc-cron-yearly-root-only "/etc/cron.yearly root-only"
check_etc_cron_yearly_root_only() { c2_crondir_check /etc/cron.yearly 1; }
fix_etc_cron_yearly_root_only() { c2_crondir_fix /etc/cron.yearly 1; }

rule etc-cron-d-root-only "/etc/cron.d root-only"
check_etc_cron_d_root_only() { c2_crondir_check /etc/cron.d; }
fix_etc_cron_d_root_only() { c2_crondir_fix /etc/cron.d; }

rule crontab-restricted-by-cron-allow "crontab restricted by cron.allow"
check_crontab_restricted_by_cron_allow() {
    local bad=0
    c2_need_cron || return
    perm_ok /etc/cron.allow 640 root 'root|crontab' || bad=1
    if [ -e /etc/cron.deny ]; then
        perm_ok /etc/cron.deny 640 root 'root|crontab' || bad=1
    else
        ev "/etc/cron.deny: absent"
    fi
    return $bad
}
fix_crontab_restricted_by_cron_allow() {
    local g=root
    [ -n "$(c2_cron_unit)" ] || return 0
    getent group crontab >/dev/null 2>&1 && g=crontab
    [ -e /etc/cron.allow ] || touch /etc/cron.allow || return 1
    perm_set /etc/cron.allow 640 root "$g"
    [ -e /etc/cron.deny ] && perm_set /etc/cron.deny 640 root "$g"
    return 0
}

rule at-restricted-by-at-allow "at restricted by at.allow"
check_at_restricted_by_at_allow() {
    local bad=0
    pkg_installed at || { ev "at: not installed"; return 2; }
    perm_ok /etc/at.allow 640 root 'daemon|root' || bad=1
    if [ -e /etc/at.deny ]; then
        perm_ok /etc/at.deny 640 root 'daemon|root' || bad=1
    else
        ev "/etc/at.deny: absent"
    fi
    return $bad
}
fix_at_restricted_by_at_allow() {
    local g=root
    pkg_installed at || return 0
    getent group daemon >/dev/null 2>&1 && g=daemon
    [ -e /etc/at.allow ] || touch /etc/at.allow || return 1
    perm_set /etc/at.allow 640 root "$g"
    [ -e /etc/at.deny ] && perm_set /etc/at.deny 640 root "$g"
    return 0
}
