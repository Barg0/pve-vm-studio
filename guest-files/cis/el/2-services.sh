# shellcheck shell=bash
# CIS AlmaLinux/Oracle/Rocky Linux 9 v3.0.0 and 10 v1.0.0 - chapter 2: services, clients,
# time sync, job schedulers. Builds on deb/2-services.sh: sourced after it, the functions here
# replace the Debian-specific ones (package and unit names, apt, /etc/chrony/).
#
# Decisions
# - c2_off_fix is redefined for dnf: `dnf remove --assumeno` first; if the transaction would
#   take a protected package (sshd, cloud-init, qemu-guest-agent, systemd, NetworkManager, dnf,
#   sudo, kernel/grub2, firewalld, chrony, cronie, audit, rsyslog, SELinux, authselect, ...),
#   the removal is refused and the units are stopped + masked instead (the benchmark's
#   "required as a dependency" branch). clean_requirements_on_remove is off: no autoremove.
#   Every deb rule whose packages have the same name on EL (autofs, dnsmasq, vsftpd, cups,
#   rpcbind, squid, telnet clients) keeps its deb check and gets this fix.
# - 2.1.4 DHCP server: dhcp-server (dhcpd, dhcpd6) and kea (kea-dhcp4/6, kea-dhcp-ddns) are
#   both checked on EL9 and EL10 (EL9 ships the first, EL10 the second).
# - 2.1.13/2.1.12 rsync: rsync-daemon is removed (rsync itself stays), units rsyncd.*.
# - 2.1.19/21 MTA: the deb rule is distro-neutral (postfix default inet_interfaces=localhost
#   passes; no MTA at all passes, as the benchmark says).
# - GUI (EL9 2.1.20, EL10 2.1.19): a server gold has none - pass when neither the
#   "Server with GUI" environment group (dnf cache only, never a metadata download in a check)
#   nor gdm is installed. If one is: EL9 accepts a multi-user default target (the fix sets it);
#   EL10's rule wants gdm gone (the fix removes gdm through c2_off_fix). The environment group
#   itself is never removed by a fix.
# - Xwayland (EL9 2.1.22) / X server (EL9 xorg-x11-server-common, EL10 Xwayland): removed
#   through c2_off_fix; rpm --whatrequires is listed as evidence.
# - 2.2.x clients: ftp, openldap-clients, telnet, tftp removed.
# - 2.3 time: chrony (chronyd). 2.3.1's fix installs chrony and enables chronyd. 2.3.2 keeps
#   the image's pool line (/etc/chrony.conf plus confdir/sourcedir files - sourcedir
#   /run/chrony-dhcp counts); only when no server/pool exists, the fix appends
#   "server <s> iburst" per name in PVS_CIS_NTP, else "pool pool.ntp.org iburst". 2.3.3: OPTIONS in /etc/sysconfig/chronyd
#   without "-u root", with "-u chrony" (the image's other options kept).
# - 2.4 cron/at: the deb rules are distro-neutral (cronie's crond.service, group root since EL
#   has no crontab group, at.allow group daemon). Kept.

e2_PROTECT='(openssh|openssh-server|openssh-clients|cloud-init|cloud-utils-growpart|qemu-guest-agent|hyperv-daemons.*|hypervkvpd|hypervvssd|hypervfcopyd|systemd|systemd-.*|NetworkManager.*|dnf|dnf-.*|python3-dnf.*|yum|rpm|rpm-.*|sudo|kernel|kernel-.*|grub2-.*|grubby|shim-.*|dracut.*|firewalld.*|chrony|cronie.*|audit|audit-libs|rsyslog.*|selinux-policy.*|policycoreutils.*|libselinux.*|authselect.*|pam|sssd.*|lvm2.*|e2fsprogs.*|xfsprogs|glibc.*|util-linux.*|passwd|shadow-utils|crypto-policies.*|openssl.*|bash|coreutils.*|dbus.*|polkit.*)'

# The packages `dnf remove PKGS` would take (dependents included), one per line.
e2_dnf_sim() {
    LC_ALL=C dnf remove --assumeno --setopt=clean_requirements_on_remove=False "$@" 2>&1 \
        | awk '/^Removing/ { s = 1; next } /^(Transaction Summary|Installing|Upgrading|Downgrading|Reinstalling|Error)/ { s = 0 } s && /^ [^ ]/ { print $1 }' \
        | sort -u
}

# dnf remove PKGS after a simulation: refused when a protected package would go with them.
e2_dnf_remove() {
    local rm bad
    rm=$(e2_dnf_sim "$@")
    if [ -z "$rm" ]; then
        echo "refused: dnf could not plan the removal of $*"
        return 1
    fi
    bad=$(grep -Ex "$e2_PROTECT" <<<"$rm" | xargs)
    if [ -n "$bad" ]; then
        echo "refused: dnf remove $* would remove $bad"
        return 1
    fi
    dnf -y -q remove --setopt=clean_requirements_on_remove=False "$@" >/dev/null
}

# EL: apt does not exist. Every deb fix that calls c2_apt directly is redefined below; this
# only guards against one that was missed.
c2_apt() { echo "c2_apt: no apt on Enterprise Linux ($*)"; return 1; }

# Stop UNITS and remove the installed PKGS; when the removal is refused, mask UNITS instead.
c2_off_fix() {
    local pkgs=$1 units=${2:-} inst
    # shellcheck disable=SC2086
    inst=$(c2_installed $pkgs)
    [ -n "$inst" ] || return 0
    # shellcheck disable=SC2086
    [ -n "$units" ] && systemctl stop $units 2>/dev/null
    # shellcheck disable=SC2086
    e2_dnf_remove $inst && return 0
    [ -n "$units" ] || return 1
    # shellcheck disable=SC2086
    svc_off $units
}

e2_major() { local v=${VERSION_ID:-0}; echo "${v%%.*}"; }

# ---- 2.1 server services ----

rule avahi-daemon-removed "avahi daemon removed"
check_avahi_daemon_removed() { c2_off_check avahi "avahi-daemon.socket avahi-daemon.service"; }
fix_avahi_daemon_removed() { c2_off_fix avahi "avahi-daemon.socket avahi-daemon.service"; }

rule cockpit-not-in-use "cockpit web service not in use"
check_cockpit_not_in_use() { c2_off_check cockpit-ws "cockpit.socket cockpit.service"; }
fix_cockpit_not_in_use() { c2_off_fix cockpit-ws "cockpit.socket cockpit.service"; }

e2_DHCP_PKGS="dhcp-server kea"
e2_DHCP_UNITS="dhcpd.service dhcpd6.service kea-dhcp4.service kea-dhcp6.service kea-dhcp-ddns.service"

rule dhcp-server-kea-removed "DHCP server (dhcpd, kea) removed"
check_dhcp_server_kea_removed() { c2_off_check "$e2_DHCP_PKGS" "$e2_DHCP_UNITS"; }
fix_dhcp_server_kea_removed() { c2_off_fix "$e2_DHCP_PKGS" "$e2_DHCP_UNITS"; }

rule dns-server-bind9-removed "DNS server (bind) removed"
check_dns_server_bind9_removed() { c2_off_check bind named.service; }
fix_dns_server_bind9_removed() { c2_off_fix bind named.service; }

rule samba-removed "samba removed"
check_samba_removed() { c2_off_check samba smb.service; }
fix_samba_removed() { c2_off_fix samba smb.service; }

e2_IMAP_UNITS="dovecot.socket dovecot.service cyrus-imapd.service"

rule imap-pop3-server-dovecot-removed "IMAP/POP3 server (dovecot, cyrus) removed"
check_imap_pop3_server_dovecot_removed() { c2_off_check "dovecot cyrus-imapd" "$e2_IMAP_UNITS"; }
fix_imap_pop3_server_dovecot_removed() { c2_off_fix "dovecot cyrus-imapd" "$e2_IMAP_UNITS"; }

rule nfs-server-removed "NFS server removed"
check_nfs_server_removed() { c2_off_check nfs-utils nfs-server.service; }
fix_nfs_server_removed() { c2_off_fix nfs-utils nfs-server.service; }

rule rsync-daemon-masked "rsync daemon not in use"
check_rsync_daemon_masked() { c2_off_check rsync-daemon "rsyncd.socket rsyncd.service"; }
fix_rsync_daemon_masked() { c2_off_fix rsync-daemon "rsyncd.socket rsyncd.service"; }

rule snmp-daemon-removed "SNMP daemon removed"
check_snmp_daemon_removed() { c2_off_check net-snmp snmpd.service; }
fix_snmp_daemon_removed() { c2_off_fix net-snmp snmpd.service; }

rule telnet-server-removed "telnet server removed"
check_telnet_server_removed() { c2_off_check telnet-server telnet.socket; }
fix_telnet_server_removed() { c2_off_fix telnet-server telnet.socket; }

rule tftp-server-removed "TFTP server removed"
check_tftp_server_removed() { c2_off_check tftp-server "tftp.socket tftp.service"; }
fix_tftp_server_removed() { c2_off_fix tftp-server "tftp.socket tftp.service"; }

rule web-servers-apache2-nginx-removed "web servers (httpd, nginx) removed"
check_web_servers_apache2_nginx_removed() {
    local bad=0
    c2_off_check httpd "httpd.socket httpd.service" || bad=1
    c2_off_check nginx nginx.service || bad=1
    return $bad
}
fix_web_servers_apache2_nginx_removed() {
    c2_off_fix httpd "httpd.socket httpd.service" || return 1
    c2_off_fix nginx nginx.service
}

# ---- GUI ----

# 0 when the "Server with GUI" environment group is recorded as installed. Cache only: a
# check must not download repository metadata.
e2_gui_group() {
    LC_ALL=C dnf -q -C group list --installed 2>/dev/null \
        | sed -n '/Installed Environment Groups:/,/Installed Groups:/p' | grep -qi 'Server with GUI'
}

rule gui-not-in-use "no graphical environment in use"
check_gui_not_in_use() {
    local gui=0 tgt
    if e2_gui_group; then ev "environment group: Server with GUI"; gui=1; fi
    if pkg_installed gdm; then ev "gdm: installed"; gui=1; fi
    if [ $gui -eq 0 ]; then
        ev "no Server with GUI group, gdm not installed"
        return 0
    fi
    tgt=$(systemctl get-default 2>/dev/null)
    ev "default target: ${tgt:-unknown}"
    [ "$tgt" = multi-user.target ]
}
fix_gui_not_in_use() {
    e2_gui_group || pkg_installed gdm || return 0
    [ "$(systemctl get-default 2>/dev/null)" = multi-user.target ] || systemctl set-default multi-user.target >/dev/null 2>&1
}

rule gdm-removed "GNOME display manager removed"
check_gdm_removed() {
    local bad=0
    if e2_gui_group; then ev "environment group: Server with GUI"; bad=1; fi
    c2_off_check gdm || bad=1
    return $bad
}
fix_gdm_removed() { c2_off_fix gdm gdm.service; }

e2_xpkg() { if [ "$(e2_major)" -ge 10 ]; then echo xorg-x11-server-Xwayland; else echo xorg-x11-server-common; fi; }

rule x-server-removed "X server removed"
check_x_server_removed() { c2_off_check "$(e2_xpkg)"; }
fix_x_server_removed() { c2_off_fix "$(e2_xpkg)"; }

rule xwayland-not-in-use "Xwayland removed"
check_xwayland_not_in_use() {
    local req
    pkg_installed xorg-x11-server-Xwayland || { ev "not installed: xorg-x11-server-Xwayland"; return 0; }
    req=$(rpm -q --whatrequires xorg-x11-server-Xwayland --qf '%{NAME}\n' 2>/dev/null | grep -v '^no package' | sort -u | xargs)
    ev "installed: xorg-x11-server-Xwayland"
    ev "required by: ${req:-nothing}"
    return 1
}
fix_xwayland_not_in_use() { c2_off_fix xorg-x11-server-Xwayland; }

# ---- 2.2 clients ----

rule ftp-clients-removed "FTP client removed"
check_ftp_clients_removed() { c2_off_check ftp; }
fix_ftp_clients_removed() { c2_off_fix ftp; }

rule ldap-client-tools-removed "LDAP client tools removed"
check_ldap_client_tools_removed() { c2_off_check openldap-clients; }
fix_ldap_client_tools_removed() { c2_off_fix openldap-clients; }

rule tftp-client-removed "TFTP client removed"
check_tftp_client_removed() { c2_off_check tftp; }
fix_tftp_client_removed() { c2_off_fix tftp; }

# ---- 2.3 time synchronization (chrony) ----

E2_CHRONY_CONF=/etc/chrony.conf
E2_CHRONY_SYSCONF=/etc/sysconfig/chronyd

rule time-sync-in-use "time sync (chrony) in use"
check_time_sync_in_use() {
    if ! pkg_installed chrony; then ev "chrony: not installed"; return 1; fi
    ev "chrony: installed"
    ev "$(c2_unit_line chronyd.service)"
    [ "$(systemctl is-enabled chronyd.service 2>/dev/null)" = enabled ] && systemctl is-active --quiet chronyd.service
}
fix_time_sync_in_use() {
    pkg_installed chrony || pkg_install chrony || return 1
    systemctl unmask chronyd.service 2>/dev/null
    systemctl enable --now chronyd.service >/dev/null 2>&1
}

# chrony.conf plus the files its confdir/sourcedir lines pull in (a directory or a glob).
e2_chrony_files() {
    local d f
    [ -f "$E2_CHRONY_CONF" ] || return 0
    echo "$E2_CHRONY_CONF"
    while read -r d; do
        [ -n "$d" ] || continue
        if [ -d "$d" ]; then
            find -L "$d" -maxdepth 1 -type f \( -name '*.conf' -o -name '*.sources' \) 2>/dev/null
        else
            # shellcheck disable=SC2086
            for f in $d; do [ -f "$f" ] && echo "$f"; done
        fi
    done < <(awk '$1 ~ /^(confdir|sourcedir)$/ { for (i = 2; i <= NF; i++) print $i }' "$E2_CHRONY_CONF" 2>/dev/null)
}

rule chrony-time-server-set "chrony: time server set"
check_chrony_time_server_set() {
    local files hits
    pkg_installed chrony || { ev "chrony: not installed"; return 1; }
    mapfile -t files < <(e2_chrony_files)
    [ "${#files[@]}" -gt 0 ] || { ev "chrony: no configuration files"; return 1; }
    hits=$(grep -HEi '^[[:space:]]*(server|pool)([[:space:]]+|[[:space:]]*:[[:space:]]*)[^[:space:]]' "${files[@]}" 2>/dev/null)
    if [ -n "$hits" ]; then ev "$hits"; return 0; fi
    ev "chrony: no server/pool line in ${files[*]}"
    return 1
}
fix_chrony_time_server_set() {
    local srv
    pkg_installed chrony || return 1
    check_chrony_time_server_set >/dev/null && return 0
    srv=$(printf '%s' "${PVS_CIS_NTP:-}" | tr -cd 'A-Za-z0-9.:_ -' | xargs)
    printf '# pvs-cis: authorized time source(s)\n' >> "$E2_CHRONY_CONF"
    if [ -n "$srv" ]; then
        # shellcheck disable=SC2086
        printf 'server %s iburst\n' $srv >> "$E2_CHRONY_CONF"
    else
        printf 'pool pool.ntp.org iburst\n' >> "$E2_CHRONY_CONF"
    fi
    systemctl reload-or-restart chronyd.service 2>/dev/null
    return 0
}

# OPTIONS= of /etc/sysconfig/chronyd without its quotes.
e2_chrony_opts() { kv_get "$E2_CHRONY_SYSCONF" OPTIONS | sed -E 's/^"(.*)"$/\1/; s/^'"'"'(.*)'"'"'$/\1/'; }

rule chrony-not-root "chrony not run as root"
check_chrony_not_root() {
    local opts procs bad=0
    pkg_installed chrony || { ev "chrony: not installed"; return 1; }
    opts=$(e2_chrony_opts)
    ev "$E2_CHRONY_SYSCONF OPTIONS: ${opts:-unset}"
    grep -Eq '(^|[[:space:]])-u[[:space:]]+root\b' <<<"$opts" && bad=1
    procs=$(ps -eo user:32=,comm= 2>/dev/null | awk '$2 == "chronyd" { print $1 }' | sort -u | xargs)
    ev "chronyd runs as: ${procs:-not running}"
    [[ " $procs " == *" root "* ]] && bad=1
    return $bad
}
fix_chrony_not_root() {
    local opts
    pkg_installed chrony || return 1
    opts=$(e2_chrony_opts)
    opts=$(sed -E 's/(^|[[:space:]])-u[[:space:]]+[^[:space:]]+//g' <<<"$opts" | xargs)
    getent passwd chrony >/dev/null 2>&1 && opts="${opts:+$opts }-u chrony"
    kv_set "$E2_CHRONY_SYSCONF" OPTIONS "\"$opts\"" =
    chmod 0644 "$E2_CHRONY_SYSCONF"
    systemctl try-restart chronyd.service 2>/dev/null
    return 0
}
