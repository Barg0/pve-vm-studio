# shellcheck shell=bash
# CIS AlmaLinux/Oracle/Rocky Linux 9 v3.0.0 and 10 v1.0.0 - chapter 4: host firewall
# (firewalld, nftables backend). Builds on deb/4-firewall.sh only in name: the UFW rules there
# are not in the EL maps, every rule here is new.
#
# Decisions
# - Permanent configuration goes through `firewall-cmd --permanent` while firewalld runs and
#   `firewall-offline-cmd` while it does not; a running firewalld is reloaded after a change, so
#   runtime and permanent stay equal (the zone target check compares them).
# - SSH first: every fix that can narrow inbound traffic (enable, zone target, services,
#   default zone drop) first allows the services ssh + dhcpv6-client, plus sshd's own port
#   when it is not 22, in the zone it touches. Clones stay reachable over SSH.
# - 4.1.4 (L1): the default zone keeps firewalld's "default" target (unmatched traffic
#   rejected, ICMP errors answered); only an ACCEPT target is changed (to default). Zones
#   holding nothing but lo/virbr* are left alone (the trusted lo zone of 4.1.5).
# - 4.1.5/4.1.6 (manual, fixed anyway): lo goes to the trusted zone (permanent; an NM
#   connection on lo gets connection.zone=trusted too), with the loopback anti-spoofing rich
#   rules - EL9 127.0.0.0/8, EL10 127.0.0.1, both ::1. Checks fail when missing, else review.
# - 4.1.7 (manual): the default zone is cut down to ssh + dhcpv6-client (cockpit and others
#   removed) and sshd's port; review lists services/ports of the active zones.
# - 4.1.8 (L2, manual): default zone = drop (target DROP) with ssh + dhcpv6-client, and ICMP
#   inverted to an allow list of the error and IPv6 neighbor/router discovery types, so path
#   MTU and IPv6 keep working; echo requests are dropped. Outbound stays open.
# - 4.1.9: nftables.service stopped, disabled, masked; iptables-services and ufw removed.
# - 4.1.10 (L2): LogDenied=unicast (not "all": broadcast/multicast noise stays out of the log).
# - 4.1.11 (L2): zones with target default get timestamp-request/-reply blocked (removed from
#   the list when ICMP inversion is on); DROP/REJECT zones already discard them.

E4_CONF=/etc/firewalld/firewalld.conf
# firewalld's own type names (British spelling: neighbour-*).
E4_ICMP_ALLOW="destination-unreachable packet-too-big time-exceeded parameter-problem neighbour-advertisement neighbour-solicitation router-advertisement router-solicitation"

e4_major() { local v=${VERSION_ID:-0}; echo "${v%%.*}"; }

e4_installed() { pkg_installed firewalld && command -v firewall-cmd >/dev/null 2>&1; }
e4_running() { systemctl is-active --quiet firewalld.service 2>/dev/null && firewall-cmd --state >/dev/null 2>&1; }

# rc 1 with evidence unless firewalld is installed and running.
e4_need_running() {
    if ! e4_installed; then ev "firewalld: not installed"; return 1; fi
    if ! e4_running; then ev "firewalld: not running"; return 1; fi
    return 0
}

# Permanent configuration, running or not.
e4_perm() {
    if e4_running; then firewall-cmd --permanent "$@"; else firewall-offline-cmd "$@"; fi
}
e4_reload() {
    e4_running && firewall-cmd -q --reload
    return 0
}

e4_default_zone() {
    if e4_running; then firewall-cmd --get-default-zone; else firewall-offline-cmd --get-default-zone; fi 2>/dev/null
}
e4_set_default_zone() {
    if e4_running; then firewall-cmd -q --set-default-zone="$1"; else firewall-offline-cmd --set-default-zone="$1" >/dev/null; fi
}

# Active zones (runtime), one per line ("public (default)" -> public).
e4_active_zones() { firewall-cmd --get-active-zones 2>/dev/null | awk '/^[^[:space:]]/ { print $1 }'; }

# The zones a fix works on: the active ones while running, else the default zone.
e4_fix_zones() {
    if e4_running; then e4_active_zones; else e4_default_zone; fi | sort -u
}

# 0 when ZONE's interfaces are only lo / virbr* (and it has at least one).
e4_lo_only() {
    local ifs
    if e4_running; then
        ifs=$(firewall-cmd --zone="$1" --list-interfaces 2>/dev/null)
    else
        ifs=$(firewall-offline-cmd --zone="$1" --list-interfaces 2>/dev/null)
    fi
    [ -n "${ifs// /}" ] || return 1
    ! tr ' ' '\n' <<<"$ifs" | sed '/^$/d' | grep -Evq '^(lo|virbr.+)$'
}

e4_ssh_port() {
    local p
    p=$(sshd_val port 2>/dev/null | awk '{ print $1 }')
    echo "${p:-22}"
}

# ssh + dhcpv6-client (+ sshd's port when it is not 22) allowed in ZONE, permanently.
e4_allow_ssh() {
    local z=$1 s p
    for s in ssh dhcpv6-client; do
        [ "$(e4_perm --zone="$z" --query-service="$s" 2>/dev/null)" = yes ] && continue
        e4_perm --zone="$z" --add-service="$s" >/dev/null || return 1
    done
    p=$(e4_ssh_port)
    if [ "$p" != 22 ] && [ "$(e4_perm --zone="$z" --query-port="$p/tcp" 2>/dev/null)" != yes ]; then
        e4_perm --zone="$z" --add-port="$p/tcp" >/dev/null || return 1
    fi
    return 0
}

# ---- 4.1 firewalld ----

rule firewalld-installed "firewalld installed"
check_firewalld_installed() {
    if pkg_installed firewalld; then ev "firewalld: installed"; return 0; fi
    ev "firewalld: not installed"
    return 1
}
fix_firewalld_installed() { pkg_installed firewalld || pkg_install firewalld; }

rule firewalld-backend-nftables "firewalld backend nftables"
check_firewalld_backend_nftables() {
    local b
    [ -f "$E4_CONF" ] || { ev "$E4_CONF: missing"; return 1; }
    b=$(kv_get "$E4_CONF" FirewallBackend)
    ev "FirewallBackend=${b:-unset (default nftables)}"
    [ "${b,,}" = iptables ] && return 1
    # EL10's text wants the value written out; EL9 accepts the default.
    [ "$(e4_major)" -ge 10 ] && [ "${b,,}" != nftables ] && return 1
    return 0
}
fix_firewalld_backend_nftables() {
    local b
    e4_installed || return 1
    b=$(kv_get "$E4_CONF" FirewallBackend)
    [ "${b,,}" = nftables ] && return 0
    kv_set "$E4_CONF" FirewallBackend nftables =
    # A backend change needs a restart, not a reload.
    systemctl try-restart firewalld.service 2>/dev/null
    return 0
}

rule firewalld-enabled "firewalld enabled and running"
check_firewalld_enabled() {
    e4_installed || { ev "firewalld: not installed"; return 1; }
    ev "$(systemctl is-enabled firewalld.service 2>/dev/null || true) / $(systemctl is-active firewalld.service 2>/dev/null || true)"
    svc_enabled firewalld.service && svc_active firewalld.service
}
fix_firewalld_enabled() {
    local z
    e4_installed || return 1
    z=$(e4_default_zone)
    [ -n "$z" ] && { e4_allow_ssh "$z" || return 1; }
    systemctl unmask firewalld.service 2>/dev/null
    systemctl enable --now firewalld.service >/dev/null 2>&1
    e4_reload
    svc_active firewalld.service
}

rule firewalld-zone-target "firewalld: active zone not ACCEPT"
check_firewalld_zone_target() {
    local z ifs t pt n=0 bad=0
    e4_need_running || return 1
    for z in $(e4_active_zones); do
        ifs=$(firewall-cmd --zone="$z" --list-interfaces 2>/dev/null | xargs)
        if e4_lo_only "$z"; then ev "$z: only $ifs - not counted"; continue; fi
        t=$(firewall-cmd --zone="$z" --list-all 2>/dev/null | awk '$1 == "target:" { print $2; exit }')
        pt=$(firewall-cmd --permanent --zone="$z" --get-target 2>/dev/null)
        ev "$z: target ${t:-none}, permanent ${pt:-none}, interfaces ${ifs:-none}"
        n=$((n + 1))
        if [ -z "$t" ] || [ "${t,,}" = accept ] || [ "${t,,}" != "${pt,,}" ]; then bad=1; fi
    done
    [ $n -gt 0 ] || { ev "no active zone"; return 1; }
    return $bad
}
fix_firewalld_zone_target() {
    local z pt
    e4_installed || return 1
    for z in $(e4_fix_zones); do
        e4_lo_only "$z" && continue
        pt=$(e4_perm --zone="$z" --get-target 2>/dev/null)
        [ "${pt,,}" = accept ] || continue
        e4_allow_ssh "$z" || return 1
        e4_perm --zone="$z" --set-target=default >/dev/null || return 1
    done
    e4_reload
}

# ---- loopback ----

# The zone lo is in (runtime), "" when none.
e4_lo_zone() {
    local z
    z=$(firewall-cmd --get-zone-of-interface=lo 2>/dev/null) || return 0
    [ "$z" = "no zone" ] || echo "$z"
}

rule firewalld-loopback-reviewed "firewalld: loopback accepted (trusted)"
check_firewalld_loopback_reviewed() {
    local z pz t
    e4_need_running || return 1
    z=$(e4_lo_zone)
    pz=$(firewall-cmd --permanent --get-zone-of-interface=lo 2>/dev/null)
    ev "lo: zone ${z:-none}, permanent ${pz:-none}"
    [ -n "$z" ] || return 1
    t=$(firewall-cmd --zone="$z" --list-all 2>/dev/null | awk '$1 == "target:" { print $2; exit }')
    ev "$z: target ${t:-none}"
    [ "${t^^}" = ACCEPT ] && [ "$pz" = "$z" ] || return 1
    ev "decision: lo in the trusted zone (target ACCEPT), permanent"
    return 3
}
fix_firewalld_loopback_reviewed() {
    local pz u
    e4_installed || return 1
    pz=$(e4_perm --get-zone-of-interface=lo 2>/dev/null)
    case $pz in
        trusted) ;;
        ''|'no zone') e4_perm --zone=trusted --add-interface=lo >/dev/null || return 1 ;;
        *) e4_perm --zone=trusted --change-interface=lo >/dev/null || return 1 ;;
    esac
    # NetworkManager (1.42+) may manage lo: its connection's zone wins at runtime.
    if command -v nmcli >/dev/null 2>&1; then
        for u in $(nmcli -t -f UUID,DEVICE connection show --active 2>/dev/null | awk -F: '$2 == "lo" { print $1 }'); do
            [ "$(nmcli -g connection.zone connection show "$u" 2>/dev/null)" = trusted ] && continue
            nmcli connection modify "$u" connection.zone trusted >/dev/null 2>&1
            nmcli connection up "$u" >/dev/null 2>&1
        done
    fi
    e4_reload
}

# The two loopback anti-spoofing rich rules (EL9: 127.0.0.0/8, EL10: 127.0.0.1).
e4_lo_rules() {
    local a=127.0.0.0/8
    [ "$(e4_major)" -ge 10 ] && a=127.0.0.1
    printf 'rule family="ipv4" source address="%s" destination not address="%s" drop\n' "$a" "$a"
    printf 'rule family="ipv6" source address="::1" destination not address="::1" drop\n'
}

rule firewalld-loopback-source-reviewed "firewalld: loopback source spoofing dropped"
check_firewalld_loopback_source_reviewed() {
    local z r bad=0
    e4_need_running || return 1
    z=$(e4_lo_zone)
    [ -n "$z" ] || { ev "lo: no zone"; return 1; }
    ev "lo zone: $z"
    while IFS= read -r r; do
        if [ "$(firewall-cmd --zone="$z" --query-rich-rule="$r" 2>/dev/null)" = yes ] \
            && [ "$(firewall-cmd --permanent --zone="$z" --query-rich-rule="$r" 2>/dev/null)" = yes ]; then
            ev "present: $r"
        else
            ev "missing (runtime or permanent): $r"
            bad=1
        fi
    done < <(e4_lo_rules)
    [ $bad -eq 0 ] || return 1
    ev "decision: loopback addresses only on lo, rules in lo's zone"
    return 3
}
fix_firewalld_loopback_source_reviewed() {
    local z r
    e4_installed || return 1
    z=$(e4_perm --get-zone-of-interface=lo 2>/dev/null)
    case $z in ''|'no zone') z=trusted ;; esac
    while IFS= read -r r; do
        [ "$(e4_perm --zone="$z" --query-rich-rule="$r" 2>/dev/null)" = yes ] && continue
        e4_perm --zone="$z" --add-rich-rule="$r" >/dev/null || return 1
    done < <(e4_lo_rules)
    e4_reload
}

# ---- services, default zone ----

rule firewalld-services-reviewed "firewalld: allowed services reviewed"
check_firewalld_services_reviewed() {
    local z
    e4_need_running || return 1
    for z in $(e4_active_zones); do
        e4_lo_only "$z" && continue
        ev "$z: services: $(firewall-cmd --zone="$z" --list-services 2>/dev/null)"
        ev "$z: ports: $(firewall-cmd --zone="$z" --list-ports 2>/dev/null)"
    done
    ev "decision: ssh and dhcpv6-client only (plus sshd's port if not 22)"
    return 3
}
fix_firewalld_services_reviewed() {
    local z s p keep
    e4_installed || return 1
    z=$(e4_default_zone)
    [ -n "$z" ] || return 1
    e4_allow_ssh "$z" || return 1
    for s in $(e4_perm --zone="$z" --list-services 2>/dev/null); do
        case $s in ssh|dhcpv6-client) continue ;; esac
        e4_perm --zone="$z" --remove-service="$s" >/dev/null
    done
    keep="$(e4_ssh_port)/tcp"
    for p in $(e4_perm --zone="$z" --list-ports 2>/dev/null); do
        [ "$p" = "$keep" ] && continue
        e4_perm --zone="$z" --remove-port="$p" >/dev/null
    done
    e4_reload
}

rule firewalld-default-zone-drop "firewalld: default zone drop"
check_firewalld_default_zone_drop() {
    local z
    e4_need_running || return 1
    z=$(firewall-cmd --get-default-zone 2>/dev/null)
    ev "default zone: ${z:-none}"
    [ "$z" = drop ] || return 1
    ev "drop: services: $(firewall-cmd --zone=drop --list-services 2>/dev/null)"
    ev "drop: ports: $(firewall-cmd --zone=drop --list-ports 2>/dev/null)"
    ev "drop: icmp allowed (inverted): $(firewall-cmd --zone=drop --list-icmp-blocks 2>/dev/null)"
    ev "decision: default zone drop with ssh + dhcpv6-client, ICMP errors and IPv6 ND allowed"
    return 3
}
fix_firewalld_default_zone_drop() {
    local t
    e4_installed || return 1
    e4_allow_ssh drop || return 1
    if [ "$(e4_perm --zone=drop --query-icmp-block-inversion 2>/dev/null)" != yes ]; then
        e4_perm --zone=drop --add-icmp-block-inversion >/dev/null || return 1
    fi
    for t in $E4_ICMP_ALLOW; do
        [ "$(e4_perm --zone=drop --query-icmp-block="$t" 2>/dev/null)" = yes ] && continue
        e4_perm --zone=drop --add-icmp-block="$t" >/dev/null || return 1
    done
    e4_reload
    [ "$(e4_default_zone)" = drop ] || e4_set_default_zone drop || return 1
    e4_reload
}

# ---- conflicts, logging, ICMP timestamps ----

rule firewalld-no-conflicting-firewalls "no other firewall beside firewalld"
check_firewalld_no_conflicting_firewalls() {
    local bad=0 p
    ev "nftables.service: $(systemctl is-enabled nftables.service 2>/dev/null || true) / $(systemctl is-active nftables.service 2>/dev/null || true)"
    svc_enabled nftables.service && bad=1
    svc_active nftables.service && bad=1
    for p in iptables-services ufw; do
        if pkg_installed "$p"; then ev "$p: installed"; bad=1; else ev "$p: not installed"; fi
    done
    return $bad
}
fix_firewalld_no_conflicting_firewalls() {
    if svc_enabled nftables.service || svc_active nftables.service; then
        systemctl disable --now nftables.service >/dev/null 2>&1
        svc_off nftables.service
    fi
    systemctl stop iptables.service ip6tables.service ufw.service 2>/dev/null
    pkg_purge iptables-services ufw || return 1
    e4_reload
}

rule firewalld-log-denied "firewalld logs denied packets"
check_firewalld_log_denied() {
    local v
    e4_installed || { ev "firewalld: not installed"; return 1; }
    if e4_running; then v=$(firewall-cmd --get-log-denied 2>/dev/null); else v=$(kv_get "$E4_CONF" LogDenied); fi
    ev "LogDenied: ${v:-off}"
    [ -n "$v" ] && [ "$v" != off ]
}
fix_firewalld_log_denied() {
    e4_installed || return 1
    if e4_running; then
        [ "$(firewall-cmd --get-log-denied 2>/dev/null)" = off ] || return 0
        firewall-cmd -q --set-log-denied=unicast
    else
        case $(kv_get "$E4_CONF" LogDenied) in ''|off) kv_set "$E4_CONF" LogDenied unicast = ;; esac
        return 0
    fi
}

rule firewalld-icmp-timestamp-blocked "firewalld blocks ICMP timestamps"
check_firewalld_icmp_timestamp_blocked() {
    local z t inv blocks n=0 bad=0 x
    e4_need_running || return 1
    for z in $(e4_active_zones); do
        t=$(firewall-cmd --permanent --zone="$z" --get-target 2>/dev/null)
        case ${t^^} in
            ACCEPT) ev "$z: target ACCEPT - not filtering"; continue ;;
            DROP|%%REJECT%%|REJECT) ev "$z: target $t - discards them"; n=$((n + 1)); continue ;;
        esac
        n=$((n + 1))
        inv=$(firewall-cmd --permanent --zone="$z" --query-icmp-block-inversion 2>/dev/null)
        blocks=" $(firewall-cmd --permanent --zone="$z" --list-icmp-blocks 2>/dev/null) "
        ev "$z: target ${t:-default}, inversion ${inv:-no}, icmp-blocks:${blocks% }"
        for x in timestamp-request timestamp-reply; do
            if [ "$inv" = yes ]; then
                [[ "$blocks" == *" $x "* ]] && bad=1
            else
                [[ "$blocks" == *" $x "* ]] || bad=1
            fi
        done
    done
    [ $n -gt 0 ] || { ev "no active zone"; return 1; }
    return $bad
}
fix_firewalld_icmp_timestamp_blocked() {
    local z t inv x q
    e4_installed || return 1
    for z in $(e4_fix_zones); do
        t=$(e4_perm --zone="$z" --get-target 2>/dev/null)
        case ${t^^} in ACCEPT|DROP|%%REJECT%%|REJECT) continue ;; esac
        inv=$(e4_perm --zone="$z" --query-icmp-block-inversion 2>/dev/null)
        for x in timestamp-request timestamp-reply; do
            q=$(e4_perm --zone="$z" --query-icmp-block="$x" 2>/dev/null)
            if [ "$inv" = yes ]; then
                [ "$q" = yes ] && { e4_perm --zone="$z" --remove-icmp-block="$x" >/dev/null || return 1; }
            else
                [ "$q" = yes ] || { e4_perm --zone="$z" --add-icmp-block="$x" >/dev/null || return 1; }
            fi
        done
    done
    e4_reload
}
