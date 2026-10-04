# shellcheck shell=bash
# CIS Ubuntu 26.04 LTS v1.0.0 - chapter 3: network devices, network kernel modules, network
# kernel parameters. Rules: our own titles; see ../README.md.
#
# Decisions
# - 3.1.1 (manual): IPv6 stays enabled (the benchmark's recommended default); the check reports
#   the status and returns review. The 3.3.2 parameters are set; they return n/a if IPv6 is off.
# - 3.1.2: a VM has no wireless NIC, so the check normally passes. The fix still denies every
#   module under kernel/drivers/net/wireless (+ drivers of any wireless NIC) in
#   /etc/modprobe.d/pvs-cis-wireless.conf. virtio_net / e1000 / hv_netvsc live elsewhere.
# - 3.1.3: bluez is purged if present; if the purge fails, bluetooth.service is stopped+masked.
# - 3.2.7 (manual): studio deny list (env PVS_CIS_NET_DENY overrides at fix time) written to
#   /etc/modprobe.d/60-pvs-cis-net-deny.conf: esp4 esp6 rxrpc af_key appletalk ax25 netrom
#   rose x25 phonet ieee802154 caif nfc kcm. This breaks IPsec (strongSwan) and AFS on clones.
#   llc / stp / bridge / vsock / mptcp are kept (bridges, hv_sock, guest agent).
#   Check: 1 if a listed module is still loadable, else review (the list is a site decision).
# - 3.3.x: values go to /etc/sysctl.d/60-pvs-cis.conf (sysctl_set). Conflicting lines are
#   commented out in other sysctl files AND in UFW's IPT_SYSCTL file (/etc/ufw/sysctl.conf by
#   default); the checks also fail on a conflicting active line in the UFW file, as the
#   benchmark's audit reads it first.
#   RISK: ufw's shipped sysctl.conf has log_martians=0. If ufw is (re)installed AFTER these
#   fixes ran (or a ufw upgrade rewrites the conffile), 3.3.1.16/17 fail - ufw must be
#   installed before chapter 3's fixes run (it is in the Ubuntu cloud image).
# - 3.3.1.12/13 rp_filter = 1 (strict): fine for a single-NIC VM; asymmetric routing breaks.
# - 3.3.2.7/8 accept_ra = 0: systemd-networkd handles router advertisements itself (it keeps
#   the kernel's accept_ra off on its links), so SLAAC via netplan keeps working.
# - Not a router: forwarding = 0 for IPv4 and IPv6 (would break Docker/LXD-style NAT on clones).

# ---- chapter helpers ----

# IPv6 is off when the ipv6 module was booted with disable=1, or both all/default
# disable_ipv6 are 1, or the kernel has no IPv6 sysctls at all.
c3_ipv6_on() {
    [ -d /proc/sys/net/ipv6 ] || return 1
    if [ -r /sys/module/ipv6/parameters/disable ] && ! grep -Eq '^[[:space:]]*0\b' /sys/module/ipv6/parameters/disable; then
        return 1
    fi
    if [ "$(sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null)" = 1 ] \
        && [ "$(sysctl -n net.ipv6.conf.default.disable_ipv6 2>/dev/null)" = 1 ]; then
        return 1
    fi
    return 0
}

# UFW's own sysctl file (IPT_SYSCTL in /etc/default/ufw), when it exists.
c3_ufw_sysctl_file() {
    local f
    [ -f /etc/default/ufw ] || return 0
    f=$(awk -F= '/^[[:space:]]*IPT_SYSCTL=/ { print $2 }' /etc/default/ufw | tail -n 1 | tr -d "\"' ")
    [ -n "$f" ] && [ -f "$f" ] && echo "$f"
    return 0
}

# sysctl_is plus: no active line in UFW's sysctl file sets KEY to something else.
c3_sysctl_is() {
    local k=$1 v=$2 rc=0 f have
    sysctl_is "$k" "$v" || rc=1
    f=$(c3_ufw_sysctl_file)
    if [ -n "$f" ]; then
        have=$(grep -E "^[[:space:]]*${k//./[./]}[[:space:]]*=" "$f" 2>/dev/null | tail -n 1 | cut -d= -f2- | xargs)
        if [ -n "$have" ]; then
            ev "$f: $k = $have"
            [ "$have" = "$(xargs <<<"$v")" ] || rc=1
        fi
    fi
    return $rc
}

# sysctl_set plus: comment KEY out in UFW's sysctl file when IPT_SYSCTL points elsewhere
# than /etc/ufw/sysctl.conf (sysctl_set handles that one).
c3_sysctl_set() {
    local k=$1 v=$2 f re
    sysctl_set "$k" "$v"
    f=$(c3_ufw_sysctl_file)
    if [ -n "$f" ] && [ "$(readlink -f "$f")" != "$(readlink -f /etc/ufw/sysctl.conf)" ]; then
        re="^[[:space:]]*${k//./[./]}[[:space:]]*="
        sed -i -E "s|${re}|# pvs-cis: set in ${SYSCTL_FILE} - &|" "$f"
    fi
    return 0
}

# IPv6 parameters: n/a when IPv6 is disabled.
c3_sysctl6_is() {
    if ! c3_ipv6_on; then
        ev "IPv6 is disabled"
        return 2
    fi
    c3_sysctl_is "$1" "$2"
}

C3_NET_DENY_FILE=/etc/modprobe.d/60-pvs-cis-net-deny.conf
C3_NET_DENY_DEFAULT="esp4 esp6 rxrpc af_key appletalk ax25 netrom rose x25 phonet ieee802154 caif nfc kcm"
# Never denied, whatever the list says: the VM's NICs, bridges, sockets the guest tools use.
C3_NET_KEEP="virtio_net e1000 e1000e hv_netvsc hv_sock vsock vmw_vsock_virtio_transport llc stp bridge mptcp"

# ---- 3.1 network devices ----

rule ipv6-status-reviewed "IPv6 status reviewed"
check_ipv6_status_reviewed() {
    if c3_ipv6_on; then ev "IPv6: enabled"; else ev "IPv6: disabled"; fi
    ev "disable param: $(cat /sys/module/ipv6/parameters/disable 2>/dev/null || echo n/a)"
    ev "all.disable_ipv6=$(sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null) default.disable_ipv6=$(sysctl -n net.ipv6.conf.default.disable_ipv6 2>/dev/null)"
    ev "studio decision: IPv6 kept enabled, hardened by 3.3.2"
    return 3
}

rule no-wireless-network-modules "No wireless network modules"
check_no_wireless_network_modules() {
    local d m mods="" bad=0
    for d in /sys/class/net/*/wireless; do
        [ -d "$d" ] || continue
        m=$(readlink -f "$(dirname "$d")/device/driver/module" 2>/dev/null)
        [ -n "$m" ] && mods="$mods $(basename "$m")"
    done
    if [ -z "${mods// /}" ]; then
        ev "no wireless interfaces"
        return 0
    fi
    for m in $(tr ' ' '\n' <<<"$mods" | sort -u); do
        mod_unavailable "$m" || bad=1
    done
    return $bad
}
fix_no_wireless_network_modules() {
    local f=/etc/modprobe.d/pvs-cis-wireless.conf d m names
    names=$(find "/lib/modules/$(uname -r)/kernel/drivers/net/wireless" -type f -name '*.ko*' -printf '%f\n' 2>/dev/null \
        | sed -E 's/\.ko(\.[xg]z|\.zst)?$//')
    for d in /sys/class/net/*/wireless; do
        [ -d "$d" ] || continue
        m=$(readlink -f "$(dirname "$d")/device/driver/module" 2>/dev/null)
        [ -n "$m" ] && names="$names
$(basename "$m")"
    done
    names=$(printf '%s\n' "$names" | sed '/^$/d' | sort -u)
    if [ -z "$names" ]; then
        rm -f "$f"
        return 0
    fi
    printf '%s\n' "$names" | awk '{ printf "install %s /bin/false\nblacklist %s\n", $1, $1 }' > "$f"
    chmod 0644 "$f"
    for m in $names; do
        if lsmod | awk '{print $1}' | grep -qx "${m//-/_}"; then
            modprobe -r "$m" 2>/dev/null || rmmod "$m" 2>/dev/null
        fi
    done
    return 0
}

rule bluetooth-not-in-use "Bluetooth not in use"
check_bluetooth_not_in_use() {
    if ! pkg_installed bluez; then
        ev "bluez: not installed"
        return 0
    fi
    local bad=0
    ev "bluez: installed"
    ev "bluetooth.service: $(systemctl is-enabled bluetooth.service 2>/dev/null || true) / $(systemctl is-active bluetooth.service 2>/dev/null || true)"
    svc_enabled bluetooth.service && bad=1
    svc_active bluetooth.service && bad=1
    return $bad
}
fix_bluetooth_not_in_use() {
    pkg_installed bluez || return 0
    systemctl stop bluetooth.service 2>/dev/null
    pkg_purge bluez && return 0
    svc_off bluetooth.service
}

# ---- 3.2 network kernel modules ----

rule atm-module-unavailable "atm module unavailable"
check_atm_module_unavailable() { mod_unavailable atm; }
fix_atm_module_unavailable() { mod_disable atm; }

rule can-module-unavailable "can module unavailable"
check_can_module_unavailable() { mod_unavailable can; }
fix_can_module_unavailable() { mod_disable can; }

rule dccp-module-unavailable "dccp module unavailable"
check_dccp_module_unavailable() { mod_unavailable dccp; }
fix_dccp_module_unavailable() { mod_disable dccp; }

rule rds-module-unavailable "rds module unavailable"
check_rds_module_unavailable() { mod_unavailable rds; }
fix_rds_module_unavailable() { mod_disable rds; }

rule sctp-module-unavailable "sctp module unavailable"
check_sctp_module_unavailable() { mod_unavailable sctp; }
fix_sctp_module_unavailable() { mod_disable sctp; }

rule tipc-module-unavailable "tipc module unavailable"
check_tipc_module_unavailable() { mod_unavailable tipc; }
fix_tipc_module_unavailable() { mod_disable tipc; }

rule unneeded-network-protocol-modules-denied "Unneeded network protocol modules denied"
check_unneeded_network_protocol_modules_denied() {
    local list m bad=0
    if [ ! -f "$C3_NET_DENY_FILE" ]; then
        ev "$C3_NET_DENY_FILE: missing"
        return 1
    fi
    list=$(awk '$1 == "install" && $3 ~ /\/bin\/(false|true)$/ { print $2 }' "$C3_NET_DENY_FILE" | sort -u)
    ev "studio deny list: $(xargs <<<"$list")"
    for m in $list; do
        mod_unavailable "$m" >/dev/null || { mod_unavailable "$m"; bad=1; }
    done
    [ $bad -eq 0 ] || return 1
    ev "all listed modules unavailable; list is the studio's decision - review for this site"
    return 3
}
fix_unneeded_network_protocol_modules_denied() {
    local m list=${PVS_CIS_NET_DENY:-$C3_NET_DENY_DEFAULT} tmp
    tmp=$(mktemp)
    printf '# pvs-cis 3.2.7: network protocol modules this gold does not need\n' > "$tmp"
    for m in $list; do
        [[ " $C3_NET_KEEP " == *" ${m//-/_} "* ]] && continue
        printf 'install %s /bin/false\nblacklist %s\n' "$m" "$m" >> "$tmp"
    done
    cat "$tmp" > "$C3_NET_DENY_FILE"
    rm -f "$tmp"
    chmod 0644 "$C3_NET_DENY_FILE"
    for m in $list; do
        [[ " $C3_NET_KEEP " == *" ${m//-/_} "* ]] && continue
        if lsmod | awk '{print $1}' | grep -qx "${m//-/_}"; then
            modprobe -r "$m" 2>/dev/null || rmmod "$m" 2>/dev/null
        fi
    done
    return 0
}

# ---- 3.3.1 IPv4 parameters ----

rule ipv4-forwarding-off "IPv4 forwarding off"
check_ipv4_forwarding_off() { c3_sysctl_is net.ipv4.ip_forward 0; }
fix_ipv4_forwarding_off() { c3_sysctl_set net.ipv4.ip_forward 0; }

rule ipv4-forwarding-off-all "IPv4 forwarding off (all)"
check_ipv4_forwarding_off_all() { c3_sysctl_is net.ipv4.conf.all.forwarding 0; }
fix_ipv4_forwarding_off_all() { c3_sysctl_set net.ipv4.conf.all.forwarding 0; }

rule ipv4-forwarding-off-default "IPv4 forwarding off (default)"
check_ipv4_forwarding_off_default() { c3_sysctl_is net.ipv4.conf.default.forwarding 0; }
fix_ipv4_forwarding_off_default() { c3_sysctl_set net.ipv4.conf.default.forwarding 0; }

rule no-icmp-redirects-sent-all "No ICMP redirects sent (all)"
check_no_icmp_redirects_sent_all() { c3_sysctl_is net.ipv4.conf.all.send_redirects 0; }
fix_no_icmp_redirects_sent_all() { c3_sysctl_set net.ipv4.conf.all.send_redirects 0; }

rule no-icmp-redirects-sent-default "No ICMP redirects sent (default)"
check_no_icmp_redirects_sent_default() { c3_sysctl_is net.ipv4.conf.default.send_redirects 0; }
fix_no_icmp_redirects_sent_default() { c3_sysctl_set net.ipv4.conf.default.send_redirects 0; }

rule bogus-icmp-error-replies-ignored "Bogus ICMP error replies ignored"
check_bogus_icmp_error_replies_ignored() { c3_sysctl_is net.ipv4.icmp_ignore_bogus_error_responses 1; }
fix_bogus_icmp_error_replies_ignored() { c3_sysctl_set net.ipv4.icmp_ignore_bogus_error_responses 1; }

rule broadcast-pings-ignored "Broadcast pings ignored"
check_broadcast_pings_ignored() { c3_sysctl_is net.ipv4.icmp_echo_ignore_broadcasts 1; }
fix_broadcast_pings_ignored() { c3_sysctl_set net.ipv4.icmp_echo_ignore_broadcasts 1; }

rule icmp-redirects-refused-all "ICMP redirects refused (all)"
check_icmp_redirects_refused_all() { c3_sysctl_is net.ipv4.conf.all.accept_redirects 0; }
fix_icmp_redirects_refused_all() { c3_sysctl_set net.ipv4.conf.all.accept_redirects 0; }

rule icmp-redirects-refused-default "ICMP redirects refused (default)"
check_icmp_redirects_refused_default() { c3_sysctl_is net.ipv4.conf.default.accept_redirects 0; }
fix_icmp_redirects_refused_default() { c3_sysctl_set net.ipv4.conf.default.accept_redirects 0; }

rule gateway-redirects-refused-all "Gateway redirects refused (all)"
check_gateway_redirects_refused_all() { c3_sysctl_is net.ipv4.conf.all.secure_redirects 0; }
fix_gateway_redirects_refused_all() { c3_sysctl_set net.ipv4.conf.all.secure_redirects 0; }

rule gateway-redirects-refused-default "Gateway redirects refused (default)"
check_gateway_redirects_refused_default() { c3_sysctl_is net.ipv4.conf.default.secure_redirects 0; }
fix_gateway_redirects_refused_default() { c3_sysctl_set net.ipv4.conf.default.secure_redirects 0; }

rule strict-reverse-path-filter-all "Strict reverse path filter (all)"
check_strict_reverse_path_filter_all() { c3_sysctl_is net.ipv4.conf.all.rp_filter 1; }
fix_strict_reverse_path_filter_all() { c3_sysctl_set net.ipv4.conf.all.rp_filter 1; }

rule strict-reverse-path-filter-default "Strict reverse path filter (default)"
check_strict_reverse_path_filter_default() { c3_sysctl_is net.ipv4.conf.default.rp_filter 1; }
fix_strict_reverse_path_filter_default() { c3_sysctl_set net.ipv4.conf.default.rp_filter 1; }

rule ipv4-source-routing-refused-all "IPv4 source routing refused (all)"
check_ipv4_source_routing_refused_all() { c3_sysctl_is net.ipv4.conf.all.accept_source_route 0; }
fix_ipv4_source_routing_refused_all() { c3_sysctl_set net.ipv4.conf.all.accept_source_route 0; }

rule ipv4-source-routing-refused-default "IPv4 source routing refused (default)"
check_ipv4_source_routing_refused_default() { c3_sysctl_is net.ipv4.conf.default.accept_source_route 0; }
fix_ipv4_source_routing_refused_default() { c3_sysctl_set net.ipv4.conf.default.accept_source_route 0; }

rule martian-packets-logged-all "Martian packets logged (all)"
check_martian_packets_logged_all() { c3_sysctl_is net.ipv4.conf.all.log_martians 1; }
fix_martian_packets_logged_all() { c3_sysctl_set net.ipv4.conf.all.log_martians 1; }

rule martian-packets-logged-default "Martian packets logged (default)"
check_martian_packets_logged_default() { c3_sysctl_is net.ipv4.conf.default.log_martians 1; }
fix_martian_packets_logged_default() { c3_sysctl_set net.ipv4.conf.default.log_martians 1; }

rule tcp-syn-cookies-on "TCP SYN cookies on"
check_tcp_syn_cookies_on() { c3_sysctl_is net.ipv4.tcp_syncookies 1; }
fix_tcp_syn_cookies_on() { c3_sysctl_set net.ipv4.tcp_syncookies 1; }

rule no-routing-of-127-8-off-loopback "No routing of 127/8 off loopback"
check_no_routing_of_127_8_off_loopback() { c3_sysctl_is net.ipv4.conf.all.route_localnet 0; }
fix_no_routing_of_127_8_off_loopback() { c3_sysctl_set net.ipv4.conf.all.route_localnet 0; }

# ---- 3.3.2 IPv6 parameters (n/a when IPv6 is disabled) ----

rule ipv6-forwarding-off-all "IPv6 forwarding off (all)"
check_ipv6_forwarding_off_all() { c3_sysctl6_is net.ipv6.conf.all.forwarding 0; }
fix_ipv6_forwarding_off_all() { c3_sysctl_set net.ipv6.conf.all.forwarding 0; }

rule ipv6-forwarding-off-default "IPv6 forwarding off (default)"
check_ipv6_forwarding_off_default() { c3_sysctl6_is net.ipv6.conf.default.forwarding 0; }
fix_ipv6_forwarding_off_default() { c3_sysctl_set net.ipv6.conf.default.forwarding 0; }

rule ipv6-redirects-refused-all "IPv6 redirects refused (all)"
check_ipv6_redirects_refused_all() { c3_sysctl6_is net.ipv6.conf.all.accept_redirects 0; }
fix_ipv6_redirects_refused_all() { c3_sysctl_set net.ipv6.conf.all.accept_redirects 0; }

rule ipv6-redirects-refused-default "IPv6 redirects refused (default)"
check_ipv6_redirects_refused_default() { c3_sysctl6_is net.ipv6.conf.default.accept_redirects 0; }
fix_ipv6_redirects_refused_default() { c3_sysctl_set net.ipv6.conf.default.accept_redirects 0; }

rule ipv6-source-routing-refused-all "IPv6 source routing refused (all)"
check_ipv6_source_routing_refused_all() { c3_sysctl6_is net.ipv6.conf.all.accept_source_route 0; }
fix_ipv6_source_routing_refused_all() { c3_sysctl_set net.ipv6.conf.all.accept_source_route 0; }

rule ipv6-source-routing-refused-default "IPv6 source routing refused (default)"
check_ipv6_source_routing_refused_default() { c3_sysctl6_is net.ipv6.conf.default.accept_source_route 0; }
fix_ipv6_source_routing_refused_default() { c3_sysctl_set net.ipv6.conf.default.accept_source_route 0; }

rule kernel-router-adverts-off-all "Kernel router adverts off (all)"
check_kernel_router_adverts_off_all() { c3_sysctl6_is net.ipv6.conf.all.accept_ra 0; }
fix_kernel_router_adverts_off_all() { c3_sysctl_set net.ipv6.conf.all.accept_ra 0; }

rule kernel-router-adverts-off-default "Kernel router adverts off (default)"
check_kernel_router_adverts_off_default() { c3_sysctl6_is net.ipv6.conf.default.accept_ra 0; }
fix_kernel_router_adverts_off_default() { c3_sysctl_set net.ipv6.conf.default.accept_ra 0; }
