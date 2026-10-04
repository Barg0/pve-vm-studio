# CIS Ubuntu 26.04 chapter 4 - host firewall (UFW).
# shellcheck shell=bash
#
# Decisions
# - UFW is the firewall (the benchmark's only one). 4.1.2's fix allows in 22/tcp (and sshd's
#   own port when it differs) BEFORE `ufw --force enable`, so the clone stays reachable.
#   Any other inbound service on a clone needs its own `ufw allow`.
# - 4.1.4 (Level 2): allows out 53/tcp, 53/udp, 853/tcp, 123/udp, 80/tcp, 443/tcp, 67/udp
#   first, then default deny outgoing. Everything else outbound (ICMP echo, DHCPv6 547/udp,
#   LDAP/Kerberos, SMTP, proxies on other ports) is blocked on Level 2 clones.
# - Loopback: this benchmark version has no separate loopback recommendation; UFW's stock
#   before.rules already accept lo traffic, so nothing is added.
# - Checks read `ufw status verbose` like the benchmark: an inactive UFW shows no defaults and
#   fails 4.1.3-4.1.5 too. 4.1.5 accepts "disabled (routed)" when /etc/default/ufw has
#   DEFAULT_FORWARD_POLICY="DROP" (kernel forwarding off), as the benchmark notes.

c4_OUT_ALLOW="53/tcp 53/udp 853/tcp 123/udp 80/tcp 443/tcp 67/udp"

# rc 1 (with evidence) when ufw is missing.
c4_need_ufw() {
    pkg_installed ufw && command -v ufw >/dev/null 2>&1 && return 0
    ev "ufw: not installed"
    return 1
}

# The default policy UFW reports for DIR (incoming|outgoing|routed), "" when inactive.
c4_default() {
    ufw status verbose 2>/dev/null | awk '/^Default:/' | tr ',' '\n' \
        | sed -nE "s/.*[[:space:]]([a-z]+)[[:space:]]+\\($1\\).*/\\1/p" | head -n 1
}

c4_status() { ufw status 2>/dev/null | awk '/^Status:/ { print $2; exit }'; }

rule ufw-installed "ufw installed"
check_ufw_installed() {
    if pkg_installed ufw; then ev "ufw: installed"; return 0; fi
    ev "ufw: not installed"
    return 1
}
fix_ufw_installed() { pkg_installed ufw || pkg_install ufw; }

rule ufw-service-enabled-and-active "ufw service enabled and active"
check_ufw_service_enabled_and_active() {
    local st en act bad=0
    c4_need_ufw || return 1
    en=$(systemctl is-enabled ufw.service 2>/dev/null)
    act=$(systemctl is-active ufw.service 2>/dev/null)
    st=$(c4_status)
    ev "ufw.service: ${en:-none}, ${act:-none}; ufw status: ${st:-unknown}"
    [ "$en" = enabled ] || bad=1
    [ "$act" = active ] || bad=1
    [ "$st" = active ] || bad=1
    return $bad
}
fix_ufw_service_enabled_and_active() {
    local p
    c4_need_ufw >/dev/null || return 1
    ufw allow in 22/tcp >/dev/null || return 1
    p=$(sshd_val port)
    if [[ "$p" =~ ^[0-9]+$ ]] && [ "$p" != 22 ]; then
        ufw allow in "$p/tcp" >/dev/null || return 1
    fi
    systemctl unmask ufw.service 2>/dev/null
    systemctl enable --now ufw.service >/dev/null 2>&1
    ufw --force enable >/dev/null || return 1
    [ "$(c4_status)" = active ]
}

rule ufw-denies-incoming-by-default "ufw denies incoming by default"
check_ufw_denies_incoming_by_default() {
    local pol
    c4_need_ufw || return 1
    pol=$(c4_default incoming)
    ev "ufw: $(c4_status); incoming: ${pol:-not reported}"
    [ "$pol" = deny ] || [ "$pol" = reject ]
}
fix_ufw_denies_incoming_by_default() {
    c4_need_ufw >/dev/null || return 1
    ufw default deny incoming >/dev/null
}

rule ufw-denies-outgoing-by-default "ufw denies outgoing by default"
check_ufw_denies_outgoing_by_default() {
    local pol n
    c4_need_ufw || return 1
    pol=$(c4_default outgoing)
    n=$(ufw status 2>/dev/null | grep -c 'ALLOW OUT')
    ev "ufw: $(c4_status); outgoing: ${pol:-not reported}; allow-out rules: ${n:-0}"
    [ "$pol" = deny ] || [ "$pol" = reject ]
}
fix_ufw_denies_outgoing_by_default() {
    local r
    c4_need_ufw >/dev/null || return 1
    for r in $c4_OUT_ALLOW; do
        ufw allow out "$r" >/dev/null || return 1
    done
    ufw default deny outgoing >/dev/null
}

rule ufw-denies-routed-by-default "ufw denies routed by default"
check_ufw_denies_routed_by_default() {
    local pol fwd
    c4_need_ufw || return 1
    pol=$(c4_default routed)
    fwd=$(kv_get /etc/default/ufw DEFAULT_FORWARD_POLICY | tr -d '"')
    ev "ufw: $(c4_status); routed: ${pol:-not reported}; DEFAULT_FORWARD_POLICY=${fwd:-unset}"
    [ "$pol" = deny ] && return 0
    [ "$pol" = disabled ] && [ "$fwd" = DROP ]
}
fix_ufw_denies_routed_by_default() {
    c4_need_ufw >/dev/null || return 1
    ufw default deny routed >/dev/null
}
