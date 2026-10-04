# shellcheck shell=bash
# suse/4-firewall.sh - openSUSE Leap 16.0 (CIS SLE 16 v1.0.0) chapter 4: what differs from
# deb/ and el/. Sourced after both: el/4-firewall.sh's firewalld rules are kept, the
# version-dependent parts are set explicitly here instead of riding on el's "VERSION_ID >= 10"
# branch (Leap's 16.0 happens to land in it).
#
# Decisions
# - firewalld is not on the image: 4.1.1 installs it (zypper), 4.1.3 enables it - ssh +
#   dhcpv6-client (and sshd's port when not 22) go into the default zone first (el's order).
# - 4.1.2: FirewallBackend=nftables written out in /etc/firewalld/firewalld.conf (the text
#   reads that file). When only a vendor copy exists, kv_set seeds /etc from it first.
# - 4.1.6: the loopback anti-spoofing rich rules use 127.0.0.1 and ::1 (SLE 16's form).
# - 4.1.8 (L1 on SLE, studio decision: fixed at L1): default zone drop, ssh + dhcpv6-client
#   allowed in it, ICMP errors and IPv6 neighbour/router discovery allowed (el's inversion),
#   outbound open (DNS/Kerberos/LDAP for a domain join; replies ride conntrack). The suse fix
#   verifies at runtime that the drop zone answers for ssh after the switch, and puts the
#   previous default zone back if it does not - a clone must never lose SSH.

rule firewalld-backend-nftables "firewalld backend nftables"
check_firewalld_backend_nftables() {
    local b
    if [ ! -f "$E4_CONF" ]; then
        ev "$E4_CONF: missing (in effect: $(effective_file "$E4_CONF"))"
        return 1
    fi
    b=$(kv_get "$E4_CONF" FirewallBackend)
    ev "FirewallBackend=${b:-unset}"
    [ "${b,,}" = nftables ]
}
fix_firewalld_backend_nftables() {
    e4_installed || return 1
    [ -f "$E4_CONF" ] && [ "$(kv_get "$E4_CONF" FirewallBackend | tr '[:upper:]' '[:lower:]')" = nftables ] && return 0
    kv_set "$E4_CONF" FirewallBackend nftables =
    chmod 0644 "$E4_CONF"
    # A backend change needs a restart, not a reload.
    systemctl try-restart firewalld.service 2>/dev/null
    return 0
}

e4_lo_rules() {
    printf 'rule family="ipv4" source address="127.0.0.1" destination not address="127.0.0.1" drop\n'
    printf 'rule family="ipv6" source address="::1" destination not address="::1" drop\n'
}

fix_firewalld_default_zone_drop() {
    local t old
    e4_installed || return 1
    old=$(e4_default_zone)
    e4_allow_ssh drop || return 1
    if [ "$(e4_perm --zone=drop --query-icmp-block-inversion 2>/dev/null)" != yes ]; then
        e4_perm --zone=drop --add-icmp-block-inversion >/dev/null || return 1
    fi
    for t in $E4_ICMP_ALLOW; do
        [ "$(e4_perm --zone=drop --query-icmp-block="$t" 2>/dev/null)" = yes ] && continue
        e4_perm --zone=drop --add-icmp-block="$t" >/dev/null || return 1
    done
    e4_reload
    [ "$old" = drop ] || e4_set_default_zone drop || return 1
    e4_reload
    # Running: the drop zone must answer for ssh now, else the previous default zone comes back.
    if e4_running && [ "$(firewall-cmd --zone=drop --query-service=ssh 2>/dev/null)" != yes ]; then
        echo "drop zone does not allow ssh at runtime - default zone set back to ${old:-public}"
        e4_set_default_zone "${old:-public}"
        e4_reload
        return 1
    fi
    return 0
}
