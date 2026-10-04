# shellcheck shell=bash
# suse/3-network.sh - openSUSE Leap 16.0 (CIS SLE 16 v1.0.0) chapter 3: what differs from
# deb/ and el/. Sourced after both.
#
# Decisions
# - Everything in deb/3-network.sh is distro-neutral on Leap (modprobe.d, sysctl.d via
#   systemd-sysctl, bluez through pkg_purge = zypper) and is kept; no UFW file exists, so
#   c3_sysctl_* behave like sysctl_*. Our values land in /etc/sysctl.d/60-pvs-cis.conf, after
#   the vendor 50-default.conf (rp_filter=2 there is overridden by the strict 1).
# - 3.3.1.19 (SLE): route_localnet = 0 on the loopback interface itself (lo), not deb's "all"
#   nor EL9's "default".

rule route-localnet-lo-off "No routing of 127/8 off loopback (lo)"
check_route_localnet_lo_off() { c3_sysctl_is net.ipv4.conf.lo.route_localnet 0; }
fix_route_localnet_lo_off() { c3_sysctl_set net.ipv4.conf.lo.route_localnet 0; }
