# shellcheck shell=bash
# CIS AlmaLinux/Oracle/Rocky Linux 9 v3.0.0 and 10 v1.0.0 - chapter 3: network devices,
# network kernel modules, network kernel parameters. Builds on deb/3-network.sh: everything
# there is distro-neutral (modprobe.d, sysctl.d, bluez is the package name on EL too) and is
# kept; this file only adds the rule EL9 has beyond it.
#
# Decisions
# - UFW's sysctl file: c3_ufw_sysctl_file finds no /etc/default/ufw on EL and returns nothing;
#   sysctl_set skips a missing /etc/ufw/sysctl.conf. The deb sysctl rules run unchanged.
# - Kernel modules: EL keeps dccp/sctp/rds/tipc/atm/can in kernel-modules-extra, which cloud
#   images do not install - mod_unavailable then passes with "no module"; the fixes still write
#   their modprobe.d entries.
# - IPv6 stays enabled (3.1.1 review); the 3.3.2 values are set as on Debian. accept_ra = 0:
#   NetworkManager handles router advertisements itself, SLAAC keeps working.
# - 3.3.1.20 (EL9 only): route_localnet = 0 for new interfaces too, next to deb's "all".

rule route-localnet-default-off "No routing of 127/8 off loopback (default)"
check_route_localnet_default_off() { c3_sysctl_is net.ipv4.conf.default.route_localnet 0; }
fix_route_localnet_default_off() { c3_sysctl_set net.ipv4.conf.default.route_localnet 0; }
