# pvs-cis - CIS hardening inside a Linux gold

`pvs-cis` applies and checks a CIS Benchmark inside the guest. The studio copies this folder
onto the bake's seed disk; the bake installs it to `/usr/local/lib/pvs-cis` (engine at
`/usr/local/sbin/pvs-cis`), runs `pvs-cis fix` in cloud-init, reboots, and runs
`pvs-cis check` from `pvs-cis-scan.service`. The same files work on Hyper-V VM Studio: nothing
here knows the hypervisor. Design: `docs/cis-benchmark.md`.

Licence: the benchmarks are CC BY-NC-SA. Rules cite the recommendation number and carry **our
own** short title; never copy CIS text (titles, rationale, audit or remediation prose).

## Layout

```
pvs-cis              the engine (bash)
lib.sh               helpers every family uses
layout.sh            Level 2's separate filesystems (LVM), bake and clone
<family>/<n>-*.sh    the rules of one family, chapter by chapter: deb = Ubuntu and Debian
<bench>/bench.conf   name, version, distro id and family of one benchmark
<bench>/map.tsv      CIS number <tab> level <tab> auto|manual <tab> rule key
```

Rules are keyed by **what they check**, not by number: the numbers move between benchmark
versions (Ubuntu 24.04 vs 26.04: ~70 renumbered), the checks stay. A benchmark is its map
over a family's rules; Debian 13 v1.1.0 has Ubuntu 26.04 v1.0.0's map, number for number.
The map carries numbers, levels and kinds only - no CIS text.

## A rule

```bash
rule sshd-permitrootlogin-off "sshd: root login off"
check_sshd_permitrootlogin_off() { sshd_is permitrootlogin no; }
fix_sshd_permitrootlogin_off()   { sshd_set PermitRootLogin no; }
```

`rule <key> "<own short title>"` registers it; the functions are the key with dashes as
underscores. A benchmark's map decides whether it runs, under which number and level.

**check** writes its evidence to stdout (what it found - one or a few lines, no prose) and
returns:

| rc | status | meaning |
|---|---|---|
| 0 | pass | |
| 1 | fail | |
| 2 | na | does not apply here (the package is not installed, no GDM, ...) |
| 3 | review | a manual recommendation: the evidence and the studio's decision, for a human |

A missing check is reported as `error`.

**fix** makes the check pass and must be idempotent (it runs once per bake, but may run
again). It runs as root in cloud-init's runcmd on the bake's first boot, with network and apt.
A fix that is only effective after a reboot is fine - the check runs after one. A fix may be
missing (manual rules, rules the bake satisfies another way); `fix` then logs `none`.

Rules are applied in file order, then id order within a file. A fix that depends on another
(install the package before configuring it) says so by order, not by calling it.

## What a fix must never break

- The clone's first boot: cloud-init NoCloud reads its seed from an ISO or a small FAT disk
  (`iso9660`, `vfat` stay loadable), DHCP on systemd-networkd/netplan, the qemu-guest-agent
  (virtio-serial; on Hyper-V the `hv_*` modules and hyperv-daemons).
- SSH login of the admin user cloud-init creates on the clone: key or password, member of
  `sudo`. sshd settings go to `/etc/ssh/sshd_config.d/00-pvs-cis.conf` (sshd keeps the first
  value it reads; cloud-init's own file is `50-cloud-init.conf`).
- The bake's own report: `/run/pvs-bake.report` must stay writable and readable by the agent.

## Helpers (lib.sh)

Evidence: `ev "..."`. Packages: `pkg_installed`, `pkg_install`, `pkg_purge`. Services:
`svc_enabled`, `svc_active`, `svc_off`. Kernel modules: `mod_unavailable`, `mod_disable`.
sysctl: `sysctl_is`, `sysctl_set`. sshd: `sshd_val`, `sshd_is`, `sshd_set`. Key/value files:
`kv_get`, `kv_set`. Files: `perm_ok`, `perm_set`. Mounts: `mount_has`, `fstab_opts`.
Audit: `audit_has`, `audit_add`. See the comments in lib.sh for the exact contracts.
Chapter-specific helpers live in the chapter's file, prefixed with `c<n>_`.
