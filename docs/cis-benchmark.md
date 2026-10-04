# CIS Benchmark hardening for Linux golds - research and design

Status: design decided 2026-10-04 (section 8); building L1 + L2 Server for Ubuntu 26.04.

The plan is CIS Level 1 **and** Level 2 Server, starting with **Ubuntu 26.04 LTS**. Other distributions follow once their benchmarks are here: CIS publishes one per distribution, and the user will provide them.

This document is written so that **Hyper-V VM Studio** can adopt the same approach. Proxmox-specific notes are marked **[PVE]**, and what changes on Hyper-V is in the last section.

Source: *CIS Ubuntu Linux 26.04 LTS Benchmark v1.0.0* (PDF, 1,138 pages). It is not stored in the repository, see the licence section. Recommendations are cited by their CIS number only.

---

## 1. The benchmark in numbers (Ubuntu 26.04, v1.0.0)

| | Count |
|---|---|
| Recommendations | **351** (333 automated, 17 manual, 1 section heading) |
| Level 1 on Server **and** Workstation | 265 |
| Level 2 on Server **and** Workstation | 75 |
| Differs between Server and Workstation | 11 |

Chapters: 1 Initial Setup (filesystem, packages, AppArmor, bootloader, process hardening, banners, GDM) · 2 Services · 3 Network · 4 Host firewall (UFW) · 5 Access control (SSH, sudo, PAM, accounts) · 6 Logging and auditing (journald/rsyslog, auditd, AIDE) · 7 System maintenance (file permissions, users and groups).

### What Level 2 adds on top of Level 1

| Area | L2-only | What it is |
|---|---|---|
| 6.2 System auditing | **54** | auditd: the rule set, log handling, file modes, `-e 2` immutable |
| 1.1 Filesystem | 8 | **separate partitions** for `/home`, `/var`, `/var/tmp`, `/var/log`, `/var/log/audit`, plus two kernel modules on workstations |
| 6.1 Logging | 3 | journald and rsyslog details |
| 5.4 Accounts | 2 | minimum password days and similar |
| 1.2, 1.3, 1.5, 1.7, 2.1, 2.3, 4.1, 5.2, 5.3, 6.3 | 1 each | weak apt dependencies, **AppArmor profiles enforcing**, process hardening, GDM, X server off (server), time sync, **UFW outgoing default deny**, sudo needs a password, faillock includes root, integrity of the audit tools |

Server and Workstation differ in 11 places. Server is stricter about firewire, usb-storage, autofs, avahi, cups, bluetooth, wireless and GDM automount (L1 on Server, L2 on Workstation). `update-notifier-motd.timer` is Server-only, and "no X server" is L2 Server-only.

### The 17 manual recommendations

These cannot be automated as a whole. The studio decides each one and writes down why: unused filesystem modules (1.1.1.11), `Signed-By` in apt sources, updates installed, only approved listeners, IPv6 status, unneeded network protocol modules, SSH post-quantum key exchange, password complexity, minimum password days, journald access and rotation, rsyslog configuration, remote syslog host, logrotate, rsyslog CA, the running audit configuration matching the one on disk, and the SUID/SGID review.

---

## 2. Tooling (state on 2026-10-04)

| Tool | Ubuntu 26.04 | Licence / cost | Use for us |
|---|---|---|---|
| **ComplianceAsCode** ("SCAP Security Guide") | Product `ubuntu2604` added 2026-05-19, with only a `default` profile. **CIS Level 1** Server and Workstation (274 controls, 447 rules) is in [PR #15097](https://github.com/ComplianceAsCode/content/pull/15097): approved by a maintainer, still waiting on Ubuntu's maintainers. **No Level 2.** Latest release v0.1.82 (2026-09-01). For 24.04, all four CIS profiles exist (they target CIS 24.04 v1.0.0). | BSD-3-Clause | **Level 1 remediation and scanning** (bash or Ansible, plus an SCAP datastream) |
| **OpenSCAP** | `openscap-scanner` 1.4.3 is in 26.04 universe. The archive's `scap-security-guide` 0.1.79 is too old for 26.04 CIS content, so we build the datastream ourselves. | LGPL | the scan: `oscap xccdf eval`, ARF and HTML report |
| **Canonical USG** (`usg`, Ubuntu Pro) | Docs stop at 24.04; 26.04 not shipped. Built from ComplianceAsCode, so it follows that PR. | needs Ubuntu Pro (free tier: 5 machines) | later, optional: `usg fix/audit cis_level{1,2}_{server,workstation}`. Needs `pro attach` in the bake and `pro detach` before generalizing. |
| **Ansible Lockdown** `UBUNTU26-CIS` | remediation repository empty, the audit repository (goss) work in progress | MIT | not usable yet; `UBUNTU24-CIS` 1.7.0 is the 24.04 model |
| **CIS-CAT** | Pro supports 26.04 | Lite is not meant for products; Pro needs CIS SecureSuite membership | not for us |
| **AIDE** | 0.19.2 in main | GPL | integrity checking (6.3) |

Links:
- https://ubuntu.com/security/certifications/docs/usg/cis
- https://documentation.ubuntu.com/security/compliance/usg/install-usg/
- https://discourse.ubuntu.com/t/cis-compliance-with-usg-for-ubuntu-24-04-lts/56178
- https://github.com/ComplianceAsCode/content
- https://ansible-lockdown.readthedocs.io/en/latest/CIS/CIS_table.html
- https://www.cisecurity.org/benchmark/ubuntu_linux

**Consequence:** no existing tool covers Level 2 on 26.04. Level 1 can come from ComplianceAsCode, built from the PR branch until it merges, with the source revision recorded. Level 2 we write ourselves from the benchmark's remediation sections. For a deterministic result we may write Level 1 the same way; see the decision in section 8.

---

## 3. Licence and wording

- The benchmark PDF is **CC BY-NC-SA 4.0** (https://www.cisecurity.org/terms-of-use-for-non-member-cis-products). Commercial use needs CIS's approval, and a modified version "is no longer a CIS Benchmark". **Do not put the PDF in the repository, and do not copy its text** (rationale, audit and remediation prose). The code cites recommendation numbers and implements the settings.
- Without CIS membership, never say "CIS certified", "CIS hardened" or "CIS compliant". Say instead:
  *"Configured per the CIS Ubuntu Linux 26.04 LTS Benchmark v1.0.0, Level 2 Server - self-assessed: 97% (12 documented exceptions)."*
- ComplianceAsCode content is BSD-3-Clause; its CIS mapping is attributed to CIS.

---

## 4. Architecture (independent of the hypervisor)

```
bake VM (cloud image)
  ├─ cloud-init: packages, region, the studio's own features
  ├─ CIS pass 1   remediation of the chosen profile + tailoring (exceptions)
  │               Level 2: partition layout (section 6), auditd rules
  ├─ reboot       auditd -e 2 and the new mounts take effect only now
  ├─ CIS scan     oscap + the studio's own checks → ARF/HTML + JSON summary
  ├─ generalize   cloud-init clean, SSH host keys, machine-id, logs (incl. /var/log/audit)
  └─ template     the sidecar carries: benchmark, version, profile, score, exceptions, report
clone (first boot, per instance)
  └─ AIDE database init · SSH host keys · the admin user with a password (sudo needs one)
```

- **Profiles:** `off` · `L1 Server` · `L2 Server` (Workstation out of scope).
- **Tailoring:** each exception is a recommendation number plus a reason, shown with the gold. Defaults are in section 5. The user can change them per bake.
- **Evidence:** the gold's sidecar gets
  ```json
  "cis": { "benchmark": "CIS Ubuntu Linux 26.04 LTS", "version": "1.0.0",
           "profile": "level2_server", "score": 97.1, "pass": 330, "fail": 0,
           "exceptions": [{"id":"1.4.1","why":"..."}], "tool": "openscap 1.4.3 + content <rev>",
           "report": "cis-<gold>.html" }
  ```
  The gold card shows `CIS L2 Server · 97% · 12 exceptions` and links to the report.
- **Rescan:** a "Scan a VM" job later re-runs the scan on a running clone (the guest agent executes the scanner) to catch drift.

---

## 5. Conflicts with cloud images, templates and cloud-init

| CIS | Conflict | Resolution (default) |
|---|---|---|
| 1.1.2.x separate partitions (L2) | the cloud image has one ext4 root | **L2: build the layout in the bake (section 6).** L1: `/tmp` as tmpfs with `nodev,nosuid,noexec`, `/dev/shm` options in fstab. The other mount-option rules apply only where the partition exists. |
| 1.1.1.x unused filesystems | `iso9660` must stay: the cloud-init seed is an ISO (NoCloud on PVE and on Hyper-V). `squashfs` is snaps, `overlay` is containers. | block the rest. `iso9660` is always an exception; `squashfs`/`overlay` per bake option. |
| 1.4.1 bootloader password | one hash on every clone; a prompt would stop unattended boots | set it with `--unrestricted` menu entries (normal boot needs no password). Optional exception. The hash per gold is kept in the studio's secrets. |
| 4.1.x UFW default deny (L2: outgoing too) | locks out SSH, and the outgoing default breaks apt and NTP | allow 22/tcp (and what the VM's roles need) **before** enabling. L2 outgoing: allow DNS, NTP, HTTP(S) to the mirrors, or make it an exception per design. The guest agent is not affected (virtio-serial / VMBus). |
| 5.1.5 sshd `AllowUsers/Groups` | clones lock out the admin user that cloud-init creates | `AllowGroups` = the studio's admin group (plus configured groups) |
| 5.1.x sshd settings | cloud-init writes `sshd_config.d/50-cloud-init.conf`, and sshd takes the **first** value it reads | write CIS settings into `sshd_config.d/00-cis.conf` |
| 5.2.4 sudo needs a password (L2) | a key-only admin with no password is stranded | the studio always gives the admin user a password (it already generates one) |
| 5.4.1.x password aging, inactive lock | an expired password blocks even SSH key logins (pam_unix account) | PASS_MAX_DAYS 365 / INACTIVE 45 as CIS says; the studio sets the user's password date at first boot |
| 6.2.x auditd (L2: 54 rules) | `-e 2` is immutable until reboot; "halt on full log" kills a VM with a small disk | reboot before the final scan; `space_left_action=email`/`syslog` instead of halt (exception with reason) unless `/var/log/audit` has its own LV (L2 layout) |
| 6.3.x AIDE | a database built on the gold alerts on every clone (hostname, keys, netplan, machine-id) | install and configure in the bake; **`aideinit` on each clone's first boot** (cloud-init per-instance) |
| 1.3.1.3 AppArmor all enforcing (L2) | can break software installed later | enforce; complain mode is an exception per design |
| generalize | logs and IDs from the bake | `cloud-init clean --logs --machine-id --seed`, remove SSH host keys, empty `/var/log/audit` and the journal. With USG: `pro detach`. |
| `/tmp` noexec | anything that runs `./script` from `/tmp` breaks | checked 2026-10-04: the studio only calls interpreters on `/tmp` (`bash /tmp/install_linux_azcmagent.sh` for Azure Arc, `apt-get install /tmp/fastfetch.deb`), and both work with noexec. **Test the Arc installer**, which may start helpers from `/tmp` itself. |

---

## 6. Level 2 partitions on a cloud image (design)

CIS L2 wants its own filesystems for `/home`, `/var`, `/var/tmp`, `/var/log` and `/var/log/audit`, each with the mount options of 1.1.2.x. The cloud image ships one root partition plus ESP and BIOS-boot. Plan, all inside the bake VM (the studio does not touch disks from outside **[PVE rule]**):

1. The bake disk is created larger (e.g. 32 GiB). `growpart` is off for this bake, so the root partition keeps its size (resized to e.g. 10 GiB at most).
2. Pass 1, early (`bootcmd`):
   - create one partition in the free space as an LVM PV;
   - create a VG with LVs `home`, `var`, `vartmp`, `varlog`, `varaudit`, sized by ratios of the disk;
   - `mkfs.ext4` them, `rsync -aHAX` the current content over, write the fstab entries with the CIS options.
3. Reboot. The new mounts are active; the old copies under the mount points are removed through a bind mount of `/`.
4. Clones: a disk grown at deploy grows the **PV**, not the root. `growpart` on the PV partition, then `pvresize`, then `lvextend -r` of `var` (and `home`), done once at first boot.

Risk: copying a running `/var`. Mitigation: do it in `bootcmd`, before most services, and reboot right away. This is how Packer-based hardened images handle it.

---

## 7. Ubuntu 26.04 specifics we already know

- **[PVE]** The studio's Linux bake is cloud-init user-data in a bake VM (`src/linux.rs`, `bake_user_data`), followed by generalize and template. Clones get their own user-data (`vm_user_data`). CIS hooks in at both points.
- Time sync: 26.04 uses systemd-timesyncd. CIS wants exactly one daemon (2.3.1.1) and an authorized server (2.3.2.1); the studio sets its NTP server(s) there.
- `apt` sources in deb822 `.sources` files with `Signed-By` (1.2.1.1), HTTPS mirrors (1.2.1.10/11): the cloud image uses HTTP for archive.ubuntu.com, so switch to HTTPS.

---

## 8. Decisions taken and still open

Taken (user, 2026-10-04):
- Full **Level 1 and Level 2**, **Server profiles only** - the studio builds Linux servers;
  the Workstation profiles and the desktop (GDM) recommendations are out of scope.
- **Ubuntu 26.04 first.** Other distributions once their benchmarks are provided.
- Document for adoption by Hyper-V VM Studio (this file).
- **Own rules for L1 and L2** (decided 2026-10-04): one rule set, each CIS number with a
  check and a fix, written from the benchmark's settings (not its text). OpenSCAP with
  ComplianceAsCode stays an independent second opinion for L1 once PR #15097 merges (still
  open 2026-10-04, one approval).
- **Level 2 checks** are the same rule set's checks.
- **Default exceptions:** `iso9660` allowed (the cloud-init seed); GRUB password set but menu
  entries `--unrestricted` (no prompt at boot); UFW outgoing allows DNS, NTP, HTTP(S) (L2).
  The audit "halt on full log" stays as CIS wants it - L2 gives `/var/log/audit` its own
  volume, and auditd is L2-only.
- **L1 + L2 in one slice**, including the L2 partition layout.

Open:
1. Where the report lives (see the options given to the user 2026-10-04).

---

## 9. Notes for Hyper-V VM Studio

- The architecture (section 4), the conflicts (section 5) and the partition plan (section 6) carry over unchanged. They all run inside the guest, through cloud-init.
- **The seed** on Hyper-V is also NoCloud on an ISO (or VHDX), so `iso9660` stays allowed. If the seed comes over KVP instead, that changes.
- **Integration services:** never block the `hv_*` modules (`hv_vmbus`, `hv_netvsc`, `hv_storvsc`, `hv_utils`, `hv_balloon`) or the `hyperv-daemons` (KVP, VSS, FCOPY). They are the guest agent's counterpart. The unused-filesystem and network-protocol module lists must not touch them.
- **Generation 2 + Secure Boot:** unchanged by CIS. The bootloader password works the same way (GRUB with `--unrestricted`).
- **The disk** is a VHDX that the template copies or differences. The L2 PV/LV layout and the first-boot `pvresize` work the same way on a differencing disk.
- The bake there is PowerShell (New-Vhdx style), but the hardening runs in the guest, so the remediation scripts and the scanner call are shared as they are.

---

## 10. As built (2026-10-04, Ubuntu 26.04, L1 + L2 Server - first bake pending)

- **Rules:** `guest-files/cis/` - the engine `pvs-cis` (bash: `fix`, `check --json`, `list`),
  `lib.sh` helpers, one file per chapter range in `ubuntu2604/`. Each recommendation is a
  `rule <id> <level> <auto|manual> "<own title>"` with `check_<id>` (evidence on stdout,
  rc 0 pass / 1 fail / 2 n/a / 3 review) and `fix_<id>`. Format: `guest-files/cis/README.md`.
  All 350 recommendations are registered.
- **Bake, first boot:** bootcmd copies the bundle from the seed disk (`pvs-cis/`) to
  `/usr/local/lib/pvs-cis`; Level 2: `layout.sh prepare` (root → 12 GiB, the rest one LVM PV,
  VG `pvs`: varaudit 15%, varlog 15%, vartmp 10%, var 35%, home 15%). runcmd: packages and
  features as always, Level 2 purges snapd (squashfs goes), `pvs-cis fix`, the GRUB password
  stashed in /root, units installed; cloud-init `power_state: reboot`.
- **Second boot:** `pvs-cis-layout.service` (before local-fs) copies /var, /var/log,
  /var/log/audit, /var/tmp, /home into their LVs with tar, empties the old directories,
  writes fstab with the CIS options, mounts. `pvs-cis-finish.service`: removes the bake
  account, `pvs-cis check` → `/run/pvs-cis/report.json`, enables the clone units, runs the
  generalize script (the same steps as a plain bake), BAKE-OK.
- **Studio:** reads the report and the GRUB password through the agent, keeps them in
  `cis-reports/<gold>.json` / `.grub` (0600), puts the summary into the manifest (`cis`) and
  the template notes. Gold card badge "CIS L2 · 97%" opens the report (filters, search,
  evidence, HTML/JSON download, GRUB password for admins).
- **Clones:** `pvs-cis-aide-init.service` builds the AIDE database on the first boot;
  `pvs-cis-grow.service` grows the PV and /var when the disk was enlarged; sudo asks for the
  password (5.2.4); `apt: preserve_sources_list` keeps the gold's HTTPS sources.
- **Known effects of Level 2 on clones:** no snaps, no containers (overlay off), outbound only
  DNS/NTP/HTTP(S)/DHCP - **a domain join (LDAP/Kerberos) is blocked by the outbound firewall**
  (open question), cron/at for root only, NFS/CIFS client modules off (1.1.1.11 decision).

## 11. First bake, first clone, second opinion (2026-10-04)

**Bake (gold 94e80daa, Level 2 Server):** fix → reboot → check → seal in under 5 minutes.
316 fixes applied, 0 failed. Check: 305 pass, 23 fail, 8 review, 14 n/a (93%). The Level 2
volumes migrated cleanly (root 12 GiB, VG `pvs` 26.9 GiB on a 40 GiB disk).

The 23 failures, five causes, all fixed since:
- 18 audit watch rules (6.2.3.x): `auditctl -l` prints a path/dir watch **without**
  `-F arch=b64`; the matcher compared the arch field. Watches now ignore arch.
- 6.2.3.35: the check trimmed `-e 2` through `xargs`, which runs `echo -e 2` → "2".
- 2.2.6 `ftp-ssl` and 6.2.3.10 `dotlockfile`: pulled in by fixes of later chapters (auditd,
  aide). The bake now runs chapter 2 and 6.2.3.10 a second time at the end.
- 5.4.2.5: `/snap/bin` stayed in `/etc/environment` after snapd was purged (Level 2).

**Clone (cis-01 from that gold):** AIDE database built on first boot, `/var` on its own
volume, outbound firewall deny with the allows, admin password set (hash, past PAM), sudo
asks for it, audit locked, apt kept HTTPS sources. Works as designed.

**Second opinion: OpenSCAP 1.4.3 + ComplianceAsCode PR #15097**
(realstuffie/content@468a0e1, profile cis_level1_server) on cis-01, compared per
recommendation (274 L1): 217 both pass, 1 both fail (2.2.6, known), 31 disagree.
OpenSCAP was right three times - all fixed:
- `lib.sh` kv_get/kv_set did not see tab-separated keys (`PASS_MAX_DAYS<TAB>99999` stayed
  beside ours) - the regex now takes blanks or `=`.
- Log files created on the clone at 0644 (aideinit; apt's daily runs) - `UMask=0027` on the
  AIDE unit and drop-ins for apt-daily(-upgrade).
- The fastfetch feature left `/etc/skel/.config` at 0755 → every new user fails 7.2.11.
The other 28 are OpenSCAP being stricter or reading differently than the CIS audit text
(underscore module names, values CIS allows ranges for, main config file only instead of
drop-ins, explicit sshd allow-lists). Full table: kept outside the repo (the agent's notes).

**Are the studio's choices necessary? (review)**
| Choice | Needed? | Why |
|---|---|---|
| Own rules instead of a tool | yes, for now | no tool covers 26.04 L2; L1 PR still unmerged |
| fix → reboot → check | yes | kernel parameters, mounts, audit `-e 2` only hold after a reboot |
| L2 volumes built in the bake | yes | CIS L2 1.1.2.3-7; a cloud image has one partition |
| snapd purged at L2 | yes (or an exception) | L2 turns squashfs off (1.1.1.7) - snaps cannot mount |
| overlay off at L2 | CIS | no containers; a Docker host needs an exception for 1.1.1.6 |
| iso9660/vfat kept loadable | yes | the clone's seed; udf is turned off (PVE seeds are FAT) |
| GRUB `--unrestricted`, UFW outgoing allows | no exception needed | both are CIS's own remediation |
| AllowGroups sudo pvs-ssh | CIS needs one | domain users must be put in pvs-ssh |
| IPv6 kept, net module deny list, no remote log host | manual recs | decisions, shown as "review" |
| L2 egress blocks LDAP/Kerberos | open | decision pending: open the AD ports on domain-joined VMs? |

## 12. The other distributions (research 2026-10-04, from the user's ten benchmark PDFs)

Parsed the same way as 26.04 (number, Server level, automated/manual - no text kept).
"Same" = same recommendation title as Ubuntu 26.04 (what the rule checks), "same id" = also the
same number.

| Benchmark | Recs | L1 / L2 Srv | Manual | Same as U26.04 | Same id | Genuinely new |
|---|---|---|---|---|---|---|
| Ubuntu 26.04 v1.0.0 (built) | 350 | 274 / 76 | 17 | - | - | - |
| **Debian 13 v1.1.0** | 350 | 274 / 76 | 17 | **350** | **350** | 0 |
| Ubuntu 24.04 v2.0.0 | 332 | 258 / 74 | 15 | 325 | 259 | 7 |
| Debian 12 v2.0.0 | 333 | 259 / 74 | 15 | 326 | 260 | 7 |
| AlmaLinux / Oracle / Rocky 9 v3.0.0 | 352 | 263 / 89 | 23 | 289 | 201 | 52 |
| AlmaLinux / Oracle / Rocky 10 v1.0.0 | 328 | 248 / 80 | 21 | 291 | 129 | 34 |

Findings:
- **Debian 13 is Ubuntu 26.04's benchmark** recommendation for recommendation (numbers,
  levels, kinds). The rule set carries over; what differs is underneath (Debian's packages,
  classic sudo instead of sudo-rs, no snapd, its cloud image's defaults) - a test bake, not
  new rules.
- **Ubuntu 24.04 and Debian 12** are the previous generation: 7 recommendations that 26.04
  dropped (AppArmor restrict_unprivileged_unconfined, sshd ListenAddress, a few audit rules
  in another cut) and ~70 that moved number.
- **Enterprise Linux 9: AlmaLinux, Oracle and Rocky share one text** (4 lines differ: the
  name). **EL10 likewise** (328/328 identical; only the PDF layout differs). Two rule sets
  cover six distributions. EL10 shares 310 of its 328 with EL9.
- What is genuinely Enterprise Linux (~50 in EL9, ~35 in EL10): **SELinux** instead of
  AppArmor (1.3.1.x, enforcing at L2), **system-wide crypto policies** (1.6.x), **firewalld**
  instead of UFW (4.1.x), **authselect** instead of pam-auth-update (5.3.x), dnf/gpgcheck
  (1.2.1.x), rescue/emergency mode authentication, cockpit, chrony as the time service,
  systemd-journal-remote/upload, NetworkManager instead of netplan in the audit rules.
- Not covered by any CIS benchmark: **Fedora, Arch, openSUSE Leap 16** (CIS publishes
  SUSE Linux Enterprise only) - these images get no CIS option.

**Consequence for the rule set (design change before the next distribution):** the numbers
move between versions while the checks stay the same, so rules should be keyed by what they
check, not by number:
```
lib/<key>.sh           check_<key> / fix_<key>, shared:   sshd-permitrootlogin, kmod-cramfs, ...
<bench>/map.tsv        5.1.20 <tab> 1 <tab> auto <tab> sshd-permitrootlogin   (per benchmark)
<bench>/<family>.sh    what only that family needs: apt|dnf, ufw|firewalld, apparmor|selinux,
                       pam-auth-update|authselect
```
The map is generated from the PDF (numbers, levels, kinds - no CIS text) plus our key per
title; a test checks every recommendation of every benchmark has a check.

**Suggested order:** Debian 13 (test bake only) → Ubuntu 24.04 + Debian 12 (7 rules, the
map) → EL9 (one set, three distributions; ~50 rules: SELinux, crypto policy, firewalld,
authselect) → EL10. Second opinions exist: ComplianceAsCode has CIS profiles for
ubuntu2404, debian12 and rhel9/almalinux9/ol9.

## 13. Restructure and Debian 13 (2026-10-04, built and baked)

- **Rules keyed by check, maps per benchmark** (section 12's design): `guest-files/cis/deb/`
  holds the Debian family's 350 rules (`rule <key> "<title>"`), `ubuntu2604/map.tsv` and
  `debian13/map.tsv` the numbers/levels/kinds. A test checks every key of every map has a
  check. Debian 13 = Ubuntu 26.04's map, unchanged.
- **Debian 13 Level 2: 99.4% on the first working bake** (312 pass, 2 fail, 6 review, 30 n/a);
  all 316 fixes applied without a failure. The 2 failures (log_martians 3.3.1.16/17): Debian's
  image has no UFW, chapter 4 installs it after chapter 3, and UFW's own
  `/etc/ufw/sysctl.conf` wins - the second fix pass now re-applies 3.3.x.
- **Level 2 volumes made on the second boot.** Debian grows its root to the whole disk
  before cloud-init (cloud-initramfs-growroot, then x-systemd.growfs); a mounted ext4 does not
  shrink. Now: the bake VM starts with a 12 GiB disk; the first boot sets
  `/etc/growroot-disabled` (the package's switch), installs lvm2 and marks the layout wanted;
  the studio grows the disk when the guest agent answers; the second boot's
  `pvs-cis-layout.service` (before local-fs) creates the partition, the VG and the LVs and
  moves the content. Waiting for the disk inside cloud-init deadlocked: qemu-guest-agent only
  starts after cloud-init's stages.
- **The first boot's report survives the reboot** (`/etc/pvs-cis/boot1.report`), so kernel,
  package and locale checks still judge a CIS bake.
