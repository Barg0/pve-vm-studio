# Notices, sources and trademarks

PVE VM Studio is MIT-licensed (see [LICENSE](LICENSE)). It stands on a lot of other people's work.
This page lists all of it: what the studio downloads while it runs, the programs it calls, the
data it ships, the libraries compiled into it, and the trademarks it mentions.

## Trademarks

The names below belong to their owners. They are used here only to say what the studio works
with. None of the owners is affiliated with this project, sponsors it or endorses it.

| Trademark | Owner |
|---|---|
| Proxmox, Proxmox VE, Proxmox Mail Gateway | Proxmox Server Solutions GmbH |
| CIS®, CIS Benchmarks™, CIS-CAT® | Center for Internet Security, Inc. |
| Microsoft, Windows, Windows Server, Hyper-V, Azure, Azure Arc, Active Directory, Exchange | Microsoft Corporation |
| Ubuntu | Canonical Ltd. |
| Debian | Software in the Public Interest, Inc. |
| Fedora, Red Hat, RHEL | Red Hat, Inc. |
| Rocky Linux | Rocky Enterprise Software Foundation |
| AlmaLinux | AlmaLinux OS Foundation |
| Oracle Linux | Oracle Corporation |
| openSUSE, SUSE, SLE | SUSE LLC |
| Arch Linux | Arch Linux / Software in the Public Interest, Inc. |
| Linux® | Linus Torvalds |
| Let's Encrypt | Internet Security Research Group |
| GitHub | GitHub, Inc. |

## CIS Benchmarks

The CIS hardening is this project's own work. Its rules map to the recommendation numbers and
profile levels of the CIS Benchmarks, so a result can be compared with the benchmark. The
repository contains **no text from the CIS Benchmarks**: no titles, descriptions, audit or
remediation procedures. The benchmarks are published by the Center for Internet Security under
CC BY-NC-SA 4.0; get them from <https://www.cisecurity.org/cis-benchmarks>.

The studio's results are a self-assessment with its own checks. They are not a CIS certification,
not produced by CIS-CAT, and not endorsed by CIS.

## What the studio downloads while it runs

None of this is part of the repository or the release. It is fetched at run time, from the
source, under that source's own terms.

| What | From | Used for |
|---|---|---|
| Linux cloud images and their checksums | cloud-images.ubuntu.com, cloud.debian.org, download.fedoraproject.org, dl.rockylinux.org, repo.almalinux.org, yum.oracle.com, download.opensuse.org, geo.mirror.pkgbuild.com | Linux golds, downloaded by PVE itself |
| Distribution packages | each distribution's mirrors, the country mirror you pick, EPEL (Rocky, AlmaLinux, Oracle) | updates and features in the golds |
| fastfetch | its GitHub releases (fastfetch-cli/fastfetch), its Ubuntu PPA (ppa:zhangsongcui3371/fastfetch) for 24.04 | the login banner, when chosen |
| yay | the AUR (aur.archlinux.org) | Arch golds |
| virtio-win drivers and the QEMU guest agent | fedorapeople.org (the virtio-win project, Red Hat) | Windows golds and WinPE |
| Windows build catalog | the UUP dump API (api.uupdump.net) | finding builds, editions and files for Windows media and WinPE |
| Windows installation files and updates | Microsoft's update servers, through the links UUP dump returns | building Windows media and WinPE |
| Azure Connected Machine agent | Microsoft (aka.ms/azcmagent) | Azure Arc onboarding, when designed |
| Certificates | Let's Encrypt, through lego | the studio's own HTTPS certificate, when chosen |
| Studio releases | the GitHub API and releases of this project | the version check and self-update |
| The container template | Proxmox's template repository (debian-13-standard) | the installer |

**Windows licensing is yours.** The studio does not supply Windows. It works with the ISOs you
upload or the media it builds from Microsoft's own files, and both are subject to Microsoft's
license terms. Golds carry the KMS client keys (GVLK) that Microsoft publishes; every VM needs a
valid license. Enter your keys under **Windows licenses**.

## Programs the studio calls

The installer adds these Debian packages to the studio's container, and the studio runs them as
separate programs. They are not compiled into it, and each keeps its own license (as stated in
the package's Debian copyright file).

| Program | Package | License | Used for |
|---|---|---|---|
| wimlib-imagex | wimtools | GPL-3.0-or-later / LGPL-3.0-or-later | reading and writing Windows images |
| 7z | 7zip | LGPL-2.1-or-later (parts BSD) | reading Windows ISOs |
| xorriso, mkisofs | xorriso | GPL-2.0-or-later, parts GPL-3.0 | ISO images |
| genisoimage | genisoimage | GPL-2.0 | ISO images |
| cabextract | cabextract | GPL | Windows update packages |
| gcab | gcab | LGPL-2.1-or-later | Windows cabinet files |
| mkfs.vfat | dosfstools | GPL-3.0-or-later | seed disks |
| mcopy, mdir | mtools | GPL-3.0 | seed disks |
| lego | lego | MIT | ACME (Let's Encrypt) |

## Data in the repository

| File | Source |
|---|---|
| `data/linux-timezones.json` | IANA Time Zone Database (`zone.tab`), public domain |
| `data/locales.json` | Locale names and identifiers read from Windows with Hyper-V VM Studio's `New-LocaleCatalog.ps1` |
| `data/linux-region.json` | Hyper-V VM Studio's keyboard and region mapping |
| `data/server-features-26100.json` | Feature names and dependencies read from Windows Server 2025's own package manifests (`tools/gen-server-features.py`) |
| `guest-files/cis/*/map.tsv` | CIS recommendation numbers and profile levels only (see above) |

## Libraries compiled into the studio

The studio binary is built from Rust crates, all under permissive licenses: MIT, Apache-2.0, ISC,
BSD-2/3-Clause, Zlib, 0BSD, BSL-1.0, Unicode-3.0, and CDLA-Permissive-2.0 (Mozilla's root
certificates via `webpki-root-certs`). The direct dependencies are axum, axum-extra,
axum-server, tokio, tokio-rustls, tokio-stream, tokio-util, tokio-tungstenite, reqwest, rustls, rcgen,
x509-parser, sqlx, serde, serde_json, toml, chrono, time, uuid, base64, urlencoding,
mime_guess, rust-embed, lettre, libc, ring, flate2, futures, anyhow, thiserror, tracing, tracing-subscriber, and
resvg (at build time, for the mail icons). `Cargo.lock` names every crate and version; each
crate's full license text is in `THIRD-PARTY-LICENSES.html`, which comes with every release
(generated by cargo-about from `about.toml` and `about.hbs`).

The maintenance console's shell page uses [xterm.js](https://github.com/xtermjs/xterm.js) 5.5.0
and its fit addon 0.10.0 (MIT), served from the binary itself: `web-console/vendor/`, with their
license in `web-console/vendor/xterm-LICENSE`.

## Design

- The studio is a port of [Hyper-V VM Studio](https://github.com/Barg0/HyperV-VM-Studio) (MIT, same author).
- The **Kaido** theme borrows its accents from [Tokyo Night](https://github.com/enkia/tokyo-night-vscode-theme) (MIT, enkia).
- The **Proxmox** theme uses Proxmox VE's own interface colours.
- All icons are drawn for this project.
