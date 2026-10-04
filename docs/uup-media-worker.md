# UUP dump media worker - research and status

Status as of 2026-10-04, 10:20. WinPE from UUP is in the studio (`src/uup.rs`, `winpe::build_uup`). The patched install ISO works as a hand-run spike; it is not a studio job yet.

## Goal

Golds should always come from the newest Windows build, not from whatever ISO someone uploaded months ago.
The worker builds a fully patched install ISO from Microsoft's own update files, which works like Microsoft's monthly media refresh.
The user picked option **b**: a temporary, very small worker VM that runs DISM. This keeps the studio inside the rule "official PVE mechanisms only, no qm and no disk access from the studio".

## Pipeline (decided)

1. **Catalog** (uupdump.net API).
   - Pick the build, for example Windows Server 2025 `26100.x`, plus edition and language.
   - Get the file list. The download links point to Microsoft's CDN (`*.dl.delivery.mp.microsoft.com`), not to UUP dump.
2. **Download** with `aria2c` in CT 100. Each file is checked against its SHA-1 from the catalog.
3. **Base conversion on Linux** with the UUP dump `convert.sh`, in `wim` mode. It ignores the `Windows11.0-KB*` update files.
   - The result is an ISO of the base build, e.g. `26100.1`, with `sources/install.wim`.
   - It needs `wimlib-imagex`, `cabextract`, `chntpw`, `genisoimage`/`mkisofs` and `7z`.
4. **Servicing in a WinPE worker VM.** Linux cannot add an LCU offline; that needs DISM.
   - The worker boots the studio's own WinPE ISO (`pvs-winpe-enus-ws2025-sep2026.iso`). `pe.cmd` comes from a seed disk.
   - It maps an SMB share on CT 100, copies `install.wim` plus the updates to a scratch disk, and mounts the image.
   - `dism /Add-Package` the LCU folder. The checkpoint (`KB5043080`) is applied first, then the September LCU (`KB5122871`).
   - It then adds the extra cabs (`KB5122883`, `KB5126027`).
   - Then `/Cleanup-Image /StartComponentCleanup /ResetBase`, `/Unmount /Commit` and `/Export-Image /Compress:max`.
   - Finally it copies `install-updated.wim` back to the share.
5. **ISO** with `xorriso` in CT 100: the base ISO tree with the serviced `install.wim` swapped in. It is uploaded to PVE `iso` storage through the API.
6. **Bake** a gold from it as usual. The sidecar records the build, e.g. `26100.<LCU revision>`.

Why not do everything on Linux: wimlib can apply and capture a WIM but cannot install CBS packages (an LCU or SSU). The only tools that do it are Windows DISM or the Windows Update servicing stack, so a WinPE worker is the lightest correct way.

### Worker VM (lightweight config)

`q35`, `ovmf` (no pre-enrolled keys), 4 cores, **4096 MB**, `balloon 0`, `x86-64-v2-AES`, `virtio-scsi-single`.

| Slot | What it holds |
|---|---|
| `scsi0` | `local-lvm` 80 GB scratch, `discard=on`, `iothread=1` |
| `sata0` | WinPE ISO |
| `sata2` | seed disk via `import-from=local:import/pvs-seed-media-worker.raw` |
| `net0` | `e1000` on `vmbr0`, because WinPE has an Intel driver built in |
| `serial0` | socket |

- Boot order is `sata0`.
- It is tagged `pvs,pvs-worker` and should be destroyed afterwards. Reconcile should also clean up leftover `pvs-worker` VMs.
- Expected runtime is still to be measured: mount, LCU, ResetBase and export, probably 20-40 min.

## Where the test run stands (2026-10-04: the spike works)

**Result:** `local:iso/ws2025-26100.33438-datacenter-core-en-us.iso` (5.3 GB, UDF), a Windows Server 2025 Datacenter Core
install ISO at **26100.33438**, built from Microsoft's UUP files with no Windows ISO involved. It has not been baked from yet.

Worker run (VM 9998, booted from the UUP-built `winpe-26100.1.iso`), 19 min 21 s in total:

| Phase | Time |
|---|---|
| boot, network, share mapped | about 30 s |
| copy in (2.7 GB WIM plus 2.5 GB updates) | 14 s |
| mount | 11 s |
| add the LCU folder (checkpoint KB5043080, then KB5122871) | **13 min 08 s** |
| cleanup (`/StartComponentCleanup /ResetBase`) | 1 min 36 s |
| unmount and commit | 2 min 48 s |
| export (`/Compress:max`) | 13 s |
| copy out (4.5 GB) | 32 s |

- The serviced image reports `ServicePack Build : 33438`, with `RollupFix 26100.33438` and `ServicingStack 33434` installed.
- The output WIM is 4.5 GB (the input was 2.7 GB) and expands to 14.4 GB.
- The ISO is built in CT 100 with `genisoimage -udf -iso-level 3 -allow-limited-size -hide '*'`, the same flags as UUP dump's converter. The extra `-allow-limited-size` is there because install.wim is larger than 4 GiB. Building it took 10 s.

What fixed the two failures of 2026-10-03:
1. The share moved to `/srv/pvs-media/spike` (owner `pvsmedia`, mode 0750), outside the studio's data directory.
2. The scratch disk moved to **SATA** (`sata1`). WinPE's built-in AHCI driver sees it, so no vioscsi is needed. `pe.cmd` picks the SATA disk that has no volume on it; the seed disk is SATA as well, but it carries a FAT volume.

The `pvsmedia` password was rotated on 2026-10-04 and never printed.

Findings to fold into the product:
- **The extra cabs are not for install.wim.** KB5122883 is the SafeOS dynamic update (it belongs in WinRE and boot.wim) and failed with 0x80070306. KB5126027 (the Setup dynamic update) was not found in `W:\cabs` (0x80070002). Only the LCU folder goes into install.wim. The SafeOS update goes into WinRE, and the Setup update into the media's `sources`; both are follow-ups.
- **Package_for_RollupFix 26100.1742 stays "Staged" after ResetBase.** That is the checkpoint's leftover, and it is harmless.
- **The worker powers off by itself** (`wpeutil shutdown`), so the studio can wait for `stopped` and does not need to poll serial.
- **The UUP set had Core only.** Desktop Experience and Standard need their own edition ESD from the catalog.

### Now a studio job (2026-10-04)

The spike is now the **Images → Windows media** blade (`src/media.rs`, routes `/api/media/*`, job kind `media`).

- **Products** (`uup::PRODUCTS`) cover everything still supported:
  - Windows Server 2025 and 2022;
  - Windows 11 26H2, 26H1, 25H2, 24H2 and 23H2;
  - Windows Server vNext, Windows 11 Insider Canary, and Windows 11 Insider Dev and Beta.

  Windows Server 2019 and 2016 are missing on purpose: Windows Update lists only their cumulative updates, never install media.
- **Builds**: the catalog is read once (`listid.php`) and kept for 15 minutes. Builds are listed newest first, and any of them can be built. Each is labelled `YYYY-MM B` (Patch Tuesday), `YYYY-MM preview` or `Insider`.
- **Server sets**: one edition ESD per edition.
- **Client and Insider sets**: a metadata ESD plus package ESDs and CABs. The CABs are turned into ESDs (`cabextract`, then `wimlib capture`), and install.wim is exported with `--ref`. This follows UUP dump's converter, without running it.
- **Every built image** gets WinRE at `Windows/System32/Recovery`, and boot.wim gets WinPE (index 1, FLAGS 9) plus the Setup environment (index 2).
- **The worker** runs only when the image is behind the catalog's revision. Afterwards every index must report the catalog's revision, or the job fails.
  - The `.msu` files go in together, then each `.cab` on its own, smallest first. A cab that is not for install.wim (Safe OS, Setup dynamic update) is skipped with a warning.
  - The worker VM is created through the PVE API with a SATA scratch disk, e1000 networking and a seed disk.
  - `windows::run_pass` follows its serial console, and the VM is destroyed afterwards.
- **No file share** (Samba was removed on 2026-10-04 to keep the container minimal). The worker's seed disk carries `curl.exe`, taken from the image being serviced; all its DLLs, Schannel included, are in WinPE.
  - It GETs its input from the studio's own HTTPS port, at `/worker/<run>/<token>/{install.wim,msu/…,cab/…}`, with the studio's certificate public key pinned (`--pinnedpubkey`).
  - It PUTs `serviced.wim` back to the same path.
  - The endpoints answer only while that run is registered.
  - Tested in WinPE: HTTP 78 MB/s, the right pin passes, a wrong pin is refused.
- **The work folder** can be a volume of its own: `WORK_VOLUME=local-lvm:200` for update-lxc.sh or install.sh (thin, `backup=0`). CT 100 has one.
- **Built ISOs** are recorded in the `media_isos` setting with their size, SHA-256 and the updates applied.

Still to do:
- Run a first full build from the blade (download, worker over HTTPS, ISO). Spike cleanup done 2026-10-04.
- Retention (keep the last N per product).
- A "keep current" schedule.
- Applying the Safe OS dynamic update to WinRE and boot.wim.

## Product design notes (for when the spike works)

- **Media blade:** a "Windows media from Microsoft" card with build, edition and language pickers fed by the UUP dump catalog. The job title would be like "Build media Windows Server 2025 26100.xxxx".
- **One studio job with measured stages for the chomp bar:**

  | Stage | Weight |
  |---|---|
  | download | 35 |
  | convert | 10 |
  | worker | 45 |
  | ISO and upload | 10 |

  The download percentage comes from aria2 bytes, and the worker progress from its PVS markers.
- **Disk space:** about 5 GB download + 3.3 GB base ISO + 2.7 GB WIM + the scratch disk (80 GB thin, in PVE). Delete the UUP files when the run ends.
- **Packages:** CT 100 needs `aria2`, `wimtools`, `cabextract`, `chntpw`, `genisoimage`, `xorriso`, `samba` and `p7zip`. Add them to `deploy/install.sh` and `update-lxc.sh` (dosfstools and mtools are already there).
- **The worker is a studio-owned temporary VM.** Under the enterprise rule the studio may destroy its own bake and worker VMs, never user VMs.
- **Editions:** the UUP set decides which indexes exist. Request a set that includes the editions the bakes need (Standard, Datacenter, Core and Desktop Experience); this run's set had Core only.
- **Open question:** whether the client (Windows 11 25H2) uses the same pipeline. The 25H2 enablement package should go in as an extra cab.

## Features on Demand from UUP (2026-10-04, built, not yet proven by a deploy)

Every UUP file set carries the build's whole FoD set - RSAT, Server Core App Compatibility,
OpenSSH, .NET 3.5, WMIC, PowerShell ISE, language features - as the same 10.0.<base>.1
packages the Languages and Optional Features ISO has.

- Each package comes twice: `X-amd64.cab` is the full canonical CAB (DISM-ready);
  `X-amd64_<sha1-8>.cab` is only an express index (`express.psf.cix.xml`) whose PSF UUP does
  not list - skipped.
- `<uuid>.AggregatedMetadata.cab` holds Microsoft's CompDBs. The target ones
  (`ServerTargetCompDB_FOD_Neutral`, `DesktopTargetCompDB_FOD_Neutral`; on 20348 the plain
  `DesktopTargetCompDB_Neutral`) list every FoD as `FeaturesOnDemand\neutral\cabs\<canonical
  name>` with its size. Canonical `X~31bf3856ad364e35~amd64~~.cab` = UUP `X-amd64.cab`;
  satellites `X~...~amd64~en-US~.cab` = `X-amd64-en-US.cab`. Name + size matched 485/485
  (ws2025, w11) and 378/378 (ws2022).
- Windows 11 24H2 and 26H2 (26300) FoD CABs are byte-identical (3345/3345 SHA-1): one
  client set. Server 2025 and Windows 11 share the packages but not the metadata.
- Sizes (neutral + en-US satellites, no language features): about 1.0 GB per 26100 set;
  ws2022 about 0.65 GB once Windows Mixed Reality (Holographic, 1.6 GB) is left out.
  Language features alone are 3.2 GB.

The studio's builder (`fod::build_uup`, `POST /fod/build`, Media → Features on Demand):
newest build of ws2025 / ws2022 / w11-26h2 → LanguagesAndOptionalFeatures\ with canonical
names, metadata\ with the FoD target CompDBs, FoDMetadata_Client.cab → genisoimage UDF →
`fod-<short>-<base>.iso` (fod-ws2025-26100) → sets that release's slot. Pure Linux, no worker.

Open: Microsoft's docs say DISM needs a "well-formed" repository; this layout mirrors the ISO
but UUP has no target CompDB for the language satellites (only express "Baseless" ones).
Proof = a deploy with RSAT + App Compat showing PVS-CAP-OK. If satellites fail, generate a
canonical `*TargetCompDB_FOD_<lang>.xml.cab` for them, or run `DISM /Export-Source` in the
worker.

## Update servicing in the media build (2026-10-04, deployed, first run pending)

The first 26H2 run (26300.9550) reached its revision but logged four DISM errors. Now, as
Microsoft's "update Windows installation media" steps put it:

- `<uuid>.AggregatedMetadata.cab` (now always downloaded) says where each update goes:
  `SafeOSDUCompDB_KB*` → WinRE, `SetupDUCompDB_KB*` → the media's `sources\` (a CAB of
  files, not a package - DISM answered 0x80070002), `outer.AggregatedMetadata_KB*` = the
  cumulative update chain (checkpoint KB5043080, then the target LCU).
- One update per KB (.msu preferred for the image, .cab for dynamic updates, `-baseless`
  never). The image updates go in one by one: the chain oldest first, then the rest in KB
  order. Each step reports PVS-UPD-OK / PVS-UPD-FAIL <code>; a failed image update fails the
  build.
- Safe OS update: the worker mounts winre.wim, adds it, exports winre-serviced.wim; the studio
  puts it into every image. Setup update: cabextract into `sources\` (names matched without
  case) before boot.wim takes Setup from there.
- Proof per image: `dism /Get-Packages` goes back to the studio; any Partially Installed /
  Install Failed / Uninstall Pending fails the build; the log shows the RollupFix levels.
- `dism.log` always goes back; kept as `dism-logs/media-<id>.log`, its error lines in the job.
- Open from the first run: KB5043080 (checkpoint) answered 0x80070228 "applying the
  Unattend.xml file from the .msu" when DISM took the folder; suspected WinPE's DISM 26100.1
  servicing a 26300 image.
- Client sets: the ~70 package CABs (FoDs, language features) are held back; they are
  fetched and converted only if an export fails for a missing blob. To learn from a run.
