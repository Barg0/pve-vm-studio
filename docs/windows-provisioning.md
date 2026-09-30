# Windows provisioning: what Hyper-V VM Studio does, and how Kiln does it on KVM

A merged analysis of `New-Vhdx.ps1` (gold), `Build-Vms.ps1` (per VM),
`guest-files/GuestProvision.ps1` + `DomainJoin.ps1`, the `.claude/` research notes,
the memory notes and the full git history (including the pre-squash
`old-history-backup` branch) — plus what the first Kiln prototype runs proved on
2026-09-29. Line numbers refer to HyperV-Scripts at commit 9094149.

Tags: **[same]** carries over to KVM as-is · **[diff]** needs another mechanism ·
**[HV]** Hyper-V only, drop · **[gap]** weakness in the Hyper-V code, don't copy.

---

## 0. Verified on KVM so far (Kiln prototype, 2026-09-29)

| Fact | Evidence |
|---|---|
| A WinPE ISO rebuilt on Linux boots without "Press any key" | `wimlib-imagex export boot.wim <idx> --boot` + `update` startnet.cmd, `xorriso -as mkisofs -e efi/microsoft/boot/efisys_noprompt.bin -no-emul-boot` |
| diskpart + `dism /Apply-Image` + `bcdboot /f UEFI` in that WinPE produce a bootable gold | Server 2025 Datacenter, ~4 min |
| **boot.wim index 1 (bare WinPE) cannot service an offline image** | every `/Image:` call → `0x80004002`, dism.log: `Failed to create DismHostManager remote object`. `regsvr32 DismCorePS.dll` and `/ScratchDir` do not help |
| **boot.wim index 2 (the Setup environment) can** | `/Get-CurrentEdition` ServerDatacenter, `/Get-TargetEditions` ServerTurbine, `/Get-Intl` — all rc 0. Needs a `winpeshl.ini` that launches startnet.cmd instead of setup.exe |
| Audit boot on SATA with a scratch virtio disk attached, `virtio-win-gt-x64.msi` + `qemu-ga-x86_64.msi`: viostor becomes `BOOT_START`, VMs then boot from virtio-blk | `sc qc viostor` in the audit log; deployed VM booted on virtio |
| Audit + sysprep `/generalize /oobe /mode:vm` takes ~2 min | log timestamps |
| **Windows Setup does NOT look at a CD for Autounattend.xml after generalize** — despite Microsoft's search-order table | Panther\setupact.log: `No unattend file was present, skipping unattend settings passes` → OOBE region page |
| A gold answer file (`sysprep /unattend:`) whose specialize `RunSynchronous` reads the VM's CD, sets the name and points `HKLM\SYSTEM\Setup\UnattendFile` at the VM's own file → the VM's **oobeSystem** answers are used | name `kiln-ws2025-01` reported by the agent 40 s after start; region page skipped |
| Without a key, Server OOBE stops at "enter the product key" | screenshot |
| `rmdir %WINDIR%\Panther` inside the audit pass only produces "file in use" noise (Setup runs from there) | screenshot |
| virt-install does not always add the guest-agent channel for Windows | `QEMU guest agent is not configured` → pass `--channel unix,target.type=virtio,name=org.qemu.guest_agent.0` |
| A Linux user can loop-mount a raw image read-only via `udisksctl loop-setup -r` + `udisksctl mount` (polkit) | used to read Panther logs of a stopped VM |
| Bake work must not live in /tmp (tmpfs with quota) | a 9.6 GB gold filled it and stalled the VM |

---

## 1. The Hyper-V pipeline, in order

`Invoke-ImageBuildPipeline` (New-Vhdx 9706), per (index, edition-upgrade) pair:

1. **Key choice** — AVMA table by version + edition (`Get-AvmaKey` 563).
2. **Apply** (`New-WindowsVhdxImage` 9268, VHDX mounted on the host): create, partition,
   `Expand-WindowsImage`, **early `/Get-TargetEditions` probe** for virtual editions (fail
   before 20 min of sysprep), write the temp boot unattend, bcdboot + verify, dismount.
3. **Generalize** (`Convert-ToGeneralizedImage` 9435): temp Gen2 VM, **no NIC**, boots to audit
   mode, deletes Panther, `sysprep /generalize /oobe [/mode:vm] /shutdown` **without /unattend**,
   host waits for Off (45 min).
4. **Edition change** (`Convert-ToVirtualEdition` 8461): offline `/Set-Edition` **after**
   generalize, read back with `/Get-CurrentEdition`; failure deletes the gold.
5. **Offline customization** (`Set-OfflineImageCustomization` 9107), after generalize:
   answer-file cleanup, DISM intl + time zone, registry policies, `/Set-ProductKey` last.
6. **Sidecar** `<gold>.vhdx.json` (`Write-GoldImageManifest` 1070).

Then per VM (`Build-Vms`): copy/differencing disk → VM → pinned MACs → unattend →
**offline** write of `Panther\unattend.xml` + `UnattendFile` pointer + GuestProvision payload +
roles via `Install-WindowsFeature -Vhd` → start. GuestProvision runs from SetupComplete.

### Kiln's pipeline (proposed, everything shown feasible)

| Step | Hyper-V | Kiln |
|---|---|---|
| Apply | host DISM on mounted VHDX | **WinPE pass 1** (index 2): diskpart, `/Apply-Image`, `/Get-TargetEditions` probe, `/Add-Driver` virtio, bcdboot + check `bootmgfw.efi`, delete stray `Sysprep_succeeded.tag`, write temp unattend |
| Generalize | temp VM, no NIC | audit boot, SATA + scratch virtio disk, **virtio NIC link down**, qemu-ga MSI, sysprep |
| Verify | only "VM is Off" **[gap]** | **WinPE pass 2** reads `Setup\State\State.ini` = `IMAGE_STATE_GENERALIZE_RESEAL_TO_OOBE` + `Sysprep_succeeded.tag`; collect Panther logs on failure |
| Edition | offline `/Set-Edition` | **WinPE pass 2** same commands |
| Customization | offline DISM + `reg load` | **WinPE pass 2** same commands (`reg.exe` + DISM) |
| Key | `/Set-ProductKey` AVMA | **WinPE pass 2** `/Set-ProductKey` **GVLK** (AVMA cannot activate off Hyper-V) |
| Per-VM unattend | written into the VHDX offline | gold carries `Kiln\firstboot.cmd` (specialize hook) → VM CD. See §4 |
| Roles, features | `Install-WindowsFeature -Vhd` offline | online in GuestProvision, or a per-VM WinPE pass (§6) |

So Kiln needs **two** WinPE boots per gold (before and after generalize) — each ~1 min apart
from the apply itself. Both use the same patched index-2 boot ISO; the seed CD says which pass.

---

## 2. Gold: source, editions, keys

- **Index choice**: every (index, edition-upgrade) pair is its own gold. **[same]**
- **Edition detection is by WIM name** (`Test-IsServerDatacenterImage` 880, `…Core` 891,
  `Test-IsClientImage` 908; Core = "server" without "desktop"). On Linux `wimlib-imagex info
  <wim> <idx> --xml` gives `EDITIONID`, `INSTALLATIONTYPE` (Server / Server Core / Client),
  `LANGUAGES/DEFAULT`, `BUILD` — more reliable. **Never classify by ProductType**:
  multi-session reports 3 like Server. **[diff]**
- **Virtual editions** (`$script:VirtualEditionCatalog` 229): multi-session from plain **Pro**
  only, pattern `(ServerRdsh|EnterpriseMultiSession)`; Azure Edition from **2025 Datacenter**,
  pattern `(ServerTurbine[A-Za-z]*|ServerAzure[A-Za-z]*)` — greedy on purpose (Core is
  `ServerTurbineCor`). Standard Core has no direct hop; 2022 has no path. **[same]**
- **Base edition first, `/Set-Edition` after generalize.** Setting it before sysprep (or
  integrating updates, or using UUP-dump multi-session) leaves staged CBS servicing that
  sysprep refuses. Verified Pro → ServerRdsh keeps `ImageState`. **[same]** (WinPE pass 2)
- **Read the result with `/Get-CurrentEdition`**, never the `EditionID` string. A failed
  change deletes the gold — "a gold named for an edition it does not carry is worse than no
  gold". **[same]**
- **Keys**: AVMA table 2016–2025 Std/DC + 2025 Azure Edition, applied last with
  `/Set-ProductKey` (refuses a key from the wrong version's pkeyconfig; unknown pairing →
  keyless). Standard golds without a key **stopped OOBE at the key page** (d48fa53).
  **[diff]**: on KVM AVMA never activates — use **GVLK** (KMS client) keys, same step, same
  exact-match rule. Multi-session activates only on AVD; Azure Edition deactivates outside
  Azure/Azure Local — both test-only on KVM.
- **Language**: image default language only, never guessed; no language packs, UI language
  never set. **[same]**
- **Names**: `<hv|azl>-<lang>-<imageId>`, e.g. `hv-enus-ws2025-datacenter-core`,
  `w11-enterprise-ms`, `ws2025-datacenter-az-*`. Reuse the imageId scheme so configs match. **[same]**

## 3. Gold: apply, boot files, generalize

- **Layout**: GPT, ESP 200 MB FAT32 "System", MSR 128 MB, NTFS "Windows" rest, **no recovery
  partition**. **[same]** (Kiln's diskpart script matches)
- **bcdboot**: judge success by `S:\EFI\Microsoft\Boot\bootmgfw.efi` existing, not the exit
  code. A WDAC-killed bcdboot shipped a bootless gold three times (5d814eb). WDAC is **[HV]**;
  the check is **[same]**. Prefer the image's own bcdboot when it is newer than WinPE.
- **Win11 24H2 BCD risk** (researched, never hit): generalize may turn `device/osdevice` into
  `locate=` → Automatic Repair. Check `bcdedit /store S:\EFI\Microsoft\Boot\BCD /enum {default}`
  in WinPE pass 2 if it ever shows up.
- **Temp unattend**: oobeSystem `Reseal/Mode=Audit`; auditUser `RunSynchronous`
  (1) remove Panther, (2) sysprep. **auditUser runs exactly once** — a reboot inside audit
  lands at a logon screen and sysprep never runs. Nothing in the audit pass may ask for a
  reboot (virtio MSIs: `/norestart`). **[same]**
- **No NIC during generalize** — a Store app updating itself between boot and sysprep is the
  documented way to fail generalize (c70119c). **[same]** Kiln: virtio NIC with link down, so
  NetKVM still binds.
- **`/mode:vm`** on Hyper-V (+ `VMModeOptimizations` in the deploy unattend), plain on Azure
  Local. **[same]** as long as the gold boots on the same QEMU machine type/device set it was
  generalized on (q35, OVMF, virtio) — Kiln controls both ends.
- **Sysprep exit 0 is not success.** Success = `Sysprep_succeeded.tag` (delete the one
  install.wim may ship first) and `State.ini` `IMAGE_STATE_GENERALIZE_RESEAL_TO_OOBE`.
  `GeneralizationState=7` is useless (install.wim reads 7). **[same]**, and Kiln should do it —
  Hyper-V does not **[gap]**.
- **Pending reboot**: only CBS `RebootPending` and WU `RebootRequired` block sysprep.
- **AppX `0x80073CF2`** remedy researched, not built (never hit).
- **Sysprep VM**: 4 GB, 2 vCPU, Secure Boot MicrosoftWindows template, vTPM for clients,
  45 min. **[diff]** OVMF with MS keys + swtpm for Windows 11.

## 4. Gold: offline customization after generalize

All of these are `reg load` writes or DISM calls — WinPE pass 2 does them unchanged. HKLM
policy keys, never HKCU (no user hive offline). The gold gets only what every VM must
inherit; per-VM choices belong to the VM step (6fbe364).

| # | Setting | Keys / command | Targets | Default |
|---|---|---|---|---|
| 1 | Answer-file cleanup | delete `Panther\unattend.xml`, `Deploy\unattend.xml`; `reg delete HKLM\<SYSTEM>\Setup /v UnattendFile` | all | always |
| 2 | Locale | `/Set-UserLocale`, `/Set-SysLocale`, `/Set-InputLocale:LANGID:KLID` (e.g. `0407:00000407`) | HyperV | from picker |
| 3 | Time zone | `/Set-TimeZone:<Windows id>` (default `W. Europe Standard Time`) | HyperV | from picker |
| 4 | RDP + ping | SYSTEM `Control\Terminal Server\fDenyTSConnections=0`, `WinStations\RDP-Tcp\UserAuthentication=1`; raw firewall rules `Baked-RDP-TCP-In`/`-UDP-In`/`Baked-ICMPv4-Echo-In`/`ICMPv6` as `v2.31\|Action=Allow\|…` strings under `SharedAccess\Parameters\FirewallPolicy\FirewallRules` | all | on |
| 5 | No device encryption | SYSTEM `Control\BitLocker\PreventDeviceEncryption=1` — 24H2 auto-encrypts with Secure Boot + TPM, and swtpm + OVMF qualifies | client | on |
| 6 | Power | SOFTWARE `Policies\Microsoft\Power\PowerSettings` `ActivePowerScheme=8c5e7fda-…` (High perf), display/sleep AC+DC 0; SYSTEM `Control\Power\HibernateEnabled(Default)=0`. Writing the scheme tree itself → "Access denied" (ACL travels with the hive) | client | on |
| 7 | Server Manager | SOFTWARE `Policies\Microsoft\Windows\Server\ServerManager\DoNotOpenAtLogon=1` | server | opt-in |
| 8 | Welcome experience | SOFTWARE `Policies\Microsoft\Windows\CloudContent\DisableWindowsSpotlightWindowsWelcomeExperience=1` | client | opt-in |
| 9 | First sign-in animation | SOFTWARE `Microsoft\Windows\CurrentVersion\Policies\System\EnableFirstLogonAnimation=0` | client | opt-in |
| 10 | Sign-in keyboard | SOFTWARE `Policies\Microsoft\Control Panel\International\BlockUserInputMethodsForSignIn=1` (STIG) | all | opt-in |
| 11 | Edge baseline | SOFTWARE `Policies\Microsoft\Edge` — 12 values (Google as managed default, no first run, NTP redirect…) | not Core | opt-in |
| 12 | Product key | `/Set-ProductKey` — last, after the edition change | server | always |

Plus the sidecar JSON: imageName, imageIndex, target, locale, keyboardLayout, inputLocale,
timeZone, localeMode, imageLanguage, createdUtc (+ sourceEdition, editionUpgrade).

- **Locale data**: `data/locales.json`, 251 locales; the generator validates keyboard IDs
  against the registry (79 of 251 `CultureInfo.KeyboardLayoutId`s were not loadable layouts);
  IME locales excluded. Only LangId + Keyboard are consumed. DISM cannot set GeoID **[gap]**.
- **Azure Local** gets a first-boot `intl.cpl /f` payload instead (its own answer file
  overwrites DISM) — only relevant if Kiln ever has that target.

## 5. Per VM: the answer file

`Get-ServerUnattendContent` (Build-Vms 1869):

**specialize** — ComputerName (lower-case, ≤15, NetBIOS regex); International-Core;
`Microsoft-Windows-TCPIP` one `<Interface>` per static NIC **keyed by MAC**
(`AA-BB-CC-DD-EE-FF`; element order Ipv4Settings, Ipv6Settings, Identifier,
UnicastIpAddresses, Routes; default route on the primary only); `DNS-Client` on the primary
only; `UnattendedJoin` unless the join is deferred.

**oobeSystem** — `AdministratorPassword` and `LocalAccount` (base64(UTF-16LE(pw + element
name)), `PlainText=false`); OOBE `HideEULAPage`, `HideWirelessSetupInOOBE`, `ProtectYourPC=3`
(+ client-only `HideLocalAccountScreen`, `HideOEMRegistrationScreen`,
`HideOnlineAccountScreens`); `VMModeOptimizations`; International-Core again (**the region page
has no hide flag** — it is skipped only when International-Core answers it).

Rules learned: a Windows 11 client needs a `LocalAccount` or OOBE hangs (built-in admin only
is fine on server and multi-session); a DC gets built-in admin only (dcpromo deletes the
SAM); malformed XML → "internal error… answer file" `0x800705b9` (validate with xmllint);
never delete a file `UnattendFile` points at (same error).

### How Kiln delivers it

The gold's own answer file (sysprep `/unattend:`) runs `C:\Windows\Kiln\firstboot.cmd` in
specialize. The script finds the VM's CD and:

- **name** → registry `ComputerName\ComputerName`, `ActiveComputerName`, Tcpip `Hostname` +
  `NV Hostname` (verified). The gold answer file must not carry `<ComputerName>`.
- **static IP + DNS** → TCPIP/DNS-Client are specialize-only and specialize is already running
  from the gold file, so the script sets them itself by MAC (`netsh` or `New-NetIPAddress`).
- **oobeSystem** → copies the VM's file to `Panther\kiln-vm.xml` and sets `UnattendFile` —
  write the file first, then the key; no CD → leave the key alone (verified).
- **GuestProvision payload** → xcopy `SetupComplete.cmd`, `GuestProvision\`, `manifest.json`,
  optional `DomainJoin.ps1`, `domain-join.json`, `arc-deploy.json` into
  `C:\Windows\Setup\Scripts\` — from there it runs exactly as on Hyper-V.
- **client OOBE registry bypass** (SOFTWARE `…\CurrentVersion\OOBE`: `HideOnlineAccountScreens`,
  `DisablePrivacyExperience`, `DisableVoice`, `PrivacyConsentStatus=1`, `Protectyourpc=3`,
  `HideEULAPage`) → identical for every client VM, so it moves into the client gold (§4).
  BypassNRO deliberately never used.

WinPE pass 2 must **not** delete the gold answer file or the pointer Kiln relies on — that is
the one deliberate difference from Hyper-V's "no cached answer file" rule, and it is safe
because the file stays where the pointer says.

## 6. Per VM: first boot (GuestProvision)

`SetupComplete.cmd` → `GuestProvision.ps1` as SYSTEM, logs to `C:\ProgramData\VmDeployLogs\`,
in this order:

1. **Rename NICs by MAC**, two passes via a scratch name (the target name is often still held).
   Needs pinned MACs — Hyper-V pins random `00155D…`; Kiln pins `52:54:00:…` in the domain XML.
2. **Data disks**: RAW, non-boot disks whose **SCSI LUN** is in the manifest → GPT, partition,
   format, letter. **[diff]** virtio-blk has no LUN: give each disk a `serial=` and match
   `Get-Disk.SerialNumber`, or use virtio-scsi with fixed `lun=`.
3. **Server Core App Compat FoD** (before roles).
4. **Windows features** (`Install-WindowsFeature`, ± management tools).
5. **RSAT capabilities** (client).
6. **Azure Arc** (service principal).
7. **Register the deferred domain join** — last, because the next boot is where domain policy
   lands.
8. `state.json`: `success`, `restartNeeded`, `completedUtc`. **It never reboots** — a reboot
   inside SetupComplete leaves Windows "in a bad state" (the Win11 OOBE hang of 2026-08-30).

**Roles offline vs online.** Hyper-V stages roles offline with `Install-WindowsFeature -Vhd`,
except a deny list: `RDS-Web-Access` (its advanced installer runs before RPC → 1753 →
"could not configure one or more system components") and `RDS-Connection-Broker` (captures
the random `WIN-*` name). Always emit the role id itself (IIS without the static handler bug).
Name traps: `RSAT-RDS-Licensing-Diagnosis-UI`; no `Rsat.Hyper-V.Tools` capability —
`Microsoft-Hyper-V-Tools-All`, whose `-All` enables the hypervisor and must be switched back
off. **Kiln**: online in GuestProvision is simplest (after specialize, so name-sensitive roles
are fine) but slow and reboot-hungry; a per-VM WinPE pass with `/Enable-Feature` is the
parity option — decide per the observed cost.

**Client**: RSAT from FoD (layout: 2019 root, 2022/2025 `LanguagesAndOptionalFeatures\`),
optional features with read-back checks, provisioned-app removal (43-app catalog + protected
list, Win11 only). All ported to online equivalents or a per-VM WinPE pass.

**Completion signal.** Build-Vms never checks whether a Windows VM finished **[gap]**. Kiln
can: poll `state.json` → `completedUtc` through qemu-guest-agent, then eject and delete the CD
(it carries passwords and, for joins, the join credential), and reboot from outside if
`restartNeeded`.

## 7. Domain join and Arc

- **Specialize join** (`UnattendedJoin`, needs static IP) is not available to Kiln — the VM's
  file only reaches oobeSystem. Options: all joins **deferred**, or an ODJ blob (`djoin
  /provision` on a DC, `/requestODJ` from firstboot.cmd) — the research note's parked
  alternative, attractive here because no password travels.
- **Deferred join** (b71aa4c, verified 09-24): GuestProvision seals the credential with DPAPI
  LocalMachine, zero-fills the plaintext; SYSTEM task `VmDeploy-DomainJoin` (+5 min and
  AtStartup, IgnoreNew, no task retries); `DomainJoin.ps1` waits for a DC (`nltest
  /dsgetdc`, 600 s), `Add-Computer` ×3, then in `finally` wipes secrets, unregisters, deletes
  itself, writes `state.json`, reboots only on success. **[same]** — ports unchanged.
- **CIS facts**: LAPS rotates the admin password after join; admin renamed; SYSTEM tasks
  survive "no stored credentials"; never `-EncodedCommand` (ASR); CIS disables the built-in
  admin on member servers.
- **Arc** (service principal): download agent with `curl.exe`, `azcmagent connect --config`
  with a BOM-less JSON (a BOM → `AZCM0019`), 3 tries with backoff (exit 42 = RBAC
  propagation), secret files deleted in `finally`. **[same]**. Host-context mode uses
  PowerShell Direct **[HV]** — drop.

## 8. Encoding and tooling traps

- Host-written JSON for Go/JSON consumers: UTF-8 **without** BOM. Guest `.ps1`: pure ASCII
  (5.1 misreads BOM-less UTF-8 with non-ASCII). `.cmd` files: CRLF.
- Back-to-back DISM sessions collide: exit 87 with "hive already mounted… Access denied" —
  retry twice after 10 s (30079aa). Applies to WinPE chains.
- `reg delete` of an absent value exits non-zero — don't log it as done.
- Differencing children break if the gold moves or is rebuilt — Kiln never rebakes in place.
- QEMU: Windows expects a localtime RTC (`<clock offset='localtime'/>`).
- Log failures at warn, never debug.

## 9. Dead ends — do not retry

1. Reboots inside the audit pass in any form (scheduled task, `WillReboot=OnRequest`, exit 2,
   `Setup\CmdLine` boot loop — `0x800706ba` from EventLog cleanup ~7 s into boot).
2. Host-driven generalize (scrapped 2026-08-30).
3. Setting the edition or integrating updates before sysprep.
4. `Add-Computer` (with reboot) inside SetupComplete.
5. Dropping a scheduled task into the offline image (`System32\Tasks` + TaskCache).
6. FirstLogonCommands + AutoLogon for the join (CIS banner, ARSO).
7. DISM locale bake when the platform brings its own International-Core.
8. BypassNRO. 9. `EditionID` registry string as an edition check.
10. Trusting sysprep exit 0 / `GeneralizationState=7`.
11. Deleting a file `UnattendFile` points at.
12. Writing the power scheme tree directly; Ultimate Performance.
13. Staging RDS-Web-Access / RDS-Connection-Broker offline.
14. Built-in-admin-only on Windows 11 client.
15. A per-VM tick (e.g. Hyper-V Manager) in the gold.
16. Kiln-specific: bare WinPE (boot.wim index 1) for offline servicing; an Autounattend.xml
    on a CD for a generalized image.

## 10. Open items

- Windows 11: Secure Boot with Microsoft keys (no enrolled OVMF VARS on the dev box yet —
  `virt-fw-vars` or a distro `OVMF_VARS.ms.fd`) + swtpm.
- Azure Edition conversion + boot never run end to end (Hyper-V included).
- Win11 24H2 `locate=` BCD — never hit.
- Hyper-V bugs found on the way: `DomainJoin.ps1` reads `dcFqdn` that Build-Vms never writes
  (KB5020276 wants the DC as FQDN); GuestProvision never deletes itself though DomainJoin's
  header says it does; `-SlowHost` phase 3 skips host-context Arc; Build-Vms' explicit-locale
  InputLocale table has 14 entries and silently falls back to de-DE.
