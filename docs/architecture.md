# PVE VM Studio — architecture

PVE VM Studio is Hyper-V VM Studio ported to Proxmox VE: design a lab in the browser, bake golds,
deploy VMs — all from one web app that keeps state. The Studio's logic and design carry
over; what changes is that there is a server now, and the hypervisor is PVE.

Sources: `HyperV-Scripts` @ 9094149 (New-Vhdx.ps1, Build-Vms.ps1, html/hyperv-vm-studio.html,
guest-files/) is the spec. `docs/windows-provisioning.md` has what the KVM prototype
(`kiln.sh`) proved. Status: draft, 2026-09-30.

---

## 1. Shape

```
 browser ──HTTPS──> Studio (LXC)                                 PVE cluster
                    ┌───────────────────────────┐             ┌──────────────────────┐
                    │ axum: REST API + static UI │──API token──>│ /api2/json (any node)│
                    │ job runner (tokio)        │             │  qemu, storage, ha   │
                    │ SQLite: labs, golds, VMs, │             └─────────┬────────────┘
                    │   jobs, secrets           │                       │
                    │ media: ISOs, WinPE, seeds │<──SMB (bake only)── WinPE / audit VM
                    └───────────────────────────┘
```

- **One Rust binary** in an unprivileged LXC. It serves the API and the UI. Tools it
  shells out to: `xorriso`, `wimlib-imagex`, `samba` (bake share), `sha256sum`.
- **PVE API only.** No bind mounts, no `qm`, no access to VM disks. Everything that
  would need one goes through ISOs we build and upload, the guest agent, or the bake share.
  This keeps the studio cluster-wide and movable.
- **Stateful.** Labs, golds, VMs and jobs live in SQLite. PVE is reconciled against it
  (the studio tags its VMs `pvs` and `pvs-lab-<id>`), so VMs changed or deleted by hand show up
  as drift instead of confusing the studio.

### Stack

| Concern | Crate |
|---|---|
| HTTP, routing | `axum`, `tower-http` (static files, compression) |
| Async, jobs | `tokio` (one task per job, bounded by a semaphore per node) |
| DB | `sqlx` + SQLite, migrations in `migrations/` |
| PVE client | own thin client on `reqwest` (typed where we use it, not a full binding) |
| Live logs | Server-Sent Events per job |
| Templates | `minijinja` for unattend.xml, cloud-init, startnet.cmd |
| Secrets at rest | `age` or `chacha20poly1305`, key file outside the DB |

The frontend stays what the Studio is: vanilla JS, same design system
(`themes.js`, `icons.js`, Design System v2). It is split out of the one 700 KB HTML
file into modules and served by the binary (embedded with `rust-embed`).

---

## 2. Auth and the PVE UI

- **Login = PVE login.** The user enters PVE credentials (any realm) in the studio. the studio calls
  `POST /access/ticket`, and keeps the ticket in the session only. Every request checks the
  user's PVE permissions (`/access/permissions`) — e.g. deploying needs `VM.Allocate` on the
  target pool/node.
- **Jobs run with the studio's API token** (`pve-vm-studio@pve!studio`), because tickets expire after 2 h
  and a bake outlives that. The token's rights are the ceiling; the user's rights are
  checked when the job is created.
- **The token's rights** (`deploy/create-lxc.sh`): `PVEVMAdmin, PVEDatastoreAdmin, PVESDNUser,
  PVEAuditor` on `/`, plus a role `VmStudioNetwork` (`Sys.AccessNetwork`, needed by
  `download-url`) on `/nodes`. An ACL on `/nodes` replaces what `/` grants there, so `/nodes`
  carries all five roles. Custom role ids must not start with `PVE`.
- **Reaching it from PVE:** Proxmox has no official way to extend its web UI, and patching
  pve-manager's files does not survive an update - so the studio does not. The installer puts a
  Markdown link into **Datacenter → Notes** (only if empty) and into the studio container's notes.
  Real single sign-on goes the official way: an OpenID Connect realm in PVE and the same IdP for
  the studio (later phase).

---

## 3. Data model (SQLite)

| Table | Holds |
|---|---|
| `labs` | a Studio design: name, defaults (naming, locale, paths → storages), revision |
| `lab_networks` | subnet catalog: bridge/VNet, VLAN, network, prefix, gateway, DNS |
| `lab_vms` | one row per designed VM — the Studio's `servers[]` entry (JSON column + indexed name/imageId) |
| `join_accounts`, `arc_principals` | catalogs; secrets encrypted |
| `media` | ISOs the studio holds: kind (windows, virtio, winpe, seed), sha256, image list from install.wim |
| `golds` | one row per bake: imageId, language, PVE template VMID + node + storage, manifest JSON (the old `.vhdx.json` sidecar), created |
| `vms` | deployed VMs: VMID, node, lab_vm id, gold id, state, last seen |
| `jobs` | kind (bake, deploy, destroy…), status, params, started/ended, log file path |

`servers[]` keeps its JSON shape from config.json (see §6 for field mapping). That way the
Studio's validation, templates and import of an old config.json keep working.

**Golds are never replaced in place** (as in the kiln.sh prototype): each bake is a new template,
named `gold-<lang>-<imageId>-<yyyymmdd-hhmm>`, and every VM remembers its gold. Removing a
gold is only offered when no VM uses it.

---

## 4. Flows

### 4.1 Linux gold

1. `POST /nodes/{n}/storage/{s}/download-url` with `content=import` — PVE downloads and
   checksums the cloud image itself (the catalog has URL + checksum URL).
2. Create bake VM, disk `import-from=<that image>`, virtio NIC, serial0, agent on.
3. Seed ISO (NoCloud, `CIDATA`) built in the studio, uploaded as `iso`: the bake user-data from
   New-Vhdx (packages, locale, qemu-guest-agent, `BAKE-OK` on serial, poweroff).
4. Wait for stop; check `BAKE-OK` via serial log (termproxy websocket) or agent.
5. Detach seed, delete seed ISO, `POST …/template`. Record gold + manifest.

### 4.2 Windows gold

The kiln.sh prototype pipeline, with two changes: WinPE talks to the studio over SMB instead of a log disk,
and every artifact reaches PVE as an uploaded ISO.

1. Windows ISO is uploaded **to the studio** (it must read install.wim's image list); the studio
   pushes it on to PVE ISO storage via `POST …/upload`. Same for virtio-win.
2. the studio builds the WinPE ISO (boot.wim **index 2**, our startnet.cmd + winpeshl.ini,
   `efisys_noprompt.bin`) and uploads it.
3. Bake VM: OVMF, `efidisk0` with `pre-enrolled-keys=1` (PVE ships Microsoft's keys, so
   Secure Boot works — unlike on the desktop), q35, **SATA** OS disk, e1000 NIC (WinPE has
   the driver built in), WinPE + Windows ISO + virtio ISO + seed ISO.
4. Pass 1 (WinPE): `net use` the studio's bake share, diskpart, `dism /Apply-Image`, bcdboot,
   audit answer file. Logs stream to the share → job log live.
5. Audit boot: virtio-win-gt + qemu-ga installed (viostor becomes BOOT_START), sysprep
   `/generalize /oobe /mode:vm` with the gold answer file (specialize reads the VM's seed CD,
   points `UnattendFile` at it — the finding from the prototype).
6. Pass 2 (WinPE): verify generalize, locale/time zone/policies, offline edition upgrade.
7. Switch the OS disk to virtio-scsi, remove bake ISOs, template.

### 4.3 Deploy a lab

Per VM, in Build-Vms order, preflight first (all checks run before anything is created):

1. **Clone**: linked clone of the gold (`useDifferencingDisk`) or full clone, target node
   chosen by placement (§5).
2. **Hardware**: cores, memory (balloon off — static, as in Hyper-V), NICs with bridge/VNet,
   `tag=<vlan>`, pinned MAC; data disks; `tpmstate0` for vTPM; Secure Boot by gold manifest.
3. **Seed ISO** per VM, built in the studio, uploaded, attached:
   - Windows: unattend.xml (specialize + oobeSystem from Get-ServerUnattendContent) +
     GuestProvision payload (GuestProvision.ps1, manifest.json, DomainJoin.ps1, arc-deploy.json).
   - Linux: user-data / meta-data / network-config from Get-CloudInitUserData.
4. Start. Linux: wait for the first poweroff (as today), detach and delete seed, start
   again. Windows: wait for the agent, then for GuestProvision `state.json` via
   `agent/file-read`; detach and delete seed.
5. Optional: add to HA (`/cluster/ha/resources`) — the old "cluster.addAfterCreate".

**Offline servicing moves online.** Build-Vms mounts the VHDX to add RSAT, features, app
removal and App Compat offline. the studio cannot mount disks, so these move into
GuestProvision (it already has the online fallback path for all of them). Cost: a slower
first boot. If that hurts, a WinPE deploy pass can bring it back later.

---

## 5. Hyper-V → PVE mapping

| Studio / Build-Vms | the studio on PVE |
|---|---|
| gold VHDX + `.vhdx.json` | template VM + `golds.manifest` |
| differencing disk / full copy | linked clone / full clone |
| vSwitch | bridge (`vmbr*`) or SDN VNet — read from the cluster |
| VLAN (access) | `netX: …,tag=<vlan>` |
| static MAC 00-15-5D-… | `netX: virtio=BC:24:11:…` (PVE's OUI) |
| vmPath / vhdPath / storagePlacement | target storage per disk; placement = node + storage by free RAM/space |
| Secure Boot template | OVMF + pre-enrolled keys (MS keys; Linux via shim) |
| vTPM | `tpmstate0: …,version=v2.0` |
| nested virtualization | `cpu: host` (+ nested on the node) |
| automaticStartAction / delay | `onboot`, `startup: order=,up=` |
| integration services | qemu-guest-agent — the card goes away |
| CIDATA seed VHDX | seed ISO (`iso` content, deleted after first boot) |
| PowerShell Direct (hostContext Arc) | guest agent `exec` |
| host failover cluster role | HA resource |
| VHD Sets (shared SCSI + PR) | **open** — PVE has no supported shared-disk-with-reservations; research later |
| Remove-Vms / Repair-VmPlacement / Migrate-Vms | destroy job / not needed / PVE migration + backup |
| Convert-Vhdx | not needed (thin storage, `fstrim` via agent) |

Dropped: `integrationServices`, `nicName` rename in the hypervisor (the guest-side rename
by MAC stays), `sxsSourcePath` (use the ISO's `sources\sxs` via the seed or Windows Update).

---

## 6. Cluster

- the studio reads nodes, storages, bridges and SDN VNets from `/cluster/resources` + per-node calls.
- Linked clones need the template on the same storage. On shared storage (Ceph, NFS) one
  template serves every node. Without shared storage the studio keeps one template per node
  (a bake produces one, a "replicate gold" job copies it) and places VMs accordingly.
- Placement: per VM a node can be pinned; otherwise the node with the most free memory
  minus what this run already planned (same rule as storagePlacement today).

---

## 7. Phases

| # | Deliverable | Done when |
|---|---|---|
| 1 ✅ | Skeleton: LXC install script, axum + SQLite, PVE login, cluster inventory, job runner with live log | log in with a PVE user, see nodes/storages/bridges, a dummy job streams its log |
| 2 | Linux gold bake | Debian 13 + Ubuntu 24.04 golds as templates from the UI |
| 3 | Linux deploy | a lab of 3 Linux VMs deploys, boots, answers SSH |
| 4 | Studio UI port | the full Studio in the studio's design, state saved server-side, old config.json imports |
| 5 | Windows gold bake | WS2025 + Win11 golds from ISO, no hands |
| 6 | Windows deploy | WS2025 VM at the login prompt with name, IP, local admin, data disks |
| 7 | Domain join, Arc, roles | DC + member servers + Linux realm join in one lab |
| 8 | HA, placement across nodes, destroy/rebuild lab, drift view | 2-node cluster test |
| 9 | Extras: PVE UI button, shared disks research, AVD/Azure Local golds | — |

---

## 8. Open questions

- The studio's own storage for ISOs: the LXC rootfs, or a separate mount point (big: several GB per Windows ISO)?
- Where does the bake share listen — must the bake VM's bridge reach the LXC? (Default: both on `vmbr0`.)
- Secrets: is an encrypted DB with a key file on the LXC enough, or should they come from elsewhere?
