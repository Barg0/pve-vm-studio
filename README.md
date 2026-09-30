# PVE VM Studio

Design VMs in the browser, bake gold images and deploy them on Proxmox VE — the
[Hyper-V VM Studio](../HyperV-Scripts) ported to PVE, with a server behind it.

- One Rust binary in an LXC: REST API, job runner, embedded web UI.
- Talks to the cluster through the PVE API only (an API token for the work).
- Sign in with your PVE account; your PVE permissions apply.

Design and plan: [docs/architecture.md](docs/architecture.md). `kiln.sh` in this folder is the
KVM/libvirt proof of concept that came first; what it proved about Windows golds: [docs/windows-provisioning.md](docs/windows-provisioning.md).

## Status

Phase 1: login, cluster inventory (nodes, storage, bridges, SDN VNets), job runner with live
logs, cluster-check job.

## Install (on a PVE node, as root)

```sh
cargo build --release                         # on the build machine
scp target/release/pve-vm-studio deploy/pve-vm-studio.service deploy/create-lxc.sh root@pve-01:/root/pvs/
ssh root@pve-01 /root/pvs/create-lxc.sh --vmid 9100 --storage local-lvm --bridge vmbr0
```

The script creates the `pve-vm-studio@pve` user and its token, a Debian 13 LXC, a
self-signed certificate and the config, then prints the studio's URL.

## Develop

```sh
PVS_CONFIG=dev/config.toml cargo run
```

with a `dev/config.toml` like [deploy/config.example.toml](deploy/config.example.toml)
(leave out `[tls]` for plain HTTP, `insecure = true` for a PVE with a self-signed cert).
