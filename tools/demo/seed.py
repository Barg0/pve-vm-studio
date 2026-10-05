#!/usr/bin/env python3
"""Sample data for the README demo: golds, built ISOs, WinPE, a few built VMs and two real
job logs, written into the demo studio's database (/tmp/pvs-demo). Run it once the studio
has started (it creates the tables), then reload the page.

    python3 tools/demo/seed.py

The golds match the templates tools/demo/mock_pve.py reports (names = gold ids).
"""
import json, os, shutil, sqlite3, time

DATA = "/tmp/pvs-demo"
HERE = os.path.dirname(os.path.abspath(__file__))
SAMPLE = os.path.join(HERE, "sample")
db = sqlite3.connect(os.path.join(DATA, "studio.db"))


def now(days=0, hours=0):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - days * 86400 - hours * 3600))


REGION = {"language": "en-US", "format": "de-DE", "keyboard": "de-DE", "timezone": "Europe/Berlin"}
LINUX_FEATURES = ["aliases", "prompt", "fastfetch", "quietmotd"]


def linux_manifest(gid, image, name, distro, family, build, kernel, cis=None, disk=32):
    m = {"schema": 2, "id": gid, "buildId": gid, "imageId": image, "displayName": name, "osFamily": "linux", "distro": distro,
         "family": family, "build": build, "kernel": kernel, "diskSizeGB": disk, "language": "en-US", "locale": "de-DE",
         "keyboardLayout": "de-DE", "timeZone": "Europe/Berlin", "localeMode": "cloud-init", "features": LINUX_FEATURES,
         "updatesApplied": True, "generalized": True, "generation": 2, "secureBoot": True, "storage": "local-lvm", "target": "pve",
         "bakeHost": "pve-01", "label": "", "missingPackages": [], "aptMirror": "", "createdUtc": now(1)}
    if cis:
        m["cis"] = cis
    return m


def windows_manifest(gid, image, name, edition, itype, build, iso, index):
    return {"schema": 2, "id": gid, "buildId": gid, "imageId": image, "displayName": name, "osFamily": "windows", "build": build,
            "language": "en-US", "locale": "de-DE", "keyboardLayout": "de-DE", "inputLocale": "0407:00000407",
            "timeZone": "W. Europe Standard Time", "localeMode": "offline", "imageName": name, "imageIndex": index, "editionId": edition,
            "evaluation": False, "generalized": True, "activation": "kms-client", "requiresTpm": image.startswith("w11"),
            "secureBootTemplate": "MicrosoftWindows", "bakeOptions": {"rdp": True, "ping": True, "blockSignInInputMethods": False},
            "sourceMedia": iso, "installationType": itype, "virtio": "0.1.302-1", "diskSizeGB": 64, "storage": "local-lvm",
            "generation": 2, "target": "pve", "label": "", "createdUtc": now(2)}


ISO_WS = "nas-iso:iso/enus-ws2025-dc-26100.6899.iso"
ISO_W11 = "nas-iso:iso/enus-w11-25h2-ent-26200.6899.iso"
cis = json.load(open(os.path.join(SAMPLE, "cis-ubuntu2604.json")))
cis_summary = {"benchmark": cis["benchmark"], "version": cis["version"], "level": 2, "profile": "level2_server", "checked": cis["checked"],
               "score": 100.0, "exceptions": [], **cis["counts"]}

BAKE_JOB = "fcc26ac0-f968-4ea0-89d8-d5c56eb30611"
DEPLOY_JOB = "72bdc126-3764-41a6-aa88-67c9e2293ef8"
GOLDS = [
    # id, image, os, vmid, options, manifest, job, age (days)
    ("b6b6510a", "ubuntu2604", "linux", 9003,
     {"features": LINUX_FEATURES, "updates": True, "region": REGION, "disk_gb": 40, "disk_storage": "local-lvm", "cis": {"level": 2, "exceptions": []}, "mirror": ""},
     linux_manifest("b6b6510a", "ubuntu2604", "Ubuntu 26.04 LTS (Resolute)", "ubuntu", "debian", "26.04", "7.0.0-38-generic", cis_summary, 40), BAKE_JOB, 0),
    ("3c1d9e27", "debian13", "linux", 9004,
     {"features": LINUX_FEATURES, "updates": True, "region": REGION, "disk_gb": 32, "mirror": "de"},
     linux_manifest("3c1d9e27", "debian13", "Debian 13 (Trixie)", "debian", "debian", "13", "6.12.48+deb13-amd64"), None, 1),
    ("5e8a1f42", "rocky10", "linux", 9005,
     {"features": LINUX_FEATURES, "updates": True, "region": REGION, "disk_gb": 32},
     linux_manifest("5e8a1f42", "rocky10", "Rocky Linux 10 (GenericCloud)", "rocky", "rhel", "10.0", "6.12.0-55.el10.x86_64"), None, 2),
    ("7d2c4b19", "ws2025-datacenter-core", "windows", 9006,
     {"iso": ISO_WS, "index": 1, "region": {"locale": "de-DE", "keyboard": "de-DE", "timezone": "W. Europe Standard Time"},
      "features": ["rdp", "ping", "svrmgr"], "edition_upgrade": "", "disk_gb": 64, "keep_current": True},
     windows_manifest("7d2c4b19", "ws2025-datacenter-core", "Windows Server 2025 Datacenter", "ServerDatacenterCor", "Server Core", "10.0.26100.6899", ISO_WS, 1), None, 2),
    ("9f4e6a03", "ws2025-datacenter-desktop", "windows", 9007,
     {"iso": ISO_WS, "index": 2, "region": {"locale": "de-DE", "keyboard": "de-DE", "timezone": "W. Europe Standard Time"},
      "features": ["rdp", "ping", "svrmgr"], "edition_upgrade": "", "disk_gb": 64, "keep_current": True},
     windows_manifest("9f4e6a03", "ws2025-datacenter-desktop", "Windows Server 2025 Datacenter (Desktop Experience)", "ServerDatacenter", "Server", "10.0.26100.6899", ISO_WS, 2), None, 2),
    ("1b7f3c58", "w11-enterprise", "windows", 9008,
     {"iso": ISO_W11, "index": 3, "region": {"locale": "de-DE", "keyboard": "de-DE", "timezone": "W. Europe Standard Time"},
      "features": ["rdp", "ping", "welcome", "firstlogon"], "edition_upgrade": "", "disk_gb": 80},
     windows_manifest("1b7f3c58", "w11-enterprise", "Windows 11 Enterprise", "Enterprise", "Client", "10.0.26200.6899", ISO_W11, 3), None, 3),
]

db.execute("DELETE FROM golds")
for gid, image, os_, vmid, opt, man, job, age in GOLDS:
    db.execute("INSERT INTO golds (id, image_id, os, name, node, vmid, storage, status, options, manifest, job_id, created_at) "
               "VALUES (?, ?, ?, ?, 'pve-01', ?, 'local-lvm', 'ready', ?, ?, ?, ?)",
               (gid, image, os_, gid, vmid, json.dumps(opt), json.dumps(man), job, now(age, 1)))

# The CIS report, as a bake leaves it.
os.makedirs(os.path.join(DATA, "cis-reports"), exist_ok=True)
shutil.copy(os.path.join(SAMPLE, "cis-ubuntu2604.json"), os.path.join(DATA, "cis-reports", "b6b6510a.json"))

# Built VMs (the design's cards find them by name).
db.execute("DELETE FROM vms")
for name, gold, vmid, node, ip in [("dc-01", "7d2c4b19", 101, "pve-01", "10.10.0.10"), ("dc-02", "7d2c4b19", 102, "pve-02", "10.10.0.11"),
                                   ("web-01", "b6b6510a", 103, "pve-02", "10.10.0.20"), ("files-01", "9f4e6a03", 104, "pve-03", "10.10.0.30")]:
    db.execute("INSERT INTO vms (id, name, lab_id, gold_id, node, vmid, status, spec, ip, job_id, created_at) VALUES (?, ?, NULL, ?, ?, ?, 'ready', '{}', ?, ?, ?)",
               (f"vm-{name}", name, gold, node, vmid, ip, DEPLOY_JOB if name == "web-01" else None, now(1, 2)))


def setting(key, value):
    db.execute("INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value", (key, json.dumps(value)))


setting("media_isos", [{"volid": ISO_WS, "product": "ws2025", "build": "26100.6899", "uuid": "demo-ws2025", "lang": "en-us",
                        "editions": ["ServerDatacenter", "ServerDatacenterCore"], "built": now(2), "size": 7_100_000_000, "sha256": "", "updates": []}])
setting("winpe", {"source_iso": "uup:26100.1", "volid": "nas-iso:iso/winpe-26100.1.iso", "node": "pve-01", "built": now(3), "build": "26100.1",
                  "vioscsi": "0.1.302-1"})
setting("windows", {"virtio": "stable", "iso_storage": "nas-iso"})
setting("server", {"fqdn": "studio.lab.example", "clock": "24h"})

# Two real job logs: the Ubuntu bake and a deploy.
os.makedirs(os.path.join(DATA, "jobs"), exist_ok=True)
db.execute("DELETE FROM jobs")
for jid, kind, title, src, age in [(BAKE_JOB, "bake", "Bake Ubuntu 26.04 LTS (Resolute) (bake-b6b6510a)", "bake-ubuntu.log", 2),
                                   (DEPLOY_JOB, "deploy", "Build web-01", "deploy-linux.log", 1)]:
    shutil.copy(os.path.join(SAMPLE, src), os.path.join(DATA, "jobs", f"{jid}.log"))
    db.execute("INSERT INTO jobs (id, kind, title, status, created_by, params, created_at, started_at, ended_at) VALUES (?, ?, ?, 'succeeded', 'root@pam', '{}', ?, ?, ?)",
               (jid, kind, title, now(0, age), now(0, age), now(0, age - 0.1)))
db.commit()
print("seeded: %d golds, 4 VMs, 2 jobs" % len(GOLDS))
