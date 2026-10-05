#!/usr/bin/env python3
"""A stand-in Proxmox VE API with sample data, for recording the README's videos.

Answers the calls the studio makes (src/pve.rs) for a believable three-node lab cluster:
nodes, storages, bridges, templates (golds) and VMs. Writes (create, config, start, upload)
are accepted; nothing is real. A clone takes a few seconds, and a cloned VM's first boot plays a
Debian cloud-init run through the guest agent for about two minutes before it powers off - so a
deploy runs the way it does on a real cluster. Unknown paths are logged, so a new call the
studio makes shows up here. POST /demo/reset forgets the VMs deploys made.

    python3 tools/demo/mock_pve.py [--port 8006]

Serves HTTPS with a throwaway self-signed certificate (the studio's config: insecure = true).
"""
import argparse, json, os, re, ssl, subprocess, sys, tempfile, time, urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

NODES = [
    {"node": "pve-01", "ip": "10.10.0.11", "maxcpu": 32, "maxmem": 256 * 2**30, "mem": 61 * 2**30, "cpu": 0.07, "disk": 14 * 2**30, "maxdisk": 94 * 2**30},
    {"node": "pve-02", "ip": "10.10.0.12", "maxcpu": 32, "maxmem": 256 * 2**30, "mem": 48 * 2**30, "cpu": 0.04, "disk": 12 * 2**30, "maxdisk": 94 * 2**30},
    {"node": "pve-03", "ip": "10.10.0.13", "maxcpu": 24, "maxmem": 128 * 2**30, "mem": 22 * 2**30, "cpu": 0.02, "disk": 11 * 2**30, "maxdisk": 94 * 2**30},
]
STORAGES = [
    {"storage": "local", "type": "dir", "content": "iso,vztmpl,import,backup", "shared": 0, "path": "/var/lib/vz", "maxdisk": 94 * 2**30, "disk": 31 * 2**30},
    {"storage": "local-lvm", "type": "lvmthin", "content": "images,rootdir", "shared": 0, "maxdisk": 1800 * 2**30, "disk": 410 * 2**30},
    {"storage": "ceph-vm", "type": "rbd", "content": "images,rootdir", "shared": 1, "maxdisk": 12 * 2**40, "disk": 3 * 2**40},
    {"storage": "nas-iso", "type": "nfs", "content": "iso,import", "shared": 1, "maxdisk": 8 * 2**40, "disk": 2 * 2**40},
]
ISOS = [
    ("nas-iso", "enus-ws2025-dc-26100.6899.iso", 7_100_000_000),
    ("nas-iso", "enus-w11-25h2-ent-26200.6899.iso", 6_800_000_000),
    ("nas-iso", "winpe-26100.1.iso", 690_000_000),
    ("nas-iso", "virtio-win-0.1.302.iso", 877_373_440),
    ("nas-iso", "SERVER_EVAL_x64FRE_en-us.iso", 5_900_000_000),
]
BRIDGES = [{"iface": "vmbr0", "type": "bridge", "active": 1, "autostart": 1, "cidr": "10.10.0.11/24", "comments": "Lab"},
           {"iface": "vmbr1", "type": "bridge", "active": 1, "autostart": 1, "comments": "Isolated"}]
VNETS = [{"vnet": "lab10", "zone": "labzone", "tag": 10, "type": "vnet"}]
# Guests: (vmid, name, node, template, status, tags)
GUESTS = [
    (9003, "b6b6510a", "pve-01", 1, "stopped", "gold;os-ubuntu"),
    (9004, "3c1d9e27", "pve-01", 1, "stopped", "gold;os-debian"),
    (9005, "5e8a1f42", "pve-01", 1, "stopped", "gold;os-rocky"),
    (9006, "7d2c4b19", "pve-01", 1, "stopped", "gold;os-windows"),
    (9007, "9f4e6a03", "pve-01", 1, "stopped", "gold;os-windows"),
    (9008, "1b7f3c58", "pve-01", 1, "stopped", "gold;os-windows"),
    (101, "dc-01", "pve-01", 0, "running", "os-windows"),
    (102, "dc-02", "pve-02", 0, "running", "os-windows"),
    (103, "web-01", "pve-02", 0, "running", "os-ubuntu"),
    (104, "files-01", "pve-03", 0, "running", "os-windows"),
]
POOLS = [{"poolid": "vm-studio", "comment": "PVE VM Studio: golds (templates) and the bakes that make them"},
         {"poolid": "lab", "comment": "The lab"}]

VMID_NEXT = [105]
TASKS = {}
# VMs deploys made: vmid -> {name, node, boots: [start times], stopped}
MADE = {}
FIRST_BOOT = 120  # seconds

# The first boot of a Debian 13 clone, as cloud-init-output.log grows: (second, line).
PKGS = ["libpython3.13-minimal", "htop", "curl", "jq", "vim-runtime", "vim", "tmux", "unattended-upgrades", "chrony",
        "nfs-common", "qemu-guest-agent", "bash-completion", "dnsutils", "rsync"]
CLOUD_INIT = [(4, "Cloud-init v. 25.1.4-1 running 'init-local' at Mon, 05 Oct 2026 10:02:03 +0000. Up 5.12 seconds."),
              (7, "Cloud-init v. 25.1.4-1 running 'init' at Mon, 05 Oct 2026 10:02:06 +0000. Up 8.40 seconds."),
              (7, "ci-info: ++++++++++++++++++++++++Net device info++++++++++++++++++++++++"),
              (7, "ci-info: | ens18  | True | 10.10.0.40 | 255.255.255.0 | global | bc:24:11:5e:3a:91 |"),
              (8, "ci-info: ++++++++++++++++++++++++Route IPv4 info++++++++++++++++++++++++"),
              (8, "ci-info: |   0   |   0.0.0.0   | 10.10.0.1 |   0.0.0.0   |   ens18   |   UG  |"),
              (9, "Generating public/private ed25519 key pair."),
              (10, "Cloud-init v. 25.1.4-1 running 'modules:config' at Mon, 05 Oct 2026 10:02:09 +0000. Up 11.02 seconds."),
              (13, "Generating locales (this might take a while)..."),
              (17, "  de_DE.UTF-8... done"),
              (18, "  en_US.UTF-8... done"),
              (19, "Generation complete."),
              (22, "Cloud-init v. 25.1.4-1 running 'modules:final' at Mon, 05 Oct 2026 10:02:21 +0000. Up 23.55 seconds."),
              (24, "Hit:1 https://deb.debian.org/debian trixie InRelease"),
              (25, "Get:2 https://security.debian.org/debian-security trixie-security InRelease [43.4 kB]"),
              (27, "Reading package lists..."),
              (30, f"0 upgraded, {len(PKGS)} newly installed, 0 to remove and 0 not upgraded."),
              (31, "Need to get 14.2 MB of archives.")]
for i, pk in enumerate(PKGS):
    CLOUD_INIT.append((34 + i * 4, f"Unpacking {pk} ..."))
    CLOUD_INIT.append((36 + i * 4, f"Setting up {pk} ..."))
CLOUD_INIT += [(95, "Processing triggers for man-db (2.13.1-1) ..."),
               (100, "PASSWORD-SET"),
               (104, "Cloud-init v. 25.1.4-1 finished at Mon, 05 Oct 2026 10:03:46 +0000. Datasource DataSourceNoCloud [seed=/dev/sdb]. Up 105.71 seconds"),
               (108, "SEED-SCRUBBED")]


def guest(vmid):
    """(vmid, name, node, template, status, tags) for a fixed guest or one a deploy made."""
    g = next((x for x in GUESTS if x[0] == vmid), None)
    if g or vmid not in MADE:
        return g
    v = MADE[vmid]
    return (vmid, v["name"], v["node"], 0, vm_state(vmid), "os-debian")


def vm_state(vmid):
    v = MADE[vmid]
    if v["stopped"] or not v["boots"]:
        return "stopped"
    if len(v["boots"]) == 1 and time.time() - v["boots"][0] > FIRST_BOOT:
        return "stopped"
    return "running"


def cloud_init_log(vmid):
    v = MADE.get(vmid)
    if not v or not v["boots"]:
        return ""
    t = time.time() - v["boots"][0]
    return "".join(l + "\n" for at, l in CLOUD_INIT if at <= t)


def resources():
    out = []
    for n in NODES:
        out.append({"id": f"node/{n['node']}", "type": "node", "node": n["node"], "status": "online", "cpu": n["cpu"],
                    "maxcpu": n["maxcpu"], "mem": n["mem"], "maxmem": n["maxmem"], "disk": n["disk"], "maxdisk": n["maxdisk"],
                    "uptime": 1_200_000, "level": ""})
        for s in STORAGES:
            out.append({"id": f"storage/{n['node']}/{s['storage']}", "type": "storage", "node": n["node"], "storage": s["storage"],
                        "status": "available", "content": s["content"], "shared": s["shared"], "plugintype": s["type"],
                        "disk": s["disk"], "maxdisk": s["maxdisk"]})
        for b in BRIDGES:
            out.append({"id": f"sdn/{n['node']}/localnetwork", "type": "sdn", "node": n["node"], "sdn": "localnetwork", "status": "ok"})
    for vmid, name, node, tpl, status, tags in GUESTS + [guest(v) for v in MADE]:
        out.append({"id": f"qemu/{vmid}", "type": "qemu", "vmid": vmid, "name": name, "node": node, "template": tpl,
                    "status": status, "tags": tags, "pool": "vm-studio" if tpl else "lab",
                    "cpu": 0.03 if status == "running" else 0, "maxcpu": 4, "mem": 3 * 2**30 if status == "running" else 0,
                    "maxmem": 8 * 2**30, "disk": 0, "maxdisk": 64 * 2**30, "uptime": 86_400 if status == "running" else 0})
    for p in POOLS:
        out.append({"id": f"/pool/{p['poolid']}", "type": "pool", "pool": p["poolid"]})
    return out


def task(node, secs=0):
    upid = f"UPID:{node}:0000AAAA:0000BBBB:{int(time.time() * 1000):08X}:qmcreate:demo:root@pam:"
    TASKS[upid] = time.time() + secs
    return upid


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass

    def send(self, data, code=200):
        body = json.dumps({"data": data}).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def route(self, method):
        u = urllib.parse.urlparse(self.path)
        p = u.path.removeprefix("/api2/json")
        q = urllib.parse.parse_qs(u.query)
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        body = urllib.parse.parse_qs(raw.decode(errors="replace")) if "urlencoded" in (self.headers.get("Content-Type") or "") else {}
        if p == "/demo/reset":
            MADE.clear()
            return self.send(None)
        if method == "POST" and p == "/access/ticket":
            return self.send({"username": "root@pam", "ticket": "PVE:root@pam:DEMO::ticket", "CSRFPreventionToken": "DEMO:csrf",
                              "cap": {}})
        if p == "/access/domains":
            return self.send([{"realm": "pam", "type": "pam", "comment": "Linux PAM standard authentication"},
                              {"realm": "pve", "type": "pve", "comment": "Proxmox VE authentication server"}])
        if p == "/access/permissions":
            allp = {k: 1 for k in ["Sys.Modify", "Sys.Audit", "VM.Allocate", "VM.Config.Disk", "Datastore.Allocate", "Pool.Allocate",
                                   "Sys.AccessNetwork", "VM.Audit", "Datastore.Audit", "SDN.Use", "VM.Console", "VM.PowerMgmt"]}
            return self.send({"/": allp, "/vms": allp, "/nodes": allp, "/storage": allp, "/pool": allp})
        if p == "/version":
            return self.send({"version": "9.0.10", "release": "9.0", "repoid": "deadbeef"})
        if p == "/cluster/status":
            st = [{"type": "cluster", "id": "cluster", "name": "lab", "quorate": 1, "nodes": len(NODES), "version": 3}]
            st += [{"type": "node", "id": f"node/{n['node']}", "name": n["node"], "online": 1, "ip": n["ip"], "local": int(i == 0),
                    "nodeid": i + 1} for i, n in enumerate(NODES)]
            return self.send(st)
        if p == "/cluster/resources":
            t = (q.get("type") or [None])[0]
            r = resources()
            if t == "vm":
                r = [x for x in r if x["type"] in ("qemu", "lxc")]
            elif t:
                r = [x for x in r if x["type"] == t]
            return self.send(r)
        if p == "/cluster/sdn/vnets":
            return self.send(VNETS)
        if p == "/cluster/nextid":
            VMID_NEXT[0] += 1
            return self.send(str(VMID_NEXT[0]))
        if p == "/cluster/options":
            return self.send({"tag-style": {"color-map": ""}} if method == "GET" else None)
        if p == "/storage":
            return self.send(STORAGES)
        if p == "/pools":
            return self.send(POOLS if method == "GET" else None)
        m = re.match(r"^/pools/([^/]+)$", p)
        if m:
            return self.send({"poolid": m[1], "members": []} if method == "GET" else None)
        if p == "/nodes":
            return self.send([{"node": n["node"], "status": "online", "maxcpu": n["maxcpu"], "maxmem": n["maxmem"], "mem": n["mem"]} for n in NODES])
        m = re.match(r"^/nodes/([^/]+)/network$", p)
        if m:
            return self.send(BRIDGES)
        m = re.match(r"^/nodes/([^/]+)/storage/([^/]+)/content$", p)
        if m:
            if method == "GET":
                ct = (q.get("content") or [None])[0]
                out = [{"volid": f"{s}:iso/{f}", "format": "iso", "size": sz, "content": "iso"} for s, f, sz in ISOS if s == m[2]]
                return self.send(out if ct in (None, "iso") else [])
            return self.send(task(m[1]))
        m = re.match(r"^/nodes/([^/]+)/storage/([^/]+)/(upload|download-url)$", p)
        if m:
            return self.send(task(m[1]))
        m = re.match(r"^/nodes/([^/]+)/storage/([^/]+)/status$", p)
        if m:
            s = next((x for x in STORAGES if x["storage"] == m[2]), STORAGES[0])
            return self.send({"total": s["maxdisk"], "used": s["disk"], "avail": s["maxdisk"] - s["disk"], "active": 1, "enabled": 1})
        m = re.match(r"^/nodes/([^/]+)/tasks/([^/]+)/status$", p)
        if m:
            upid = urllib.parse.unquote(m[2])
            if time.time() < TASKS.get(upid, 0):
                return self.send({"status": "running", "upid": upid})
            return self.send({"status": "stopped", "exitstatus": "OK", "upid": upid})
        m = re.match(r"^/nodes/([^/]+)/tasks/([^/]+)/log$", p)
        if m:
            return self.send([{"n": 1, "t": "TASK OK"}])
        m = re.match(r"^/nodes/([^/]+)/qemu/?$", p)
        if m:
            if method == "POST":
                return self.send(task(m[1]))
            return self.send([{"vmid": g[0], "name": g[1], "status": g[4], "template": g[3]} for g in GUESTS + [guest(v) for v in MADE] if g[2] == m[1]])
        m = re.match(r"^/nodes/([^/]+)/qemu/(\d+)/(config|resize|status/\w+|clone|template|agent/[\w-]+|agent)$", p)
        if m:
            vmid, what = int(m[2]), m[3]
            if what == "clone" and method == "POST":
                new = int(body["newid"][0])
                MADE[new] = {"name": body.get("name", [f"vm-{new}"])[0], "node": body.get("target", [m[1]])[0], "boots": [], "stopped": True}
                return self.send(task(m[1], 9))
            if vmid in MADE and what.startswith("status/") and method == "POST":
                if what == "status/start":
                    MADE[vmid]["boots"].append(time.time())
                    MADE[vmid]["stopped"] = False
                elif what in ("status/stop", "status/shutdown"):
                    MADE[vmid]["stopped"] = True
                return self.send(task(m[1], 2))
            if vmid in MADE and what == "agent/file-read":
                off = int((q.get("offset") or ["0"])[0])
                return self.send({"content": cloud_init_log(vmid)[off:], "bytes-read": 0})
            if vmid in MADE and what == "agent/network-get-interfaces" and vm_state(vmid) == "running" and len(MADE[vmid]["boots"]) > 1:
                return self.send({"result": [{"name": "ens18", "ip-addresses": [{"ip-address": "10.10.0.40", "ip-address-type": "ipv4", "prefix": 24}]}]})
            g = guest(vmid)
            if what == "config" and method == "GET":
                return self.send({"name": g[1] if g else f"vm-{vmid}", "cores": 4, "memory": "8192", "scsi0": "local-lvm:base-9001-disk-1,size=40G",
                                  "efidisk0": "local-lvm:vm-9001-disk-0,efitype=4m,ms-cert=2023k,pre-enrolled-keys=1,size=4M",
                                  "net0": "virtio=BC:24:11:00:00:01,bridge=vmbr0", "tags": g[5] if g else "", "template": g[3] if g else 0})
            if what == "status/current":
                return self.send({"status": g[4] if g else "stopped", "qmpstatus": g[4] if g else "stopped", "agent": 1})
            if what.startswith("agent"):
                return self.send({"result": []})
            return self.send(task(m[1]) if method == "POST" else None)
        m = re.match(r"^/nodes/([^/]+)/qemu/(\d+)$", p)
        if m and method == "DELETE":
            return self.send(task(m[1]))
        m = re.match(r"^/nodes/([^/]+)/(status|version)$", p)
        if m:
            n = next((x for x in NODES if x["node"] == m[1]), NODES[0])
            return self.send({"cpu": n["cpu"], "memory": {"total": n["maxmem"], "used": n["mem"]}, "pveversion": "pve-manager/9.0.10", "version": "9.0.10"})
        print(f"404 {method} {self.path}", file=sys.stderr, flush=True)
        return self.send(None, 404)

    def do_GET(self):
        self.route("GET")

    def do_POST(self):
        self.route("POST")

    def do_PUT(self):
        self.route("PUT")

    def do_DELETE(self):
        self.route("DELETE")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8006)
    a = ap.parse_args()
    d = tempfile.mkdtemp()
    cert, key = os.path.join(d, "c.pem"), os.path.join(d, "k.pem")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=pve-01", "-days", "2",
                    "-keyout", key, "-out", cert], check=True, capture_output=True)
    srv = ThreadingHTTPServer(("127.0.0.1", a.port), H)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    print(f"mock PVE on https://127.0.0.1:{a.port}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
