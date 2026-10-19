"""Configuration: paths, SSH, the inventory of test VMs. See config.example.toml."""
import datetime
import json
import os
from pathlib import Path

from . import guard

TOOL_DIR = Path(__file__).resolve().parent.parent
REPO = TOOL_DIR.parent.parent


class Config:
    def __init__(self, data, path=None):
        p = data.get('paths', {})
        today = datetime.date.today().isoformat()
        x = lambda v: Path(os.path.expanduser(v)) if v else None
        self.path = path
        self.pdf_dir = x(p.get('pdf_dir', '~/Documents/cis'))
        self.work = x(p.get('work_dir', f'~/Documents/cis/run-{today}'))
        self.cis_dir = x(p.get('cis_dir')) or REPO / 'guest-files' / 'cis'
        self.inventory = x(p.get('inventory')) or self.work / 'inventory.tsv'
        self.thirdparty = x(p.get('thirdparty_dir')) or self.work / 'thirdparty'
        b = data.get('bin', {})
        self.pdftotext = b.get('pdftotext', 'pdftotext')
        s = data.get('ssh', {})
        self.ssh_key = x(s.get('key'))
        self.ssh_opts = s.get('options', ['-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=accept-new',
                                          '-o', 'ConnectTimeout=15'])
        self.pve_host = s.get('pve_host', 'root@pve-01.testitfirst.dev')
        st = data.get('studio', {})
        self.studio_ct = int(st.get('ct', 100))
        self.studio_data = st.get('data_dir', '/var/lib/pve-vm-studio')
        g = data.get('guard', {})
        self.extra_vmids = g.get('vmids', [])
        self.extra_names = g.get('names', [])
        # cisv deploy: where test VMs go (first_ip, bridge, vlan, gateway, dns, memory_mb, cores)
        self.deploy = data.get('deploy', {})
        a = data.get('audit', {})
        self.lockdown_concurrency = int(a.get('lockdown_concurrency', 5))
        self.ssg_dir = x(a.get('ssg_dir')) or self.thirdparty / 'ssg'

    # ---- the work tree ----
    def pdf_out(self, base, ext):
        d = self.work / 'pdf'
        d.mkdir(parents=True, exist_ok=True)
        return d / f'{base}.{ext}'

    def vm_dir(self, name):
        d = self.work / 'vm' / name
        d.mkdir(parents=True, exist_ok=True)
        return d

    def guard(self, name=None, vmid=None):
        guard.ensure_allowed(name, vmid, self.extra_vmids, self.extra_names)

    # ---- inventory: name ip user image [vmid] [password], tab separated, # comments ----
    def vms(self):
        if not self.inventory.exists():
            raise SystemExit(f'no inventory at {self.inventory}')
        out = {}
        for line in self.inventory.read_text().splitlines():
            if not line.strip() or line.startswith('#'):
                continue
            f = line.split('\t') + [''] * 6
            vm = dict(name=f[0], ip=f[1], user=f[2], image=f[3], vmid=f[4], password=f[5])
            self.guard(vm['name'], vm['vmid'])
            out[vm['name']] = vm
        return out

    def vm(self, name):
        self.guard(name)
        vms = self.vms()
        if name not in vms:
            raise SystemExit(f'{name}: not in {self.inventory}')
        return vms[name]


def load(path=None):
    path = path or os.environ.get('CISV_CONFIG') or TOOL_DIR / 'config.toml'
    path = Path(path)
    if not path.exists():
        return Config({}, None)
    raw = path.read_bytes()
    if path.suffix == '.json':
        return Config(json.loads(raw), path)
    import tomllib
    return Config(tomllib.loads(raw.decode()), path)
