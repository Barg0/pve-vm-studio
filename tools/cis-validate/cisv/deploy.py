"""cisv deploy: test VMs from the newest ready CIS gold of each image and level, through the
Studio API (POST /api/vms) - the path a user's VM takes, so the clone is what users get.

Each VM gets a static address from the configured range, the admin user cisadmin with a
generated password (pwquality: 20 characters, four classes) and the runner's SSH key. The
inventory line (name ip user image vmid password) goes to the inventory file, which must not be
readable by anyone else: it holds the passwords.
"""
import json
import os
import secrets
import string
import time

from . import guard
from .log import log
from .studio import Studio

ALPHABET = string.ascii_letters + string.digits + '#%+-_=.'


def password():
    while True:
        p = ''.join(secrets.choice(ALPHABET) for _ in range(20))
        if all(any(c in s for c in p) for s in (string.ascii_lowercase, string.ascii_uppercase, string.digits, '#%+-_=.')):
            return p


def golds(st):
    """(image, level) -> newest ready gold with a CIS level."""
    out = {}
    for g in st.get('/api/golds'):
        if g.get('os') == 'windows' or g.get('status') != 'ready':
            continue
        try:
            lvl = (json.loads(g.get('options') or '{}').get('cis') or {}).get('level')
        except ValueError:
            lvl = None
        if not lvl:
            continue
        k = (g['image_id'], int(lvl))
        if k not in out or g['created_at'] > out[k]['created_at']:
            out[k] = g
    return out


def read_inventory(path):
    rows = {}
    if path.exists():
        for line in path.read_text().splitlines():
            if line.strip() and not line.startswith('#'):
                f = line.split('\t')
                rows[f[0]] = f
    return rows


def cmd_deploy(cfg, args):
    inv = cfg.inventory
    inv.parent.mkdir(parents=True, exist_ok=True)
    if inv.exists() and inv.stat().st_mode & 0o077:
        raise SystemExit(f'{inv} is readable by others - chmod 600 it first')
    have = read_inventory(inv)
    st = Studio()
    gs = golds(st)
    pub = open(str(cfg.ssh_key) + ".pub").read().strip()
    d = cfg.deploy
    used = {r[1] for r in have.values()}
    base = d['first_ip'].rsplit('.', 1)
    nxt = int(base[1])
    for spec in args.specs:
        img, _, lvl = spec.partition(':')
        lvl = int(lvl or 2)
        name = f"{args.prefix}{img}-l{lvl}{args.suffix}"
        guard.ensure_allowed(name=name, extra_names=cfg.extra_names)
        if name in have and not args.again:
            log('info', f'{name}: already in the inventory ({have[name][1]})')
            continue
        g = gs.get((img, lvl))
        if not g:
            log('warn', f'{name}: no ready CIS L{lvl} gold of {img}')
            continue
        ip = have[name][1] if name in have else None
        while not ip:
            cand = f'{base[0]}.{nxt}'
            nxt += 1
            if cand not in used:
                ip = cand
                used.add(ip)
        pw = password()
        body = dict(name=name, gold=g['id'], cores=d.get('cores', 2), memory_mb=d.get('memory_mb', 8192),
                    bridge=d['bridge'], vlan=d.get('vlan'), ip=ip, prefix=d.get('prefix', 24),
                    gateway=d['gateway'], dns=d['dns'], user='cisadmin', password=pw, ssh_key=pub,
                    start_after=True, tags=['cis-test'])
        r = st.post('/api/vms', body)
        log('run', f'{name}: deploying from gold {g["id"]} ({g.get("name_short", "")}) at {ip}, job {r.get("id")}')
        have[name] = [name, ip, 'cisadmin', img, '', pw, r.get('vm', '')]
        old = os.umask(0o077)
        try:
            inv.write_text('# name\tip\tuser\timage\tvmid\tpassword\tstudio-vm-id\n' +
                           ''.join('\t'.join(v) + '\n' for v in have.values()))
        finally:
            os.umask(old)
        os.chmod(inv, 0o600)
        time.sleep(1)
    return 0


def cmd_vmids(cfg, args):
    """Fill the inventory's vmid column from the Studio's VM list (after the deploys built)."""
    inv = cfg.inventory
    have = read_inventory(inv)
    st = Studio()
    by_name = {v['name']: v for v in st.get('/api/vms')}
    for n, f in have.items():
        v = by_name.get(n)
        if v and v.get('vmid'):
            guard.ensure_allowed(name=n, vmid=v['vmid'], extra_vmids=cfg.extra_vmids, extra_names=cfg.extra_names)
            f[4] = str(v['vmid'])
            log('ok', f'{n}: vmid {v["vmid"]} ({v.get("status")})')
    old = os.umask(0o077)
    try:
        inv.write_text('# name\tip\tuser\timage\tvmid\tpassword\tstudio-vm-id\n' + ''.join('\t'.join(f) + '\n' for f in have.values()))
    finally:
        os.umask(old)
    return 0
