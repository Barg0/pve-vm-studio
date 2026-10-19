"""cisv third: second opinions - Ansible Lockdown (goss/syver) and OpenSCAP with ComplianceAsCode -
run on a test VM and normalised to one verdict per CIS number in <work>/vm/<name>/third.json.
Ported from tpaudit.sh, cmpld.py, ldfail.py and profiles.py (2026-10-16).

Both install things on the VM (Lockdown: /opt/<repo> and a binary; OpenSCAP: a package with
--install), so run them after `cisv vm run`, never before.
"""
import collections
import hashlib
import io
import json
import re
import shutil
import subprocess
import tarfile
import tempfile
import urllib.request
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path

from . import benchmarks, pdf, vm as vmmod
from .log import log

XCCDF = '{http://checklists.nist.gov/xccdf/1.2}'


# ---- fetch: audit repositories at the right branch, the binaries ----
def fetch(cfg):
    tp = cfg.thirdparty
    (tp / 'bin').mkdir(parents=True, exist_ok=True)
    seen = set()
    for img, ld in benchmarks.LOCKDOWN.items():
        d = tp / f'{ld["repo"]}@{ld["branch"]}'
        if d in seen:
            continue
        seen.add(d)
        if d.exists():
            subprocess.run(['git', '-C', str(d), 'pull', '--ff-only', '-q'], check=False)
        else:
            subprocess.run(['git', 'clone', '-q', '--depth', '1', '-b', ld['branch'],
                            f'https://github.com/ansible-lockdown/{ld["repo"]}.git', str(d)], check=True)
        rev = subprocess.run(['git', '-C', str(d), 'rev-parse', '--short', 'HEAD'], capture_output=True, text=True)
        log('ok', f'{d.name}: {rev.stdout.strip()}')
    for name, b in benchmarks.BINARIES.items():
        dst = tp / 'bin' / name
        if dst.exists():
            continue
        data = urllib.request.urlopen(b['url']).read()
        if 'sums' in b:
            sums = urllib.request.urlopen(b['sums']).read().decode()
            want = next((l.split()[0] for l in sums.splitlines() if l.strip().endswith(b['asset'])), None)
            got = hashlib.sha256(data).hexdigest()
            if want != got:
                raise SystemExit(f'{name}: sha256 {got} does not match SHA256SUMS ({want})')
        if b.get('member'):
            with tarfile.open(fileobj=io.BytesIO(data)) as t:
                data = t.extractfile(b['member']).read()
        dst.write_bytes(data)
        dst.chmod(0o755)
        log('get', f'{name}: {hashlib.sha256(data).hexdigest()}  {dst}')
    # the SSG release: only the datastreams the OSCAP table names are kept
    ssg = cfg.ssg_dir
    want = [o['ds'] for o in benchmarks.OSCAP.values() if o['source'] == 'zip']
    if not all((ssg / d).exists() for d in want):
        data = urllib.request.urlopen(benchmarks.SSG_ZIP['url']).read()
        ref = urllib.request.urlopen(benchmarks.SSG_ZIP['sha512']).read().decode().split()[0]
        got = hashlib.sha512(data).hexdigest()
        if ref != got:
            raise SystemExit(f'SSG zip: sha512 {got} does not match the published {ref}')
        ssg.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            for m in z.namelist():
                if Path(m).name in want:
                    (ssg / Path(m).name).write_bytes(z.read(m))
        log('get', f'SSG v0.1.82: sha512 ok, {len(want)} datastreams -> {ssg}')
    for d in want:
        if not (ssg / d).exists():
            raise SystemExit(f'{d}: not in the SSG release')


# ---- Lockdown ----
def lockdown(cfg, name):
    vm = cfg.vm(name)
    ld = benchmarks.LOCKDOWN.get(vm['image'])
    if not ld:
        log('warn', f'{name}: no Lockdown audit for {vm["image"]}')
        return
    src = cfg.thirdparty / f'{ld["repo"]}@{ld["branch"]}'
    binp = cfg.thirdparty / 'bin' / ld['bin']
    o = cfg.vm_dir(name)
    with tempfile.TemporaryDirectory() as tmp:
        stage = Path(tmp) / ld['repo']
        shutil.copytree(src, stage, ignore=shutil.ignore_patterns('.git'))
        for key, val in (ld.get('vars') or {}).items():
            vf = stage / 'vars' / 'CIS.yml'
            t = vf.read_text()
            t, n = re.subn(rf'(?m)^({re.escape(key)}:).*$', rf'\g<1> {val}', t)
            if not n:
                raise SystemExit(f'{key} not found in {vf}')
            vf.write_text(t)
        shutil.copy(binp, Path(tmp) / ld['bin'])
        tarp = Path(tmp) / 'tp.tar'
        with tarfile.open(tarp, 'w') as t:
            t.add(stage, arcname=ld['repo'])
            t.add(Path(tmp) / ld['bin'], arcname=ld['bin'])
        vmmod.put(cfg, vm, tarp, '/tmp/tp.tar')
    r = ld['repo']
    script = (f'set -u; rm -rf /tmp/tp /opt/{r}; mkdir -p /tmp/tp; tar xf /tmp/tp.tar -C /tmp/tp; '
              f'cp -r /tmp/tp/{r} /opt/{r}; install -m 0755 /tmp/tp/{ld["bin"]} /usr/local/bin/{ld["bin"]}; '
              f'cd /opt/{r} && AUDIT_BIN=/usr/local/bin/{ld["bin"]} bash run_audit.sh '
              f'-m {cfg.lockdown_concurrency} -f json -o /tmp/lockdown.json > /tmp/lockdown.log 2>&1; '
              f'chmod 644 /tmp/lockdown.json /tmp/lockdown.log\n')
    vmmod.root(cfg, vm, script)
    vmmod.get(cfg, vm, ['/tmp/lockdown.json', '/tmp/lockdown.log'], o)
    size = (o / 'lockdown.json').stat().st_size
    log('ok' if size else 'error', f'{name}: lockdown.json {size} bytes' + ('  (EMPTY - see lockdown.log; OOM?)' if not size else ''))


def lockdown_verdicts(path):
    """CIS number -> {'verdict': PASS|FAIL|SKIP, 'fail': [tests]} (cmpld.py's rule: any failed test fails)."""
    ld = json.loads(Path(path).read_text())
    by = collections.defaultdict(lambda: {'ok': 0, 'fail': [], 'skip': 0})
    for t in ld['results']:
        ids = (t.get('meta') or {}).get('CIS_ID') or []
        if isinstance(ids, str):
            ids = [ids]
        for cid in ids:
            b = by[cid]
            if t.get('skipped'):
                b['skip'] += 1
            elif t.get('successful'):
                b['ok'] += 1
            else:
                b['fail'].append(t)
    out = {}
    for cid, b in by.items():
        out[cid] = dict(verdict='FAIL' if b['fail'] else ('PASS' if b['ok'] else 'SKIP'),
                        fail=[f"{t.get('title', '')[:60]} :: {t.get('summary-line-compact', '')[:220]}"
                              for t in b['fail'][:3]])
    return out, ld.get('summary', {}).get('summary-line', '')


def lockdown_fails(path):
    d = json.loads(Path(path).read_text())
    for r in d['results']:
        if r.get('successful') or r.get('skipped'):
            continue
        ids = (r.get('meta') or {}).get('CIS_ID', ['?'])
        ids = ids if isinstance(ids, str) else ','.join(ids)
        m = r.get('matcher-result') or {}
        print(f"== {ids} | {r.get('title', '')[:70]} | {r.get('resource-id')} {r.get('property')}")
        print('   actual:', json.dumps(m.get('actual'))[:600])
        print('   expected:', json.dumps(m.get('expected'))[:400], 'missing:', json.dumps(m.get('missing-elements'))[:300])


# ---- OpenSCAP ----
def oscap(cfg, name, install=False):
    vm = cfg.vm(name)
    o = benchmarks.OSCAP.get(vm['image'])
    if not o or not o.get('profile'):
        log('warn', f'{name}: no OpenSCAP CIS profile for {vm["image"]}')
        return
    inst = ('command -v oscap >/dev/null || { command -v apt-get >/dev/null && apt-get install -y -q openscap-scanner '
            '|| dnf -y -q install openscap-scanner || zypper -q -n in openscap-utils; }; ') if install else ''
    if o['source'] == 'zip':
        ds = cfg.ssg_dir / o['ds']
        if not ds.exists():
            raise SystemExit(f'{ds} missing (SSG release zip, content/ folder)')
        vmmod.put(cfg, vm, ds, '/tmp/ssg-ds.xml')
        prep = 'cp /tmp/ssg-ds.xml /tmp/ssg-ds.xml.run'
    else:
        pkg = f'/usr/share/xml/scap/ssg/content/{o["ds"]}'
        if install:
            inst += f'test -f {pkg} || dnf -y -q install scap-security-guide; '
        prep = (f'test -f {pkg} || {{ echo "{pkg} missing (use --install)"; exit 9; }}; cp {pkg} /tmp/ssg-ds.xml.run; '
                f'rpm -q scap-security-guide > /tmp/oscap.ssg-version')
    script = (f'{inst}command -v oscap >/dev/null || {{ echo "oscap not installed (use --install)"; exit 9; }}; {prep}; '
              f'oscap xccdf eval --profile {o["profile"]} --results /tmp/oscap.xml --report /tmp/oscap.html '
              f'/tmp/ssg-ds.xml.run > /tmp/oscap.log 2>&1; chmod 644 /tmp/oscap.xml /tmp/oscap.html /tmp/oscap.log '
              f'/tmp/ssg-ds.xml.run\n')
    r = vmmod.root(cfg, vm, script)
    if r.returncode == 9:
        raise SystemExit(f'{name}: oscap or its datastream not installed (rerun with --install; that adds packages to the VM)')
    # the datastream that was run comes back too: oscap_verdicts() maps rules to CIS numbers with it
    vmmod.get(cfg, vm, ['/tmp/oscap.xml', '/tmp/oscap.html', '/tmp/oscap.log', '/tmp/ssg-ds.xml.run'], cfg.vm_dir(name))
    log('ok', f'{name}: oscap done')


def oscap_verdicts(results_xml, ds_xml):
    """CIS number -> {'verdict': pass|fail|other, 'rules': [rule ids]} via the CIS references in the datastream."""
    refs = collections.defaultdict(set)
    for rule in ET.parse(ds_xml).getroot().iter(XCCDF + 'Rule'):
        for ref in rule.findall(XCCDF + 'reference'):
            # benchmark numbers only: .../benchmark/<product>/ (debian13: .../cis-benchmarks/);
            # .../controls/ references carry CIS Controls ids, which look like rec numbers
            href = ref.get('href') or ''
            if 'cisecurity' in href and '/controls/' not in href and ref.text:
                for n in re.split(r'[,\s]+', ref.text.strip()):
                    if re.match(r'^\d+(\.\d+)+$', n):
                        refs[rule.get('id')].add(n)
    by = collections.defaultdict(lambda: {'pass': 0, 'fail': [], 'other': 0})
    for rr in ET.parse(results_xml).getroot().iter(XCCDF + 'rule-result'):
        res = rr.find(XCCDF + 'result')
        res = res.text if res is not None else ''
        for n in refs.get(rr.get('idref'), ()):
            if res == 'pass':
                by[n]['pass'] += 1
            elif res in ('fail', 'error'):
                by[n]['fail'].append(rr.get('idref'))
            else:
                by[n]['other'] += 1
    return {n: dict(verdict='fail' if b['fail'] else ('pass' if b['pass'] else 'other'), rules=b['fail'][:5])
            for n, b in by.items()}


def profiles(paths):
    ns = {'x': XCCDF[1:-1]}
    for f in paths:
        r = ET.parse(f).getroot()
        print('=====', Path(f).name)
        for b in r.iter(XCCDF + 'Benchmark'):
            for pl in b.findall('x:platform', ns):
                print('  platform:', pl.get('idref'))
            for p in b.findall('x:Profile', ns):
                pid = p.get('id')
                if 'cis' not in pid.lower():
                    continue
                title = p.find('x:title', ns).text
                d = p.find('x:description', ns)
                d = (d.text or '') if d is not None else ''
                m = re.findall(r'[Vv]ersion\s*[\w.]+|v\d+\.\d+\.\d+', d)
                n = len([s for s in p.findall('x:select', ns) if s.get('selected') == 'true'])
                print('  ', pid, '|', title, '|', m[:3], '| selected:', n)


# ---- normalise + diff against our live check ----
def normalise(cfg, name):
    vm = cfg.vm(name)
    o = cfg.vm_dir(name)
    ours = {r['id']: r for r in json.loads((o / 'live.json').read_text())['results']}
    third = {}
    lines = []
    if (o / 'lockdown.json').exists() and (o / 'lockdown.json').stat().st_size:
        ldv, summ = lockdown_verdicts(o / 'lockdown.json')
        lines.append(f'{name} lockdown: {summ}')
        agree = collections.Counter()
        for n in sorted(set(ldv) | set(ours), key=pdf.numkey):
            our = ours.get(n, {}).get('status', '-')
            l = ldv[n]['verdict'] if n in ldv else '-'
            agree[(our, l)] += 1
            if n in ldv:
                third.setdefault(n, {})['lockdown'] = l
            if (our == 'pass' and l == 'FAIL') or (our == 'fail' and l == 'PASS') or (our == 'na' and l == 'FAIL'):
                lines.append(f'{n:10} ours={our:9} lockdown={l:5} {ours.get(n, {}).get("title", "")[:40]} || '
                             + ' || '.join(ldv[n]['fail']))
        lines.insert(1, str(sorted(agree.items(), key=lambda x: -x[1])))
    osc = benchmarks.OSCAP.get(vm['image'])
    if (o / 'oscap.xml').exists() and osc:
        ov = oscap_verdicts(o / 'oscap.xml', o / 'ssg-ds.xml.run')
        for n, v in ov.items():
            third.setdefault(n, {})['oscap'] = v['verdict']
            our = ours.get(n, {}).get('status', '-')
            if (our == 'pass' and v['verdict'] == 'fail') or (our == 'fail' and v['verdict'] == 'pass'):
                lines.append(f'{n:10} ours={our:9} oscap={v["verdict"]:5} {", ".join(v["rules"])}')
    (o / 'third.json').write_text(json.dumps(third, indent=1))
    (o / 'third-diff.txt').write_text('\n'.join(lines) + '\n')
    log('ok', f"{name}: {len(third)} recs with a second opinion, {sum(1 for l in lines if ' ours=' in l)} disagreements -> third-diff.txt")


def cmd_third(cfg, args):
    a = args.action
    if a == 'fetch':
        fetch(cfg)
    elif a == 'profiles':
        profiles(args.names)
    elif a == 'fails':
        lockdown_fails(cfg.vm_dir(cfg.vm(args.names[0])['name']) / 'lockdown.json')
    else:
        for n in args.names or list(cfg.vms()):
            if a == 'lockdown':
                lockdown(cfg, n)
            elif a == 'oscap':
                oscap(cfg, n, args.install)
            elif a == 'diff':
                normalise(cfg, n)
    return 0
