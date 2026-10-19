"""cisv vm: the test VMs from the inventory - list, root shell, file copy, the PDF runner + our live
check, and the gold bake reports from the studio. Ported from vmsh.sh, vmx.sh, vmrun.sh, pull.sh
and summ.py (2026-10-16).

Root is reached with `sudo -S` when the inventory has a password (the first stdin line), with
`sudo -n` otherwise. Every entry point goes through Config.vm(), which runs the guard.
"""
import io
import json
import subprocess
import sys
import tarfile

from . import benchmarks
from .log import log


def ssh_base(cfg):
    cmd = ['ssh'] + list(cfg.ssh_opts)
    if cfg.ssh_key:
        cmd += ['-i', str(cfg.ssh_key)]
    return cmd


def scp_base(cfg):
    cmd = ['scp', '-q'] + list(cfg.ssh_opts)
    if cfg.ssh_key:
        cmd += ['-i', str(cfg.ssh_key)]
    return cmd


def target(vm):
    return f'{vm["user"]}@{vm["ip"]}'


def root(cfg, vm, script, timeout=None, capture=True):
    """Run a bash script as root on the VM; returns CompletedProcess (text)."""
    if vm['password']:
        stdin = vm['password'] + '\n' + script
        remote = 'sudo -S -p "" bash -s'
    else:
        stdin = script
        remote = 'sudo -n bash -s'
    return subprocess.run(ssh_base(cfg) + [target(vm), remote], input=stdin, text=True,
                          capture_output=capture, timeout=timeout)


def put(cfg, vm, local, remote):
    subprocess.run(scp_base(cfg) + [str(local), f'{target(vm)}:{remote}'], check=True)


def get(cfg, vm, remotes, local_dir):
    subprocess.run(scp_base(cfg) + [f'{target(vm)}:{r}' for r in remotes] + [str(local_dir)], check=True)


def live_check(level=2):
    return (f'/usr/local/sbin/pvs-cis check --level {level} --exceptions /etc/pvs-cis/exceptions '
            f'--json /tmp/live.json > /tmp/live.txt 2>&1; chmod 644 /tmp/live.json /tmp/live.txt')


def run_pdf_audit(cfg, name):
    """PDF runner + our live check on one VM -> <work>/vm/<name>/{pdf-audit.out,live.json,live.txt}."""
    vm = cfg.vm(name)
    base = benchmarks.PDFS[vm['image']]
    runner = cfg.pdf_out(base, 'runner.sh')
    if not runner.exists():
        raise SystemExit(f'{runner} missing - run `cisv runner {vm["image"]}`')
    o = cfg.vm_dir(name)
    put(cfg, vm, runner, '/tmp/pdf-audit.sh')
    # ours first: the PDF runner only reads, but third-party audits later install things
    r = root(cfg, vm, live_check() + '\nbash /tmp/pdf-audit.sh > /tmp/pdf-audit.out 2> /tmp/pdf-audit.log; '
                                     'chmod 644 /tmp/pdf-audit.out /tmp/pdf-audit.log\n')
    if r.returncode:
        log('error', f'{name}: runner exit {r.returncode}', r.stderr.strip())
    get(cfg, vm, ['/tmp/pdf-audit.out', '/tmp/pdf-audit.log', '/tmp/live.json', '/tmp/live.txt'], o)
    recs = sum(1 for l in (o / 'pdf-audit.out').read_text(errors='ignore').splitlines() if l.startswith('@@@REC'))
    log('ok', f'{name}: {recs} recs')


def pull_golds(cfg):
    """Every gold's CIS report from the studio container (not the .grub password files)."""
    out = cfg.work / 'gold-reports'
    out.mkdir(parents=True, exist_ok=True)
    remote = (f'pct exec {cfg.studio_ct} -- sh -c "cd {cfg.studio_data}/cis-reports && tar cf - *.json"')
    p = subprocess.run(ssh_base(cfg) + [cfg.pve_host, remote], capture_output=True, check=True)
    with tarfile.open(fileobj=io.BytesIO(p.stdout)) as t:
        names = [m for m in t.getmembers() if m.isfile() and m.name.endswith('.json') and '/' not in m.name]
        t.extractall(out, members=names)
    log('ok', f'{len(names)} reports -> {out}')


def summary(paths, only=()):
    for f in sorted(paths):
        if only and not any(x in str(f) for x in only):
            continue
        r = json.loads(open(f).read())
        c = {}
        for x in r['results']:
            c[x['status']] = c.get(x['status'], 0) + 1
        print('==', f.name[:24], r['benchmark'], r['version'], 'L' + str(r['level']), c)
        for x in r['results']:
            if x['status'] not in ('pass', 'na', 'review'):
                print('   ', x['status'], x['id'], x['title'], '::',
                      str(x['evidence'])[:260].replace('\n', ' / '))


def cmd_vm(cfg, args):
    if args.action == 'list':
        for vm in cfg.vms().values():
            print('\t'.join([vm['name'], vm['ip'], vm['user'], vm['image'], vm['vmid'] or '-']))
    elif args.action == 'sh':
        vm = cfg.vm(args.name)
        script = sys.stdin.read() if args.script in (None, '-') else open(args.script).read()
        r = root(cfg, vm, script, capture=False)
        return r.returncode
    elif args.action == 'put':
        put(cfg, cfg.vm(args.name), args.src, args.dst)
    elif args.action == 'get':
        get(cfg, cfg.vm(args.name), [args.src], args.dst)
    elif args.action == 'run':
        for n in args.names or list(cfg.vms()):
            run_pdf_audit(cfg, n)
    elif args.action == 'golds':
        pull_golds(cfg)
    elif args.action == 'summary':
        if args.names:
            paths = [cfg.vm_dir(n) / 'live.json' for n in args.names]
        else:
            paths = list((cfg.work / 'gold-reports').glob('*.json'))
        summary(paths)
    return 0
