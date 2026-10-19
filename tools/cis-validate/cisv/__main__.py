"""cisv - validate the studio's CIS implementation against the benchmarks' own audit procedures."""
import argparse
import sys

from . import config, deploy, guard, join, mapcheck, mutate, pdf, runner, static, studio, third, vm, winmap, winparse
from .log import log, set_file


def main(argv=None):
    ap = argparse.ArgumentParser(prog='cisv', description=__doc__)
    ap.add_argument('-c', '--config', help='config file (default: $CISV_CONFIG or tools/cis-validate/config.toml)')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('extract', help='PDF -> text, recommendations, audit sections (work/pdf/)')
    p.add_argument('images', nargs='*')
    p.add_argument('--force', action='store_true', help='rerun pdftotext')
    p.set_defaults(fn=pdf.cmd_extract)

    p = sub.add_parser('mapcheck', help='map.tsv against the PDF; loose title matches')
    p.add_argument('images', nargs='*')
    p.add_argument('--no-loose', dest='loose', action='store_false')
    p.add_argument('--threshold', type=float, default=0.34)
    p.set_defaults(fn=mapcheck.cmd_mapcheck)

    p = sub.add_parser('runner', help='bash runner of the PDF audit commands + parse report')
    p.add_argument('images', nargs='*')
    p.add_argument('--no-syntax', action='store_true', help='skip bash -n per block')
    p.set_defaults(fn=runner.cmd_runner)

    p = sub.add_parser('vm', help='test VMs: list | sh | put | get | run | golds | summary')
    p.add_argument('action', choices=['list', 'sh', 'put', 'get', 'run', 'golds', 'summary'])
    p.add_argument('names', nargs='*', help='sh: <vm> [script|-]; put/get: <vm> <src> <dst>; run/summary: [vm...]')
    p.set_defaults(fn=_vm)

    p = sub.add_parser('third', help='second opinions: fetch | lockdown | oscap | diff | fails | profiles')
    p.add_argument('action', choices=['fetch', 'lockdown', 'oscap', 'diff', 'fails', 'profiles'])
    p.add_argument('names', nargs='*', help='VM names (profiles: datastream files)')
    p.add_argument('--install', action='store_true', help='oscap: install the scanner on the VM if missing')
    p.set_defaults(fn=third.cmd_third)

    p = sub.add_parser('mutate', help='mutation tests: gen <image...> | run <vm...> | sum <vm...>')
    p.add_argument('action', choices=['gen', 'run', 'sum'])
    p.add_argument('names', nargs='+')
    p.set_defaults(fn=mutate.cmd_mutate)

    p = sub.add_parser('join', help='review files per VM and chapter (work/vm/<name>/review/)')
    p.add_argument('names', nargs='*', help='VM names, or review files with --compact')
    p.add_argument('--compact', action='store_true')
    p.set_defaults(fn=join.cmd_join)

    p = sub.add_parser('deploy', help='test VMs from the newest CIS golds: <image[:level]...> | --vmids')
    p.add_argument('specs', nargs='*', help='e.g. ubuntu2604:2 rocky9:1')
    p.add_argument('--prefix', default='cis-')
    p.add_argument('--suffix', default='')
    p.add_argument('--again', action='store_true', help='deploy even if the name is in the inventory')
    p.add_argument('--vmids', action='store_true', help='fill the vmid column from the Studio')
    p.set_defaults(fn=lambda cfg, a: deploy.cmd_vmids(cfg, a) if a.vmids else deploy.cmd_deploy(cfg, a))

    p = sub.add_parser('static', help='review packs: PDF audit + remediation + our code (work/static/)')
    p.add_argument('images', nargs='*', help='primary images (default: all, with deltas)')
    p.add_argument('--delta', action='store_true', help='also the delta packs for named images')
    p.set_defaults(fn=static.cmd_static)

    p = sub.add_parser('studio', help='the Studio API: get|put|post|delete <path> [json body], log <job id>')
    p.add_argument('method', choices=['get', 'put', 'post', 'delete', 'log'])
    p.add_argument('path', help='e.g. /api/settings/queue, or the job id for log')
    p.add_argument('body', nargs='?')
    p.set_defaults(fn=studio.cmd_studio)

    p = sub.add_parser('winparse', help='Windows benchmark PDFs -> TSV (work/windows/)')
    p.add_argument('pdfs', nargs='+', help='PDF file names in pdf_dir')
    p.set_defaults(fn=winparse.cmd_winparse)
    p = sub.add_parser('winmap', help='Windows Stand-alone benchmarks -> guest-files/cis/win/<bench>/rules.tsv')
    p.set_defaults(fn=winmap.cmd_winmap)

    args = ap.parse_args(argv)
    cfg = config.load(args.config)
    set_file(cfg.work / 'cisv.log')
    try:
        return args.fn(cfg, args) or 0
    except guard.GuardError as e:
        log('error', f'cisv: {e}')
        return 3


def _vm(cfg, args):
    n = args.names
    args.name = n[0] if n and args.action in ('sh', 'put', 'get') else None
    if args.action == 'sh':
        args.script = n[1] if len(n) > 1 else None
    if args.action in ('put', 'get'):
        if len(n) != 3:
            raise SystemExit(f'cisv vm {args.action} <vm> <src> <dst>')
        args.src, args.dst = n[1], n[2]
    return vm.cmd_vm(cfg, args)


if __name__ == '__main__':
    sys.exit(main())
