"""cisv static: review packs for reading every rule implementation against its PDF, no VM needed.

Per map and chapter group, one markdown file in <work>/static/<map>/: for each recommendation the
map row, the PDF's audit and remediation text, and the check_/fix_ functions the engine would run
for that benchmark (the families sourced in bench.conf order, as pvs-cis does, so a redefined
function shows the version that wins, with its file and line). The packs hold CIS text and stay
in the work tree.

A benchmark that shares its rule code and numbering with another one (Debian 13 with Ubuntu 26.04,
Debian 12 with Ubuntu 24.04, the three EL9 and EL10 PDFs) also gets a delta pack: only the
recommendations whose audit or remediation text differs from the primary's.
"""
import json
import re
import subprocess

from . import benchmarks, mapcheck, pdf
from .log import log

GROUPS = [('ch1', ['1']), ('ch2-4', ['2', '3', '4']), ('ch5', ['5']), ('ch6-7', ['6', '7'])]
# primary image -> images reviewed as a delta against it
DELTA = {'ubuntu2604': ['debian13'], 'ubuntu2404': ['debian12'],
         'alma9': ['rocky9', 'oracle9'], 'alma10': ['rocky10', 'oracle10']}
END = re.compile(r'\n\s*(Default Value:|References:|Additional Information:|CIS Controls:|MITRE ATT&CK)')

DUMP = r'''
set -u
LIB=$1; shift; FAMILY=$1; shift
. "$LIB/lib.sh"
declare -A K_TITLE
rule() { K_TITLE[$1]=$2; }
for fam in $FAMILY; do for f in "$LIB/$fam"/[0-9]*.sh; do [ -f "$f" ] && . "$f"; done; done
shopt -s extdebug
for k in "$@"; do
    fn=${k//-/_}
    printf '@@@KEY %s\t%s\n' "$k" "${K_TITLE[$k]:-}"
    for p in check fix; do
        if declare -F "${p}_$fn" >/dev/null; then
            printf '@@@FN %s\n' "$(declare -F "${p}_$fn")"
            declare -f "${p}_$fn"
        else
            printf '@@@FN %s_%s missing\n' "$p" "$fn"
        fi
    done
done
'''


def remediations(text, recs):
    """Each recommendation's text from 'Remediation:' to the next section heading."""
    L = text.split('\n')
    nums = sorted(recs, key=lambda n: recs[n]['line'])
    out = {}
    for idx, n in enumerate(nums):
        a = recs[n]['line']
        b = recs[nums[idx + 1]]['line'] if idx + 1 < len(nums) else len(L)
        body = '\n'.join(L[a:b])
        m = re.search(r'\n\s*Remediation:\s*\n', body)
        r = body[m.end():] if m else ''
        e = END.search(r)
        out[n] = re.sub(r'\n\s*Page \d+\s*\n\f?', '\n', r[:e.start()] if e else r)
    return out


def code(cfg, image, keys):
    conf = mapcheck.bench_conf(cfg, image)
    res = subprocess.run(['bash', '-c', DUMP, 'dump', str(cfg.cis_dir), conf['FAMILY'], *keys],
                         capture_output=True, text=True)
    if res.returncode:
        log('warn', f'{image}: function dump rc {res.returncode}: {res.stderr.strip()[:200]}')
    out, cur = {}, None
    for line in res.stdout.splitlines():
        if line.startswith('@@@KEY '):
            k, _, t = line[7:].partition('\t')
            cur = out[k] = {'title': t, 'text': []}
        elif cur is not None:
            cur['text'].append(line)
    return {k: (v['title'], '\n'.join(v['text'])) for k, v in out.items()}


def texts(cfg, image):
    base, recs, aud = pdf.load(cfg, image)
    txt = cfg.pdf_out(base, 'txt').read_text(encoding='utf-8', errors='ignore')
    return recs, aud, remediations(txt, recs)


DISTRO = re.compile(r'AlmaLinux OS|AlmaLinux|Rocky Linux|Oracle Linux|\b(?:almalinux|rocky|oracle|ol|rl|alma)\b')


def norm(s):
    """Text for 'is it the same rec': page numbers, wrapping, line continuations and the distro's
    own name do not count."""
    s = re.sub(r'Page \d+', '', s)
    s = DISTRO.sub('DISTRO', s)
    return re.sub(r'[\s\\•]+', '', s)


def entry(n, rec, row, audit, rem, fns):
    lvl, kind, key = row or ('-', '-', '-')
    title, body = fns.get(key, ('', '')) if row else ('', '')
    return (f'## {n} - {rec["title"]}\n'
            f'PDF: Server level {rec["level"]}, {rec["kind"]}. Map: level {lvl}, {kind}, key `{key}`'
            f'{" (" + title + ")" if title else ""}\n\n'
            f'### PDF audit\n```\n{audit.strip()}\n```\n### PDF remediation\n```\n{rem.strip()}\n```\n'
            f'### Our code\n```bash\n{body.strip() or "(not mapped)"}\n```\n')


def cmd_static(cfg, args):
    imgs = args.images or list(DELTA) + ['leap16']
    for img in imgs:
        mapd = mapcheck.map_dir(cfg, img)
        mp = mapcheck.read_map(cfg, mapd)
        recs, aud, rem = texts(cfg, img)
        fns = code(cfg, img, sorted({r[2] for r in mp.values() if r[2]}))
        d = cfg.work / 'static' / img
        d.mkdir(parents=True, exist_ok=True)
        for name, chs in GROUPS:
            ns = sorted((n for n in recs if n.split('.')[0] in chs), key=pdf.numkey)
            (d / f'{name}.md').write_text(
                f'# {benchmarks.PDFS[img]} - {name} ({len(ns)} recommendations)\n\n' +
                '\n'.join(entry(n, recs[n], mp.get(n), aud.get(n, {}).get('audit', ''), rem.get(n, ''), fns)
                          for n in ns))
        log('ok', f'{img}: packs in {d} ({len(recs)} recs, {len(fns)} rule keys)')
        for other in DELTA.get(img, []) if not args.images or args.delta else []:
            orecs, oaud, orem = texts(cfg, other)
            omap = mapcheck.read_map(cfg, mapcheck.map_dir(cfg, other))
            ofns = code(cfg, other, sorted({r[2] for r in omap.values() if r[2]}))
            diff = []
            for n in sorted(orecs, key=pdf.numkey):
                same = (n in recs and norm(orecs[n]['title']) == norm(recs[n]['title'])
                        and norm(oaud.get(n, {}).get('audit', '')) == norm(aud.get(n, {}).get('audit', ''))
                        and norm(orem.get(n, '')) == norm(rem.get(n, ''))
                        and omap.get(n) == mp.get(n)
                        and ofns.get((omap.get(n) or ['', '', ''])[2]) == fns.get((mp.get(n) or ['', '', ''])[2]))
                if not same:
                    diff.append(n)
            (d / f'delta-{other}.md').write_text(
                f'# {benchmarks.PDFS[other]} vs {benchmarks.PDFS[img]}: {len(diff)} recommendations differ\n'
                f'(title, audit, remediation, map row or effective code; everything else is identical '
                f'and covered by the {img} packs)\n\n' +
                '\n'.join(entry(n, orecs[n], omap.get(n), oaud.get(n, {}).get('audit', ''), orem.get(n, ''), ofns)
                          for n in diff))
            log('ok', f'{other}: delta vs {img}: {len(diff)} of {len(orecs)} recs differ')
