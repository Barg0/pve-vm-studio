"""cisv join: one review file per chapter under <work>/vm/<name>/review/, each recommendation with
our live verdict + evidence, the PDF's audit text, the raw output of every audit block, and the
second opinions (PDF script verdict, Lockdown, OpenSCAP) with a flag where they disagree.
Plus review/INDEX.md: counts and the disagreement list to start from. Ported from join.py and
compact.py (2026-10-16); the layout is unchanged so REVIEW-INSTRUCTIONS.md still applies.
"""
import json
import re

from . import pdf, runner
from .log import log

BAD = {'fail'}
GOOD = {'pass'}


def parse_runner_output(raw):
    """'<num>.<k>' -> (output, rc)."""
    blocks = {}
    cur = None
    for part in re.split(r'^(@@@(?:REC|CMD|SCRIPT) \S+.*)$', raw, flags=re.M):
        m = re.match(r'@@@(CMD|SCRIPT) (\S+)', part)
        if m:
            cur = m.group(2)
            blocks[cur] = ''
            continue
        if part.startswith('@@@REC'):
            cur = None
            continue
        if cur:
            blocks[cur] += part
    out = {}
    for k, v in blocks.items():
        v = v.strip()
        rc = re.search(r'@@@RC (\d+)\s*$', v)
        out[k] = (re.sub(r'@@@RC \d+\s*$', '', v).strip(), rc.group(1) if rc else '?')
    return out


def opinions(ours, pdfv, third):
    """Normalised second opinions and whether any contradicts ours."""
    ops = {}
    if pdfv in ('pass', 'fail'):
        ops['pdf'] = pdfv
    for src, v in (third or {}).items():
        v = v.lower()
        if v in ('pass', 'fail'):
            ops[src] = v
    contra = (ours in GOOD and any(v in BAD for v in ops.values())) or \
             (ours in BAD and any(v in GOOD for v in ops.values())) or \
             (ours == 'na' and any(v in BAD for v in ops.values()))
    return ops, contra


def build(cfg, name):
    v = cfg.vm(name)
    base, recs, aud = pdf.load(cfg, v['image'])
    o = cfg.vm_dir(name)
    live = json.loads((o / 'live.json').read_text())
    ours = {r['id']: r for r in live['results']}
    blocks = parse_runner_output((o / 'pdf-audit.out').read_text(errors='ignore'))
    third = json.loads((o / 'third.json').read_text()) if (o / 'third.json').exists() else {}
    rd = o / 'review'
    rd.mkdir(exist_ok=True)
    by_ch = {}
    flagged = []
    counts = {}
    for n in sorted(recs, key=pdf.numkey):
        r = recs[n]
        mine = ours.get(n, {})
        st = mine.get('status', 'MISSING')
        counts[st] = counts.get(st, 0) + 1
        keys = sorted([k for k in blocks if k.rsplit('.', 1)[0] == n], key=lambda k: int(k.rsplit('.', 1)[1]))
        pv = [runner.verdict(blocks[k][0]) for k in keys]
        pdfv = 'fail' if 'fail' in pv else ('pass' if 'pass' in pv else 'raw')
        ops, contra = opinions(st, pdfv, third.get(n))
        flag = '  FLAG: DISAGREE' if contra else ''
        if contra or st == 'MISSING':
            flagged.append(f'- {n} ours={st} ' + ' '.join(f'{k}={x}' for k, x in ops.items()))
        txt = [f'### {n}  L{r["level"]} {r["kind"]}  OURS: {st}  — {r["title"]}',
               f'second opinions: pdf-script={pdfv} ' + ' '.join(f'{k}={x}' for k, x in (third.get(n) or {}).items()) + flag,
               f'our evidence: {mine.get("evidence", "")}',
               '--- PDF audit text ---', aud[n]['audit'].strip(), '--- raw outputs ---']
        for k in keys:
            out, rc = blocks[k]
            txt.append(f'[{k} rc={rc}] ' + (out[:1500] if out else '(no output)'))
        by_ch.setdefault(n.split('.')[0], []).append('\n'.join(txt))
    for ch, items in by_ch.items():
        (rd / f'ch{ch}.md').write_text(f'# {base} on {name} - chapter {ch}\n\n' + '\n\n'.join(items) + '\n')
    extra = sorted(set(ours) - set(recs), key=pdf.numkey)
    idx = [f'# {base} on {name}', '', f'ours: {counts}', f'checked by us but not in the PDF: {extra or "none"}', '',
           f'## Disagreements and gaps ({len(flagged)})', ''] + flagged
    (rd / 'INDEX.md').write_text('\n'.join(idx) + '\n')
    log('ok', name, {ch: len(v) for ch, v in by_ch.items()}, f'flagged {len(flagged)}')


def compact(path):
    """Header, evidence and raw output only - a review file without the PDF text, for a quick pass."""
    txt = open(path).read()
    out_all = []
    for blk in re.split(r'\n(?=### )', txt):
        if not blk.startswith('###'):
            continue
        lines = blk.split('\n')
        out = [lines[0]]
        mode = None
        for l in lines[1:]:
            if l.startswith('our evidence') or l.startswith('second opinions'):
                mode = 'ev'
            elif l.startswith('--- PDF audit'):
                mode = 'pdf'
                continue
            elif l.startswith('--- raw'):
                mode = 'raw'
                out.append('RAW:')
                continue
            if mode in ('ev', 'raw'):
                out.append(l[:220])
        out_all.append('\n'.join(out[:60]))
    print('\n'.join(out_all))


def cmd_join(cfg, args):
    if args.compact:
        for f in args.names:
            compact(f)
        return 0
    for n in args.names or list(cfg.vms()):
        build(cfg, n)
    return 0
