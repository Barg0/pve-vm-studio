"""cisv extract: CIS PDF -> text -> recommendations (number, title, Server level, auto|manual)
and each recommendation's Audit section. Outputs go to <work>/pdf/ - they hold CIS text and
never belong in the repo.

Ported from pdfrecs.py and audits.py (run 2026-10-16). The leading [\\s\\f]* in HEAD is the fix
for the Enterprise Linux PDFs: there a recommendation heading often starts a page, and pdftotext
puts the form feed in front of the number.
"""
import json
import re
import subprocess

from . import benchmarks
from .log import log

HEAD = re.compile(r'^[\s\f]*(\d+(?:\.\d+)+)\s+(\S.*)$')
KIND = re.compile(r'\((Automated|Manual)\)\s*$')


def numkey(n):
    return [int(p) if p.isdigit() else 0 for p in n.split('.')]


def to_text(cfg, pdf, txt, force=False):
    if txt.exists() and not force:
        return
    # -layout keeps long audit commands on their line: on all 11 PDFs it gives fewer cut-off
    # commands and bash syntax errors than the default mode, with the same recommendations
    # (run-2026-10-17/pdftotext-modes.txt). What it drops are prose lines with <module>
    # placeholders the default mode took for commands.
    subprocess.run([cfg.pdftotext, '-layout', str(pdf), str(txt)], check=True)


def parse_recs(text):
    """Recommendations by number: title, kind (auto|manual), Server level (1|2|None), profiles, line."""
    L = text.split('\n')
    recs = {}
    i = 0
    while i < len(L):
        m = HEAD.match(L[i])
        if m and '....' not in L[i]:
            num, t = m.group(1), m.group(2).strip()
            # the title may wrap; look up to 3 lines for (Automated)/(Manual), then Profile Applicability
            k = i
            while not KIND.search(t) and k < i + 3 and k + 1 < len(L):
                k += 1
                t += ' ' + L[k].strip()
            km = KIND.search(t)
            if km:
                win = L[k + 1:k + 14]
                if any('Profile Applicability' in x for x in win[:3]):
                    prof = []
                    for x in win:
                        x2 = x.strip().lstrip('•o ').strip()
                        if x2.startswith('Description'):
                            break
                        if x2:
                            prof.append(x2)
                    srv = [p for p in prof if re.search(r'Level [12] - Server', p)]
                    lvl = min(int(re.search(r'Level ([12])', p).group(1)) for p in srv) if srv else None
                    recs[num] = dict(title=KIND.sub('', t).strip(),
                                     kind=km.group(1).lower().replace('automated', 'auto'),
                                     level=lvl, profiles=prof, line=i + 1)
                    i = k
        i += 1
    return recs


def parse_audits(text, recs):
    """Each recommendation's text between 'Audit:' and 'Remediation:', page furniture removed."""
    L = text.split('\n')
    nums = sorted(recs, key=lambda n: recs[n]['line'])
    out = {}
    for idx, n in enumerate(nums):
        a = recs[n]['line']
        b = recs[nums[idx + 1]]['line'] if idx + 1 < len(nums) else len(L)
        body = '\n'.join(L[a:b])
        m = re.search(r'\n\s*Audit:\s*\n(.*?)\n\s*Remediation:\s*\n', body, re.S)
        au = m.group(1) if m else ''
        au = re.sub(r'\n\s*Page \d+\s*\n(\f)?(Internal Only - General)?', '\n', au)
        out[n] = dict(audit=au,
                      script=('#!/usr/bin/env bash' in au or '#!/bin/bash' in au),
                      verdict=('** PASS **' in au or '**PASS**' in au or '** FAIL **' in au))
    return out


def load(cfg, image):
    base = benchmarks.PDFS[image]
    recs = json.loads(cfg.pdf_out(base, 'json').read_text())
    aud = json.loads(cfg.pdf_out(base, 'audit.json').read_text())
    return base, recs, aud


def cmd_extract(cfg, args):
    imgs = args.images or benchmarks.images()
    done = set()
    for img in imgs:
        base = benchmarks.PDFS[img]
        if base in done:
            continue
        done.add(base)
        pdf = cfg.pdf_dir / f'{base}.pdf'
        if not pdf.exists():
            log('error', f'{img}: missing {pdf}')
            continue
        txt = cfg.pdf_out(base, 'txt')
        to_text(cfg, pdf, txt, args.force)
        text = txt.read_text(encoding='utf-8', errors='ignore')
        recs = parse_recs(text)
        aud = parse_audits(text, recs)
        cfg.pdf_out(base, 'json').write_text(json.dumps(recs))
        cfg.pdf_out(base, 'audit.json').write_text(json.dumps(aud))
        lv = {1: 0, 2: 0, None: 0}
        for r in recs.values():
            lv[r['level']] += 1
        log('ok', f'{img}: {len(recs)} recs (L1 {lv[1]} / L2 {lv[2]} / no Server {lv[None]}, '
              f'manual {sum(r["kind"] == "manual" for r in recs.values())}), '
              f'audit text {sum(1 for x in aud.values() if x["audit"].strip())}, '
              f'scripts {sum(x["script"] for x in aud.values())}, '
              f'PASS/FAIL markers {sum(x["verdict"] for x in aud.values())}')
