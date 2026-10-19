"""cisv mapcheck: every map.tsv against its PDF - numbers, Server levels, kinds, rule keys that
exist in the families - plus a title-similarity pass that lists loose matches (possible wrong
mappings) for a human to go through. Ported from mapcheck.py and semcheck.py (2026-10-16)."""
import re

from . import benchmarks, pdf
from .log import log

STOP = set('ensure is are the a an of to and or for not on in be configured set with by if all only '
           'properly correctly that this from'.split())


def bench_conf(cfg, image):
    d = {}
    for line in (cfg.cis_dir / image / 'bench.conf').read_text().splitlines():
        m = re.match(r'(\w+)="?([^"\n]*)"?', line)
        if m:
            d[m.group(1)] = m.group(2)
    return d


def map_dir(cfg, image):
    return bench_conf(cfg, image).get('MAP', image)


def read_map(cfg, mapd):
    """CIS number -> [level, kind, key]."""
    mp = {}
    for line in (cfg.cis_dir / mapd / 'map.tsv').read_text().splitlines():
        if line.startswith('#') or not line.strip():
            continue
        f = line.split('\t')
        mp[f[0]] = (f[1:] + ['', '', ''])[:3]
    return mp


def family_rules(cfg):
    """family -> {key: title} from `rule <key> "<title>"` lines."""
    out = {}
    for fam in ('deb', 'el', 'suse'):
        keys = {}
        for f in sorted((cfg.cis_dir / fam).glob('*.sh')):
            for line in f.read_text(errors='ignore').splitlines():
                m = re.match(r'\s*rule\s+(\S+)\s+"([^"]*)"', line)
                if m:
                    keys.setdefault(m.group(1), m.group(2))
        out[fam] = keys
    return out


def toks(s):
    return {w for w in re.findall(r'[a-z0-9]+', s.lower().replace('_', '-').replace('-', ' '))
            if w not in STOP and len(w) > 1}


def cmd_mapcheck(cfg, args):
    rules = family_rules(cfg)
    titles = {}
    for fam in rules.values():
        for k, t in fam.items():
            titles.setdefault(k, t)
    total = 0
    loose_seen = set()
    for img in args.images or benchmarks.images():
        c = bench_conf(cfg, img)
        mapd, fams = c.get('MAP', img), c.get('FAMILY', '').split()
        try:
            _, recs, _ = pdf.load(cfg, img)
        except FileNotFoundError:
            log('warn', f'{img}: no extract - run `cisv extract {img}` first')
            continue
        mp = read_map(cfg, mapd)
        issues = []
        for n in sorted(set(recs) | set(mp), key=pdf.numkey):
            if n not in mp:
                r = recs[n]
                issues.append(f'MISSING in map: {n} L{r["level"]} {r["kind"]}')
                continue
            if n not in recs:
                issues.append(f'NOT in PDF: {n} {mp[n]}')
                continue
            lv, kind, key = mp[n]
            r = recs[n]
            if r['level'] is None:
                issues.append(f'{n}: PDF has no Server profile, map L{lv}')
            elif str(r['level']) != lv:
                issues.append(f'LEVEL {n}: pdf L{r["level"]} map L{lv}')
            if r['kind'] != kind:
                issues.append(f'KIND {n}: pdf {r["kind"]} map {kind}')
            if not key:
                issues.append(f'NO KEY {n}')
            elif not any(key in rules.get(fm, {}) for fm in fams):
                issues.append(f'NO RULE {n}: key {key} not defined in {fams}')
        total += len(issues)
        log('warn' if issues else 'ok', f'{img} (map {mapd}, families {fams}): pdf {len(recs)} map {len(mp)} issues {len(issues)}')
        for i in issues:
            log('warn', '   ', i)
        # title similarity, once per map (Alma/Rocky/Oracle share one)
        if args.loose and mapd not in loose_seen:
            loose_seen.add(mapd)
            loose = []
            for n, (lv, kind, key) in sorted(mp.items(), key=lambda x: pdf.numkey(x[0])):
                if n not in recs:
                    continue
                a, b = toks(recs[n]['title']), toks(key + ' ' + titles.get(key, ''))
                ov = len(a & b) / max(1, min(len(a), len(b)))
                if ov < args.threshold:
                    loose.append(f'{n:10} {ov:.2f} {key} :: {titles.get(key, "?")[:60]}')
            out = cfg.work / 'mapcheck' / f'loose-{mapd}.txt'
            out.parent.mkdir(parents=True, exist_ok=True)
            # the PDF title goes into the work tree only, never the repo
            out.write_text('\n'.join(f'{l} || PDF: {recs[l.split()[0]]["title"][:80]}' for l in loose) + '\n')
            log('info', f'{img}: loose title matches: {len(loose)} -> {out}')
    return 1 if total else 0
