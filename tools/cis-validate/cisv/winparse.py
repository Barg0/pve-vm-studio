"""cisv winparse: Windows benchmarks (Phase 8, not used for Linux) -> TSV per recommendation:
number, profile levels, auto|manual, mechanism (account, user right, security option, audit
policy, admin template, service, firewall), registry path or setting, short own title.
Ported unchanged from cisparse.py (2026-10-16); only the entry point is new."""
import re, sys, json
from .log import log

START = re.compile(r'^(\d+(?:\.\d+)+)\s+(.*)$')
PAGE = re.compile(r'^\s*Page \d+\s*$')

def load(path):
    lines = [l.replace('\f', '').rstrip() for l in open(path, encoding='utf-8', errors='replace')]
    return lines

def parse(path):
    L = load(path)
    marks = [i for i, l in enumerate(L) if l.startswith('Profile Applicability')]
    recs = []
    starts = []
    for m in marks:
        # walk back to the numbered title line
        j = m - 1
        while j > m - 8 and not START.match(L[j].strip()):
            j -= 1
        mo = START.match(L[j].strip())
        if not mo:
            log('warn', 'no start for', m)
            continue
        title = ' '.join(x.strip() for x in L[j:m] if x.strip() and not PAGE.match(x))
        title = START.match(title).group(2)
        starts.append((j, m, mo.group(1), title))
    for k, (j, m, num, title) in enumerate(starts):
        end = starts[k + 1][0] if k + 1 < len(starts) else len(L)
        body = [x for x in L[m:end] if not PAGE.match(x)]
        # profiles
        prof = []
        for x in body[1:12]:
            if x.startswith('Description'):
                break
            if x.strip().startswith('•'):
                prof.append(x.strip('• ').strip())
        def section(name, stops):
            out, on = [], False
            for x in body:
                s = x.strip()
                if s == name or s.startswith(name):
                    on = True
                    continue
                if on and any(s.startswith(t) for t in stops):
                    break
                if on:
                    out.append(s)
            return out
        audit = section('Audit:', ['Remediation:'])
        rem = section('Remediation:', ['Default Value:', 'References:', 'CIS Controls:'])
        recs.append(dict(num=num, title=title, prof=prof, audit=audit, rem=rem))
    return recs

def regs(audit):
    out = []
    i = 0
    while i < len(audit):
        s = audit[i]
        if re.match(r'^(HKLM|HKU|HKCU|HKEY_)', s):
            acc = s
            i += 1
            while i < len(audit) and audit[i] and not re.match(r'^(HKLM|HKU|HKCU|HKEY_|Note|Remediation|OR$|To audit|Navigate|This |and |Also)', audit[i]) and len(audit[i].split()) == 1:
                acc += audit[i]
                i += 1
            out.append(acc)
            continue
        i += 1
    return out

def classify(r):
    rem = ' '.join(r['rem'])
    remj = rem.replace(' ', '')
    au = ' '.join(r['audit'])
    num = r['num']
    if 'PasswordPolicy\\' in remj or 'AccountLockoutPolicy\\' in remj:
        kind = 'a_account'
    elif 'UserRightsAssignment' in remj:
        kind = 'b_user_rights'
    elif 'SecurityOptions\\' in remj:
        kind = 'c_security_option'
    elif 'AdvancedAuditPolicyConfiguration' in remj or 'auditpol' in au:
        kind = 'd_audit_policy'
    elif 'AdministrativeTemplates' in remj:
        kind = 'e_admin_template'
    elif 'SystemServices' in remj or num.startswith('5.'):
        kind = 'f_service'
    elif 'WindowsDefenderFirewall' in remj or 'WindowsFirewall' in remj:
        kind = 'f_firewall'
    else:
        kind = 'f_other'
    return kind

def level(prof, server):
    out = []
    for p in prof:
        p2 = p.replace('Level 1 - Member Server', 'L1-MS').replace('Level 2 - Member Server', 'L2-MS') \
              .replace('Level 1 - Domain Controller', 'L1-DC').replace('Level 2 - Domain Controller', 'L2-DC') \
              .replace('Next Generation Windows Security - Member Server', 'NG-MS') \
              .replace('Next Generation Windows Security - Domain Controller', 'NG-DC') \
              .replace('Level 1 (L1) + BitLocker (BL)', 'L1+BL').replace('Level 2 (L2) + BitLocker (BL)', 'L2+BL') \
              .replace('BitLocker (BL)', 'BL').replace('Level 1 (L1)', 'L1').replace('Level 2 (L2)', 'L2')
        out.append(p2)
    return ','.join(out)

def setting(r, kind):
    rem = r['rem']
    au = r['audit']
    if kind in ('c_security_option', 'e_admin_template', 'f_firewall', 'f_service', 'f_other'):
        rg = regs(au)
        if rg:
            # value
            m = re.search(r'(REG_\w+) value of ([^.]+(?:\.\d+)?)', ' '.join(au))
            v = (' = ' + m.group(1) + ' ' + m.group(2).strip()) if m else ''
            return ' | '.join(rg) + v
    if kind == 'd_audit_policy':
        m = re.search(r'auditpol /get /subcategory:"(\{[^}]+\})"', ''.join(au).replace(' ', ''))
        if m:
            return 'auditpol ' + m.group(1)
    # fall back to GP path last element
    path = ''.join(rem)
    m = re.search(r'Computer\s*Configuration\\(.*)', ' '.join(rem))
    if m:
        p = m.group(1)
        p = re.split(r'Note:', p)[0].strip()
        return 'GP: ' + p.split('\\')[-1][:90]
    return ''

def own_title(r):
    t = r['title']
    t = re.sub(r'\s*\((Automated|Manual)\)\s*$', '', t)
    t = re.sub(r'^\((L1|L2|BL|NG)\)\s*', '', t)
    m = re.match(r"Ensure '(.+?)' (is set to|is NOT set to|is|are set to|is configured)(.*)", t)
    if m:
        name, op, val = m.group(1), m.group(2), m.group(3).strip()
        val = val.strip("' ")
        op2 = '!=' if 'NOT' in op else '='
        return f"{name} {op2} {val}"[:140]
    t = re.sub(r"^Ensure '(.+?)' to include (.*)", lambda m: m.group(1)+' includes '+m.group(2).replace("'",''), t)
    t = re.sub(r"^Ensure ", '', t).replace("'", '')
    return t[:140]

FIX = [('`',''),('1or ','1 or '),('WindowsNT','Windows NT'),('InternetSettings','Internet Settings'),('CurrentVersion\\Policies','CurrentVersion\\Policies'),
       ('WindowsDefender','Windows Defender'),('Windows Defender\\','Windows Defender\\'),('TerminalServices','Terminal Services'),('WindowsSearch','Windows Search'),('MicrosoftDefender','Microsoft Defender')]
def fix(s):
    for a,b in FIX: s = s.replace(a,b)
    return s

def run(path, out):
    recs = parse(path)
    server = 'Server' in path
    rows = []
    for r in recs:
        kind = classify(r)
        auto = 'Manual' if r['title'].rstrip().endswith('(Manual)') else 'Automated'
        rows.append(dict(number=r['num'], level=level(r['prof'], server), kind=auto,
                         mechanism=kind, registry_or_setting=setting(r, kind), own_title=own_title(r), raw=r))
    with open(out, 'w') as f:
        f.write('number\tlevel\tkind\tmechanism\tregistry_or_setting\town_title\n')
        for x in rows:
            f.write('\t'.join([x['number'], x['level'], x['kind'], x['mechanism'], fix(x['registry_or_setting']).replace('\t', ' '), x['own_title']]) + '\n')
    return rows


def cmd_winparse(cfg, args):
    import subprocess
    from collections import Counter
    for f in args.pdfs:
        pdf = cfg.pdf_dir / (f if f.endswith('.pdf') else f + '.pdf')
        out = cfg.work / 'windows'
        out.mkdir(parents=True, exist_ok=True)
        txt = out / (pdf.stem + '.txt')
        if not txt.exists():
            subprocess.run([cfg.pdftotext, str(pdf), str(txt)], check=True)
        tsv = out / (pdf.stem + '.tsv')
        rows = run(str(txt), str(tsv))
        json.dump(rows, open(str(tsv) + '.json', 'w'))
        log('ok', pdf.stem, len(rows), dict(Counter(x['kind'] for x in rows)), dict(Counter(x['mechanism'] for x in rows)))
    return 0
