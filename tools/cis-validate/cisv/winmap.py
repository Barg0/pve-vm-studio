"""cisv winmap: the Windows Stand-alone benchmarks as machine rules for guest-files/cis/win/.

Input: the `cisv winparse` extract (<work>/windows/<pdf>.tsv.json). Output, per benchmark,
guest-files/cis/win/<bench>/rules.tsv - one rule per line:

    id  level  kind  mech  target  op  value  title

mech   reg      target HIVE\\path:ValueName (HKLM, or HKU for the user section 19.x), value TYPE:data
       acct     target the secedit [System Access] key
       right    target the Se* privilege, value a comma list of principals (SIDs or names the
                engine resolves); op eq (exactly), none (no one), has (includes)
       audit    target the subcategory GUID, value Success|Failure|Success and Failure
op     eq, ne, ge, le, range (value lo..hi), in (value a|b), has, none, eq_or_absent
title  the Microsoft setting name - no CIS text (the benchmarks are CC BY-NC-SA).

The levels: L1, L2, NG (next generation add-on), BL (BitLocker add-on); kind auto|manual.
"""
import json
import re
from pathlib import Path

from .log import log

BENCHES = {
    'w11sa': 'CIS_Microsoft_Windows_11_Stand-alone_Benchmark_v5.0.0',
    'ws2025sa': 'CIS_Microsoft_Windows_Server_2025_Stand-alone_v2.0.0',
    'ws2022sa': 'CIS_Microsoft_Windows_Server_2022_Stand-alone_Benchmark_v2.0.0',
}

# secedit [System Access] keys of the account policy and the security options set there
ACCT = {
    'Enforce password history': 'PasswordHistorySize',
    'Maximum password age': 'MaximumPasswordAge',
    'Minimum password age': 'MinimumPasswordAge',
    'Minimum password length': 'MinimumPasswordLength',
    'Password must meet complexity requirements': 'PasswordComplexity',
    'Relax minimum password length limits': 'RelaxMinimumPasswordLengthLimits',
    'Store passwords using reversible encryption': 'ClearTextPassword',
    'Account lockout duration': 'LockoutDuration',
    'Account lockout threshold': 'LockoutBadCount',
    'Reset account lockout counter after': 'ResetLockoutCount',
    'Allow Administrator account lockout': 'AllowAdministratorLockout',
    'Accounts: Guest account status': 'EnableGuestAccount',
    'Accounts: Rename administrator account': 'NewAdministratorName',
    'Accounts: Rename guest account': 'NewGuestName',
    'Network access: Allow anonymous SID/Name translation': 'LSAAnonymousNameLookup',
    'Network security: Force logoff when logon hours expire': 'ForceLogoffWhenHourExpire',
}

RIGHTS = {
    'Access Credential Manager as a trusted caller': 'SeTrustedCredManAccessPrivilege',
    'Access this computer from the network': 'SeNetworkLogonRight',
    'Act as part of the operating system': 'SeTcbPrivilege',
    'Adjust memory quotas for a process': 'SeIncreaseQuotaPrivilege',
    'Allow log on locally': 'SeInteractiveLogonRight',
    'Allow log on through Remote Desktop Services': 'SeRemoteInteractiveLogonRight',
    'Back up files and directories': 'SeBackupPrivilege',
    'Change the system time': 'SeSystemtimePrivilege',
    'Create a pagefile': 'SeCreatePagefilePrivilege',
    'Create a token object': 'SeCreateTokenPrivilege',
    'Create global objects': 'SeCreateGlobalPrivilege',
    'Create permanent shared objects': 'SeCreatePermanentPrivilege',
    'Create symbolic links': 'SeCreateSymbolicLinkPrivilege',
    'Debug programs': 'SeDebugPrivilege',
    'Deny access to this computer from the network': 'SeDenyNetworkLogonRight',
    'Deny log on as a batch job': 'SeDenyBatchLogonRight',
    'Deny log on as a service': 'SeDenyServiceLogonRight',
    'Deny log on locally': 'SeDenyInteractiveLogonRight',
    'Deny log on through Remote Desktop Services': 'SeDenyRemoteInteractiveLogonRight',
    'Enable computer and user accounts to be trusted for delegation': 'SeEnableDelegationPrivilege',
    'Force shutdown from a remote system': 'SeRemoteShutdownPrivilege',
    'Generate security audits': 'SeAuditPrivilege',
    'Impersonate a client after authentication': 'SeImpersonatePrivilege',
    'Increase scheduling priority': 'SeIncreaseBasePriorityPrivilege',
    'Load and unload device drivers': 'SeLoadDriverPrivilege',
    'Lock pages in memory': 'SeLockMemoryPrivilege',
    'Log on as a batch job': 'SeBatchLogonRight',
    'Log on as a service': 'SeServiceLogonRight',
    'Manage auditing and security log': 'SeSecurityPrivilege',
    'Modify an object label': 'SeRelabelPrivilege',
    'Modify firmware environment values': 'SeSystemEnvironmentPrivilege',
    'Perform volume maintenance tasks': 'SeManageVolumePrivilege',
    'Profile single process': 'SeProfileSingleProcessPrivilege',
    'Profile system performance': 'SeSystemProfilePrivilege',
    'Replace a process level token': 'SeAssignPrimaryTokenPrivilege',
    'Restore files and directories': 'SeRestorePrivilege',
    'Shut down the system': 'SeShutdownPrivilege',
    'Take ownership of files or other objects': 'SeTakeOwnershipPrivilege',
}

# Principals as the benchmarks name them -> what secedit takes (well-known SIDs; service and
# virtual-account names stay names: the engine translates them on the machine)
PRINCIPALS = {
    'Administrators': '*S-1-5-32-544', 'Users': '*S-1-5-32-545', 'Guests': '*S-1-5-32-546',
    'Remote Desktop Users': '*S-1-5-32-555', 'Authenticated Users': '*S-1-5-11',
    'LOCAL SERVICE': '*S-1-5-19', 'NETWORK SERVICE': '*S-1-5-20', 'SERVICE': '*S-1-5-6',
    'Window Manager\\Window Manager Group': '*S-1-5-90-0',
    'NT VIRTUAL MACHINE\\Virtual Machines': '*S-1-5-83-0',
    'NT SERVICE\\WdiServiceHost': 'NT SERVICE\\WdiServiceHost',
    'RESTRICTED SERVICES\\PrintSpoolerService': 'RESTRICTED SERVICES\\PrintSpoolerService',
}

AUDIT = {
    'Audit Credential Validation': '0CCE923F-69AE-11D9-BED3-505054503030',
    'Audit Application Group Management': '0CCE9239-69AE-11D9-BED3-505054503030',
    'Audit Security Group Management': '0CCE9237-69AE-11D9-BED3-505054503030',
    'Audit User Account Management': '0CCE9235-69AE-11D9-BED3-505054503030',
    'Audit PNP Activity': '0CCE9248-69AE-11D9-BED3-505054503030',
    'Audit Process Creation': '0CCE922B-69AE-11D9-BED3-505054503030',
    'Audit Account Lockout': '0CCE9217-69AE-11D9-BED3-505054503030',
    'Audit Group Membership': '0CCE9249-69AE-11D9-BED3-505054503030',
    'Audit Logoff': '0CCE9216-69AE-11D9-BED3-505054503030',
    'Audit Logon': '0CCE9215-69AE-11D9-BED3-505054503030',
    'Audit Other Logon/Logoff Events': '0CCE921C-69AE-11D9-BED3-505054503030',
    'Audit Special Logon': '0CCE921B-69AE-11D9-BED3-505054503030',
    'Audit Detailed File Share': '0CCE9244-69AE-11D9-BED3-505054503030',
    'Audit File Share': '0CCE9224-69AE-11D9-BED3-505054503030',
    'Audit Other Object Access Events': '0CCE9227-69AE-11D9-BED3-505054503030',
    'Audit Removable Storage': '0CCE9245-69AE-11D9-BED3-505054503030',
    'Audit Audit Policy Change': '0CCE922F-69AE-11D9-BED3-505054503030',
    'Audit Authentication Policy Change': '0CCE9230-69AE-11D9-BED3-505054503030',
    'Audit Authorization Policy Change': '0CCE9231-69AE-11D9-BED3-505054503030',
    'Audit MPSSVC Rule-Level Policy Change': '0CCE9232-69AE-11D9-BED3-505054503030',
    'Audit MPSSVC RuleLevel Policy Change': '0CCE9232-69AE-11D9-BED3-505054503030',
    'Audit Other Policy Change Events': '0CCE9234-69AE-11D9-BED3-505054503030',
    'Audit Sensitive Privilege Use': '0CCE9228-69AE-11D9-BED3-505054503030',
    'Audit IPsec Driver': '0CCE9213-69AE-11D9-BED3-505054503030',
    'Audit Other System Events': '0CCE9214-69AE-11D9-BED3-505054503030',
    'Audit Security State Change': '0CCE9210-69AE-11D9-BED3-505054503030',
    'Audit Security System Extension': '0CCE9211-69AE-11D9-BED3-505054503030',
    'Audit System Integrity': '0CCE9212-69AE-11D9-BED3-505054503030',
}

LEVELS = (('NG', 'NG'), ('BL', 'BL'), ('L2', 'L2'), ('L1', 'L1'))

# Path components of 2.3.10.8's list, for words the PDF text broke ("CurrentControlS et")
WORDS = {w.replace(' ', ''): w for w in ('CurrentControlSet', 'Control', 'Print', 'Printers', 'Services', 'Eventlog', 'Software',
                                         'Microsoft', 'OLAP Server', 'Windows NT', 'CurrentVersion', 'Windows', 'ContentIndex',
                                         'Terminal Server', 'UserConfig', 'DefaultUserConfiguration', 'Perflib', 'SysmonLog', 'System',
                                         'ProductOptions', 'Server Applications', 'CertSvc', 'WINS')}
# "is configured" recs: any non-empty value passes (op nonempty); the fix writes the studio's
# value - the PDF's own example for the firewall logs, the Linux banner's text for the notice.
SITE_VALUES = {
    'LegalNoticeText': 'Authorized use only. Activity on this system is monitored and recorded.',
    'LegalNoticeCaption': 'Authorized use only',
    'PrivateProfile\\Logging:LogFilePath': '%SystemRoot%\\System32\\logfiles\\firewall\\privatefw.log',
    'PublicProfile\\Logging:LogFilePath': '%SystemRoot%\\System32\\logfiles\\firewall\\publicfw.log',
    'DomainProfile\\Logging:LogFilePath': '%SystemRoot%\\System32\\logfiles\\firewall\\domainfw.log',
}
# Paths the PDF text cut off at a line end: the full Microsoft names (same in every benchmark)
TRUNCATED = {
    '18.10.58.2': [('HKLM\\SOFTWARE\\Policies\\Microsoft\\Internet Explorer\\Feeds:AllowBasicAuthInClear', 'eq', 'REG_DWORD:0')],
    # BitLocker add-on only (out of the studio's L1/L2 offer): the device classes as the policy writes them
    '18.9.7.1.2': [('HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceInstall\\Restrictions:DenyDeviceClasses', 'eq', 'REG_DWORD:1')],
    '18.10.63.1': [('HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\CurrentVersion\\Software Protection Platform:NoGenTicket', 'eq', 'REG_DWORD:1')],
    '18.10.93.2.1': [('HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender Security Center\\App and Browser protection:DisallowExploitProtectionOverride', 'eq', 'REG_DWORD:1')],
}
# Words the PDF text glued together inside paths
UNGLUE = [('WindowsNT', 'Windows NT'), ('InternetSettings', 'Internet Settings'), ('InternetExplorer', 'Internet Explorer'),
          ('TerminalServices', 'Terminal Services'), ('ControlPanel', 'Control Panel'), ('ErrorReporting', 'Error Reporting')]
# Paths HardeningKitty's lists do not carry, checked by hand against the PDF / Microsoft's ADMX
HAND_OK = {
    'HKLM\\SOFTWARE\\Microsoft\\Policies\\PassportForWork\\Biometrics:EnableESSwithSupportedPeripherals',
    'HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Printers\\IPP:RequireIpps',
    'HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Printers\\IPP:SecurityFlagsBlockCertCNInvalid',
    'HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Printers\\IPP:SecurityFlagsBlockCertDateInvalid',
    'HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Printers\\IPP:SecurityFlagsBlockCertWrongUsage',
    'HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Printers\\IPP:SecurityFlagsBlockUnknownCA',
    'HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\System:RunAsPPL',
    'HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsAI:AllowRecallEnablement',
    'HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate:SetAllowOptionalContent',
    'HKLM\\SYSTEM\\CurrentControlSet\\Policies:ClfsAuthenticationChecking',
    'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon:PasswordExpiryWarning',
    'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings:DisableProxyAuthenticationSchemes',
    'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\WinHttp:DisableWpad',
}


def level_of(raw_level):
    """The lowest profile the rec is in: 'L1', 'L2', or an add-on ('NG', 'BL') alone."""
    s = raw_level.upper()
    if 'L1' in s:
        return 'L1'
    if 'L2' in s:
        return 'L2'
    for k, v in LEVELS:
        if k in s:
            return v
    return 'L2'


def num_op(v):
    """'24 or more ...' -> (ge, 24); '365 or fewer ..., but not 0' -> (range, 1..365);
    '15 or more minute(s)' -> (ge, 15); 'Enabled' -> (eq, 1); 'Disabled' -> (eq, 0)."""
    v = v.strip()
    if v.startswith('Enabled'):
        return 'eq', '1'
    if v.startswith('Disabled'):
        return 'eq', '0'
    m = re.match(r'(\d+) or (?:more|greater)', v)
    if m:
        return 'ge', m.group(1)
    m = re.match(r'(\d+) or fewer.*but not 0', v)
    if m:
        return 'range', f'1..{m.group(1)}'
    m = re.match(r'(\d+) or fewer', v)
    if m:
        return 'le', m.group(1)
    m = re.match(r'(\d+)\b', v)
    if m:
        return 'eq', m.group(1)
    return None, v


def reg_rule(spec):
    """'HKLM\\...:Name = REG_DWORD 1' -> (target, op, value) or None."""
    m = re.match(r'^(HK(?:LM|U)\\.+?):([^:=]+?) = (REG_\w+) (.*)$', spec.strip())
    if not m:
        return None
    path, name, typ, val = m.groups()
    path = path.replace('HKU\\[USERSID]', 'HKU')
    val = val.strip()
    if typ in ('REG_DWORD', 'REG_QWORD'):
        val = val.lstrip('`').strip()
        mm = re.match(r'^(\d+) or (?:less|fewer),? but not 0', val)
        if mm:
            return f'{path}:{name}', 'range', f'{typ}:1..{mm.group(1)}'
        mm = re.match(r'^(\d+) or (?:less|fewer)$', val)
        if mm:
            return f'{path}:{name}', 'le', f'{typ}:{mm.group(1)}'
        mm = re.match(r'^anything other than (\d+)$', val)
        if mm:
            return f'{path}:{name}', 'ne', f'{typ}:{mm.group(1)}'
        # "1 or2", "1or 3": the PDF text lost a space
        val = re.sub(r'(\d)or\b', r'\1 or', re.sub(r'\bor(\d)', r'or \1', val))
        mm = re.match(r'^(\d+) or (\d+)$', val)
        if mm:
            return f'{path}:{name}', 'in', f'{typ}:{mm.group(1)}|{mm.group(2)}'
        mm = re.match(r'^(\d+) or (?:greater|more)$', val)
        if mm:
            return f'{path}:{name}', 'ge', f'{typ}:{mm.group(1)}'
        mm = re.match(r'^(\d+) or that the key does? not exist', val)
        if mm:
            return f'{path}:{name}', 'eq_or_absent', f'{typ}:{mm.group(1)}'
        mm = re.match(r'^(\d+)$', val)
        if mm:
            return f'{path}:{name}', 'eq', f'{typ}:{mm.group(1)}'
        return None
    target = f'{path}:{name}'
    site = next((v for k, v in SITE_VALUES.items() if target.endswith(k) or target.endswith(':' + k)), None)
    if site is not None and val in ('text', '<path>\\<filename>'):
        return target, 'nonempty', f'{typ}:{site}'
    # "<blank> (i.e. None)", cut at a line end as "blank (i" or "<blank> i": the empty value
    if re.match(r'^<?blank>?\s*\(?i', val) or val in ('', '<blank>'):
        return target, 'eq', f'{typ}:'
    # "1, 2, or 3" / "1, 2 or 3"
    if re.fullmatch(r'\d+(?:,\s*\d+)*,?\s+or\s+\d+', val):
        return target, 'in', f'{typ}:' + '|'.join(re.findall(r'\d+', val))
    # a placeholder or prose the rules above do not know: never written as a value
    if re.search(r'[<>]|\(i\.e\.|^text$', val):
        return None
    return target, 'eq', f'{typ}:{val}'


def rule(x):
    """One extracted rec -> (mech, target, op, value, title) or (None, reason)."""
    s = x['registry_or_setting'].strip()
    title_val = x['own_title'].split(' = ', 1)
    name = title_val[0].strip()
    val = title_val[1].strip() if len(title_val) > 1 else ''
    if ' includes ' in x['own_title'] and not val:
        name, rest = x['own_title'].split(' includes ', 1)
        name, val = name.strip(), 'includes ' + rest.strip()
    if s.startswith(('HKLM', 'HKU', 'HKEY_LOCAL_MACHINE')):
        s = s.replace('HKEY_LOCAL_MACHINE', 'HKLM')
        if x['number'] in TRUNCATED:
            return [('reg',) + t + (name,) for t in TRUNCATED[x['number']]], None
        # Remotely accessible registry paths (and sub-paths): a REG_MULTI_SZ list, comma- or
        # "and"-separated in the PDF text (sometimes typed as REG_DWORD)
        if 'AllowedPaths:Machine' in s or 'AllowedExactPaths:Machine' in s:
            listed = re.split(r' = (?:REG_\w+ )?', s, maxsplit=1)[1]
            items = ['\\'.join(WORDS.get(c.replace(' ', ''), c) for c in i.strip().split('\\'))
                     for i in re.split(r',\s*|\s+and\s+', listed) if i.strip()]
            return ('reg', s.split(' = ')[0], 'eq', 'REG_MULTI_SZ:' + '|'.join(items), name), None
        # "A | B | C = REG_DWORD 0": the same value for every key
        if ' | ' in s.split(' = ')[0] and not re.search(r'\(\w+\)\s*$', s):
            keys, spec_val = s.split(' = ', 1)
            out = []
            for k in keys.split(' | '):
                r = reg_rule(f'{k.strip()} = {spec_val}')
                if not r:
                    return None, f'multi-key value not parsed: {spec_val[:60]}'
                out.append(('reg',) + r + (name,))
            return out, None
        # "A | B = REG_DWORD 1 (A) and 0 (B)" (or "REG_SZ value of Block (B)"): one rule per key
        m = re.match(r'^(HK\S.*?:[^|=]+?) \| (HK\S.*?:[^|=]+?) = (.*)$', s)
        if m:
            out = []
            first_typ = re.match(r'(REG_\w+)', m.group(3))
            for part in re.split(r'\s+and\s+', m.group(3)):
                mm = re.match(r'^(?:(REG_\w+) )?(?:value of )?(\S+) \((\w+)\)$', part.strip())
                if not mm:
                    return None, f'two-key value not parsed: {m.group(3)[:80]}'
                typ = mm.group(1) or (first_typ.group(1) if first_typ else 'REG_DWORD')
                key = next((k for k in (m.group(1), m.group(2)) if k.endswith(':' + mm.group(3))), None)
                if not key:
                    return None, f'two-key name not found: {part[:60]}'
                out.append(('reg', key.replace('HKU\\[USERSID]', 'HKU'), 'eq', f'{typ}:{mm.group(2)}', name))
            return out, None
        # the spec without its value: the PDF prints it only in the title
        if ' = ' not in s or re.search(r'= REG_\w+\s*$', s):
            path = s.split(' = ')[0].strip().replace('HKU\\[USERSID]', 'HKU')
            if val == 'None':
                return ('reg', path, 'eq', 'REG_MULTI_SZ:', name), None
            mm = re.match(r'between (\d+) and (\d+)', val)
            if mm:
                return ('reg', path, 'range', f'REG_DWORD:{mm.group(1)}..{mm.group(2)}', name), None
            if val == 'Enabled':
                return ('reg', path, 'eq', 'REG_DWORD:1', name), None
            if val == 'Disabled':
                return ('reg', path, 'eq_or_absent', 'REG_SZ:', name), None
            return None, f'registry value only in the title: {val[:60]}'
        # WS2025 prints the path a second time after the value: the first one counts
        s = re.sub(r'(= REG_\w+ \S+(?: or less,? but not 0)?)\s+HKLM\\.*$', r'\1', s)
        r = reg_rule(s)
        if not r:
            return None, f'registry value not parsed: {s[:80]}'
        return ('reg',) + r + (name,), None
    if not s.startswith('GP: '):
        return None, f'no setting: {s[:60]}'
    gp = s[4:].strip()
    # not a secedit key: the SAM's registry value (secedit /export does not show it either)
    if gp == 'Relax minimum password length limits':
        return ('reg', 'HKLM\\SYSTEM\\CurrentControlSet\\Control\\SAM:RelaxMinimumPasswordLengthLimits', 'eq', 'REG_DWORD:1', gp), None
    if gp in ACCT:
        key = ACCT[gp]
        if key in ('NewAdministratorName', 'NewGuestName'):
            return ('acct', key, 'ne', 'Administrator' if key == 'NewAdministratorName' else 'Guest', gp), None
        op, v = num_op(val)
        if not op:
            return None, f'account value not parsed: {val[:60]}'
        return ('acct', key, op, v, gp), None
    if gp in RIGHTS:
        if val == 'No One':
            return ('right', RIGHTS[gp], 'none', '', gp), None
        if val.startswith('includes'):
            who = val.split('includes', 1)[1].strip()
            return ('right', RIGHTS[gp], 'has', PRINCIPALS.get(who, who), gp), None
        names = [p.strip() for p in val.split(',')]
        bad = [n for n in names if n not in PRINCIPALS]
        if bad:
            return None, f'unknown principal(s): {bad}'
        return ('right', RIGHTS[gp], 'eq', ','.join(PRINCIPALS[n] for n in names), gp), None
    if gp in AUDIT:
        if val.startswith("include 'Success"):
            return ('audit', AUDIT[gp], 'has', 'Success', gp), None
        if val.startswith("include 'Failure"):
            return ('audit', AUDIT[gp], 'has', 'Failure', gp), None
        if val in ('Success and Failure', 'Success', 'Failure'):
            return ('audit', AUDIT[gp], 'eq', val, gp), None
        return None, f'audit value not parsed: {val[:60]}'
    return None, f'unknown GP setting: {gp[:60]}'


# The PDF text loses spaces and hyphens inside registry paths ("WindowsNT", "TerminalServices",
# GUIDs): every path is matched, ignoring those and case, against HardeningKitty's CIS lists and
# takes their spelling. A path they do not have is listed for a hand check.
_CANON = {}


def squash(t):
    return re.sub(r'[\s-]', '', t).lower()


def load_canon(work):
    import csv
    for f in sorted((Path(work) / 'thirdparty' / 'hardeningkitty').glob('finding_list_*.csv')):
        for row in csv.DictReader(open(f, encoding='utf-8-sig')):
            p, i = (row.get('RegistryPath') or '').strip(), (row.get('RegistryItem') or '').strip()
            if p.startswith(('HKLM:', 'HKCU:', 'HKU:')) and i:
                p = re.sub(r'^HK(LM|CU|U):', lambda m: 'HKLM' if m.group(1) == 'LM' else 'HKU', p)
                _CANON.setdefault(squash(f'{p}:{i}'), f'{p}:{i}')


def canon(target):
    c = _CANON.get(squash(target))
    if c:
        return c, True
    for glued, spaced in UNGLUE:
        target = target.replace(glued, spaced)
    return target, target in HAND_OK


def ascii_title(t):
    return re.sub(r'[‘’“”]', "'", t).encode('ascii', 'replace').decode()


def build(work, out_root):
    load_canon(work)
    for bench, pdf in BENCHES.items():
        src = Path(work) / 'windows' / f'{pdf}.tsv.json'
        recs = json.loads(src.read_text())
        lines, bad, unverified = [], [], []
        for x in recs:
            kind = 'auto' if x['kind'].lower().startswith('auto') else 'manual'
            r, why = rule(x)
            if r is None:
                bad.append(f"{x['number']}\t{why}")
                lines.append('\t'.join([x['number'], level_of(x['level']), kind, 'manual', '-', '-', '-', ascii_title(x['own_title'].split(' = ')[0])]))
                continue
            for mech, target, op, value, title in (r if isinstance(r, list) else [r]):
                if mech == 'reg':
                    target, ok = canon(target)
                    if not ok:
                        unverified.append(f"{x['number']}\t{target}")
                lines.append('\t'.join([x['number'], level_of(x['level']), kind, mech, target, op, value, ascii_title(title)]))
        d = Path(out_root) / bench
        d.mkdir(parents=True, exist_ok=True)
        (d / 'rules.tsv').write_text('# id\tlevel\tkind\tmech\ttarget\top\tvalue\ttitle (generated by cisv winmap - no CIS text)\n'
                                     + '\n'.join(lines) + '\n', newline='\n')
        (Path(work) / 'windows' / f'{bench}.winmap-unparsed.txt').write_text('\n'.join(bad) + '\n')
        (Path(work) / 'windows' / f'{bench}.winmap-unverified.txt').write_text('\n'.join(unverified) + '\n')
        log('warn' if bad or unverified else 'ok', f'{bench}: {len(lines)} rules, {len(bad)} not machine-readable, '
            f'{len(unverified)} registry paths HardeningKitty does not have -> {bench}.winmap-*.txt')


def cmd_winmap(cfg, args):
    build(cfg.work, Path(__file__).resolve().parents[3] / 'guest-files' / 'cis' / 'win')
    return 0
