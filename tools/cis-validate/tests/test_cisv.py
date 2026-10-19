"""Unit tests: python3 -m unittest discover -s tests (from tools/cis-validate). Synthetic text only."""
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cisv import config, fixups, guard, join, mutate, pdf, runner  # noqa: E402


class Guard(unittest.TestCase):
    def test_vmid_101_refused(self):
        for v in (101, '101', ' 101 '):
            with self.assertRaises(guard.GuardError):
                guard.ensure_allowed(vmid=v)

    def test_name_refused_any_case(self):
        for n in ('jh-pve-01', 'JH-PVE-01', ' jh-pve-01 '):
            with self.assertRaises(guard.GuardError):
                guard.ensure_allowed(name=n)

    def test_others_allowed(self):
        guard.ensure_allowed(name='cis-rocky9', vmid=9101)
        guard.ensure_allowed(name='cis-rocky9', vmid='')
        guard.ensure_allowed()

    def test_garbage_vmid_refused(self):
        with self.assertRaises(guard.GuardError):
            guard.ensure_allowed(vmid='abc')

    def test_config_cannot_drop_builtin(self):
        cfg = config.Config({'guard': {'vmids': [], 'names': []}})
        with self.assertRaises(guard.GuardError):
            cfg.guard(vmid=101)

    def test_config_adds(self):
        cfg = config.Config({'guard': {'vmids': [100], 'names': ['studio']}})
        with self.assertRaises(guard.GuardError):
            cfg.guard(vmid=100)
        with self.assertRaises(guard.GuardError):
            cfg.guard(name='Studio')

    def test_inventory_with_protected_vm_refused(self):
        with tempfile.TemporaryDirectory() as d:
            inv = Path(d) / 'inv.tsv'
            inv.write_text('cis-a\t10.0.0.2\tcisadmin\trocky9\t9100\n'
                           'jh-pve-01\t10.0.0.3\tx\trocky9\t\n')
            cfg = config.Config({'paths': {'inventory': str(inv), 'work_dir': d}})
            with self.assertRaises(guard.GuardError):
                cfg.vm('cis-a')
            inv.write_text('cis-b\t10.0.0.4\tcisadmin\trocky9\t101\n')
            with self.assertRaises(guard.GuardError):
                cfg.vms()
            inv.write_text('cis-c\t10.0.0.5\tcisadmin\trocky9\t9102\tpw\n')
            self.assertEqual(cfg.vm('cis-c')['password'], 'pw')


class Blocks(unittest.TestCase):
    def test_cmd_and_script(self):
        text = '\n'.join([
            'Run the following command:',
            '# grep -E "^x" /etc/example',
            'Nothing should be returned.',
            '#!/usr/bin/env bash',
            '{',
            '  a=1',
            'Page 12',
            '  if [ "$a" = 1 ]; then',
            '    echo "** PASS **"',
            '  fi',
            '}',
            'Afterwards text.',
        ])
        bl = runner.blocks(text)
        self.assertEqual([b[0] for b in bl], ['cmd', 'script'])
        self.assertEqual(bl[0][1], 'grep -E "^x" /etc/example')
        self.assertNotIn('Page 12', bl[1][1])
        self.assertTrue(bl[1][1].rstrip().endswith('}'))
        self.assertEqual(bl[1][2], '')

    def test_wrapped_command_rejoined(self):
        bl = runner.blocks('# stat -Lc "%n %a" /etc/a |\ngrep -v 600\n')
        self.assertEqual(bl[0][1], 'stat -Lc "%n %a" /etc/a | grep -v 600')
        self.assertEqual(bl[0][2], '')
        bl = runner.blocks("# awk '/x/ {print\n$1}' /etc/f\n")
        self.assertEqual(bl[0][1], "awk '/x/ {print $1}' /etc/f")
        bl = runner.blocks('# find / -xdev \\\n-type f\n')
        self.assertEqual(bl[0][1], 'find / -xdev -type f')

    def test_pdf_wraps_2026_10_18(self):
        # a path hyphenated at the line end
        bl = runner.blocks("# grep -Pi -- '^x' /etc/crypto-\npolicies/state/CURRENT.pol\n")
        self.assertEqual(bl[0][1], "grep -Pi -- '^x' /etc/crypto-policies/state/CURRENT.pol")
        # grep cut after its options, the pattern on the next line
        bl = runner.blocks("# systemctl is-enabled a 2>/dev/null | grep\n'enabled'\n")
        self.assertEqual(bl[0][1], "systemctl is-enabled a 2>/dev/null | grep 'enabled'")
        bl = runner.blocks("# grep -Psi --\n'^\\h*x' /etc/f\n")
        self.assertEqual(bl[0][1], "grep -Psi -- '^\\h*x' /etc/f")
        # the file operands of a grep on the next line ('|' inside the pattern is not a pipe)
        bl = runner.blocks("# grep -Psi -- '^(a|b)\\b'\n/etc/x /etc/y.d/*.conf\nExample output:\n")
        self.assertEqual(bl[0][1], "grep -Psi -- '^(a|b)\\b' /etc/x /etc/y.d/*.conf")
        # an escape cut inside a single-quoted regex, and a cut between regex operators
        bl = runner.blocks("# grep -P '([^#\\n\\\nr]+)((?!\\2)\n(use_uid))' /etc/f\n")
        self.assertEqual(bl[0][1], "grep -P '([^#\\n\\r]+)((?!\\2)(use_uid))' /etc/f")
        # a brace group keeps its lines; backslash-newline stays for bash
        bl = runner.blocks('# {\nU=$(id -u)\n[ -n "$U" ] && echo "a \\\nb"\n}\n')
        self.assertEqual(bl[0][1], '{\nU=$(id -u)\n[ -n "$U" ] && echo "a \\\nb"\n}')
        self.assertEqual(runner.syntax_error(bl[0][1]), '')

    def test_unjoinable_reported(self):
        bl = runner.blocks("# grep 'never closes\n\n")
        self.assertEqual(bl[0][2], 'command looks cut off')

    def test_unclosed_script_reported(self):
        bl = runner.blocks('#!/bin/bash\n{\n  echo x\n')
        self.assertEqual(bl[0][0], 'script')
        self.assertIn('never closes', bl[0][2])

    def test_shebang_is_not_a_command(self):
        self.assertEqual([b[0] for b in runner.blocks('#!/bin/bash\n{\n}\n')], ['script'])

    def test_verdict(self):
        self.assertEqual(runner.verdict('- Audit Result:\n ** FAIL **\n'), 'fail')
        self.assertEqual(runner.verdict('**PASS**'), 'pass')
        self.assertEqual(runner.verdict('** PASS ** then ** FAIL **'), 'fail')
        self.assertEqual(runner.verdict('nothing here'), 'raw')

    def test_emit_frames_and_real_rc(self):
        text, report, (nc, ns) = runner.emit('x', {'1.2': {'audit': '# false\n'}}, check_syntax=False)
        self.assertEqual((nc, ns), (1, 0))
        self.assertIn('@@@REC 1.2 1', text)
        self.assertIn('rc=$?', text)          # the command's code, not head's
        self.assertNotIn('| head', text)


class Fixups(unittest.TestCase):
    def test_generic(self):
        s = fixups.apply('x', '1.1', '# grep ‘a’ “b” ﬁle\nPage 3\nend')
        self.assertEqual(s, "# grep 'a' \"b\" file\nend")

    def test_per_rec(self):
        fixups.PER_REC[('img', '9.9')] = [(r'gre p', 'grep')]
        try:
            self.assertEqual(fixups.apply('img', '9.9', '# gre p x'), '# grep x')
            self.assertEqual(fixups.apply('other', '9.9', '# gre p x'), '# gre p x')
            self.assertTrue(fixups.has_fixup('img', '9.9'))
        finally:
            del fixups.PER_REC[('img', '9.9')]


class Pdf(unittest.TestCase):
    TEXT = '\n'.join([
        'Table of contents 1.1.1 Something ....... 5',
        '\f1.1.1 Ensure the widget is',
        'configured (Automated)',
        'Profile Applicability:',
        '• Level 2 - Server',
        '• Level 1 - Workstation',
        'Description:',
        'Words.',
        'Audit:',
        '# widget --show',
        'Remediation:',
        'Do it.',
        '1.1.2 Ensure a second thing (Manual)',
        'Profile Applicability:',
        '• Level 1 - Server',
        'Description:',
        'Audit:',
        '# second',
        'Remediation:',
        'Do it.',
        '',
    ])

    def test_recs_formfeed_and_wrap(self):
        r = pdf.parse_recs(self.TEXT)
        self.assertEqual(sorted(r), ['1.1.1', '1.1.2'])
        self.assertEqual(r['1.1.1']['title'], 'Ensure the widget is configured')
        self.assertEqual((r['1.1.1']['level'], r['1.1.1']['kind']), (2, 'auto'))
        self.assertEqual((r['1.1.2']['level'], r['1.1.2']['kind']), (1, 'manual'))

    def test_audits(self):
        a = pdf.parse_audits(self.TEXT, pdf.parse_recs(self.TEXT))
        self.assertEqual(a['1.1.1']['audit'].strip(), '# widget --show')
        self.assertEqual(a['1.1.2']['audit'].strip(), '# second')


class Join(unittest.TestCase):
    def test_runner_output(self):
        raw = '@@@REC 1.1 2\n@@@CMD 1.1.0\nhello\n@@@RC 0\n@@@SCRIPT 1.1.1\n ** FAIL **\n@@@RC 1\n'
        b = join.parse_runner_output(raw)
        self.assertEqual(b['1.1.0'], ('hello', '0'))
        self.assertEqual(b['1.1.1'], ('** FAIL **', '1'))

    def test_opinions(self):
        self.assertTrue(join.opinions('pass', 'fail', {})[1])
        self.assertTrue(join.opinions('pass', 'raw', {'lockdown': 'FAIL'})[1])
        self.assertTrue(join.opinions('na', 'raw', {'oscap': 'fail'})[1])
        self.assertFalse(join.opinions('pass', 'raw', {'lockdown': 'SKIP', 'oscap': 'pass'})[1])
        self.assertFalse(join.opinions('review', 'fail', {})[1])


class Mutations(unittest.TestCase):
    def test_banner_writes_backslash_v_not_vt(self):
        m = dict((k, v) for k, v, _ in mutate.M)['local-login-banner-shows-no-os-details']
        self.assertIn('printf "%s\\n" "\\\\v"', m)

    def test_grub_covers_user_cfg(self):
        m = dict((k, v) for k, v, _ in mutate.M)['grub-superuser-password']
        self.assertIn('GRUB2?_PASSWORD=', m)
        self.assertIn('-name user.cfg', m)


class WinmapStrings(unittest.TestCase):
    """PDF placeholders in string values never become the value written (found 2026-10-18)."""
    P = 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanManServer\\Parameters'

    def test_blank_is_empty(self):
        from cisv import winmap
        for v in ('blank (i', '<blank> i', '<blank> (i.e. None)'):
            self.assertEqual(winmap.reg_rule(f'{self.P}:NullSessionPipes = REG_MULTI_SZ {v}')[1:], ('eq', 'REG_MULTI_SZ:'))

    def test_list_of_numbers_is_in(self):
        from cisv import winmap
        for v in ('1, 2, or 3', '1, 2 or 3'):
            self.assertEqual(winmap.reg_rule(f'HKLM\\X\\Winlogon:ScRemoveOption = REG_SZ {v}')[1:], ('in', 'REG_SZ:1|2|3'))

    def test_configured_takes_the_site_value(self):
        from cisv import winmap
        r = winmap.reg_rule('HKLM\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile\\Logging:LogFilePath = REG_SZ <path>\\<filename>')
        self.assertEqual(r[1:], ('nonempty', 'REG_SZ:%SystemRoot%\\System32\\logfiles\\firewall\\publicfw.log'))
        self.assertEqual(winmap.reg_rule('HKLM\\X\\System:LegalNoticeText = REG_SZ text')[1], 'nonempty')

    def test_unknown_placeholder_is_not_a_value(self):
        from cisv import winmap
        self.assertIsNone(winmap.reg_rule('HKLM\\X\\Y:Z = REG_SZ <something>'))

    def test_exact_paths_split(self):
        from cisv import winmap
        x = {'number': '2.3.10.7', 'own_title': 'Network access: Remotely accessible registry paths = configured',
             'registry_or_setting': 'HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurePipeServers\\Winreg\\AllowedExactPaths:Machine = REG_MULTI_SZ '
                                    'System\\CurrentControlSet\\Control\\ProductOptions,System\\CurrentControlS et\\Control\\Server Applications,Software\\Microsoft\\Windows NT\\CurrentVersion'}
        r, _ = winmap.rule(x)
        self.assertEqual(r[3], 'REG_MULTI_SZ:System\\CurrentControlSet\\Control\\ProductOptions|System\\CurrentControlSet\\Control\\Server Applications|Software\\Microsoft\\Windows NT\\CurrentVersion')


if __name__ == '__main__':
    unittest.main()
