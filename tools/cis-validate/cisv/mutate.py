"""cisv mutate: mutation tests. Each mutation breaks one setting on a running test VM, expects
`pvs-cis check --only <id>` to turn to fail, reverts it and expects the old verdict back; a final
full check reports any residue. Ported from mutate.py, mutrun.sh and mutsum.py (2026-10-16).

Mutations are keyed by our rule key, so one list serves every family: a mutation whose key the
benchmark's map does not have is skipped. Two were fixed after the 2026-10-16 run:
- the banner mutation wrote a vertical tab (printf "\v") where it meant the two characters \v;
- the GRUB password one missed Enterprise Linux, which keeps GRUB2_PASSWORD= in user.cfg.
Only for disposable mutation VMs: a mutation that fails to revert leaves the VM changed.
"""
import re

from . import mapcheck, vm as vmmod
from .mutsets import B_EXTRA, MORE
from .runner import LOG_FN
from .log import log

# bk/rs keep a symlink a symlink and its target's content (Leap's /etc/issue -> ../run/issue: a
# mutation appends through the link; EL's default.target -> multi-user.target: a mutation
# replaces the link - restored as a plain copy it boots without multi-user's .wants, sshd never
# starts).
B = ('mkdir -p /root/mutbak; '
     'bk() { local b="/root/mutbak/$(echo $1 | tr / _)"; rm -f "$b.link"; '
     'if [ -L "$1" ]; then readlink "$1" > "$b.link"; cp -a "$(readlink -f "$1")" "$b"; else cp -a "$1" "$b"; fi; }; '
     'rs() { local b="/root/mutbak/$(echo $1 | tr / _)"; '
     'if [ -f "$b.link" ]; then [ -L "$1" ] && [ "$(readlink "$1")" = "$(cat "$b.link")" ] || ln -sfn "$(cat "$b.link")" "$1"; '
     'cmp -s "$b" "$(readlink -f "$1")" || cp --remove-destination -a "$b" "$(readlink -f "$1")"; '
     'else cp --remove-destination -a "$b" "$1"; fi; }')
M = [
 # key, mutate, revert   (SSHD drop-in "00-aaa" sorts before 00-pvs-cis: sshd keeps the first value)
 ('sshd-root-login-off', 'echo "PermitRootLogin yes" > /etc/ssh/sshd_config.d/00-aaa-mut.conf', 'rm -f /etc/ssh/sshd_config.d/00-aaa-mut.conf'),
 ('sshd-all-forwarding-off', 'printf "Match User cisadmin\\n    DisableForwarding no\\n" > /etc/ssh/sshd_config.d/99-zzz-mut.conf', 'rm -f /etc/ssh/sshd_config.d/99-zzz-mut.conf'),
 ('sshd-login-grace-time-60s-or-less', 'echo "LoginGraceTime 120" > /etc/ssh/sshd_config.d/00-aaa-mut.conf', 'rm -f /etc/ssh/sshd_config.d/00-aaa-mut.conf'),
 ('sshd-no-weak-ciphers', 'echo "Ciphers +3des-cbc" > /etc/ssh/sshd_config.d/00-aaa-mut.conf', 'rm -f /etc/ssh/sshd_config.d/00-aaa-mut.conf'),
 ('sshd-no-weak-macs', 'echo "MACs +hmac-md5" > /etc/ssh/sshd_config.d/00-aaa-mut.conf', 'rm -f /etc/ssh/sshd_config.d/00-aaa-mut.conf'),
 ('ipv4-forwarding-off', 'sysctl -qw net.ipv4.ip_forward=1', 'sysctl -qw net.ipv4.ip_forward=0'),
 ('ipv4-forwarding-off#config', 'echo "net.ipv4.ip_forward = 1" > /etc/sysctl.d/99-zzz-mut.conf', 'rm -f /etc/sysctl.d/99-zzz-mut.conf'),
 ('full-aslr', 'sysctl -qw kernel.randomize_va_space=1', 'sysctl -qw kernel.randomize_va_space=2'),
 ('ptrace-restricted-yama', 'echo "kernel.yama.ptrace_scope = 0" > /etc/sysctl.d/99-zzz-mut.conf', 'rm -f /etc/sysctl.d/99-zzz-mut.conf'),
 ('no-core-dumps-from-setuid-programs', 'sysctl -qw fs.suid_dumpable=1', 'sysctl -qw fs.suid_dumpable=0'),
 ('kmod-cramfs-unavailable', 'for f in $(grep -lE "^\\s*install\\s+cramfs" /etc/modprobe.d/*.conf); do bk $f; sed -i -E "/^\\s*(install|blacklist)\\s+cramfs/d" $f; echo $f >> /root/mutbak/files; done', 'for f in $(cat /root/mutbak/files); do rs $f; done; rm -f /root/mutbak/files'),
 ('kmod-usb-storage-unavailable', 'for f in $(grep -lE "^\\s*install\\s+usb[-_]storage" /etc/modprobe.d/*.conf); do bk $f; sed -i -E "/^\\s*install\\s+usb[-_]storage/d" $f; echo $f >> /root/mutbak/files; done', 'for f in $(cat /root/mutbak/files); do rs $f; done; rm -f /root/mutbak/files'),
 ('dev-shm-mounted-noexec', 'mount -o remount,exec /dev/shm', 'mount -o remount,noexec /dev/shm'),
 ('tmp-mounted-nosuid', 'mount -o remount,suid /tmp', 'mount -o remount,nosuid /tmp'),
 ('pwquality-minimum-length-14', 'mkdir -p /etc/security/pwquality.conf.d; echo "minlen = 8" > /etc/security/pwquality.conf.d/99-zzz-mut.conf', 'rm -f /etc/security/pwquality.conf.d/99-zzz-mut.conf'),
 ('faillock-lock-after-5-failures', 'bk /etc/security/faillock.conf; echo "deny = 10" >> /etc/security/faillock.conf', 'rs /etc/security/faillock.conf'),
 ('passwords-expire-within-365-days', 'bk /etc/shadow; chage -M 99999 cisadmin', 'rs /etc/shadow'),
 ('sudo-password-required-no-nopasswd', 'echo "cisadmin ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/99-zzz-mut; chmod 440 /etc/sudoers.d/99-zzz-mut', 'rm -f /etc/sudoers.d/99-zzz-mut'),
 ('su-limited-to-an-empty-group', 'g=$(grep -oP "pam_wheel.so.*group=\\K\\S+" /etc/pam.d/su | head -1); echo $g > /root/mutbak/sugroup; gpasswd -a cisadmin $g >/dev/null', 'gpasswd -d cisadmin $(cat /root/mutbak/sugroup) >/dev/null'),
 ('audit-sudoers-changes', 'for f in $(grep -lE "path=/etc/sudoers|-w /etc/sudoers" /etc/audit/rules.d/*.rules); do bk $f; sed -i -E "/\\/etc\\/sudoers/d" $f; echo $f >> /root/mutbak/files; done', 'for f in $(cat /root/mutbak/files); do rs $f; done; rm -f /root/mutbak/files'),
 ('etc-shadow-640-root-shadow', 'm=$(stat -c %a /etc/shadow); echo $m > /root/mutbak/shmode; chmod 644 /etc/shadow', 'chmod $(cat /root/mutbak/shmode) /etc/shadow'),
 # the two characters backslash-v (agetty's OS version escape), not a vertical tab
 ('local-login-banner-shows-no-os-details', 'bk /etc/issue; printf "%s\\n" "\\\\v" >> /etc/issue', 'rs /etc/issue'),
 ('grub-cfg-0600-root-root', 'g=$(ls /boot/grub*/grub.cfg | head -1); echo $g > /root/mutbak/grubcfg; chmod 644 $g', 'chmod 600 $(cat /root/mutbak/grubcfg)'),
 # deb/suse: password_pbkdf2 in /etc/grub.d/01_pvs-cis and grub.cfg; EL: GRUB2_PASSWORD= in any user.cfg under /boot
 ('grub-superuser-password', 'for f in $(grep -lsE "password_pbkdf2|^[[:space:]]*GRUB2?_PASSWORD=" /boot/grub*/grub.cfg /etc/grub.d/* $(find /boot -type f -name user.cfg 2>/dev/null)); do bk $f; sed -i -E "/password_pbkdf2|^[[:space:]]*GRUB2?_PASSWORD=/d" $f; echo $f >> /root/mutbak/files; done', 'for f in $(cat /root/mutbak/files); do rs $f; done; rm -f /root/mutbak/files'),
 ('root-umask-027-or-stricter', 'if test -e /root/.bashrc; then bk /root/.bashrc; else touch /root/mutbak/bashrc.new; fi; echo "umask 022" >> /root/.bashrc',
  'if test -f /root/mutbak/bashrc.new; then rm -f /root/.bashrc /root/mutbak/bashrc.new; else rs /root/.bashrc; fi'),
 ('default-umask-027', 'echo "umask 022" > /etc/profile.d/zzz-mut.sh', 'rm -f /etc/profile.d/zzz-mut.sh'),
 ('no-world-writable-files-sticky-world-writable-di', 'install -d -m 0777 /srv/mutww', 'rmdir /srv/mutww'),
 ('no-empty-password-fields-in-shadow', 'useradd -M -s /usr/sbin/nologin mutuser && passwd -d mutuser >/dev/null', 'userdel -r mutuser 2>/dev/null'),
 ('interactive-users-dot-files-locked-down', 'm=$(stat -c %a /home/cisadmin/.bashrc); echo $m > /root/mutbak/dotmode; chmod 666 /home/cisadmin/.bashrc', 'chmod $(cat /root/mutbak/dotmode) /home/cisadmin/.bashrc'),
 ('journald-compression-on', 'mkdir -p /etc/systemd/journald.conf.d; echo -e "[Journal]\\nCompress=no" > /etc/systemd/journald.conf.d/99-zzz-mut.conf', 'rm -f /etc/systemd/journald.conf.d/99-zzz-mut.conf'),
 ('selinux-enforcing', 'setenforce 0', 'setenforce 1'),
 ('firewalld-enabled', 'systemctl stop firewalld', 'systemctl start firewalld'),
 ('ufw-service-enabled-and-active', 'ufw disable >/dev/null', 'ufw --force enable >/dev/null'),
 ('ufw-denies-outgoing-by-default', 'ufw default allow outgoing >/dev/null', 'ufw default deny outgoing >/dev/null'),
 ('firewalld-default-zone-drop', 'z=$(firewall-cmd --get-default-zone); echo $z > /root/mutbak/zone; firewall-cmd -q --set-default-zone=public', 'firewall-cmd -q --set-default-zone=$(cat /root/mutbak/zone)'),
 ('crypto-policy-not-legacy', 'update-crypto-policies --show > /root/mutbak/cp; update-crypto-policies --no-reload --set LEGACY >/dev/null 2>&1', 'update-crypto-policies --no-reload --set $(cat /root/mutbak/cp) >/dev/null 2>&1'),
 ('dnf-gpgcheck', 'test -d /etc/yum.repos.d || exit 0; f=$(ls /etc/yum.repos.d/*.repo | head -1); bk $f; echo $f > /root/mutbak/repo; sed -i -E "0,/^gpgcheck=1/s//gpgcheck=0/" $f', 'test -f /root/mutbak/repo && rs $(cat /root/mutbak/repo); rm -f /root/mutbak/repo'),
 ('etc-crontab-root-only', 'test -f /etc/crontab && { m=$(stat -c %a /etc/crontab); echo $m > /root/mutbak/ctmode; chmod 644 /etc/crontab; }', 'test -f /root/mutbak/ctmode && chmod $(cat /root/mutbak/ctmode) /etc/crontab'),
 ('motd-files-0644-root-root', 'test -f /etc/motd && { m=$(stat -c %a /etc/motd); echo $m > /root/mutbak/motdmode; chmod 666 /etc/motd; }', 'test -f /root/mutbak/motdmode && chmod $(cat /root/mutbak/motdmode) /etc/motd'),
]


# One mutation set per chapter beside the original list (mutsets.py, 2026-10-18).
B += B_EXTRA
M += MORE


def key_to_num(cfg, image):
    return {key: n for n, (lv, kind, key) in mapcheck.read_map(cfg, mapcheck.map_dir(cfg, image)).items()}


def generate(cfg, image):
    mp = key_to_num(cfg, image)
    ck = '/usr/local/sbin/pvs-cis check --level 2 --exceptions $EX'
    sh = ['#!/usr/bin/env bash', 'export LC_ALL=C', LOG_FN, B, 'EX=/etc/pvs-cis/exceptions',
          'st() { python3 -c "import json,sys; r=json.load(open(\'/tmp/mut.json\'))[\'results\']; '
          'print(r[0][\'status\'] if r else \'none\', \'::\', str(r[0][\'evidence\'])[:200].replace(chr(10),\' / \') '
          'if r else \'\')" 2>/dev/null || echo "status-unreadable"; }',
          'sshok() { ss -ltn 2>/dev/null | grep -Eq "[:.]22[[:space:]]"; }',
          'sshfix() { sshd -t 2>&1 | head -3; systemctl reset-failed sshd.service ssh.service 2>/dev/null; systemctl restart sshd.service 2>/dev/null || systemctl restart ssh.service 2>/dev/null; sleep 2; sshok && log ok "sshd back"; }',
          f'{ck} --json /tmp/before.json >/dev/null 2>&1']
    n_mut = 0
    for key, mut, rev in M:
        k = key.split('#')[0]
        if k not in mp:
            continue
        # Toggling forwarding resets accept_redirects and friends on every interface: the
        # configured values go back with the revert.
        if 'forwarding' in key:
            rev += '; sysctl -q --system >/dev/null 2>&1'
        n = mp[k]
        n_mut += 1
        sh.append(f'echo "@@@MUT {key} {n}"; log run "mutation {key} ({n})"')
        sh.append(f'{ck} --only {n} --json /tmp/mut.json >/dev/null 2>&1; echo "before: $(st)"')
        sh.append(f'( {mut} ) 2>&1 | head -3')
        sh.append(f'{ck} --only {n} --json /tmp/mut.json >/dev/null 2>&1; m=$(st); echo "mutated: $m"; '
                  f'case $m in fail*) log ok "{n} caught: $m" ;; *) log error "{n} NOT caught: $m" ;; esac')
        sh.append(f'( {rev} ) 2>&1 | head -3')
        sh.append(f'{ck} --only {n} --json /tmp/mut.json >/dev/null 2>&1; echo "reverted: $(st)"')
        # sshd must survive every mutation: a dead listener is reported and brought back
        sh.append(f'sshok || {{ echo "@@@SSHDOWN {key}"; log error "{n} {key}: sshd down after revert"; sshfix; }}')
    sh.append(f'{ck} --json /tmp/after.json >/dev/null 2>&1')
    sh.append('python3 -c "import json; a={r[\'id\']:r[\'status\'] for r in json.load(open(\'/tmp/before.json\'))[\'results\']}; '
              'b={r[\'id\']:r[\'status\'] for r in json.load(open(\'/tmp/after.json\'))[\'results\']}; '
              'd=[(k,a[k],b.get(k)) for k in a if a[k]!=b.get(k)]; print(\'@@@RESIDUE\', d)"')
    return '\n'.join(sh) + '\n', n_mut


def summarise(text):
    rows = []
    for blk in re.split(r'^@@@MUT ', text, flags=re.M)[1:]:
        head = blk.split('\n')[0]
        g = lambda k: (re.search(rf'^{k}: (\S+)(.*)$', blk, re.M) or [None, '?', ''])
        b, m, r = g('before'), g('mutated'), g('reverted')
        ok = b[1] in ('pass', 'na', 'review', 'exception') and m[1] == 'fail' and r[1] == b[1]
        rows.append(f"{'OK ' if ok else 'XX '}{head:48} before={b[1]:7} mutated={m[1]:7} reverted={r[1]:7} "
                    f"{m[2][:150] if not ok else ''}")
    rows += [f'XX SSHDOWN after {m}' for m in re.findall(r'^@@@SSHDOWN (\S+)', text, re.M)]
    res = re.search(r'@@@RESIDUE.*', text)
    rows.append(res.group(0) if res else 'no residue line')
    return '\n'.join(rows)


def cmd_mutate(cfg, args):
    if args.action == 'gen':
        for img in args.names:
            text, n = generate(cfg, img)
            out = cfg.work / 'mutations' / f'mut-{img}.sh'
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(text, newline='\n')
            log('ok', f'{out}: {n} mutations')
        return 0
    for name in args.names:
        vm = cfg.vm(name)
        o = cfg.vm_dir(name)
        if args.action == 'run':
            text, n = generate(cfg, vm['image'])
            scr = o / 'mut.sh'
            scr.write_text(text, newline='\n')
            vmmod.put(cfg, vm, scr, '/tmp/mut.sh')
            # stdout is the @@@ stream summarise() reads; the log lines go beside it
            # copies in /root survive a reboot (EL's /tmp does not)
            vmmod.root(cfg, vm, 'bash /tmp/mut.sh > /tmp/mut.out 2> /tmp/mut.log; cp /tmp/mut.out /tmp/mut.log /root/; '
                       'chmod 644 /tmp/mut.out /tmp/mut.log\n')
            vmmod.get(cfg, vm, ['/tmp/mut.out', '/tmp/mut.log'], o)
            (o / 'mut.out').replace(o / 'mutations.out')
        s = summarise((o / 'mutations.out').read_text(errors='ignore'))
        (o / 'mutations.txt').write_text(s + '\n')
        rows = s.split('\n')
        bad = sum(r.startswith('XX') for r in rows)
        for r in rows:
            log('ok' if r.startswith('OK') else 'error' if r.startswith('XX') else 'info', f'{name}: {r}')
        log('error' if bad else 'ok', f'{name}: {len(rows) - 1 - bad} of {len(rows) - 1} mutations caught and reverted')
    return 0
