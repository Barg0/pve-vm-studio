"""cisv runner: one bash file per benchmark that runs every recommendation's audit commands and
scripts exactly as the PDF prints them, framing each output, plus a parse report of what could
not be cut cleanly. Run the file as root on a test VM (`cisv vm run`).

Block parsing is mkrunner.py's (2026-10-16): a '#!/bin/bash' or '#!/usr/bin/env bash' line
starts a script that ends on the line closing its outermost { ... }; a '# <command>' line is
one command. New here: wrapped commands are rejoined, fixups.py repairs known breakage, every
block can be syntax-checked with `bash -n`, and the exit code is the command's, not head's.

Output frame, read by `cisv join`:
    @@@REC <num> <blocks>
    @@@CMD|SCRIPT <num>.<k>
    <output, capped>
    @@@RC <exit code>
"""
import re
import shlex
import shutil
import subprocess

from . import benchmarks, fixups, pdf
from .log import log

# The studio's log layout (deploy/install.sh log()), on stderr only: stdout is the @@@ evidence
# stream `cisv join` reads, and nothing may land between a block's @@@CMD and its @@@RC.
# The verdict line is a reading aid; `cisv join` still decides from the evidence.
LOG_FN = r"""if [[ -z ${NO_COLOR:-} && -t 2 ]]; then
    C_RESET=$'\e[0m' C_DIM=$'\e[38;2;139;147;173m' C_ACCENT=$'\e[38;2;122;162;247m' C_OK=$'\e[38;2;158;206;106m'
    C_WARN=$'\e[38;2;224;175;104m' C_ERR=$'\e[38;2;247;118;142m' C_INFO=$'\e[38;2;230;222;120m'
    C_HOST=$'\e[38;2;125;207;255m' C_IDENT=$'\e[38;2;187;154;247m'
else
    C_RESET="" C_DIM="" C_ACCENT="" C_OK="" C_WARN="" C_ERR="" C_INFO="" C_HOST="" C_IDENT=""
fi
log() {
    local tag=$1; shift
    local shown=$tag color
    [[ $tag == ok ]] && shown="o.k."
    case $tag in
        start|end) color=$C_ACCENT ;; get) color=$C_HOST ;; run) color=$C_IDENT ;;
        info) color=$C_INFO ;; warn) color=$C_WARN ;; ok) color=$C_OK ;; error) color=$C_ERR ;;
        *) color=$C_DIM ;;
    esac
    printf ' %s%s [ %s%s%-5s%s%s ]%s %s\n' "$C_DIM" "$(date '+%H:%M:%S')" "$C_RESET" "$color" "$shown" "$C_RESET" "$C_DIM" "$C_RESET" "$*" >&2
}
verdict() { # <rec.block> <rc>
    local o
    o=$(sed 's/\*\*FAIL\*\*/** FAIL **/g; s/\*\*PASS\*\*/** PASS **/g' "$O")
    if [[ $o == *'** FAIL **'* ]]; then log error "$1 ** FAIL ** (rc $2)"
    elif [[ $o == *'** PASS **'* ]]; then log ok "$1 ** PASS ** (rc $2)"
    else log info "$1 raw output for review (rc $2)"; fi
}"""

FURNITURE =re.compile(r'^(Page \d+|Internal Only - General)$')
CONT_END = ('|', '\\', '&&', '||', '(', '{')


def balanced(s):
    """True when quotes, parens and braces close - a cheap test for a cut-off command."""
    sq = dq = False
    depth = 0
    esc = False
    for ch in s:
        if esc:
            esc = False
            continue
        if ch == '\\' and not sq:
            esc = True
            continue
        if ch == "'" and not dq:
            sq = not sq
        elif ch == '"' and not sq:
            dq = not dq
        elif not sq and not dq:
            if ch in '({[':
                depth += 1
            elif ch in ')}]':
                depth -= 1
    return not sq and not dq and depth <= 0


# A tool that takes a pattern or program first: cut off when only options follow it.
PATTERN_TOOLS = ('grep', 'egrep', 'awk', 'sed')
# Regex operators: a quoted pattern the PDF cut next to one of them had no space there.
REGEX_EDGE = set('()[]|\\?*+^.')


def last_segment(c):
    """The words of the last pipeline stage, or [] when the line does not split."""
    try:
        words = shlex.split(c, posix=True)
    except ValueError:
        return []
    seg = []
    for w in words:
        seg = [] if w in ('|', '||', '&&', ';') else seg + [w]
    return seg


def open_quote(s):
    """"'" or '"' when s ends inside a single- or double-quoted string, else ''."""
    sq = dq = esc = False
    for ch in s:
        if esc:
            esc = False
            continue
        if ch == '\\' and not sq:
            esc = True
            continue
        if ch == "'" and not dq:
            sq = not sq
        elif ch == '"' and not sq:
            dq = not dq
    return "'" if sq else '"' if dq else ''


def wants_files(cmd, nxt):
    """grep with its pattern last and no file, the next line a path: the PDF wrapped the file
    operands (a grep without files would read stdin)."""
    try:
        if '|' in shlex.split(cmd, posix=True):
            return False
    except ValueError:
        return False
    seg = last_segment(cmd.rstrip())
    if not seg or seg[0] not in ('grep', 'egrep'):
        return False
    ops = [w for w in seg[1:] if not w.startswith('-')]
    return len(ops) == 1 and nxt.strip().startswith('/')


def incomplete(cmd):
    c = cmd.rstrip()
    if c.endswith(CONT_END) or c.endswith('<<<') or re.search(r'(^|\s)-$', c) or not balanced(c):
        return True
    # "... /etc/crypto-" + "policies/...": a path the PDF hyphenated at the line end
    if re.search(r'/[^\s\'"]*[A-Za-z0-9]-$', c):
        return True
    # "... | grep" or "grep -Psi --" with the pattern on the next line
    seg = last_segment(c)
    if seg and seg[0] in PATTERN_TOOLS and all(w.startswith('-') for w in seg[1:]):
        return True
    # A for/while/if/case the PDF wrapped over several lines: bash says the end is missing.
    if re.search(r'\b(for|while|until|if|case)\b', c):
        err = syntax_error(c)
        return bool(err) and 'unexpected end of file' in err
    return False


def blocks(text, max_join=15):
    """[(kind, code, problem)] with kind 'cmd' or 'script'; problem is '' when the block parsed cleanly."""
    L = [l.rstrip() for l in text.split('\n')]
    out = []
    i = 0
    while i < len(L):
        s = L[i].strip()
        if s.startswith('#!/usr/bin/env bash') or s.startswith('#!/bin/bash'):
            body = []
            depth = 0
            seen = closed = False
            # pdftotext -layout puts a script's lines at its base indent (the shebang's column)
            # plus the script's own indentation; a line the PDF wrapped continues at the base
            # indent itself. Such a line inside the braces belongs to the line before it.
            base = len(L[i]) - len(L[i].lstrip())
            i += 1
            while i < len(L):
                t = L[i].strip()
                if FURNITURE.match(t):
                    i += 1
                    continue
                ind = len(L[i]) - len(L[i].lstrip())
                if seen and depth > 0 and t and ind == base and t not in ('{', '}') and body:
                    # an option split after its dash ("grep -" / "Pio") joins without a space
                    prev = body[-1].rstrip()
                    # ... as does a word the PDF hyphenated at the line end ("systemd-" / "journal")
                    body[-1] = prev + ('' if prev.endswith('-') else ' ') + t
                    depth += t.count('{') - t.count('}')
                    i += 1
                    continue
                body.append(L[i])
                depth += t.count('{') - t.count('}')
                if '{' in t:
                    seen = True
                if seen and depth <= 0 and t.endswith('}'):
                    closed = True
                    break
                i += 1
            out.append(('script', '\n'.join(body), '' if closed else 'script never closes its outer { }'))
        elif re.match(r'^#\s+\S', s) and not s.startswith('#!'):
            cmd = s[1:].strip()
            joined = 0
            # "# {" opens a brace group the PDF prints line by line: its lines stay lines (a
            # space would turn "UID_MIN=... <newline> [ ..." into a one-command assignment).
            group = cmd == '{'
            while (incomplete(cmd) or (i + 1 < len(L) and wants_files(cmd, L[i + 1]))) \
                    and joined < (60 if group else max_join) and i + 1 < len(L):
                nxt = L[i + 1].strip()
                if group and FURNITURE.match(nxt):
                    i += 1
                    continue
                if not nxt or nxt.startswith('#') or FURNITURE.match(nxt):
                    break
                q = open_quote(cmd)
                if group:
                    cmd = cmd + '\n' + nxt
                elif cmd.endswith('\\') and q == '"':
                    cmd = cmd[:-1] + nxt     # backslash-newline in double quotes: bash joins the lines
                elif cmd.endswith('\\') and q:
                    cmd = cmd + nxt          # "\n\" + "r]+": an escape the PDF cut inside a quoted regex
                elif cmd.endswith('\\'):
                    cmd = cmd[:-1].rstrip() + ' ' + nxt
                elif re.search(r'(^|\s)-$', cmd) or re.search(r'/[^\s\'"]*[A-Za-z0-9]-$', cmd):
                    cmd = cmd + nxt          # an option or a path split after its dash
                elif open_quote(cmd) and (cmd[-1] in REGEX_EDGE or nxt[0] in REGEX_EDGE):
                    cmd = cmd + nxt          # a quoted regex cut between two of its operators
                else:
                    cmd = cmd + ' ' + nxt
                i += 1
                joined += 1
            out.append(('cmd', cmd, 'command looks cut off' if incomplete(cmd) else ''))
        i += 1
    return out


def verdict(output):
    """'fail' / 'pass' only when the PDF's own script says so; everything else needs a reader."""
    o = output.replace('**FAIL**', '** FAIL **').replace('**PASS**', '** PASS **')
    if '** FAIL **' in o:
        return 'fail'
    if '** PASS **' in o:
        return 'pass'
    return 'raw'


def syntax_error(code):
    bash = shutil.which('bash')
    if not bash:
        return None
    p = subprocess.run([bash, '-n'], input=code, capture_output=True, text=True)
    return p.stderr.strip()[:300] if p.returncode else ''


def emit(image, aud, check_syntax=True):
    """(runner script text, [report lines], counts)."""
    sh = ['#!/usr/bin/env bash', 'export LC_ALL=C', 'shopt -s globstar 2>/dev/null',
          'O=$(mktemp); trap \'rm -f "$O"\' EXIT', LOG_FN, f'log start "PDF audit runner: {image}"', '']
    report = []
    n_cmd = n_scr = 0
    for n in sorted(aud, key=pdf.numkey):
        text = fixups.apply(image, n, aud[n]['audit'])
        bl = blocks(text)
        if aud[n]['audit'].strip() and not bl:
            report.append(f'{n}\tno-blocks\taudit text has no command or script (prose-only audit)')
        sh.append(f'echo "@@@REC {n} {len(bl)}"')
        for k, (kind, code, problem) in enumerate(bl):
            if problem:
                report.append(f'{n}.{k}\t{kind}\t{problem}')
            if check_syntax:
                err = syntax_error(code)
                if err:
                    report.append(f'{n}.{k}\t{kind}\tbash -n: {err}')
            sh.append(f'echo "@@@{kind.upper()} {n}.{k}"')
            if kind == 'cmd':
                n_cmd += 1
                sh.append(f'timeout 60 bash -c {shlex.quote(code)} </dev/null >"$O" 2>&1; rc=$?; '
                          f'head -c 4000 "$O"; echo; echo "@@@RC $rc"; verdict {n}.{k} $rc')
            else:
                n_scr += 1
                d = f'PVS_EOF_{n.replace(".", "_")}_{k}'
                sh.append(f'timeout 300 bash -s >"$O" 2>&1 <<\'{d}\'\n{code}\n{d}')
                sh.append(f'rc=$?; head -c 8000 "$O"; echo; echo "@@@RC $rc"; verdict {n}.{k} $rc')
    sh.append(f'log end "PDF audit runner: {image} - {n_cmd} commands, {n_scr} scripts"')
    return '\n'.join(sh) + '\n', report, (n_cmd, n_scr)


def cmd_runner(cfg, args):
    for img in args.images or benchmarks.images():
        base, _, aud = pdf.load(cfg, img)
        text, report, (nc, ns) = emit(img, aud, not args.no_syntax)
        out = cfg.pdf_out(base, 'runner.sh')
        out.write_text(text, newline='\n')
        cfg.pdf_out(base, 'parse.txt').write_text('\n'.join(report) + '\n')
        log('warn' if report else 'ok', f'{img}: {out.name} {nc} cmds {ns} scripts, {len(report)} parse problems '
              f'-> {base}.parse.txt')
