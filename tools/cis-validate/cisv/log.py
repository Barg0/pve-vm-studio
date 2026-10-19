"""The studio's log layout, as deploy/install.sh's log() and GuestProvision.ps1's Write-Log draw it.

time, a five-wide tag, the message - the clock and brackets in muted, the tag coloured. Status
lines go to stderr so stdout stays free for data (TSV, reports, JSON); the log file gets the
same line with the full date and no colour.
"""
import datetime
import os
import sys

TAGS = ('start', 'get', 'run', 'info', 'warn', 'ok', 'error', 'debug', 'end')

# Kaido (Tokyo Night) as exact colours, so every terminal draws the same thing.
_RESET = '\033[0m'
_DIM = '\033[38;2;139;147;173m'
_COLOR = {
    'start': '\033[38;2;122;162;247m', 'end': '\033[38;2;122;162;247m',
    'get': '\033[38;2;125;207;255m', 'run': '\033[38;2;187;154;247m',
    # info takes the log's own yellow, one step below warn's gold.
    'info': '\033[38;2;230;222;120m', 'warn': '\033[38;2;224;175;104m',
    'ok': '\033[38;2;158;206;106m', 'error': '\033[38;2;247;118;142m',
}

_file = None


def set_file(path):
    """Append every line to path as well (the run's cisv.log)."""
    global _file
    path.parent.mkdir(parents=True, exist_ok=True)
    _file = path


def _color():
    return not os.environ.get('NO_COLOR') and sys.stderr.isatty()


def log(tag, *msg):
    # A tag outside the set renders as an error rather than being dropped, so a typo is loud.
    if tag not in TAGS:
        tag = 'error'
    if tag == 'debug' and not os.environ.get('CISV_DEBUG'):
        return
    shown = 'o.k.' if tag == 'ok' else tag
    text = ' '.join(str(m) for m in msg)
    now = datetime.datetime.now()
    if _file:
        with open(_file, 'a', encoding='utf-8') as f:
            f.write(f'{now:%Y-%m-%d %H:%M:%S} [ {shown:<5} ] {text}\n')
    if _color():
        c = _COLOR.get(tag, _DIM)
        line = f' {_DIM}{now:%H:%M:%S} [ {_RESET}{c}{shown:<5}{_RESET}{_DIM} ]{_RESET} {text}'
    else:
        line = f' {now:%H:%M:%S} [ {shown:<5} ] {text}'
    print(line, file=sys.stderr, flush=True)
