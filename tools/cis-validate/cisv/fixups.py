"""Repairs for audit text that pdftotext breaks. Transforms only - no CIS text lives here.

GENERIC runs on every recommendation's audit text before it is cut into blocks: typographic
quotes and ligatures back to ASCII, page furniture that lands inside a script.

PER_REC is keyed by (image-or-'*', CIS number) and holds (regex, replacement) pairs applied in
order after GENERIC. Add an entry when the parse report or `bash -n` flags a block, and keep
the pattern as narrow as it can be. Example shape:

    ('ubuntu2604', '5.4.2.7'): [(r'awk -F:\\s*\\n\\s*\\'', "awk -F: '")],
"""
import re

GENERIC = [
    (r'[\u2018\u2019\u201a\u2032]', "'"),
    (r'[\u201c\u201d\u201e\u2033]', '"'),
    (r'[\u2013\u2014]', '-'),
    (r'\ufb01', 'fi'),
    (r'\ufb02', 'fl'),
    (r'\u00a0', ' '),
    (r'\n\s*Page \d+\s*(?=\n)', ''),
    (r'\n\s*Internal Only - General\s*(?=\n)', ''),
    (r'\f', ''),
    # pdftotext splits short options after the dash inside a line: "cut - d=", "-d= - f2"
    (r'\bcut\s+-\s+d=', 'cut -d='),
    (r'(\bcut -d\S*)\s+-\s+f(\d)', r'\1 -f\2'),
]

PER_REC = {
}


def apply(image, num, text):
    for pat, rep in GENERIC:
        text = re.sub(pat, rep, text)
    for key in ((image, num), ('*', num)):
        for pat, rep in PER_REC.get(key, []):
            text = re.sub(pat, rep, text)
    return text


def has_fixup(image, num):
    return (image, num) in PER_REC or ('*', num) in PER_REC
