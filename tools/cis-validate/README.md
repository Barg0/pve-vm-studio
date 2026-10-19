# cis-validate (`cisv`)

This tool checks the studio's CIS implementation (`guest-files/cis`) against each benchmark's own
audit procedure, using the real PDFs, on real test VMs. It also lines up second opinions from Ansible
Lockdown and OpenSCAP. It grew out of the review run of 2026-10-16; the method and the findings are in
`docs/cis-review-2026-10-16.md` (local) and `REVIEW-INSTRUCTIONS.md` in that run's folder.

It needs Python 3.11+ (standard library only), `pdftotext` (poppler-utils), `ssh`/`scp` and `git`.
It is meant to run on a Linux runner next to the test VMs, not on a workstation.

## Licence boundary

CIS benchmarks are CC BY-NC-SA, and their text must not be redistributed (see `docs/cis-benchmark.md`).

- **In the repo:** code, benchmark file *names*, repository branches, rule keys, mutation commands, and
  fixup *transforms* (regexes keyed by CIS number).
- **Never in the repo:** extracted PDF text, audit commands copied from a PDF, runner scripts, VM output,
  review files and findings. All of these are written under `work_dir`, which is outside the repo by
  configuration. `.gitignore` here is a second fence, not the first.

## Never touch VMID 101

VMID 101 (`jh-pve-01`) is the machine the operator works from. `cisv/guard.py` refuses it by number and
by name for every VM action, including any inventory that merely lists it. Configuration can add more
protected VMs, but it cannot remove these.

## Setup

```sh
cp config.example.toml config.toml        # set pdf_dir, work_dir, ssh key
./cisv.py third fetch                     # Lockdown audit repos at the matching branches, goss + syver
```

The inventory is `<work_dir>/inventory.tsv`. It is tab-separated, one VM per line:

```
# name        ip           user      image       vmid  password (optional; sudo -n without it)
cis-rocky9    10.10.0.62   cisadmin  rocky9      9102  ...
```

`image` is the folder name under `guest-files/cis` (`ubuntu2604`, `rocky9`, `leap16`, ...).

## Flow

| Step | Command | Writes |
|---|---|---|
| 1. PDFs to recommendations and audit sections | `cisv extract [image...]` | `pdf/<base>.{txt,json,audit.json}` |
| 2. Each map against its PDF | `cisv mapcheck [image...]` | stdout, plus `mapcheck/loose-<map>.txt` |
| 3. Runner of every audit command and script, as printed | `cisv runner [image...]` | `pdf/<base>.runner.sh`, `pdf/<base>.parse.txt` |
| 4. Runner + our live `pvs-cis check` on each VM | `cisv vm run [vm...]` | `vm/<name>/{pdf-audit.out,live.json,live.txt}` |
| 5. Second opinions (they install things, so they run after 4) | `cisv third lockdown [vm...]`, `cisv third oscap --install [vm...]` | `vm/<name>/{lockdown,oscap}.*` |
| 6. Normalise second opinions per CIS number | `cisv third diff [vm...]` | `vm/<name>/{third.json,third-diff.txt}` |
| 7. Review files | `cisv join [vm...]` | `vm/<name>/review/{INDEX.md,chN.md}` |
| 8. Mutation tests (disposable VMs only) | `cisv mutate run <vm...>` | `vm/<name>/{mutations.out,mutations.txt}` |

More commands:
- `cisv vm list|sh <vm> [script]|put|get`
- `cisv vm golds` copies the gold bake reports out of the studio container.
- `cisv vm summary [vm...]` summarises those reports, or the VMs' live reports.
- `cisv third fails <vm>` shows Lockdown's failed tests with actual and expected values.
- `cisv third profiles <ds.xml...>` lists the CIS profiles of a datastream.
- `cisv join --compact <chN.md>` shows a review file without its PDF text.
- `cisv winparse <pdf...>` handles the Windows benchmarks (Phase 8).

## Reading the results

- **Parse report** (`*.parse.txt`): blocks that pdftotext broke. These are commands that look cut off,
  scripts that never close, and `bash -n` errors. Add a transform to `cisv/fixups.py` (`PER_REC`) and
  rerun `cisv runner`. A block nobody fixes still runs, and the reviewer reruns it by hand.
- **PDF verdicts:** a block counts as pass or fail only when its output has the PDF's own `** PASS **` /
  `** FAIL **` marker. Everything else is `raw`, which means a person reads the output against the
  audit text.
- **Lockdown and OpenSCAP:** they follow their own conventions and often target older benchmark versions.
  A disagreement is a lead, not a verdict. The PDF procedure on the VM decides.
- **`FLAG: DISAGREE`** in a review file means our pass, fail or n/a is contradicted by at least one other
  source. `INDEX.md` lists these.

## Tests

```sh
python3 -m unittest discover -s tests
```
