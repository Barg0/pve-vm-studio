"""The eleven Linux benchmarks the studio implements, and where each one's second opinions live.

Names only: PDF file names, folder names in guest-files/cis, third-party repository branches.
No CIS text. The folder under guest-files/cis is the image id (bench.conf says which map it uses).
"""

# image id -> PDF basename (no .pdf) in the configured pdf_dir
PDFS = {
    'ubuntu2604': 'CIS_Ubuntu_Linux_26.04_LTS_Benchmark_v1.0.0',
    'ubuntu2404': 'CIS_Ubuntu_Linux_24.04_LTS_Benchmark_v2.0.0',
    'debian13': 'CIS_Debian_Linux_13_Benchmark_v1.1.0',
    'debian12': 'CIS_Debian_Linux_12_Benchmark_v2.0.0',
    'alma9': 'CIS_AlmaLinux_OS_9_Benchmark_v3.0.0',
    'rocky9': 'CIS_Rocky_Linux_9_Benchmark_v3.0.0',
    'oracle9': 'CIS_Oracle_Linux_9_Benchmark_v3.0.0',
    'alma10': 'CIS_AlmaLinux_OS_10_Benchmark_v1.0.0',
    'rocky10': 'CIS_Rocky_Linux_10_Benchmark_v1.0.0',
    'oracle10': 'CIS_Oracle_Linux_10_Benchmark_v1.0.0',
    'leap16': 'CIS_SUSE_Linux_Enterprise_16_Benchmark_v1.0.0',
}

# Ansible Lockdown audit repositories (github.com/ansible-lockdown/<repo>), the branch that
# matches our benchmark version, and the binary that branch runs. From research-cis-tools.md
# (re-verified 2026-10-17). match: exact, or near/behind when no branch implements our version -
# a disagreement there is a lead, not a verdict.
# vars: overrides written into the copy's vars/CIS.yml before it goes to the VM.
LOCKDOWN = {
    'ubuntu2604': dict(repo='UBUNTU26-CIS-Audit', branch='benchmark_1.0.0', bin='syver'),
    # The chrony branch of this audit's templates breaks (missing .options); timesyncd is ours anyway.
    'ubuntu2404': dict(repo='UBUNTU24-CIS-Audit', branch='benchmark_v2.0.0', bin='goss',
                       vars={'ubtu24cis_time_sync_tool': 'systemd-timesyncd'}),
    'debian13': dict(repo='DEBIAN13-CIS-Audit', branch='benchmark_v1.1.0', bin='syver'),
    # No 2.0.0 branch exists; `latest` implements 1.1.0.
    'debian12': dict(repo='DEBIAN12-CIS-Audit', branch='latest', bin='goss', match='behind'),
    # RHEL 9 3.0.0; the per-distro 3.0.0 PDFs' numbering is diffed against it before trusting it.
    'alma9': dict(repo='RHEL9-CIS-Audit', branch='benchmark_v3.0.0', bin='syver'),
    'rocky9': dict(repo='RHEL9-CIS-Audit', branch='benchmark_v3.0.0', bin='syver'),
    'oracle9': dict(repo='RHEL9-CIS-Audit', branch='benchmark_v3.0.0', bin='syver'),
    # RHEL 10 1.0.1 (maintained; benchmark_v1.0.0 is stale since 2025-09-30). Needs 8 GB RAM.
    'alma10': dict(repo='RHEL10-CIS-Audit', branch='benchmark_v1.0.1', bin='syver', match='near'),
    'rocky10': dict(repo='RHEL10-CIS-Audit', branch='benchmark_v1.0.1', bin='syver', match='near'),
    'oracle10': dict(repo='RHEL10-CIS-Audit', branch='benchmark_v1.0.1', bin='syver', match='near'),
    # SLE 16 1.0.0; not documented for Leap, the audit has no OS detection that would refuse it.
    'leap16': dict(repo='SUSE16-CIS-Audit', branch='benchmark_v1.0.0', bin='goss'),
}

BINARIES = {
    'goss': dict(url='https://github.com/goss-org/goss/releases/download/v0.4.10/goss_0.4.10_linux_x86_64.tar.gz',
                 sums='https://github.com/goss-org/goss/releases/download/v0.4.10/goss_0.4.10_SHA256SUMS',
                 asset='goss_0.4.10_linux_x86_64.tar.gz', member='goss'),
    'syver': dict(url='https://github.com/krameff/syver/releases/download/v0.15.1/syver-linux-amd64',
                  sums='https://github.com/krameff/syver/releases/download/v0.15.1/syver_0.15.1_SHA256SUMS',
                  asset='syver-linux-amd64'),
}

# The upstream SSG release, checked against its published sha512 and unpacked into ssg_dir.
SSG_ZIP = dict(url='https://github.com/ComplianceAsCode/content/releases/download/v0.1.82/scap-security-guide-0.1.82.zip',
               sha512='https://github.com/ComplianceAsCode/content/releases/download/v0.1.82/scap-security-guide-0.1.82.zip.sha512')

# ComplianceAsCode (SSG) datastreams with a CIS profile (research-cis-tools.md, 2026-10-17). Every
# one targets an older benchmark version than ours, so a disagreement is a lead, not a verdict.
# source: 'zip' = the upstream v0.1.82 release (put on the VM; Debian/Ubuntu's own packages lack
# their release's datastream), 'pkg' = the distro's scap-security-guide package (installed on the
# VM; rl9/rl10/almalinux10 exist only there, and ssg-rhel* is notapplicable off RHEL).
# Oracle Linux 9/10, Ubuntu 26.04 and SLE/Leap 16 have no CIS profile anywhere.
_P = 'xccdf_org.ssgproject.content_profile_'
OSCAP = {
    'ubuntu2404': dict(ds='ssg-ubuntu2404-ds.xml', source='zip', profile=_P + 'cis_level2_server'),  # 1.0.0
    'debian12': dict(ds='ssg-debian12-ds.xml', source='zip', profile=_P + 'cis_level2_server'),  # 1.1.0
    'debian13': dict(ds='ssg-debian13-ds.xml', source='zip', profile=_P + 'cis_level2_server'),  # 1.0.0
    'alma9': dict(ds='ssg-almalinux9-ds.xml', source='pkg', profile=_P + 'cis'),  # 2.0.0
    'rocky9': dict(ds='ssg-rl9-ds.xml', source='pkg', profile=_P + 'cis'),  # RHEL 9 2.0.0
    'alma10': dict(ds='ssg-almalinux10-ds.xml', source='pkg', profile=_P + 'cis'),  # 1.0.1
    'rocky10': dict(ds='ssg-rl10-ds.xml', source='pkg', profile=_P + 'cis'),  # RHEL 10 1.0.1
}


def images():
    return list(PDFS)
