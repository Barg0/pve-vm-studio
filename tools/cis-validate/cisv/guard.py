"""The one place that decides whether a VM may be touched.

VMID 101 (jh-pve-01) is the machine the operator - and Claude - runs on. Stopping, changing or
even SSHing into it from a loop would cut the session off. These are built in and cannot be
switched off by configuration; a config may only add to them.
"""

FORBIDDEN_VMIDS = frozenset({101})
FORBIDDEN_NAMES = frozenset({'jh-pve-01'})


class GuardError(Exception):
    pass


def ensure_allowed(name=None, vmid=None, extra_vmids=(), extra_names=()):
    """Raise GuardError if name or vmid is protected. Call before any action on a VM."""
    vmids = FORBIDDEN_VMIDS | {int(v) for v in extra_vmids}
    names = FORBIDDEN_NAMES | {n.lower() for n in extra_names}
    if vmid not in (None, ''):
        try:
            v = int(str(vmid).strip())
        except ValueError:
            raise GuardError(f'refusing: VMID {vmid!r} is not a number')
        if v in vmids:
            raise GuardError(f'refusing: VMID {v} is protected (the machine this runs on)')
    if name:
        n = str(name).strip().lower()
        if n in names:
            raise GuardError(f'refusing: VM {name!r} is protected (the machine this runs on)')
