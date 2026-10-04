#!/bin/bash
# pvs-update.sh - the root half of the studio's self-update (pve-vm-studio-update.path starts
# it when the studio leaves a request). The studio runs unprivileged and cannot replace its
# own binary; this script trusts nothing it wrote: it fetches the release's SHA256SUMS from
# GitHub itself, checks the staged binary against it, swaps it in (the old one kept as .prev)
# and restarts the service. The result goes into a status file the next start reads.
set -u
REPO=Barg0/pve-vm-studio
ASSET=pve-vm-studio-x86_64
D=/var/lib/pve-vm-studio/update
REQ=$D/request
[ -f "$REQ" ] || exit 0
# One-shot: a second run never acts on the same request.
mv -f "$REQ" "$D/request.taken" || exit 1
val() { sed -n "s/^$1=//p" "$D/request.taken" | head -n 1; }
TAG=$(val TAG) VERSION=$(val VERSION) JOB=$(val JOB)
status() {
    printf 'JOB=%s\nRESULT=%s\nMESSAGE=%s\n' "$JOB" "$1" "$2" > "$D/status.tmp"
    chown pve-vm-studio:pve-vm-studio "$D/status.tmp" 2>/dev/null
    mv -f "$D/status.tmp" "$D/status"
}
fail() { status fail "$1"; rm -f "$D/pve-vm-studio.new" "$D/request.taken"; systemctl restart pve-vm-studio; exit 1; }
# A release tag, or "edge" - the development channel's rolling pre-release of main.
[[ $TAG =~ ^v?[0-9]+(\.[0-9]+){1,3}(-[A-Za-z0-9.]+)?$ || $TAG == edge ]] || fail "the updater refused the request: no release tag in it"
[[ $JOB =~ ^[0-9a-f-]{36}$ ]] || JOB=""
sums=$(curl -fsSL --max-time 60 "https://github.com/$REPO/releases/download/$TAG/SHA256SUMS") || fail "the updater could not fetch SHA256SUMS of $TAG from GitHub - nothing installed"
want=$(awk -v a="$ASSET" '$2 == a || $2 == "*" a { print tolower($1); exit }' <<<"$sums")
[ -f "$D/pve-vm-studio.new" ] || fail "no staged binary - nothing installed"
have=$(sha256sum "$D/pve-vm-studio.new" | cut -d' ' -f1)
[ -n "$want" ] && [ "$want" = "$have" ] || fail "the staged binary does not match $TAG's SHA256SUMS on GitHub - nothing installed"
cp -f /usr/local/bin/pve-vm-studio /usr/local/bin/pve-vm-studio.prev 2>/dev/null
install -m 0755 -o root -g root "$D/pve-vm-studio.new" /usr/local/bin/pve-vm-studio.next || fail "could not install the binary"
mv -f /usr/local/bin/pve-vm-studio.next /usr/local/bin/pve-vm-studio
rm -f "$D/pve-vm-studio.new" "$D/request.taken"
status ok "Now running ${VERSION:-$TAG} (the previous binary is kept as /usr/local/bin/pve-vm-studio.prev)"
systemctl restart pve-vm-studio
