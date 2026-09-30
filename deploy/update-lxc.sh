#!/usr/bin/env bash
#
# update-lxc.sh - replaces the studio's binary in its container and restarts it. Run on
# the PVE node as root, next to the new pve-vm-studio binary:
#
#   ./update-lxc.sh [vmid]      (default 9100)
#
# Jobs running at that moment are marked interrupted; the database and logs stay.

set -euo pipefail
VMID=${1:-9100}
HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)

[[ -x $HERE/pve-vm-studio ]] || { echo "no pve-vm-studio binary next to this script" >&2; exit 1; }
pct status "$VMID" | grep -q running || { echo "container $VMID is not running" >&2; exit 1; }

# Packages a newer studio needs, installed when missing (the same list as install.sh).
PACKAGES="ca-certificates xorriso lego 7zip wimtools"
pct exec "$VMID" -- bash -c "missing=\$(for p in $PACKAGES; do dpkg -s \$p >/dev/null 2>&1 || echo \$p; done); [ -z \"\$missing\" ] || { apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \$missing >/dev/null; }"
# ISO storages read-only into the container (newer studios read Windows ISOs' editions).
# A new mount point takes a container restart to appear.
restart=0
while read -r id; do
    path=$(pvesm path "$id:iso/x.iso" 2>/dev/null) || continue
    path=${path%/x.iso}
    [[ -d $path ]] || continue
    pct config "$VMID" | grep -q "mp=/mnt/pve-iso/$id," && continue
    i=0; while pct config "$VMID" | grep -q "^mp$i:"; do i=$((i + 1)); done
    ((i > 9)) && break
    pct set "$VMID" -mp$i "$path,mp=/mnt/pve-iso/$id,ro=1" && echo "ISO storage $id mounted read-only" && restart=1
done < <(pvesm status --content iso 2>/dev/null | awk 'NR > 1 {print $1}')
if ((restart)); then
    pct reboot "$VMID"
    for _ in $(seq 30); do pct exec "$VMID" -- true 2>/dev/null && break; sleep 2; done
fi
pct push "$VMID" "$HERE/pve-vm-studio" /usr/local/bin/pve-vm-studio.new --perms 0755
[[ -f $HERE/pve-vm-studio.service ]] && pct push "$VMID" "$HERE/pve-vm-studio.service" /etc/systemd/system/pve-vm-studio.service
pct exec "$VMID" -- bash -c 'mv -f /usr/local/bin/pve-vm-studio.new /usr/local/bin/pve-vm-studio && systemctl daemon-reload && systemctl restart pve-vm-studio'
sleep 2
pct exec "$VMID" -- systemctl is-active --quiet pve-vm-studio && echo "updated and running" ||
    { echo "the service did not come back - pct exec $VMID -- journalctl -u pve-vm-studio" >&2; exit 1; }
