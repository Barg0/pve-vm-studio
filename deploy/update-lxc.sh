#!/usr/bin/env bash
#
# update-lxc.sh - replaces the studio's binary in its container and restarts it. Run on
# the PVE node as root, next to the new pve-vm-studio binary:
#
#   ./update-lxc.sh [vmid]      (default 9100)
#
# WORK_VOLUME="local-lvm:200" gives the studio's work folder (bakes, Windows media builds)
# a volume of its own on a PVE storage - thin where the storage is thin, left out of
# backups. Added once; later runs leave it alone.
#
# Jobs running at that moment are marked interrupted; the database and logs stay.

set -euo pipefail
VMID=${1:-9100}
HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)

[[ -x $HERE/pve-vm-studio ]] || { echo "no pve-vm-studio binary next to this script" >&2; exit 1; }
pct status "$VMID" | grep -q running || { echo "container $VMID is not running" >&2; exit 1; }

# Packages a newer studio needs, installed when missing (the same list as install.sh).
PACKAGES="ca-certificates xorriso lego 7zip wimtools dosfstools mtools cabextract genisoimage gcab"
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
# The work folder on a volume of its own (WORK_VOLUME="storage:GB"): a mount point PVE
# creates on that storage - a container restart makes it appear.
WORK=/var/lib/pve-vm-studio/work
work_new=0
if [[ -n ${WORK_VOLUME:-} ]] && ! pct config "$VMID" | grep -q "mp=$WORK[,]*"; then
    i=0; while pct config "$VMID" | grep -q "^mp$i:"; do i=$((i + 1)); done
    pct set "$VMID" -mp$i "$WORK_VOLUME,mp=$WORK,backup=0,mountoptions=discard" && echo "work folder on its own volume: $WORK_VOLUME GB" && restart=1 && work_new=1
fi
if ((restart)); then
    pct reboot "$VMID"
    for _ in $(seq 30); do pct exec "$VMID" -- true 2>/dev/null && break; sleep 2; done
fi
# Studios from 2026-10-04 had an SMB share for the media worker; it fetches over HTTPS from
# the studio now. What the share left behind goes (once - then there is nothing to find).
pct exec "$VMID" -- bash -c '
    if dpkg -s samba &>/dev/null; then
        systemctl disable --now smbd nmbd &>/dev/null || true
        DEBIAN_FRONTEND=noninteractive apt-get purge -y -qq samba samba-common samba-common-bin &>/dev/null || true
        DEBIAN_FRONTEND=noninteractive apt-get autoremove -y -qq --purge &>/dev/null || true
        echo "removed samba (the media worker uses HTTPS now)"
    fi
    id pvsmedia &>/dev/null && userdel pvsmedia
    rm -f /etc/pve-vm-studio/media-share.secret /usr/local/sbin/pvs-media-share
    rm -rf /srv/pvs-media
    true'
((work_new)) && pct exec "$VMID" -- bash -c "chown pve-vm-studio:pve-vm-studio $WORK && chmod 0750 $WORK"
pct push "$VMID" "$HERE/pve-vm-studio" /usr/local/bin/pve-vm-studio.new --perms 0755
[[ -f $HERE/pve-vm-studio.service ]] && pct push "$VMID" "$HERE/pve-vm-studio.service" /etc/systemd/system/pve-vm-studio.service
# Tag colours (datacenter tag-style map) take Sys.Modify on /: on / alone, not inherited.
if pveum user list --output-format json | grep -q '"userid":"pve-vm-studio@pve"'; then
    pveum role list --output-format json | grep -q '"roleid":"VmStudioTagStyle"' ||
        pveum role add VmStudioTagStyle --privs Sys.Modify
    pveum acl modify / --users pve-vm-studio@pve --roles VmStudioTagStyle --propagate 0
fi
# The self-update's root helper (the studio cannot replace its own binary).
if [[ -f $HERE/pvs-update.sh ]]; then
    pct exec "$VMID" -- mkdir -p /usr/local/lib/pve-vm-studio
    pct push "$VMID" "$HERE/pvs-update.sh" /usr/local/lib/pve-vm-studio/pvs-update.sh --perms 0755
    pct push "$VMID" "$HERE/pve-vm-studio-update.path" /etc/systemd/system/pve-vm-studio-update.path
    pct push "$VMID" "$HERE/pve-vm-studio-update.service" /etc/systemd/system/pve-vm-studio-update.service
    pct exec "$VMID" -- bash -c 'install -d -o pve-vm-studio -g pve-vm-studio -m 0750 /var/lib/pve-vm-studio/update && systemctl daemon-reload && systemctl enable --now pve-vm-studio-update.path &>/dev/null'
fi
pct exec "$VMID" -- bash -c 'mv -f /usr/local/bin/pve-vm-studio.new /usr/local/bin/pve-vm-studio && systemctl daemon-reload && systemctl restart pve-vm-studio'
sleep 2
# Space the container's volumes freed (deleted files) goes back to a thin storage.
pct fstrim "$VMID" &>/dev/null || true
pct exec "$VMID" -- systemctl is-active --quiet pve-vm-studio && echo "updated and running" ||
    { echo "the service did not come back - pct exec $VMID -- journalctl -u pve-vm-studio" >&2; exit 1; }
