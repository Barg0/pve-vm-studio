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

# A restart cuts off every running job (a bake, a two-hour media build). Refused while one
# runs: its log does not end with "[ end" or "[ error" yet - the studio writes one of them when a
# job ends, and an "interrupted" line at start for every job a stopped studio left behind.
# A stopped studio runs nothing. FORCE=1 restarts anyway.
if [[ ${FORCE:-0} != 1 ]] && pct exec "$VMID" -- systemctl is-active -q pve-vm-studio; then
    running=$(pct exec "$VMID" -- bash -c 'for f in /var/lib/pve-vm-studio/jobs/*.log; do [ -f "$f" ] || continue; l=$(tail -n 1 "$f"); case $l in *"[ end"*|*"[ error"*) ;; *) echo "  $(head -n 1 "$f" | sed "s/.*\] //")";; esac; done')
    if [[ -n $running ]]; then
        echo "not updated: a job is running - the restart would cut it off:" >&2
        echo "$running" >&2
        echo "wait for it, or FORCE=1 $0 $VMID" >&2
        exit 3
    fi
fi

# Packages a newer studio needs, installed when missing (the same list as install.sh).
PACKAGES="ca-certificates curl xorriso 7zip wimtools dosfstools mtools cabextract genisoimage gcab"
pct exec "$VMID" -- bash -c "missing=\$(for p in $PACKAGES; do dpkg -s \$p >/dev/null 2>&1 || echo \$p; done); [ -z \"\$missing\" ] || { apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \$missing >/dev/null; }"
# lego from Debian's backports, as install.sh does: the stable release keeps 4.9.1, whose INWX
# support no longer reads INWX's answers (fixed in 4.29). Once - a newer lego is left alone.
pct exec "$VMID" -- bash -c '
v=$(dpkg-query -W -f="\${Version}" lego 2>/dev/null)
if [ -z "$v" ] || dpkg --compare-versions "$v" lt 4.29; then
    codename=$(. /etc/os-release && echo "$VERSION_CODENAME")
    echo "deb http://deb.debian.org/debian ${codename}-backports main" > /etc/apt/sources.list.d/backports.list
    apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq -t "${codename}-backports" lego >/dev/null &&
        echo "lego $(dpkg-query -W -f="\${Version}" lego) from ${codename}-backports"
fi'
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
[[ -f $HERE/pve-vm-studio-console.service ]] && pct push "$VMID" "$HERE/pve-vm-studio-console.service" /etc/systemd/system/pve-vm-studio-console.service
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
pct exec "$VMID" -- systemctl is-active --quiet pve-vm-studio ||
    { echo "the service did not come back - pct exec $VMID -- journalctl -u pve-vm-studio" >&2; exit 1; }
# The maintenance console (its own service on 8443). A studio from before it gets its
# user's password now - shown here once, as install.sh shows it.
if pct exec "$VMID" -- test -f /etc/systemd/system/pve-vm-studio-console.service; then
    pw=$(pct exec "$VMID" -- env PVS_CONFIG=/etc/pve-vm-studio/config.toml /usr/local/bin/pve-vm-studio console-password --init --quiet)
    pct exec "$VMID" -- bash -c 'systemctl enable pve-vm-studio-console &>/dev/null; systemctl restart pve-vm-studio-console'
    if [[ -n $pw ]]; then
        ip=$(pct exec "$VMID" -- hostname -I | awk '{print $1}')
        printf '\n  Maintenance console   https://%s:8443\n  User                  maint\n  Password              %s\n\n' "$ip" "$pw"
        printf '  Write the password down now - it is shown only this once.\n  Lost it: pct exec %s -- /usr/local/bin/pve-vm-studio console-password --reset\n\n' "$VMID"
    fi
fi
echo "updated and running"
