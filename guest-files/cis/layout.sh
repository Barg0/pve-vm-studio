#!/bin/bash
# layout.sh - CIS Level 2's separate filesystems (/home, /var, /var/tmp, /var/log,
# /var/log/audit) on a cloud image that ships one root partition. All of it runs inside the
# guest; the studio never touches a disk from outside.
#
#   layout.sh migrate   bake, second boot, before local-fs: root partition to ROOT_GB (when
#                       smaller), the rest of the disk one LVM PV, VG "system" with one LV per
#                       filesystem; then the content copied over, the old directories emptied,
#                       fstab, mount. The studio grew the disk during the first boot; the
#                       first boot grows the root to the ROOT_GB disk (growpart), then stops it
#                       from growing again (/etc/growroot-disabled) and marks the layout wanted.
#   layout.sh grow      every boot of a clone: a disk grown at deploy grows the PV and /var.
#
# Markers: /etc/pvs-cis/layout.wanted (first boot), layout.prepared, layout.done.
set -u
STATE=/etc/pvs-cis
# The volume group: "system" on a partition of its own (lsblk shows system-var, system-home),
# or - when the root is an LV already (Oracle Linux's KVM template: vg_main) - the root's own,
# grown by the rest of the disk. A clone reads the name its gold used from layout.vg (golds
# baked before 2026-10-05 call it "pvs").
VG=system
[ -s "$STATE/layout.vg" ] && VG=$(cat "$STATE/layout.vg")
# The root's size, as the first boot wrote it into the marker (ROOT_GB=12).
# shellcheck disable=SC1091
[ -f "$STATE/layout.wanted" ] && . "$STATE/layout.wanted"
ROOT_GB=${ROOT_GB:-12}
REPORT=/run/pvs-bake.report
# name : mount point : share of the VG in % : mount options (CIS 1.1.2.x)
LVS="varaudit:/var/log/audit:15:nodev,nosuid,noexec
varlog:/var/log:15:nodev,nosuid,noexec
vartmp:/var/tmp:10:nodev,nosuid,noexec
var:/var:35:nodev,nosuid
home:/home:15:nodev,nosuid"

say() { echo "BAKE-LAYOUT $*" | tee -a "$REPORT"; }
# A failure is kept on disk too: the first boot's /run is gone by the time the studio looks.
fail() {
    echo "BAKE-LAYOUT-FAILED $*" | tee -a "$REPORT"
    mkdir -p "$STATE" && echo "$*" > "$STATE/layout.failed"
    exit 1
}

root_part() { findmnt -no SOURCE / | sed 's/\[.*//'; }

# The root on LVM: the PV's partition grows to the end of the disk, the volumes go into the
# root's VG beside it. The root LV keeps its size (XFS does not shrink).
prepare_lvm() {
    local root=$1 pv dev disk num want i fe name mp pct opts
    VG=$(lvs --noheadings -o vg_name "$root" 2>/dev/null | tr -d ' ')
    [ -n "$VG" ] || fail "no volume group for $root"
    pv=$(pvs --noheadings -o pv_name --select "vg_name=$VG" 2>/dev/null | head -n 1 | tr -d ' ')
    dev=$(basename "$(readlink -f "$pv")")
    disk=/dev/$(lsblk -dno PKNAME "/dev/$dev")
    num=$(cat "/sys/class/block/$dev/partition")
    say "found: root $root in VG $VG on $pv, disk $disk $(( $(cat "/sys/block/$(basename "$disk")/size") / 2048 ))M"
    # The studio grows the disk by the volumes' space once the first boot is done with it.
    want=$(( $(cat "/sys/class/block/$dev/start") + $(cat "/sys/class/block/$dev/size") + 8 * 1024 * 1024 * 2 ))
    for i in $(seq 1 15); do
        echo 1 > "/sys/block/$(basename "$disk")/device/rescan" 2>/dev/null
        [ "$(cat "/sys/block/$(basename "$disk")/size")" -ge "$want" ] && break
        sleep 2
    done
    [ "$(cat "/sys/block/$(basename "$disk")/size")" -ge "$want" ] || fail "the disk did not grow (the studio grows it once the first boot is done)"
    sgdisk -e "$disk" >/dev/null 2>&1 || sfdisk --relocate gpt-bak-std "$disk" >/dev/null 2>&1
    growpart "$disk" "$num" >/dev/null 2>&1 || fail "growpart $disk $num"
    pvresize "$pv" >/dev/null || fail "pvresize $pv"
    fe=$(vgs --noheadings -o vg_free_count "$VG" | tr -d ' ')
    [ "${fe:-0}" -gt 0 ] || fail "no free space in $VG"
    while IFS=: read -r name mp pct opts; do
        lvcreate -y -n "$name" -l $(( fe * pct / 100 )) "$VG" >/dev/null || fail "lvcreate $name"
        mkfs.ext4 -q -L "$name" "/dev/$VG/$name" || fail "mkfs $name"
    done <<<"$LVS"
    echo "$VG" > "$STATE/layout.vg"
    touch "$STATE/layout.prepared"
    say "prepared: root LV kept, $pv grown -> VG $VG ($(vgs --noheadings -o vg_size "$VG" | tr -d ' '))"
}

prepare() {
    [ -e "$STATE/layout.prepared" ] && return 0
    mkdir -p "$STATE"
    command -v pvcreate >/dev/null || fail "lvm2 is not installed (the first boot installs it)"
    case $(root_part) in
        /dev/mapper/* | /dev/dm-*) prepare_lvm "$(root_part)"; return ;;
    esac
    local part disk num start sectors end_sector newpart want i
    part=$(root_part)
    disk=/dev/$(lsblk -dno PKNAME "$part")
    num=$(cat "/sys/class/block/$(basename "$part")/partition")
    say "found: root $part $(( $(cat "/sys/class/block/$(basename "$part")/size") / 2048 ))M on $disk $(( $(cat "/sys/block/$(basename "$disk")/size") / 2048 ))M"
    # The bake VM started with a disk of ROOT_GB: some images grow the root to the whole disk
    # before cloud-init (Debian: growroot in the initramfs, then x-systemd.growfs), and a
    # mounted ext4 does not shrink. The studio grew the disk during the first boot.
    want=$(( (ROOT_GB + 8) * 1024 * 1024 * 1024 / 512 ))
    for i in $(seq 1 15); do
        echo 1 > "/sys/block/$(basename "$disk")/device/rescan" 2>/dev/null
        [ "$(cat "/sys/block/$(basename "$disk")/size")" -ge "$want" ] && break
        sleep 2
    done
    [ "$(cat "/sys/block/$(basename "$disk")/size")" -ge "$want" ] || fail "the disk did not grow beyond ${ROOT_GB}G (the studio grows it once the guest agent answers)"
    # The backup GPT header to the end of the (grown) disk.
    sgdisk -e "$disk" >/dev/null 2>&1 || sfdisk --relocate gpt-bak-std "$disk" >/dev/null 2>&1
    start=$(cat "/sys/class/block/$(basename "$part")/start")
    sectors=$(( ROOT_GB * 1024 * 1024 * 1024 / 512 ))
    # Root keeps its start and gets ROOT_GB - the cloud image's root is the last partition.
    if [ "$(cat "/sys/class/block/$(basename "$part")/size")" -lt "$sectors" ]; then
        echo ",$sectors" | sfdisk --no-reread --no-tell-kernel -N "$num" "$disk" >/dev/null 2>&1 || fail "could not resize the root partition"
        resizepart "$disk" "$num" "$sectors" || partx -u -n "$num" "$disk" || fail "the kernel did not take the new root size"
        # Enterprise Linux: XFS, grown mounted.
        case $(findmnt -no FSTYPE /) in
            xfs) xfs_growfs / >/dev/null 2>&1 || fail "xfs_growfs /" ;;
            *) resize2fs "$part" >/dev/null 2>&1 || fail "resize2fs $part" ;;
        esac
    fi
    # After the root as it is - it may be larger than ROOT_GB already.
    end_sector=$(( start + $(cat "/sys/class/block/$(basename "$part")/size") ))
    [ "$end_sector" -ge $(( start + sectors )) ] || end_sector=$(( start + sectors ))
    # The rest of the disk: one LVM partition.
    local err
    err=$(echo "$end_sector,,E6D6D379-F507-44C2-A23C-238F2A3DF928" | sfdisk --no-reread --no-tell-kernel --append "$disk" 2>&1 >/dev/null) \
        || fail "could not create the LVM partition at sector $end_sector: $(tr '\n' ' ' <<<"$err" | cut -c1-300)"
    partx -a "$disk" >/dev/null 2>&1
    udevadm settle
    newpart=$(lsblk -lnpo NAME,TYPE "$disk" | awk '$2 == "part" { print $1 }' | while read -r p; do
        [ "$(cat "/sys/class/block/$(basename "$p")/start")" -ge "$end_sector" ] && echo "$p"; done | head -n 1)
    [ -n "$newpart" ] || fail "the new partition did not appear"
    pvcreate -ff -y "$newpart" >/dev/null || fail "pvcreate $newpart"
    vgcreate "$VG" "$newpart" >/dev/null || fail "vgcreate"
    local name mp pct opts
    while IFS=: read -r name mp pct opts; do
        lvcreate -y -n "$name" -l "${pct}%VG" "$VG" >/dev/null || fail "lvcreate $name"
        mkfs.ext4 -q -L "$name" "/dev/$VG/$name" || fail "mkfs $name"
    done <<<"$LVS"
    echo "$VG" > "$STATE/layout.vg"
    touch "$STATE/layout.prepared"
    say "prepared: root ${ROOT_GB}G, $newpart -> VG $VG ($(vgs --noheadings -o vg_size "$VG" | tr -d ' '))"
}

# One directory's content to its LV: the nested mount points stay behind as empty
# directories with their modes.
copy_into() {
    local src=$1 dst=$2
    shift 2
    local ex=() d
    for d in "$@"; do ex+=(--exclude="./$d"); done
    tar -C "$src" --one-file-system --xattrs --xattrs-include='*' --acls --numeric-owner "${ex[@]}" -cpf - . \
        | tar -C "$dst" --xattrs --xattrs-include='*' --acls --numeric-owner -xpf - || return 1
    for d in "$@"; do
        mkdir -p "$dst/$d"
        chmod "$(stat -c %a "$src/$d")" "$dst/$d"
        chown "$(stat -c %u:%g "$src/$d")" "$dst/$d"
    done
}

migrate() {
    [ -e "$STATE/layout.done" ] && return 0
    [ -e "$STATE/layout.wanted" ] || return 0
    # Never in the first boot, whatever started the unit: its filesystems are mounted and busy.
    [ "$(cat /proc/sys/kernel/random/boot_id)" = "$(cat "$STATE/boot1.id" 2>/dev/null)" ] && return 0
    prepare
    vgchange -ay "$VG" >/dev/null 2>&1
    udevadm settle
    local name mp pct opts t
    # Deepest first: /var/log/audit, /var/log, /var/tmp, then /var and /home.
    while IFS=: read -r name mp pct opts; do
        t=/run/pvs-layout/$name
        mkdir -p "$t"
        mount "/dev/$VG/$name" "$t" || fail "mount $name"
        case $name in
            var) copy_into /var "$t" log tmp ;;
            varlog) copy_into /var/log "$t" audit ;;
            *) copy_into "$mp" "$t" ;;
        esac || fail "copying $mp"
        umount "$t"
    done <<<"$LVS"
    # Copied: the old content goes (nothing has opened it yet this early), then the mounts.
    while IFS=: read -r name mp pct opts; do
        case $name in
            var) find /var -mindepth 1 -maxdepth 1 ! -name log ! -name tmp -exec rm -rf {} + ;;
            varlog) find /var/log -mindepth 1 -maxdepth 1 ! -name audit -exec rm -rf {} + ;;
            *) find "$mp" -mindepth 1 -maxdepth 1 -exec rm -rf {} + ;;
        esac
    done <<<"$LVS"
    # fstab parent first (/var before /var/log before /var/log/audit): systemd orders mounts
    # itself, but mount -a and findmnt --verify read the file top to bottom.
    while IFS=: read -r name mp pct opts; do
        grep -qE "^[^#]*[[:space:]]${mp}[[:space:]]" /etc/fstab || printf '/dev/%s/%s\t%s\text4\tdefaults,%s\t0\t2\n' "$VG" "$name" "$mp" "$opts" >> /etc/fstab
    done < <(printf '%s\n' "$LVS" | sort -t: -k2,2)
    for mp in /var /var/log /var/log/audit /var/tmp /home; do
        mount "$mp" || fail "mount $mp"
    done
    # SELinux: the content kept its labels (tar --xattrs); a new filesystem's top directory
    # has none of its mount point's.
    if command -v restorecon >/dev/null 2>&1 && selinuxenabled 2>/dev/null; then
        restorecon /var /var/log /var/log/audit /var/tmp /home
    fi
    touch "$STATE/layout.done"
    say "migrated: $(findmnt -rno TARGET,SOURCE | grep "/dev/mapper/$VG-" | tr '\n' ' ')"
}

grow() {
    [ -e "$STATE/layout.done" ] || return 0
    local pv disk num
    pv=$(pvs --noheadings -o pv_name --select "vg_name=$VG" 2>/dev/null | head -n 1 | tr -d ' ')
    [ -n "$pv" ] || return 0
    disk=/dev/$(lsblk -dno PKNAME "$pv")
    num=$(cat "/sys/class/block/$(basename "$(readlink -f "$pv")")/partition")
    if growpart "$disk" "$num" >/dev/null 2>&1; then
        pvresize "$pv" >/dev/null
        lvextend -r -l +100%FREE "$VG/var" >/dev/null 2>&1
        echo "pvs-cis layout: grew $pv, /var is $(df -h --output=size /var | tail -n 1 | tr -d ' ')"
    fi
}

case ${1:-} in
    migrate) migrate ;;
    grow) grow ;;
    *) sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'; exit 2 ;;
esac
