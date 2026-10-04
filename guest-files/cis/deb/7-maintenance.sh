# CIS Ubuntu 26.04 - chapter 7: system maintenance (file permissions, local users/groups).
#
# Decisions
# - Backup files (passwd-, group-, shadow-, gshadow-) and opasswd(.old): a missing file
#   passes (nothing to protect); the evidence says "missing".
# - shadow/gshadow files keep group "shadow" (Ubuntu default) when it is root or shadow;
#   anything else is set to root:shadow.
# - Filesystem scans (7.1.11-7.1.13) walk each local mount once with find -xdev. Skipped:
#   pseudo filesystems (findmnt --df), nfs/cifs/smb/fuse/network types, vfat/iso9660
#   (seed disk), squashfs (snaps), /run, /tmp, /var/tmp, /sys, /snap, /boot/efi and
#   container storage - the benchmark's own exclusions plus squashfs/network types.
# - 7.1.11 fix: o-w on world-writable files, +t on world-writable dirs. What it changed is
#   kept in /var/lib/pvs-cis/7.1.11.fixed and shown in the check's evidence.
# - 7.1.12 fix: files with no owner/group get root (user and/or group); list kept in
#   /var/lib/pvs-cis/7.1.12.fixed and shown by the check. Deviation: CIS leaves the choice
#   to the admin; root is the safe owner on a fresh image.
# - 7.1.13 (manual): check lists SUID/SGID files with their dpkg package and flags files
#   that no package owns or whose md5 differs from the package; returns 3 (review).
# - 7.2.3, 7.2.5-7.2.8 (duplicates, missing groups): check only, no fix - fixing needs a
#   human decision; a fresh cloud image has none.
# - 7.2.4 fix: empties the shadow group's member list (group and gshadow); a user whose
#   primary group is shadow is moved to its own same-named group, else the fix fails.
# - 7.2.9 fix: owner and g-w,o-rwx on existing homes; a missing home is NOT created (fails).
#   It also sets HOME_MODE 0750 in login.defs so the clone's admin (created by cloud-init
#   later, not present at bake time) gets a compliant home.
# - 7.2.10: .forward/.rhosts are never deleted by the fix (fix fails and lists them).
#   Dot files are searched recursively in each home, as the benchmark does.
# - Interactive users = shell listed in /etc/shells and not *nologin (root included).
# - Bake: remove the `bake` user WITH its home (userdel -r) before the check, or
#   7.1.12 (unowned files) and 7.2.x will report /home/bake.

C7_STATE=/var/lib/pvs-cis

# ---- chapter helpers ----

# Perm check where a missing file passes.
c7_perm_opt() {
    if [ ! -e "$1" ]; then ev "$1: missing (ok)"; return 0; fi
    perm_ok "$@"
}

# The group a shadow-type file should get: keep root or shadow, prefer shadow.
c7_shadow_grp() {
    if getent group shadow >/dev/null 2>&1; then echo "shadow|root"; else echo "root"; fi
}

# Fix for a shadow-type file: mode 0640 max, owner root, group root or shadow.
c7_shadow_fix() {
    local f=$1 g
    [ -e "$f" ] || return 0
    g=$(stat -Lc '%G' "$f")
    if [ "$g" = root ] || [ "$g" = shadow ]; then
        chmod u-x,g-wx,o-rwx "$f" && chown root "$f"
    else
        perm_set "$f" 0640 root "$(c7_shadow_grp)"
    fi
}

# Local mount points to scan, one per line. MODE=suid also drops nosuid/noexec mounts.
c7_mounts() {
    local mode=${1:-} fst tgt opts
    findmnt -Dkrn -o FSTYPE,TARGET,OPTIONS 2>/dev/null | while read -r fst tgt opts; do
        case $fst in
            nfs*|proc|cifs|smb*|vfat|iso9660|efivarfs|selinuxfs|ncpfs|squashfs|fuse*|9p|ceph|glusterfs|afs|autofs|udf) continue ;;
        esac
        tgt=$(printf '%b' "$tgt")
        if [ "$mode" = suid ]; then
            case $tgt in /run/user/*) continue ;; esac
            [[ ",$opts," == *,nosuid,* || ",$opts," == *,noexec,* ]] && continue
        else
            case $tgt in /run|/run/*|/tmp|/tmp/*|/var/tmp|/var/tmp/*) continue ;; esac
        fi
        printf '%s\n' "$tgt"
    done
}

C7_PRUNE=(-path "*/containers/storage/*" -o -path "*/containerd/*" -o -path "*/kubelet/*"
    -o -path "/sys/*" -o -path "/snap/*" -o -path "/boot/efi/*")

# Prints the first N lines of stdin, then a count of the rest.
c7_cap() {
    local n=${1:-25}
    awk -v n="$n" 'NR <= n { print } END { if (NR > n) print "... and " NR - n " more" }'
}

# Shows what a fix recorded in the state file (may be absent).
c7_fixed_ev() {
    local f="$C7_STATE/$1.fixed" c
    [ -s "$f" ] || return 0
    c=$(wc -l < "$f")
    ev "changed by the bake fix ($c): $f"
    c7_cap 10 < "$f"
}

# "user:home" of every local interactive user.
c7_users() {
    awk -F: 'NR == FNR { if ($0 ~ /^\// && $0 !~ /nologin$/) sh[$0] = 1; next }
             ($7 in sh) && $1 != "" && $6 != "" { print $1 ":" $6 }' /etc/shells /etc/passwd
}

# 0 when HOME lives on a network filesystem (out of scope).
c7_remote_home() {
    case $(findmnt -no FSTYPE --target "$1" 2>/dev/null) in
        nfs|nfs4|cifs|smbfs|smb3|fuse.sshfs|afs|ncpfs|glusterfs|ceph) return 0 ;;
    esac
    return 1
}

# ---- 7.1 system file permissions ----

rule etc-passwd-644-root-root "/etc/passwd 644 root:root"
check_etc_passwd_644_root_root() { perm_ok /etc/passwd 0644 root root; }
fix_etc_passwd_644_root_root()   { perm_set /etc/passwd 0644 root root; }

rule etc-passwd-bak-644-root-root "/etc/passwd- 644 root:root"
check_etc_passwd_bak_644_root_root() { c7_perm_opt /etc/passwd- 0644 root root; }
fix_etc_passwd_bak_644_root_root()   { perm_set /etc/passwd- 0644 root root; }

rule etc-group-644-root-root "/etc/group 644 root:root"
check_etc_group_644_root_root() { perm_ok /etc/group 0644 root root; }
fix_etc_group_644_root_root()   { perm_set /etc/group 0644 root root; }

rule etc-group-bak-644-root-root "/etc/group- 644 root:root"
check_etc_group_bak_644_root_root() { c7_perm_opt /etc/group- 0644 root root; }
fix_etc_group_bak_644_root_root()   { perm_set /etc/group- 0644 root root; }

rule etc-shadow-640-root-shadow "/etc/shadow 640 root:shadow"
check_etc_shadow_640_root_shadow() { perm_ok /etc/shadow 0640 root "root|shadow"; }
fix_etc_shadow_640_root_shadow()   { c7_shadow_fix /etc/shadow; }

rule etc-shadow-bak-640-root-shadow "/etc/shadow- 640 root:shadow"
check_etc_shadow_bak_640_root_shadow() { c7_perm_opt /etc/shadow- 0640 root "root|shadow"; }
fix_etc_shadow_bak_640_root_shadow()   { c7_shadow_fix /etc/shadow-; }

rule etc-gshadow-present-640-root-shadow "/etc/gshadow present, 640 root:shadow"
check_etc_gshadow_present_640_root_shadow() { perm_ok /etc/gshadow 0640 root "root|shadow"; }
fix_etc_gshadow_present_640_root_shadow() {
    [ -e /etc/gshadow ] || grpconv || return 1
    c7_shadow_fix /etc/gshadow
}

rule etc-gshadow-bak-640-root-shadow "/etc/gshadow- 640 root:shadow"
check_etc_gshadow_bak_640_root_shadow() { c7_perm_opt /etc/gshadow- 0640 root "root|shadow"; }
fix_etc_gshadow_bak_640_root_shadow()   { c7_shadow_fix /etc/gshadow-; }

rule etc-shells-644-root-root "/etc/shells 644 root:root"
check_etc_shells_644_root_root() { perm_ok /etc/shells 0644 root root; }
fix_etc_shells_644_root_root()   { perm_set /etc/shells 0644 root root; }

rule opasswd-files-600-root-root "opasswd files 600 root:root"
check_opasswd_files_600_root_root() {
    local rc=0
    c7_perm_opt /etc/security/opasswd 0600 root root || rc=1
    c7_perm_opt /etc/security/opasswd.old 0600 root root || rc=1
    return $rc
}
fix_opasswd_files_600_root_root() {
    perm_set /etc/security/opasswd 0600 root root
    perm_set /etc/security/opasswd.old 0600 root root
    return 0
}

# World-writable files, and world-writable dirs without the sticky bit: "f path" / "d path".
c7_ww_scan() {
    local m p mode
    while IFS= read -r m; do
        [ -d "$m" ] || continue
        while IFS= read -r -d '' p; do
            if [ -f "$p" ] && [ ! -L "$p" ]; then
                printf 'f %s\n' "$p"
            elif [ -d "$p" ] && [ ! -L "$p" ]; then
                mode=$(stat -c '%a' "$p" 2>/dev/null) || continue
                (( 8#$mode & 01000 )) || printf 'd %s\n' "$p"
            fi
        done < <(find "$m" -xdev \( "${C7_PRUNE[@]}" \) -prune -o \( -type f -o -type d \) -perm -0002 -print0 2>/dev/null)
    done < <(c7_mounts)
}

rule no-world-writable-files-sticky-world-writable-di "No world-writable files; sticky world-writable dirs"
check_no_world_writable_files_sticky_world_writable_di() {
    local out nf nd
    out=$(c7_ww_scan | sort -u)
    nf=$(grep -c '^f ' <<<"$out")
    nd=$(grep -c '^d ' <<<"$out")
    ev "world-writable files: $nf, world-writable dirs without sticky bit: $nd"
    [ -n "$out" ] && c7_cap 25 <<<"$out"
    c7_fixed_ev 7.1.11
    [ "$nf" -eq 0 ] && [ "$nd" -eq 0 ]
}
fix_no_world_writable_files_sticky_world_writable_di() {
    local t p rc=0
    mkdir -p "$C7_STATE"
    while read -r t p; do
        [ -n "$p" ] || continue
        if [ "$t" = f ]; then
            chmod o-w "$p" && printf 'o-w %s\n' "$p" >> "$C7_STATE/7.1.11.fixed" || rc=1
        else
            chmod a+t "$p" && printf '+t %s\n' "$p" >> "$C7_STATE/7.1.11.fixed" || rc=1
        fi
    done < <(c7_ww_scan | sort -u)
    return $rc
}

# Files/dirs with no owner and/or no group: "<U|G|UG> path".
c7_unowned_scan() {
    local m p u g t
    while IFS= read -r m; do
        [ -d "$m" ] || continue
        while IFS= read -r -d '' p; do
            read -r u g < <(stat -c '%U %G' "$p" 2>/dev/null) || continue
            t=""
            [ "$u" = UNKNOWN ] && t=U
            [ "$g" = UNKNOWN ] && t="${t}G"
            [ -n "$t" ] && printf '%s %s\n' "$t" "$p"
        done < <(find "$m" -xdev \( "${C7_PRUNE[@]}" \) -prune -o \( -type f -o -type d \) \( -nouser -o -nogroup \) -print0 2>/dev/null)
    done < <(c7_mounts)
}

rule no-files-without-an-owner-or-group "No files without an owner or group"
check_no_files_without_an_owner_or_group() {
    local out nu ng
    out=$(c7_unowned_scan | sort -u)
    nu=$(grep -c '^U' <<<"$out")
    ng=$(grep -c '^U\{0,1\}G ' <<<"$out")
    ev "no owner: $nu, no group: $ng"
    [ -n "$out" ] && c7_cap 25 <<<"$out"
    c7_fixed_ev 7.1.12
    [ "$nu" -eq 0 ] && [ "$ng" -eq 0 ]
}
fix_no_files_without_an_owner_or_group() {
    local t="" p rc=0
    mkdir -p "$C7_STATE"
    while read -r t p; do
        [ -n "$p" ] || continue
        case $t in
            UG) chown -h root:root "$p" || rc=1 ;;
            U) chown -h root "$p" || rc=1 ;;
            G) chgrp -h root "$p" || rc=1 ;;
        esac
        printf '%s->root %s\n' "$t" "$p" >> "$C7_STATE/7.1.12.fixed"
    done < <(c7_unowned_scan | sort -u)
    return $rc
}

# The (first) package that ships PATH, "" when none.
c7_pkg_of() {
    dpkg -S "$1" 2>/dev/null | grep -v '^diversion' | head -n 1 | sed -E 's/: .*//; s/,.*//; s/:[a-z0-9_]+$//'
}

rule suid-sgid-files-reviewed "SUID/SGID files reviewed"
check_suid_sgid_files_reviewed() {
    local m p mode list="" ns=0 ng=0 pkg flag odd="" pkgs="" bad
    while IFS= read -r m; do
        [ -d "$m" ] || continue
        while IFS= read -r -d '' p; do
            mode=$(stat -c '%a' "$p" 2>/dev/null) || continue
            flag=""
            (( 8#$mode & 04000 )) && { flag=u; ns=$((ns + 1)); }
            (( 8#$mode & 02000 )) && { flag="${flag}g"; ng=$((ng + 1)); }
            [ -n "$flag" ] || continue
            pkg=$(c7_pkg_of "$p")
            [ -n "$pkg" ] || pkg=$(c7_pkg_of "${p#/usr}")
            if [ -z "$pkg" ]; then
                odd+="NOT-PACKAGED $flag $p"$'\n'
                pkg=-
            else
                pkgs+="$pkg"$'\n'
            fi
            list+="$flag $p ($pkg)"$'\n'
        done < <(find "$m" -xdev -type f \( -perm -2000 -o -perm -4000 \) -print0 2>/dev/null)
    done < <(c7_mounts suid | sort -u)
    # Package files whose checksum differs from the package's.
    if [ -n "$pkgs" ]; then
        bad=$(sort -u <<<"$pkgs" | grep . | xargs -r dpkg -V 2>/dev/null | awk '$1 ~ /5/ { print $NF }')
        while IFS= read -r p; do
            [ -n "$p" ] || continue
            grep -qF " $p (" <<<"$list" && odd+="MODIFIED $p"$'\n'
        done <<<"$bad"
    fi
    ev "suid: $ns, sgid: $ng"
    [ -n "$odd" ] && printf '%s' "$odd"
    printf '%s' "$list" | c7_cap 30
    ev "decision: listed for review; flagged entries need a look"
    return 3
}

# ---- 7.2 local users and groups ----

rule all-accounts-use-shadowed-passwords "All accounts use shadowed passwords"
check_all_accounts_use_shadowed_passwords() {
    local out
    out=$(awk -F: '$2 != "x" { print "not shadowed: " $1 }' /etc/passwd)
    [ -z "$out" ] && { ev "all /etc/passwd entries: x"; return 0; }
    printf '%s\n' "$out"
    return 1
}
fix_all_accounts_use_shadowed_passwords() { pwconv; }

rule no-empty-password-fields-in-shadow "No empty password fields in shadow"
check_no_empty_password_fields_in_shadow() {
    local out
    out=$(awk -F: '$2 == "" { print "empty password: " $1 }' /etc/shadow)
    [ -z "$out" ] && { ev "no empty password fields"; return 0; }
    printf '%s\n' "$out"
    return 1
}
fix_no_empty_password_fields_in_shadow() {
    local u rc=0
    for u in $(awk -F: '$2 == "" { print $1 }' /etc/shadow); do
        passwd -l "$u" >/dev/null || rc=1
    done
    return $rc
}

rule primary-groups-of-all-users-exist "Primary groups of all users exist"
check_primary_groups_of_all_users_exist() {
    local out
    out=$(awk -F: 'NR == FNR { g[$3] = 1; next } !($4 in g) { print "user " $1 ": gid " $4 " not in /etc/group" }' /etc/group /etc/passwd)
    [ -z "$out" ] && { ev "all primary GIDs exist"; return 0; }
    printf '%s\n' "$out"
    return 1
}

rule shadow-group-has-no-members "shadow group has no members"
check_shadow_group_has_no_members() {
    local mem gid users rc=0
    mem=$(awk -F: '$1 == "shadow" { print $4 }' /etc/group)
    gid=$(getent group shadow | cut -d: -f3)
    ev "shadow members: ${mem:-none}"
    [ -z "$mem" ] || rc=1
    if [ -n "$gid" ]; then
        users=$(awk -F: -v g="$gid" '$4 == g { print $1 }' /etc/passwd | xargs)
        ev "primary group shadow: ${users:-none}"
        [ -z "$users" ] || rc=1
    fi
    return $rc
}
fix_shadow_group_has_no_members() {
    local gid u rc=0
    sed -ri 's/^(shadow:[^:]*:[^:]*:)[^:]+$/\1/' /etc/group
    [ -f /etc/gshadow ] && sed -ri 's/^(shadow:[^:]*:[^:]*:)[^:]+$/\1/' /etc/gshadow
    gid=$(getent group shadow | cut -d: -f3)
    [ -n "$gid" ] || return 0
    for u in $(awk -F: -v g="$gid" '$4 == g { print $1 }' /etc/passwd); do
        if getent group "$u" >/dev/null 2>&1; then
            usermod -g "$u" "$u" || rc=1
        else
            echo "user $u: primary group shadow, no group of its own"
            rc=1
        fi
    done
    return $rc
}

rule no-duplicate-uids "No duplicate UIDs"
check_no_duplicate_uids() {
    local out
    out=$(awk -F: '{ n[$3]++; u[$3] = u[$3] " " $1 } END { for (i in n) if (n[i] > 1) print "uid " i ":" u[i] }' /etc/passwd)
    [ -z "$out" ] && { ev "no duplicate UIDs"; return 0; }
    printf '%s\n' "$out"
    return 1
}

rule no-duplicate-gids "No duplicate GIDs"
check_no_duplicate_gids() {
    local out
    out=$(awk -F: '{ n[$3]++; u[$3] = u[$3] " " $1 } END { for (i in n) if (n[i] > 1) print "gid " i ":" u[i] }' /etc/group)
    [ -z "$out" ] && { ev "no duplicate GIDs"; return 0; }
    printf '%s\n' "$out"
    return 1
}

rule no-duplicate-user-names "No duplicate user names"
check_no_duplicate_user_names() {
    local out
    out=$(cut -d: -f1 /etc/passwd | sort | uniq -d | sed 's/^/duplicate user: /')
    [ -z "$out" ] && { ev "no duplicate user names"; return 0; }
    printf '%s\n' "$out"
    return 1
}

rule no-duplicate-group-names "No duplicate group names"
check_no_duplicate_group_names() {
    local out
    out=$(cut -d: -f1 /etc/group | sort | uniq -d | sed 's/^/duplicate group: /')
    [ -z "$out" ] && { ev "no duplicate group names"; return 0; }
    printf '%s\n' "$out"
    return 1
}

rule interactive-homes-exist-owned-max-750 "Interactive homes exist, owned, max 750"
check_interactive_homes_exist_owned_max_750() {
    local u h own mode rc=0
    while IFS=: read -r u h; do
        [ -n "$u" ] || continue
        if [ ! -d "$h" ]; then
            ev "$u: home $h missing"; rc=1; continue
        fi
        read -r own mode < <(stat -Lc '%U %a' "$h")
        ev "$u: $h $mode $own"
        [ "$own" = "$u" ] || rc=1
        (( 8#$mode & 027 )) && rc=1
    done < <(c7_users)
    return $rc
}
fix_interactive_homes_exist_owned_max_750() {
    local u h own mode rc=0
    while IFS=: read -r u h; do
        [ -n "$u" ] || continue
        if [ ! -d "$h" ]; then echo "$u: home $h missing (not created)"; rc=1; continue; fi
        read -r own mode < <(stat -Lc '%U %a' "$h")
        [ "$own" = "$u" ] || chown "$u" "$h" || rc=1
        (( 8#$mode & 027 )) && { chmod g-w,o-rwx "$h" || rc=1; }
    done < <(c7_users)
    # Homes created later (the clone's admin by cloud-init) come out 0750.
    kv_set /etc/login.defs HOME_MODE 0750
    return $rc
}

# Dot files of one user's home that break the rule: prints "<problem> path".
# Called with FIX=1 it repairs mode/owner/group as it goes.
c7_dotfiles() {
    local u=$1 h=$2 grp f b mode own gown mask chg
    grp=$(id -gn "$u" 2>/dev/null)
    while IFS= read -r -d '' f; do
        read -r mode own gown < <(stat -Lc '%a %U %G' "$f" 2>/dev/null) || continue
        b=${f##*/}
        case $b in
            .forward|.rhosts) printf 'present %s\n' "$f"; continue ;;
            .netrc|.bash_history) mask=0177; chg=u-x,go-rwx ;;
            *) mask=0133; chg=u-x,go-wx ;;
        esac
        if (( 8#$mode & mask )); then
            printf 'mode %s %s\n' "$mode" "$f"
            [ "${FIX:-0}" = 1 ] && chmod "$chg" "$f"
        fi
        if [ "$own" != "$u" ]; then
            printf 'owner %s %s\n' "$own" "$f"
            [ "${FIX:-0}" = 1 ] && chown "$u" "$f"
        fi
        if [ -n "$grp" ] && [ "$gown" != "$grp" ]; then
            printf 'group %s %s\n' "$gown" "$f"
            [ "${FIX:-0}" = 1 ] && chgrp "$grp" "$f"
        fi
        [ "$b" = .netrc ] && printf 'netrc-present %s\n' "$f"
    done < <(find "$h" -xdev -type f -name '.*' -print0 2>/dev/null)
}

rule interactive-users-dot-files-locked-down "Interactive users' dot files locked down"
check_interactive_users_dot_files_locked_down() {
    local u h out all="" warn=""
    while IFS=: read -r u h; do
        [ -n "$u" ] && [ -d "$h" ] || continue
        if c7_remote_home "$h"; then ev "$u: $h on a network filesystem, skipped"; continue; fi
        out=$(c7_dotfiles "$u" "$h")
        warn+=$(grep '^netrc-present ' <<<"$out")$'\n'
        all+=$(grep -v '^netrc-present ' <<<"$out")$'\n'
    done < <(c7_users)
    all=$(grep . <<<"$all")
    warn=$(grep . <<<"$warn")
    [ -n "$warn" ] && printf 'warning: %s\n' "$warn"
    if [ -z "$all" ]; then ev "dot files of interactive users: ok"; return 0; fi
    c7_cap 25 <<<"$all"
    return 1
}
fix_interactive_users_dot_files_locked_down() {
    local u h out rc=0
    while IFS=: read -r u h; do
        [ -n "$u" ] && [ -d "$h" ] || continue
        c7_remote_home "$h" && continue
        out=$(FIX=1 c7_dotfiles "$u" "$h")
        if grep -q '^present ' <<<"$out"; then
            grep '^present ' <<<"$out"   # .forward/.rhosts: left for a human to delete
            rc=1
        fi
    done < <(c7_users)
    return $rc
}

# Dot directories of one user's home that break the rule (FIX=1 repairs).
c7_dotdirs() {
    local u=$1 h=$2 grp d mode own gown mask chg
    grp=$(id -gn "$u" 2>/dev/null)
    while IFS= read -r -d '' d; do
        read -r mode own gown < <(stat -Lc '%a %U %G' "$d" 2>/dev/null) || continue
        if [ "${d##*/}" = .ssh ]; then mask=0077; chg=g-rwx,o-rwx; else mask=0027; chg=g-w,o-rwx; fi
        if (( 8#$mode & mask )); then
            printf 'mode %s %s\n' "$mode" "$d"
            [ "${FIX:-0}" = 1 ] && chmod "$chg" "$d"
        fi
        if [ "$own" != "$u" ]; then
            printf 'owner %s %s\n' "$own" "$d"
            [ "${FIX:-0}" = 1 ] && chown "$u" "$d"
        fi
        if [ -n "$grp" ] && [ "$gown" != "$grp" ]; then
            printf 'group %s %s\n' "$gown" "$d"
            [ "${FIX:-0}" = 1 ] && chgrp "$grp" "$d"
        fi
    done < <(find "$h" -xdev -type d -name '.*' -print0 2>/dev/null)
}

rule interactive-users-dot-dirs-locked-down "Interactive users' dot dirs locked down"
check_interactive_users_dot_dirs_locked_down() {
    local u h all=""
    while IFS=: read -r u h; do
        [ -n "$u" ] && [ -d "$h" ] || continue
        if c7_remote_home "$h"; then ev "$u: $h on a network filesystem, skipped"; continue; fi
        all+=$(c7_dotdirs "$u" "$h")$'\n'
    done < <(c7_users)
    all=$(grep . <<<"$all")
    if [ -z "$all" ]; then ev "dot directories of interactive users: ok"; return 0; fi
    c7_cap 25 <<<"$all"
    return 1
}
fix_interactive_users_dot_dirs_locked_down() {
    local u h
    while IFS=: read -r u h; do
        [ -n "$u" ] && [ -d "$h" ] || continue
        c7_remote_home "$h" && continue
        FIX=1 c7_dotdirs "$u" "$h" >/dev/null
    done < <(c7_users)
    return 0
}
