# CIS AlmaLinux/Oracle/Rocky Linux 9 v3.0.0 and 10 v1.0.0 - chapter 7: system maintenance.
# Builds on deb/7-maintenance.sh (sourced first): passwd/group/shells/opasswd modes, the
# filesystem scans and the account checks are the same on Enterprise Linux and stay there.
#
# Decisions
# - shadow, shadow-, gshadow, gshadow-: EL wants mode 0000 root:root (its default; there is
#   no shadow group). A missing backup file passes, as in deb.
# - SUID/SGID review: owning package and integrity from rpm (rpm -qf / rpm -V) instead of dpkg.

e7_shadow_check() {
    if [ ! -e "$1" ]; then
        ev "$1: missing (ok)"
        [ "${2:-}" = required ] && return 1
        return 0
    fi
    perm_ok "$1" 0000 root root
}
e7_shadow_fix() {
    [ -e "$1" ] || return 0
    chown root:root "$1" && chmod 0000 "$1"
}

rule etc-shadow-640-root-shadow "/etc/shadow 000 root:root"
check_etc_shadow_640_root_shadow() { e7_shadow_check /etc/shadow required; }
fix_etc_shadow_640_root_shadow()   { e7_shadow_fix /etc/shadow; }

rule etc-shadow-bak-640-root-shadow "/etc/shadow- 000 root:root"
check_etc_shadow_bak_640_root_shadow() { e7_shadow_check /etc/shadow-; }
fix_etc_shadow_bak_640_root_shadow()   { e7_shadow_fix /etc/shadow-; }

rule etc-gshadow-present-640-root-shadow "/etc/gshadow present, 000 root:root"
check_etc_gshadow_present_640_root_shadow() { e7_shadow_check /etc/gshadow required; }
fix_etc_gshadow_present_640_root_shadow() {
    [ -e /etc/gshadow ] || grpconv || return 1
    e7_shadow_fix /etc/gshadow
}

rule etc-gshadow-bak-640-root-shadow "/etc/gshadow- 000 root:root"
check_etc_gshadow_bak_640_root_shadow() { e7_shadow_check /etc/gshadow-; }
fix_etc_gshadow_bak_640_root_shadow()   { e7_shadow_fix /etc/gshadow-; }

# The package that ships PATH, "" when none.
c7_pkg_of() {
    local o
    o=$(rpm -qf --qf '%{NAME}\n' -- "$1" 2>/dev/null) || return 0
    head -n 1 <<<"$o"
}

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
            if [ -z "$pkg" ]; then
                odd+="NOT-PACKAGED $flag $p"$'\n'
                pkg=-
            else
                pkgs+="$pkg"$'\n'
            fi
            list+="$flag $p ($pkg)"$'\n'
        done < <(find "$m" -xdev -type f \( -perm -2000 -o -perm -4000 \) -print0 2>/dev/null)
    done < <(c7_mounts suid | sort -u)
    # Package files whose digest differs from the package's ("5" in rpm -V's flags).
    if [ -n "$pkgs" ]; then
        bad=$(sort -u <<<"$pkgs" | grep . | xargs -r rpm -V 2>/dev/null | awk '$1 ~ /5/ { print $NF }')
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
