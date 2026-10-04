# suse/7-maintenance.sh - openSUSE Leap 16.0 (CIS SLE 16): what differs from deb/ and el/. Sourced after both.
#
# Decisions
# - shadow, shadow-, gshadow, gshadow-: back to deb's rule (0640 at most, root, group root or
#   shadow) over el's 0000 root:root - SUSE ships shadow 0640 root:shadow and unix_chkpwd
#   reads it through the shadow group. A missing backup file passes; gshadow is created with
#   grpconv when the image has none.
# - Group passwords (7.2.10): none may sit in /etc/group; the fix removes them (gpasswd -r) -
#   a fresh image has none. HOME_MODE (7.2.8) goes through kv_set, which copies the vendor
#   /usr/etc/login.defs to /etc first.

# /etc/gshadow without grpconv (Leap's minimal image has none): one "name:!::members" line per
# group, from /etc/group - what grpconv writes for groups without a password.
s7_gshadow() {
    [ -e /etc/gshadow ] && return 0
    if command -v grpconv >/dev/null 2>&1; then grpconv && return 0; fi
    (umask 0137; awk -F: '{ print $1 ":!::" $4 }' /etc/group > /etc/gshadow.pvs) || return 1
    chown root:shadow /etc/gshadow.pvs 2>/dev/null || chown root:root /etc/gshadow.pvs
    chmod 0640 /etc/gshadow.pvs
    mv -f /etc/gshadow.pvs /etc/gshadow
    command -v restorecon >/dev/null 2>&1 && restorecon /etc/gshadow
    return 0
}

rule etc-shadow-640-root-shadow "/etc/shadow 640 root:shadow"
check_etc_shadow_640_root_shadow() { perm_ok /etc/shadow 0640 root "root|shadow"; }
fix_etc_shadow_640_root_shadow()   { c7_shadow_fix /etc/shadow; }

rule etc-shadow-bak-640-root-shadow "/etc/shadow- 640 root:shadow"
check_etc_shadow_bak_640_root_shadow() { c7_perm_opt /etc/shadow- 0640 root "root|shadow"; }
fix_etc_shadow_bak_640_root_shadow()   { c7_shadow_fix /etc/shadow-; }

rule etc-gshadow-present-640-root-shadow "/etc/gshadow present, 640 root:shadow"
check_etc_gshadow_present_640_root_shadow() { perm_ok /etc/gshadow 0640 root "root|shadow"; }
fix_etc_gshadow_present_640_root_shadow() {
    s7_gshadow || return 1
    c7_shadow_fix /etc/gshadow
}

rule etc-gshadow-bak-640-root-shadow "/etc/gshadow- 640 root:shadow"
check_etc_gshadow_bak_640_root_shadow() { c7_perm_opt /etc/gshadow- 0640 root "root|shadow"; }
fix_etc_gshadow_bak_640_root_shadow()   { c7_shadow_fix /etc/gshadow-; }

# Groups whose /etc/group password field is neither x, ! nor empty.
s7_group_pw() { awk -F: '$2 != "x" && $2 != "!" && $2 != "" { print $1 }' /etc/group; }

rule no-group-passwords "No group passwords in /etc/group"
check_no_group_passwords() {
    local g
    g=$(s7_group_pw | xargs)
    if [ -z "$g" ]; then ev "/etc/group: no password fields"; return 0; fi
    ev "/etc/group password field set: $g"
    return 1
}
fix_no_group_passwords() {
    local g rc=0
    s7_gshadow || return 1
    if command -v gpasswd >/dev/null 2>&1; then
        for g in $(s7_group_pw); do
            gpasswd -r "$g" >/dev/null || rc=1
        done
    elif [ -n "$(s7_group_pw)" ]; then
        # No gpasswd (Leap minimal): the password field becomes "x" - the password, if any,
        # lives in /etc/gshadow (s7_gshadow above gave every group "!" there).
        awk -F: 'BEGIN { OFS = ":" } $2 != "x" && $2 != "" { $2 = "x" } { print }' /etc/group > /etc/group.pvs \
            && cat /etc/group.pvs > /etc/group && rm -f /etc/group.pvs || rc=1
    fi
    [ -z "$(s7_group_pw)" ] || rc=1
    return $rc
}
