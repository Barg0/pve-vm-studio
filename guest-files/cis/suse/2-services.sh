# shellcheck shell=bash
# suse/2-services.sh - openSUSE Leap 16.0 (CIS SLE 16 v1.0.0) chapter 2: what differs from
# deb/ and el/. Sourced after both: the functions here replace the dnf helper and the EL
# package names that do not exist on openSUSE (they would report "not installed" while the
# SUSE package is there).
#
# Decisions
# - c2_off_fix is redefined for zypper: `zypper remove --dry-run --no-clean-deps` first; if the
#   transaction would take a protected package (sshd, cloud-init, qemu-guest-agent, systemd,
#   NetworkManager, zypper/rpm, sudo, kernel/grub2, firewalld, chrony, cronie, audit, SELinux,
#   PAM, permissions, sssd/krb5, btrfs/xfs/lvm tools, ...), the removal is refused and the
#   units are stopped + masked instead. Patterns a removal drags along are not counted (zypper
#   never removes what they pulled in). No --clean-deps: nothing is autoremoved.
# - openSUSE package names: openldap2/openldap2_6 (slapd), nfs-kernel-server, rsync (ships
#   rsyncd.socket/.service itself), tftp/atftp (the TFTP server lives in "tftp"), apache2,
#   xwayland, openldap2(_6)-client, ypbind.
# - 2.1.13 rsync: rsync stays installed, rsyncd.socket and rsyncd.service are masked.
# - 2.3.1.1 chrony: Leap keeps chrony.conf in /usr/etc (chronyd reads /etc/chrony.conf when it
#   exists); the sources come in through `include` (/etc/chrony.d), confdir and sourcedir - all
#   followed. The image's servers are kept; only when there is none, the fix writes
#   /etc/chrony.d/60-pvs-cis.conf (when chrony.conf includes that directory, else a copy of the
#   vendor file in /etc gets the line): "server <s> iburst" per name in PVS_CIS_NTP, else
#   "pool 2.opensuse.pool.ntp.org iburst". OPTIONS in /etc/sysconfig/chronyd gets "-u chrony"
#   (chronyd.service passes $OPTIONS); the image's other options are kept. The fix installs
#   chrony when missing (it runs before 2.3.1.2's).
# - 2.4.1.x/2.4.2.1 cron and at: n/a while cronie / at are not installed (Leap's image has
#   neither; nothing here installs them). When present, every mode the fixes set is also
#   written to /etc/permissions.local (and "local" kept in PERMISSION_SECURITY), so chkstat
#   does not put the package modes back on the next zypper transaction. /etc/cron.yearly is
#   created 0700 (SLE has no "absent is fine").
# - 2.4.3.1-3 systemd units: timer/service files <= 0644 root:root, unit directories without
#   group/other write or s-bits, root:root. Never written under /usr: a vendor file or
#   directory there with other modes is reported and the fix fails (package bug, for review).
# - 2.4.3.4: no user but root with Linger (loginctl, plus /var/lib/systemd/linger for users
#   without a session); the fix disables it.

s2_PROTECT='(openssh|openssh-.*|cloud-init.*|cloud-utils.*|growpart|qemu-guest-agent|hyper-v|systemd|systemd-.*|udev|libudev.*|dbus-.*|NetworkManager.*|wicked.*|zypper|libzypp|rpm|rpm-.*|sudo|kernel-default.*|kernel-firmware.*|grub2.*|shim|dracut.*|firewalld.*|python3-firewall|chrony.*|cronie.*|cron|audit.*|libaudit.*|selinux-policy.*|policycoreutils.*|libselinux.*|pam|pam-.*|pam_.*|permissions.*|shadow|login_defs|sssd.*|krb5.*|crypto-policies.*|openssl.*|libopenssl.*|polkit.*|lvm2|xfsprogs|e2fsprogs|btrfsprogs|snapper.*|glibc.*|util-linux.*|bash|coreutils|aaa_base.*|filesystem)'

# The packages `zypper remove PKGS` would take (dependents included), one per line; nothing
# when zypper cannot plan it.
s2_zypper_sim() {
    LC_ALL=C zypper -n remove --dry-run --no-clean-deps "$@" 2>/dev/null \
        | awk '/^The following .*packages? (is|are) going to be REMOVED:/ { s = 1; next }
               s && /^[[:space:]]*$/ { s = 0; next }
               /^The following / { s = 0 }
               s { for (i = 1; i <= NF; i++) print $i }' \
        | sort -u
}

# zypper remove PKGS after a simulation: refused when a protected package would go with them.
s2_zypper_remove() {
    local rm bad
    rm=$(s2_zypper_sim "$@")
    if [ -z "$rm" ]; then
        echo "refused: zypper could not plan the removal of $*"
        return 1
    fi
    bad=$(grep -Ex "$s2_PROTECT" <<<"$rm" | xargs)
    if [ -n "$bad" ]; then
        echo "refused: zypper remove $* would remove $bad"
        return 1
    fi
    zypper -n -q remove --no-clean-deps "$@" >/dev/null
}

# Stop UNITS and remove the installed PKGS; when the removal is refused, mask UNITS instead.
c2_off_fix() {
    local pkgs=$1 units=${2:-} inst
    # shellcheck disable=SC2086
    inst=$(c2_installed $pkgs)
    [ -n "$inst" ] || return 0
    # shellcheck disable=SC2086
    [ -n "$units" ] && systemctl stop $units 2>/dev/null
    # shellcheck disable=SC2086
    s2_zypper_remove $inst && return 0
    [ -n "$units" ] || return 1
    # shellcheck disable=SC2086
    svc_off $units
}

# EL's dnf helper must never run here.
e2_dnf_remove() { echo "e2_dnf_remove: no dnf on openSUSE ($*)"; return 1; }

# ---- 2.1 server services (openSUSE names) ----

rule ldap-server-slapd-removed "LDAP server (openldap2) removed"
check_ldap_server_slapd_removed() { c2_off_check "openldap2 openldap2_6" slapd.service; }
fix_ldap_server_slapd_removed() { c2_off_fix "openldap2 openldap2_6" slapd.service; }

rule nfs-server-removed "NFS server removed"
check_nfs_server_removed() { c2_off_check nfs-kernel-server nfs-server.service; }
fix_nfs_server_removed() { c2_off_fix nfs-kernel-server nfs-server.service; }

rule rsync-daemon-masked "rsync daemon masked"
check_rsync_daemon_masked() { c2_off_check rsync "rsyncd.socket rsyncd.service"; }
fix_rsync_daemon_masked() {
    pkg_installed rsync || return 0
    svc_off rsyncd.socket rsyncd.service
}

s2_TFTP_PKGS="tftp-server tftp atftp"
s2_TFTP_UNITS="tftp.socket tftp.service atftpd.socket atftpd.service"

rule tftp-server-removed "TFTP server (tftp, atftp) removed"
check_tftp_server_removed() { c2_off_check "$s2_TFTP_PKGS" "$s2_TFTP_UNITS"; }
fix_tftp_server_removed() { c2_off_fix "$s2_TFTP_PKGS" "$s2_TFTP_UNITS"; }

rule web-servers-apache2-nginx-removed "web servers (apache2, nginx) removed"
check_web_servers_apache2_nginx_removed() {
    local bad=0
    c2_off_check apache2 apache2.service || bad=1
    c2_off_check nginx nginx.service || bad=1
    return $bad
}
fix_web_servers_apache2_nginx_removed() {
    c2_off_fix apache2 apache2.service || return 1
    c2_off_fix nginx nginx.service
}

rule x-server-removed "X server (Xwayland, Xorg) removed"
check_x_server_removed() { c2_off_check "xwayland xorg-x11-server"; }
fix_x_server_removed() { c2_off_fix "xwayland xorg-x11-server"; }

# ---- 2.2 clients ----

rule ldap-client-tools-removed "LDAP client tools removed"
check_ldap_client_tools_removed() { c2_off_check "openldap2_6-client openldap2-client"; }
fix_ldap_client_tools_removed() { c2_off_fix "openldap2_6-client openldap2-client"; }

rule nis-client-removed "NIS client (ypbind) removed"
check_nis_client_removed() { c2_off_check ypbind ypbind.service; }
fix_nis_client_removed() { c2_off_fix ypbind ypbind.service; }

# ---- 2.3 time synchronization (chrony, /usr/etc vendor file) ----

S2_CHRONY_CONF=/etc/chrony.conf

# A chrony directive's files: a directory (its *.conf, or *.sources for sourcedir) or a glob.
s2_chrony_expand() {
    local arg=$1 kind=$2 f
    if [ -d "$arg" ]; then
        if [ "$kind" = sourcedir ]; then
            find -L "$arg" -maxdepth 1 -type f -name '*.sources' 2>/dev/null
        else
            find -L "$arg" -maxdepth 1 -type f -name '*.conf' 2>/dev/null
        fi
    else
        # shellcheck disable=SC2086
        for f in $arg; do [ -f "$f" ] && echo "$f"; done
    fi
    return 0
}

# The chrony configuration in effect (/etc's chrony.conf, else /usr/etc's) plus every file its
# include/confdir/sourcedir lines pull in, two levels deep.
s2_chrony_files() {
    local conf seen="" todo next f kind arg
    conf=$(effective_file "$S2_CHRONY_CONF")
    [ -f "$conf" ] || return 0
    todo=$conf
    for _ in 1 2 3; do
        next=""
        for f in $todo; do
            [[ " $seen " == *" $f "* ]] && continue
            seen="$seen $f"
            echo "$f"
            while read -r kind arg; do
                [ -n "$arg" ] || continue
                for arg in $arg; do
                    next="$next $(s2_chrony_expand "$arg" "$kind" | xargs)"
                done
            done < <(awk '$1 ~ /^(include|confdir|sourcedir)$/ { $1 = $1; print }' "$f" 2>/dev/null)
        done
        todo=$next
        [ -n "${todo// /}" ] || break
    done
}

rule chrony-time-server-set "chrony: time server set, runs as chrony"
check_chrony_time_server_set() {
    local files hits opts bad=0
    pkg_installed chrony || { ev "chrony: not installed"; return 1; }
    mapfile -t files < <(s2_chrony_files)
    if [ "${#files[@]}" -eq 0 ]; then
        ev "chrony: no configuration files"
        bad=1
    else
        hits=$(grep -HEi '^[[:space:]]*(server|pool)[[:space:]]+[^[:space:]]' "${files[@]}" 2>/dev/null)
        if [ -n "$hits" ]; then ev "$hits"; else ev "chrony: no server/pool line in ${files[*]}"; bad=1; fi
    fi
    opts=$(e2_chrony_opts)
    ev "$E2_CHRONY_SYSCONF OPTIONS: ${opts:-unset}"
    grep -Eq '(^|[[:space:]])-u[[:space:]]+chrony([[:space:]]|$)' <<<"$opts" || bad=1
    return $bad
}
fix_chrony_time_server_set() {
    local srv conf target opts
    pkg_installed chrony || pkg_install chrony || return 1
    # shellcheck disable=SC2046
    if ! grep -qEi '^[[:space:]]*(server|pool)[[:space:]]+[^[:space:]]' $(s2_chrony_files) /dev/null 2>/dev/null; then
        srv=$(printf '%s' "${PVS_CIS_NTP:-}" | tr -cd 'A-Za-z0-9.:_ -' | xargs)
        conf=$(effective_file "$S2_CHRONY_CONF")
        if grep -Eq '^[[:space:]]*include[[:space:]]+/etc/chrony\.d/\*\.conf' "$conf" 2>/dev/null; then
            mkdir -p /etc/chrony.d
            target=/etc/chrony.d/60-pvs-cis.conf
            : > "$target"
        else
            vendor_copy "$S2_CHRONY_CONF"
            target=$S2_CHRONY_CONF
        fi
        printf '# pvs-cis: authorized time source(s)\n' >> "$target"
        if [ -n "$srv" ]; then
            # shellcheck disable=SC2086
            printf 'server %s iburst\n' $srv >> "$target"
        else
            printf 'pool 2.opensuse.pool.ntp.org iburst\n' >> "$target"
        fi
        chmod 0644 "$target"
    fi
    opts=$(e2_chrony_opts)
    if ! grep -Eq '(^|[[:space:]])-u[[:space:]]+chrony([[:space:]]|$)' <<<"$opts"; then
        getent passwd chrony >/dev/null 2>&1 || { echo "no chrony user"; return 1; }
        opts=$(sed -E 's/(^|[[:space:]])-u[[:space:]]+[^[:space:]]+//g' <<<"$opts" | xargs)
        kv_set "$E2_CHRONY_SYSCONF" OPTIONS "\"${opts:+$opts }-u chrony\"" =
        chmod 0644 "$E2_CHRONY_SYSCONF"
    fi
    systemctl try-restart chronyd.service 2>/dev/null
    return 0
}

# ---- 2.4 job schedulers: chkstat-proof modes ----

S2_PERM_LOCAL=/etc/permissions.local

# Records PATH's current owner:group and mode in permissions.local (a directory with a trailing
# slash, as the permissions files write it), and keeps "local" in PERMISSION_SECURITY.
s2_pin() {
    local p=$1 key o g m sec
    [ -e "$p" ] || return 0
    key=$p
    [ -d "$p" ] && key="${p%/}/"
    read -r m o g < <(stat -Lc '%a %U %G' "$p")
    touch "$S2_PERM_LOCAL"
    awk -v k="$key" '$1 != k' "$S2_PERM_LOCAL" > "$S2_PERM_LOCAL.pvs" && cat "$S2_PERM_LOCAL.pvs" > "$S2_PERM_LOCAL"
    rm -f "$S2_PERM_LOCAL.pvs"
    printf '%s %s:%s %04o\n' "$key" "$o" "$g" "$((8#$m))" >> "$S2_PERM_LOCAL"
    sec=$(kv_get /etc/sysconfig/security PERMISSION_SECURITY | tr -d "\"'")
    if [ -n "$sec" ] && [[ " $sec " != *" local "* ]]; then
        kv_set /etc/sysconfig/security PERMISSION_SECURITY "\"$sec local\"" =
    fi
    return 0
}

fix_etc_crontab_root_only() {
    [ -n "$(c2_cron_unit)" ] || return 0
    perm_set /etc/crontab 600 root root
    s2_pin /etc/crontab
}

c2_crondir_fix() {
    [ -n "$(c2_cron_unit)" ] || return 0
    if [ ! -e "$1" ]; then
        [ "${2:-0}" = 1 ] && return 0
        mkdir -m 0700 "$1" || return 1
    fi
    perm_set "$1" 700 root root
    s2_pin "$1"
}

rule etc-cron-yearly-root-only "/etc/cron.yearly root-only"
check_etc_cron_yearly_root_only() { c2_crondir_check /etc/cron.yearly; }
fix_etc_cron_yearly_root_only() { c2_crondir_fix /etc/cron.yearly; }

fix_crontab_restricted_by_cron_allow() {
    local g=root
    [ -n "$(c2_cron_unit)" ] || return 0
    getent group crontab >/dev/null 2>&1 && g=crontab
    [ -e /etc/cron.allow ] || touch /etc/cron.allow || return 1
    perm_set /etc/cron.allow 640 root "$g"
    s2_pin /etc/cron.allow
    if [ -e /etc/cron.deny ]; then
        perm_set /etc/cron.deny 640 root "$g"
        s2_pin /etc/cron.deny
    fi
    return 0
}

fix_at_restricted_by_at_allow() {
    local g=root
    pkg_installed at || return 0
    getent group daemon >/dev/null 2>&1 && g=daemon
    [ -e /etc/at.allow ] || touch /etc/at.allow || return 1
    perm_set /etc/at.allow 640 root "$g"
    s2_pin /etc/at.allow
    if [ -e /etc/at.deny ]; then
        perm_set /etc/at.deny 640 root "$g"
        s2_pin /etc/at.deny
    fi
    return 0
}

# ---- 2.4.3 systemd timers and units ----

# The system unit directories that exist, each once (/lib is /usr/lib on a merged /usr).
s2_unit_dirs() {
    local d
    for d in /run/systemd/system /etc/systemd/system /usr/lib/systemd/system /lib/systemd/system; do
        [ -d "$d" ] && readlink -f "$d"
    done | awk '!s[$0]++'
}

# Unit files named *.SUFFIX (links followed) that are not root:root or have u+x / g+wx / o+wx.
s2_bad_unit_files() {
    local dirs
    mapfile -t dirs < <(s2_unit_dirs)
    [ "${#dirs[@]}" -gt 0 ] || return 0
    find -L "${dirs[@]}" -mount -xdev -type f -name "*.$1" \
        \( ! -user root -o ! -group root -o -perm /133 \) -print 2>/dev/null | sort -u
}

# Directories under the unit directories that are not root:root, group/other writable or carry
# setuid/setgid/sticky.
s2_bad_unit_dirs() {
    local dirs
    mapfile -t dirs < <(s2_unit_dirs)
    [ "${#dirs[@]}" -gt 0 ] || return 0
    find "${dirs[@]}" -xdev -type d \
        \( ! -user root -o ! -group root -o -perm /022 -o -perm /7000 \) -print 2>/dev/null | sort -u
}

# Evidence for a list of paths (first 20), rc 1 when there is one.
s2_list_check() {
    local what=$1 list=$2 p n
    if [ -z "$list" ]; then ev "$what: none with excess access"; return 0; fi
    n=$(wc -l <<<"$list")
    ev "$what with excess access: $n"
    while IFS= read -r p; do
        ev "$(stat -Lc '%n %a %U:%G' "$p" 2>/dev/null)"
    done < <(head -n 20 <<<"$list")
    return 1
}

# chmod MODE + chown root:root on every path of LIST, except under /usr (vendor: reported).
s2_list_fix() {
    local mode=$1 list=$2 p real left=""
    while IFS= read -r p; do
        [ -n "$p" ] || continue
        real=$(readlink -f "$p")
        case $real in /usr/*) left="$left $real"; continue ;; esac
        chmod "$mode" "$real" && chown root:root "$real" || return 1
    done <<<"$list"
    if [ -n "$left" ]; then
        echo "left alone (vendor files under /usr):$left"
        return 1
    fi
    return 0
}

rule systemd-timer-units-access "systemd timer unit files root-only writable"
check_systemd_timer_units_access() { s2_list_check "timer units" "$(s2_bad_unit_files timer)"; }
fix_systemd_timer_units_access() { s2_list_fix u-x,go-wx "$(s2_bad_unit_files timer)"; }

rule systemd-service-units-access "systemd service unit files root-only writable"
check_systemd_service_units_access() { s2_list_check "service units" "$(s2_bad_unit_files service)"; }
fix_systemd_service_units_access() { s2_list_fix u-x,go-wx "$(s2_bad_unit_files service)"; }

rule systemd-unit-dropins-access "systemd unit directories root-only writable"
check_systemd_unit_dropins_access() { s2_list_check "unit directories" "$(s2_bad_unit_dirs)"; }
fix_systemd_unit_dropins_access() { s2_list_fix g-w,o-w,u-s,g-s,-t "$(s2_bad_unit_dirs)"; }

# Users other than root with lingering on: loginctl's view plus /var/lib/systemd/linger.
s2_lingering() {
    local u
    {
        loginctl list-users --no-legend 2>/dev/null | awk '{ if ($1 ~ /^[0-9]+$/) print $2; else print $1 }' \
            | while read -r u; do
                [ -n "$u" ] || continue
                [ "$(loginctl show-user "$u" --property=Linger --value 2>/dev/null)" = yes ] && echo "$u"
            done
        [ -d /var/lib/systemd/linger ] && find /var/lib/systemd/linger -mindepth 1 -maxdepth 1 -printf '%f\n' 2>/dev/null
    } | grep -vx root | sed '/^$/d' | sort -u
}

rule systemd-user-linger-off "no user lingering (user timers)"
check_systemd_user_linger_off() {
    local l
    l=$(s2_lingering | xargs)
    if [ -z "$l" ]; then ev "linger: no user"; return 0; fi
    ev "linger on: $l"
    return 1
}
fix_systemd_user_linger_off() {
    local u
    for u in $(s2_lingering); do
        loginctl disable-linger "$u" >/dev/null 2>&1 || rm -f "/var/lib/systemd/linger/$u"
    done
    [ -z "$(s2_lingering)" ]
}
