# shellcheck shell=bash
# CIS SUSE Linux Enterprise 16 v1.0.0 on openSUSE Leap 16.0 - chapter 1 (part a): builds on
# deb/ and el/1a-filesystem-packages.sh, sourced after both. The filesystem modules, /tmp,
# /dev/shm and the partitions (1.1.x) stay on the deb rules. This file redefines the package
# manager rules (1.2.x) for zypper: the el ones read dnf.conf and yum.repos.d, which Leap does
# not have (they would pass with nothing to look at).
# Rules: our own titles; see ../README.md.
#
# Decisions
# - zypp.conf: /etc/zypp/zypp.conf (the file the benchmark audits). libzypp reads it INSTEAD of
#   /usr/etc/zypp/zypp.conf, so the fixes vendor_copy it first and change only their key in
#   [main]. Checks read the effective file.
# - 1.2.1.1 (manual): every imported gpg-pubkey listed (key id, date, packager). 0 when all are
#   SUSE/openSUSE signing keys and every enabled repository checks signatures, else review.
#   No fix.
# - 1.2.1.2: gpgcheck=on in [main]; repository files with gpgcheck off or a non-boolean value
#   (2-9, multi-digit) get gpgcheck=1.
# - 1.2.1.3 (L2, manual): repo_gpgcheck=on in [main] only. Each enabled repository is
#   refreshed before and after; when one that refreshed before no longer does, the old value
#   is put back and the fix fails (decision needed). No per-repository exceptions: Leap's
#   repositories come from the openSUSE-repos service, whose refresh rewrites the repo files.
#   Check: 1 without [main] on, review when a repository switches it off.
# - 1.2.1.4 (manual): 0 when every enabled repository comes from a repo service (or a package-
#   owned file) and uses https, else review with the list. No fix.
# - 1.2.1.5 (L2): solver.onlyRequires = true in [main]. Packages installed later in the bake
#   come without their Recommends (pkg_install passes --no-recommends anyway).
# - 1.2.2.1 (manual): fix = `zypper patch` (again while zypper reports it updated itself, rc
#   103), then `zypper update`. rc 100-103 are information, not errors. No
#   --gpg-auto-import-keys, no --auto-agree-with-licenses: a patch that needs a licence
#   confirmation fails the fix (studio decision). Check: refresh, list-updates, list-patches,
#   needs-rebooting (rc 102 = reboot needed); 0 when nothing is pending, else review.

S1_ZYPP_CONF=/etc/zypp/zypp.conf
S1_REPO_DIR=/etc/zypp/repos.d

# ---- chapter helpers ----

# zypper return codes 100-106 are information (updates/patches pending, reboot or restart
# needed, repositories skipped); 0 and those count as success.
s1_zypper_ok() { [ "$1" -eq 0 ] || { [ "$1" -ge 100 ] && [ "$1" -le 106 ]; }; }

# The [main] value of KEY in the zypp.conf in effect.
s1_zypp_get() { e1_ini_get "$(effective_file "$S1_ZYPP_CONF")" main "$1"; }

# KEY=VALUE in [main] of /etc/zypp/zypp.conf (the vendor copy first, when /etc has none).
s1_zypp_set() {
    vendor_copy "$S1_ZYPP_CONF"
    e1_ini_set "$S1_ZYPP_CONF" main "$1" "$2"
}

# One line per repository: file, alias, enabled, gpgcheck, repo_gpgcheck, url, service (tab
# separated; "-" when unset, enabled defaults to 1).
s1_repos() {
    local f
    for f in "$S1_REPO_DIR"/*.repo; do
        [ -f "$f" ] || continue
        awk -v F="$f" '
            function out() {
                if (id != "") printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", F, id, (en == "" ? "1" : en),
                    (gc == "" ? "-" : gc), (rg == "" ? "-" : rg), (url == "" ? "-" : url), (svc == "" ? "-" : svc)
            }
            /^[[:space:]]*\[/ { out(); id = $0; gsub(/^[[:space:]]*\[|\][[:space:]]*$/, "", id); en = gc = rg = url = svc = ""; next }
            /^[[:space:]]*[#;]/ { next }
            index($0, "=") {
                k = tolower(substr($0, 1, index($0, "=") - 1)); v = substr($0, index($0, "=") + 1)
                gsub(/^[[:space:]]+|[[:space:]]+$/, "", k); gsub(/^[[:space:]]+|[[:space:]]+$/, "", v)
                if (k == "enabled") en = v
                else if (k == "gpgcheck") gc = v
                else if (k == "repo_gpgcheck") rg = v
                else if ((k == "baseurl" || k == "mirrorlist") && url == "") url = v
                else if (k == "service") svc = v
            }
            END { out() }' "$f"
    done
    return 0
}

s1_repos_enabled() { s1_repos | awk -F'\t' 'tolower($3) !~ /^(0|false|no|off)$/'; }

# Aliases of the enabled repositories that refresh now (one per line).
s1_repos_refreshing() {
    local file id rest
    while IFS=$'\t' read -r file id rest; do
        timeout 300 zypper -n -q refresh -f -r "$id" >/dev/null 2>&1 </dev/null && echo "$id"
    done < <(s1_repos_enabled)
    return 0
}

# ---- 1.2.1 zypper configuration ----

rule dnf-gpg-keys-reviewed "zypper: package signing keys reviewed"
check_dnf_gpg_keys_reviewed() {
    local k ver rel pk date bad=0 n=0 file id en gc rg url svc
    while IFS= read -r k; do
        [ -n "$k" ] || continue
        n=$((n + 1))
        ver=$(rpm -q --qf '%{VERSION}' "$k" 2>/dev/null)
        rel=$(rpm -q --qf '%{RELEASE}' "$k" 2>/dev/null)
        pk=$(rpm -q --qf '%{PACKAGER}' "$k" 2>/dev/null)
        date=$(date -u -d "@$((16#${rel:-0}))" +%F 2>/dev/null)
        ev "key $ver ($date): $pk"
        grep -qi 'suse' <<<"$pk" || bad=1
    done < <(rpm -q gpg-pubkey 2>/dev/null | grep '^gpg-pubkey-')
    [ $n -gt 0 ] || { ev "no imported package signing keys"; bad=1; }
    while IFS=$'\t' read -r file id en gc rg url svc; do
        e1_false "$gc" && { ev "$id: gpgcheck=$gc"; bad=1; }
    done < <(s1_repos_enabled)
    [ $bad -eq 0 ] && return 0
    ev "decision: review - keys not from SUSE/openSUSE, or repositories without signature checks"
    return 3
}

rule dnf-gpgcheck "zypper: package signatures checked (gpgcheck)"
check_dnf_gpgcheck() {
    local f main off hits
    f=$(effective_file "$S1_ZYPP_CONF")
    main=$(s1_zypp_get gpgcheck)
    ev "$f [main] gpgcheck=${main:-unset (default on)}"
    off=$(grep -Pi -- '^\h*gpgcheck\h*=\h*(0|false|no|off)\b' "$f" 2>/dev/null)
    [ -n "$off" ] && ev "$f: $off"
    hits=$(grep -Pris -- '^\h*gpgcheck\h*=\h*(0|[2-9]|[1-9][0-9]+|false|no|off)\b' "$S1_REPO_DIR" 2>/dev/null)
    [ -n "$hits" ] && head -n 10 <<<"$hits"
    [ -z "$off" ] && [ -z "$hits" ]
}
fix_dnf_gpgcheck() {
    local f
    s1_zypp_set gpgcheck on || return 1
    for f in "$S1_REPO_DIR"/*.repo; do
        [ -f "$f" ] || continue
        sed -i -E 's/^([[:space:]]*gpgcheck[[:space:]]*=[[:space:]]*)(0|[2-9]|[1-9][0-9]+|false|no|off)([[:space:]]*(#.*)?)$/\11\3/I' "$f"
    done
    return 0
}

rule dnf-repo-gpgcheck "zypper: repository metadata signatures checked"
check_dnf_repo_gpgcheck() {
    local main file id en gc rg url svc exc=()
    main=$(s1_zypp_get repo_gpgcheck)
    ev "$(effective_file "$S1_ZYPP_CONF") [main] repo_gpgcheck=${main:-unset}"
    while IFS=$'\t' read -r file id en gc rg url svc; do
        e1_false "$rg" && exc+=("$id")
    done < <(s1_repos)
    [ ${#exc[@]} -gt 0 ] && ev "repositories with repo_gpgcheck off: ${exc[*]}"
    e1_true "$main" || return 1
    [ ${#exc[@]} -eq 0 ] && return 0
    ev "decision: review - per-repository exceptions"
    return 3
}
fix_dnf_repo_gpgcheck() {
    local old before after lost
    old=$(s1_zypp_get repo_gpgcheck)
    e1_true "$old" && return 0
    before=$(s1_repos_refreshing)
    s1_zypp_set repo_gpgcheck on || return 1
    after=$(s1_repos_refreshing)
    lost=$(comm -23 <(sort <<<"$before") <(sort <<<"$after") | xargs)
    [ -z "$lost" ] && return 0
    ev "no longer refresh with repo_gpgcheck=on: $lost - previous value put back"
    if [ -n "$old" ]; then
        e1_ini_set "$S1_ZYPP_CONF" main repo_gpgcheck "$old"
    else
        sed -i -E '/^[[:space:]]*repo_gpgcheck[[:space:]]*=/d' "$S1_ZYPP_CONF"
    fi
    return 1
}

rule dnf-repos-reviewed "zypper: repositories reviewed"
check_dnf_repos_reviewed() {
    local file id en gc rg url svc src bad=0 n=0
    while IFS=$'\t' read -r file id en gc rg url svc; do
        n=$((n + 1))
        if [ "$svc" != - ]; then src="service $svc"
        elif src=$(rpm -qf --qf '%{NAME}\n' "$file" 2>/dev/null); then src="package $src"
        else src="local file"; bad=1; fi
        ev "$id: $url ($src)"
        case $url in https://*) ;; *) bad=1 ;; esac
    done < <(s1_repos_enabled)
    [ $n -gt 0 ] || { ev "no enabled repositories"; bad=1; }
    command -v zypper >/dev/null 2>&1 && ev "services: $(zypper -n -q ls -u 2>/dev/null | awk -F'|' 'NR > 2 { gsub(/^ +| +$/, "", $2); gsub(/^ +| +$/, "", $NF); printf "%s %s; ", $2, $NF }')"
    [ $bad -eq 0 ] && return 0
    ev "decision: review - repositories not from a repo service or package, or not on https"
    return 3
}

rule apt-no-recommends-suggests "zypper: no weak dependencies (onlyRequires)"
check_apt_no_recommends_suggests() {
    local f v
    f=$(effective_file "$S1_ZYPP_CONF")
    v=$(s1_zypp_get solver.onlyRequires)
    ev "$f [main] solver.onlyRequires=${v:-unset (default false)}"
    grep -Piq -- '^\h*solver\.onlyRequires\h*=\h*true\b' "$f" 2>/dev/null && [ "${v,,}" = true ]
}
fix_apt_no_recommends_suggests() { s1_zypp_set solver.onlyRequires true; }

# ---- 1.2.2 updates ----

rule all-package-updates-installed "All package updates installed"
check_all_package_updates_installed() {
    local rc nu np r=0
    timeout 600 zypper -n -q refresh >/dev/null 2>&1 </dev/null
    rc=$?
    s1_zypper_ok $rc || { ev "zypper refresh failed (rc $rc) - repositories unreachable"; r=3; }
    nu=$(timeout 300 zypper -n -x list-updates 2>/dev/null </dev/null | grep -c '<update ')
    np=$(timeout 300 zypper -n -x list-patches 2>/dev/null </dev/null | grep -c '<update ')
    ev "pending package updates: $nu, needed patches: $np"
    [ "$nu" -eq 0 ] && [ "$np" -eq 0 ] || r=3
    zypper -n needs-rebooting >/dev/null 2>&1 </dev/null
    case $? in
        0) ev "no reboot required" ;;
        102) ev "reboot required"; r=3 ;;
        *) ev "reboot state unknown" ;;
    esac
    [ $r = 3 ] && ev "decision: the bake installs all updates; clones patch per site policy"
    return $r
}
fix_all_package_updates_installed() {
    local i rc
    for i in 1 2 3; do
        timeout 3600 zypper -n -q patch >/dev/null 2>&1 </dev/null
        rc=$?
        [ $rc -eq 103 ] && continue
        break
    done
    s1_zypper_ok $rc || { ev "zypper patch failed (rc $rc)"; return 1; }
    timeout 3600 zypper -n -q update >/dev/null 2>&1 </dev/null
    rc=$?
    s1_zypper_ok $rc || { ev "zypper update failed (rc $rc)"; return 1; }
    return 0
}
