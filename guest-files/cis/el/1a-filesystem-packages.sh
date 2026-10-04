# shellcheck shell=bash
# CIS AlmaLinux/Oracle/Rocky Linux 9 v3.0.0 and 10 v1.0.0 - chapter 1 (part a): builds on
# deb/1a-filesystem-packages.sh. Sourced after it: the filesystem kernel modules (1.1.1.x),
# /tmp, /dev/shm and the separate partitions with their mount options (1.1.2.x) stay on the
# deb implementation (modprobe, findmnt, fstab - nothing Debian-specific). This file adds the
# DNF rules and redefines the two deb package rules for dnf.
# Rules: our own titles; see ../README.md.
#
# Decisions
# - 1.1.x: the deb rules apply unchanged. The L2 partitions come from layout.sh on the bake's
#   second boot (its LVs carry nodev/nosuid/noexec already); the mount-option fixes only add
#   what an fstab entry lacks.
# - 1.2.1.1 (manual): 0 when every enabled repository names a gpgkey that is a local file
#   owned by an installed package (the vendor's release package), else review with the list.
#   Installed gpg-pubkey keys are listed as evidence. No fix.
# - 1.2.1.2: gpgcheck=1 in [main] of /etc/dnf/dnf.conf; any repository line that switches it
#   off (yum.repos.d, yum/repos.d, distro.repos.d) is set to 1.
# - 1.2.1.3 (L2; automated on EL9, manual on EL10): repo_gpgcheck=1 in [main]. Each enabled
#   repository is then tried with `dnf makecache` with repodata signatures required; one
#   that answers without the check but fails with it gets repo_gpgcheck=0 in its own section
#   (the per-repository exception the benchmark allows). A repository that does not answer at
#   all is left alone. Check: EL9 0 when [main] has it (exceptions in the evidence); EL10 0
#   without exceptions, review with them. RISK: repositories added later (cloud-init
#   yum_repos, site mirrors) without signed repodata fail on clones until they get their own
#   repo_gpgcheck=0.
# - 1.2.1.4 (manual): 0 when every enabled repository is defined in a package-owned file and
#   reaches its source over https; else review with the list. No fix.
# - 1.2.1.5 (L2, key apt-no-recommends-suggests): install_weak_deps=0 in [main] of dnf.conf.
#   Weak dependencies already installed stay.
# - 1.2.2.1 (manual, key all-package-updates-installed): fix = dnf upgrade --refresh. Check:
#   0 when `dnf check-update` has nothing and no reboot is pending (dnf needs-restarting -r;
#   without the plugin: running kernel vs newest installed kernel), else review.

E1_DNF_CONF=/etc/dnf/dnf.conf
E1_REPO_DIRS="/etc/yum.repos.d /etc/yum/repos.d /etc/distro.repos.d"

# ---- chapter helpers ----

# Major EL version (9, 10) from /etc/os-release (the engine sourced it).
e1_el() { local v=${VERSION_ID:-0}; echo "${v%%.*}"; }

e1_true() { case ${1,,} in 1 | true | yes | on) return 0 ;; esac; return 1; }
e1_false() { case ${1,,} in 0 | false | no | off) return 0 ;; esac; return 1; }

# The last value of KEY in [SECTION] of an INI file (dnf.conf, *.repo), "" when unset.
e1_ini_get() {
    local f=$1 s=$2 k=$3
    [ -f "$f" ] || return 0
    awk -v s="$s" -v k="${k,,}" '
        /^[[:space:]]*\[/ { cur = $0; gsub(/^[[:space:]]*\[|\][[:space:]]*$/, "", cur); next }
        /^[[:space:]]*[#;]/ { next }
        cur == s && index($0, "=") {
            kk = substr($0, 1, index($0, "=") - 1); vv = substr($0, index($0, "=") + 1)
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", kk); gsub(/^[[:space:]]+|[[:space:]]+$/, "", vv)
            if (tolower(kk) == k) v = vv
        }
        END { print v }' "$f"
}

# KEY=VALUE in [SECTION]: every KEY line of the section removed, one written right after the
# section header; the section is appended when missing.
e1_ini_set() {
    local f=$1 s=$2 k=$3 v=$4 tmp
    touch "$f"
    tmp=$(mktemp) || return 1
    awk -v s="$s" -v k="$k" -v v="$v" '
        BEGIN { kl = tolower(k) }
        /^[[:space:]]*\[/ {
            cur = $0; gsub(/^[[:space:]]*\[|\][[:space:]]*$/, "", cur); print
            if (cur == s && !done) { print k "=" v; done = 1 }
            next
        }
        cur == s && $0 !~ /^[[:space:]]*[#;]/ && index($0, "=") {
            kk = substr($0, 1, index($0, "=") - 1); gsub(/^[[:space:]]+|[[:space:]]+$/, "", kk)
            if (tolower(kk) == kl) next
        }
        { print }
        END { if (!done) { print "[" s "]"; print k "=" v } }' "$f" > "$tmp" || { rm -f "$tmp"; return 1; }
    cat "$tmp" > "$f"
    rm -f "$tmp"
}

e1_repo_files() {
    local d
    for d in $E1_REPO_DIRS; do
        [ -d "$d" ] && find -L "$d" -maxdepth 1 -type f -name '*.repo' 2>/dev/null
    done | sort
    return 0
}

# One line per repository section: file, id, enabled, gpgcheck, repo_gpgcheck, gpgkey, url
# (tab separated; "-" when unset, enabled defaults to 1).
e1_repos() {
    local f
    while IFS= read -r f; do
        awk -v F="$f" '
            function out() {
                if (id != "") printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", F, id, (en == "" ? "1" : en),
                    (gc == "" ? "-" : gc), (rg == "" ? "-" : rg), (key == "" ? "-" : key), (url == "" ? "-" : url)
            }
            /^[[:space:]]*\[/ { out(); id = $0; gsub(/^[[:space:]]*\[|\][[:space:]]*$/, "", id); en = gc = rg = key = url = ""; next }
            /^[[:space:]]*[#;]/ { next }
            index($0, "=") {
                k = tolower(substr($0, 1, index($0, "=") - 1)); v = substr($0, index($0, "=") + 1)
                gsub(/^[[:space:]]+|[[:space:]]+$/, "", k); gsub(/^[[:space:]]+|[[:space:]]+$/, "", v)
                if (k == "enabled") en = v
                else if (k == "gpgcheck") gc = v
                else if (k == "repo_gpgcheck") rg = v
                else if (k == "gpgkey") key = v
                else if ((k == "baseurl" || k == "mirrorlist" || k == "metalink") && url == "") url = v
            }
            END { out() }' "$f"
    done < <(e1_repo_files)
}

# Enabled repositories only (same columns).
e1_repos_enabled() { e1_repos | awk -F'\t' 'tolower($3) !~ /^(0|false|no|off)$/'; }

# ---- 1.2.1 DNF configuration ----

rule dnf-gpg-keys-reviewed "dnf: repository GPG keys reviewed"
check_dnf_gpg_keys_reviewed() {
    local file id en gc rg key url k p bad=0 n=0
    while IFS=$'\t' read -r file id en gc rg key url; do
        n=$((n + 1))
        if [ "$key" = - ]; then
            ev "$id ($file): no gpgkey"
            bad=1
            continue
        fi
        for k in $key; do
            case $k in
                file://*)
                    k=${k#file://}
                    if [ ! -f "$k" ]; then ev "$id: $k missing"; bad=1; continue; fi
                    if p=$(rpm -qf --qf '%{NAME}\n' "$k" 2>/dev/null); then
                        ev "$id: $k ($p)"
                    else
                        ev "$id: $k (not owned by a package)"; bad=1
                    fi
                    ;;
                *) ev "$id: remote key $k"; bad=1 ;;
            esac
        done
    done < <(e1_repos_enabled)
    [ $n -gt 0 ] || ev "no enabled repositories"
    ev "imported keys: $(rpm -q gpg-pubkey --qf '%{VERSION}-%{RELEASE} %{PACKAGER}\n' 2>/dev/null | tr '\n' ';' | sed 's/;$//')"
    [ $bad -eq 0 ] && return 0
    ev "decision: review - keys not shipped by a package (not added by the studio)"
    return 3
}

rule dnf-gpgcheck "dnf: package signatures checked (gpgcheck)"
check_dnf_gpgcheck() {
    local main hits
    main=$(e1_ini_get "$E1_DNF_CONF" main gpgcheck)
    ev "$E1_DNF_CONF [main] gpgcheck=${main:-unset}"
    # shellcheck disable=SC2086
    hits=$(grep -PrisH -- '^\h*gpgcheck\h*=\h*(0|false|no|off)\b' $E1_REPO_DIRS 2>/dev/null)
    [ -n "$hits" ] && head -n 10 <<<"$hits"
    e1_true "$main" && [ -z "$hits" ]
}
fix_dnf_gpgcheck() {
    local f
    e1_ini_set "$E1_DNF_CONF" main gpgcheck 1 || return 1
    while IFS= read -r f; do
        sed -i -E 's/^([[:space:]]*gpgcheck[[:space:]]*=[[:space:]]*)(0|false|no|off)([[:space:]]*(#.*)?)$/\11\3/I' "$f"
    done < <(e1_repo_files)
    return 0
}

# 0: the repository answers with repodata signatures required; 1: only without; 2: neither.
e1_repo_signed() {
    local id=$1
    if timeout 300 dnf -y -q --disablerepo='*' --enablerepo="$id" --setopt="$id.repo_gpgcheck=1" makecache --refresh >/dev/null 2>&1 </dev/null; then
        return 0
    fi
    if timeout 300 dnf -y -q --disablerepo='*' --enablerepo="$id" --setopt="$id.repo_gpgcheck=0" makecache --refresh >/dev/null 2>&1 </dev/null; then
        return 1
    fi
    return 2
}

rule dnf-repo-gpgcheck "dnf: repodata signatures checked"
check_dnf_repo_gpgcheck() {
    local main file id en gc rg key url exc=()
    main=$(e1_ini_get "$E1_DNF_CONF" main repo_gpgcheck)
    ev "$E1_DNF_CONF [main] repo_gpgcheck=${main:-unset}"
    while IFS=$'\t' read -r file id en gc rg key url; do
        e1_false "$rg" && exc+=("$id")
    done < <(e1_repos)
    [ ${#exc[@]} -gt 0 ] && ev "repositories with repo_gpgcheck=0 (no signed repodata): ${exc[*]}"
    e1_true "$main" || return 1
    [ "$(e1_el)" -ge 10 ] && [ ${#exc[@]} -gt 0 ] && {
        ev "decision: review - per-repository exceptions where the source signs no repodata"
        return 3
    }
    return 0
}
fix_dnf_repo_gpgcheck() {
    local file id en gc rg key url
    e1_ini_set "$E1_DNF_CONF" main repo_gpgcheck 1 || return 1
    while IFS=$'\t' read -r file id en gc rg key url; do
        e1_repo_signed "$id"
        case $? in
            0) e1_false "$rg" && e1_ini_set "$file" "$id" repo_gpgcheck 1 ;;
            1) ev "$id: no signed repodata - repo_gpgcheck=0 for this repository"
               e1_ini_set "$file" "$id" repo_gpgcheck 0 ;;
            *) ev "$id: unreachable - left as it is" ;;
        esac
    done < <(e1_repos_enabled)
    return 0
}

rule dnf-repos-reviewed "dnf: repositories reviewed"
check_dnf_repos_reviewed() {
    local file id en gc rg key url p bad=0 n=0
    while IFS=$'\t' read -r file id en gc rg key url; do
        n=$((n + 1))
        p=$(rpm -qf --qf '%{NAME}\n' "$file" 2>/dev/null) || { p="not owned by a package"; bad=1; }
        ev "$id: $url ($file, $p)"
        case $url in https://*) ;; *) bad=1 ;; esac
    done < <(e1_repos_enabled)
    [ $n -gt 0 ] || { ev "no enabled repositories"; bad=1; }
    [ $bad -eq 0 ] && return 0
    ev "decision: review - repositories not from the vendor release package or not on https"
    return 3
}

rule apt-no-recommends-suggests "dnf: no weak dependencies"
check_apt_no_recommends_suggests() {
    local v on
    v=$(e1_ini_get "$E1_DNF_CONF" main install_weak_deps)
    ev "$E1_DNF_CONF [main] install_weak_deps=${v:-unset (default on)}"
    on=$(grep -Pi -- '^\h*install_weak_deps\h*=\h*(1|true|yes)\b' "$E1_DNF_CONF" 2>/dev/null)
    [ -n "$on" ] && ev "also set: $on"
    e1_false "$v" && [ -z "$on" ]
}
fix_apt_no_recommends_suggests() { e1_ini_set "$E1_DNF_CONF" main install_weak_deps 0; }

# ---- 1.2.2 updates ----

# 0: a reboot is pending, 1: not, 2: cannot tell.
e1_reboot_pending() {
    local newest running
    if dnf -q needs-restarting --help >/dev/null 2>&1 </dev/null; then
        dnf -q needs-restarting -r >/dev/null 2>&1 </dev/null
        case $? in
            0) return 1 ;;
            1) return 0 ;;
        esac
    fi
    newest=$(rpm -q --last kernel-core kernel-uek-core kernel-uek kernel 2>/dev/null | awk '$1 != "package" { print $1; exit }')
    running=$(uname -r)
    [ -n "$newest" ] || return 2
    [[ "$newest" == *"$running" ]] && return 1
    return 0
}

rule all-package-updates-installed "All package updates installed"
check_all_package_updates_installed() {
    local out rc pend n=0 r=0
    out=$(timeout 300 dnf -q check-update --refresh 2>/dev/null </dev/null)
    rc=$?
    case $rc in
        0) ev "dnf check-update: nothing pending" ;;
        100)
            pend=$(awk 'NF == 3 && $1 ~ /\./ { print $1 } /^Obsoleting/ { exit }' <<<"$out")
            n=$(grep -c . <<<"$pend")
            ev "pending updates: $n"
            head -n 15 <<<"$pend" | xargs
            r=3
            ;;
        *) ev "dnf check-update failed (rc $rc) - repositories unreachable"; r=3 ;;
    esac
    e1_reboot_pending
    case $? in
        0) ev "reboot required"; r=3 ;;
        1) ev "no reboot required" ;;
        *) ev "reboot state unknown" ;;
    esac
    [ $r = 3 ] && ev "decision: the bake installs all updates; clones patch per site policy"
    return $r
}
fix_all_package_updates_installed() { dnf -y -q upgrade --refresh >/dev/null </dev/null; }
