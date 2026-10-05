#!/usr/bin/env bash
#
# install.sh - installs PVE VM Studio into its own LXC. Run on any node of the cluster,
# as root:
#
#   ./install.sh                 menus: container id, DNS name, storage, network, size
#   ./install.sh --defaults      no questions - everything on its default (DHCP)
#
# Next to this script: the pve-vm-studio binary (a release names it pve-vm-studio-x86_64)
# and pve-vm-studio.service. Without a binary here it downloads the latest release's - or,
# while there is no release yet, the development build (the rolling "development" pre-release) -
# or what PVS_BINARY_URL names.
#
# What it does, in order:
#   1. A service account (pve-vm-studio@pve) and its API token, with the roles the
#      studio needs - and nothing like Administrator.
#   2. A Debian 13 container: unprivileged, started with the node, the node's time zone.
#   3. The studio inside it as a systemd service on 443 (HTTPS) and 80 (Let's Encrypt
#      challenges, redirect to HTTPS), with a self-signed certificate to begin with -
#      Let's Encrypt or your own certificate are one click in the studio's Settings.
#   4. A link to it in Datacenter -> Notes and in the container's notes.
#
# Same menus and log as New-Vhdx.ps1 / Build-Vms.ps1: arrow keys, Enter, Backspace goes
# back a step, q quits. The full log is in /var/log/pve-vm-studio-install.log.

set -uo pipefail

HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
LOG_FILE=/var/log/pve-vm-studio-install.log
USER_ID=pve-vm-studio@pve
TOKEN=studio
ROLES=PVEVMAdmin,PVEDatastoreAdmin,PVESDNUser,PVEAuditor
PACKAGES="ca-certificates xorriso lego 7zip wimtools dosfstools mtools cabextract genisoimage gcab"

# ---------------------------------------------------------------------------------
# Output - the studio's palette and the PowerShell log layout
# ---------------------------------------------------------------------------------

if [[ -n ${NO_COLOR:-} || ! -t 1 ]]; then
    C_RESET="" C_BOLD="" C_DIM="" C_ACCENT="" C_OK="" C_WARN="" C_ERR="" C_INFO="" C_HOST="" C_IDENT="" C_FG=""
else
    # Kaido (Tokyo Night) as exact colours, so every terminal draws the same thing.
    C_RESET=$'\e[0m' C_BOLD=$'\e[1m' C_DIM=$'\e[38;2;139;147;173m' C_FG=$'\e[38;2;215;219;236m'
    C_ACCENT=$'\e[38;2;122;162;247m' C_OK=$'\e[38;2;158;206;106m'
    C_WARN=$'\e[38;2;224;175;104m' C_ERR=$'\e[38;2;247;118;142m'
    # info takes the log's own yellow, one step below warn's gold (New-Vhdx: `yellow`).
    C_INFO=$'\e[38;2;230;222;120m' C_HOST=$'\e[38;2;125;207;255m' C_IDENT=$'\e[38;2;187;154;247m'
fi

# time, a five-wide tag, the message - the clock and brackets in muted, the tag coloured.
log() {
    local tag=$1; shift
    local shown=$tag color
    [[ $tag == ok ]] && shown="o.k."
    case $tag in
        start|end) color=$C_ACCENT ;; get) color=$C_HOST ;; run) color=$C_IDENT ;;
        info) color=$C_INFO ;; warn) color=$C_WARN ;; ok) color=$C_OK ;; error) color=$C_ERR ;;
        *) color=$C_DIM ;;
    esac
    printf '%s [ %-5s ] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$shown" "$*" >>"$LOG_FILE"
    printf ' %s%s [ %s%s%-5s%s%s ]%s %s\n' "$C_DIM" "$(date '+%H:%M:%S')" "$C_RESET" "$color" "$shown" "$C_RESET" "$C_DIM" "$C_RESET" "$*"
}
die() { log error "$*"; printf '\e[?25h'; exit 1; }

repeat() { local s="" i; for ((i = 0; i < $2; i++)); do s+=$1; done; printf '%s' "$s"; }

# pacman's ILoveCandy bar, as Write-ChompBar draws it: the chewed track in fg, the
# mouth in the log's yellow, the dots ahead (every third cell, fixed) in the accent.
chomp_bar() { # percent frame
    local width=40 filled mouth at cell dots=""
    filled=$(($1 * width / 100)); ((filled > width)) && filled=$width
    if ((filled >= width)); then printf '%s%s%s' "$C_FG" "$(repeat - "$width")" "$C_RESET"; return; fi
    at=$((filled - 1)); ((at < 0)) && at=0
    (($2 % 4 < 2)) && mouth=C || mouth=c
    for ((cell = at + 1; cell < width; cell++)); do ((cell % 3 == 0)) && dots+=o || dots+=' '; done
    printf '%s%s%s%s%s%s%s' "$C_FG" "$(repeat - "$at")" "$C_INFO$C_BOLD" "$mouth" "$C_RESET$C_ACCENT" "$dots" "$C_RESET"
}

# How far a command is, in percent, read from what it measured - never guessed:
#   pct         the command prints its own percentages (curl --progress-bar)
#   wget:<dir>  wget's "Length:" against the bytes already in <dir> (pveam's wget prints
#               a dot line only every 32 MiB - a quarter of a template at a time)
#   apt         dpkg's Unpacking/Setting up lines against apt's "N newly installed"
# Until there is a number it stays at 0; only the mouth moves.
measure() { # mode outfile
    local mode=$1 out=$2 total done n
    case $mode in
        pct)
            tr '\r' '\n' <"$out" | grep -oE '[0-9]{1,3}(\.[0-9]+)?%' | tail -n1 | cut -d. -f1 | tr -d % ;;
        wget:*)
            total=$(grep -oE '^Length: [0-9]+' "$out" | tail -n1 | awk '{print $2}')
            [[ -n $total && $total -gt 0 ]] || { echo 0; return; }
            done=$(find "${mode#wget:}" -maxdepth 1 -type f -newer "$out" -printf '%s\n' 2>/dev/null | sort -n | tail -n1)
            echo $(( ${done:-0} * 100 / total )) ;;
        apt)
            n=$(grep -oE '[0-9]+ newly installed' "$out" | tail -n1 | cut -d' ' -f1)
            [[ -n $n && $n -gt 0 ]] || { echo 0; return; }
            done=$(grep -cE '^(Unpacking|Setting up) ' "$out")
            echo $(( done * 100 / (2 * n) )) ;;
    esac
}

# Runs a command in the background while one line shows its measured progress.
with_bar() { # label mode -- command...
    local label=$1 mode=$2 out pid frame=0 pct last=0; shift 3
    out=$(mktemp)
    "$@" >"$out" 2>&1 &
    pid=$!
    printf '\e[?25l'
    while kill -0 "$pid" 2>/dev/null; do
        pct=$(measure "$mode" "$out")
        # Monotonic: a number that goes back is a re-count, not progress lost.
        [[ $pct =~ ^[0-9]+$ ]] && ((pct > last)) && last=$pct
        ((last > 100)) && last=100
        printf '\r\e[2K   %s%-24s%s [%s] %3d%%' "$C_DIM" "$label" "$C_RESET" "$(chomp_bar "$last" "$frame")" "$last"
        frame=$((frame + 1)); sleep 0.16
    done
    wait "$pid"; local rc=$?
    printf '\r\e[2K\e[?25h'
    cat "$out" >>"$LOG_FILE"; rm -f "$out"
    return $rc
}

# ---------------------------------------------------------------------------------
# Menus - the ones New-Vhdx.ps1 and kiln.sh have
# ---------------------------------------------------------------------------------

KEY=""
read_key() {
    local k rest
    IFS= read -rsn1 k </dev/tty || { KEY=quit; return; }
    if [[ $k == $'\e' ]]; then IFS= read -rsn2 -t 0.05 rest </dev/tty; k+=$rest; fi
    case $k in
        $'\e[A'|k) KEY=up ;; $'\e[B'|j) KEY=down ;; '') KEY=enter ;;
        $'\x7f'|$'\b'|$'\e') KEY=back ;; q) KEY=quit ;; *) KEY=other ;;
    esac
}

PICK=0
menu_one() { # title default option...  ("label" or "label|detail")
    local title=$1 cur=$2; shift 2
    local opts=("$@") n=$# i label detail first=1
    printf '\n  %s%s%s\n\n' "$C_BOLD" "$title" "$C_RESET"
    printf '\e[?25l'
    while :; do
        ((first)) || printf '\e[%dA' $((n + 3))
        first=0
        for ((i = 0; i < n; i++)); do
            label=${opts[i]%%|*} detail=""
            [[ ${opts[i]} == *"|"* ]] && detail=${opts[i]#*|}
            if ((i == cur)); then
                printf '\e[2K  %s❯ %s%s  %s%s%s\n' "$C_ACCENT" "$label" "$C_RESET" "$C_DIM" "$detail" "$C_RESET"
            else
                printf '\e[2K    %s  %s%s%s\n' "$label" "$C_DIM" "$detail" "$C_RESET"
            fi
        done
        printf '\e[2K\n\e[2K  %s%s%s\n\e[2K  %s↑↓ move · Enter pick · Backspace back · q quit%s\n' "$C_DIM" "$(repeat - 62)" "$C_RESET" "$C_DIM" "$C_RESET"
        read_key
        case $KEY in
            up) cur=$(((cur - 1 + n) % n)) ;; down) cur=$(((cur + 1) % n)) ;;
            enter) PICK=$cur; printf '\e[?25h'; return 0 ;;
            back) printf '\e[?25h'; return 1 ;; quit) printf '\e[?25h\n'; exit 0 ;;
        esac
    done
}

TEXT=""
ask_text() { # prompt default
    printf '\n  %s%s%s  %s(Enter keeps the default · < goes back)%s\n' "$C_BOLD" "$1" "$C_RESET" "$C_DIM" "$C_RESET"
    IFS= read -e -r -p "  › " -i "$2" TEXT </dev/tty || exit 0
    [[ $TEXT == "<" ]] && return 1
    return 0
}

declare -A ANS
ANS_ORDER=()
MENU_TITLE="" MENU_SECTION=""

# The studio's mark - three stacked, stepped bars, as the favicon draws it - in the accent,
# the host band and the identity band.
LOGO=(
    "${C_ACCENT}██████████████${C_RESET}"
    "${C_ACCENT}██████████████${C_RESET}"
    "  ${C_HOST}██████████████${C_RESET}"
    "  ${C_HOST}██████████████${C_RESET}"
    "    ${C_IDENT}██████████████${C_RESET}"
    "    ${C_IDENT}██████████████${C_RESET}"
)
# What each logo line shows, in cells (the escape codes take none, and ${#} would count
# the block characters' bytes on a console without a UTF-8 locale).
LOGO_CELLS=(14 14 16 16 18 18)
LOGO_WIDTH=20

# Show-MenuHeader from New-Vhdx.ps1: the logo on the left, the facts on the right -
# what this is, which menu, what has been answered so far, and where it runs.
header() {
    local info=() k i rows line
    info+=("${C_FG}${C_BOLD}PVE VM Studio installer${C_RESET}")
    info+=("${C_DIM}menu     ${C_RESET}${MENU_TITLE}")
    [[ -n $MENU_SECTION ]] && info+=("${C_DIM}section  ${C_RESET}${MENU_SECTION}")
    info+=("")
    for k in "${ANS_ORDER[@]}"; do
        [[ -n ${ANS[$k]:-} ]] && info+=("$(printf '%s%-8s%s %s' "$C_DIM" "${k,,}" "$C_RESET" "${ANS[$k]}")")
    done
    ((${#ANS_ORDER[@]})) && info+=("")
    info+=("${C_DIM}node     ${C_RESET}$NODE")
    info+=("${C_DIM}pve      ${C_RESET}$(pveversion 2>/dev/null | cut -d/ -f2)")
    printf '\e[H\e[2J\n'
    rows=$(( ${#LOGO[@]} > ${#info[@]} ? ${#LOGO[@]} : ${#info[@]} ))
    for ((i = 0; i < rows; i++)); do
        line=${LOGO[i]:-}
        printf '  %s%*s   %s\n' "$line" $((LOGO_WIDTH - ${LOGO_CELLS[i]:-0})) "" "${info[i]:-}"
    done
}

# The foot of every blade: a rule and the keys.
legend() { # text
    printf '\n  %s%s%s\n  %s%s%s\n' "$C_DIM" "$(repeat - 62)" "$C_RESET" "$C_DIM" "$1" "$C_RESET"
}

# Steps return 0 = next, 1 = back, 4 = ask again.
run_steps() {
    local steps=("$@") i=0 rc
    while ((i < ${#steps[@]})); do
        ANS_ORDER=()
        local j; for ((j = 0; j < i; j++)); do ANS_ORDER+=("${STEP_KEY[${steps[j]}]}"); done
        MENU_TITLE="${STEP_KEY[${steps[i]}]}  ($((i + 1))/${#steps[@]})"
        header
        "${steps[i]}"; rc=$?
        case $rc in 0) i=$((i + 1)) ;; 4) ;; *) i=$((i - 1)) ;; esac
        ((i < 0)) && i=0
    done
}

# ---------------------------------------------------------------------------------
# What there is to choose from
# ---------------------------------------------------------------------------------

NODE=$(hostname)
SEARCH=$(awk '/^search/ {print $2; exit}' /etc/resolv.conf 2>/dev/null)
VMID="" FQDN="" STORAGE="" BRIDGE="" IPMODE=dhcp IP="" GW="" VLAN="" CORES=2 MEMORY=2048 DISK=8 WORK=64

step_vmid() {
    local next; next=$(pvesh get /cluster/nextid 2>/dev/null)
    ask_text "Container ID" "${VMID:-$next}" || return 1
    [[ $TEXT =~ ^[0-9]+$ ]] && ((TEXT >= 100)) || { log warn "a number, 100 or more"; sleep 1; return 4; }
    pct status "$TEXT" &>/dev/null && { log warn "$TEXT is taken"; sleep 1; return 4; }
    qm status "$TEXT" &>/dev/null && { log warn "$TEXT is taken"; sleep 1; return 4; }
    VMID=$TEXT; ANS[ID]=$VMID
}

step_fqdn() {
    local def=${FQDN:-pve-vm-studio${SEARCH:+.$SEARCH}}
    ask_text "DNS name of the studio (the certificate is issued for it)" "$def" || return 1
    TEXT=${TEXT,,}; TEXT=${TEXT%.}
    [[ $TEXT =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$ ]] || { log warn "not a DNS name"; sleep 1; return 4; }
    FQDN=$TEXT; ANS[Name]=$FQDN
}

step_storage() {
    local rows=() ids=() id type avail cur=0 i=0
    while read -r id type _ _ _ avail _; do
        [[ $id == Name ]] && continue
        rows+=("$id|$type, $((avail / 1048576)) GiB free"); ids+=("$id")
        [[ $id == "${STORAGE:-local-lvm}" ]] && cur=$i
        i=$((i + 1))
    done < <(pvesm status --content rootdir 2>/dev/null)
    ((${#ids[@]})) || die "no storage on $NODE holds containers (content rootdir)"
    menu_one "Storage for the container's disk" "$cur" "${rows[@]}" || return 1
    STORAGE=${ids[PICK]}; ANS[Storage]=$STORAGE
}

step_bridge() {
    local ids=() rows=() b cidr cur=0 i=0
    while read -r b; do
        cidr=$(pvesh get "/nodes/$NODE/network/$b" --output-format json 2>/dev/null | sed -n 's/.*"cidr":"\([^"]*\)".*/\1/p')
        rows+=("$b|${cidr:-no address on the node}"); ids+=("$b")
        [[ $b == "${BRIDGE:-vmbr0}" ]] && cur=$i
        i=$((i + 1))
    done < <(pvesh get "/nodes/$NODE/network" --type any_bridge --output-format json 2>/dev/null | grep -o '"iface":"[^"]*"' | cut -d'"' -f4 | sort)
    ((${#ids[@]})) || die "no bridge on $NODE"
    menu_one "Network" "$cur" "${rows[@]}" || return 1
    BRIDGE=${ids[PICK]}; ANS[Network]=$BRIDGE
}

step_address() {
    menu_one "Address" "$([[ $IPMODE == static ]] && echo 1 || echo 0)" "DHCP|the network hands one out" "Static|an address of its own - better for a DNS record" || return 1
    if ((PICK == 0)); then IPMODE=dhcp IP="" GW=""; ANS[Address]=DHCP; return 0; fi
    IPMODE=static
    ask_text "Address with prefix length" "${IP:-}" || return 4
    [[ $TEXT =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$ ]] || { log warn "like 192.0.2.10/24"; sleep 1; return 4; }
    IP=$TEXT
    local gw_def=${GW:-$(ip route show default 2>/dev/null | awk '{print $3; exit}')}
    ask_text "Gateway" "$gw_def" || return 4
    GW=$TEXT; ANS[Address]="$IP via $GW"
}

step_vlan() {
    ask_text "VLAN tag (empty: none)" "$VLAN" || return 1
    [[ -z $TEXT || ( $TEXT =~ ^[0-9]+$ && TEXT -ge 1 && TEXT -le 4094 ) ]] || { log warn "1-4094 or empty"; sleep 1; return 4; }
    VLAN=$TEXT; ANS[VLAN]=${VLAN:-none}
}

step_size() {
    menu_one "Size" 1 \
        "Small|1 core, 1 GiB, 32 GiB work volume - Linux golds only" \
        "Standard|2 cores, 2 GiB, 64 GiB work volume - Windows golds and media" \
        "Large|4 cores, 4 GiB, 128 GiB work volume - several Windows media builds" || return 1
    # The studio itself fits in 8 GiB; what bakes and media builds need while they run goes
    # on the work volume - thin, out of backups, emptied by the studio between jobs.
    case $PICK in
        0) CORES=1 MEMORY=1024 WORK=32 ;; 1) CORES=2 MEMORY=2048 WORK=64 ;; 2) CORES=4 MEMORY=4096 WORK=128 ;;
    esac
    ANS[Size]="$CORES cores, $MEMORY MiB, $DISK GiB system, $WORK GiB work"
}

step_confirm() {
    menu_one "Install?" 0 "Install|creates container $VMID and the service account" "Back|change something" || return 1
    ((PICK == 0)) || return 1
}

declare -A STEP_KEY=([step_vmid]=ID [step_fqdn]=Name [step_storage]=Storage [step_bridge]=Network
    [step_address]=Address [step_vlan]=VLAN [step_size]=Size [step_confirm]=Install)

# ---------------------------------------------------------------------------------
# Install
# ---------------------------------------------------------------------------------

# Every directory-based storage on this node that holds ISOs, mounted read-only into the
# container at /mnt/pve-iso/<storage>. Mount points mp0..mp9 that are free are used.
iso_mounts() { # vmid
    local vmid=$1 id path i=0 used
    used=$(pct config "$vmid" | grep -oE '^mp[0-9]+' | tr '\n' ' ')
    while read -r id; do
        path=$(pvesm path "$id:iso/x.iso" 2>/dev/null) || continue
        path=${path%/x.iso}
        [[ -d $path ]] || continue
        pct config "$vmid" | grep -q "mp=/mnt/pve-iso/$id," && continue
        while [[ " $used " == *" mp$i "* ]]; do i=$((i + 1)); done
        ((i > 9)) && break
        pct set "$vmid" -mp$i "$path,mp=/mnt/pve-iso/$id,ro=1" >>"$LOG_FILE" 2>&1 &&
            log ok "ISO storage $id visible to the studio (read-only)"
        used+=" mp$i"
    done < <(pvesm status --content iso 2>/dev/null | awk 'NR > 1 {print $1}')
}

install() {
    : >"$LOG_FILE"
    printf '\n'
    log start "PVE VM Studio install on $NODE"

    # ---- the binary ----
    local bin=$HERE/pve-vm-studio
    [[ -f $bin ]] || bin=$HERE/pve-vm-studio-x86_64
    [[ -f $bin ]] && chmod 0755 "$bin"
    if [[ ! -x $bin ]]; then
        if [[ -z ${PVS_BINARY_URL:-} ]]; then
            local gh=https://github.com/Barg0/pve-vm-studio/releases
            PVS_BINARY_URL=$gh/latest/download/pve-vm-studio-x86_64
            if ! curl -fsIL --max-time 30 -o /dev/null "$PVS_BINARY_URL"; then
                PVS_BINARY_URL=$gh/download/development/pve-vm-studio-x86_64
                log info "No release yet - installing the development build; updates come through Studio settings -> Version -> Development"
            fi
        fi
        bin=$(mktemp)
        log get "Downloading the studio from $PVS_BINARY_URL"
        with_bar "downloading" pct -- curl -fL --progress-bar -o "$bin" "$PVS_BINARY_URL" || die "download failed"
        chmod 0755 "$bin"
    fi
    [[ -f $HERE/pve-vm-studio.service ]] || die "no pve-vm-studio.service next to this script"

    # ---- service account ----
    log run "Service account $USER_ID and its token"
    pveum user list --output-format json | grep -q "\"userid\":\"$USER_ID\"" ||
        pveum user add "$USER_ID" --comment "PVE VM Studio service account" >>"$LOG_FILE" 2>&1
    pveum acl modify / --users "$USER_ID" --roles "$ROLES" >>"$LOG_FILE" 2>&1
    # download-url needs Sys.AccessNetwork on the nodes, which no built-in role short of
    # Administrator has. An ACL on /nodes replaces what / grants there, so it repeats them.
    pveum role list --output-format json | grep -q '"roleid":"VmStudioNetwork"' ||
        pveum role add VmStudioNetwork --privs Sys.AccessNetwork >>"$LOG_FILE" 2>&1
    pveum acl modify /nodes --users "$USER_ID" --roles "$ROLES,VmStudioNetwork" >>"$LOG_FILE" 2>&1
    # Tag colours: the studio keeps its entries in the datacenter tag-style map (PUT
    # /cluster/options), which takes Sys.Modify on / - granted on / alone, not inherited.
    pveum role list --output-format json | grep -q '"roleid":"VmStudioTagStyle"' ||
        pveum role add VmStudioTagStyle --privs Sys.Modify >>"$LOG_FILE" 2>&1
    pveum acl modify / --users "$USER_ID" --roles VmStudioTagStyle --propagate 0 >>"$LOG_FILE" 2>&1
    # Golds are parked in a pool of their own (and labs get pools later): pool rights.
    pveum acl modify /pool --users "$USER_ID" --roles PVEPoolAdmin >>"$LOG_FILE" 2>&1
    pvesh get /pools/vm-studio &>/dev/null ||
        pvesh create /pools --poolid vm-studio --comment "PVE VM Studio: golds (templates) and the bakes that make them" >>"$LOG_FILE" 2>&1
    # A token's secret is shown once, at creation - a fresh install gets a fresh token.
    if pveum user token list "$USER_ID" --output-format json | grep -q "\"tokenid\":\"$TOKEN\""; then
        pveum user token remove "$USER_ID" "$TOKEN" >>"$LOG_FILE" 2>&1
    fi
    local secret
    secret=$(pveum user token add "$USER_ID" "$TOKEN" --privsep 0 --output-format json | sed -n 's/.*"value":"\([^"]*\)".*/\1/p')
    [[ -n $secret ]] || die "could not create the API token"
    log ok "Token $USER_ID!$TOKEN with $ROLES"

    # ---- template ----
    log run "Debian 13 container template"
    pveam update >>"$LOG_FILE" 2>&1
    local template
    template=$(pveam available --section system | awk '{print $2}' | grep -E '^debian-13-standard_.*_amd64\.' | sort -V | tail -1)
    [[ -n $template ]] || die "no debian-13-standard template offered by pveam"
    if pveam list local | grep -q "$template"; then
        log ok "$template is here already"
    else
        log get "Downloading $template"
        with_bar "downloading template" "wget:$(dirname "$(pvesm path "local:vztmpl/$template")")" -- pveam download local "$template" || die "template download failed"
        log ok "$template"
    fi

    # ---- container ----
    local net="name=eth0,bridge=$BRIDGE"
    [[ $IPMODE == static ]] && net+=",ip=$IP,gw=$GW" || net+=",ip=dhcp"
    [[ -n $VLAN ]] && net+=",tag=$VLAN"
    local host=${FQDN%%.*} domain=""
    [[ $FQDN == *.* ]] && domain=${FQDN#*.}
    log run "Creating container $VMID ($FQDN)"
    pct create "$VMID" "local:vztmpl/$template" \
        --hostname "$host" ${domain:+--searchdomain "$domain"} \
        --description "PVE VM Studio" --tags pve-vm-studio \
        --cores "$CORES" --memory "$MEMORY" --swap 512 --rootfs "$STORAGE:$DISK" \
        --mp9 "${WORK_VOLUME:-$STORAGE:$WORK},mp=/var/lib/pve-vm-studio/work,backup=0,mountoptions=discard" \
        --net0 "$net" --unprivileged 1 --features nesting=1 --onboot 1 --timezone host \
        >>"$LOG_FILE" 2>&1 || die "pct create failed - see $LOG_FILE"
    # The ISO storages, read-only: the studio reads which editions a Windows ISO holds.
    # Directory-based storages only (dir, NFS, CIFS, CephFS); one folder per storage.
    iso_mounts "$VMID"
    pct start "$VMID" >>"$LOG_FILE" 2>&1 || die "container $VMID did not start"

    local i
    for i in $(seq 60); do pct exec "$VMID" -- getent hosts deb.debian.org &>/dev/null && break; sleep 2; done
    pct exec "$VMID" -- getent hosts deb.debian.org &>/dev/null || die "container $VMID has no working network or DNS"
    log ok "Container $VMID is up"

    log get "Packages: $PACKAGES"
    with_bar "installing packages" apt -- pct exec "$VMID" -- bash -c "apt-get update -q && DEBIAN_FRONTEND=noninteractive apt-get install -y -q $PACKAGES" ||
        die "package installation failed - see $LOG_FILE"

    # ---- the studio ----
    log run "Installing the studio"
    pct exec "$VMID" -- bash -c '
        useradd --system --home-dir /var/lib/pve-vm-studio --shell /usr/sbin/nologin pve-vm-studio
        install -d -o pve-vm-studio -g pve-vm-studio -m 0750 /var/lib/pve-vm-studio
        install -d -o pve-vm-studio -g pve-vm-studio -m 0750 /var/lib/pve-vm-studio/work
        install -d -g pve-vm-studio -m 0750 /etc/pve-vm-studio' >>"$LOG_FILE" 2>&1
    pct push "$VMID" "$bin" /usr/local/bin/pve-vm-studio --perms 0755
    pct push "$VMID" "$HERE/pve-vm-studio.service" /etc/systemd/system/pve-vm-studio.service
    if [[ -f $HERE/pvs-update.sh ]]; then
        pct exec "$VMID" -- mkdir -p /usr/local/lib/pve-vm-studio
        pct push "$VMID" "$HERE/pvs-update.sh" /usr/local/lib/pve-vm-studio/pvs-update.sh --perms 0755
        pct push "$VMID" "$HERE/pve-vm-studio-update.path" /etc/systemd/system/pve-vm-studio-update.path
        pct push "$VMID" "$HERE/pve-vm-studio-update.service" /etc/systemd/system/pve-vm-studio-update.service
    fi
    pct push "$VMID" /etc/pve/pve-root-ca.pem /etc/pve-vm-studio/pve-root-ca.pem --perms 0644

    # The node's own address: its certificate names it, and no DNS is needed to reach it.
    local node_ip config
    node_ip=$(hostname -I | awk '{print $1}')
    config=$(mktemp)
    cat >"$config" <<CFG
# PVE VM Studio - written by install.sh on $(date -Is)

listen = "0.0.0.0:443"
http_listen = "0.0.0.0:80"
data_dir = "/var/lib/pve-vm-studio"
fqdn = "$FQDN"

[pve]
url = "https://$node_ip:8006"
token_id = "$USER_ID!$TOKEN"
token_secret = "$secret"
ca_file = "/etc/pve-vm-studio/pve-root-ca.pem"
CFG
    pct push "$VMID" "$config" /etc/pve-vm-studio/config.toml --perms 0640 --group pve-vm-studio
    rm -f "$config"
    pct exec "$VMID" -- systemctl daemon-reload
    pct exec "$VMID" -- systemctl enable --now pve-vm-studio >>"$LOG_FILE" 2>&1
    pct exec "$VMID" -- bash -c '[ -x /usr/local/lib/pve-vm-studio/pvs-update.sh ] && install -d -o pve-vm-studio -g pve-vm-studio -m 0750 /var/lib/pve-vm-studio/update && systemctl daemon-reload && systemctl enable --now pve-vm-studio-update.path' >>"$LOG_FILE" 2>&1 || true
    sleep 2
    pct exec "$VMID" -- systemctl is-active --quiet pve-vm-studio ||
        die "the service did not start - pct exec $VMID -- journalctl -u pve-vm-studio"
    log ok "Service running"

    # ---- the way in from the PVE UI ----
    local ip url note
    ip=$(pct exec "$VMID" -- hostname -I | awk '{print $1}')
    if getent hosts "$FQDN" >/dev/null; then url="https://$FQDN"; else url="https://$ip"; fi
    # Proxmox has no official way to add UI elements; notes are Markdown and survive updates.
    note="## PVE VM Studio

[Open PVE VM Studio]($url) - design, bake and deploy VMs. Sign in with your Proxmox VE account."
    pct set "$VMID" --description "$note"
    if [[ -z $(pvesh get /cluster/options --output-format json | sed -n 's/.*"description":"\([^"]*\)".*/\1/p') ]]; then
        pvesh set /cluster/options --description "$note"
        log ok "Linked from Datacenter -> Notes and from container $VMID"
    else
        log info "Datacenter notes are in use - linked from container $VMID only"
    fi

    getent hosts "$FQDN" >/dev/null ||
        log warn "$FQDN does not resolve yet - create an A record for $ip, then set it in the studio's Settings"
    log end "Done: $url  - sign in with any PVE account; Let's Encrypt is under Settings"
}

# ---------------------------------------------------------------------------------

main() {
    [[ $EUID -eq 0 ]] || die "run as root on a PVE node"
    command -v pct >/dev/null && command -v pveum >/dev/null || die "pct/pveum not found - is this a PVE node?"
    trap 'printf "\e[?25h"' EXIT
    if [[ ${1:-} == --defaults ]]; then
        VMID=$(pvesh get /cluster/nextid) FQDN=pve-vm-studio${SEARCH:+.$SEARCH} STORAGE=local-lvm BRIDGE=vmbr0
    else
        run_steps step_vmid step_fqdn step_storage step_bridge step_address step_vlan step_size step_confirm
    fi
    install
}

# Sourced (for a test of the screens) it only defines; run, it installs.
[[ ${BASH_SOURCE[0]} == "$0" ]] && main "$@"
