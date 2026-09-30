#!/usr/bin/env bash
#
# pve-setup.sh - run ONCE on any PVE node, as root. Creates the user and API token the
# studio works with, and prints what goes into config.toml.
#
# The token runs every job (bakes, deploys), so it needs to create and configure VMs,
# allocate disks and templates, and read the cluster. Users signing in to the studio keep
# their own PVE permissions; this token is only the ceiling.

set -euo pipefail

USER_ID=${1:-pve-vm-studio@pve}
TOKEN=${2:-studio}
ROLES=PVEVMAdmin,PVEDatastoreAdmin,PVESDNUser,PVEAuditor

[[ $EUID -eq 0 ]] || { echo "run as root on a PVE node" >&2; exit 1; }
command -v pveum >/dev/null || { echo "pveum not found - is this a PVE node?" >&2; exit 1; }

if pveum user list --output-format json | grep -q "\"userid\":\"$USER_ID\""; then
    echo "user $USER_ID exists"
else
    pveum user add "$USER_ID" --comment "PVE VM Studio service account"
    echo "created user $USER_ID"
fi

# No privilege separation: the token has exactly what the user has, so the ACL lives in
# one place.
pveum acl modify / --users "$USER_ID" --roles "$ROLES"
# PVE downloading cloud images itself (download-url) also needs Sys.AccessNetwork on the
# nodes - no built-in role short of Administrator has it, so it gets a role of its own.
# An ACL on /nodes replaces what / grants there, so /nodes repeats the other roles.
pveum role list --output-format json | grep -q '"roleid":"VmStudioNetwork"' ||
    pveum role add VmStudioNetwork --privs Sys.AccessNetwork
pveum acl modify /nodes --users "$USER_ID" --roles "$ROLES,VmStudioNetwork"
echo "granted $ROLES on / to $USER_ID"

if pveum user token list "$USER_ID" --output-format json | grep -q "\"tokenid\":\"$TOKEN\""; then
    echo "token $USER_ID!$TOKEN exists already - its secret was shown only when it was made."
    echo "to start over: pveum user token remove $USER_ID $TOKEN"
    exit 0
fi

SECRET=$(pveum user token add "$USER_ID" "$TOKEN" --privsep 0 --output-format json |
    sed -n 's/.*"value":"\([^"]*\)".*/\1/p')

cat <<OUT

Put this into /etc/pve-vm-studio/config.toml:

[pve]
url = "https://$(hostname -f):8006"
token_id = "$USER_ID!$TOKEN"
token_secret = "$SECRET"
ca_file = "/etc/pve-vm-studio/pve-root-ca.pem"

and copy the cluster CA next to it: /etc/pve/pve-root-ca.pem
(deploy/create-lxc.sh does both for you).
OUT
