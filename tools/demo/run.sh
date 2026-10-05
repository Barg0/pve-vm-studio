#!/usr/bin/env bash
# The README demo: mock PVE + the studio on http://127.0.0.1:8443 (root@pam, any password).
# Ctrl-C stops both. RESET=1 starts from an empty /tmp/pvs-demo.
# tools/demo/bin stands in for mkfs.vfat and mcopy, so deploys run without dosfstools/mtools.
set -euo pipefail
cd "$(dirname "$0")/../.."
[[ ${RESET:-} == 1 ]] && rm -rf /tmp/pvs-demo
mkdir -p /tmp/pvs-demo/iso
python3 tools/demo/mock_pve.py --port 8006 &
mock=$!
trap 'kill $mock 2>/dev/null' EXIT
sleep 1
PATH="$PWD/tools/demo/bin:$PATH" PVS_CONFIG=tools/demo/demo.toml cargo run --quiet
