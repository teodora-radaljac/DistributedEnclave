#!/bin/bash
#
# Tear down the Linux bridge created by setup-bridge.sh.
#
# Usage (must run as root):
#   sudo ./teardown-bridge.sh [N]        # remove N tap devices, default 1

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "Run as root: sudo $0 $*"
    exit 1
fi

N=${1:-1}
BRIDGE=br0
DUMMY=vnet0

echo "Tearing down bridge ${BRIDGE} and ${N} tap device(s)..."

# ── Tap devices ──────────────────────────────────────────────────────────────
for i in $(seq 0 $((N - 1))); do
    TAP="tap${i}"
    if ip link show "${TAP}" &>/dev/null; then
        ip link delete "${TAP}"
        echo "  Deleted ${TAP}"
    else
        echo "  ${TAP} not found, skipping"
    fi
done

# ── Bridge ───────────────────────────────────────────────────────────────────
if ip link show "${BRIDGE}" &>/dev/null; then
    ip link delete "${BRIDGE}"
    echo "  Deleted ${BRIDGE}"
else
    echo "  ${BRIDGE} not found, skipping"
fi

# ── Dummy interface ──────────────────────────────────────────────────────────
if ip link show "${DUMMY}" &>/dev/null; then
    ip link delete "${DUMMY}"
    echo "  Deleted ${DUMMY}"
else
    echo "  ${DUMMY} not found, skipping"
fi

echo "Done."
