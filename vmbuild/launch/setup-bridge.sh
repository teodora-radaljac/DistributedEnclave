#!/bin/bash
#
# Set up a Linux bridge (br0) with a dummy interface and N tap devices for
# QEMU CVM workers.
#
# Usage (must run as root):
#   sudo ./setup-bridge.sh [N]        # N tap devices, default 1
#
# Creates:
#   vnet0          dummy interface anchoring the bridge
#   br0            bridge at 192.168.100.1/24
#   tap0..tapN-1   one tap per worker, owned by the invoking user

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "Run as root: sudo $0 $*"
    exit 1
fi

N=${1:-1}
BRIDGE=br0
DUMMY=vnet0
BRIDGE_IP=192.168.100.1/24
# The user who will own the tap devices (the one who called sudo)
TAP_USER=${SUDO_USER:-$(logname 2>/dev/null || echo root)}

echo "Setting up bridge ${BRIDGE} with ${N} tap device(s) for user '${TAP_USER}'..."

# ── Dummy interface ──────────────────────────────────────────────────────────
if ip link show "${DUMMY}" &>/dev/null; then
    echo "  ${DUMMY} already exists, skipping"
else
    ip link add name "${DUMMY}" type dummy
    echo "  Created ${DUMMY}"
fi

# ── Bridge ───────────────────────────────────────────────────────────────────
if ip link show "${BRIDGE}" &>/dev/null; then
    echo "  ${BRIDGE} already exists, skipping"
else
    ip link add name "${BRIDGE}" type bridge
    echo "  Created ${BRIDGE}"
fi

ip addr flush dev "${DUMMY}" 2>/dev/null || true
ip link set "${DUMMY}" master "${BRIDGE}" 2>/dev/null || true

# ── Tap devices ──────────────────────────────────────────────────────────────
for i in $(seq 0 $((N - 1))); do
    TAP="tap${i}"
    if ip link show "${TAP}" &>/dev/null; then
        echo "  ${TAP} already exists, skipping"
    else
        ip tuntap add dev "${TAP}" mode tap user "${TAP_USER}"
        echo "  Created ${TAP} (owner: ${TAP_USER})"
    fi
    ip link set "${TAP}" master "${BRIDGE}"
    ip link set "${TAP}" up
done

# ── Bring everything up ──────────────────────────────────────────────────────
ip link set "${DUMMY}" up
ip link set "${BRIDGE}" up

# ── Assign IP to bridge ──────────────────────────────────────────────────────
if ip addr show "${BRIDGE}" | grep -q "${BRIDGE_IP%%/*}"; then
    echo "  ${BRIDGE} already has ${BRIDGE_IP}, skipping"
else
    ip addr add "${BRIDGE_IP}" dev "${BRIDGE}"
    echo "  Assigned ${BRIDGE_IP} to ${BRIDGE}"
fi

# ── IP forwarding + NAT (so CVM can reach the internet) ─────────────────────
echo 1 > /proc/sys/net/ipv4/ip_forward

# Detect the host's default internet interface
HOST_IF=$(ip route show default | awk '{print $5; exit}')
if [[ -n "${HOST_IF}" ]]; then
    if ! iptables -t nat -C POSTROUTING -s "${BRIDGE_IP%/*}/24" ! -d "${BRIDGE_IP%/*}/24" -o "${HOST_IF}" -j MASQUERADE 2>/dev/null; then
        iptables -t nat -A POSTROUTING -s "${BRIDGE_IP%/*}/24" ! -d "${BRIDGE_IP%/*}/24" -o "${HOST_IF}" -j MASQUERADE
        echo "  NAT masquerade enabled (${BRIDGE} → ${HOST_IF})"
    else
        echo "  NAT masquerade already set, skipping"
    fi
else
    echo "  WARNING: no default route found, skipping NAT masquerade"
fi

echo ""
echo "Bridge status:"
ip link show "${BRIDGE}"
ip addr show "${BRIDGE}"
echo ""
echo "Bridge members:"
bridge link show 2>/dev/null || brctl show "${BRIDGE}" 2>/dev/null || true
echo ""
echo "Done. Tap device(s): $(seq -s ' ' -f 'tap%.0f' 0 $((N-1)))"
echo "Use -netdev tap,id=vmnic,ifname=tapN,script=no,downscript=no in QEMU."
