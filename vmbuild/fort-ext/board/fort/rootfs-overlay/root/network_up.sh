#!/bin/sh

cmdline_param() {
    awk -F"$1=" '{print $2}' /proc/cmdline | cut -d' ' -f1
}

# Wait for all udev events (including interface renames) to complete before
# querying the interface name, so we always get the final post-rename name.
udevadm settle --timeout=10
IFACE=$(ip -o link show | awk -F': ' '$3 !~ /LOOPBACK/ {print $2; exit}')

# Prefer ray_worker_id from kernel cmdline; fall back to the last octet of the
# MAC address, which QEMU sets to the 1-based worker index (52:54:00:12:34:XX).
WORKER_ID=$(cmdline_param ray_worker_id)
if [ -z "$WORKER_ID" ]; then
    MAC=$(ip link show "$IFACE" | awk '/ether/ {print $2}')
    WORKER_ID=$(printf '%d' "0x${MAC##*:}")
fi

WORKER_IP="192.168.100.$((WORKER_ID + 1))"
GATEWAY="192.168.100.1"

ip link set "$IFACE" up
ip addr add "${WORKER_IP}/24" dev "$IFACE" 2>/dev/null || true
ip route add default via "$GATEWAY" 2>/dev/null || true
echo "nameserver 8.8.8.8" > /etc/resolv.conf
