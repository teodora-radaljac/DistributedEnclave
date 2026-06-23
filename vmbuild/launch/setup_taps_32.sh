#!/usr/bin/env bash
# Create tap interfaces tap11..tap32, enslave to br0, bring up.
# tap0..tap10 already exist (master + Ubuntu workers). Idempotent.
set -u
for N in $(seq 11 32); do
  ip tuntap add "tap${N}" mode tap 2>/dev/null || true
  ip link set "tap${N}" master br0 2>/dev/null || true
  ip link set "tap${N}" up
done
echo "tap count on br0:"
ls /sys/class/net/br0/brif/ | grep -c '^tap'
ls /sys/class/net/br0/brif/ | sort -V | tr '\n' ' '
echo
