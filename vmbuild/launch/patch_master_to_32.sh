#!/usr/bin/env bash
# Runs ON THE MASTER VM. Scales the cluster config from 10 -> 32 minimal workers:
#  1. /etc/hosts: add worker11..worker32 (IP 192.168.100.(2+N)); idempotent.
#  2. bench_run_all.sh: MAXNODES=33, DVM host list + cleanup loops 1..32,
#     full worker sweep 1..32, and host-key-agnostic ssh (minimal workers
#     regenerate their host key every boot -> avoid known_hosts churn).
set -u
B=/root/bench_run_all.sh

# --- /etc/hosts: worker11..worker32 ---
for N in $(seq 11 32); do
  IP="192.168.100.$((2 + N))"
  grep -qE "[[:space:]]worker${N}\$" /etc/hosts || echo "${IP} worker${N}" >> /etc/hosts
done
echo "== /etc/hosts cluster tail =="
grep -E 'worker[0-9]+' /etc/hosts | tail -5

# --- bench_run_all.sh ---
cp -n "$B" "${B}.bak10" 2>/dev/null || true

sed -i 's/^MAXNODES=11.*/MAXNODES=33   # master + worker1..worker32/' "$B"
sed -i 's/^DVMHOSTS="master:4"/DVMHOSTS="master:1"/' "$B"
sed -i 's|for _i in \$(seq 1 10); do DVMHOSTS="\$DVMHOSTS,worker\${_i}:4"; done|for _i in $(seq 1 32); do DVMHOSTS="$DVMHOSTS,worker${_i}:1"; done|' "$B"
sed -i 's/for _w in \$(seq 1 10); do/for _w in $(seq 1 32); do/g' "$B"
sed -i 's/StrictHostKeyChecking=accept-new/StrictHostKeyChecking=no -o UserKnownHostsFile=\/dev\/null/g' "$B"
sed -i 's/^WORKERS="\${WORKERS:-1 2 3 4 5 6 7 8 9 10}"/WORKERS="${WORKERS:-1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32}"/' "$B"

echo
echo "== verify patched lines =="
grep -nE 'MAXNODES=|DVMHOSTS="master|seq 1 32|WORKERS=\"\$\{WORKERS|UserKnownHostsFile' "$B"
echo
echo "== syntax check =="
bash -n "$B" && echo "bash -n OK" || echo "bash -n FAILED"
