#!/bin/bash
# Quick full-cluster sanity: DVM over master + worker1..worker32, then
# mpiexec hostname (1 rank per node). Prints how many distinct nodes answered.
set -u
export PATH=/root/mpi-stack/bin:/usr/local/bin:$PATH
export LD_LIBRARY_PATH=/root/mpi-stack/lib
PREFIX=/root/mpi-stack
NET=192.168.100.0/24
URI=/root/dvm-uri-test32.txt
SSHARGS="-o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=6"

HOSTS="master:1"
for i in $(seq 1 32); do HOSTS="$HOSTS,worker${i}:1"; done

pkill -9 -f prte 2>/dev/null; pkill -9 -f prted 2>/dev/null; pkill -9 -f mpiexec 2>/dev/null
sleep 1; rm -f "$URI" /root/prte-test32.out

prte --prefix "$PREFIX" --allow-run-as-root --host "$HOSTS" \
    --prtemca oob_tcp_if_include "$NET" --pmixmca ptl_tcp_if_include "$NET" \
    --prtemca plm ssh --prtemca plm_ssh_args "$SSHARGS" \
    --report-uri "$URI" > /root/prte-test32.out 2>&1 &

for i in $(seq 1 40); do [ -s "$URI" ] && break; sleep 1; done
if [ ! -s "$URI" ]; then echo "!! DVM nije startovao"; cat /root/prte-test32.out; exit 1; fi
echo "DVM URI: $(head -1 "$URI")"

echo "=== mpiexec hostname over all 33 nodes ==="
mpiexec --dvm file:"$URI" --allow-run-as-root -x PATH -x LD_LIBRARY_PATH \
    --bind-to none --mca btl self,tcp --mca btl_tcp_if_include "$NET" \
    -np 33 --map-by ppr:1:node hostname > /tmp/hn32.txt 2>/tmp/hn32.err
RC=$?
echo "mpiexec RC=$RC"
echo "distinct hosts answering: $(sort -u /tmp/hn32.txt | wc -l)"
echo "worker lines: $(grep -c worker /tmp/hn32.txt)  master lines: $(grep -c master /tmp/hn32.txt)"
echo "--- any errors (tail) ---"; tail -5 /tmp/hn32.err 2>/dev/null

pterm --dvm file:"$URI" 2>/dev/null
pkill -9 -f prte 2>/dev/null
exit $RC
