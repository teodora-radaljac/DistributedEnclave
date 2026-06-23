#!/bin/bash
# Quick integration test: prte DVM over master + worker1 (minimal SEV-SNP),
# then mpiexec hostname across both. Confirms prted launches on the minimal
# worker and the MPI runtime works (prte --prefix sets LD_LIBRARY_PATH).
set -u
export PATH=/root/mpi-stack/bin:/usr/local/bin:$PATH
export LD_LIBRARY_PATH=/root/mpi-stack/lib
export SNP_CERTS_DIR=/root/certs
PREFIX=/root/mpi-stack
NET=192.168.100.0/24
URI=/root/dvm-uri-test.txt
SSHARGS="-o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=6"

pkill -9 -f prte 2>/dev/null; pkill -9 -f prted 2>/dev/null; pkill -9 -f mpiexec 2>/dev/null
sleep 1; rm -f "$URI" /root/prte-test.out

prte --prefix "$PREFIX" --allow-run-as-root \
    --host master:1,worker1:1 \
    --prtemca oob_tcp_if_include "$NET" --pmixmca ptl_tcp_if_include "$NET" \
    --prtemca plm ssh --prtemca plm_ssh_args "$SSHARGS" \
    --report-uri "$URI" > /root/prte-test.out 2>&1 &

for i in $(seq 1 30); do [ -s "$URI" ] && break; sleep 1; done
if [ ! -s "$URI" ]; then echo "!! DVM nije startovao"; cat /root/prte-test.out; exit 1; fi
echo "DVM URI: $(head -1 "$URI")"

echo "=== mpiexec hostname (np=2, master+worker1) ==="
mpiexec --dvm file:"$URI" --allow-run-as-root -x PATH -x LD_LIBRARY_PATH \
    --bind-to none --mca btl self,tcp --mca btl_tcp_if_include "$NET" \
    -np 2 --map-by node --host master,worker1 hostname
RC=$?
echo "mpiexec RC=$RC"

echo "=== pterm ==="
pterm --dvm file:"$URI" 2>/dev/null
pkill -9 -f prte 2>/dev/null
exit $RC
