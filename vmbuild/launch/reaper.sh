#!/bin/bash
# Orphan-prted reaper for the worker VMs.
# The bench's in-script cleanup is unreliable (its ssh commands get SIGKILLed,
# and the minimal workers lack pkill), so orphaned prted from crashed/retried
# DVMs pile up on the workers, hold OOB ports, and destabilize the next
# MPI_Comm_accept enrollment (-> ompi_dpm_connect_accept segfaults).
#
# SAFE reaping rule: only reap when NO active DVM head (prte HNP) is running on
# the master. When prte is up, a DVM is active -> its worker prted are legit ->
# skip. Re-check prte before each worker so a freshly started DVM aborts the reap.
LOG=/root/reaper.log
echo "REAPER START $(date -u +%H:%M:%S)" >> "$LOG"
while true; do
  if ! pgrep -x prte >/dev/null 2>&1; then
    for n in $(seq 3 16); do
      pgrep -x prte >/dev/null 2>&1 && break
      ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=4 \
        "192.168.100.$n" killall -9 prted 2>/dev/null
    done
    rm -rf /tmp/prte.* /tmp/ompi.* /tmp/pmix* 2>/dev/null
  fi
  sleep 3
done
