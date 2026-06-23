#!/usr/bin/env bash
# Probe which user/key logs into the master VM at 192.168.100.2.
set -u
HOSTIP=192.168.100.2
for KEY in ~/.ssh/vm_key ~/.ssh/id_rsa ~/.ssh/id_ed25519; do
  [ -f "$KEY" ] || continue
  for U in teodora root mpi ubuntu master admin; do
    echo "=== key=$KEY user=$U ==="
    ssh -i "$KEY" -o StrictHostKeyChecking=no -o ConnectTimeout=8 \
        -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no \
        "$U@$HOSTIP" 'echo OK_LOGIN $(hostname) $(whoami)' 2>&1 | head -2
  done
done
