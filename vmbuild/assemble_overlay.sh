#!/bin/bash
# Assemble the worker rootfs-overlay payload by pulling pre-built artifacts
# from the master VM (192.168.100.2) into the Buildroot external tree on the
# build host. Run this ON THE HOST (Linux), not on Windows.
#
#   bash assemble_overlay.sh
#
set -euo pipefail

MASTER_IP=192.168.100.2
KEY="$HOME/.ssh/vm_key"
M=(ssh -o ConnectTimeout=10 -o StrictHostKeyChecking=no -i "$KEY" "root@${MASTER_IP}")

OVL="$HOME/br/worker-ext/board/worker/rootfs-overlay"
ROOT="$OVL/root"
mkdir -p "$ROOT/src" "$ROOT/certs" "$OVL/usr/bin"

echo "[1/5] mpi-stack (trimmed: no src/include/doc/man) ..."
rm -rf "$ROOT/mpi-stack"
"${M[@]}" "cd /root && tar cf - \
    --exclude='mpi-stack/src' \
    --exclude='mpi-stack/include' \
    --exclude='mpi-stack/share/doc' \
    --exclude='mpi-stack/share/man' \
    --exclude='mpi-stack/share/info' \
    mpi-stack" | tar xf - -C "$ROOT"

echo "[2/5] leaf .so (Ubuntu glibc 2.39 build) -> mpi-stack/lib ..."
LIBS="libsodium.so.23 libevent_core-2.1.so.7 libevent_pthreads-2.1.so.7 \
      libhwloc.so.15 libudev.so.1 libcap.so.2 libgcc_s.so.1"
for l in $LIBS; do
    "${M[@]}" "cat /lib/x86_64-linux-gnu/$l 2>/dev/null || cat /usr/lib/x86_64-linux-gnu/$l" \
        > "$ROOT/mpi-stack/lib/$l"
    echo "    + $l ($(stat -c%s "$ROOT/mpi-stack/lib/$l") B)"
done

echo "[3/5] worker binaries -> /root/src ..."
for b in worker_bench worker_bench_noatt worker_npb worker_npb_noatt worker_attest; do
    "${M[@]}" "cat /root/src/$b" > "$ROOT/src/$b"
    chmod 755 "$ROOT/src/$b"
done

echo "[4/5] AMD certs -> /root/certs ..."
for c in ark ask vcek cert_chain; do
    "${M[@]}" "cat /root/certs/$c.pem" > "$ROOT/certs/$c.pem"
done

echo "[5/5] snpguest -> /usr/bin ..."
"${M[@]}" "cat /root/.cargo/bin/snpguest" > "$OVL/usr/bin/snpguest"
chmod 755 "$OVL/usr/bin/snpguest"

echo
echo "=== overlay payload assembled ==="
du -sh "$ROOT/mpi-stack" "$ROOT/src" "$ROOT/certs" "$OVL/usr/bin/snpguest"
echo "mpi-stack/lib contents:"; ls "$ROOT/mpi-stack/lib"
