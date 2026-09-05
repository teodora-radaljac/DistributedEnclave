#!/bin/sh
set -eu

cmdline_param() {
    awk -F"$1=" '{print $2}' /proc/cmdline | cut -d' ' -f1
}

# Prefer ray_worker_id from kernel cmdline; fall back to the last octet of the
# MAC address, which QEMU sets to the 1-based worker index (52:54:00:12:34:XX).
WORKER_ID=$(cmdline_param ray_worker_id)
if [ -z "$WORKER_ID" ]; then
    IFACE=$(ip -o link show | awk -F': ' '$3 !~ /LOOPBACK/ {print $2; exit}')
    MAC=$(ip link show "$IFACE" | awk '/ether/ {print $2}')
    WORKER_ID=$(printf '%d' "0x${MAC##*:}")
fi

NODE_MANAGER_PORT=$((6380 + 2 * WORKER_ID - 1))
OBJECT_MANAGER_PORT=$((6380 + 2 * WORKER_ID))

WORKER_IP=$(cmdline_param ray_worker_ip)
WORKER_IP=${WORKER_IP:-192.168.100.$((WORKER_ID + 1))}

HEAD_IP=$(cmdline_param verifier_ip)
HEAD_IP=${HEAD_IP:-192.168.100.1}
RAY_HEAD_PORT=6379

# Wait for TLS certs written by fort-client (ATLS attestation + cert issuance).
while [ ! -f /root/ray-worker.crt ] || [ ! -f /root/ray-worker.key ] || [ ! -f /root/ca.crt ]; do
    echo "Waiting for Ray TLS certs from verifier..."
    sleep 2
done

# Disable Ray's memory monitor by default.  The monitor uses OS-level memory
# accounting which includes plasma mmap pages, causing false OOM kills when
# DGEMM objects remain evictable in the store.  The OS OOM killer handles true
# exhaustion; Ray's monitor just gets in the way on memory-constrained CVMs.
# Override via kernel cmdline: ray_memory_monitor_ms=250 to re-enable.
RAY_MON_MS=$(cmdline_param ray_memory_monitor_ms)
export RAY_memory_monitor_refresh_ms=${RAY_MON_MS:-0}

export RAY_USE_TLS=1
export RAY_TLS_SERVER_CERT=/root/ray-worker.crt
export RAY_TLS_SERVER_KEY=/root/ray-worker.key
export RAY_TLS_CA_CERT=/root/ca.crt
export RAY_raylet_start_wait_time_s=300

# ray_object_store_mb in the kernel cmdline overrides Ray's default (30% of RAM).
OBJ_STORE_MB=$(cmdline_param ray_object_store_mb)
if [ -n "$OBJ_STORE_MB" ]; then
    OBJ_STORE_ARG="--object-store-memory=$((OBJ_STORE_MB * 1024 * 1024))"
else
    OBJ_STORE_ARG=""
fi

ray start \
    --address="${HEAD_IP}:${RAY_HEAD_PORT}" \
    --node-ip-address="${WORKER_IP}" \
    --node-manager-port="${NODE_MANAGER_PORT}" \
    --object-manager-port="${OBJECT_MANAGER_PORT}" \
    --num-cpus="$(nproc)" \
    ${OBJ_STORE_ARG} || true

echo "=== ray start failed — dumping internal logs ==="
LOG_DIR=$(ls -dt /tmp/ray/session_*/logs 2>/dev/null | head -1)
if [ -n "$LOG_DIR" ]; then
    for f in "$LOG_DIR"/raylet.out "$LOG_DIR"/raylet.err \
              "$LOG_DIR"/gcs_server.out "$LOG_DIR"/gcs_server.err \
              "$LOG_DIR"/python-core-worker*.log; do
        [ -f "$f" ] || continue
        echo "--- $f ---"
        tail -50 "$f"
    done
else
    echo "(no ray session logs found in /tmp/ray)"
fi
