#!/bin/bash

QEMU_BIN="qemu-system-x86_64"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
BR_ROOT="$(cd "$REPO_ROOT/../buildroot" && pwd)"

BUILDROOT_IMAGES="${FORT_BUILDROOT_IMAGES:-$BR_ROOT/output-ray/images}"
KERNEL="${FORT_KERNEL_PATH:-$BUILDROOT_IMAGES/bzImage}"
INITRD="${FORT_INITRD_PATH:-$BUILDROOT_IMAGES/rootfs.cpio.gz}"

VERIFIER_IP="${FORT_VERIFIER_IP:-192.168.100.1}"
VERIFIER_PORT="${FORT_VERIFIER_PORT:-9443}"

WORKER_ID="${FORT_WORKER_ID:-1}"
TAP_IF="tap$((WORKER_ID - 1))"
NODE_MGR_PORT=$((6380 + 2 * WORKER_ID - 1))
OBJ_MGR_PORT=$((6380 + 2 * WORKER_ID))
MONITOR_SOCK="monitor-worker-nosnp-${WORKER_ID}"
MEM="2G"

CORE_START=$((WORKER_ID - 1))
sudo taskset -c "${CORE_START},$((CORE_START + 16))" $QEMU_BIN \
    -enable-kvm \
    -cpu EPYC-v4 \
    -machine q35,memory-backend=ram1 \
    -smp 1,sockets=1,threads=1 \
    -m ${MEM},slots=5,maxmem=40G \
    -object memory-backend-memfd,id=ram1,size=${MEM},share=true,prealloc=false,reserve=false \
    -kernel "$KERNEL" \
    -initrd "$INITRD" \
    -append "console=ttyS0 root=/dev/ram0 rw verifier_ip=${VERIFIER_IP} verifier_port=${VERIFIER_PORT} ray_worker_id=${WORKER_ID} atls_snp_attestation=false${FORT_RAY_OBJECT_STORE_MB:+ ray_object_store_mb=${FORT_RAY_OBJECT_STORE_MB}}${FORT_RAY_MEMORY_THRESHOLD:+ ray_memory_threshold=${FORT_RAY_MEMORY_THRESHOLD}}" \
    -netdev "tap,id=vmnic,ifname=${TAP_IF},script=no,downscript=no" \
    -device "virtio-net-pci,disable-legacy=on,iommu_platform=true,netdev=vmnic,romfile=,mac=52:54:00:12:34:$(printf '%02x' ${WORKER_ID})" \
    -nographic \
    -monitor pty \
    -monitor "unix:${MONITOR_SOCK},server,nowait"
