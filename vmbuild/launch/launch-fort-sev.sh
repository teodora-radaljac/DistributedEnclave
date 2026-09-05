#!/bin/bash

QEMU_BIN="qemu-system-x86_64"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
BR_ROOT="$(cd "$REPO_ROOT/../buildroot" && pwd)"

BUILDROOT_IMAGES="${FORT_BUILDROOT_IMAGES:-$BR_ROOT/output-ray/images}"
KERNEL="${FORT_KERNEL_PATH:-$BUILDROOT_IMAGES/bzImage}"
INITRD="${FORT_INITRD_PATH:-$BUILDROOT_IMAGES/rootfs.cpio.gz}"
OVMF="${FORT_OVMF_PATH:?FORT_OVMF_PATH must be set (path to AMD SEV OVMF binary)}"

VERIFIER_IP="${FORT_VERIFIER_IP:-192.168.100.1}"
VERIFIER_PORT="${FORT_VERIFIER_PORT:-9443}"

# Worker index (1-based). Each worker gets:
#   bridge IP  192.168.100.(ID+1)   assigned inside the VM by network_up.sh
#   tap device tap(ID-1)            must exist on the host (run setup-bridge.sh N first)
#   Ray ports  node-manager = 6380+2*ID-1, object-manager = 6380+2*ID
WORKER_ID="${FORT_WORKER_ID:-1}"
TAP_IF="tap$((WORKER_ID - 1))"
NODE_MGR_PORT=$((6380 + 2 * WORKER_ID - 1))
OBJ_MGR_PORT=$((6380 + 2 * WORKER_ID))
MONITOR_SOCK="monitor-worker-${WORKER_ID}"
MEM="3G"

CORE_START=$((WORKER_ID - 1))
sudo taskset -c "${CORE_START},$((CORE_START + 16))" $QEMU_BIN \
    -enable-kvm \
    -cpu EPYC-v4 \
    -machine q35,confidential-guest-support=sev0,memory-backend=ram1 \
    -smp 1,sockets=1,threads=1 \
    -m ${MEM},slots=5,maxmem=40G \
    -object memory-backend-memfd,id=ram1,size=${MEM},share=true,prealloc=true,reserve=true \
    -object sev-snp-guest,id=sev0,cbitpos=51,reduced-phys-bits=1,kernel-hashes=on \
    -bios $OVMF \
    -kernel "$KERNEL" \
    -initrd "$INITRD" \
    -append "console=ttyS0 root=/dev/ram0 rw verifier_ip=${VERIFIER_IP} verifier_port=${VERIFIER_PORT} atls_snp_attestation=true${FORT_RAY_OBJECT_STORE_MB:+ ray_object_store_mb=${FORT_RAY_OBJECT_STORE_MB}}${FORT_RAY_MEMORY_THRESHOLD:+ ray_memory_threshold=${FORT_RAY_MEMORY_THRESHOLD}}" \
    -netdev "tap,id=vmnic,ifname=${TAP_IF},script=no,downscript=no" \
    -device "virtio-net-pci,disable-legacy=on,iommu_platform=true,netdev=vmnic,romfile=,mac=52:54:00:12:34:$(printf '%02x' ${WORKER_ID})" \
    -nographic \
    -monitor pty \
    -monitor "unix:${MONITOR_SOCK},server,nowait"
