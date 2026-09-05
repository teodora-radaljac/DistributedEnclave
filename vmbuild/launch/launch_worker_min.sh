#!/bin/bash
# Minimal SEV-SNP worker - direct kernel/initramfs boot (Buildroot image).
# Mirrors launch_worker1.sh but boots bzImage + rootfs.cpio.gz instead of a
# qcow2 disk, and assigns a static IP via the kernel ip= cmdline.
#
# Usage:  bash launch_worker_min.sh <N>     # N=1..10
#   IP=192.168.100.(2+N), TAP=tapN, MAC=52:55:00:d1:55:(1+N), hostname=workerN
# Env overrides: MEM (default 1G), SMP (default 1), KERNEL, INITRD, OVMF
# NB: -smp 1 per worker => 32 workers = 32 hw threads (no oversubscription;
# this is what removes the N=6,7 CPU-contention artifact). Worker = 1 MPI rank.
set -u
N="${1:?usage: launch_worker_min.sh <N>}"
IP="192.168.100.$((2 + N))"
TAP="tap${N}"
MAC="$(printf '52:55:00:d1:55:%02x' $((1 + N)))"
HOST="worker${N}"
GW="192.168.100.1"
MEM="${MEM:-1G}"
SMP="${SMP:-1}"
QEMU_BIN="qemu-system-x86_64"
OVMF="${OVMF:-/usr/share/ovmf/OVMF.fd}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
# Buildroot tree lives beside the repo; override BR_ROOT (or KERNEL/INITRD
# directly) if it is elsewhere.  Matches the convention in launch-fort-sev.sh.
BR_ROOT="${BR_ROOT:-$REPO_ROOT/../buildroot}"
[ -d "$BR_ROOT" ] || BR_ROOT="$REPO_ROOT/../../buildroot"   # nested checkout
KERNEL="${KERNEL:-$BR_ROOT/output/images/bzImage}"
INITRD="${INITRD:-$BR_ROOT/output/images/rootfs.cpio.gz}"

sudo $QEMU_BIN \
    -enable-kvm -cpu EPYC-v4 \
    -machine q35,confidential-guest-support=sev0,memory-backend=ram1 \
    -smp ${SMP},sockets=1,threads=1 \
    -m ${MEM} \
    -object memory-backend-memfd,id=ram1,size=${MEM},share=true,prealloc=false,reserve=false \
    -object sev-snp-guest,id=sev0,cbitpos=51,reduced-phys-bits=1,kernel-hashes=on \
    -bios $OVMF \
    -kernel "$KERNEL" \
    -initrd "$INITRD" \
    -append "console=ttyS0 root=/dev/ram0 rw ip=${IP}::${GW}:255.255.255.0:${HOST}:eth0:off" \
    -netdev tap,id=vmnic,ifname=$TAP,script=no,downscript=no \
    -device virtio-net-pci,disable-legacy=on,iommu_platform=true,netdev=vmnic,mac=$MAC,romfile= \
    -nographic -monitor pty \
    -monitor unix:monitor-${HOST}-min,server,nowait
