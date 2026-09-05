#!/bin/bash
# Minimal PLAIN worker (NO SEV-SNP) - direct kernel/initramfs boot.
# Identical to launch_worker_min.sh but with the SEV-SNP bits removed:
#   - no  confidential-guest-support=sev0 / memory-backend=ram1 on -machine
#   - no  memory-backend-memfd object
#   - no  sev-snp-guest object (and no kernel-hashes)
# Everything else (CPU model EPYC-v4, OVMF, -smp 1, 1G, taps/IP/MAC/hostname,
# kernel/initrd, monitor) stays identical so the ONLY difference vs the SEV run
# is the absence of hardware memory encryption + attestation. This is the
# "plain machines" baseline (prev phase2_plain), now on the minimal BR image.
#
# Usage:  bash launch_worker_min_plain.sh <N>     # N=1..32
#   IP=192.168.100.(2+N), TAP=tapN, MAC=52:55:00:d1:55:(1+N), hostname=workerN
# Env overrides: MEM (default 1G), SMP (default 1), KERNEL, INITRD, OVMF
set -u
N="${1:?usage: launch_worker_min_plain.sh <N>}"
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
    -machine q35 \
    -smp ${SMP},sockets=1,threads=1 \
    -m ${MEM} \
    -bios $OVMF \
    -kernel "$KERNEL" \
    -initrd "$INITRD" \
    -append "console=ttyS0 root=/dev/ram0 rw ip=${IP}::${GW}:255.255.255.0:${HOST}:eth0:off" \
    -netdev tap,id=vmnic,ifname=$TAP,script=no,downscript=no \
    -device virtio-net-pci,disable-legacy=on,iommu_platform=true,netdev=vmnic,mac=$MAC,romfile= \
    -nographic -monitor pty \
    -monitor unix:monitor-${HOST}-plain,server,nowait
