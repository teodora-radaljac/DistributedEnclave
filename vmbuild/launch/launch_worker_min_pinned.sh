#!/bin/bash
# PINNED minimal SEV-SNP worker - direct kernel/initramfs boot (Buildroot image).
# Same as launch_worker_min.sh but pins the worker's qemu (1 vCPU) to host CPU N-1,
# giving worker k a dedicated physical core's primary thread (cores 0..15 for k=1..16).
# Master/OS go on CPUs 16-31 (SMT siblings). => exact "1 worker = 1 core" layout.
#
# Usage:  bash launch_worker_min_pinned.sh <N>     # N=1..16
# Env overrides: MEM (default 1G), SMP (default 1), PIN (default N-1), KERNEL, INITRD, OVMF
set -u
N="${1:?usage: launch_worker_min_pinned.sh <N>}"
IP="192.168.100.$((2 + N))"
TAP="tap${N}"
MAC="$(printf '52:55:00:d1:55:%02x' $((1 + N)))"
HOST="worker${N}"
GW="192.168.100.1"
MEM="${MEM:-1G}"
SMP="${SMP:-1}"
PIN="${PIN:-$((N - 1))}"
QEMU_BIN="qemu-system-x86_64"
OVMF="${OVMF:-/usr/share/ovmf/OVMF.fd}"
KERNEL="${KERNEL:-/home/teodora/br/buildroot/output/images/bzImage}"
INITRD="${INITRD:-/home/teodora/br/buildroot/output/images/rootfs.cpio.gz}"

sudo taskset -c "${PIN}" $QEMU_BIN \
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
