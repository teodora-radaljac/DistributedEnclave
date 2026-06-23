#!/bin/bash
# PLAIN master VM (NO SEV-SNP) — same master.qcow2 image, launched without any
# SEV objects. Boots the full Ubuntu master (with the MPI stack + bench scripts)
# as an ordinary VM so it can drive the plain (non-confidential) worker cluster.
# Counterpart to launch_master.sh (which adds confidential-guest-support=sev0 +
# sev-snp-guest). Same tap0 / MAC / IP (192.168.100.2) so the bench scripts and
# worker hostnames work unchanged.
QEMU_BIN="qemu-system-x86_64"
OVMF="/usr/share/ovmf/OVMF.fd"
DISK="/home/teodora/images/master.qcow2"
TAP="tap0"
MAC="52:55:00:d1:55:01"
sudo nohup setsid "$QEMU_BIN" \
    -enable-kvm -cpu EPYC-v4 \
    -machine q35 \
    -smp 16,sockets=1,threads=1 \
    -m 4G \
    -bios "$OVMF" \
    -drive file="$DISK",if=none,id=vdisk0,format=qcow2 \
    -device virtio-blk-pci,drive=vdisk0,disable-legacy=on,iommu_platform=true,bootindex=1 \
    -netdev tap,id=vmnic,ifname=$TAP,script=no,downscript=no \
    -device virtio-net-pci,disable-legacy=on,iommu_platform=true,netdev=vmnic,mac=$MAC,romfile= \
    -nographic -monitor unix:monitor-master-plain,server,nowait \
    >/home/teodora/logs/master_plain.log 2>&1 </dev/null &
disown 2>/dev/null || true
echo "PLAIN master launched (tap0, 192.168.100.2, no SEV)"
