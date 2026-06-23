# Minimal SEV-SNP OpenMPI worker (Buildroot)

Builds a tiny initramfs-based worker VM that contains **only** what is needed to
run the OpenMPI/PRRTE benchmarks under AMD SEV-SNP:

- Buildroot **glibc** toolchain + **busybox** (no systemd)
- **OpenSSH** server (for the master's PRRTE `plm ssh` to launch `prted`)
- Linux **v6.12** with SEV-SNP guest support (`CONFIG_SEV_GUEST`,
  `CONFIG_AMD_MEM_ENCRYPT`), virtio, and `CONFIG_IP_PNP` (static IP via kernel
  cmdline `ip=`)
- The OpenMPI stack + worker binaries + AMD certs + `snpguest`, provided
  **pre-built** through the rootfs overlay (copied 1:1 from the master VM, so the
  OpenMPI build is never modified)

## Layout

```
worker-ext/
  external.desc / external.mk / Config.in
  configs/worker_defconfig
  board/worker/
    linux.config            # generated on host from fort's + IP_PNP
    post-build.sh           # fix perms, make init scripts executable
    rootfs-overlay/
      root/.ssh/authorized_keys     # master's public key
      etc/ssh/sshd_config           # root key-only login
      etc/ld.so.conf.d/mpi.conf     # /root/mpi-stack/lib
      etc/profile.d/mpi.sh          # PATH + LD_LIBRARY_PATH
      etc/init.d/S00ldconfig        # rebuild ld cache at boot
      root/mpi-stack/ ...           # (payload, added by assemble_overlay.sh)
      root/src/worker_* ...         # (payload)
      root/certs/*.pem ...          # (payload)
      usr/bin/snpguest              # (payload)
assemble_overlay.sh         # pulls payload from master VM (run on host)
```

## Build (on host, NO sudo)

```sh
cd ~/br
# 1. payload from master VM
bash worker-ext/../assemble_overlay.sh     # or: bash assemble_overlay.sh
# 2. configure + build
cd buildroot
make BR2_EXTERNAL=../worker-ext worker_defconfig
make -j"$(nproc)"
# outputs: output/images/bzImage  output/images/rootfs.cpio.gz
```
