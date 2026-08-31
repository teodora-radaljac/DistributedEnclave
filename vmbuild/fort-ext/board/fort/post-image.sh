#!/bin/sh
set -eu

verifier_ip="${FORT_VERIFIER_IP:-10.0.2.2}"
verifier_port="${FORT_VERIFIER_PORT:-9443}"
# IP the Ray worker advertises to the head. Must be reachable FROM the host;
# 127.0.0.1 works when head and QEMU run on the same machine because QEMU
# hostfwd binds to 0.0.0.0 on the host. Set FORT_RAY_WORKER_IP to the host's
# LAN IP when the head runs on a different machine.
ray_worker_ip="${FORT_RAY_WORKER_IP:-127.0.0.1}"
binaries_dir="${BINARIES_DIR:-${1:?missing Buildroot images directory}}"
script="${binaries_dir}/start-qemu.sh"

cat > "${script}" <<EOF
#!/bin/sh
set -eu

dir=\$(dirname "\$0")
dir=\$(cd "\${dir}" && pwd)

qemu=\${FORT_QEMU:-qemu-system-x86_64}
verifier_ip=\${FORT_VERIFIER_IP:-${verifier_ip}}
verifier_port=\${FORT_VERIFIER_PORT:-${verifier_port}}
ray_worker_ip=\${FORT_RAY_WORKER_IP:-${ray_worker_ip}}

exec "\${qemu}" \\
	-M q35 \\
	-cpu max \\
	-m \${FORT_QEMU_MEMORY:-2048M} \\
	-kernel "\${dir}/bzImage" \\
	-initrd "\${dir}/rootfs.cpio.gz" \\
	-append "console=ttyS0 root=/dev/ram0 rw verifier_ip=\${verifier_ip} verifier_port=\${verifier_port} ray_worker_ip=\${ray_worker_ip}" \\
	-netdev user,id=net0,hostfwd=tcp::6381-:6381,hostfwd=tcp::6382-:6382 \\
	-device virtio-net-pci,netdev=net0 \\
	-nographic
EOF

chmod +x "${script}"
