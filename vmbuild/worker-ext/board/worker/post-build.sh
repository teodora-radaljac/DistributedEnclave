#!/bin/sh
# Buildroot post-build script for the SEV-SNP MPI worker.
# $1 = $(TARGET_DIR)
set -u
TARGET_DIR="$1"

# Secure root's SSH directory and authorized_keys (overlay copies them in)
mkdir -p "${TARGET_DIR}/root/.ssh"
chmod 700 "${TARGET_DIR}/root/.ssh"
if [ -f "${TARGET_DIR}/root/.ssh/authorized_keys" ]; then
    chmod 600 "${TARGET_DIR}/root/.ssh/authorized_keys"
fi

# Make init / helper scripts executable (busybox rcS only runs +x S?? scripts).
# NB: glob must be S??* (S + 2 digits + name); plain S?? only matches 4-char names.
chmod 0755 "${TARGET_DIR}"/etc/init.d/S??* 2>/dev/null || true

exit 0
