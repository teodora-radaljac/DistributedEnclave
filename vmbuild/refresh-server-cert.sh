#!/usr/bin/env bash
# Regenerate the ATLS server certificate and rebuild the Ray worker image.
#
# Run this whenever you need a fresh server identity (first-time setup or
# key rotation). The new cert is embedded in the measured initramfs, so
# workers will pin it and reject any server presenting a different cert.
#
# Usage:
#   ./vmbuild/refresh-server-cert.sh [buildroot-output-dir]
#
# Default buildroot output dir: <repo-root>/../buildroot/output-ray

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BR_DIR="$(cd "$REPO_ROOT/../buildroot" && pwd)"
BR_OUTPUT="${1:-"$BR_DIR/output-ray"}"

SERVER_DIR="$REPO_ROOT/fort/server"
CERT_PATH="$SERVER_DIR/atls-server.crt"
KEY_PATH="$SERVER_DIR/atls-server.key"
OVERLAY_CERT="$SCRIPT_DIR/fort-ext/board/fort/rootfs-overlay/root/atls-server.crt"

# ── Step 1: build the server binary ──────────────────────────────────────────
echo "==> Building server binary..."
(cd "$SERVER_DIR" && go build -o server .)

# ── Step 2: run the server briefly to generate a fresh cert ──────────────────
echo "==> Generating ATLS server certificate..."

rm -f "$CERT_PATH" "$KEY_PATH"

FORT_ATLS_CERT_PATH="$CERT_PATH" \
FORT_ATLS_KEY_PATH="$KEY_PATH" \
ATLS_ADDR=127.0.0.1:19443 \
    "$SERVER_DIR/server" &
SERVER_PID=$!

for i in $(seq 1 100); do
    if [[ -f "$CERT_PATH" ]]; then
        break
    fi
    sleep 0.1
done
kill "$SERVER_PID" 2>/dev/null || true
wait "$SERVER_PID" 2>/dev/null || true

if [[ ! -f "$CERT_PATH" ]]; then
    echo "ERROR: server did not write $CERT_PATH within 10 s" >&2
    exit 1
fi
echo "    Certificate written: $CERT_PATH"

# ── Step 3: copy cert into buildroot overlay ──────────────────────────────────
echo "==> Copying cert into rootfs overlay..."
cp "$CERT_PATH" "$OVERLAY_CERT"
echo "    Overlay cert: $OVERLAY_CERT"

# ── Step 4: rebuild worker image ──────────────────────────────────────────────
echo "==> Rebuilding worker image (fort-client-rebuild + all)..."
echo "    Buildroot output: $BR_OUTPUT"
make -C "$BR_DIR" O="$BR_OUTPUT" fort-client-rebuild all

echo ""
echo "Done. New ATLS identity is baked into the worker image."
echo "  Server cert : $CERT_PATH"
echo "  Server key  : $KEY_PATH"
echo "  Start the server with:"
echo "    FORT_ATLS_CERT_PATH=$CERT_PATH FORT_ATLS_KEY_PATH=$KEY_PATH \\"
echo "    $SERVER_DIR/server"
