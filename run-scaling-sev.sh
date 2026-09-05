#!/bin/bash
# run-scaling-sev.sh — SEV-SNP Ray scaling study: N=1..WORKERS, RUNS outer runs each.
#
# Boots all CVMs once, runs all workloads for every N in 1..WORKERS, then tears
# everything down. No VM restarts between scaling points.
#
# Usage: ./run-scaling-sev.sh [WORKERS [RUNS [START_N [cg-only [CG_CLASSES]]]]]
#   WORKERS    – total CVMs to boot and max N (default: 14)
#   RUNS       – outer runs per scaling point (default: 10)
#   START_N    – first N to run (default: 1; use to resume a partial run)
#   cg-only    – pass literal "cg-only" to skip EP and DGEMM
#   CG_CLASSES – comma-separated classes e.g. "B,C"
#
# Env:
#   WORKLOADS  – optional subset, e.g. WORKLOADS=STREAM to validate one kernel
#
# Prerequisites:
#   1. Bridge/tap interfaces:  sudo ./vmbuild/launch/setup-bridge.sh WORKERS
#   2. sudo pre-authenticated: sudo -v
#   3. Server binary built:    cd fort/server && go build -o server .
#
# Output:
#   results-scaling/scaling-sev-YYYYMMDD-HHMMSS.csv
#   verifier.log

set -euo pipefail

WORKERS="${1:-14}"
RUNS="${2:-10}"
START_N="${3:-1}"
CG_ONLY="${4:-}"
CG_CLASSES="${5:-}"
SCALING="$(seq "$START_N" "$WORKERS" | paste -sd,)"
OUTDIR="results-scaling"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CERT_DIR="$SCRIPT_DIR/fort/server"
SERVER_BIN="$CERT_DIR/server"

mkdir -p "$OUTDIR"

echo "Fort SEV-SNP Ray scaling study"
echo "  Workers: $WORKERS   Scaling: N=$START_N..$WORKERS   Runs per point: $RUNS"
echo "  Output:  $OUTDIR/"
echo ""

if [[ ! -x "$SERVER_BIN" ]]; then
    echo "ERROR: server binary not found at $SERVER_BIN" >&2
    echo "       Build it:  cd fort/server && go build -o server ." >&2
    exit 1
fi

RAY_HEAD_IP="${RAY_HEAD_IP:-$(hostname -I | awk '{print $1}')}"
SERVER_PID=""
LAUNCHER_PID=""

cleanup() {
    echo ""
    echo "Shutting down..."
    if [[ -n "$LAUNCHER_PID" ]]; then
        kill "$LAUNCHER_PID" 2>/dev/null || true
        wait "$LAUNCHER_PID" 2>/dev/null || true
    fi
    sudo pkill -f qemu-system-x86_64 2>/dev/null || true
    ray stop --force >/dev/null 2>&1 || true
    if [[ -n "$SERVER_PID" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

rm -f "$CERT_DIR/ca.crt" "$CERT_DIR/head.crt" "$CERT_DIR/head.key"

echo "Starting verifier server (AMD chain verification, no measurement pin)..."
(cd "$CERT_DIR" && exec env \
    RAY_HEAD_IP="$RAY_HEAD_IP" \
    ./server) > "$SCRIPT_DIR/verifier.log" 2>&1 &
SERVER_PID=$!

for i in $(seq 1 20); do
    [[ -f "$CERT_DIR/ca.crt" ]] && break
    sleep 0.5
done
if [[ ! -f "$CERT_DIR/ca.crt" ]]; then
    echo "ERROR: verifier did not start within 10 s — check verifier.log" >&2
    exit 1
fi
echo "  Verifier ready ✓  (log → verifier.log)"

export RAY_USE_TLS=1
export RAY_TLS_SERVER_CERT="$CERT_DIR/head.crt"
export RAY_TLS_SERVER_KEY="$CERT_DIR/head.key"
export RAY_TLS_CA_CERT="$CERT_DIR/ca.crt"

echo "Starting Ray head (--num-cpus=0)..."
ray stop --force >/dev/null 2>&1 || true
ray start --head --port=6379 --num-cpus=0 \
    --node-ip-address="$RAY_HEAD_IP" \
    --disable-usage-stats >/dev/null 2>&1
sleep 2
echo "  Ray head ready ✓"
echo ""

echo "Launching $WORKERS SEV-SNP CVMs..."
"$SCRIPT_DIR/vmbuild/launch/launch-fort-workers-sev.sh" "$WORKERS" &
LAUNCHER_PID=$!
echo "  Monitor: tail -f worker-logs/worker-*.log"
echo ""

TIMESTAMP=$(date +%Y%m%d-%H%M%S)
CSV="$OUTDIR/scaling-sev-${TIMESTAMP}.csv"

echo "Starting scaling benchmark  (N=$START_N..$WORKERS × $RUNS runs)"
echo ""

python "$SCRIPT_DIR/analysis/bench_ray.py" \
    --scaling "$SCALING" \
    --runs    "$RUNS" \
    --timeout 600 \
    --csv     "$CSV" \
    ${WORKLOADS:+--workloads "$WORKLOADS"} \
    ${CG_ONLY:+--cg-only} \
    ${CG_CLASSES:+--cg-classes "$CG_CLASSES"}

echo ""
echo "═══ Scaling study complete ══════════════════════════"
echo "  CSV:  $CSV"
printf "  Rows: %d\n" "$(tail -n +2 "$CSV" | wc -l)"
