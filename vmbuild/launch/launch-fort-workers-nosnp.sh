#!/bin/bash
# Launch N plain (non-SEV) VM Ray workers in parallel.
#
# Usage: ./launch-fort-workers-nosnp.sh <N>
#
# Prerequisites:
#   sudo ./setup-bridge.sh N
#   sudo -v

set -euo pipefail

N=${1:?Usage: $0 <num_workers>}
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
LOG_DIR="${REPO_ROOT}/worker-logs"
mkdir -p "$LOG_DIR"

pids=()

cleanup() {
    if [[ ${#pids[@]} -gt 0 ]]; then
        echo ""
        echo "Stopping ${#pids[@]} worker(s)..."
        for pid in "${pids[@]}"; do
            sudo kill "$pid" 2>/dev/null || true
        done
        wait 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

echo "Starting $N plain VM worker(s) (no SEV-SNP)..."
for i in $(seq 1 "$N"); do
    log="${LOG_DIR}/worker-nosnp-${i}.log"
    NODE_MGR_PORT=$((6380 + 2 * i - 1))
    OBJ_MGR_PORT=$((6380 + 2 * i))
    echo "  Worker $i — node-mgr :${NODE_MGR_PORT}  obj-mgr :${OBJ_MGR_PORT}  log: worker-logs/worker-nosnp-${i}.log"
    FORT_WORKER_ID="$i" bash "${SCRIPT_DIR}/launch-fort-nosnp.sh" >"$log" 2>&1 &
    pids+=($!)
done

echo ""
echo "All $N plain VM worker(s) launched. Waiting for Ray connections..."
echo "Monitor logs:   tail -f ${LOG_DIR}/worker-nosnp-*.log"
echo "Ray status:     ray status"
echo "Run benchmark:  python analysis/bench_ray.py --workers $N --csv results-nosnp.csv"
echo ""
echo "Press Ctrl+C to stop all workers."
wait
