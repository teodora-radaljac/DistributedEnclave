#!/bin/bash
# Launch N SEV-SNP CVM Ray workers in parallel.
#
# Usage: ./launch-fort-workers-sev.sh <N>
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
        sudo pkill -f qemu-system-x86_64 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

echo "Starting $N SEV-SNP CVM worker(s)..."
for i in $(seq 1 "$N"); do
    log="${LOG_DIR}/worker-${i}.log"
    NODE_MGR_PORT=$((6380 + 2 * i - 1))
    OBJ_MGR_PORT=$((6380 + 2 * i))
    SVC_PORT=$((7020 + i))
    echo "  Worker $i — node-mgr :${NODE_MGR_PORT}  obj-mgr :${OBJ_MGR_PORT}  svc :${SVC_PORT}  log: worker-logs/worker-${i}.log"
    FORT_WORKER_ID="$i" bash "${SCRIPT_DIR}/launch-fort-sev.sh" >"$log" 2>&1 &
    pids+=($!)
done

echo ""
echo "All $N worker(s) launched. Waiting for Ray connections..."
echo "Monitor logs:   tail -f ${LOG_DIR}/worker-*.log"
echo "Ray status:     ray status"
echo "Run benchmark:  python analysis/bench_ray.py --workers $N"
echo ""
echo "Press Ctrl+C to stop all workers."
wait
