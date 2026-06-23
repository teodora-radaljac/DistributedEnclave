#!/usr/bin/env bash
# Launch a RANGE of minimal SEV-SNP workers, each fully detached (setsid).
# Run as root. Exits immediately after spawning (qemu children are detached
# with stdin</dev/null and stdout/stderr to per-worker log files).
#
# Usage:  sudo MEM=1G bash launch_all_min.sh <FIRST> <LAST>
set -u
A="${1:-1}"; B="${2:-32}"
MEM="${MEM:-1G}"
LOGDIR=/home/teodora/logs/qemu_logs_min
mkdir -p "$LOGDIR"
sed 's/^sudo //' /home/teodora/launch/launch_worker_min.sh > /tmp/minrun_worker.sh
for N in $(seq "$A" "$B"); do
  MEM="$MEM" setsid bash /tmp/minrun_worker.sh "$N" </dev/null >"$LOGDIR/qemu_worker${N}.log" 2>&1 &
  disown 2>/dev/null || true
  sleep 0.5
done
echo "launched workers ${A}..${B}"
