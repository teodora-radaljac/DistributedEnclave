#!/usr/bin/env bash
# Launch a RANGE of minimal PLAIN workers (NO SEV-SNP), each detached (setsid).
# Run as root. Exits immediately after spawning.
#
# Usage:  sudo MEM=1G bash launch_all_plain.sh <FIRST> <LAST>
set -u
A="${1:-1}"; B="${2:-32}"
MEM="${MEM:-1G}"
LOGDIR=/home/teodora/logs/qemu_logs_plain
mkdir -p "$LOGDIR"
sed 's/^sudo //' /home/teodora/launch/launch_worker_min_plain.sh > /tmp/plainrun_worker.sh
for N in $(seq "$A" "$B"); do
  MEM="$MEM" setsid bash /tmp/plainrun_worker.sh "$N" </dev/null >"$LOGDIR/qemu_worker${N}.log" 2>&1 &
  disown 2>/dev/null || true
  sleep 0.5
done
echo "launched PLAIN workers ${A}..${B}"
