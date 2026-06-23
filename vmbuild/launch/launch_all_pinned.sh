#!/usr/bin/env bash
# Launch a RANGE of PINNED minimal SEV-SNP workers (worker k -> CPU k-1), detached.
# Run as root.  Usage:  sudo MEM=1G bash launch_all_pinned.sh <FIRST> <LAST>
set -u
A="${1:-1}"; B="${2:-16}"
MEM="${MEM:-1G}"
LOGDIR=/home/teodora/logs/qemu_logs_pinned
mkdir -p "$LOGDIR"
sed 's/^sudo //' /home/teodora/launch/launch_worker_min_pinned.sh > /tmp/pinrun_worker.sh
for N in $(seq "$A" "$B"); do
  MEM="$MEM" setsid bash /tmp/pinrun_worker.sh "$N" </dev/null >"$LOGDIR/qemu_worker${N}.log" 2>&1 &
  disown 2>/dev/null || true
  sleep 0.5
done
echo "launched PINNED workers ${A}..${B}"
