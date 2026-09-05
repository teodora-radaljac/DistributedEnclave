#!/usr/bin/env bash
# Launch a RANGE of minimal SEV-SNP workers, each fully detached (setsid).
# Run as root. Exits immediately after spawning (qemu children are detached
# with stdin</dev/null and stdout/stderr to per-worker log files).
#
# Usage:  sudo MEM=1G bash launch_all_min.sh <FIRST> <LAST>
set -u
A="${1:-1}"; B="${2:-32}"
MEM="${MEM:-1G}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
# Buildroot tree lives beside the repo; override BR_ROOT (or KERNEL/INITRD
# directly) if it is elsewhere.  Matches the convention in launch-fort-sev.sh.
BR_ROOT="${BR_ROOT:-$REPO_ROOT/../buildroot}"
[ -d "$BR_ROOT" ] || BR_ROOT="$REPO_ROOT/../../buildroot"   # nested checkout
LOGDIR="${LOGDIR:-$HOME/logs/qemu_logs_min}"
mkdir -p "$LOGDIR"
sed 's/^sudo //' "$SCRIPT_DIR/launch_worker_min.sh" > /tmp/minrun_worker.sh
for N in $(seq "$A" "$B"); do
  MEM="$MEM" BR_ROOT="$BR_ROOT" setsid bash /tmp/minrun_worker.sh "$N" </dev/null >"$LOGDIR/qemu_worker${N}.log" 2>&1 &
  disown 2>/dev/null || true
  sleep 0.5
done
echo "launched workers ${A}..${B}"
