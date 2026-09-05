#!/usr/bin/env bash
# Launch a RANGE of PINNED minimal SEV-SNP workers (worker k -> CPU k-1), detached.
# Run as root.  Usage:  sudo MEM=1G bash launch_all_pinned.sh <FIRST> <LAST>
set -u
A="${1:-1}"; B="${2:-16}"
MEM="${MEM:-1G}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
# Buildroot tree lives beside the repo; override BR_ROOT (or KERNEL/INITRD
# directly) if it is elsewhere.  Matches the convention in launch-fort-sev.sh.
BR_ROOT="${BR_ROOT:-$REPO_ROOT/../buildroot}"
[ -d "$BR_ROOT" ] || BR_ROOT="$REPO_ROOT/../../buildroot"   # nested checkout
LOGDIR="${LOGDIR:-$HOME/logs/qemu_logs_pinned}"
mkdir -p "$LOGDIR"
sed 's/^sudo //' "$SCRIPT_DIR/launch_worker_min_pinned.sh" > /tmp/pinrun_worker.sh
for N in $(seq "$A" "$B"); do
  MEM="$MEM" BR_ROOT="$BR_ROOT" setsid bash /tmp/pinrun_worker.sh "$N" </dev/null >"$LOGDIR/qemu_worker${N}.log" 2>&1 &
  disown 2>/dev/null || true
  sleep 0.5
done
echo "launched PINNED workers ${A}..${B}"
