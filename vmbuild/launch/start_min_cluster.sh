#!/usr/bin/env bash
# Start N minimal SEV-SNP workers (initramfs direct kernel boot).
# Master stays a full Ubuntu VM (start it separately with launch_master.sh).
#
# NOTE: minimal workers reuse tap1..tapN / IP 192.168.100.3.. (same as the
# Ubuntu workers). Stop the Ubuntu workers first (keep master) before using
# these, otherwise the TAPs/IPs collide.
#
# One outer sudo (auth with tty); 'sudo' is stripped from the launch script so
# qemu runs directly as root under setsid (avoids 'A terminal is required').
#
# Usage:  NWORKERS=10 MEM=3G bash start_min_cluster.sh
set -u
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
BR_ROOT="${BR_ROOT:-$REPO_ROOT/../buildroot}"
[ -d "$BR_ROOT" ] || BR_ROOT="$REPO_ROOT/../../buildroot"   # nested checkout
NWORKERS="${NWORKERS:-2}"
MEM="${MEM:-4G}"
LOGDIR="${LOGDIR:-$HOME/logs/qemu_logs_min}"
mkdir -p "$LOGDIR"
echo "=== sudo (kucajte lozinku ako se trazi) ==="
sudo env MEM="$MEM" NWORKERS="$NWORKERS" LOGDIR="$LOGDIR" \
     BR_ROOT="$BR_ROOT" scr="$SCRIPT_DIR/launch_worker_min.sh" bash -c '
mkdir -p "$LOGDIR"
sed "s/^sudo //" "$scr" > /tmp/minrun_worker.sh
for N in $(seq 1 "$NWORKERS"); do
  echo "--- worker${N} (MEM=$MEM) ---"
  BR_ROOT="$BR_ROOT" setsid bash /tmp/minrun_worker.sh "$N" </dev/null >"$LOGDIR/qemu_worker${N}.log" 2>&1 &
  sleep 1
done
sleep 4
'
echo MIN_WORKERS_POKRENUTI
