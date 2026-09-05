#!/usr/bin/env bash
# Start ONLY the master VM (full Ubuntu SEV-SNP), detached as root.
# One outer sudo; 'sudo' is stripped from launch_master.sh and qemu is run
# under setsid (detached from tty) so it survives ssh disconnect.
set -u
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
BR_ROOT="${BR_ROOT:-$REPO_ROOT/../buildroot}"
[ -d "$BR_ROOT" ] || BR_ROOT="$REPO_ROOT/../../buildroot"   # nested checkout
LOGDIR="${LOGDIR:-$HOME/logs}"
# launch_master.sh is not part of this repo; point MASTER_SCRIPT at it.
MASTER_SCRIPT="${MASTER_SCRIPT:-$SCRIPT_DIR/launch_master.sh}"
mkdir -p "$LOGDIR"
sudo env LOGDIR="$LOGDIR" scr="$MASTER_SCRIPT" bash -c '
  sed "s/^sudo //" "$scr" > /tmp/masrun.sh
  setsid bash /tmp/masrun.sh </dev/null >"$LOGDIR/qemu_master.log" 2>&1 &
  sleep 2
'
echo MASTER_LAUNCHED
