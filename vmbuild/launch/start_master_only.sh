#!/usr/bin/env bash
# Start ONLY the master VM (full Ubuntu SEV-SNP), detached as root.
# One outer sudo; 'sudo' is stripped from launch_master.sh and qemu is run
# under setsid (detached from tty) so it survives ssh disconnect.
set -u
mkdir -p "$HOME/logs"
sudo bash -c '
  scr=/home/teodora/launch/launch_master.sh
  sed "s/^sudo //" "$scr" > /tmp/masrun.sh
  setsid bash /tmp/masrun.sh </dev/null >/home/teodora/logs/qemu_master.log 2>&1 &
  sleep 2
'
echo MASTER_LAUNCHED
