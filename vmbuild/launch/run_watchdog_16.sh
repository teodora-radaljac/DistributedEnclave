#!/bin/bash
# Self-detaching launcher for the N=1..16 watchdog.
nohup setsid bash /root/bench_watchdog_16.sh >>/root/bench_watchdog_16.log 2>&1 </dev/null &
exit 0
