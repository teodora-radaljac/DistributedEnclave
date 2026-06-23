#!/bin/bash
# Self-detaching launcher for the benchmark watchdog. Returns immediately;
# watchdog keeps running after the ssh session closes.
nohup setsid bash /root/bench_watchdog.sh >>/root/bench_watchdog.log 2>&1 </dev/null &
exit 0
