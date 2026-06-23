#!/bin/bash
nohup setsid bash /root/bench_watchdog_14.sh >>/root/bench_watchdog_14.log 2>&1 </dev/null &
exit 0
