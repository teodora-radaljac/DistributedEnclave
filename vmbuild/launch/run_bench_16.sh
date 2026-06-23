#!/bin/bash
# Self-detaching launcher for the pinned N=1..16 sweep.
nohup setsid bash /root/_bench_driver_16.sh >>/root/bench_16.log 2>&1 </dev/null &
exit 0
