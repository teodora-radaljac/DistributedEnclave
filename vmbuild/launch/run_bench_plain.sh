#!/bin/bash
# Self-detaching launcher for the PLAIN sweep. Returns immediately;
# driver keeps running after the ssh session closes.
nohup setsid bash /root/_bench_driver_plain.sh >/root/bench_plain.log 2>&1 </dev/null &
exit 0
