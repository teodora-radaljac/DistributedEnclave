#!/bin/bash
# Self-detaching launcher: returns immediately, driver keeps running
# even after the ssh session that started it closes.
nohup setsid bash /root/_bench_driver_32.sh >/root/bench_32.log 2>&1 </dev/null &
exit 0
