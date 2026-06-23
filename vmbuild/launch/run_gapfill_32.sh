#!/bin/bash
# Self-detaching launcher for the gap-fill pass. Returns immediately.
nohup setsid bash /root/gap_fill_32.sh >>/root/bench_gapfill.log 2>&1 </dev/null &
exit 0
