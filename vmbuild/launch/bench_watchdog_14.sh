#!/bin/bash
# Watchdog for the pinned N=1..14 sweep. Restarts driver if it dies; nudges stalls.
set -u
LOG=/root/bench_watchdog_14.log
RES=/root/bench_results_pin14
RUNLOG=/root/bench_14.log
DRIVER=/root/_bench_driver_14.sh
STALL=1200
last_action=0
newest_epoch() {
    local newest=0 f m
    for f in "$RES"/*.csv "$RUNLOG"; do
        [ -e "$f" ] || continue
        m=$(stat -c %Y "$f" 2>/dev/null || echo 0)
        [ "$m" -gt "$newest" ] && newest=$m
    done
    echo "$newest"
}
echo "WATCHDOG14 START $(date)" >> "$LOG"
while true; do
    sleep 60
    if grep -q "BENCH14 DONE" "$RUNLOG" 2>/dev/null; then
        echo "WATCHDOG14: DONE, exiting $(date)" >> "$LOG"; break
    fi
    now=$(date +%s)
    drv=0; pgrep -f _bench_driver_14 >/dev/null 2>&1 && drv=1
    csv=$(ls "$RES"/*.csv 2>/dev/null | wc -l)
    if [ "$drv" = "0" ]; then
        echo "WATCHDOG14: driver DEAD (csv=$csv/196) -> restart $(date)" >> "$LOG"
        nohup setsid bash "$DRIVER" >>"$RUNLOG" 2>&1 </dev/null &
        last_action=$now; sleep 30; continue
    fi
    idle=$(( now - $(newest_epoch) ))
    if [ "$idle" -ge "$STALL" ] && [ $(( now - last_action )) -ge "$STALL" ]; then
        echo "WATCHDOG14: STALL ${idle}s -> kill prte/mpiexec $(date)" >> "$LOG"
        for n in prterun prte prted mpiexec; do pkill -9 -x "$n" 2>/dev/null; done
        last_action=$now
    fi
done
