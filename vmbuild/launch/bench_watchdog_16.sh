#!/bin/bash
# Watchdog for the pinned N=1..16 sweep. Restarts the driver if it dies; nudges a
# hard stall. RESUME-safe. Exits on "BENCH16 DONE". Log: /root/bench_watchdog_16.log
set -u
LOG=/root/bench_watchdog_16.log
RES=/root/bench_results_pinned_16
RUNLOG=/root/bench_16.log
DRIVER=/root/_bench_driver_16.sh
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
echo "WATCHDOG16 START $(date)" >> "$LOG"
while true; do
    sleep 60
    if grep -q "BENCH16 DONE" "$RUNLOG" 2>/dev/null; then
        echo "WATCHDOG16: BENCH16 DONE, exiting $(date)" >> "$LOG"; break
    fi
    now=$(date +%s)
    drv=0; pgrep -f _bench_driver_16 >/dev/null 2>&1 && drv=1
    csv=$(ls "$RES"/*.csv 2>/dev/null | wc -l)
    if [ "$drv" = "0" ]; then
        echo "WATCHDOG16: driver DEAD (csv=$csv/224) -> restart $(date)" >> "$LOG"
        nohup setsid bash "$DRIVER" >>"$RUNLOG" 2>&1 </dev/null &
        last_action=$now; sleep 30; continue
    fi
    idle=$(( now - $(newest_epoch) ))
    if [ "$idle" -ge "$STALL" ] && [ $(( now - last_action )) -ge "$STALL" ]; then
        echo "WATCHDOG16: STALL ${idle}s (csv=$csv/224) -> kill prte/mpiexec $(date)" >> "$LOG"
        for n in prterun prte prted mpiexec; do pkill -9 -x "$n" 2>/dev/null; done
        last_action=$now
    fi
done
