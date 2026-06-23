#!/bin/bash
# Watchdog for the 32-worker SEV benchmark (bench_results_32 / _bench_driver_32).
# Auto-recovers from stalls. RESUME-safe (restart skips completed CSVs).
# Run detached:  nohup setsid bash /root/bench_watchdog.sh >/dev/null 2>&1 &
# Logs decisions to /root/bench_watchdog.log. Exits when "BENCH32 DONE" appears.
set -u
LOG=/root/bench_watchdog.log
RES=/root/bench_results_32
RUNLOG=/root/bench_32.log
DRIVER=/root/_bench_driver_32.sh
STALL=1200          # 20 min of ZERO progress (no new CSV AND log not growing) -> act
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

echo "WATCHDOG START $(date)" >> "$LOG"
while true; do
    sleep 60
    # Completed cleanly?
    if grep -q "BENCH32 DONE" "$RUNLOG" 2>/dev/null; then
        echo "WATCHDOG: BENCH32 DONE detected, exiting $(date)" >> "$LOG"
        break
    fi
    now=$(date +%s)
    csv=$(ls "$RES"/*.csv 2>/dev/null | wc -l)
    drv=0; pgrep -f _bench_driver_32 >/dev/null 2>&1 && drv=1

    # (a) Driver died but run not finished -> restart (append to keep history).
    if [ "$drv" = "0" ]; then
        echo "WATCHDOG: driver DEAD (csv=$csv/448) -> restarting $(date)" >> "$LOG"
        nohup setsid bash "$DRIVER" >>"$RUNLOG" 2>&1 </dev/null &
        last_action=$now
        sleep 30
        continue
    fi

    # (b) Hard stall: no new CSV AND log silent for STALL seconds -> nudge.
    idle=$(( now - $(newest_epoch) ))
    if [ "$idle" -ge "$STALL" ] && [ $(( now - last_action )) -ge "$STALL" ]; then
        echo "WATCHDOG: STALL ${idle}s (csv=$csv/448) -> killing prte/mpiexec to force retry $(date)" >> "$LOG"
        for n in prterun prte prted mpiexec; do pkill -9 -x "$n" 2>/dev/null; done
        last_action=$now
    fi
done
