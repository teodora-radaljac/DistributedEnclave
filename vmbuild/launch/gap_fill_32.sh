#!/bin/bash
# GAP-FILL pass for the 32-worker SEV run. Run AFTER the main A+D sweep finishes.
# RESUME=1 -> skips every point that already has data; retries ONLY the missing/
# failed ones (failed points have NO CSV). MAXTRIES=5 + two rounds so the flaky
# heavy-EP points (prte segfault in enrollment) get many fresh attempts.
# Detached:  bash /root/run_gapfill_32.sh   (log /root/bench_gapfill.log)
set -u
export RES=/root/bench_results_32
SWEEP="1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32"
echo "GAPFILL START $(date)"
for round in 1 2; do
  echo "==== gap-fill round ${round} ====  $(date)"
  for CFG in A D; do
    echo "-------- CONFIG ${CFG} (round ${round}) --------  $(date)"
    RUNS=10 CONFIG="$CFG" RESUME=1 MAXTRIES=5 RES="$RES" WORKERS="$SWEEP" bash /root/bench_run_all.sh
  done
done
echo "GAPFILL DONE $(date)"
