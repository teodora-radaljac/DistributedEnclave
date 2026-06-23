#!/bin/bash
# Clean PINNED N=1..14 sweep. Workers 1-14 pinned to cores 0-13 (siblings idle);
# master VM pinned to cores 14-15 -> NO SMT contention with worker cores.
# Configs A+D, RUNS=10, MAXTRIES=5, RESUME=1, bench_run_all_v3.sh.
set -u
export RES=/root/bench_results_pin14
mkdir -p "$RES"
SWEEP="1 2 3 4 5 6 7 8 9 10 11 12 13 14"
echo "BENCH14 START $(date)"
for CFG in A D; do
  echo "######## CONFIG ${CFG} ########  $(date)"
  RUNS=10 CONFIG="$CFG" RESUME=1 MAXTRIES=5 RES="$RES" WORKERS="$SWEEP" bash /root/bench_run_all_v3.sh
done
echo "BENCH14 DONE $(date)"
