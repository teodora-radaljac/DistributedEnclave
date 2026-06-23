#!/bin/bash
# Clean PINNED N=1..16 sweep. Uses bench_run_all_v3.sh (DVM sized to N + generous
# slots). Configs A (attest+encrypt) and D (no attest, no encrypt). RUNS=10.
# MAXTRIES=5 (cheap below the ~18 race threshold). RESUME=1 -> restart-safe.
# Results -> /root/bench_results_pinned_16/.
set -u
export RES=/root/bench_results_pinned_16
mkdir -p "$RES"
SWEEP="1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16"
echo "BENCH16 START $(date)"
for CFG in A D; do
  echo "######## CONFIG ${CFG} ########  $(date)"
  RUNS=10 CONFIG="$CFG" RESUME=1 MAXTRIES=5 RES="$RES" WORKERS="$SWEEP" bash /root/bench_run_all_v3.sh
done
echo "BENCH16 DONE $(date)"
