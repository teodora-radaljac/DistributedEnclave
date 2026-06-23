#!/bin/bash
# Full 32-worker benchmark sweep on the minimal SEV-SNP cluster.
# Same parameters as phase1_sev, extended to N=1..32:
#   configs A (attest+encrypt) and D (no attest, no encrypt)
#   workloads DGEMM(512,1024,2048), EP(2^24,2^26,2^28), CG(S,W,A)
#   RUNS=10 per point. RESUME=1 -> already-completed CSVs are skipped on restart.
set -u
export RES=/root/bench_results_32
mkdir -p "$RES"
SWEEP="1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32"
echo "BENCH32 START $(date)"
for CFG in A D; do
  echo "######## CONFIG ${CFG} ########  $(date)"
  RUNS=10 CONFIG="$CFG" RESUME=1 RES="$RES" WORKERS="$SWEEP" bash /root/bench_run_all.sh
done
echo "BENCH32 DONE $(date)"
