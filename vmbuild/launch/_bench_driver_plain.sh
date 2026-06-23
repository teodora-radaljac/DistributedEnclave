#!/bin/bash
# Full 32-worker PLAIN (no SEV-SNP) benchmark sweep.
# Counterpart to _bench_driver_32.sh but for plain VMs -> configs C and D:
#   C = no attestation, AEAD encryption ON
#   D = no attestation, no encryption (baseline)
# (A/B need SEV attestation -> not applicable to plain machines.)
# Same workloads (DGEMM/EP/CG), RUNS=10, N=1..32. Separate results dir.
# RESUME=1 -> already-completed CSVs are skipped on restart.
set -u
export RES=/root/bench_results_plain_32
mkdir -p "$RES"
SWEEP="1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32"
echo "BENCHPLAIN START $(date)"
for CFG in C D; do
  echo "######## CONFIG ${CFG} ########  $(date)"
  RUNS=10 CONFIG="$CFG" RESUME=1 RES="$RES" WORKERS="$SWEEP" bash /root/bench_run_all.sh
done
echo "BENCHPLAIN DONE $(date)"
