#!/bin/bash
# PLAIN (no SEV-SNP) sweep, N=1..14, using the FIXED bench_run_all_v3.sh
# (synchronous killall cleanup + /tmp self-clean + per-point DVM sizing).
# Configs: C = no attestation + AEAD encryption ON; D = no attestation + no
# encryption (pure baseline). A/B need SEV attestation -> N/A on plain VMs.
# Single instance, NO watchdog (the watchdog spawned duplicate bench instances
# in the SEV run). Results -> /root/bench_results_plain14.
set -u
export RES=/root/bench_results_plain14
mkdir -p "$RES"
SWEEP="1 2 3 4 5 6 7 8 9 10 11 12 13 14"
echo "BENCHPLAIN14 START $(date)"
for CFG in C D; do
  echo "######## CONFIG ${CFG} ########  $(date)"
  RUNS=10 CONFIG="$CFG" RESUME=1 MAXTRIES=5 RES="$RES" WORKERS="$SWEEP" bash /root/bench_run_all_v3.sh
done
echo "BENCHPLAIN14 DONE $(date)"
