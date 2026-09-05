#!/bin/bash
# run-both-campaigns.sh — SEV-SNP campaign followed by the plain-VM campaign.
#
# Runs the two configurations back-to-back on the same host in one sitting.
# That ordering matters: within a campaign the run-to-run CV is ~0.5%, but
# campaigns started hours apart have drifted by ~10%, which is larger than
# the SEV-SNP effect being measured.  Back-to-back keeps host conditions as
# close as they can be without interleaving.
#
# Usage: ./run-both-campaigns.sh [WORKERS [RUNS]]
#   WORKERS – CVMs to boot and max N (default: 13)
#   RUNS    – runs per scaling point  (default: 10)
#
# Env:
#   FORT_OVMF_PATH – REQUIRED, path to the AMD SEV OVMF binary
#   WORKLOADS      – optional subset, e.g. WORKLOADS=STREAM,CG
#   CG_CLASSES     – NAS CG classes, e.g. CG_CLASSES=C  (default: A)
#   ORDER          – sev-first (default) | plain-first; which campaign runs
#                    first.  Reverse it to test for campaign-order bias.
#   SKIP_SEV=1     – run only the plain campaign
#   SKIP_PLAIN=1   – run only the SEV campaign
#
# Example — probe CG at class C on both configurations:
#   WORKLOADS=CG CG_CLASSES=C ./run-both-campaigns.sh 13 3
#
# Example — EP-only control with the campaign order reversed:
#   WORKLOADS=EP ORDER=plain-first ./run-both-campaigns.sh 13 3
#
# Prerequisites (same as the individual scripts):
#   sudo ./vmbuild/launch/setup-bridge.sh WORKERS
#   sudo -v
#   cd fort/server && go build -o server .

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WORKERS="${1:-13}"
RUNS="${2:-10}"

: "${FORT_OVMF_PATH:?FORT_OVMF_PATH must be set (path to AMD SEV OVMF binary)}"
if [[ ! -f "$FORT_OVMF_PATH" ]]; then
    echo "error: FORT_OVMF_PATH does not exist: $FORT_OVMF_PATH" >&2
    exit 1
fi

# Whichever configuration runs second inherits whatever host state the first
# left behind, which showed up as a systematic ~1-5% bias in the compute-bound
# EP result (plain, always second, was consistently slower).  ORDER=plain-first
# reverses the sequence: if the sign of the penalty flips with it, the bias is
# from ordering rather than from SEV-SNP.
ORDER="${ORDER:-sev-first}"
case "$ORDER" in
    sev-first)   PHASE_ORDER=(sev plain) ;;
    plain-first) PHASE_ORDER=(plain sev) ;;
    *) echo "error: ORDER must be 'sev-first' or 'plain-first', got '$ORDER'" >&2
       exit 1 ;;
esac

STARTED_AT="$(date +%s)"
LOG="$SCRIPT_DIR/results-scaling/campaign-$(date +%Y%m%d-%H%M%S).log"
mkdir -p "$(dirname "$LOG")"

# VMs are booted with `sudo taskset ... qemu-system-x86_64` and torn down with
# `sudo pkill`.  sudo's timestamp expires after ~15 min by default, but phase 2
# boots its VMs well over an hour after we authenticate here — without a
# keepalive it would block on a password prompt in the middle of an unattended
# run.  Authenticate once, then refresh in the background until we exit.
echo "Authenticating for VM launch/teardown (sudo)..."
sudo -v
( while true; do
      sleep 60
      kill -0 "$$" 2>/dev/null || exit 0   # parent gone: stop refreshing
      sudo -n true 2>/dev/null || exit 0
  done ) &
SUDO_KEEPALIVE_PID=$!
cleanup() {
    kill "$SUDO_KEEPALIVE_PID" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

banner() {
    echo ""
    echo "═══════════════════════════════════════════════════════════"
    echo "  $*"
    echo "  $(date '+%Y-%m-%d %H:%M:%S')"
    echo "═══════════════════════════════════════════════════════════"
    echo ""
}

# Newest CSV matching a prefix, so we can report exactly what each phase wrote.
newest_csv() {
    ls -t "$SCRIPT_DIR/results-scaling/$1"-*.csv 2>/dev/null | head -1
}

SEV_CSV=""
PLAIN_CSV=""
SEV_STATUS="skipped"
PLAIN_STATUS="skipped"

# run-scaling-*.sh take CG_CLASSES as the 5th positional argument, after
# START_N and the cg-only flag, so those two are passed through as defaults.
PHASE_ARGS=("$WORKERS" "$RUNS")
if [[ -n "${CG_CLASSES:-}" ]]; then
    PHASE_ARGS+=(1 "" "$CG_CLASSES")
fi

# Drop skipped configurations, then number the phases that actually run.
PHASES=()
for k in "${PHASE_ORDER[@]}"; do
    [[ "$k" == sev   && -n "${SKIP_SEV:-}"   ]] && continue
    [[ "$k" == plain && -n "${SKIP_PLAIN:-}" ]] && continue
    PHASES+=("$k")
done
TOTAL_PHASES=${#PHASES[@]}
PHASE_NUM=0

# Campaigns are long; a failure in the first must not silently swallow the
# second, so each is run with errexit suspended and its status recorded.
run_phase() {
    local kind="$1" script label rc
    PHASE_NUM=$((PHASE_NUM + 1))
    if [[ "$kind" == sev ]]; then
        script="run-scaling-sev.sh";   label="SEV-SNP"
    else
        script="run-scaling-nosnp.sh"; label="plain-VM"
    fi
    banner "Phase $PHASE_NUM/$TOTAL_PHASES — $label campaign (N=1..$WORKERS x $RUNS runs)"
    set +e
    "$SCRIPT_DIR/$script" "${PHASE_ARGS[@]}"
    rc=$?
    set -e
    if [[ "$kind" == sev ]]; then
        SEV_CSV="$(newest_csv scaling-sev)"
        if [[ $rc -eq 0 ]]; then SEV_STATUS="ok"; else SEV_STATUS="FAILED (exit $rc)"; fi
        echo "Phase $PHASE_NUM result: $SEV_STATUS"
    else
        PLAIN_CSV="$(newest_csv scaling-nosnp)"
        if [[ $rc -eq 0 ]]; then PLAIN_STATUS="ok"; else PLAIN_STATUS="FAILED (exit $rc)"; fi
        echo "Phase $PHASE_NUM result: $PLAIN_STATUS"
    fi
}

for k in "${PHASES[@]}"; do
    run_phase "$k"
done

ELAPSED=$(( $(date +%s) - STARTED_AT ))

{
    echo "campaign pair finished $(date '+%Y-%m-%d %H:%M:%S')"
    echo "workers=$WORKERS runs=$RUNS workloads=${WORKLOADS:-all} cg_classes=${CG_CLASSES:-A} order=$ORDER"
    echo "sev   : $SEV_STATUS  ${SEV_CSV:-(none)}"
    echo "plain : $PLAIN_STATUS  ${PLAIN_CSV:-(none)}"
    echo "elapsed: $((ELAPSED / 3600))h $(((ELAPSED % 3600) / 60))m"
} | tee "$LOG"

banner "Both campaigns complete — $((ELAPSED / 3600))h $(((ELAPSED % 3600) / 60))m"
echo "  SEV  : $SEV_STATUS"
[[ -n "$SEV_CSV"   ]] && printf "         %s  (%d rows)\n" "$SEV_CSV"   "$(tail -n +2 "$SEV_CSV" | wc -l)"
echo "  plain: $PLAIN_STATUS"
[[ -n "$PLAIN_CSV" ]] && printf "         %s  (%d rows)\n" "$PLAIN_CSV" "$(tail -n +2 "$PLAIN_CSV" | wc -l)"
echo "  log  : $LOG"
echo ""

# Non-zero exit if either phase failed, so this is safe to chain or cron.
[[ "$SEV_STATUS"   == ok || "$SEV_STATUS"   == skipped ]] || exit 1
[[ "$PLAIN_STATUS" == ok || "$PLAIN_STATUS" == skipped ]] || exit 1
exit 0
