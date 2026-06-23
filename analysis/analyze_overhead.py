#!/usr/bin/env python3
"""A-vs-D confidential-computing overhead analysis for the SEV-SNP MPI benchmark.

Config A = attestation + AEAD message encryption (full confidential path).
Config D = no attestation, no encryption (baseline).
Both run inside SEV-SNP VMs (hardware memory encryption is always on), so the
A/D delta isolates the *application-level* attestation + channel-encryption cost.

Metrics (per run, averaged over the 10 runs):
  t_compute_max_ms : worker compute (should be ~equal A vs D -> sanity check)
  t_gather_ms      : result gather (message decryption shows up here)
  t_round_ms       : end-to-end round time (headline overhead)

DGEMM = strong scaling (data only at N dividing the matrix: 1,2,4,8 within N<=14).
EP    = weak scaling (per-worker work fixed; compute ~flat across N).
CG    = strong scaling; NOTE t_round/gather is a known unreliable gather artifact.
"""
import os, glob, csv, statistics

DIR = os.environ.get("RESDIR", "bench_results_32")
NMAX = 14
COMPUTE, GATHER, ROUND = "t_compute_max_ms", "t_gather_ms", "t_round_ms"


def load_rows(path):
    if not os.path.exists(path) or os.path.getsize(path) == 0:
        return []
    with open(path, newline="") as fh:
        lines = [l for l in fh if not l.lstrip().startswith("#")]
    if not lines:
        return []
    rdr = csv.DictReader(lines)
    return list(rdr)


def mean(rows, col):
    vals = []
    for r in rows:
        try:
            vals.append(float(r[col]))
        except (ValueError, KeyError, TypeError):
            pass
    return statistics.mean(vals) if vals else None


def fmt(x):
    return f"{x:8.1f}" if x is not None else "     -- "


def ov(a, d):
    if a is None or d is None or d == 0:
        return None
    return (a / d - 1.0) * 100.0


def analyze_ep():
    print("\n" + "=" * 78)
    print("EP  (weak scaling: per-worker work fixed; compute ~flat across N)")
    print("=" * 78)
    for size in ("2p24", "2p26", "2p28"):
        print(f"\n-- EP 2^{size[2:]}  (compute_max / round, ms) --")
        print(f"{'N':>3} | {'A_comp':>8} {'D_comp':>8} {'comp%':>6} | {'A_round':>8} {'D_round':>8} {'round%':>7}")
        ros, cos = [], []
        for n in range(1, NMAX + 1):
            a = load_rows(f"{DIR}/ep_{size}_w{n}_A.csv")
            d = load_rows(f"{DIR}/ep_{size}_w{n}_D.csv")
            if not a or not d:
                continue
            ac, dc = mean(a, COMPUTE), mean(d, COMPUTE)
            ar, dr = mean(a, ROUND), mean(d, ROUND)
            co, ro = ov(ac, dc), ov(ar, dr)
            if co is not None: cos.append(co)
            if ro is not None: ros.append(ro)
            cs = f"{co:+5.1f}" if co is not None else "   --"
            rs = f"{ro:+6.1f}" if ro is not None else "    --"
            print(f"{n:>3} | {fmt(ac)} {fmt(dc)} {cs:>6} | {fmt(ar)} {fmt(dr)} {rs:>7}")
        if ros:
            print(f"    -> avg over N: compute {statistics.mean(cos):+.1f}%   round {statistics.mean(ros):+.1f}%")


def analyze_dgemm():
    print("\n" + "=" * 78)
    print("DGEMM  (strong scaling: data only at N in {1,2,4,8} within N<=14)")
    print("=" * 78)
    for size in ("512", "1024", "2048"):
        print(f"\n-- DGEMM M={size}  (compute_max / round, ms) --")
        print(f"{'N':>3} | {'A_comp':>8} {'D_comp':>8} {'comp%':>6} | {'A_round':>8} {'D_round':>8} {'round%':>7}")
        for n in (1, 2, 4, 8, 16):
            if n > NMAX:
                continue
            a = [r for r in load_rows(f"{DIR}/dgemm_w{n}_A.csv") if r.get("matrix_size") == size]
            d = [r for r in load_rows(f"{DIR}/dgemm_w{n}_D.csv") if r.get("matrix_size") == size]
            if not a or not d:
                continue
            ac, dc = mean(a, COMPUTE), mean(d, COMPUTE)
            ar, dr = mean(a, ROUND), mean(d, ROUND)
            co, ro = ov(ac, dc), ov(ar, dr)
            cs = f"{co:+5.1f}" if co is not None else "   --"
            rs = f"{ro:+6.1f}" if ro is not None else "    --"
            print(f"{n:>3} | {fmt(ac)} {fmt(dc)} {cs:>6} | {fmt(ar)} {fmt(dr)} {rs:>7}")


def analyze_cg():
    print("\n" + "=" * 78)
    print("CG  (strong scaling; t_round/gather is an UNRELIABLE gather artifact)")
    print("=" * 78)
    for cls in ("S", "W", "A"):
        print(f"\n-- CG class {cls}  (compute_max, ms; round shown but unreliable) --")
        print(f"{'N':>3} | {'A_comp':>8} {'D_comp':>8} {'comp%':>6} | {'A_round':>8} {'D_round':>8}")
        for n in range(1, NMAX + 1):
            a = load_rows(f"{DIR}/cg_{cls}_w{n}_A.csv")
            d = load_rows(f"{DIR}/cg_{cls}_w{n}_D.csv")
            if not a or not d:
                continue
            ac, dc = mean(a, COMPUTE), mean(d, COMPUTE)
            ar, dr = mean(a, ROUND), mean(d, ROUND)
            co = ov(ac, dc)
            cs = f"{co:+5.1f}" if co is not None else "   --"
            print(f"{n:>3} | {fmt(ac)} {fmt(dc)} {cs:>6} | {fmt(ar)} {fmt(dr)}")


if __name__ == "__main__":
    print(f"### Confidential-computing overhead (A=attest+encrypt vs D=baseline)  dir={DIR}  N<={NMAX}")
    analyze_ep()
    analyze_dgemm()
    analyze_cg()
