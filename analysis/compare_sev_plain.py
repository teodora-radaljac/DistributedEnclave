#!/usr/bin/env python3
"""SEV-SNP vs PLAIN comparison — isolates the confidential-computing cost layers.

Two complete datasets (N=1..14, 10 runs/point, 1 worker = 1 dedicated core):
  bench_results_pin14  : SEV-SNP VMs   (config A=attest+enc, D=noatt,noenc)
  bench_results_plain14: PLAIN VMs     (config C=noatt,enc,  D=noatt,noenc)

Key comparisons:
  D_sev  vs D_plain  -> SEV-SNP HARDWARE memory-encryption cost (VM level)
  C_plain vs D_plain -> SOFTWARE AEAD channel-encryption cost (no SEV)
  A_sev  vs D_sev    -> attestation + channel encryption inside SEV (done earlier)

Metric: t_compute_max_ms (col 6) and t_round_ms (col 8), averaged over 10 runs.
"""
import os, csv, statistics

SEV = "bench_results_pin14"
PLAIN = "bench_results_plain14"
NMAX = 14
COMPUTE, ROUND = "t_compute_max_ms", "t_round_ms"


def load(path):
    if not os.path.exists(path) or os.path.getsize(path) == 0:
        return []
    with open(path, newline="") as fh:
        lines = [l for l in fh if not l.lstrip().startswith("#")]
    return list(csv.DictReader(lines)) if lines else []


def mean(rows, col, msize=None):
    vals = []
    for r in rows:
        if msize is not None and r.get("matrix_size") != msize:
            continue
        try:
            vals.append(float(r[col]))
        except (ValueError, KeyError, TypeError):
            pass
    return statistics.mean(vals) if vals else None


def ov(a, b):
    return (a / b - 1.0) * 100.0 if (a is not None and b and b != 0) else None


def fmt(x):
    return f"{x:8.0f}" if x is not None else "    --  "


def pct(x):
    return f"{x:+6.1f}" if x is not None else "   -- "


def cmp_ep():
    print("\n" + "=" * 70)
    print("EP  D_sev vs D_plain = SEV hw memory-encryption cost (compute-bound)")
    print("=" * 70)
    for size in ("2p24", "2p26", "2p28"):
        print(f"\n-- EP 2^{size[2:]}  compute (ms) --")
        print(f"{'N':>3} | {'D_sev':>8} {'D_plain':>8} {'SEV%':>6} | {'C_plain':>8} {'C/D%':>6}")
        sev_ov, sw_ov = [], []
        for n in range(1, NMAX + 1):
            ds = mean(load(f"{SEV}/ep_{size}_w{n}_D.csv"), COMPUTE)
            dp = mean(load(f"{PLAIN}/ep_{size}_w{n}_D.csv"), COMPUTE)
            cp = mean(load(f"{PLAIN}/ep_{size}_w{n}_C.csv"), COMPUTE)
            o1, o2 = ov(ds, dp), ov(cp, dp)
            if o1 is not None: sev_ov.append(o1)
            if o2 is not None: sw_ov.append(o2)
            print(f"{n:>3} | {fmt(ds)} {fmt(dp)} {pct(o1)} | {fmt(cp)} {pct(o2)}")
        if sev_ov:
            print(f"    -> avg SEV hw cost {statistics.mean(sev_ov):+.1f}%   sw-enc cost {statistics.mean(sw_ov):+.1f}%")


def cmp_dgemm():
    print("\n" + "=" * 70)
    print("DGEMM  D_sev vs D_plain = SEV hw memory-encryption cost (memory-bound)")
    print("=" * 70)
    for size in ("512", "1024", "2048"):
        print(f"\n-- DGEMM M={size}  compute / round (ms) --")
        print(f"{'N':>3} | {'Dsev_c':>8} {'Dpln_c':>8} {'SEV%':>6} | {'Dsev_r':>8} {'Dpln_r':>8} {'SEV_r%':>6}")
        for n in (1, 2, 4, 8):
            ds = load(f"{SEV}/dgemm_w{n}_D.csv")
            dp = load(f"{PLAIN}/dgemm_w{n}_D.csv")
            sc, pc = mean(ds, COMPUTE, size), mean(dp, COMPUTE, size)
            sr, pr = mean(ds, ROUND, size), mean(dp, ROUND, size)
            print(f"{n:>3} | {fmt(sc)} {fmt(pc)} {pct(ov(sc, pc))} | {fmt(sr)} {fmt(pr)} {pct(ov(sr, pr))}")


if __name__ == "__main__":
    print("### SEV-SNP vs PLAIN  (D=baseline both; isolates SEV hardware cost)")
    cmp_ep()
    cmp_dgemm()
