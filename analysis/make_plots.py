#!/usr/bin/env python3
# Generise standardne benchmark grafike iz lokalnih CSV rezultata.
#   bench_results_pin14   = SEV-SNP (config A=atest+enc, D=baseline)
#   bench_results_plain14 = plain   (config C=enc, D=baseline)
# Izlaz: plots/*.png
import os, csv, statistics
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

SEV, PLAIN, OUT = "bench_results_pin14", "bench_results_plain14", "plots"
NMAX = 14
COMPUTE, ROUND = "t_compute_max_ms", "t_round_ms"
os.makedirs(OUT, exist_ok=True)


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


def fig1_dgemm_strong():
    plt.figure(figsize=(7, 5))
    Ns = [1, 2, 4, 8]
    for size, mk in zip(("512", "1024", "2048"), ("o", "s", "^")):
        base = mean(load(f"{SEV}/dgemm_w1_A.csv"), COMPUTE, size)
        xs, ys = [], []
        for n in Ns:
            v = mean(load(f"{SEV}/dgemm_w{n}_A.csv"), COMPUTE, size)
            if v and base:
                xs.append(n); ys.append(base / v)
        plt.plot(xs, ys, mk + "-", label=f"M={size}")
    plt.plot([1, 8], [1, 8], "k--", alpha=0.5, label="ideal (linear)")
    plt.xlabel("Number of workers N"); plt.ylabel("Speedup  T(1)/T(N)")
    plt.title("DGEMM — strong scaling (SEV-SNP, attest+encrypt)")
    plt.legend(); plt.grid(True, alpha=0.3); plt.xticks(Ns)
    plt.savefig(f"{OUT}/fig1_dgemm_strong_scaling.png", dpi=140, bbox_inches="tight")
    plt.close()


def fig2_ep_weak():
    plt.figure(figsize=(7, 5))
    Ns = list(range(1, NMAX + 1))
    for size, mk in zip(("2p24", "2p26", "2p28"), ("o", "s", "^")):
        xs, ys = [], []
        for n in Ns:
            v = mean(load(f"{SEV}/ep_{size}_w{n}_A.csv"), COMPUTE)
            if v:
                xs.append(n); ys.append(v)
        plt.plot(xs, ys, mk + "-", label="EP 2^" + size[2:])
    plt.xlabel("Number of workers N"); plt.ylabel("Compute per worker (ms)")
    plt.title("EP — weak scaling (SEV-SNP) — ideal: flat line")
    plt.legend(); plt.grid(True, alpha=0.3); plt.ylim(bottom=0); plt.xticks(Ns)
    plt.savefig(f"{OUT}/fig2_ep_weak_scaling.png", dpi=140, bbox_inches="tight")
    plt.close()


def fig3_sev_overhead():
    plt.figure(figsize=(7, 5))
    Ns = [1, 2, 4, 8]
    for size, mk in zip(("512", "1024", "2048"), ("o", "s", "^")):
        xs, ys = [], []
        for n in Ns:
            a = mean(load(f"{SEV}/dgemm_w{n}_A.csv"), ROUND, size)
            d = mean(load(f"{SEV}/dgemm_w{n}_D.csv"), ROUND, size)
            if a and d:
                xs.append(n); ys.append((a / d - 1) * 100)
        plt.plot(xs, ys, mk + "-", label=f"M={size}")
    plt.axhline(0, color="k", alpha=0.4)
    plt.xlabel("Number of workers N"); plt.ylabel("Round-time overhead A vs D (%)")
    plt.title("Attestation + channel-encryption cost (SEV A vs D) — DGEMM")
    plt.legend(); plt.grid(True, alpha=0.3); plt.xticks(Ns)
    plt.savefig(f"{OUT}/fig3_sev_overhead_dgemm.png", dpi=140, bbox_inches="tight")
    plt.close()


def fig4_sev_vs_plain():
    sizes = ["2p24", "2p26", "2p28"]
    ov = []
    for size in sizes:
        rs = []
        for n in range(1, NMAX + 1):
            ds = mean(load(f"{SEV}/ep_{size}_w{n}_D.csv"), COMPUTE)
            dp = mean(load(f"{PLAIN}/ep_{size}_w{n}_D.csv"), COMPUTE)
            if ds and dp:
                rs.append((ds / dp - 1) * 100)
        ov.append(statistics.mean(rs) if rs else 0)
    plt.figure(figsize=(7, 5))
    bars = plt.bar([f"EP 2^{s[2:]}" for s in sizes], ov, color="steelblue")
    plt.axhline(0, color="k", alpha=0.4)
    plt.ylabel("Compute overhead (%)")
    plt.title("SEV-SNP vs plain (D vs D) — hardware memory-encryption cost")
    plt.grid(True, axis="y", alpha=0.3)
    for b, v in zip(bars, ov):
        plt.text(b.get_x() + b.get_width() / 2, v, f"{v:+.1f}%", ha="center",
                 va="bottom" if v >= 0 else "top")
    plt.savefig(f"{OUT}/fig4_sev_vs_plain.png", dpi=140, bbox_inches="tight")
    plt.close()


if __name__ == "__main__":
    fig1_dgemm_strong()
    fig2_ep_weak()
    fig3_sev_overhead()
    fig4_sev_vs_plain()
    print("Saved 4 figures to", OUT + "/")
