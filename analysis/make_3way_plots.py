#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Reproduces the two "earlier" figures from the NEW clean datasets:
#   1) Throughput vs N (3 subplots: EP 2^28, DGEMM 2048, CG A) for 4 configs
#   2) Confidentiality cost decomposition (relative slowdown on MIN measurements)
# Data:  bench_results_pin14  (A->SEV-A, D->SEV-D) ; bench_results_plain14 (C->Plain-C, D->Plain-D)
import os, csv, glob, re, statistics
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

SEV, PLAIN, OUT = "bench_results_pin14", "bench_results_plain14", "plots"
os.makedirs(OUT, exist_ok=True)
CG = {"S": (1400, 7, 15), "W": (7000, 8, 15), "A": (14000, 11, 15)}

CFG = {
    "Plain-D": dict(color="#2ca02c", marker="o", label="Plain-D (plain, no enc.)"),
    "Plain-C": dict(color="#1f77b4", marker="s", label="Plain-C (plain, enc.)"),
    "SEV-D":   dict(color="#ff7f0e", marker="^", label="SEV-D (SEV, no att/enc.)"),
    "SEV-A":   dict(color="#d62728", marker="D", label="SEV-A (SEV, att+enc.)"),
}
CFG_ORDER = ["Plain-D", "Plain-C", "SEV-D", "SEV-A"]
REP = [("EP", "2^28"), ("DGEMM", "2048"), ("CG", "A")]


def load(path):
    if not os.path.exists(path) or os.path.getsize(path) == 0:
        return []
    with open(path) as f:
        lines = [l for l in f if not l.startswith("#")]
    return list(csv.DictReader(lines)) if lines else []


def col(rows, c, msize=None):
    out = []
    for r in rows:
        if msize is not None and r.get("matrix_size") != msize:
            continue
        try:
            out.append(float(r[c]))
        except (ValueError, KeyError, TypeError):
            pass
    return out


def collect():
    # data[cfg][(wl,size,N)] = {compute:[...], round:[...], par:..}
    data = {c: {} for c in CFG_ORDER}
    for d, letter, name in [(SEV, "A", "SEV-A"), (SEV, "D", "SEV-D"),
                            (PLAIN, "C", "Plain-C"), (PLAIN, "D", "Plain-D")]:
        for path in glob.glob(os.path.join(d, f"*_{letter}.csv")):
            base = os.path.basename(path)
            rows = load(path)
            if base.startswith("dgemm"):
                m = re.search(r"_w(\d+)_", base); N = int(m.group(1))
                for sz in ("512", "1024", "2048"):
                    cv = col(rows, "t_compute_max_ms", sz)
                    if cv:
                        data[name][("DGEMM", sz, N)] = dict(
                            compute=cv, round=col(rows, "t_round_ms", sz), par=int(sz))
                continue
            m = re.match(r"ep_2p(\d+)_w(\d+)_", base)
            if m:
                e, N = int(m.group(1)), int(m.group(2))
                cv = col(rows, "t_compute_max_ms")
                if cv:
                    data[name][("EP", f"2^{e}", N)] = dict(
                        compute=cv, round=col(rows, "t_round_ms"), par=2 ** e)
                continue
            m = re.match(r"cg_([SWA])_w(\d+)_", base)
            if m:
                cls, N = m.group(1), int(m.group(2))
                cv = col(rows, "t_compute_max_ms")
                if cv:
                    data[name][("CG", cls, N)] = dict(
                        compute=cv, round=col(rows, "t_round_ms"), par=CG[cls])
    return data


def throughput(wl, par, N, compute_ms):
    s = compute_ms / 1000.0
    if s <= 0:
        return float("nan")
    if wl == "DGEMM":
        return 2.0 * par ** 3 / s / 1e9          # GFLOP/s
    if wl == "EP":
        return par * N / s / 1e6                 # Mop/s
    n, nzpc, iters = par
    return n * nzpc * 2.0 * iters / s / 1e6       # CG Mop/s


# ---------------- Figure 1: throughput vs N ----------------
def fig_throughput(data):
    fig, axes = plt.subplots(1, 3, figsize=(16, 4.5))
    for ax, (wl, sz) in zip(axes, REP):
        for cfg in CFG_ORDER:
            xs, ys = [], []
            for N in range(1, 15):
                rec = data[cfg].get((wl, sz, N))
                if rec and rec["compute"]:
                    ys.append(throughput(wl, rec["par"], N, statistics.mean(rec["compute"])))
                    xs.append(N)
            if xs:
                st = CFG[cfg]
                ax.plot(xs, ys, marker=st["marker"], color=st["color"], label=st["label"])
        ax.set_title(f"Throughput \u2014 {wl} ({sz})")
        ax.set_xlabel("Number of workers N"); ax.set_ylabel("throughput")
        ax.grid(True, alpha=0.3); ax.set_xticks(range(1, 15, 1) if wl != "DGEMM" else [1, 2, 4, 8])
    axes[0].legend(fontsize=8)
    fig.tight_layout()
    fig.savefig(f"{OUT}/fig5_throughput_3way.png", dpi=140, bbox_inches="tight")
    plt.close(fig)


# ---------------- Figure 2: cost decomposition (MIN) ----------------
def ratios_over_N(data, wl, sz, metric):
    """Per-N min-based ratios for the 4 cost layers; returns dict layer->list%."""
    layers = {"sevhw": [], "appenc": [], "attsw": [], "total": []}
    for N in range(1, 15):
        def mn(cfg):
            r = data[cfg].get((wl, sz, N))
            v = [x for x in (r[metric] if r else []) if x == x]
            return min(v) if v else None
        pD, pC, sD, sA = mn("Plain-D"), mn("Plain-C"), mn("SEV-D"), mn("SEV-A")
        if pD:
            if sD: layers["sevhw"].append((sD / pD - 1) * 100)
            if pC: layers["appenc"].append((pC / pD - 1) * 100)
            if sA: layers["total"].append((sA / pD - 1) * 100)
        if sD and sA:
            layers["attsw"].append((sA / sD - 1) * 100)
    return layers


def fig_decomp(data):
    BARS = [("sevhw", "SEV HW (memory enc.)", "#ff7f0e"),
            ("appenc", "App encryption", "#1f77b4"),
            ("attsw", "Att+enc layer (SEV)", "#9467bd"),
            ("total", "Total (SEV-A/Plain-D)", "#d62728")]
    fig, (axa, axb) = plt.subplots(1, 2, figsize=(15, 5.5))
    fig.suptitle("Confidentiality cost decomposition \u2014 relative slowdown on minimum measurements")

    def draw(ax, reps, metric, ylab, title):
        x = np.arange(len(reps)); w = 0.2
        for i, (k, lbl, cspec) in enumerate(BARS):
            means, errs = [], []
            for wl, sz in reps:
                vals = ratios_over_N(data, wl, sz, metric).get(k, [])
                means.append(statistics.mean(vals) if vals else 0)
                errs.append(statistics.pstdev(vals) if len(vals) > 1 else 0)
            bars = ax.bar(x + (i - 1.5) * w, means, w, yerr=errs, capsize=3,
                          color=cspec, label=lbl)
            for b, m in zip(bars, means):
                ax.text(b.get_x() + b.get_width() / 2, m, f"{m:+.0f}%",
                        ha="center", va="bottom" if m >= 0 else "top", fontsize=7)
        ax.axhline(0, color="k", lw=0.8)
        ax.set_xticks(x); ax.set_xticklabels([f"{w}\n({s})" for w, s in reps])
        ax.set_ylabel(ylab); ax.set_title(title); ax.grid(True, axis="y", alpha=0.3)

    draw(axa, REP, "compute", "Relative slowdown [%] on MIN (t_compute \u2014 pure compute)",
         "(a) Cost on pure compute (all workloads)")
    draw(axb, [("EP", "2^28"), ("DGEMM", "2048")], "round",
         "Relative slowdown [%] on MIN (t_round \u2014 end-to-end)",
         "(b) End-to-end (CG excluded: gather artifact)")
    axa.legend(fontsize=8, loc="upper left")
    fig.tight_layout(rect=[0, 0, 1, 0.96])
    fig.savefig(f"{OUT}/fig6_cost_decomposition.png", dpi=140, bbox_inches="tight")
    plt.close(fig)


if __name__ == "__main__":
    data = collect()
    fig_throughput(data)
    fig_decomp(data)
    print("Saved fig5_throughput_3way.png + fig6_cost_decomposition.png to", OUT + "/")
