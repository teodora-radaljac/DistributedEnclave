#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# THE headline comparison: SEV-A (full protection: SEV-SNP + attestation + AEAD)
# vs Plain-D (no protection: plain VM, no enc) — end-to-end across N.
import os, csv, glob, re, statistics
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

SEV, PLAIN, OUT = "bench_results_pin14", "bench_results_plain14", "plots"
os.makedirs(OUT, exist_ok=True)
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


def series(d, letter, wl, sz, metric):
    """min over 10 runs (most representative) per N -> (Ns, vals)."""
    xs, ys = [], []
    for N in range(1, 15):
        if wl == "DGEMM":
            f = f"{d}/dgemm_w{N}_{letter}.csv"; v = col(load(f), metric, sz)
        elif wl == "EP":
            f = f"{d}/ep_2p{sz[2:]}_w{N}_{letter}.csv"; v = col(load(f), metric)
        else:
            f = f"{d}/cg_{sz}_w{N}_{letter}.csv"; v = col(load(f), metric)
        if v:
            xs.append(N); ys.append(min(v))
    return xs, ys


def make():
    metric = "t_round_ms"
    fig, axes = plt.subplots(1, 3, figsize=(16, 4.8))
    for ax, (wl, sz) in zip(axes, REP):
        xp, yp = series(PLAIN, "D", wl, sz, metric)   # Plain-D (no protection)
        xs, ys = series(SEV, "A", wl, sz, metric)      # SEV-A (full protection)
        ax.plot(xp, yp, "o-", color="#2ca02c", label="No protection (Plain-D)")
        ax.plot(xs, ys, "D-", color="#d62728", label="Full protection (SEV-A)")
        # overhead % per matched N
        ov = []
        mp = dict(zip(xp, yp))
        for n, a in zip(xs, ys):
            if n in mp and mp[n]:
                ov.append((a / mp[n] - 1) * 100)
        med = statistics.median(ov) if ov else 0
        ax.set_title(f"{wl} ({sz})  —  full vs none: median {med:+.0f}%")
        ax.set_xlabel("Number of workers N"); ax.set_ylabel("End-to-end round time (ms)")
        ax.grid(True, alpha=0.3)
        ax.set_xticks(range(1, 15, 2) if wl != "DGEMM" else [1, 2, 4, 8])
    axes[0].legend(fontsize=9)
    fig.suptitle("Cost of full confidential computing — SEV-A (SEV+attest+enc) vs Plain-D (none)")
    fig.tight_layout(rect=[0, 0, 1, 0.95])
    fig.savefig(f"{OUT}/fig7_full_vs_none.png", dpi=140, bbox_inches="tight")
    plt.close(fig)

    # second figure: overhead % vs N (one line per workload)
    fig2, ax = plt.subplots(figsize=(8, 5))
    for (wl, sz), cspec, mk in zip(REP, ("#1f77b4", "#ff7f0e", "#9467bd"), ("o", "s", "^")):
        xp, yp = series(PLAIN, "D", wl, sz, metric)
        xs, ys = series(SEV, "A", wl, sz, metric)
        mp = dict(zip(xp, yp))
        xx, oo = [], []
        for n, a in zip(xs, ys):
            if n in mp and mp[n]:
                xx.append(n); oo.append((a / mp[n] - 1) * 100)
        ax.plot(xx, oo, mk + "-", color=cspec, label=f"{wl} ({sz})")
    ax.axhline(0, color="k", lw=0.8)
    ax.set_xlabel("Number of workers N")
    ax.set_ylabel("Overhead of full protection vs none [%]  (end-to-end)")
    ax.set_title("SEV-A vs Plain-D — total confidentiality overhead vs N")
    ax.legend(); ax.grid(True, alpha=0.3); ax.set_xticks(range(1, 15, 1))
    fig2.tight_layout()
    fig2.savefig(f"{OUT}/fig8_full_vs_none_overhead.png", dpi=140, bbox_inches="tight")
    plt.close(fig2)


if __name__ == "__main__":
    make()
    print("Saved fig7_full_vs_none.png + fig8_full_vs_none_overhead.png to", OUT + "/")
