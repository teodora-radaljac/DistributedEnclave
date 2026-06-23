#!/usr/bin/env python3
# Analiza benchmark CSV-ova: zbirna tabela + speedup/efikasnost + throughput.
# Pokrece se NA MASTER VM-u:  python3 bench_analyze.py [DIR=/root/bench_results]
import csv, glob, os, re, sys, statistics

DIR = sys.argv[1] if len(sys.argv) > 1 else "/root/bench_results"

# CG klase: (n, nzpc, iters)
CG = {"S": (1400, 7, 15), "W": (7000, 8, 15), "A": (14000, 11, 15),
      "B": (75000, 13, 75), "C": (150000, 15, 75)}

def parse_meta(path):
    """Vrati dict iz # komentara (enrollment_total_ms itd.)."""
    meta = {}
    with open(path) as f:
        for line in f:
            if not line.startswith("#"):
                break
            m = re.match(r"#\s*([\w]+):\s*(.+)", line)
            if m:
                meta[m.group(1)] = m.group(2).strip()
    return meta

def data_rows(path):
    """Vrati listu dict-ova (preskace # komentare)."""
    with open(path) as f:
        lines = [ln for ln in f if not ln.startswith("#")]
    return list(csv.DictReader(lines))

def label_from_name(fn):
    """('DGEMM'|'EP'|'CG', size_label, size_params) iz imena fajla."""
    base = os.path.basename(fn)
    if base.startswith("dgemm"):
        return ("DGEMM", None, None)          # size je u koloni matrix_size
    m = re.match(r"ep_2p(\d+)_", base)
    if m:
        e = int(m.group(1))
        return ("EP", f"2^{e}", 2 ** e)
    m = re.match(r"cg_([SWABC])_", base)
    if m:
        return ("CG", m.group(1), CG[m.group(1)])
    return (base, None, None)

def config_from_name(fn):
    """CONFIG (A/B/C/D) iz sufiksa imena: ..._w{N}_{CONFIG}.csv."""
    m = re.search(r"_w\d+_([ABCD])\.csv$", os.path.basename(fn))
    return m.group(1) if m else "?"

def fnum(x):
    try: return float(x)
    except: return float("nan")

# groups[(wl,size,nw)] = {col: [vals]}, enroll[(wl,size,nw)] = ms
groups, enroll = {}, {}

for path in sorted(glob.glob(os.path.join(DIR, "*.csv"))):
    if os.path.basename(path) == "summary.csv":
        continue
    wl, size_lbl, size_par = label_from_name(path)
    cfg = config_from_name(path)
    meta = parse_meta(path)
    et = fnum(meta.get("enrollment_total_ms", "nan"))
    for r in data_rows(path):
        if "t_round_ms" not in r:
            continue                      # preskoci fajlove/redove sa drugom semom
        nw = int(r.get("num_workers", "0") or 0)
        if wl == "DGEMM":
            slbl = r.get("matrix_size"); spar = int(slbl)
        else:
            slbl, spar = size_lbl, size_par
        key = (wl, slbl, nw, cfg)
        g = groups.setdefault(key, {"scatter": [], "compute": [], "gather": [], "round": [], "par": spar})
        g["scatter"].append(fnum(r.get("t_scatter_ms", "nan")))
        g["compute"].append(fnum(r.get("t_compute_max_ms", "nan")))
        g["gather"].append(fnum(r.get("t_gather_ms", "nan")))
        g["round"].append(fnum(r.get("t_round_ms", "nan")))
        enroll[key] = et

def mean(xs):
    xs = [x for x in xs if x == x]
    return statistics.mean(xs) if xs else float("nan")

def throughput(wl, par, nw, compute_ms):
    s = compute_ms / 1000.0
    if s <= 0: return (float("nan"), "")
    if wl == "DGEMM":
        return (2.0 * par**3 / s / 1e9, "GFLOP/s")     # M=par
    if wl == "EP":
        return (par * nw / s / 1e6, "Mop/s")           # par=parovi/worker
    if wl == "CG":
        n, nzpc, iters = par
        return (n * nzpc * 2.0 * iters / s / 1e6, "Mop/s")
    return (float("nan"), "")

# ── round_ms prosek po kljucu (za speedup T(1)/T(N)) ──
round_by = {k: mean(g["round"]) for k, g in groups.items()}

# ── Zbirna tabela ──
rows = []
for key in sorted(groups, key=lambda k: (k[3], k[0], str(k[1]), k[2])):
    wl, slbl, nw, cfg = key
    g = groups[key]
    sc, cm, ga, rd = mean(g["scatter"]), mean(g["compute"]), mean(g["gather"]), mean(g["round"])
    thr, unit = throughput(wl, g["par"], nw, cm)
    t1 = round_by.get((wl, slbl, 1, cfg))
    spd = (t1 / rd) if (t1 and rd and t1 == t1 and rd == rd) else float("nan")
    eff = (100.0 * spd / nw) if spd == spd else float("nan")
    rows.append((cfg, wl, slbl, nw, enroll.get(key, float("nan")), sc, cm, ga, sc + ga, rd, spd, eff, thr, unit))

hdr = ["config", "workload", "size", "N", "enroll_ms", "scatter_ms", "compute_ms",
       "gather_ms", "scat+gath_ms", "round_ms", "speedup", "effic_%", "throughput", "unit"]
w = [6, 9, 6, 2, 10, 11, 11, 10, 13, 10, 8, 8, 11, 8]

def fmt_row(vals):
    out = []
    for v, width in zip(vals, w):
        if isinstance(v, float):
            s = "nan" if v != v else f"{v:.2f}"
        else:
            s = str(v)
        out.append(s.rjust(width))
    return "  ".join(out)

print(f"\n=== ZBIRNA TABELA ({DIR}) ===")
print(fmt_row(hdr))
print("-" * (sum(w) + 2 * len(w)))
for r in rows:
    print(fmt_row(r))

# ── Speedup / efikasnost (N=1 vs N=2, isti workload+size) ──
print("\n=== SPEEDUP / EFIKASNOST  (round_ms: T(1)/T(N)) ===")
print(fmt_row(["config", "workload", "size", "N", "T1_round", "TN_round", "speedup", "efic.%", "", "", "", "", "", ""]))
print("-" * (sum(w) + 2 * len(w)))
seen = set()
for (wl, slbl, nw, cfg) in sorted(round_by, key=lambda k: (k[3], k[0], str(k[1]), k[2])):
    if (wl, slbl, cfg) in seen:
        continue
    t1 = round_by.get((wl, slbl, 1, cfg))
    for n in (2, 3, 4):
        tn = round_by.get((wl, slbl, n, cfg))
        if t1 and tn and t1 == t1 and tn == tn:
            s = t1 / tn
            print(fmt_row([cfg, wl, slbl, n, t1, tn, s, 100.0 * s / n, "", "", "", "", "", ""]))
    seen.add((wl, slbl, cfg))

# ── Upis summary.csv ──
out = os.path.join(DIR, "summary.csv")
with open(out, "w", newline="") as f:
    wcsv = csv.writer(f)
    wcsv.writerow(hdr)
    for r in rows:
        wcsv.writerow([f"{v:.3f}" if isinstance(v, float) else v for v in r])
print(f"\n[OK] zbirna tabela upisana u {out}")
