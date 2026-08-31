#!/usr/bin/env python3
"""
bench_ray.py – six-metric CVM Ray worker benchmark.

Metrics
-------
  1  enrollment_ms  – ray.init() → worker node appears in ray.nodes()
  2  t_round_ms     – remote_fn.remote() → ray.get() wall time
  3  t_compute_ms   – worker-side compute only (self-reported via perf_counter)
  4  t_scatter_ms   – ray.put() of task inputs on the head
  5  t_gather_ms    – t_round − t_compute  (queue + object fetch + return path)
  6  throughput     – GFLOPS for DGEMM, Mop/s for EP and CG

Workloads
---------
  DGEMM   N = 512, 1024, 2048          2·N³ FLOPs
  EP      pairs = 2²⁴, 2²⁶, 2²⁸       1 op/pair
  CG      Class S (N=1 400)
          Class W (N=7 000)
          Class A (N=14 000)            2·nnz·iters ops

Speedup / efficiency (metric from the spec)
-------------------------------------------
  Requires multiple worker nodes. Run with --workers N after starting N CVMs.
  S(N) = T(1) / T(N),   E(N) = S(N) / N
  When --workers 1 (default) this section is skipped.

Usage
-----
  # Start Ray head on host
  ray start --head --port=6379

  # Boot one or more CVMs, then:
  python bench_ray.py [--repeat N] [--timeout SEC] [--workers N] [--csv FILE]
"""

import argparse
import csv
import statistics
import sys
import time
from dataclasses import dataclass, fields

import numpy as np
import ray
from ray.util.placement_group import placement_group, remove_placement_group
from ray.util.scheduling_strategies import (
    PlacementGroupSchedulingStrategy,
    NodeAffinitySchedulingStrategy,
)


# ---------------------------------------------------------------------------
# NAS benchmark parameters
# ---------------------------------------------------------------------------

CG_CLASSES = {
    "S": dict(n=1_400,   nz=7,  niter=15,  shift=10),
    "W": dict(n=7_000,   nz=8,  niter=15,  shift=12),
    "A": dict(n=14_000,  nz=11, niter=15,  shift=20),
    "B": dict(n=75_000,  nz=13, niter=75,  shift=60),
    "C": dict(n=150_000, nz=15, niter=75,  shift=110),
}
DGEMM_SIZES = [512, 1024, 2048]
EP_PAIRS    = [1 << 24, 1 << 26, 1 << 28]
EP_BATCH    = 1 << 19   # 512 K pairs per chunk (~8 MB peak) to fit in constrained VMs


# ---------------------------------------------------------------------------
# Result
# ---------------------------------------------------------------------------

@dataclass
class Result:
    workload:      str
    size:          str
    t_scatter_ms:  float
    t_round_ms:    float
    t_compute_ms:  float
    t_gather_ms:   float
    throughput:    float
    unit:          str   # "GFLOPS" or "Mop/s"


# ---------------------------------------------------------------------------
# Remote workloads
# ---------------------------------------------------------------------------

@ray.remote
def remote_dgemm(A, B):
    """C = A @ B.  Returns (t_compute_s, flops)."""
    import time
    import numpy as np
    t0 = time.perf_counter()
    C = np.matmul(A, B)
    t = time.perf_counter() - t0
    _ = float(C[0, 0])          # prevent dead-code elimination
    return t, 2 * A.shape[0] ** 3


@ray.remote
def remote_dgemm_block(A_block, B):
    """Strong-scaling DGEMM: compute C_block = A_block @ B and return it.
    Returning C_block forces the gather transfer, matching MPI's MPI_Recv of C."""
    import time
    import numpy as np
    t0 = time.perf_counter()
    C_block = np.matmul(A_block, B)
    t = time.perf_counter() - t0
    flops = 2 * A_block.shape[0] * A_block.shape[1] * B.shape[1]
    return t, flops, C_block


@ray.remote
def remote_ep(num_pairs, batch_size):
    """NAS EP: generate Gaussian pairs, bin by floor(r) into 10 radial bins,
    accumulate sx/sy sums.  Matches MPI master_npb EP_BINS=10 kernel.
    Returns (t_compute_s, num_pairs, counts[10], sx, sy)."""
    import time
    import numpy as np
    EP_BINS = 10
    counts = np.zeros(EP_BINS, dtype=np.int64)
    sx = 0.0
    sy = 0.0
    remaining = num_pairs
    t0 = time.perf_counter()
    while remaining > 0:
        n = min(batch_size, remaining)
        xy = np.random.standard_normal((n, 2))
        # MPI worker_npb.c ep_compute: bin = floor(max(|x|,|y|)), capped at 9.
        # L∞ norm (Chebyshev), NOT L2 radius — matches the C annular-bin definition.
        lmax = np.maximum(np.abs(xy[:, 0]), np.abs(xy[:, 1]))
        k = np.minimum(lmax.astype(np.intp), EP_BINS - 1)
        for b in range(EP_BINS):
            mask = k == b
            counts[b] += int(mask.sum())
            sx += float(xy[mask, 0].sum())
            sy += float(xy[mask, 1].sum())
        remaining -= n
    t = time.perf_counter() - t0
    return t, num_pairs, counts, sx, sy


@ray.remote
def remote_cg(n, nz, niter, shift, b):
    """
    NAS CG: conjugate gradient on a sparse SPD matrix.
    Returns (t_compute_s, ops, converged).
    """
    import time
    import numpy as np
    import scipy.sparse as sp
    import scipy.sparse.linalg as spla

    rng = np.random.default_rng(0)
    cols = rng.integers(0, n, size=(n, nz))
    ones = np.ones(n * nz, dtype=np.float64)
    rows = np.repeat(np.arange(n), nz)
    A = sp.coo_matrix((ones, (rows, cols.ravel())), shape=(n, n)).tocsr()
    A = A + A.T
    diag = np.asarray(A.sum(axis=1)).ravel() + shift
    A = (A + sp.diags(diag)).tocsr()

    t0 = time.perf_counter()
    _x, info = spla.cg(A, b, maxiter=niter, rtol=1e-8)
    t = time.perf_counter() - t0

    return t, 2 * A.nnz * niter, info == 0


# ---------------------------------------------------------------------------
# CG worker actor — holds a persistent row block for distributed SpMV
# ---------------------------------------------------------------------------

@ray.remote(num_cpus=0)
class CGWorkerActor:
    """Holds one row block of A for the distributed strong-scaling CG benchmark.
    Created once per scaling point (N) so matrix setup is not inside the timed loop,
    matching MPI where the master distributes the matrix once before all runs."""
    def __init__(self, n, nz, row_start, row_count):
        import numpy as np
        import scipy.sparse as sp
        # Matches MPI master_npb.c generate_sparse_matrix(seed=42):
        #   nz random column indices per row, values uniform in [-1, 1],
        #   NO symmetrization, NO diagonal shift.
        # Using numpy RNG seeded at 42 so all actors (same seed) produce
        # the same global matrix structure that MPI would generate.
        rng = np.random.default_rng(42)
        cols = rng.integers(0, n, size=(n, nz))
        vals = rng.uniform(-1.0, 1.0, size=(n, nz))
        rows_idx = np.repeat(np.arange(n), nz)
        A = sp.coo_matrix(
            (vals.ravel(), (rows_idx, cols.ravel())), shape=(n, n)
        ).tocsr()
        self.A_block = A[row_start:row_start + row_count, :]
        self._nnz = int(self.A_block.nnz)

    def get_nnz(self):
        return self._nnz

    def spmv(self, x):
        """y_block = A_block @ x  (matches MPI worker SpMV per CG iteration)."""
        import time
        t0 = time.perf_counter()
        y = self.A_block @ x
        t = time.perf_counter() - t0
        return t, y


def _make_cg_actors(n, nz, n_active, worker_node_ids):
    """Create n_active CGWorkerActors pinned to specific worker nodes."""
    base, rem = divmod(n, n_active)
    row_counts = [base + (1 if i < rem else 0) for i in range(n_active)]
    row_starts = [sum(row_counts[:i]) for i in range(n_active)]
    actors = [
        CGWorkerActor.options(
            scheduling_strategy=NodeAffinitySchedulingStrategy(
                node_id=worker_node_ids[i], soft=False
            )
        ).remote(n, nz, row_starts[i], row_counts[i])
        for i in range(n_active)
    ]
    ray.get([a.get_nnz.remote() for a in actors])   # wait for matrix init
    return actors


# ---------------------------------------------------------------------------
# Per-run measurement helpers
# ---------------------------------------------------------------------------

def _once_dgemm(n):
    A = np.random.standard_normal((n, n))
    B = np.random.standard_normal((n, n))

    t0 = time.perf_counter()
    A_ref = ray.put(A)
    B_ref = ray.put(B)
    t_scatter = time.perf_counter() - t0

    t1 = time.perf_counter()
    t_compute, flops = ray.get(remote_dgemm.remote(A_ref, B_ref))
    t_round = time.perf_counter() - t1

    return t_scatter, t_round, t_compute, flops


def _once_ep(num_pairs):
    # Scatter for EP is trivially small (int argument); measure it anyway
    # to establish the Ray overhead floor.
    dummy = np.array([num_pairs], dtype=np.int64)
    t0 = time.perf_counter()
    _ref = ray.put(dummy)
    t_scatter = time.perf_counter() - t0

    t1 = time.perf_counter()
    t_compute, ops, _count = ray.get(remote_ep.remote(num_pairs, EP_BATCH))
    t_round = time.perf_counter() - t1

    return t_scatter, t_round, t_compute, ops


def _once_cg(n, nz, niter, shift):
    b = np.ones(n, dtype=np.float64)

    t0 = time.perf_counter()
    b_ref = ray.put(b)
    t_scatter = time.perf_counter() - t0

    t1 = time.perf_counter()
    t_compute, ops, converged = ray.get(remote_cg.remote(n, nz, niter, shift, b_ref))
    t_round = time.perf_counter() - t1

    if not converged:
        print(f"  [warn] CG n={n} did not converge", file=sys.stderr)

    return t_scatter, t_round, t_compute, ops


# ---------------------------------------------------------------------------
# Scaling-study dispatch helpers (N simultaneous tasks, one per worker)
# ---------------------------------------------------------------------------

def _once_dgemm_n(n, n_active, pg):
    """Strong-scaling DGEMM: partition A's rows across n_active workers.
    Matches MPI master_bench: scatter A_block+B to each worker, gather C_block."""
    from ray._private.internal_api import free as ray_free
    strat = PlacementGroupSchedulingStrategy(placement_group=pg)

    A = np.random.standard_normal((n, n))
    B = np.random.standard_normal((n, n))

    # Distribute rows as evenly as possible; last workers get one extra row if remainder.
    base, rem = divmod(n, n_active)
    row_counts = [base + (1 if i < rem else 0) for i in range(n_active)]
    starts = [sum(row_counts[:i]) for i in range(n_active)]

    t0 = time.perf_counter()
    B_ref = ray.put(B)
    block_refs = [ray.put(A[starts[i]:starts[i] + row_counts[i], :])
                  for i in range(n_active)]
    t_scatter = time.perf_counter() - t0

    t1 = time.perf_counter()
    refs = [remote_dgemm_block.options(scheduling_strategy=strat).remote(br, B_ref)
            for br in block_refs]
    outs = ray.get(refs)   # transfers C_blocks back to head (matches MPI gather)
    t_round = time.perf_counter() - t1

    t_compute = max(r[0] for r in outs)
    total_flops = sum(r[1] for r in outs)

    # Explicitly free all plasma objects so the 32–96 MB of DGEMM matrices are
    # reclaimed before the next workload (EP/CG) runs.  Without this, evictable
    # objects stay in the plasma store as physical RAM, causing false OOM kills.
    ray_free(refs + block_refs + [B_ref])

    return t_scatter, t_round, t_compute, total_flops


def _once_ep_n(num_pairs, n_active, pg):
    """Dispatch n_active simultaneous NAS EP tasks.
    Scatter = task dispatch time (analogous to MPI secure_send of 64-bit seed).
    Gather payload is tiny (10 int64 counts + 2 floats), matching MPI EP."""
    from ray._private.internal_api import free as ray_free
    strat = PlacementGroupSchedulingStrategy(placement_group=pg)
    t0 = time.perf_counter()
    refs = [remote_ep.options(scheduling_strategy=strat).remote(num_pairs, EP_BATCH)
            for _ in range(n_active)]
    t_scatter = time.perf_counter() - t0
    t1 = time.perf_counter()
    outs = ray.get(refs)
    ray_free(refs)
    t_round = time.perf_counter() - t1
    t_compute = max(r[0] for r in outs)
    total_ops = sum(r[1] for r in outs)   # r[1] = num_pairs per worker
    return t_scatter, t_round, t_compute, total_ops


def _once_cg_n(actors, n, niter):
    """Strong-scaling CG: niter rounds of scatter-x / SpMV / gather-y_block.
    Matches MPI master_npb: one full x scatter + one y_block gather per iteration.
    ops are computed by the caller as 2*n*nz*niter to match MPI's Mop/s formula."""
    from ray._private.internal_api import free as ray_free
    x = np.ones(n, dtype=np.float64)
    t_scatter_total = 0.0
    t_compute_max_total = 0.0
    t_start = time.perf_counter()
    for _ in range(niter):
        t0 = time.perf_counter()
        x_ref = ray.put(x)
        t_scatter_total += time.perf_counter() - t0
        refs = [actor.spmv.remote(x_ref) for actor in actors]
        outs = ray.get(refs)
        ray_free([x_ref])
        t_compute_max_total += max(r[0] for r in outs)
        y = np.concatenate([r[1] for r in outs])
        norm = float(np.linalg.norm(y))
        if norm > 0:
            x = y / norm
    t_round = time.perf_counter() - t_start
    return t_scatter_total, t_round, t_compute_max_total


# ---------------------------------------------------------------------------
# Benchmark runner (repeats → median)
# ---------------------------------------------------------------------------

def bench(workload, size, runner, repeat, unit):
    samples = []
    for i in range(repeat):
        print(f"  {workload:5s} {size:10s}  run {i+1}/{repeat}", end="\r", flush=True)
        samples.append(runner())
    print()

    med = lambda idx: statistics.median(s[idx] for s in samples)
    t_scatter = med(0)
    t_round   = med(1)
    t_compute = med(2)
    ops       = samples[0][3]

    t_gather   = max(0.0, t_round - t_compute)
    scale      = 1e9 if unit == "GFLOPS" else 1e6
    throughput = ops / t_compute / scale

    return Result(
        workload=workload,
        size=size,
        t_scatter_ms=t_scatter * 1e3,
        t_round_ms=t_round   * 1e3,
        t_compute_ms=t_compute * 1e3,
        t_gather_ms=t_gather  * 1e3,
        throughput=throughput,
        unit=unit,
    )


# ---------------------------------------------------------------------------
# Enrollment (metric 1)
# ---------------------------------------------------------------------------

def wait_for_workers(n_workers, timeout, head_ip):
    t0 = time.perf_counter()
    print(f"Waiting for {n_workers} CVM worker(s)...", end="", flush=True)
    while True:
        alive = [nd for nd in ray.nodes()
                 if nd["Alive"] and nd["NodeManagerAddress"] != head_ip]
        if len(alive) >= n_workers:
            elapsed = time.perf_counter() - t0
            addrs = ", ".join(nd["NodeManagerAddress"] for nd in alive[:n_workers])
            print(f" connected [{addrs}].")
            return elapsed * 1e3
        if time.perf_counter() - t0 > timeout:
            print()
            sys.exit(f"Timed out waiting for {n_workers} worker(s).")
        time.sleep(0.5)


# ---------------------------------------------------------------------------
# Speedup / efficiency (metric 5)
# ---------------------------------------------------------------------------

def measure_speedup(n_workers, repeat):
    """
    Run DGEMM N=1024 with 1 worker (serial) and then with all N workers
    (parallel) to compute S(N) and E(N).
    """
    if n_workers < 2:
        return None

    SIZE = 1024

    def serial():
        A = np.random.standard_normal((SIZE, SIZE))
        B = np.random.standard_normal((SIZE, SIZE))
        A_ref = ray.put(A)
        B_ref = ray.put(B)
        t0 = time.perf_counter()
        ray.get(remote_dgemm.remote(A_ref, B_ref))
        return time.perf_counter() - t0

    def parallel():
        refs = []
        for _ in range(n_workers):
            A = np.random.standard_normal((SIZE, SIZE))
            B = np.random.standard_normal((SIZE, SIZE))
            refs.append(remote_dgemm.remote(ray.put(A), ray.put(B)))
        t0 = time.perf_counter()
        ray.get(refs)
        return time.perf_counter() - t0

    t1 = statistics.median(serial() for _ in range(repeat))
    tN = statistics.median(parallel() for _ in range(repeat))

    speedup    = t1 / tN
    efficiency = speedup / n_workers
    return t1 * 1e3, tN * 1e3, speedup, efficiency


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

HEADER = (
    f"{'Workload':<8} {'Size':<10} "
    f"{'t_scatter':>11} {'t_round':>9} {'t_compute':>11} {'t_gather':>9} "
    f"{'Throughput':>12}  {'Unit'}"
)
SEP = "─" * len(HEADER)

def _fmt(ms):
    return f"{ms:8.1f} ms"

def print_results(enrollment_ms, results, speedup_row, n_workers):
    print()
    print(f"  ┌─ Metric 1 – Enrollment: {enrollment_ms:.0f} ms")
    print()
    print("  " + HEADER)
    print("  " + SEP)
    for r in results:
        print(
            f"  {r.workload:<8} {r.size:<10} "
            f"  {_fmt(r.t_scatter_ms)} {_fmt(r.t_round_ms)} "
            f"  {_fmt(r.t_compute_ms)} {_fmt(r.t_gather_ms)} "
            f"  {r.throughput:10.3f}   {r.unit}"
        )
    print()
    if speedup_row:
        t1, tN, S, E = speedup_row
        print(
            f"  ┌─ Metric 5 – Speedup / efficiency  (DGEMM N=1024, {n_workers} workers)\n"
            f"  │  T(1)={t1:.1f} ms   T({n_workers})={tN:.1f} ms\n"
            f"  │  S({n_workers}) = {S:.2f}   E({n_workers}) = {E:.2f}"
        )
        print()
    print(
        "  Notes:\n"
        "    t_scatter  = ray.put() of task inputs on the head\n"
        "    t_round    = remote_fn.remote() → ray.get() (excludes scatter)\n"
        "    t_compute  = worker self-reported (perf_counter around core compute)\n"
        "    t_gather   = t_round − t_compute  (queue + object fetch + return path)\n"
        "    Throughput = ops / t_compute"
    )


def _mpi_size(workload, size):
    """Normalise size label to match MPI summary format."""
    if workload == "DGEMM":
        return size.removeprefix("N=")
    if workload == "CG":
        return size.removeprefix("Class ")
    return size  # EP: "2^24" etc. unchanged


def _mpi_unit(unit):
    return "GFLOP/s" if unit == "GFLOPS" else unit


def write_csv(path, enrollment_ms, results, speedup_row, n_workers):
    # speedup_row covers only DGEMM N=1024; build a lookup for that one entry.
    speedup_lookup = {}
    if speedup_row:
        _t1, _tN, S, E = speedup_row
        speedup_lookup[("DGEMM", "1024")] = (S, E * 100)

    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow([
            "workload", "size", "N", "enroll_ms",
            "scatter_ms", "compute_ms", "gather_ms", "scat+gath_ms",
            "round_ms", "speedup", "effic_%", "throughput", "unit",
        ])
        for r in results:
            size = _mpi_size(r.workload, r.size)
            scat_gath = r.t_scatter_ms + r.t_gather_ms
            key = (r.workload, size)
            if n_workers == 1:
                speedup_val, effic_val = "1.000", "100.000"
            elif key in speedup_lookup:
                S, E = speedup_lookup[key]
                speedup_val, effic_val = f"{S:.3f}", f"{E:.3f}"
            else:
                speedup_val, effic_val = "", ""
            w.writerow([
                r.workload,
                size,
                n_workers,
                f"{enrollment_ms:.3f}",
                f"{r.t_scatter_ms:.3f}",
                f"{r.t_compute_ms:.3f}",
                f"{r.t_gather_ms:.3f}",
                f"{scat_gath:.3f}",
                f"{r.t_round_ms:.3f}",
                speedup_val,
                effic_val,
                f"{r.throughput:.3f}",
                _mpi_unit(r.unit),
            ])
    print(f"  CSV written to {path}")


# ---------------------------------------------------------------------------
# Scaling study
# ---------------------------------------------------------------------------

SCALING_FIELDS = [
    "N", "run", "workload", "size",
    "scatter_ms", "round_ms", "compute_ms", "gather_ms", "scat_gath_ms",
    "throughput", "unit",
]


def run_scaling(scaling_list, runs, head_ip, skip_cg_a, csv_path, timeout, cg_only=False, cg_classes_arg=None):
    """
    For each N in scaling_list: create a STRICT_SPREAD placement group across
    N worker nodes, run all workloads `runs` times, write every row to CSV.
    CVMs stay up for the entire study — no restart between scaling points.

    compute_ms = max worker compute time (matches MPI's t_compute_max_ms).
    throughput  = total_ops / compute_max (aggregate compute throughput).
    """
    max_n = max(scaling_list)
    if cg_classes_arg:
        cg_classes = [c.strip() for c in cg_classes_arg.split(",")]
    else:
        cg_classes = ["S", "W"] + ([] if skip_cg_a else ["A", "B", "C"])

    # Wait for all workers to connect before starting any scaling point.
    print(f"Waiting for {max_n} CVM worker(s)...", end="", flush=True)
    t_start = time.perf_counter()
    while True:
        alive = [nd for nd in ray.nodes()
                 if nd["Alive"] and nd["NodeManagerAddress"] != head_ip]
        if len(alive) >= max_n:
            enroll_ms = (time.perf_counter() - t_start) * 1e3
            addrs = ", ".join(nd["NodeManagerAddress"] for nd in alive[:max_n])
            print(f"\n  Connected [{addrs}]")
            print(f"  Enrollment (all {max_n}): {enroll_ms:.0f} ms\n")
            break
        if time.perf_counter() - t_start > timeout:
            print()
            sys.exit(f"Timed out after {timeout}s waiting for {max_n} workers")
        time.sleep(0.5)

    f_out = None
    writer = None
    if csv_path:
        f_out = open(csv_path, "w", newline="")
        writer = csv.DictWriter(f_out, fieldnames=SCALING_FIELDS)
        writer.writeheader()
        f_out.flush()

    def emit(n_active, run_idx, workload, size, t_sc, t_round, t_comp, ops, scale, unit_str):
        t_gather = max(0.0, t_round - t_comp)
        tp = ops / t_comp / scale if t_comp > 0 else 0.0
        row = {
            "N":            n_active,
            "run":          run_idx,
            "workload":     workload,
            "size":         size,
            "scatter_ms":   f"{t_sc * 1e3:.3f}",
            "round_ms":     f"{t_round * 1e3:.3f}",
            "compute_ms":   f"{t_comp * 1e3:.3f}",
            "gather_ms":    f"{t_gather * 1e3:.3f}",
            "scat_gath_ms": f"{(t_sc + t_gather) * 1e3:.3f}",
            "throughput":   f"{tp:.3f}",
            "unit":         unit_str,
        }
        if writer:
            writer.writerow(row)
            f_out.flush()

    try:
        for n_active in sorted(scaling_list):
            pg = placement_group(
                [{"CPU": 1} for _ in range(n_active)],
                strategy="STRICT_SPREAD",
            )
            ray.get(pg.ready(), timeout=60)

            # Worker node IDs for actor placement (head has --num-cpus=0 so excluded).
            worker_node_ids = sorted(
                nd["NodeID"] for nd in ray.nodes()
                if nd["Alive"] and nd["NodeManagerAddress"] != head_ip
            )[:n_active]

            print(f"N={n_active:2d}  ", end="", flush=True)

            # DGEMM — all runs, no actors alive during this phase.
            if not cg_only:
                for run_idx in range(1, runs + 1):
                    for n in DGEMM_SIZES:
                        if n % n_active != 0:
                            # MPI master_bench.c:790 skips sizes not evenly divisible
                            continue
                        t_sc, t_rd, t_cp, flops = _once_dgemm_n(n, n_active, pg)
                        emit(n_active, run_idx, "DGEMM", str(n),
                             t_sc, t_rd, t_cp, flops, 1e9, "GFLOP/s")
                    print("d", end="", flush=True)

            # EP — all runs, no actors alive during this phase.
            if not cg_only:
                for run_idx in range(1, runs + 1):
                    for pairs in EP_PAIRS:
                        exp = pairs.bit_length() - 1
                        t_sc, t_rd, t_cp, ops = _once_ep_n(pairs, n_active, pg)
                        emit(n_active, run_idx, "EP", f"2^{exp}",
                             t_sc, t_rd, t_cp, ops, 1e6, "Mop/s")
                    print("e", end="", flush=True)

            # CG — one class at a time so only one actor process/node exists at once.
            # Three classes alive simultaneously would add ~150 MB/node (3 × Python base),
            # pushing idle memory above the 95% Ray kill threshold on 1 GB CVMs.
            for cls in cg_classes:
                p = CG_CLASSES[cls]
                actors = _make_cg_actors(
                    p["n"], p["nz"], n_active, worker_node_ids
                )
                for run_idx in range(1, runs + 1):
                    t_sc, t_rd, t_cp = _once_cg_n(actors, p["n"], p["niter"])
                    ops = 2 * p["n"] * p["nz"] * p["niter"]
                    emit(n_active, run_idx, "CG", cls,
                         t_sc, t_rd, t_cp, ops, 1e6, "Mop/s")
                    print("c", end="", flush=True)
                for actor in actors:
                    ray.kill(actor)

            remove_placement_group(pg)
            print(" ✓")
    finally:
        if f_out:
            f_out.close()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--repeat",   type=int, default=3,
                    help="timed repetitions per configuration (default: 3)")
    ap.add_argument("--timeout",  type=int, default=180,
                    help="seconds to wait for workers (default: 180)")
    ap.add_argument("--workers",  type=int, default=1,
                    help="number of CVM workers expected (default: 1)")
    ap.add_argument("--skip-cg-a", action="store_true",
                    help="skip CG Class A (N=14000, can be slow)")
    ap.add_argument("--cg-only", action="store_true",
                    help="run only CG workloads, skip EP and DGEMM")
    ap.add_argument("--cg-classes", metavar="S,W,A,B,C",
                    help="comma-separated CG classes to run (default: S,W,A,B,C)")
    ap.add_argument("--csv",      metavar="FILE",
                    help="also write results to a CSV file")
    ap.add_argument("--scaling",  metavar="N1,N2,...",
                    help="scaling study: comma-separated worker counts, e.g. 1,2,3,...,14; "
                         "uses Ray placement groups (STRICT_SPREAD); Ray head must have --num-cpus=0")
    ap.add_argument("--runs",     type=int, default=10,
                    help="outer runs per scaling point in --scaling mode (default: 10)")
    args = ap.parse_args()

    import warnings
    warnings.filterwarnings("ignore")          # suppress Ray FutureWarning noise

    ray.init(address="auto")

    head_ip = ray.get_runtime_context().gcs_address.split(":")[0]

    if args.scaling:
        scaling_list = [int(x.strip()) for x in args.scaling.split(",")]
        run_scaling(scaling_list, args.runs, head_ip,
                    args.skip_cg_a, args.csv, args.timeout,
                    cg_only=args.cg_only, cg_classes_arg=args.cg_classes)
        ray.shutdown()
        return

    # Metric 1: enrollment
    existing = [nd for nd in ray.nodes()
                if nd["Alive"] and nd["NodeManagerAddress"] != head_ip]
    if len(existing) >= args.workers:
        addrs = ", ".join(nd["NodeManagerAddress"] for nd in existing[:args.workers])
        print(f"Worker(s) already connected [{addrs}]; enrollment time not captured.")
        enrollment_ms = 0.0
    else:
        enrollment_ms = wait_for_workers(args.workers, args.timeout, head_ip)

    results = []

    # DGEMM – metrics 2-6
    for n in DGEMM_SIZES:
        results.append(bench("DGEMM", f"N={n}",
                             lambda n=n: _once_dgemm(n),
                             args.repeat, "GFLOPS"))

    # EP – metrics 2-6
    for pairs in EP_PAIRS:
        exp = pairs.bit_length() - 1
        results.append(bench("EP", f"2^{exp}",
                             lambda p=pairs: _once_ep(p),
                             args.repeat, "Mop/s"))

    # CG – metrics 2-6
    cg_classes = ["S", "W"] + ([] if args.skip_cg_a else ["A"])
    for cls in cg_classes:
        p = CG_CLASSES[cls]
        results.append(bench("CG", f"Class {cls}",
                             lambda p=p: _once_cg(**p),
                             args.repeat, "Mop/s"))

    # Metric 5: speedup / efficiency (only meaningful with >1 worker)
    speedup_row = measure_speedup(args.workers, args.repeat)

    print_results(enrollment_ms, results, speedup_row, args.workers)

    if args.csv:
        write_csv(args.csv, enrollment_ms, results, speedup_row, args.workers)

    ray.shutdown()


if __name__ == "__main__":
    main()
