#!/usr/bin/env python3
"""
bench_ray.py – Ray CVM benchmark suite matching the OpenMPI campaign.

Workloads
---------
  DGEMM   M=2048 (N=1,2,4,8)  M=4096 (N=1,2,4,8)  M=6144 (N=4,8)
          Strong scaling: head scatters A-blocks + full B, workers return C-blocks.
  EP      2^28 pairs per worker (weak scaling, N=1..13)
  STREAM  128 MiB/array × 3 arrays per worker (weak scaling, N=1..13)
          Triad: A = B + alpha*C; 2 warm-up passes, then all N workers
          rendezvous on a barrier and sustain Triads for a fixed 2 s window
          so the timed regions provably overlap (see STREAM_MEASURE_SECONDS).
  RANDOM  256 MiB int32 permutation per worker (weak scaling, N=1..13)
          50 M timed dependent pointer-chase accesses per worker.
  CG      NAS Class S/W/A/B/C (strong scaling)

Metrics
-------
  DGEMM   GFLOP/s (aggregate)
  EP      Mop/s   (aggregate pairs/s)
  STREAM  GiB/s   (aggregate read+write bandwidth)
  RANDOM  ns/access (slowest worker latency)
  CG      Mop/s   (aggregate)

All timings use the slowest-worker compute interval as t_compute_max,
matching the MPI campaign's t_compute_max_ms column.
Enrollment is measured separately and excluded from workload timers.

Usage (scaling study)
---------------------
  ray start --head --port=6379 --num-cpus=0
  python bench_ray.py --scaling 1,2,...,13 --runs 10 --csv out.csv
"""

import argparse
import csv
import os
import sys
import time

import numpy as np
import ray
from ray.util.scheduling_strategies import NodeAffinitySchedulingStrategy


# ---------------------------------------------------------------------------
# Workload parameters
# ---------------------------------------------------------------------------

# DGEMM: matrix_size → list of valid worker counts.
# M=6144, N=1/2 excluded: B alone is 288 MiB; MPI campaign constraint kept.
DGEMM_CONFIGS = {
    2048: [1, 2, 4, 8],
    4096: [1, 2, 4, 8],
    6144: [4, 8],
}

# EP: only 2^28 for paper parity with MPI campaign.
EP_PAIRS = [1 << 28]
EP_BATCH = 1 << 19   # 512 K pairs/chunk to avoid OOM on 2 GiB workers

# NAS CG classes
CG_CLASSES = {
    "S": dict(n=1_400,   nz=7,  niter=15,  shift=10),
    "W": dict(n=7_000,   nz=8,  niter=15,  shift=12),
    "A": dict(n=14_000,  nz=11, niter=15,  shift=20),
    "B": dict(n=75_000,  nz=13, niter=75,  shift=60),
    "C": dict(n=150_000, nz=15, niter=75,  shift=110),
}
# One SpMV over a single worker's row block is microseconds of work, while a
# Ray actor call costs milliseconds.  Timing one multiply therefore measures
# the per-call noise floor: the old code reported 8-44 ms for a ~12 k-nonzero
# block and, worse, the value *grew* with N even though the block shrinks.
# (MPI's CG shows the correct behaviour, falling from 2.18 ms at N=1 to
# 0.24 ms at N=10.)  Repeating the multiply inside the timer and dividing
# lifts the kernel above that floor without altering the algorithm or the
# communication pattern.
#
# The count is chosen adaptively from a warm-up multiply so that the timed
# loop lasts about CG_SPMV_TARGET_MS regardless of class and worker count.
# A fixed count cannot serve both ends: class A at N=13 is ~1.8 ms per
# multiply (wants many reps) while class C at N=1 is ~44 ms (where 50 reps
# would cost 165 s per run).
CG_SPMV_TARGET_MS = 100.0
CG_SPMV_MIN_REPS  = 2
CG_SPMV_MAX_REPS  = 200

# STREAM Triad: A = B + alpha*C
STREAM_ARRAY_BYTES = 128 * 1024 * 1024        # 128 MiB per array
STREAM_ARRAY_ELEMS = STREAM_ARRAY_BYTES // 8  # float64 elements
STREAM_ALPHA       = 1.0
STREAM_WARMUP      = 2                         # warm-up passes before the barrier
# A single Triad pass over 128 MiB takes ~29 ms, but a Ray round costs
# 200-1000 ms of dispatch/collect overhead.  A one-shot timed pass therefore
# lands at a random offset inside the round, so the N workers' timed windows
# do not reliably overlap and the "aggregate" bandwidth measures nothing.
# Fix: barrier-synchronise all workers, then sustain Triads for a fixed
# wall-clock window so every worker is hammering memory at the same time.
STREAM_MEASURE_SECONDS = 2.0
# The Triad must move exactly 3 arrays' worth of DRAM traffic (read B, read C,
# write A) for the reported byte count to be honest.  Expressed as two whole-
# array numpy calls it moves 5: the 128 MiB intermediate A is written by the
# multiply, then re-read by the add, and at 128 MiB against a 32 MiB LLC it
# cannot stay cached.  Running the pair over chunks small enough that the
# intermediate stays LLC-resident restores true 3-array traffic (measured:
# 15.39 -> 18.68 GiB/s single-core, matching the MPI C kernel's 17.60).
# 512 Ki float64 = 4 MiB per array, so B/C/A chunks together are 12 MiB.
STREAM_CHUNK_ELEMS = 512 * 1024

# RANDOM pointer chasing
RANDOM_ARRAY_BYTES = 256 * 1024 * 1024        # 256 MiB per worker
RANDOM_ARRAY_ELEMS = RANDOM_ARRAY_BYTES // 4  # int32 indices
RANDOM_WARMUP      = 5_000_000                # dependent accesses (outside timer)
RANDOM_MEASURED    = 50_000_000               # timed dependent accesses


# ---------------------------------------------------------------------------
# Remote workloads
# ---------------------------------------------------------------------------

@ray.remote(num_cpus=0)
class DGEMMWorker:
    """Persistent actor for proper scatter / compute / gather phase separation.

    One actor per worker node, pinned via NodeAffinitySchedulingStrategy.
    Protocol per run:
      1. head calls load(A_block, B) — data travels over the network to this node;
         ray.get() on the ack means the inputs are local when the call returns.
      2. head calls compute() — actor runs matmul locally and returns C_block;
         ray.get() on the result measures compute + result transfer back to head.

    This gives:  scatter_ms  = true network delivery of inputs (load ack)
                 round_ms    = compute + gather (compute() return)
                 noncompute_ms = round_ms - compute_max_ms ≈ gather transfer
    """

    def __init__(self):
        import os, ctypes
        for _v in ("OMP_NUM_THREADS", "OPENBLAS_NUM_THREADS",
                   "MKL_NUM_THREADS", "NUMEXPR_NUM_THREADS"):
            os.environ[_v] = "1"
        try:
            _lib = ctypes.cdll.LoadLibrary("libopenblas.so")
            _lib.openblas_set_num_threads(1)
            _lib.openblas_get_num_threads.restype = ctypes.c_int
            _actual = _lib.openblas_get_num_threads()
            if _actual != 1:
                import sys
                print(f"[warn] DGEMMWorker: BLAS still using {_actual} threads",
                      file=sys.stderr)
        except Exception:
            pass
        self._A_block = None
        self._B = None

    def ready(self):
        return True

    def load(self, A_block, B):
        """Receive and store input matrices; returns True when data is local.

        Old arrays are explicitly released before new copies are made so that
        old-B (288 MiB for M=6144) is freed before new-B is allocated.
        Without this, old-B + new-B + plasma-B overlap in memory, pushing
        peak usage above the 2 GiB worker limit.
        np.array() forces process-heap allocation, releasing plasma refs when
        load() returns so plasma holds at most one A_block+B pair at a time."""
        import numpy as np
        self._A_block = None   # free old 72 MiB before new allocation
        self._B = None         # free old 288 MiB before new allocation
        self._A_block = np.array(A_block)
        self._B = np.array(B)
        return True

    def compute(self):
        """Execute C_block = A_block @ B. Returns (t_s, flops, C_block)."""
        import time, numpy as np
        t0 = time.perf_counter()
        C_block = np.matmul(self._A_block, self._B)
        t = time.perf_counter() - t0
        flops = 2 * self._A_block.shape[0] * self._A_block.shape[1] * self._B.shape[1]
        return t, flops, C_block


@ray.remote
def remote_ep(num_pairs, batch_size):
    """NAS EP: Gaussian pairs binned by L∞-norm into 10 radial bins."""
    import time
    import numpy as np
    EP_BINS = 10
    counts = np.zeros(EP_BINS, dtype=np.int64)
    sx = sy = 0.0
    remaining = num_pairs
    t0 = time.perf_counter()
    while remaining > 0:
        n = min(batch_size, remaining)
        xy = np.random.standard_normal((n, 2))
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


@ray.remote(num_cpus=0)
class StreamBarrier:
    """Release all n_parties callers at once.

    Async actor: every caller blocks server-side on a shared asyncio.Event, so
    when the last participant arrives all of them are woken within ~1 ms of
    each other.  Against a multi-second measurement window that residual skew
    is negligible, which is what makes an aggregate-bandwidth number
    meaningful: all N workers are provably in their timed region together."""

    def __init__(self, n_parties):
        import asyncio
        self._n_parties = n_parties
        self._arrived = 0
        self._event = asyncio.Event()

    async def wait(self):
        self._arrived += 1
        if self._arrived >= self._n_parties:
            self._event.set()
        await self._event.wait()
        return True


@ray.remote
def remote_stream_triad(n_elements, alpha, n_warmup, barrier, measure_seconds,
                        chunk_elems):
    """STREAM Triad: A = B + alpha*C, sustained over a synchronised window.

    Arrays are allocated once per worker process and reused across calls so
    all physical pages are resident (no page-fault noise in the timed pass).
    The Triad is evaluated in cache-resident chunks so it moves exactly the
    3 arrays of DRAM traffic the byte count assumes (see STREAM_CHUNK_ELEMS).
    After allocation and n_warmup warm-up Triads, the worker joins `barrier`;
    all N workers are released simultaneously and then run Triads back-to-back
    for `measure_seconds`.  Each worker reports its own sustained bandwidth
    over a window that genuinely overlaps every other worker's.

    Returns (t_elapsed_s, n_iters, checksum)."""
    import time
    import numpy as np

    # Module-level cache: allocate once, reuse forever in this worker process.
    global _stream_B, _stream_C, _stream_A, _stream_init_n
    try:
        _stream_init_n
    except NameError:
        _stream_init_n = 0

    if _stream_init_n != n_elements:
        _stream_B = np.random.standard_normal(n_elements)
        _stream_C = np.random.standard_normal(n_elements)
        _stream_A = np.empty(n_elements, dtype=np.float64)
        # Touch every page to ensure physical allocation and TLB population.
        np.multiply(_stream_C, alpha, out=_stream_A)
        np.add(_stream_A, _stream_B, out=_stream_A)
        _stream_init_n = n_elements

    B, C, A = _stream_B, _stream_C, _stream_A

    def triad():
        """A = B + alpha*C over LLC-resident chunks: 3 array-passes of DRAM
        traffic, matching the bytes reported by the caller."""
        for i in range(0, n_elements, chunk_elems):
            s = slice(i, i + chunk_elems)
            np.multiply(C[s], alpha, out=A[s])
            np.add(A[s], B[s], out=A[s])

    for _ in range(n_warmup):
        triad()

    # Everything above is per-worker setup with highly variable cost; the
    # barrier absorbs that skew so the timed windows below coincide.
    ray.get(barrier.wait.remote())

    n_iters = 0
    t0 = time.perf_counter()
    while True:
        triad()
        n_iters += 1
        t = time.perf_counter() - t0
        if t >= measure_seconds:
            break
    return t, n_iters, float(A[0])  # checksum prevents dead-code elimination


@ray.remote
def remote_random_chase(n_elements, n_warmup, n_measured):
    """Random pointer chasing: traverse a randomised int32 permutation.
    n_warmup dependent accesses are made outside the timer to warm caches
    consistently; n_measured accesses are timed. Each access depends on the
    value read at the previous position (full sequential dependency chain).

    Attempts to use a GCC-compiled C kernel for accuracy. Falls back to a
    Python loop if gcc is unavailable; in that case absolute latency values
    include ~50 ns of Python loop overhead per access, but the protected/plain
    relative comparison remains valid.

    Returns (t_compute_s, end_pos, used_c_kernel)."""
    import ctypes
    import os
    import subprocess
    import tempfile
    import time

    import numpy as np

    # In-place shuffle avoids the 512 MiB int64 intermediate from permutation().
    rng = np.random.default_rng()
    arr = np.arange(n_elements, dtype=np.int32)
    rng.shuffle(arr)

    # ── C kernel (accurate clock_gettime timing, no Python overhead) ─────────
    _CHASE_C = r"""
#include <stdint.h>
#include <time.h>
void chase(int32_t *arr, long n_warmup, long n_measured,
           long *end_pos, double *elapsed_s) {
    int32_t pos = 0;
    for (long i = 0; i < n_warmup; i++) pos = arr[pos];
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (long i = 0; i < n_measured; i++) pos = arr[pos];
    clock_gettime(CLOCK_MONOTONIC, &t1);
    *end_pos = pos;
    *elapsed_s = (t1.tv_sec - t0.tv_sec) +
                 (t1.tv_nsec - t0.tv_nsec) * 1e-9;
}
"""
    c_path  = tempfile.mktemp(suffix=".c")
    so_path = tempfile.mktemp(suffix=".so")
    try:
        with open(c_path, "w") as f:
            f.write(_CHASE_C)
        ret = subprocess.run(
            ["gcc", "-O2", "-shared", "-fPIC", "-o", so_path, c_path],
            capture_output=True,
        )
        if ret.returncode == 0:
            lib = ctypes.CDLL(so_path)
            lib.chase.restype = None
            lib.chase.argtypes = [
                ctypes.POINTER(ctypes.c_int32),
                ctypes.c_long, ctypes.c_long,
                ctypes.POINTER(ctypes.c_long),
                ctypes.POINTER(ctypes.c_double),
            ]
            ptr     = arr.ctypes.data_as(ctypes.POINTER(ctypes.c_int32))
            end_pos = ctypes.c_long(0)
            elapsed = ctypes.c_double(0.0)
            lib.chase(ptr, n_warmup, n_measured,
                      ctypes.byref(end_pos), ctypes.byref(elapsed))
            return float(elapsed.value), int(end_pos.value), True
    except Exception:
        pass
    finally:
        for p in (c_path, so_path):
            try:
                os.unlink(p)
            except OSError:
                pass

    # ── Python fallback ───────────────────────────────────────────────────────
    # Reduce measured count to avoid Ray health-check timeout (~20s limit).
    # ns/access is the same metric; fewer iterations just reduce averaging.
    py_measured = min(n_measured, 5_000_000)
    py_warmup   = min(n_warmup,   500_000)
    print(
        f"[warn] remote_random_chase: gcc unavailable; using Python loop "
        f"({py_measured // 1_000_000}M iters). Absolute latency includes "
        f"~50 ns/iter Python overhead. Protected/plain comparison is still valid.",
        file=sys.stderr,
    )
    pos = 0
    for _ in range(py_warmup):
        pos = int(arr[pos])
    t0 = time.perf_counter()
    for _ in range(py_measured):
        pos = int(arr[pos])
    t = time.perf_counter() - t0
    return t, pos, False


# ---------------------------------------------------------------------------
# CG actor (holds persistent row block for distributed SpMV)
# ---------------------------------------------------------------------------

@ray.remote(num_cpus=0)
class CGWorkerActor:
    """Holds one row block of A for distributed strong-scaling CG.
    Created once per scaling point so matrix setup is outside the timed loop."""
    def __init__(self, n, nz, row_start, row_count):
        import numpy as np
        import scipy.sparse as sp
        rng = np.random.default_rng(42)
        cols = rng.integers(0, n, size=(n, nz))
        vals = rng.uniform(-1.0, 1.0, size=(n, nz))
        rows_idx = np.repeat(np.arange(n), nz)
        A = sp.coo_matrix(
            (vals.ravel(), (rows_idx, cols.ravel())), shape=(n, n)
        ).tocsr()
        self.A_block = A[row_start:row_start + row_count, :]
        self._nnz = int(self.A_block.nnz)
        # Preallocated result buffer: scipy's `A @ x` allocates a fresh output
        # on every multiply, and at these sizes numpy may serve that from
        # mmap/munmap, whose page-table churn is expensive inside an SEV guest.
        # MPI writes into a malloc'd buffer once, so we do the same.
        self._y = np.zeros(row_count, dtype=np.float64)
        # Raw CSR kernel, bypassing scipy's dispatch and allocation layer.
        # Private API, so fall back to `A @ x` if it ever moves.
        try:
            from scipy.sparse import _sparsetools
            self._csr_matvec = _sparsetools.csr_matvec
        except Exception:
            self._csr_matvec = None

    def get_nnz(self):
        return self._nnz

    def uses_raw_kernel(self):
        return self._csr_matvec is not None

    def spmv(self, x, target_ms, min_reps, max_reps):
        """Timed SpMV, reported per multiply.

        Two things keep the timer on the kernel rather than on Ray:
        `x` arrives as a plasma-backed buffer, so it is copied into a private
        array *before* t0 (otherwise shared-memory access and first-touch page
        faults land inside the measurement); and the multiply is repeated,
        because a single SpMV over one row block can be far below the
        per-call noise floor.  The repetition count is derived from a warm-up
        multiply so the timed loop runs for about `target_ms` at any class or
        worker count.  Dividing by it yields the same quantity MPI's
        t_compute_max_ms reports, with the noise divided by the count.

        Returns (t_per_multiply_s, y, reps_used)."""
        import time
        import numpy as np
        # Private writable copy: `x` arrives as a read-only plasma mapping, and
        # the SpMV gathers from it once per nonzero.  MPI receives x into a
        # malloc'd buffer, so copying here matches it and keeps shared-memory
        # access cost out of the kernel measurement.
        x = np.array(x, dtype=np.float64)
        A = self.A_block
        mv = self._csr_matvec

        def one(dst):
            if mv is None:
                return A @ x
            dst.fill(0.0)                     # csr_matvec accumulates into y
            mv(A.shape[0], A.shape[1], A.indptr, A.indices, A.data, x, dst)
            return dst

        y = self._y
        # Warm-up doubles as the calibration sample: fault pages, prime the
        # kernel, and measure one multiply to size the timed loop.
        t_warm = time.perf_counter()
        y = one(y)
        t_one = time.perf_counter() - t_warm

        reps = int((target_ms / 1000.0) / t_one) if t_one > 0 else max_reps
        reps = max(min_reps, min(max_reps, reps))

        t0 = time.perf_counter()
        for _ in range(reps):
            y = one(y)
        t = (time.perf_counter() - t0) / reps
        return t, y, reps


def _make_cg_actors(n, nz, n_active, worker_node_ids):
    base, rem = divmod(n, n_active)
    row_counts = [base + (1 if i < rem else 0) for i in range(n_active)]
    row_starts  = [sum(row_counts[:i]) for i in range(n_active)]
    actors = [
        CGWorkerActor.options(
            scheduling_strategy=NodeAffinitySchedulingStrategy(
                node_id=worker_node_ids[i], soft=False
            )
        ).remote(n, nz, row_starts[i], row_counts[i])
        for i in range(n_active)
    ]
    ray.get([a.get_nnz.remote() for a in actors])
    return actors


# ---------------------------------------------------------------------------
# Per-run dispatch helpers (one call = one complete round across N workers)
# ---------------------------------------------------------------------------

def _make_dgemm_actors(n_active, worker_node_ids):
    """Create one DGEMMWorker actor per worker node and wait until all are placed."""
    actors = [
        DGEMMWorker.options(
            scheduling_strategy=NodeAffinitySchedulingStrategy(
                node_id=worker_node_ids[i], soft=False
            )
        ).remote()
        for i in range(n_active)
    ]
    ray.get([a.ready.remote() for a in actors])
    return actors


def _once_dgemm_actors(m, actors):
    """Scatter A-blocks + B to persistent DGEMMWorker actors, gather C-blocks.

    t_scatter: all load() acks received — inputs are local on each worker node.
    t_round:   compute() submission to all C-blocks received — compute + gather.

    Explicit ray.put() + ray_free() is required so we hold handles to the
    plasma entries.  Passing numpy arrays directly as method arguments creates
    internal ObjectRefs we cannot free, causing old plasma entries (360 MiB for
    M=6144) to linger until Ray's GC runs.  On the next iteration those stale
    entries overlap with fresh ones, pushing plasma usage to 720 MiB and
    triggering an OOM on 2 GiB workers (plasma store is 614 MiB by default).
    ray_free() after the load() ack forces immediate eviction."""
    from ray._private.internal_api import free as ray_free
    n_active = len(actors)
    A = np.random.standard_normal((m, m))
    B = np.random.standard_normal((m, m))
    base, rem = divmod(m, n_active)
    row_counts = [base + (1 if i < rem else 0) for i in range(n_active)]
    starts = [sum(row_counts[:i]) for i in range(n_active)]

    # Put B once and each A-block separately so we can free them explicitly.
    B_ref = ray.put(B)
    block_refs = [ray.put(A[starts[i]:starts[i] + row_counts[i], :])
                  for i in range(n_active)]
    del A, B  # release head-side copies immediately

    # Scatter: deliver inputs to each actor, wait for acks.
    t0 = time.perf_counter()
    load_refs = [actors[i].load.remote(block_refs[i], B_ref)
                 for i in range(n_active)]
    ray.get(load_refs)
    t_scatter = time.perf_counter() - t0

    # Force eviction from all plasma stores — actors hold heap copies via .copy()
    # so they no longer reference these plasma objects.
    ray_free(block_refs + [B_ref])

    # Compute + gather: run matmul on each actor, collect C-blocks.
    t1 = time.perf_counter()
    compute_refs = [actor.compute.remote() for actor in actors]
    outs = ray.get(compute_refs)
    t_round = time.perf_counter() - t1
    ray_free(compute_refs)  # C-block results are in `outs`; evict from plasma

    t_compute = max(r[0] for r in outs)
    total_flops = sum(r[1] for r in outs)
    return t_scatter, t_round, t_compute, total_flops


def _pinned(node_id):
    """Hard-pin one task to one worker node.

    Replaces PlacementGroupSchedulingStrategy for the stateless workloads.
    A STRICT_SPREAD placement group guarantees one bundle per node but not
    *which* nodes, so each campaign got an arbitrary subset of the 13 workers.
    Since worker i is pinned to physical core i-1 and those cores span several
    CCDs with separate L3 slices, the subset changed aggregate memory
    bandwidth between campaigns -- a ~10% SEV-vs-plain swing in STREAM with
    inconsistent sign, sitting on top of a 0.2-1.5% within-campaign CV.
    Each worker node has exactly 1 CPU, so hard affinity preserves the
    one-task-per-node guarantee the placement group provided.
    """
    return NodeAffinitySchedulingStrategy(node_id=node_id, soft=False)


def _once_ep_n(num_pairs, n_active, node_ids):
    """Dispatch n_active EP tasks simultaneously, one per pinned worker."""
    from ray._private.internal_api import free as ray_free
    t0 = time.perf_counter()
    refs = [remote_ep.options(scheduling_strategy=_pinned(node_ids[i]))
            .remote(num_pairs, EP_BATCH)
            for i in range(n_active)]
    t_scatter = time.perf_counter() - t0
    t1 = time.perf_counter()
    outs = ray.get(refs)
    ray_free(refs)
    t_round = time.perf_counter() - t1
    t_compute = max(r[0] for r in outs)
    total_pairs = sum(r[1] for r in outs)
    return t_scatter, t_round, t_compute, total_pairs


def _once_stream_n(n_elements, alpha, n_warmup, n_active, node_ids,
                   measure_seconds, chunk_elems):
    """Dispatch n_active STREAM Triad tasks and measure them concurrently.

    The tasks rendezvous on a barrier after their per-worker setup, then all
    sustain Triads for `measure_seconds`.  Because the timed windows overlap by
    construction, summing the bytes each worker actually moved and dividing by
    the longest window is a true aggregate bandwidth for N concurrent workers.

    The barrier actor is num_cpus=0, so it never competes for a worker's CPU.
    Exactly n_active tasks are pinned to exactly n_active distinct nodes, so
    every party can reach the barrier and it cannot deadlock on scheduling."""
    from ray._private.internal_api import free as ray_free
    barrier = StreamBarrier.remote(n_active)
    try:
        t0 = time.perf_counter()
        refs = [remote_stream_triad.options(scheduling_strategy=_pinned(node_ids[i]))
                .remote(n_elements, alpha, n_warmup, barrier, measure_seconds,
                        chunk_elems)
                for i in range(n_active)]
        t_scatter = time.perf_counter() - t0
        t1 = time.perf_counter()
        outs = ray.get(refs)
        ray_free(refs)
        t_round = time.perf_counter() - t1
        # Longest measurement window; all windows start together at the barrier.
        t_compute = max(r[0] for r in outs)
        # 3 array passes (read B, read C, write A) per Triad, summed over the
        # Triads each worker actually completed inside the shared window.
        total_bytes = sum(r[1] for r in outs) * 3 * n_elements * 8
        return t_scatter, t_round, t_compute, total_bytes
    finally:
        ray.kill(barrier)


def _once_random_n(n_elements, n_warmup, n_measured, n_active, node_ids):
    """Dispatch n_active RANDOM tasks simultaneously, one per pinned worker."""
    from ray._private.internal_api import free as ray_free
    t0 = time.perf_counter()
    refs = [remote_random_chase.options(scheduling_strategy=_pinned(node_ids[i]))
            .remote(n_elements, n_warmup, n_measured)
            for i in range(n_active)]
    t_scatter = time.perf_counter() - t0
    t1 = time.perf_counter()
    outs = ray.get(refs)
    ray_free(refs)
    t_round = time.perf_counter() - t1
    t_compute = max(r[0] for r in outs)   # slowest worker
    return t_scatter, t_round, t_compute


def _once_cg_n(actors, n, niter, target_ms, min_reps, max_reps):
    """niter rounds of scatter-x / distributed SpMV / gather-y_block."""
    from ray._private.internal_api import free as ray_free
    x = np.ones(n, dtype=np.float64)
    t_scatter_total = t_compute_total = 0.0
    t_start = time.perf_counter()
    for _ in range(niter):
        t0 = time.perf_counter()
        x_ref = ray.put(x)
        t_scatter_total += time.perf_counter() - t0
        refs = [actor.spmv.remote(x_ref, target_ms, min_reps, max_reps)
                for actor in actors]
        outs = ray.get(refs)
        ray_free([x_ref])
        t_compute_total += max(r[0] for r in outs)
        y = np.concatenate([r[1] for r in outs])
        norm = float(np.linalg.norm(y))
        if norm > 0:
            x = y / norm
    t_round = time.perf_counter() - t_start
    return t_scatter_total, t_round, t_compute_total


# ---------------------------------------------------------------------------
# CSV output
# ---------------------------------------------------------------------------

SCALING_FIELDS = [
    "N", "run", "workload", "size",
    # scatter_ms    : DGEMM: DGEMMWorker.load() wall time — ack means inputs are
    #                 local on the worker node (true network scatter).
    #                 EP/STREAM/RANDOM: task-submission time (scalar args only,
    #                 trivially small).  CG: ray.put(x) local write only.
    # compute_max_ms: slowest worker's kernel time, actor/function-reported.
    # noncompute_ms : full_round_ms - compute_max_ms.  DGEMM: ≈ gather transfer
    #                 (C_block return) + head overhead.  Other workloads: includes
    #                 Ray scheduling, worker input-fetch, and head overhead.
    # round_ms      : compute() submission to ray.get() return (excludes scatter).
    # full_round_ms : scatter_ms + round_ms — true end-to-end wall time.
    "scatter_ms", "compute_max_ms", "noncompute_ms", "round_ms", "full_round_ms",
    "throughput", "unit",
]


def _make_writer(csv_path):
    if not csv_path:
        return None, None
    f = open(csv_path, "w", newline="")
    w = csv.DictWriter(f, fieldnames=SCALING_FIELDS)
    w.writeheader()
    f.flush()
    return f, w


def _emit(writer, f_out, n_active, run_idx, workload, size,
          t_sc, t_round, t_comp, throughput, unit_str):
    t_full      = t_sc + t_round          # true end-to-end (scatter + round)
    noncompute  = max(0.0, t_full - t_comp)
    row = {
        "N":               n_active,
        "run":             run_idx,
        "workload":        workload,
        "size":            size,
        "scatter_ms":      f"{t_sc * 1e3:.3f}",
        "compute_max_ms":  f"{t_comp * 1e3:.3f}",
        "noncompute_ms":   f"{noncompute * 1e3:.3f}",
        "round_ms":        f"{t_round * 1e3:.3f}",
        "full_round_ms":   f"{t_full * 1e3:.3f}",
        "throughput":      f"{throughput:.4f}",
        "unit":            unit_str,
    }
    if writer:
        writer.writerow(row)
        f_out.flush()


# ---------------------------------------------------------------------------
# Scaling study
# ---------------------------------------------------------------------------

def run_scaling(scaling_list, runs, head_ip, csv_path, timeout,
                workloads=None, cg_classes_arg=None):
    """
    For each N in scaling_list: create a STRICT_SPREAD placement group across
    N worker nodes, run the selected workloads `runs` times each, write every
    row to the CSV immediately.

    workloads: set of strings from {"DGEMM","EP","STREAM","RANDOM","CG"}.
               Defaults to all five.
    """
    if workloads is None:
        workloads = {"DGEMM", "EP", "STREAM", "RANDOM", "CG"}

    if cg_classes_arg:
        cg_classes = [c.strip() for c in cg_classes_arg.split(",")]
    else:
        # Classes S (n=1400) and W (n=7000) have Ray RPC overhead >> compute
        # time at most N values; only A (n=14000) and above give stable results.
        cg_classes = ["A"]

    max_n = max(scaling_list)

    # ── Wait for all workers ─────────────────────────────────────────────────
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
            sys.exit(f"\nTimed out after {timeout}s waiting for {max_n} workers")
        time.sleep(0.5)

    f_out, writer = _make_writer(csv_path)

    try:
        for n_active in sorted(scaling_list):
            # Order by worker IP (192.168.100.<id+1>), NOT by NodeID.  NodeID
            # is a random hex string, so sorting on it picks an arbitrary
            # subset of physical workers that differs between campaigns.  Each
            # worker is pinned to physical core <id-1>, and those cores span
            # several CCDs with separate L3 slices, so an arbitrary subset
            # changes aggregate memory bandwidth — which showed up as a ~10%
            # SEV-vs-plain difference in STREAM with inconsistent sign, on top
            # of a 0.2-1.5% within-campaign CV.  Sorting by IP makes N=k always
            # mean workers 1..k in every campaign.
            worker_node_ids = [
                nid for _, nid in sorted(
                    ((nd["NodeManagerAddress"], nd["NodeID"])
                     for nd in ray.nodes()
                     if nd["Alive"] and nd["NodeManagerAddress"] != head_ip),
                    key=lambda t: tuple(int(o) for o in t[0].split("."))
                )
            ][:n_active]

            print(f"N={n_active:2d}  ", end="", flush=True)

            # ── DGEMM ──────────────────────────────────────────────────────
            # Run first so the worker processes the stateless workloads spawn
            # (one per node, ~300 MiB each) don't compete with the DGEMMWorker
            # actors for RAM.  For M=6144 the B-matrix alone is 288 MiB.
            if "DGEMM" in workloads:
                for m, valid_ns in sorted(DGEMM_CONFIGS.items()):
                    if n_active not in valid_ns:
                        continue
                    dgemm_actors = _make_dgemm_actors(n_active, worker_node_ids)
                    for _ in range(2):          # warm-up (not recorded)
                        _once_dgemm_actors(m, dgemm_actors)
                    for run_idx in range(1, runs + 1):
                        t_sc, t_rd, t_cp, flops = _once_dgemm_actors(m, dgemm_actors)
                        tp = flops / t_cp / 1e9 if t_cp > 0 else 0.0
                        _emit(writer, f_out, n_active, run_idx,
                              "DGEMM", str(m), t_sc, t_rd, t_cp, tp, "GFLOP/s")
                    print("d", end="", flush=True)
                    for actor in dgemm_actors:
                        ray.kill(actor)

            # ── EP ─────────────────────────────────────────────────────────
            if "EP" in workloads:
                for run_idx in range(1, runs + 1):
                    for pairs in EP_PAIRS:
                        exp = pairs.bit_length() - 1
                        t_sc, t_rd, t_cp, total_p = _once_ep_n(pairs, n_active, worker_node_ids)
                        tp = total_p / t_cp / 1e6 if t_cp > 0 else 0.0
                        _emit(writer, f_out, n_active, run_idx,
                              "EP", f"2^{exp}", t_sc, t_rd, t_cp, tp, "Mop/s")
                    print("e", end="", flush=True)

            # ── STREAM Triad ───────────────────────────────────────────────
            if "STREAM" in workloads:
                for run_idx in range(1, runs + 1):
                    t_sc, t_rd, t_cp, total_bytes = _once_stream_n(
                        STREAM_ARRAY_ELEMS, STREAM_ALPHA, STREAM_WARMUP,
                        n_active, worker_node_ids, STREAM_MEASURE_SECONDS,
                        STREAM_CHUNK_ELEMS,
                    )
                    tp = total_bytes / t_cp / (1024 ** 3) if t_cp > 0 else 0.0
                    _emit(writer, f_out, n_active, run_idx,
                          "STREAM", "128MiB", t_sc, t_rd, t_cp, tp, "GiB/s")
                    print("s", end="", flush=True)

            # ── RANDOM pointer chasing ─────────────────────────────────────
            if "RANDOM" in workloads:
                for run_idx in range(1, runs + 1):
                    t_sc, t_rd, t_cp = _once_random_n(
                        RANDOM_ARRAY_ELEMS, RANDOM_WARMUP, RANDOM_MEASURED,
                        n_active, worker_node_ids,
                    )
                    # ns/access = slowest worker compute time / accesses
                    tp = t_cp / RANDOM_MEASURED * 1e9 if t_cp > 0 else 0.0
                    _emit(writer, f_out, n_active, run_idx,
                          "RANDOM", "256MiB", t_sc, t_rd, t_cp, tp, "ns/access")
                    print("r", end="", flush=True)

            # ── CG (one class at a time to limit per-node memory) ──────────
            if "CG" in workloads:
                for cls in cg_classes:
                    p = CG_CLASSES[cls]
                    actors = _make_cg_actors(p["n"], p["nz"], n_active, worker_node_ids)
                    for run_idx in range(1, runs + 1):
                        t_sc, t_rd, t_cp = _once_cg_n(
                            actors, p["n"], p["niter"],
                            CG_SPMV_TARGET_MS, CG_SPMV_MIN_REPS,
                            CG_SPMV_MAX_REPS)
                        ops = 2 * p["n"] * p["nz"] * p["niter"]
                        tp = ops / t_cp / 1e6 if t_cp > 0 else 0.0
                        _emit(writer, f_out, n_active, run_idx,
                              "CG", cls, t_sc, t_rd, t_cp, tp, "Mop/s")
                        print("c", end="", flush=True)
                    for actor in actors:
                        ray.kill(actor)

            print(" ✓")
    finally:
        if f_out:
            f_out.close()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--timeout",  type=int, default=600,
                    help="seconds to wait for workers (default: 600)")
    ap.add_argument("--csv",      metavar="FILE",
                    help="write results to a CSV file")
    ap.add_argument("--scaling",  metavar="N1,N2,...", required=True,
                    help="comma-separated worker counts, e.g. 1,2,...,13")
    ap.add_argument("--runs",     type=int, default=10,
                    help="runs per scaling point (default: 10)")
    ap.add_argument("--workloads", metavar="DGEMM,EP,STREAM,RANDOM,CG",
                    default="DGEMM,EP,STREAM,RANDOM,CG",
                    help="comma-separated workloads to run (default: all)")
    ap.add_argument("--cg-classes", metavar="S,W,A,...",
                    help="CG classes to run (default: S,W,A)")
    # Legacy flags kept for backward compatibility with run-scaling-*.sh scripts
    ap.add_argument("--cg-only", action="store_true",
                    help="shorthand for --workloads CG")
    ap.add_argument("--skip-cg-a", action="store_true",
                    help="remove class A from CG run")
    args = ap.parse_args()

    import warnings
    warnings.filterwarnings("ignore")

    if args.cg_only:
        args.workloads = "CG"

    workloads = {w.strip().upper() for w in args.workloads.split(",")}

    cg_classes_arg = args.cg_classes
    if args.skip_cg_a and not cg_classes_arg:
        cg_classes_arg = "S,W"

    ray.init(address="auto")
    head_ip = ray.get_runtime_context().gcs_address.split(":")[0]

    scaling_list = [int(x.strip()) for x in args.scaling.split(",")]
    run_scaling(
        scaling_list, args.runs, head_ip, args.csv, args.timeout,
        workloads=workloads, cg_classes_arg=cg_classes_arg,
    )
    ray.shutdown()


if __name__ == "__main__":
    main()
