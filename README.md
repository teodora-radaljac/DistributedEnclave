# DistributedEnclave

Performance study of AMD SEV-SNP confidential VMs running distributed workloads.
Two distributed computing frameworks are benchmarked — **OpenMPI** and **Ray** —
each running inside minimal initramfs-based CVMs on an AMD EPYC 7313P host.
The goal is to isolate and quantify the overhead introduced by SEV-SNP (inline
DRAM encryption + attestation) on real distributed HPC workloads.

## Benchmarks

| Workload | Class | Type | What it measures |
|---|---|---|---|
| NAS EP | 2^24 / 2^26 / 2^28 samples | Embarrassingly parallel | Pure compute; minimal inter-node communication |
| NAS CG | S / W / A / B / C | Strong scaling | Sparse matrix–vector multiply; scatter/gather intensive |
| DGEMM | 512 / 1024 / 2048 | Strong scaling | Dense matrix multiply; memory-bandwidth bound |

SEV and plain runs are compared at identical worker counts (N = 1–13) to produce
overhead curves. 100 runs per point; minimum latency / maximum throughput is reported.

## Hardware

- **Host:** AMD EPYC 7313P — 16 physical cores / 32 SMT threads, 1 NUMA node, ~61 GiB RAM
- Each worker VM gets **1 vCPU** pinned to a dedicated physical core (both hyperthreads via `taskset`)
- Maximum workers: 13 (leaves cores 13–15 for the host and Ray head)

## Repository structure

```
src/                    C sources for the OpenMPI master/worker application
analysis/               Python analysis and plotting scripts
  bench_ray.py          Ray benchmark driver (run from the host)
  test_ray.py           Ray cluster smoke test
  make_plots.py / ...   Plot generation for MPI results
fort/                   Go source for the ATLS/attestation layer (Ray stack)
  atls/                 ATLS library — TLS 1.3 + Exported Authenticator
  client/               Fort worker client (cross-compiled into the Ray image)
  server/               Fort ATLS verifier + Ray CA (runs on the host)
  tools/                compute-measurement utility
vmbuild/
  worker-ext/           Buildroot external tree — OpenMPI worker image
  fort-ext/             Buildroot external tree — Ray worker image
  launch/
    launch_worker_min_pinned.sh    Launch one SEV-SNP MPI worker
    launch_worker_min_plain.sh     Launch one plain MPI worker
    launch_all_pinned.sh / ...     Launch N MPI workers
    launch-fort-sev.sh             Launch one SEV-SNP Ray worker
    launch-fort-nosnp.sh           Launch one plain Ray worker
    launch-fort-workers-sev.sh     Launch N SEV-SNP Ray workers
    launch-fort-workers-nosnp.sh   Launch N plain Ray workers
    setup-bridge.sh / teardown-bridge.sh
  refresh-server-cert.sh   Regenerate ATLS server cert and rebuild Ray worker image
  assemble_overlay.sh      Pull MPI stack from master VM into the worker overlay
run-both-campaigns.sh   Both Ray campaigns back-to-back (preferred entry point)
run-scaling-sev.sh      Full SEV-SNP Ray scaling study (host entry point)
run-scaling-nosnp.sh    Full plain-VM Ray scaling study (host entry point)
RUNBOOK.md              Operational runbook — MPI cluster setup and benchmark procedure
```

## The two worker stacks

### OpenMPI workers

The MPI setup follows the PRRTE dynamic-process model. A **master VM** (full Ubuntu
qcow2, 16 vCPUs) runs `prte` and drives work distribution. **Worker VMs** are
minimal Buildroot initramfs images containing only OpenMPI, OpenSSH, and the worker
binaries. The master SSH's into workers to launch `prted`, then submits jobs via
`mpiexec`.

```
Host ──── tap0 ──── master VM  (Ubuntu qcow2, SEV or plain)
          tap1 ──── worker 1   (Buildroot initramfs, SEV or plain)
          tap2 ──── worker 2
          ...
```

Network: each VM gets a static IP via the kernel `ip=` parameter
(`192.168.100.2` for master, `.3`–`.16` for workers 1–14).

### Ray workers (Fort)

There is no master VM. The **Ray head** runs directly on the host. Each worker VM
boots a Buildroot initramfs with Python 3.14, Ray, and the `fort-client` binary.
On boot, `fort-client` performs an ATLS (Attestation-bound TLS) handshake with the
host-side `fort/server`, which verifies the worker's SEV-SNP attestation report and
issues it a Ray TLS certificate. The worker then joins the Ray cluster.

```
Host:  fort/server  ──── ATLS/attestation ──── worker 1 (initramfs)
       Ray head     ──── Ray cluster TLS  ──── worker 2
                                               ...
```

Network: each worker computes its IP (`192.168.100.(ID+1)`) from the kernel
`ray_worker_id` parameter and configures it via `network_up.sh` at boot.

## Building

Both stacks use the same upstream Buildroot tree (cloned at `../buildroot/`
relative to this repo). They are built into separate output directories.

### OpenMPI worker image

```sh
# Pull the pre-built MPI stack from the master VM into the overlay
bash vmbuild/assemble_overlay.sh

cd ../buildroot
make BR2_EXTERNAL=../DistributedEnclave/vmbuild/worker-ext O=output-mpi worker_defconfig
make O=output-mpi -j$(nproc)
# outputs: output-mpi/images/bzImage  output-mpi/images/rootfs.cpio.gz
```

### Ray worker image

First-time setup — generate a stable ATLS server certificate and bake it into
the image (workers pin this cert to authenticate the host server):

```sh
bash vmbuild/refresh-server-cert.sh
# Builds fort/server, generates atls-server.crt, copies it into the overlay,
# then runs make fort-client-rebuild all in ../buildroot/output-ray/
```

On subsequent builds (no cert rotation needed):

```sh
cd ../buildroot
make BR2_EXTERNAL=../DistributedEnclave/vmbuild/fort-ext O=output-ray fort_defconfig
make O=output-ray -j$(nproc)
# outputs: output-ray/images/bzImage  output-ray/images/rootfs.cpio.gz
```

## Running

### Network setup (both stacks)

```sh
sudo vmbuild/launch/setup-bridge.sh 13   # creates br0 + tap0..tap12
```

### OpenMPI benchmark

See `RUNBOOK.md` for the full procedure. In brief:

```sh
# Launch master and workers
sudo bash vmbuild/launch/launch_master_plain.sh
sudo MEM=1G bash vmbuild/launch/launch_all_plain.sh 1 13

# SSH into master and run the benchmark
ssh -i ~/.ssh/vm_key root@192.168.100.2
bash /root/bench_run_all_v3.sh
```

### Ray benchmark

```sh
# Build the server binary
cd fort/server && go build -o server . && cd -

# Pre-authenticate sudo (workers need it for QEMU + KVM)
sudo -v

# Both campaigns back-to-back (recommended)
export FORT_OVMF_PATH=/path/to/OVMF.amdsev.fd
./run-both-campaigns.sh 13 10

# ...or one configuration at a time
./run-scaling-sev.sh 13 10      # results-scaling/scaling-sev-YYYYMMDD-HHMMSS.csv
./run-scaling-nosnp.sh 13 10    # results-scaling/scaling-nosnp-YYYYMMDD-HHMMSS.csv
```

`run-scaling-sev.sh` starts the ATLS server, starts the Ray head, launches all
CVMs in the background, then runs `analysis/bench_ray.py` across N = 1–13 workers.
Ctrl+C stops everything cleanly.

To run only NAS CG with a larger working set:

```sh
./run-scaling-sev.sh 13 10 1 cg-only "B,C"
```

### Running both campaigns

`run-both-campaigns.sh` runs the SEV-SNP and plain-VM campaigns one after the
other in a single sitting. Prefer it over invoking the two scripts by hand:

- **Back-to-back ordering.** Within a campaign the run-to-run CV is ~0.5%, but
  campaigns started hours apart have drifted by ~10% — larger than the SEV-SNP
  effect being measured. Running them together keeps host conditions close.
- **Unattended sudo.** VMs are booted with `sudo qemu-system-x86_64` and torn
  down with `sudo pkill`, but sudo's timestamp expires after ~15 min and the
  second campaign starts well over an hour in. The script authenticates once and
  refreshes in the background until it exits.
- **Independent phases.** A failure in the first campaign does not prevent the
  second from running; each phase's status and CSV path are reported at the end
  and written to `results-scaling/campaign-YYYYMMDD-HHMMSS.log`. The script exits
  non-zero if either phase failed.

```sh
./run-both-campaigns.sh [WORKERS [RUNS]]      # defaults: 13 workers, 10 runs
```

| Variable | Default | Purpose |
|---|---|---|
| `FORT_OVMF_PATH` | *(required)* | AMD SEV OVMF binary; validated before the sudo prompt |
| `WORKLOADS` | all | Subset to run, e.g. `WORKLOADS=STREAM,CG` |
| `CG_CLASSES` | `A` | NAS CG classes, e.g. `CG_CLASSES=C` |
| `ORDER` | `sev-first` | `sev-first` or `plain-first` — which campaign runs first |
| `SKIP_SEV` | *(unset)* | Set to `1` to run only the plain campaign |
| `SKIP_PLAIN` | *(unset)* | Set to `1` to run only the SEV campaign |

Whichever configuration runs second measures slightly slower, which biases the
reported penalty. `ORDER=plain-first` reverses the sequence, so measuring a pair
both ways brackets the effect:

```sh
# validate one workload cheaply before committing to a full pair
WORKLOADS=STREAM ./run-both-campaigns.sh 13 3

# same pair with the campaign order reversed, to quantify order bias
ORDER=plain-first ./run-both-campaigns.sh 13 10
```

### Environment overrides (Ray stack)

| Variable | Default | Purpose |
|---|---|---|
| `FORT_BUILDROOT_IMAGES` | `../buildroot/output-ray/images` | Path to kernel + initrd |
| `FORT_OVMF_PATH` | *(required for SEV)* | AMD SEV OVMF binary |
| `FORT_VERIFIER_IP` | `192.168.100.1` | ATLS server IP seen by workers |
| `FORT_VERIFIER_PORT` | `9443` | ATLS server port |
| `RAY_HEAD_IP` | first non-loopback IP | IP advertised to Ray workers |
| `FORT_RAY_OBJECT_STORE_MB` | *(Ray default)* | Ray object store size per worker |

## Analysis

```sh
# Ray results — scaling plots (SEV vs plain)
python analysis/bench_ray.py --help

# MPI results
python analysis/make_plots.py         # fig1-4: scaling, SEV vs plain
python analysis/make_3way_plots.py    # fig5-6: throughput decomposition
python analysis/make_full_vs_none.py  # fig7-8: full protection vs baseline
python analysis/compare_sev_plain.py  # SEV hardware cost (D_sev vs D_plain)
python analysis/analyze_overhead.py   # attestation + encryption overhead (A vs D)
```

MPI analysis scripts read from `bench_results_pin14/` (SEV) and
`bench_results_plain14/` (plain) and write figures to `plots/`.

