# RUNBOOK — SEV-SNP MPI benchmark klaster

Operativni vodič: kako je sve postavljeno i kako se pokreće. (Rad/paper je
zaseban — vidi `paper/` i `docs/`.)

---

## 1. Hardver i pristup

- **Host:** AMD EPYC 7313P, 16 fizičkih jezgara / 32 niti (SMT: cpu `n` i `n+16`
  su iste fizičke jezgre), 1 NUMA, ~61 GiB RAM. Hostname `rtisev`.
- **SSH na host:** `ssh teodora@147.91.12.238` (NOPASSWD sudo).
- **Mreža VM-ova:** bridge `br0` = 192.168.100.1; master = `.2`, workeri
  `worker1..worker14` = `.3 .. .16`. Workeri su iz mastera dostupni po hostname-u.
- **Pristup VM-ovima sa hosta:**
  ```bash
  ssh -i ~/.ssh/vm_key -o StrictHostKeyChecking=no root@192.168.100.2   # master
  ```
  > Plain master ima spor SSH banner (~30 s) jer `systemd-networkd-wait-online`
  > visi na bootu (kozmetički — mreža/ping/sshd rade). Koristiti
  > `-o ConnectTimeout=35` za plain master.

---

## 2. Struktura repozitorijuma

| Folder | Sadržaj |
|--------|---------|
| `src/` | C izvori MPI aplikacije (`master*.c`, `worker*.c`) |
| `analysis/` | Aktivne Python skripte za analizu/grafike (pokreću se iz root-a) |
| `vmbuild/` | Buildroot minimal-worker build + `launch/` (staging launch skripti) |
| `bench_results_pin14/` | SEV-SNP podaci (config A=atest+enc, D=baseline) |
| `bench_results_plain14/` | Plain podaci (config C=enc, D=baseline) |
| `bench_results_32/` | Stariji 32-worker set (referenca) |
| `plots/` | Generisane figure (`fig1..fig8`) |
| `diagrams/` | Mermaid dijagrami (`.mmd`) |
| `docs/` | Sadržaj rada (RW, ekstrakti) |
| `references/` | Pročitani radovi (PDF + tekstualni izvodi) |
| `paper/` | Aktivni draft rada (`.docx`) |
| `backups/` | tar.gz snapshot-i merenja |
| `archive/` | Stare/zamenjene skripte (`old_setup/`) — ne koristi se, čuva se za istoriju |
| `rezultati merenja/` | STARA merenja iz ranije faze (netaknuto) |

---

## 3. VM-ovi i launch skripte (na hostu, `~/launch/`)

Sve QEMU komande koriste `-smp <vCPU>,sockets=1,threads=1` (bez SMT u gostu,
1 soket). CPU model `EPYC-v4`, OVMF firmware.

| Skripta | Uloga | Ključno |
|---------|-------|---------|
| `launch_master.sh` | **SEV** master | `-machine q35,confidential-guest-support=sev0` + `sev-snp-guest`; `-smp 16` `-m 4G`; qcow2 `~/images/master.qcow2`; tap0 |
| `launch_master_plain.sh` | **Plain** master | isti qcow2, BEZ SEV objekata; `-smp 16` `-m 4G`; monitor `monitor-master-plain` |
| `launch_worker_min_pinned.sh` | **SEV** worker | Buildroot `bzImage`+`rootfs.cpio.gz`; `-smp 1` `-m 1G`; SEV; **`taskset -c N-1`** (1:1 sa jezgrom) |
| `launch_worker_min_plain.sh` | **Plain** worker | isto, BEZ SEV, BEZ taskset (neprikovan) |
| `launch_worker_min.sh` | SEV worker (baza, neprikovana) | osnova iz koje su izvedene gornje dve |
| `launch_all_pinned.sh A B` | pokreni SEV workere `A..B` | poziva `launch_worker_min_pinned.sh` |
| `launch_all_plain.sh A B` | pokreni plain workere `A..B` | poziva `launch_worker_min_plain.sh` |

> Stari **full-VM** pristup (svaki worker = ceo Ubuntu qcow2) je arhiviran u
> `~/launch/_archive_oldfullvm/` na hostu — više se ne koristi.

### Podizanje plain klastera (primer)
```bash
ssh teodora@147.91.12.238
sudo bash ~/launch/launch_master_plain.sh
sudo MEM=1G bash ~/launch/launch_all_plain.sh 1 14
```

### Provera šta je QEMU stvarno alocirao
```bash
# host strana — tražena topologija + stvarni RAM (RSS):
tr '\0' ' ' < /proc/<pid>/cmdline          # -smp / -m / -machine
grep VmRSS /proc/<pid>/status               # stvarno zauzet RAM
grep Cpus_allowed_list /proc/<pid>/status   # na kojim host jezgrima sme
# gost strana:
ssh root@192.168.100.2 lscpu                 # Socket(s)/Core(s)/Thread(s)
ssh root@192.168.100.2 'dmesg | grep -i "Memory Encryption"'  # SEV aktivan?
```

---

## 4. Benchmark (`/root/bench_run_all_v3.sh` na masteru)

Master pokreće DVM (PRTE) i deli zadatke workerima preko MPI dynamic-process
modela. Skripta je „produkciona" (počišćena verzija).

### Konfiguracije
| CFG | Atestacija | Enkripcija | Binari | ENC flag |
|-----|-----------|-----------|--------|----------|
| A | da | da | `master_npb`/`master_bench` | `""` |
| B | da | ne | — | — |
| C | ne | da | `_noatt` binari | `""` |
| D | ne | ne | `_noatt` binari | `--no-encrypt` |

A/B traže SEV atestaciju (N/A na plainu). Poređenje SEV↔plain koristi **D**
(baseline) i **C** (samo app-enkripcija).

### Workload-i (po N workera)
- **DGEMM** 512/1024/2048 (strong scaling)
- **EP** 2^24 / 2^26 / 2^28 (weak scaling, po-worker)
- **CG** S/W/A (strong; `t_round` je nepouzdan — gather artefakt)

### Env promenljive
```
RUNS=10           # ponavljanja po tački
CONFIG=D          # A/B/C/D
WORKERS="1 2 ..14"# lista N (space-separated)
ONLY=ep           # filter workload-a (ep|dgemm|cg); prazno = svi
RES=/root/bench_results_plain14   # izlazni dir
RESUME=1          # 1=preskoči postojeće CSV; 0=ponovo uradi
MAXTRIES=3        # pokušaja enrollmenta po tački
```
Primer (ponovi samo EP na N=14, config D):
```bash
RUNS=10 CONFIG=D RESUME=0 ONLY=ep WORKERS=14 \
  RES=/root/bench_results_plain14 bash /root/bench_run_all_v3.sh
```

### CSV format
Komentari počinju sa `#` (uklj. `# enrollment_total_ms`,
`# enrollment_workerK_ms`). Header:
`workload,num_workers,encryption,run,t_scatter_ms,t_compute_max_ms,t_gather_ms,t_round_ms[,t_comm_ms za DGEMM]`.
Bitne kolone: **compute = kolona 6**, **round = kolona 8**.
Imena: `dgemm_w{N}_{CFG}.csv`, `ep_2p{24,26,28}_w{N}_{CFG}.csv`, `cg_{S,W,A}_w{N}_{CFG}.csv`.

---

## 5. Poznati problem: prte enrollment + čišćenje

Na velikom N (naročito N=14) `prte` povremeno **core-dumpuje** pri enrollmentu
(intrinsični OpenMPI dynamic-connect bug). To ostavlja **orphan `prted`** na
workerima koji drže slotove → kaskada otkaza i hung `master_npb`.

**Pre svakog pokretanja proveriti da nema druge instance:**
```bash
ssh root@192.168.100.2 'pgrep -fc bench_run_all_[v]3'   # mora 0
```

**Potpuno čišćenje (kad zaglavi):**
```bash
# na masteru:
pkill -9 -f bench_run_all_[v]3; pkill -9 -f master_[n]pb
pkill -9 -x prte; pkill -9 -x prterun; pkill -9 -x mpiexec
for w in $(seq 1 14); do ssh worker$w 'killall -9 prted worker_npb_noat'; done
rm -rf /tmp/prte.* /tmp/ompi.* /tmp/pmix*
# zatim proveriti 0 orphan prted po workeru pre relaunch-a
```
> OPREZ sa `pkill -9 -f <obrazac>`: ako obrazac sadrži ime tekuće bash komande,
> ubije se sama ssh sesija. Koristiti bracket-trik: `pkill -9 -f bench_run_all_[v]3`,
> `master_[n]pb` itd., ili `pkill -9 -x <comm>` za prte/prterun/mpiexec.

---

## 6. CPU pinning (taskset)

- **SEV workeri:** prikovani `taskset -c N-1` → worker `k` na fizičko jezgro
  `k-1` (jezgra 0–13 za N=1..14). Master (16 vCPU) je **neprikovan** (lebdi 0–31)
  i u SEV i u plain varijanti.
- **Plain workeri:** podrazumevano **neprikovani**.
- Žive (već pokrenute) workere moguće je prikovati bez relaunch-a:
  ```bash
  pid=$(ps -ww -eo pid=,args= | grep "[q]emu.*monitor-worker${N}-plain," | awk '{print $1}')
  sudo taskset -acp $((N-1)) "$pid"
  ```

---

## 7. Analiza i grafici (`analysis/`, pokretati iz root-a)

```bash
& .venv\Scripts\python.exe analysis\make_plots.py          # fig1-4 (scaling, SEV-vs-plain)
& .venv\Scripts\python.exe analysis\make_3way_plots.py     # fig5-6 (throughput 4 konfig + dekompozicija)
& .venv\Scripts\python.exe analysis\make_full_vs_none.py   # fig7-8 (puna zaštita vs bez)
& .venv\Scripts\python.exe analysis\compare_sev_plain.py   # D_sev vs D_plain (SEV hw trošak)
& .venv\Scripts\python.exe analysis\analyze_overhead.py    # A-vs-D overhead (RESDIR env)
```
Sve čitaju `bench_results_pin14` (SEV) i `bench_results_plain14` (plain),
upisuju u `plots/`. Min-bazirana analiza (min po runovima) je robusna na
povremene loše placement-e.

---

## 8. Ključni nalazi (kontekst za rad)

- Compute je praktično nepromenjen poverljivim putem; **EP overhead ~0%**.
- **SEV hw (memorijska enkripcija)** trošak na compute ~2–4%.
- **DGEMM round** (enkripcija komunikacije) raste sa N (do ~90% za male matrice).
- **Atestacija** dodaje ~0 ms na enrollment (dominira MPI dynamic-connect, ~1340 ms/worker).
- **N=14 je visoko-varijabilna tačka** (±~20% po DVM-sesiji) zbog placement/kontencije;
  pojedinačno merenje nepouzdano — koristiti min/medijan preko više sesija.
- Pinning plain workera (da se uskladi sa SEV-om) ne ubrzava plain; na N=14 ga čak
  i uspori (16-vCPU master lebdi po 0–31 i otima cikluse prikovanim workerima 0–13).
  Posledica: nepinovani plain baseline NIJE pristrasan u korist plaina.
