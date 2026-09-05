# Uputstvo — SEV-SNP attestation klaster (3 CVM)

Korak-po-korak vodič za pokretanje klastera od tri SEV-SNP poverljive VM
(`master`, `worker1`, `worker2`) i izvršavanje pune atestacije sa šifrovanom
distribucijom zadataka.

---

## Arhitektura

| Uloga   | qcow2          | TAP  | MAC                 | IP              |
|---------|----------------|------|---------------------|-----------------|
| host    | —              | —    | —                   | `br0` 192.168.100.1 |
| master  | `master.qcow2` | tap0 | `52:55:00:d1:55:01` | 192.168.100.2   |
| worker1 | `worker1.qcow2`| tap1 | `52:55:00:d1:55:02` | 192.168.100.3   |
| worker2 | `worker2.qcow2`| tap2 | `52:55:00:d1:55:03` | 192.168.100.4   |

- Host server: `teodora@147.91.12.238` (traži SSH lozinku + sudo lozinku).
- Pristup VM-ovima ide preko ključa `~/.ssh/vm_key` na serveru (bez lozinke).
- MPI stek (`/root/mpi-stack`: PMIx 5.0.6 + PRTE 3.0.8 + OpenMPI 5.0.5),
  `snpguest`, i binari `/root/src/master_attest`, `/root/src/worker_attest`
  su već ugrađeni u sve klonove.

Sve potrebne skripte se već nalaze na serveru u home direktorijumu
(`~/setup_network.sh`, `~/launch_*.sh`, `~/setup_cluster_ssh.sh`,
`~/cluster_attest_run.sh`).

---

## A) Redovno pokretanje

### Korak 1 — Prijava na server
```bash
ssh teodora@147.91.12.238
```
> Unosi se SSH lozinka servera.

### Korak 2 — Podizanje mreže (bridge + TAP + NAT)
```bash
bash ~/setup_network.sh
```
> Unosi se sudo lozinka. Na kraju treba da piše `br0 ... 192.168.100.1/24`
> i da su `tap0/1/2` članovi `br0`.
> NAPOMENA: ako se server u međuvremenu restartovao, ovaj korak mora ponovo.

### Korak 3 — Pokretanje sve tri VM (jedna sudo lozinka)
```bash
sudo bash -c 'cd "${VM_DIR:-$HOME}"; for v in master worker1 worker2; do screen -dmS $v bash launch_$v.sh; done; sleep 3; screen -ls'
```
> Treba da prikaže tri `screen` sesije: `master`, `worker1`, `worker2`.
> Ceo blok se izvršava kao root da interni `sudo qemu` ne bi tražio lozinku ponovo.

### Korak 4 — Provera da su se VM podigle (čeka i ponavlja)
```bash
for ip in 2 3 4; do
  echo "=== 192.168.100.$ip ==="
  for try in $(seq 1 20); do
    if ssh -i ~/.ssh/vm_key -o StrictHostKeyChecking=accept-new -o ConnectTimeout=5 root@192.168.100.$ip hostname 2>/dev/null; then
      break
    fi
    sleep 5
  done
done
```
> Očekivano: `master`, `worker1`, `worker2`.

### Korak 5 — Podešavanje klaster SSH-a (prvi put; idempotentno)
```bash
bash ~/setup_cluster_ssh.sh
```
> Sređuje `/etc/hosts` na realne IP-ove i passwordless SSH master→workeri.
> Na kraju: `master -> master/worker1/worker2` vraća tačne hostname-ove.
> Ovo ostaje sačuvano u qcow2 disku — pri sledećem boot-u nije obavezno,
> ali je bezbedno ponovo pokrenuti.

### Korak 6 — Pokretanje atestacije
```bash
scp -i ~/.ssh/vm_key ~/cluster_attest_run.sh root@192.168.100.2:/root/ && \
ssh -i ~/.ssh/vm_key root@192.168.100.2 'bash /root/cluster_attest_run.sh'
```
Skripta automatski radi: DVM preko 3 noda → warmup →
`master_attest --master 2` → `worker_attest` na worker1 pa worker2
(sa BTL warmup-om između) → ispis logova → `pterm`.

**Uspešan rezultat sadrži:**
- `[MASTER] round 1: EA attestation PASSED` i `round 2: ... PASSED`
- `worker #1 joined` i `worker #2 joined`
- `[MASTER] result 1/9 ...` do `9/9` i `[MASTER] done.`
- `exit codes: master=0 worker1=0 worker2=0`

---

## B) Gašenje i čišćenje

### Gašenje VM-ova
```bash
sudo pkill -9 -f qemu-system-x86_64
screen -wipe 2>/dev/null
```

### Razgradnja mreže
```bash
bash ~/cleanup_network.sh
```

---

## C) Dijagnostika

| Problem | Provera / rešenje |
|---|---|
| VM ne odgovara na SSH | `sudo screen -r master` (izlaz: `Ctrl+A` pa `D`) — gleda se da li je stigao do `login:` |
| `Cannot find device br0` | `brctl` nije instaliran — koriste se `ip` komande (već u skriptama); ponovo `bash ~/setup_network.sh` |
| `prte/mpiexec` odbija start kao root | mora `--allow-run-as-root` (već u skriptama) |
| URI piše `127.0.0.1` | bezopasno; bitno je `--prtemca oob_tcp_if_include 192.168.100.0/24` (već postavljeno) |
| Atestacija padne (`... FAILED`) | na master-u u `/root/src`: `snpguest_verify.log` i `snpguest_fetch_vcek.log` |
| Nedostaju `ark.pem`/`ask.pem` | `snpguest fetch ca pem /root/certs milan` (skripta to radi automatski) |

---

## D) Ponovna gradnja od nule (samo ako treba novi qcow2)

Pokreće se sa Windows mašine iz foldera projekta (`C:\Users\admin\Desktop\OPENMPI`):

```powershell
# 1) prebaci skripte i izvor na server
scp -r setup src teodora@147.91.12.238:~/staging/

# 2) napravi osnovni noble.qcow2 iz orig.qcow2 (paketi, ključ, izvor, MPI tarball-ovi)
ssh -t teodora@147.91.12.238 'bash ~/staging/setup/prepare_vm.sh'

# 3) (u VM-u) build MPI steka + atest binara — preko build_mpi.sh / postboot.sh

# 4) kloniraj u master/worker1/worker2 + hostname/hosts
ssh -t teodora@147.91.12.238 'bash ~/clone_vms.sh'

# 5) ubaci netplan po MAC-u u klonove
ssh -t teodora@147.91.12.238 'bash ~/configure_vm_network.sh'
```

Posle toga važi deo **A**.

---

## Lokacije skripti (u repozitorijumu)

Sve su u folderu [setup/](setup/):
`setup_network.sh`, `cleanup_network.sh`, `configure_vm_network.sh`,
`launch_master.sh`, `launch_worker1.sh`, `launch_worker2.sh`,
`setup_cluster_ssh.sh`, `cluster_dvm_test.sh`, `cluster_attest_run.sh`,
`clone_vms.sh`, `prepare_vm.sh`, `build_mpi.sh`, `postboot.sh`.
