/*
 * master_npb.c – NPB-kernel benchmark for MPI + SEV-SNP star topology.
 *
 * Uses the same EA/aTLS attestation protocol as master_attest.c, then
 * distributes NPB-derived workloads (EP and CG) through the encrypted
 * star-topology framework.
 *
 * Workloads:
 *   EP  — Embarrassingly Parallel: Gaussian random deviate generation
 *          and bin counting. Minimal communication, pure compute.
 *   CG  — Conjugate Gradient (SpMV kernel): Sparse matrix-vector
 *          multiply with iterative communication. Tests frequent
 *          small message exchange overhead.
 *
 * Usage:
 *   ./master_npb --master <N> --workload ep  [--ep-n <2^M pairs>] [--runs R]
 *   ./master_npb --master <N> --workload cg  [--cg-n <rows>] [--cg-iters <I>] [--runs R]
 *                [--no-encrypt] [--output FILE]
 *
 * Compile (production):
 *   mpicc -O2 -Wall -Wextra -o master_npb master_npb.c -lsodium -lm
 *
 * Compile (skip real SNP):
 *   mpicc -DSKIP_ATTESTATION -O2 -Wall -Wextra -o master_npb master_npb.c -lsodium -lm
 */

#include <mpi.h>
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <sys/wait.h>
#include <sys/stat.h>

/* ── MPI message tags: EA attestation protocol ── */
enum {
    TAG_EA_REQUEST       = 70,
    TAG_EA_AUTH_HDR      = 71,
    TAG_EA_EVIDENCE_DATA = 72,
    TAG_EA_FINISHED      = 73,
    TAG_EA_RESULT        = 74,
    TAG_KX_SERVER_PK     = 91
};

/* ── MPI message tags: NPB data plane ── */
enum {
    TAG_NPB_CMD      = 130,   /* npb_cmd struct */
    TAG_NPB_EP_RESULT= 131,   /* EP bin counts + sums */
    TAG_NPB_CG_X     = 132,   /* CG: vector x */
    TAG_NPB_CG_Y     = 133,   /* CG: partial result y */
    TAG_NPB_CG_MATRIX= 134,   /* CG: sparse matrix data */
    TAG_NPB_TIME     = 135    /* worker compute time */
};

/* ── NPB workload types ── */
#define WORKLOAD_EP   1
#define WORKLOAD_CG   2

/* ── NPB command codes ── */
#define CMD_NPB_START  1
#define CMD_NPB_ITER   2
#define CMD_NPB_DONE   3

/* ── Crypto constants ── */
#define MAX_WORKERS  128
#define KEYB   crypto_aead_chacha20poly1305_ietf_KEYBYTES
#define NPUB   crypto_aead_chacha20poly1305_ietf_NPUBBYTES
#define ABYTES crypto_aead_chacha20poly1305_ietf_ABYTES

#define HASH_LEN         32
#define BINDING_LEN      32
#define REPORT_DATA_SIZE 64
#define SNP_REPORT_TMP   "snp_report.bin"
#define MAX_REPORT_LEN   16384

#define SECURE_MAX_PLAIN 256

_Static_assert(crypto_kx_SESSIONKEYBYTES == KEYB,
               "kx session key size must match AEAD key size");

/* ── EA / CMW Attestation types ── */

#define EA_CONTEXT_LEN     32
#define EA_MEDIA_TYPE      "application/eat+cwt"
#define EA_EXPORTER_LABEL  "Attestation"
#define EA_PAYLOAD_VERSION 1

struct ea_binder {
    uint8_t aik_pub_hash[HASH_LEN];
    uint8_t binding[BINDING_LEN];
    char    exporter_label[64];
} __attribute__((packed));

struct ea_payload_hdr {
    uint32_t        version;
    char            media_type[64];
    uint32_t        evidence_len;
    struct ea_binder binder;
} __attribute__((packed));

struct ea_request {
    uint8_t context[EA_CONTEXT_LEN];
    uint8_t attestation_offer;
} __attribute__((packed));

struct ea_auth_hdr {
    uint8_t             client_pk[crypto_kx_PUBLICKEYBYTES];
    struct ea_payload_hdr payload_hdr;
} __attribute__((packed));

/* ── NPB command struct ── */
struct npb_cmd {
    int32_t cmd;           /* CMD_NPB_START / CMD_NPB_ITER / CMD_NPB_DONE */
    int32_t workload;      /* WORKLOAD_EP or WORKLOAD_CG */
    int32_t encrypt_data;  /* 1 = AEAD, 0 = plaintext bulk */
    int32_t num_runs;      /* iterations for timing */
    /* EP-specific */
    int64_t ep_pairs;      /* number of Gaussian pairs per worker */
    /* CG-specific */
    int32_t cg_rows;       /* total sparse matrix rows */
    int32_t cg_row_start;  /* this worker's first row */
    int32_t cg_row_count;  /* rows for this worker */
    int32_t cg_n;          /* vector length */
    int32_t cg_nzpc;       /* nonzeros per row (fixed for regular sparse) */
    int32_t cg_iters;      /* CG iterations */
};

/* ── EP result struct ── */
#define EP_BINS 10
struct ep_result {
    int64_t counts[EP_BINS];
    double  sx;
    double  sy;
};

/* ── Per-worker nonce counters ── */
static uint64_t send_nonce_ctr[MAX_WORKERS];
static uint64_t recv_nonce_ctr[MAX_WORKERS];

/* ── Result storage ── */
#define MAX_RUNS    1000
#define MAX_RESULTS (MAX_RUNS * 4)

struct npb_result {
    int    workload;
    int    num_workers;
    int    encrypted;
    int    run;
    double t_scatter_ms;
    double t_compute_max_ms;
    double t_gather_ms;
    double t_round_ms;
    /* EP-specific */
    int64_t ep_pairs_total;
    /* CG-specific */
    int    cg_n;
    int    cg_iters;
};

static struct npb_result g_results[MAX_RESULTS];
static int g_nresults = 0;

/* ──────────────────────────────────────────────────────────────────────
 *  Utility helpers
 * ────────────────────────────────────────────────────────────────────── */

static void die_mpi(const char *msg, int rc)
{
    char es[256]; int n = 0;
    MPI_Error_string(rc, es, &n);
    fprintf(stderr, "[MASTER] FATAL: %s rc=%d (%s)\n", msg, rc, es);
    fflush(stderr);
    MPI_Abort(MPI_COMM_WORLD, 1);
    exit(1);
}

static void bytes_to_hex(const unsigned char *in, size_t len,
                         char *out, size_t out_len)
{
    static const char hc[] = "0123456789abcdef";
    if (out_len < 2 * len + 1) { if (out_len) out[0] = '\0'; return; }
    for (size_t i = 0; i < len; i++) {
        out[2 * i]     = hc[(in[i] >> 4) & 0xF];
        out[2 * i + 1] = hc[ in[i]       & 0xF];
    }
    out[2 * len] = '\0';
}

static int sanitize_path(const char *p)
{
    for (; *p; p++) {
        unsigned char c = (unsigned char)*p;
        if (c < 0x20 || c == ';' || c == '&' || c == '|' ||
            c == '$' || c == '`' || c == '\'' || c == '"' ||
            c == '(' || c == ')' || c == '{' || c == '}' ||
            c == '<' || c == '>' || c == '!' || c == '\n')
            return -1;
    }
    return 0;
}

static void mpi_send_f(const void *buf, int count, MPI_Datatype dt,
                       int dest, int tag, MPI_Comm comm, const char *ctx)
{
    int rc = MPI_Send(buf, count, dt, dest, tag, comm);
    if (rc != MPI_SUCCESS) die_mpi(ctx, rc);
}

static void mpi_recv_f(void *buf, int count, MPI_Datatype dt,
                       int src, int tag, MPI_Comm comm, MPI_Status *st,
                       const char *ctx)
{
    int rc = MPI_Recv(buf, count, dt, src, tag, comm, st);
    if (rc != MPI_SUCCESS) die_mpi(ctx, rc);
}

/* ──────────────────────────────────────────────────────────────────────
 *  EA Attestation Binding
 * ────────────────────────────────────────────────────────────────────── */

static void ea_export_attestation_value(const uint8_t context[EA_CONTEXT_LEN],
                                        uint8_t out[HASH_LEN])
{
    crypto_generichash(out, HASH_LEN, context, EA_CONTEXT_LEN, NULL, 0);
}

static void ea_aik_pub_hash(const uint8_t *pub_key, size_t pub_key_len,
                            uint8_t out[HASH_LEN])
{
    crypto_generichash(out, HASH_LEN, pub_key, pub_key_len, NULL, 0);
}

static void ea_binding_value(const uint8_t *pub_key, size_t pub_key_len,
                             const uint8_t exported_value[HASH_LEN],
                             uint8_t out[BINDING_LEN])
{
    crypto_generichash_state st;
    crypto_generichash_init(&st, NULL, 0, BINDING_LEN);
    crypto_generichash_update(&st, pub_key, pub_key_len);
    crypto_generichash_update(&st, exported_value, HASH_LEN);
    crypto_generichash_final(&st, out, BINDING_LEN);
}

static void ea_compute_binding(const uint8_t context[EA_CONTEXT_LEN],
                               const uint8_t *pub_key, size_t pub_key_len,
                               uint8_t exported_value[HASH_LEN],
                               uint8_t aik_hash[HASH_LEN],
                               uint8_t binding[BINDING_LEN])
{
    ea_export_attestation_value(context, exported_value);
    ea_aik_pub_hash(pub_key, pub_key_len, aik_hash);
    ea_binding_value(pub_key, pub_key_len, exported_value, binding);
}

static void ea_derive_report_data(const uint8_t binding[BINDING_LEN],
                                  uint8_t report_data[REPORT_DATA_SIZE])
{
    crypto_generichash(report_data, REPORT_DATA_SIZE,
                       binding, BINDING_LEN, NULL, 0);
}

static void ea_compute_finished(const uint8_t context[EA_CONTEXT_LEN],
                                const uint8_t *pub_key, size_t pub_key_len,
                                const struct ea_payload_hdr *hdr,
                                const uint8_t *evidence, uint32_t evidence_len,
                                uint8_t finished[HASH_LEN])
{
    crypto_generichash_state st;
    crypto_generichash_init(&st, NULL, 0, HASH_LEN);
    crypto_generichash_update(&st, context, EA_CONTEXT_LEN);
    crypto_generichash_update(&st, pub_key, pub_key_len);
    crypto_generichash_update(&st, (const uint8_t *)hdr, sizeof(*hdr));
    if (evidence && evidence_len > 0)
        crypto_generichash_update(&st, evidence, evidence_len);
    crypto_generichash_final(&st, finished, HASH_LEN);
}

static int ea_verify_payload(const struct ea_payload_hdr *hdr,
                             const uint8_t context[EA_CONTEXT_LEN],
                             const uint8_t *pub_key, size_t pub_key_len)
{
    if (hdr->version != EA_PAYLOAD_VERSION) return -1;
    if (strncmp(hdr->media_type, EA_MEDIA_TYPE, sizeof(hdr->media_type)) != 0) return -1;
    if (strncmp(hdr->binder.exporter_label, EA_EXPORTER_LABEL,
                sizeof(hdr->binder.exporter_label)) != 0) return -1;

    uint8_t exported_value[HASH_LEN], expected_aik[HASH_LEN], expected_binding[BINDING_LEN];
    ea_compute_binding(context, pub_key, pub_key_len,
                       exported_value, expected_aik, expected_binding);
    if (sodium_memcmp(expected_aik, hdr->binder.aik_pub_hash, HASH_LEN) != 0) return -1;
    if (sodium_memcmp(expected_binding, hdr->binder.binding, BINDING_LEN) != 0) return -1;
    return 0;
}

/* ── SEV-SNP evidence verification ── */

static int verify_sev_snp_report(const unsigned char *report, int report_len,
                                 const unsigned char expected_rd[REPORT_DATA_SIZE])
{
    if (!report || report_len <= 0) return -1;
    FILE *f = fopen(SNP_REPORT_TMP, "wb");
    if (!f) return -1;
    if ((int)fwrite(report, 1, (size_t)report_len, f) != report_len) { fclose(f); return -1; }
    fclose(f);

    char rd_hex[REPORT_DATA_SIZE * 2 + 1];
    bytes_to_hex(expected_rd, REPORT_DATA_SIZE, rd_hex, sizeof rd_hex);

    const char *certs_dir = getenv("SNP_CERTS_DIR");
    if (!certs_dir || !*certs_dir) certs_dir = "certs";
    if (sanitize_path(certs_dir) != 0) return -1;

    char cmd[1024];
    /* VCEK je per-cip/TCB konstanta i svi VM-ovi dele isti fizicki cip, pa se
     * fetch radi samo jednom. Bez ovoga AMD KDS vraca 429 (rate limit) posle
     * vise atestacija, ali keshirani vcek.pem i dalje validno potpisuje. */
    char vcek_path[1100];
    snprintf(vcek_path, sizeof vcek_path, "%s/vcek.pem", certs_dir);
    struct stat vst;
    if (stat(vcek_path, &vst) != 0 || vst.st_size <= 0) {
        snprintf(cmd, sizeof cmd,
                 "snpguest fetch vcek pem %s %s > snpguest_fetch_vcek.log 2>&1",
                 certs_dir, SNP_REPORT_TMP);
        system(cmd);
    }

    snprintf(cmd, sizeof cmd,
             "snpguest verify attestation %s %s --report-data 0x%s > snpguest_verify.log 2>&1",
             certs_dir, SNP_REPORT_TMP, rd_hex);
    int status = system(cmd);
    if (status == -1 || !WIFEXITED(status)) return -1;
    return (WEXITSTATUS(status) == 0) ? 0 : -1;
}

/* ──────────────────────────────────────────────────────────────────────
 *  AEAD secure send / recv — SMALL messages (control, ≤ 256 B)
 * ────────────────────────────────────────────────────────────────────── */

static void secure_send(MPI_Comm comm, const unsigned char key[KEYB],
                        uint64_t *nonce_ctr,
                        const void *plaintext, int plain_len,
                        int dest, int tag, const char *ctx)
{
    if (plain_len < 0 || plain_len > SECURE_MAX_PLAIN) {
        fprintf(stderr, "[MASTER] secure_send: plain_len %d out of range\n", plain_len);
        MPI_Abort(MPI_COMM_WORLD, 1);
    }
    unsigned char nonce[NPUB];
    memset(nonce, 0, NPUB);
    memcpy(nonce, nonce_ctr, sizeof(uint64_t));
    (*nonce_ctr)++;

    unsigned char buf[NPUB + SECURE_MAX_PLAIN + ABYTES];
    unsigned long long clen = 0;
    crypto_aead_chacha20poly1305_ietf_encrypt(
        buf + NPUB, &clen,
        (const unsigned char *)plaintext, (unsigned long long)plain_len,
        NULL, 0, NULL, nonce, key);
    memcpy(buf, nonce, NPUB);
    int total = NPUB + plain_len + (int)ABYTES;
    mpi_send_f(buf, total, MPI_UNSIGNED_CHAR, dest, tag, comm, ctx);
}

static int secure_recv(MPI_Comm comm, const unsigned char key[KEYB],
                       uint64_t *nonce_ctr,
                       void *plaintext, int plain_len,
                       int src, int tag, const char *ctx)
{
    if (plain_len < 0 || plain_len > SECURE_MAX_PLAIN) return -1;
    unsigned char buf[NPUB + SECURE_MAX_PLAIN + ABYTES];
    int total = NPUB + plain_len + (int)ABYTES;
    MPI_Status st;
    mpi_recv_f(buf, total, MPI_UNSIGNED_CHAR, src, tag, comm, &st, ctx);

    uint64_t received_ctr = 0;
    memcpy(&received_ctr, buf, sizeof(uint64_t));
    if (received_ctr < *nonce_ctr) {
        fprintf(stderr, "[MASTER] REPLAY detected [%s]\n", ctx);
        return -1;
    }
    unsigned long long mlen = 0;
    if (crypto_aead_chacha20poly1305_ietf_decrypt(
            (unsigned char *)plaintext, &mlen, NULL,
            buf + NPUB, (unsigned long long)(plain_len + (int)ABYTES),
            NULL, 0, buf, key) != 0) {
        fprintf(stderr, "[MASTER] AEAD decryption FAILED [%s]\n", ctx);
        return -1;
    }
    *nonce_ctr = received_ctr + 1;
    return 0;
}

/* ── AEAD bulk send / recv — LARGE messages ── */

static void send_bulk(MPI_Comm comm, const unsigned char key[KEYB],
                      uint64_t *nonce_ctr,
                      const void *data, size_t data_bytes,
                      int dest, int tag, int encrypt, const char *ctx)
{
    if (!encrypt) {
        mpi_send_f(data, (int)data_bytes, MPI_UNSIGNED_CHAR, dest, tag, comm, ctx);
        return;
    }
    size_t total = NPUB + data_bytes + ABYTES;
    unsigned char *buf = (unsigned char *)malloc(total);
    if (!buf) { fprintf(stderr, "malloc failed\n"); MPI_Abort(MPI_COMM_WORLD, 1); }

    unsigned char nonce[NPUB];
    memset(nonce, 0, NPUB);
    memcpy(nonce, nonce_ctr, sizeof(uint64_t));
    (*nonce_ctr)++;

    unsigned long long clen = 0;
    crypto_aead_chacha20poly1305_ietf_encrypt(
        buf + NPUB, &clen,
        (const unsigned char *)data, (unsigned long long)data_bytes,
        NULL, 0, NULL, nonce, key);
    memcpy(buf, nonce, NPUB);
    mpi_send_f(buf, (int)total, MPI_UNSIGNED_CHAR, dest, tag, comm, ctx);
    free(buf);
}

static int recv_bulk(MPI_Comm comm, const unsigned char key[KEYB],
                     uint64_t *nonce_ctr,
                     void *data, size_t data_bytes,
                     int src, int tag, int encrypt, const char *ctx)
{
    if (!encrypt) {
        MPI_Status st;
        mpi_recv_f(data, (int)data_bytes, MPI_UNSIGNED_CHAR, src, tag, comm, &st, ctx);
        return 0;
    }
    size_t total = NPUB + data_bytes + ABYTES;
    unsigned char *buf = (unsigned char *)malloc(total);
    if (!buf) return -1;

    MPI_Status st;
    mpi_recv_f(buf, (int)total, MPI_UNSIGNED_CHAR, src, tag, comm, &st, ctx);

    uint64_t received_ctr = 0;
    memcpy(&received_ctr, buf, sizeof(uint64_t));
    if (received_ctr < *nonce_ctr) { free(buf); return -1; }

    unsigned long long mlen = 0;
    if (crypto_aead_chacha20poly1305_ietf_decrypt(
            (unsigned char *)data, &mlen, NULL,
            buf + NPUB, (unsigned long long)(data_bytes + ABYTES),
            NULL, 0, buf, key) != 0) {
        free(buf); return -1;
    }
    *nonce_ctr = received_ctr + 1;
    free(buf);
    return 0;
}

/* ── Port file helper ── */

static void write_port_file(const char *path, const char *port_name)
{
    char tmp[256];
    snprintf(tmp, sizeof tmp, "%s.tmp", path);
    FILE *f = fopen(tmp, "w");
    if (!f) { perror("fopen(port.txt.tmp)"); exit(1); }
    fprintf(f, "%s\n", port_name);
    fclose(f);
    if (rename(tmp, path) != 0) { perror("rename(port.txt)"); exit(1); }
}

/* ── Statistics ── */

static double compute_mean(const double *v, int n)
{
    double s = 0; for (int i = 0; i < n; i++) s += v[i]; return s / n;
}

static double compute_stddev(const double *v, int n, double mean)
{
    double s = 0; for (int i = 0; i < n; i++) s += (v[i]-mean)*(v[i]-mean);
    return sqrt(s / n);
}

/* ──────────────────────────────────────────────────────────────────────
 *  CG: Generate a regular sparse matrix (like NPB CG Class A/B)
 *  Each row has exactly `nzpc` nonzero entries at random column positions.
 *  Values are random in [-1, 1].  Stored in CSR format.
 * ────────────────────────────────────────────────────────────────────── */

static void generate_sparse_matrix(int n, int nzpc, int seed,
                                   int **out_row_ptr, int **out_col_idx,
                                   double **out_val, int *out_nnz)
{
    int nnz = n * nzpc;
    int *row_ptr = (int *)malloc((size_t)(n + 1) * sizeof(int));
    int *col_idx = (int *)malloc((size_t)nnz * sizeof(int));
    double *val  = (double *)malloc((size_t)nnz * sizeof(double));

    srand((unsigned)seed);
    for (int i = 0; i <= n; i++) row_ptr[i] = i * nzpc;
    for (int i = 0; i < n; i++) {
        for (int j = 0; j < nzpc; j++) {
            col_idx[i * nzpc + j] = rand() % n;
            val[i * nzpc + j] = (double)rand() / RAND_MAX * 2.0 - 1.0;
        }
    }
    *out_row_ptr = row_ptr;
    *out_col_idx = col_idx;
    *out_val = val;
    *out_nnz = nnz;
}

/* ══════════════════════════════════════════════════════════════════════
 *  main()
 * ══════════════════════════════════════════════════════════════════════ */

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    /* ── Parse command-line arguments ── */
    int target    = 2;
    int num_runs  = 10;
    int encrypt   = 1;
    int workload  = WORKLOAD_EP;
    int64_t ep_n  = (int64_t)1 << 26;   /* 2^26 pairs per worker (default) */
    int cg_n      = 14000;              /* NPB CG Class A size */
    int cg_nzpc   = 11;                 /* nonzeros per row (Class A) */
    int cg_iters  = 15;                 /* CG iterations (Class A) */
    const char *csv_file = "npb_results.csv";

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--master") == 0 && i + 1 < argc)
            target = atoi(argv[++i]);
        else if (strcmp(argv[i], "--workload") == 0 && i + 1 < argc) {
            i++;
            if (strcmp(argv[i], "ep") == 0) workload = WORKLOAD_EP;
            else if (strcmp(argv[i], "cg") == 0) workload = WORKLOAD_CG;
            else { fprintf(stderr, "Unknown workload: %s\n", argv[i]); return 1; }
        }
        else if (strcmp(argv[i], "--ep-n") == 0 && i + 1 < argc)
            ep_n = atoll(argv[++i]);
        else if (strcmp(argv[i], "--cg-n") == 0 && i + 1 < argc)
            cg_n = atoi(argv[++i]);
        else if (strcmp(argv[i], "--cg-nzpc") == 0 && i + 1 < argc)
            cg_nzpc = atoi(argv[++i]);
        else if (strcmp(argv[i], "--cg-iters") == 0 && i + 1 < argc)
            cg_iters = atoi(argv[++i]);
        else if (strcmp(argv[i], "--runs") == 0 && i + 1 < argc)
            num_runs = atoi(argv[++i]);
        else if (strcmp(argv[i], "--no-encrypt") == 0)
            encrypt = 0;
        else if (strcmp(argv[i], "--output") == 0 && i + 1 < argc)
            csv_file = argv[++i];
    }
    if (target <= 0) target = 1;
    if (num_runs <= 0) num_runs = 1;

    /* ── MPI + libsodium init ── */
    MPI_Init(&argc, &argv);
    if (sodium_init() < 0) { fprintf(stderr, "sodium_init failed\n"); MPI_Abort(MPI_COMM_WORLD, 1); }

    MPI_Comm workers[MAX_WORKERS];
    unsigned char wkey[MAX_WORKERS][KEYB];
    int nworkers = 0;
    memset(send_nonce_ctr, 0, sizeof send_nonce_ctr);
    memset(recv_nonce_ctr, 0, sizeof recv_nonce_ctr);

    printf("============================================================\n");
    printf("  MPI + SEV-SNP Star Topology — NPB Kernel Benchmark\n");
    printf("============================================================\n");
    printf("  target_workers = %d\n", target);
    printf("  workload       = %s\n", workload == WORKLOAD_EP ? "EP" : "CG");
    if (workload == WORKLOAD_EP)
        printf("  ep_pairs/worker= %" PRId64 " (2^%.0f)\n", ep_n, log2((double)ep_n));
    else
        printf("  cg_n=%d  nzpc=%d  iters=%d\n", cg_n, cg_nzpc, cg_iters);
    printf("  runs           = %d\n", num_runs);
    printf("  data encrypt   = %s\n", encrypt ? "AEAD" : "plaintext");
#ifdef SKIP_ATTESTATION
    printf("  attestation    = SKIPPED\n");
#else
    printf("  attestation    = ENABLED (real SEV-SNP)\n");
#endif
    printf("  csv output     = %s\n", csv_file);
    printf("============================================================\n\n");

    /* ════════════════════════════════════════════════════════════════
     *  ENROLLMENT PHASE
     * ════════════════════════════════════════════════════════════════ */

    double t_enroll_per_worker[MAX_WORKERS];
    double t_enroll_start = MPI_Wtime();

    for (int round = 1; round <= target; round++)
    {
        double t_worker_start = MPI_Wtime();

        char port[MPI_MAX_PORT_NAME];
        memset(port, 0, sizeof port);
        int rc = MPI_Open_port(MPI_INFO_NULL, port);
        if (rc != MPI_SUCCESS) die_mpi("MPI_Open_port", rc);
        write_port_file("port.txt", port);
        printf("[ENROLL] round %d/%d: waiting for worker...\n", round, target);

        MPI_Comm inter = MPI_COMM_NULL;
        rc = MPI_Comm_accept(port, MPI_INFO_NULL, 0, MPI_COMM_SELF, &inter);
        if (rc != MPI_SUCCESS) die_mpi("MPI_Comm_accept", rc);
        MPI_Barrier(inter);
        MPI_Close_port(port);

        /* EA AuthenticatorRequest */
        struct ea_request ea_req;
        randombytes_buf(ea_req.context, EA_CONTEXT_LEN);
        ea_req.attestation_offer = 1;
        mpi_send_f(&ea_req, sizeof(ea_req), MPI_UNSIGNED_CHAR, 0,
                   TAG_EA_REQUEST, inter, "Send(EA_REQUEST)");

        /* Receive EA Authenticator */
        struct ea_auth_hdr auth_hdr;
        mpi_recv_f(&auth_hdr, sizeof(auth_hdr), MPI_UNSIGNED_CHAR, 0,
                   TAG_EA_AUTH_HDR, inter, MPI_STATUS_IGNORE, "Recv(EA_AUTH_HDR)");

        uint32_t evidence_len = auth_hdr.payload_hdr.evidence_len;
        unsigned char *evidence = NULL;
        if (evidence_len > MAX_REPORT_LEN) {
            MPI_Comm_disconnect(&inter); continue;
        }
        if (evidence_len > 0) {
            evidence = (unsigned char *)malloc(evidence_len);
            mpi_recv_f(evidence, (int)evidence_len, MPI_UNSIGNED_CHAR, 0,
                       TAG_EA_EVIDENCE_DATA, inter, MPI_STATUS_IGNORE, "Recv(EVIDENCE)");
        }

        unsigned char finished_recv[HASH_LEN];
        mpi_recv_f(finished_recv, HASH_LEN, MPI_UNSIGNED_CHAR, 0,
                   TAG_EA_FINISHED, inter, MPI_STATUS_IGNORE, "Recv(FINISHED)");

        /* Validate */
        int attest_ok = 1;
        if (ea_verify_payload(&auth_hdr.payload_hdr, ea_req.context,
                              auth_hdr.client_pk, crypto_kx_PUBLICKEYBYTES) != 0)
            attest_ok = 0;

        if (attest_ok) {
            unsigned char expected_finished[HASH_LEN];
            ea_compute_finished(ea_req.context, auth_hdr.client_pk,
                                crypto_kx_PUBLICKEYBYTES, &auth_hdr.payload_hdr,
                                evidence, evidence_len, expected_finished);
            if (sodium_memcmp(expected_finished, finished_recv, HASH_LEN) != 0)
                attest_ok = 0;
        }

        if (attest_ok && evidence_len > 0) {
            uint8_t expected_rd[REPORT_DATA_SIZE];
            ea_derive_report_data(auth_hdr.payload_hdr.binder.binding, expected_rd);
            if (verify_sev_snp_report(evidence, (int)evidence_len, expected_rd) != 0)
                attest_ok = 0;
        }
#ifndef SKIP_ATTESTATION
        /* Prava HW atestacija je OBAVEZNA: prazna evidencija (npr. pad snpguest-a
         * na workeru) ne sme tiho da prodje kao prihvacena. */
        if (evidence_len == 0) attest_ok = 0;
#endif
        free(evidence);

#ifdef SKIP_ATTESTATION
        attest_ok = 1;
#endif
        mpi_send_f(&attest_ok, 1, MPI_INT, 0, TAG_EA_RESULT, inter, "Send(EA_RESULT)");
        if (!attest_ok) { MPI_Comm_disconnect(&inter); continue; }

        /* ECDH Key Exchange */
        unsigned char server_pk[crypto_kx_PUBLICKEYBYTES];
        unsigned char server_sk[crypto_kx_SECRETKEYBYTES];
        unsigned char rx[KEYB], tx[KEYB], app_key[KEYB];
        crypto_kx_keypair(server_pk, server_sk);
        mpi_send_f(server_pk, crypto_kx_PUBLICKEYBYTES, MPI_UNSIGNED_CHAR, 0,
                   TAG_KX_SERVER_PK, inter, "Send(KX_SERVER_PK)");

        if (crypto_kx_server_session_keys(rx, tx, server_pk, server_sk,
                                          auth_hdr.client_pk) != 0)
            die_mpi("crypto_kx failed", 0);

        crypto_generichash_state hst;
        crypto_generichash_init(&hst, NULL, 0, KEYB);
        crypto_generichash_update(&hst, tx, KEYB);
        const char *label = "app_key";
        crypto_generichash_update(&hst, (const unsigned char *)label, strlen(label));
        crypto_generichash_final(&hst, app_key, KEYB);

        sodium_memzero(server_sk, sizeof server_sk);
        sodium_memzero(rx, sizeof rx);
        sodium_memzero(tx, sizeof tx);

        workers[nworkers] = inter;
        memcpy(wkey[nworkers], app_key, KEYB);
        sodium_memzero(app_key, KEYB);

        t_enroll_per_worker[nworkers] = (MPI_Wtime() - t_worker_start) * 1000.0;
        printf("[ENROLL] round %d: worker #%d enrolled in %.1f ms\n",
               round, nworkers + 1, t_enroll_per_worker[nworkers]);
        nworkers++;
    }

    double t_enroll_total = (MPI_Wtime() - t_enroll_start) * 1000.0;
    if (nworkers == 0) { printf("No workers enrolled.\n"); MPI_Finalize(); return 1; }

    printf("\n[ENROLL] Total: %.1f ms (%d workers)\n\n", t_enroll_total, nworkers);

    /* ════════════════════════════════════════════════════════════════
     *  NPB BENCHMARK PHASE
     * ════════════════════════════════════════════════════════════════ */

    if (workload == WORKLOAD_EP)
    {
        /* ── EP: Embarrassingly Parallel ──
         * Master sends: seed + pair count (tiny payload)
         * Worker computes: Gaussian pairs, bin counts
         * Worker returns: 10 bin counts + sx + sy (tiny payload)
         */
        printf("[NPB-EP] pairs/worker=%" PRId64 "  total_pairs=%" PRId64 "\n\n",
               ep_n, ep_n * nworkers);

        /* Send start command */
        for (int w = 0; w < nworkers; w++) {
            struct npb_cmd cmd = {0};
            cmd.cmd          = CMD_NPB_START;
            cmd.workload     = WORKLOAD_EP;
            cmd.encrypt_data = encrypt;
            cmd.num_runs     = num_runs;
            cmd.ep_pairs     = ep_n;
            secure_send(workers[w], wkey[w], &send_nonce_ctr[w],
                        &cmd, sizeof(cmd), 0, TAG_NPB_CMD, "Send(NPB_CMD_EP)");
        }

        double t_scatter_arr[MAX_RUNS], t_gather_arr[MAX_RUNS];
        double t_round_arr[MAX_RUNS], t_compute_max_arr[MAX_RUNS];

        for (int run = 1; run <= num_runs; run++)
        {
            /* Scatter: send seed per worker (via secure_send — tiny) */
            double t0 = MPI_Wtime();
            for (int w = 0; w < nworkers; w++) {
                int64_t seed = (int64_t)run * nworkers + w;
                secure_send(workers[w], wkey[w], &send_nonce_ctr[w],
                            &seed, sizeof(seed), 0, TAG_NPB_CMD, "Send(EP_seed)");
            }
            double t1 = MPI_Wtime();

            /* Gather: receive results from each worker */
            struct ep_result total_result = {0};
            double t_compute_max = 0.0;

            for (int w = 0; w < nworkers; w++) {
                struct ep_result wr;
                if (secure_recv(workers[w], wkey[w], &recv_nonce_ctr[w],
                                &wr, sizeof(wr), 0, TAG_NPB_EP_RESULT,
                                "Recv(EP_RESULT)") != 0) {
                    fprintf(stderr, "EP result recv failed from worker %d\n", w);
                    MPI_Abort(MPI_COMM_WORLD, 1);
                }
                for (int b = 0; b < EP_BINS; b++)
                    total_result.counts[b] += wr.counts[b];
                total_result.sx += wr.sx;
                total_result.sy += wr.sy;

                double tw = 0.0;
                if (secure_recv(workers[w], wkey[w], &recv_nonce_ctr[w],
                                &tw, sizeof(tw), 0, TAG_NPB_TIME,
                                "Recv(EP_TIME)") != 0) {
                    fprintf(stderr, "EP time recv failed from worker %d\n", w);
                    MPI_Abort(MPI_COMM_WORLD, 1);
                }
                if (tw > t_compute_max) t_compute_max = tw;
            }
            double t2 = MPI_Wtime();

            double t_scatter = (t1 - t0) * 1000.0;
            double t_gather  = (t2 - t1) * 1000.0;
            double t_round   = (t2 - t0) * 1000.0;

            t_scatter_arr[run-1] = t_scatter;
            t_gather_arr[run-1]  = t_gather;
            t_round_arr[run-1]   = t_round;
            t_compute_max_arr[run-1] = t_compute_max;

            if (g_nresults < MAX_RESULTS) {
                struct npb_result *r = &g_results[g_nresults++];
                r->workload = WORKLOAD_EP;
                r->num_workers = nworkers;
                r->encrypted = encrypt;
                r->run = run;
                r->t_scatter_ms = t_scatter;
                r->t_compute_max_ms = t_compute_max;
                r->t_gather_ms = t_gather;
                r->t_round_ms = t_round;
                r->ep_pairs_total = ep_n * nworkers;
            }

            printf("[NPB-EP] run %d/%d: scatter=%.2f compute=%.1f "
                   "gather=%.2f round=%.1f ms\n",
                   run, num_runs, t_scatter, t_compute_max, t_gather, t_round);
        }

        /* Summary */
        printf("\n[NPB-EP] Summary (%d runs):\n", num_runs);
        printf("  scatter : %.2f +/- %.2f ms\n",
               compute_mean(t_scatter_arr, num_runs),
               compute_stddev(t_scatter_arr, num_runs, compute_mean(t_scatter_arr, num_runs)));
        printf("  compute : %.1f +/- %.1f ms\n",
               compute_mean(t_compute_max_arr, num_runs),
               compute_stddev(t_compute_max_arr, num_runs, compute_mean(t_compute_max_arr, num_runs)));
        printf("  gather  : %.2f +/- %.2f ms\n",
               compute_mean(t_gather_arr, num_runs),
               compute_stddev(t_gather_arr, num_runs, compute_mean(t_gather_arr, num_runs)));
        printf("  round   : %.1f +/- %.1f ms\n",
               compute_mean(t_round_arr, num_runs),
               compute_stddev(t_round_arr, num_runs, compute_mean(t_round_arr, num_runs)));
        double mops = (double)(ep_n * nworkers) / (compute_mean(t_round_arr, num_runs) / 1000.0) / 1e6;
        printf("  Mop/s   : %.1f\n\n", mops);
    }
    else /* WORKLOAD_CG */
    {
        /* ── CG: Sparse Matrix-Vector Multiply (iterative) ──
         * Master generates sparse matrix, distributes row blocks.
         * Each iteration: master sends vector x → workers compute y=Ax → return y.
         * Tests frequent message exchange overhead.
         */
        printf("[NPB-CG] n=%d  nzpc=%d  iters=%d\n\n", cg_n, cg_nzpc, cg_iters);

        /* Generate sparse matrix */
        int *row_ptr, *col_idx, nnz;
        double *val;
        generate_sparse_matrix(cg_n, cg_nzpc, 42, &row_ptr, &col_idx, &val, &nnz);

        /* Compute row distribution */
        int rows_per_worker = cg_n / nworkers;
        int row_starts[MAX_WORKERS], row_counts_arr[MAX_WORKERS];
        for (int w = 0; w < nworkers; w++) {
            row_starts[w] = w * rows_per_worker;
            row_counts_arr[w] = (w == nworkers - 1) ?
                                (cg_n - w * rows_per_worker) : rows_per_worker;
        }

        /* Send start command + matrix data to each worker */
        for (int w = 0; w < nworkers; w++) {
            struct npb_cmd cmd = {0};
            cmd.cmd          = CMD_NPB_START;
            cmd.workload     = WORKLOAD_CG;
            cmd.encrypt_data = encrypt;
            cmd.num_runs     = num_runs;
            cmd.cg_rows      = cg_n;
            cmd.cg_row_start = row_starts[w];
            cmd.cg_row_count = row_counts_arr[w];
            cmd.cg_n         = cg_n;
            cmd.cg_nzpc      = cg_nzpc;
            cmd.cg_iters     = cg_iters;
            secure_send(workers[w], wkey[w], &send_nonce_ctr[w],
                        &cmd, sizeof(cmd), 0, TAG_NPB_CMD, "Send(NPB_CMD_CG)");

            /* Send this worker's slice of the sparse matrix (CSR data) */
            int rs = row_starts[w];
            int rc_w = row_counts_arr[w];
            int nnz_w = row_ptr[rs + rc_w] - row_ptr[rs];

            /* Send: local row_ptr (rc_w+1 ints), col_idx (nnz_w ints), val (nnz_w doubles) */
            int *local_rp = (int *)malloc((size_t)(rc_w + 1) * sizeof(int));
            for (int r = 0; r <= rc_w; r++)
                local_rp[r] = row_ptr[rs + r] - row_ptr[rs];

            send_bulk(workers[w], wkey[w], &send_nonce_ctr[w],
                      local_rp, (size_t)(rc_w + 1) * sizeof(int),
                      0, TAG_NPB_CG_MATRIX, encrypt, "Send(CG_rowptr)");
            send_bulk(workers[w], wkey[w], &send_nonce_ctr[w],
                      col_idx + row_ptr[rs], (size_t)nnz_w * sizeof(int),
                      0, TAG_NPB_CG_MATRIX, encrypt, "Send(CG_colidx)");
            send_bulk(workers[w], wkey[w], &send_nonce_ctr[w],
                      val + row_ptr[rs], (size_t)nnz_w * sizeof(double),
                      0, TAG_NPB_CG_MATRIX, encrypt, "Send(CG_val)");
            free(local_rp);
        }

        /* Benchmark iterations */
        double t_scatter_arr[MAX_RUNS], t_gather_arr[MAX_RUNS];
        double t_round_arr[MAX_RUNS], t_compute_max_arr[MAX_RUNS];

        /* Initial x vector */
        double *x = (double *)malloc((size_t)cg_n * sizeof(double));
        double *y = (double *)malloc((size_t)cg_n * sizeof(double));
        for (int i = 0; i < cg_n; i++) x[i] = 1.0 / cg_n;

        for (int run = 1; run <= num_runs; run++)
        {
            double t_scatter_total = 0, t_gather_total = 0, t_compute_max_total = 0;

            /* Reset x */
            for (int i = 0; i < cg_n; i++) x[i] = 1.0 / cg_n;

            for (int iter = 0; iter < cg_iters; iter++)
            {
                /* Scatter: send x to all workers */
                double t0 = MPI_Wtime();
                for (int w = 0; w < nworkers; w++) {
                    send_bulk(workers[w], wkey[w], &send_nonce_ctr[w],
                              x, (size_t)cg_n * sizeof(double),
                              0, TAG_NPB_CG_X, encrypt, "Send(CG_x)");
                }
                double t1 = MPI_Wtime();

                /* Gather: receive partial y from each worker */
                double t_compute_max = 0.0;
                for (int w = 0; w < nworkers; w++) {
                    int rc_w = row_counts_arr[w];
                    if (recv_bulk(workers[w], wkey[w], &recv_nonce_ctr[w],
                                  y + row_starts[w], (size_t)rc_w * sizeof(double),
                                  0, TAG_NPB_CG_Y, encrypt, "Recv(CG_y)") != 0) {
                        fprintf(stderr, "CG y recv failed\n");
                        MPI_Abort(MPI_COMM_WORLD, 1);
                    }
                    double tw = 0.0;
                    if (secure_recv(workers[w], wkey[w], &recv_nonce_ctr[w],
                                    &tw, sizeof(tw), 0, TAG_NPB_TIME,
                                    "Recv(CG_TIME)") != 0) {
                        fprintf(stderr, "CG time recv failed\n");
                        MPI_Abort(MPI_COMM_WORLD, 1);
                    }
                    if (tw > t_compute_max) t_compute_max = tw;
                }
                double t2 = MPI_Wtime();

                t_scatter_total += (t1 - t0) * 1000.0;
                t_gather_total  += (t2 - t1) * 1000.0;
                t_compute_max_total += t_compute_max;

                /* Update x = y / ||y|| for next iteration */
                double norm = 0.0;
                for (int i = 0; i < cg_n; i++) norm += y[i] * y[i];
                norm = sqrt(norm);
                if (norm > 0.0)
                    for (int i = 0; i < cg_n; i++) x[i] = y[i] / norm;
            }

            double t_round = t_scatter_total + t_gather_total;
            t_scatter_arr[run-1] = t_scatter_total;
            t_gather_arr[run-1]  = t_gather_total;
            t_round_arr[run-1]   = t_round;
            t_compute_max_arr[run-1] = t_compute_max_total;

            if (g_nresults < MAX_RESULTS) {
                struct npb_result *r = &g_results[g_nresults++];
                r->workload = WORKLOAD_CG;
                r->num_workers = nworkers;
                r->encrypted = encrypt;
                r->run = run;
                r->t_scatter_ms = t_scatter_total;
                r->t_compute_max_ms = t_compute_max_total;
                r->t_gather_ms = t_gather_total;
                r->t_round_ms = t_round;
                r->cg_n = cg_n;
                r->cg_iters = cg_iters;
            }

            printf("[NPB-CG] run %d/%d: scatter=%.1f compute=%.1f "
                   "gather=%.1f round=%.1f ms (%d iters)\n",
                   run, num_runs, t_scatter_total, t_compute_max_total,
                   t_gather_total, t_round, cg_iters);
        }

        /* Summary */
        printf("\n[NPB-CG] Summary (%d runs, %d iters each):\n", num_runs, cg_iters);
        printf("  scatter : %.1f +/- %.1f ms (total over %d iters)\n",
               compute_mean(t_scatter_arr, num_runs),
               compute_stddev(t_scatter_arr, num_runs, compute_mean(t_scatter_arr, num_runs)), cg_iters);
        printf("  compute : %.1f +/- %.1f ms\n",
               compute_mean(t_compute_max_arr, num_runs),
               compute_stddev(t_compute_max_arr, num_runs, compute_mean(t_compute_max_arr, num_runs)));
        printf("  gather  : %.1f +/- %.1f ms\n",
               compute_mean(t_gather_arr, num_runs),
               compute_stddev(t_gather_arr, num_runs, compute_mean(t_gather_arr, num_runs)));
        printf("  round   : %.1f +/- %.1f ms\n",
               compute_mean(t_round_arr, num_runs),
               compute_stddev(t_round_arr, num_runs, compute_mean(t_round_arr, num_runs)));
        double mops = (double)cg_n * cg_nzpc * 2.0 * cg_iters /
                      (compute_mean(t_round_arr, num_runs) / 1000.0) / 1e6;
        printf("  Mop/s   : %.1f\n\n", mops);

        free(row_ptr); free(col_idx); free(val);
        free(x); free(y);
    }

    /* ════════════════════════════════════════════════════════════════
     *  SHUTDOWN
     * ════════════════════════════════════════════════════════════════ */

    for (int w = 0; w < nworkers; w++) {
        struct npb_cmd cmd = {0};
        cmd.cmd = CMD_NPB_DONE;
        secure_send(workers[w], wkey[w], &send_nonce_ctr[w],
                    &cmd, sizeof(cmd), 0, TAG_NPB_CMD, "Send(NPB_DONE)");
        MPI_Comm_disconnect(&workers[w]);
    }
    sodium_memzero(wkey, sizeof wkey);

    /* ════════════════════════════════════════════════════════════════
     *  OUTPUT CSV
     * ════════════════════════════════════════════════════════════════ */

    FILE *csv = fopen(csv_file, "w");
    if (csv) {
        fprintf(csv, "# MPI+SEV-SNP Star Topology — NPB Kernel Benchmark\n");
        fprintf(csv, "# workload: %s\n", workload == WORKLOAD_EP ? "EP" : "CG");
#ifdef SKIP_ATTESTATION
        fprintf(csv, "# attestation: skipped\n");
#else
        fprintf(csv, "# attestation: enabled\n");
#endif
        fprintf(csv, "# data_encryption: %s\n", encrypt ? "AEAD" : "plaintext");
        fprintf(csv, "# runs: %d\n", num_runs);
        fprintf(csv, "# enrollment_total_ms: %.1f\n", t_enroll_total);
        for (int w = 0; w < nworkers; w++)
            fprintf(csv, "# enrollment_worker%d_ms: %.1f\n", w+1, t_enroll_per_worker[w]);
        fprintf(csv, "#\n");
        fprintf(csv, "workload,num_workers,encryption,run,"
                     "t_scatter_ms,t_compute_max_ms,t_gather_ms,t_round_ms\n");
        for (int i = 0; i < g_nresults; i++) {
            struct npb_result *r = &g_results[i];
            fprintf(csv, "%s,%d,%s,%d,%.3f,%.3f,%.3f,%.3f\n",
                    r->workload == WORKLOAD_EP ? "EP" : "CG",
                    r->num_workers, r->encrypted ? "encrypted" : "plaintext",
                    r->run, r->t_scatter_ms, r->t_compute_max_ms,
                    r->t_gather_ms, r->t_round_ms);
        }
        fclose(csv);
        printf("[OUTPUT] Results written to %s\n", csv_file);
    }

    printf("\n[MASTER] NPB benchmark complete.\n");
    MPI_Finalize();
    return 0;
}
