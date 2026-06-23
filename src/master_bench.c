/*
 * master_bench.c – Matrix-multiply benchmark for MPI + SEV-SNP star topology.
 *
 * Uses the same EA/aTLS attestation protocol as master_attest.c, then
 * replaces the trivial x² workload with distributed DGEMM benchmarking.
 *
 * Usage:
 *   ./master_bench --master <N> [--size <M>] [--sizes <M1,M2,...>]
 *                  [--runs <R>] [--no-encrypt] [--verify]
 *
 * Compile (production):
 *   mpicc -O2 -Wall -Wextra -o master_bench master_bench.c -lsodium -lm
 *
 * Compile (skip real SNP — for testing on non-CVM hosts):
 *   mpicc -DSKIP_ATTESTATION -O2 -Wall -Wextra -o master_bench master_bench.c -lsodium -lm
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

/* ── MPI message tags: benchmark data plane ── */
enum {
    TAG_BENCH_CMD  = 120,   /* bench_cmd struct (small, always encrypted)  */
    TAG_BENCH_A    = 121,   /* A_block matrix data (encrypted or plaintext)*/
    TAG_BENCH_B    = 122,   /* B matrix data (encrypted or plaintext)      */
    TAG_BENCH_C    = 123,   /* C_block result data (encrypted or plaintext)*/
    TAG_BENCH_TIME = 124    /* worker compute time (double, always encrypted)*/
};

/* ── Benchmark command codes ── */
#define CMD_BENCH_SIZE  1
#define CMD_BENCH_DONE  2

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

/* ── EA / CMW Attestation types (identical to master_attest.c) ── */

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

/* ── Benchmark command struct (fits in SECURE_MAX_PLAIN) ── */
struct bench_cmd {
    int32_t cmd;           /* CMD_BENCH_SIZE or CMD_BENCH_DONE */
    int32_t matrix_size;   /* M (square matrix dimension)      */
    int32_t row_start;     /* this worker's first row           */
    int32_t row_count;     /* number of rows for this worker    */
    int32_t encrypt_data;  /* 1 = AEAD, 0 = plaintext bulk     */
    int32_t num_runs;      /* iterations for this size          */
};

/* ── Per-worker nonce counters for AEAD ── */
static uint64_t send_nonce_ctr[MAX_WORKERS];
static uint64_t recv_nonce_ctr[MAX_WORKERS];

/* ── Benchmark result storage ── */
#define MAX_SIZES   32
#define MAX_RUNS    1000
#define MAX_RESULTS (MAX_SIZES * MAX_RUNS)

struct bench_result {
    int    matrix_size;
    int    num_workers;
    int    encrypted;
    int    run;
    double t_scatter_ms;
    double t_compute_max_ms;
    double t_gather_ms;
    double t_round_ms;
    double t_comm_ms;
};

static struct bench_result g_results[MAX_RESULTS];
static int g_nresults = 0;

/* ──────────────────────────────────────────────────────────────────────
 *  Utility helpers
 * ────────────────────────────────────────────────────────────────────── */

static void die_mpi(const char *msg, int rc)
{
    char es[256];
    int n = 0;
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

/* ── Checked MPI wrappers ── */

static void mpi_send(const void *buf, int count, MPI_Datatype dt,
                     int dest, int tag, MPI_Comm comm, const char *ctx)
{
    int rc = MPI_Send(buf, count, dt, dest, tag, comm);
    if (rc != MPI_SUCCESS) die_mpi(ctx, rc);
}

static void mpi_recv(void *buf, int count, MPI_Datatype dt,
                     int src, int tag, MPI_Comm comm, MPI_Status *st,
                     const char *ctx)
{
    int rc = MPI_Recv(buf, count, dt, src, tag, comm, st);
    if (rc != MPI_SUCCESS) die_mpi(ctx, rc);
}

/* ──────────────────────────────────────────────────────────────────────
 *  EA Attestation Binding (identical to master_attest.c)
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
    if (hdr->version != EA_PAYLOAD_VERSION) {
        fprintf(stderr, "[MASTER] EA payload version mismatch: %u\n", hdr->version);
        return -1;
    }
    if (strncmp(hdr->media_type, EA_MEDIA_TYPE, sizeof(hdr->media_type)) != 0) {
        fprintf(stderr, "[MASTER] EA media type mismatch\n");
        return -1;
    }
    if (strncmp(hdr->binder.exporter_label, EA_EXPORTER_LABEL,
                sizeof(hdr->binder.exporter_label)) != 0) {
        fprintf(stderr, "[MASTER] EA exporter label mismatch\n");
        return -1;
    }

    uint8_t exported_value[HASH_LEN];
    uint8_t expected_aik[HASH_LEN];
    uint8_t expected_binding[BINDING_LEN];
    ea_compute_binding(context, pub_key, pub_key_len,
                       exported_value, expected_aik, expected_binding);

    if (sodium_memcmp(expected_aik, hdr->binder.aik_pub_hash, HASH_LEN) != 0) {
        fprintf(stderr, "[MASTER] EA AIK public key hash mismatch\n");
        return -1;
    }
    if (sodium_memcmp(expected_binding, hdr->binder.binding, BINDING_LEN) != 0) {
        fprintf(stderr, "[MASTER] EA attestation binding mismatch\n");
        return -1;
    }
    return 0;
}

/* ── SEV-SNP evidence verification ── */

static int verify_sev_snp_report(const unsigned char *report, int report_len,
                                 const unsigned char expected_report_data[REPORT_DATA_SIZE])
{
    if (!report || report_len <= 0) return -1;

    FILE *f = fopen(SNP_REPORT_TMP, "wb");
    if (!f) return -1;
    if ((int)fwrite(report, 1, (size_t)report_len, f) != report_len) {
        fclose(f); return -1;
    }
    fclose(f);

    char rd_hex[REPORT_DATA_SIZE * 2 + 1];
    bytes_to_hex(expected_report_data, REPORT_DATA_SIZE, rd_hex, sizeof rd_hex);

    const char *certs_dir = getenv("SNP_CERTS_DIR");
    if (!certs_dir || !*certs_dir) certs_dir = "certs";
    if (sanitize_path(certs_dir) != 0) {
        fprintf(stderr, "[MASTER] SNP_CERTS_DIR contains unsafe characters\n");
        return -1;
    }

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
        fprintf(stderr, "[MASTER] running: %s\n", cmd);
        fflush(stderr);
        int fetch_rc = system(cmd);
        if (fetch_rc != 0)
            fprintf(stderr, "[MASTER] VCEK fetch returned %d (will try verify anyway)\n", fetch_rc);
    } else {
        fprintf(stderr, "[MASTER] using cached VCEK (%s)\n", vcek_path);
    }

    snprintf(cmd, sizeof cmd,
             "snpguest verify attestation %s %s --report-data 0x%s > snpguest_verify.log 2>&1",
             certs_dir, SNP_REPORT_TMP, rd_hex);
    fprintf(stderr, "[MASTER] running: %s\n", cmd);
    fflush(stderr);

    int status = system(cmd);
    if (status == -1) return -1;
    if (!WIFEXITED(status)) return -1;
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
    mpi_send(buf, total, MPI_UNSIGNED_CHAR, dest, tag, comm, ctx);
}

static int secure_recv(MPI_Comm comm, const unsigned char key[KEYB],
                       uint64_t *nonce_ctr,
                       void *plaintext, int plain_len,
                       int src, int tag, const char *ctx)
{
    if (plain_len < 0 || plain_len > SECURE_MAX_PLAIN) {
        fprintf(stderr, "[MASTER] secure_recv: plain_len %d out of range\n", plain_len);
        return -1;
    }
    unsigned char buf[NPUB + SECURE_MAX_PLAIN + ABYTES];
    int total = NPUB + plain_len + (int)ABYTES;
    MPI_Status st;
    mpi_recv(buf, total, MPI_UNSIGNED_CHAR, src, tag, comm, &st, ctx);

    uint64_t received_ctr = 0;
    memcpy(&received_ctr, buf, sizeof(uint64_t));
    if (received_ctr < *nonce_ctr) {
        fprintf(stderr, "[MASTER] REPLAY detected (nonce %" PRIu64
                        " < %" PRIu64 ") [%s]\n",
                received_ctr, *nonce_ctr, ctx);
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
    if ((int)mlen != plain_len) return -1;
    *nonce_ctr = received_ctr + 1;
    return 0;
}

/* ──────────────────────────────────────────────────────────────────────
 *  AEAD bulk send / recv — LARGE messages (matrix data)
 *  Single AEAD call over the full buffer.  ChaCha20-Poly1305 supports
 *  up to ~256 GB per message, so even large matrices are fine.
 * ────────────────────────────────────────────────────────────────────── */

static void send_matrix(MPI_Comm comm, const unsigned char key[KEYB],
                        uint64_t *nonce_ctr,
                        const double *data, int num_doubles,
                        int dest, int tag, int encrypt, const char *ctx)
{
    if (!encrypt) {
        mpi_send(data, num_doubles, MPI_DOUBLE, dest, tag, comm, ctx);
        return;
    }

    size_t data_bytes = (size_t)num_doubles * sizeof(double);
    size_t total = NPUB + data_bytes + ABYTES;
    unsigned char *buf = (unsigned char *)malloc(total);
    if (!buf) {
        fprintf(stderr, "[MASTER] malloc(%zu) failed in send_matrix\n", total);
        MPI_Abort(MPI_COMM_WORLD, 1);
    }

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

    mpi_send(buf, (int)total, MPI_UNSIGNED_CHAR, dest, tag, comm, ctx);
    free(buf);
}

static int recv_matrix(MPI_Comm comm, const unsigned char key[KEYB],
                       uint64_t *nonce_ctr,
                       double *data, int num_doubles,
                       int src, int tag, int encrypt, const char *ctx)
{
    if (!encrypt) {
        MPI_Status st;
        mpi_recv(data, num_doubles, MPI_DOUBLE, src, tag, comm, &st, ctx);
        return 0;
    }

    size_t data_bytes = (size_t)num_doubles * sizeof(double);
    size_t total = NPUB + data_bytes + ABYTES;
    unsigned char *buf = (unsigned char *)malloc(total);
    if (!buf) {
        fprintf(stderr, "[MASTER] malloc(%zu) failed in recv_matrix\n", total);
        return -1;
    }

    MPI_Status st;
    mpi_recv(buf, (int)total, MPI_UNSIGNED_CHAR, src, tag, comm, &st, ctx);

    uint64_t received_ctr = 0;
    memcpy(&received_ctr, buf, sizeof(uint64_t));
    if (received_ctr < *nonce_ctr) {
        fprintf(stderr, "[MASTER] REPLAY detected in recv_matrix [%s]\n", ctx);
        free(buf);
        return -1;
    }

    unsigned long long mlen = 0;
    if (crypto_aead_chacha20poly1305_ietf_decrypt(
            (unsigned char *)data, &mlen, NULL,
            buf + NPUB, (unsigned long long)(data_bytes + ABYTES),
            NULL, 0, buf, key) != 0) {
        fprintf(stderr, "[MASTER] AEAD decryption FAILED in recv_matrix [%s]\n", ctx);
        free(buf);
        return -1;
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

/* ── Partial verification: check first row of C against local computation ── */

static int verify_first_row(const double *A, const double *B,
                            const double *C, int M)
{
    for (int j = 0; j < M; j++) {
        double expected = 0.0;
        for (int k = 0; k < M; k++)
            expected += A[k] * B[k * M + j];   /* A[0][k] * B[k][j] */
        double diff = fabs(expected - C[j]);
        double scale = fabs(expected) > 1.0 ? fabs(expected) : 1.0;
        if (diff / scale > 1e-9) {
            fprintf(stderr, "[MASTER] VERIFY FAIL: C[0][%d] expected %.6e got %.6e\n",
                    j, expected, C[j]);
            return -1;
        }
    }
    return 0;
}

/* ── Statistics helpers ── */

static double compute_mean(const double *v, int n)
{
    double s = 0.0;
    for (int i = 0; i < n; i++) s += v[i];
    return s / n;
}

static double compute_stddev(const double *v, int n, double mean)
{
    double s = 0.0;
    for (int i = 0; i < n; i++) s += (v[i] - mean) * (v[i] - mean);
    return sqrt(s / n);
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
    int verify    = 0;
    int sizes[MAX_SIZES];
    int num_sizes = 0;
    const char *csv_file = "bench_results.csv";

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--master") == 0 && i + 1 < argc) {
            target = atoi(argv[++i]);
            if (target <= 0) target = 1;
        } else if (strcmp(argv[i], "--size") == 0 && i + 1 < argc) {
            sizes[0] = atoi(argv[++i]);
            num_sizes = 1;
        } else if (strcmp(argv[i], "--sizes") == 0 && i + 1 < argc) {
            i++;
            char buf[256];
            strncpy(buf, argv[i], sizeof(buf) - 1);
            buf[sizeof(buf) - 1] = '\0';
            char *tok = strtok(buf, ",");
            while (tok && num_sizes < MAX_SIZES) {
                sizes[num_sizes++] = atoi(tok);
                tok = strtok(NULL, ",");
            }
        } else if (strcmp(argv[i], "--runs") == 0 && i + 1 < argc) {
            num_runs = atoi(argv[++i]);
            if (num_runs <= 0) num_runs = 1;
        } else if (strcmp(argv[i], "--no-encrypt") == 0) {
            encrypt = 0;
        } else if (strcmp(argv[i], "--verify") == 0) {
            verify = 1;
        } else if (strcmp(argv[i], "--output") == 0 && i + 1 < argc) {
            csv_file = argv[++i];
        }
    }

    /* Defaults: 512, 1024, 2048 */
    if (num_sizes == 0) {
        sizes[0] = 512; sizes[1] = 1024; sizes[2] = 2048;
        num_sizes = 3;
    }

    /* ── MPI + libsodium init ── */
    MPI_Init(&argc, &argv);
    if (sodium_init() < 0) {
        fprintf(stderr, "[MASTER] sodium_init failed\n");
        MPI_Abort(MPI_COMM_WORLD, 1);
    }

    MPI_Comm workers[MAX_WORKERS];
    unsigned char wkey[MAX_WORKERS][KEYB];
    int nworkers = 0;
    memset(send_nonce_ctr, 0, sizeof send_nonce_ctr);
    memset(recv_nonce_ctr, 0, sizeof recv_nonce_ctr);

    printf("============================================================\n");
    printf("  MPI + SEV-SNP Star Topology — DGEMM Benchmark\n");
    printf("============================================================\n");
    printf("  target_workers = %d\n", target);
    printf("  matrix sizes   =");
    for (int i = 0; i < num_sizes; i++) printf(" %d", sizes[i]);
    printf("\n");
    printf("  runs/size      = %d\n", num_runs);
    printf("  data encrypt   = %s\n", encrypt ? "AEAD" : "plaintext");
#ifdef SKIP_ATTESTATION
    printf("  attestation    = SKIPPED (compiled with -DSKIP_ATTESTATION)\n");
#else
    printf("  attestation    = ENABLED (real SEV-SNP)\n");
#endif
    printf("  csv output     = %s\n", csv_file);
    printf("============================================================\n\n");

    /* ════════════════════════════════════════════════════════════════
     *  ENROLLMENT PHASE — EA attestation + ECDH (timed)
     * ════════════════════════════════════════════════════════════════ */

    double t_enroll_per_worker[MAX_WORKERS];
    double t_enroll_start = MPI_Wtime();

    for (int round = 1; round <= target; round++)
    {
        double t_worker_start = MPI_Wtime();

        char port[MPI_MAX_PORT_NAME];
        memset(port, 0, sizeof port);
        int rc = MPI_Open_port(MPI_INFO_NULL, port);
        if (rc != MPI_SUCCESS) die_mpi("MPI_Open_port failed", rc);

        write_port_file("port.txt", port);
        printf("[ENROLL] round %d/%d: waiting for worker...\n", round, target);

        MPI_Comm inter = MPI_COMM_NULL;
        rc = MPI_Comm_accept(port, MPI_INFO_NULL, 0, MPI_COMM_SELF, &inter);
        if (rc != MPI_SUCCESS) die_mpi("MPI_Comm_accept failed", rc);
        MPI_Barrier(inter);
        rc = MPI_Close_port(port);
        if (rc != MPI_SUCCESS) die_mpi("MPI_Close_port failed", rc);

        /* ── EA AuthenticatorRequest ── */
        struct ea_request ea_req;
        randombytes_buf(ea_req.context, EA_CONTEXT_LEN);
        ea_req.attestation_offer = 1;
        mpi_send(&ea_req, sizeof(ea_req), MPI_UNSIGNED_CHAR, 0,
                 TAG_EA_REQUEST, inter, "Send(EA_REQUEST)");

        /* ── Receive EA Authenticator ── */
        struct ea_auth_hdr auth_hdr;
        mpi_recv(&auth_hdr, sizeof(auth_hdr), MPI_UNSIGNED_CHAR, 0,
                 TAG_EA_AUTH_HDR, inter, MPI_STATUS_IGNORE, "Recv(EA_AUTH_HDR)");

        uint32_t evidence_len = auth_hdr.payload_hdr.evidence_len;
        unsigned char *evidence = NULL;
        if (evidence_len > MAX_REPORT_LEN) {
            fprintf(stderr, "[ENROLL] round %d: evidence too large, rejecting\n", round);
            MPI_Comm_disconnect(&inter);
            continue;
        }
        if (evidence_len > 0) {
            evidence = (unsigned char *)malloc(evidence_len);
            if (!evidence) { fprintf(stderr, "malloc evidence failed\n"); MPI_Abort(MPI_COMM_WORLD, 1); }
            mpi_recv(evidence, (int)evidence_len, MPI_UNSIGNED_CHAR, 0,
                     TAG_EA_EVIDENCE_DATA, inter, MPI_STATUS_IGNORE, "Recv(EA_EVIDENCE_DATA)");
        }

        unsigned char finished_recv[HASH_LEN];
        mpi_recv(finished_recv, HASH_LEN, MPI_UNSIGNED_CHAR, 0,
                 TAG_EA_FINISHED, inter, MPI_STATUS_IGNORE, "Recv(EA_FINISHED)");

        /* ── Validate EA Authenticator ── */
        int attest_ok = 1;

        if (ea_verify_payload(&auth_hdr.payload_hdr, ea_req.context,
                              auth_hdr.client_pk, crypto_kx_PUBLICKEYBYTES) != 0) {
            fprintf(stderr, "[ENROLL] round %d: binding verification FAILED\n", round);
            attest_ok = 0;
        }

        if (attest_ok) {
            unsigned char expected_finished[HASH_LEN];
            ea_compute_finished(ea_req.context,
                                auth_hdr.client_pk, crypto_kx_PUBLICKEYBYTES,
                                &auth_hdr.payload_hdr, evidence, evidence_len,
                                expected_finished);
            if (sodium_memcmp(expected_finished, finished_recv, HASH_LEN) != 0) {
                fprintf(stderr, "[ENROLL] round %d: Finished hash mismatch\n", round);
                attest_ok = 0;
            }
        }

        if (attest_ok && evidence_len > 0) {
            uint8_t expected_rd[REPORT_DATA_SIZE];
            ea_derive_report_data(auth_hdr.payload_hdr.binder.binding, expected_rd);
            if (verify_sev_snp_report(evidence, (int)evidence_len, expected_rd) != 0) {
                fprintf(stderr, "[ENROLL] round %d: SNP evidence verification FAILED\n", round);
                attest_ok = 0;
            }
        }
#ifndef SKIP_ATTESTATION
        /* Prava HW atestacija je OBAVEZNA: prazna evidencija (npr. pad snpguest-a
         * na workeru) ne sme tiho da prodje kao prihvacena. */
        if (evidence_len == 0) {
            fprintf(stderr, "[ENROLL] round %d: REJECTED (nema SNP evidencije)\n", round);
            attest_ok = 0;
        }
#endif
        free(evidence);

#ifdef SKIP_ATTESTATION
        attest_ok = 1;
#endif

        mpi_send(&attest_ok, 1, MPI_INT, 0, TAG_EA_RESULT, inter, "Send(EA_RESULT)");
        if (!attest_ok) {
            fprintf(stderr, "[ENROLL] round %d: REJECTED\n", round);
            MPI_Comm_disconnect(&inter);
            continue;
        }

        /* ── ECDH Key Exchange ── */
        unsigned char server_pk[crypto_kx_PUBLICKEYBYTES];
        unsigned char server_sk[crypto_kx_SECRETKEYBYTES];
        unsigned char rx[KEYB], tx[KEYB], app_key[KEYB];
        crypto_kx_keypair(server_pk, server_sk);
        mpi_send(server_pk, crypto_kx_PUBLICKEYBYTES, MPI_UNSIGNED_CHAR, 0,
                 TAG_KX_SERVER_PK, inter, "Send(KX_SERVER_PK)");

        if (crypto_kx_server_session_keys(rx, tx, server_pk, server_sk,
                                          auth_hdr.client_pk) != 0) {
            fprintf(stderr, "[MASTER] crypto_kx failed\n");
            MPI_Abort(MPI_COMM_WORLD, 1);
        }

        crypto_generichash_state hst;
        crypto_generichash_init(&hst, NULL, 0, KEYB);
        crypto_generichash_update(&hst, tx, KEYB);
        const char *label = "app_key";
        crypto_generichash_update(&hst, (const unsigned char *)label, strlen(label));
        crypto_generichash_final(&hst, app_key, KEYB);

        sodium_memzero(server_sk, sizeof server_sk);
        sodium_memzero(rx, sizeof rx);
        sodium_memzero(tx, sizeof tx);

        if (nworkers >= MAX_WORKERS) {
            fprintf(stderr, "[MASTER] too many workers\n");
            MPI_Abort(MPI_COMM_WORLD, 1);
        }
        workers[nworkers] = inter;
        memcpy(wkey[nworkers], app_key, KEYB);
        sodium_memzero(app_key, KEYB);

        t_enroll_per_worker[nworkers] = (MPI_Wtime() - t_worker_start) * 1000.0;
        printf("[ENROLL] round %d: worker #%d enrolled in %.1f ms\n",
               round, nworkers + 1, t_enroll_per_worker[nworkers]);
        nworkers++;
    }

    double t_enroll_total = (MPI_Wtime() - t_enroll_start) * 1000.0;

    if (nworkers == 0) {
        printf("[MASTER] no workers enrolled, exiting.\n");
        MPI_Finalize();
        return 1;
    }

    printf("\n[ENROLL] Summary:\n");
    printf("  total enrollment time: %.1f ms\n", t_enroll_total);
    for (int w = 0; w < nworkers; w++)
        printf("  worker #%d: %.1f ms\n", w + 1, t_enroll_per_worker[w]);
    printf("\n");

    /* ════════════════════════════════════════════════════════════════
     *  BENCHMARK PHASE — distributed matrix multiplication
     * ════════════════════════════════════════════════════════════════ */

    for (int si = 0; si < num_sizes; si++)
    {
        int M = sizes[si];
        if (M % nworkers != 0) {
            printf("[BENCH] WARNING: M=%d not divisible by %d workers, skipping\n",
                   M, nworkers);
            continue;
        }

        printf("[BENCH] === Matrix size %d x %d  (%d workers, %s) ===\n",
               M, M, nworkers, encrypt ? "encrypted" : "plaintext");

        /* ── Allocate matrices ── */
        size_t mat_elems = (size_t)M * M;
        double *A = (double *)malloc(mat_elems * sizeof(double));
        double *B = (double *)malloc(mat_elems * sizeof(double));
        double *C = (double *)malloc(mat_elems * sizeof(double));
        if (!A || !B || !C) {
            fprintf(stderr, "[BENCH] malloc failed for M=%d\n", M);
            free(A); free(B); free(C);
            continue;
        }

        /* Generate reproducible random matrices */
        srand(42 + M);
        for (size_t i = 0; i < mat_elems; i++) {
            A[i] = (double)rand() / RAND_MAX * 2.0 - 1.0;
            B[i] = (double)rand() / RAND_MAX * 2.0 - 1.0;
        }

        /* Compute row assignments for each worker */
        int rows_per_worker = M / nworkers;
        int row_starts[MAX_WORKERS], row_counts[MAX_WORKERS];
        for (int w = 0; w < nworkers; w++) {
            row_starts[w] = w * rows_per_worker;
            row_counts[w] = rows_per_worker;
        }

        /* ── Send benchmark command to each worker ── */
        for (int w = 0; w < nworkers; w++) {
            struct bench_cmd cmd;
            cmd.cmd          = CMD_BENCH_SIZE;
            cmd.matrix_size  = M;
            cmd.row_start    = row_starts[w];
            cmd.row_count    = row_counts[w];
            cmd.encrypt_data = encrypt;
            cmd.num_runs     = num_runs;
            secure_send(workers[w], wkey[w], &send_nonce_ctr[w],
                        &cmd, sizeof(cmd), 0, TAG_BENCH_CMD,
                        "Send(BENCH_CMD)");
        }

        /* Per-run timing arrays for statistics */
        double t_scatter_arr[MAX_RUNS];
        double t_gather_arr[MAX_RUNS];
        double t_round_arr[MAX_RUNS];
        double t_compute_max_arr[MAX_RUNS];
        double t_comm_arr[MAX_RUNS];

        /* ── Run benchmark iterations ── */
        for (int run = 1; run <= num_runs; run++)
        {
            /* Scatter: send A_block + B to each worker */
            double t0 = MPI_Wtime();

            for (int w = 0; w < nworkers; w++) {
                int rs = row_starts[w];
                int rc_count = row_counts[w];
                int a_elems = rc_count * M;

                send_matrix(workers[w], wkey[w], &send_nonce_ctr[w],
                            A + (size_t)rs * M, a_elems,
                            0, TAG_BENCH_A, encrypt, "Send(A_block)");
                send_matrix(workers[w], wkey[w], &send_nonce_ctr[w],
                            B, (int)mat_elems,
                            0, TAG_BENCH_B, encrypt, "Send(B)");
            }

            double t1 = MPI_Wtime();

            /* Gather: receive C_blocks + compute times */
            double t_compute_max = 0.0;

            for (int w = 0; w < nworkers; w++) {
                int c_elems = row_counts[w] * M;
                double *C_block = C + (size_t)row_starts[w] * M;

                if (recv_matrix(workers[w], wkey[w], &recv_nonce_ctr[w],
                                C_block, c_elems,
                                0, TAG_BENCH_C, encrypt, "Recv(C_block)") != 0) {
                    fprintf(stderr, "[BENCH] recv C_block FAILED from worker #%d\n", w + 1);
                    MPI_Abort(MPI_COMM_WORLD, 1);
                }

                double t_compute_w = 0.0;
                if (secure_recv(workers[w], wkey[w], &recv_nonce_ctr[w],
                                &t_compute_w, sizeof(double),
                                0, TAG_BENCH_TIME, "Recv(compute_time)") != 0) {
                    fprintf(stderr, "[BENCH] recv compute_time FAILED from worker #%d\n", w + 1);
                    MPI_Abort(MPI_COMM_WORLD, 1);
                }

                if (t_compute_w > t_compute_max)
                    t_compute_max = t_compute_w;
            }

            double t2 = MPI_Wtime();

            double t_scatter = (t1 - t0) * 1000.0;
            double t_gather  = (t2 - t1) * 1000.0;
            double t_round   = (t2 - t0) * 1000.0;
            double t_comm    = t_round - t_compute_max;

            int ri = run - 1;
            t_scatter_arr[ri]      = t_scatter;
            t_gather_arr[ri]       = t_gather;
            t_round_arr[ri]        = t_round;
            t_compute_max_arr[ri]  = t_compute_max;
            t_comm_arr[ri]         = t_comm;

            /* Store result */
            if (g_nresults < MAX_RESULTS) {
                struct bench_result *r = &g_results[g_nresults++];
                r->matrix_size    = M;
                r->num_workers    = nworkers;
                r->encrypted      = encrypt;
                r->run            = run;
                r->t_scatter_ms   = t_scatter;
                r->t_compute_max_ms = t_compute_max;
                r->t_gather_ms    = t_gather;
                r->t_round_ms     = t_round;
                r->t_comm_ms      = t_comm;
            }

            /* Verify first iteration */
            if (run == 1 && verify) {
                if (verify_first_row(A, B, C, M) == 0)
                    printf("[BENCH] run %d: verification PASSED\n", run);
                else
                    printf("[BENCH] run %d: verification FAILED\n", run);
            }

            printf("[BENCH] M=%d run %d/%d: scatter=%.1f compute=%.1f "
                   "gather=%.1f round=%.1f comm=%.1f ms\n",
                   M, run, num_runs, t_scatter, t_compute_max,
                   t_gather, t_round, t_comm);
        }

        /* ── Per-size summary ── */
        double mean_scatter = compute_mean(t_scatter_arr, num_runs);
        double mean_compute = compute_mean(t_compute_max_arr, num_runs);
        double mean_gather  = compute_mean(t_gather_arr, num_runs);
        double mean_round   = compute_mean(t_round_arr, num_runs);
        double mean_comm    = compute_mean(t_comm_arr, num_runs);

        double sd_scatter = compute_stddev(t_scatter_arr, num_runs, mean_scatter);
        double sd_compute = compute_stddev(t_compute_max_arr, num_runs, mean_compute);
        double sd_gather  = compute_stddev(t_gather_arr, num_runs, mean_gather);
        double sd_round   = compute_stddev(t_round_arr, num_runs, mean_round);
        double sd_comm    = compute_stddev(t_comm_arr, num_runs, mean_comm);

        printf("\n[BENCH] M=%d  Summary (%d runs):\n", M, num_runs);
        printf("  scatter : %8.1f +/- %6.1f ms\n", mean_scatter, sd_scatter);
        printf("  compute : %8.1f +/- %6.1f ms\n", mean_compute, sd_compute);
        printf("  gather  : %8.1f +/- %6.1f ms\n", mean_gather, sd_gather);
        printf("  round   : %8.1f +/- %6.1f ms\n", mean_round, sd_round);
        printf("  comm    : %8.1f +/- %6.1f ms  (round - compute)\n", mean_comm, sd_comm);
        printf("\n");

        free(A);
        free(B);
        free(C);
    }

    /* ════════════════════════════════════════════════════════════════
     *  SHUTDOWN — send CMD_BENCH_DONE to all workers
     * ════════════════════════════════════════════════════════════════ */

    for (int w = 0; w < nworkers; w++) {
        struct bench_cmd cmd;
        memset(&cmd, 0, sizeof cmd);
        cmd.cmd = CMD_BENCH_DONE;
        secure_send(workers[w], wkey[w], &send_nonce_ctr[w],
                    &cmd, sizeof(cmd), 0, TAG_BENCH_CMD, "Send(BENCH_DONE)");
        MPI_Comm_disconnect(&workers[w]);
    }

    sodium_memzero(wkey, sizeof wkey);

    /* ════════════════════════════════════════════════════════════════
     *  OUTPUT — write CSV results file
     * ════════════════════════════════════════════════════════════════ */

    FILE *csv = fopen(csv_file, "w");
    if (csv) {
        fprintf(csv, "# MPI+SEV-SNP Star Topology — DGEMM Benchmark\n");
#ifdef SKIP_ATTESTATION
        fprintf(csv, "# attestation: skipped\n");
#else
        fprintf(csv, "# attestation: enabled\n");
#endif
        fprintf(csv, "# data_encryption: %s\n", encrypt ? "AEAD" : "plaintext");
        fprintf(csv, "# runs_per_size: %d\n", num_runs);
        fprintf(csv, "# enrollment_total_ms: %.1f\n", t_enroll_total);
        for (int w = 0; w < nworkers; w++)
            fprintf(csv, "# enrollment_worker%d_ms: %.1f\n",
                    w + 1, t_enroll_per_worker[w]);
        fprintf(csv, "#\n");
        fprintf(csv, "matrix_size,num_workers,encryption,run,"
                     "t_scatter_ms,t_compute_max_ms,t_gather_ms,"
                     "t_round_ms,t_comm_ms\n");

        for (int i = 0; i < g_nresults; i++) {
            struct bench_result *r = &g_results[i];
            fprintf(csv, "%d,%d,%s,%d,%.3f,%.3f,%.3f,%.3f,%.3f\n",
                    r->matrix_size, r->num_workers,
                    r->encrypted ? "encrypted" : "plaintext",
                    r->run,
                    r->t_scatter_ms, r->t_compute_max_ms,
                    r->t_gather_ms, r->t_round_ms, r->t_comm_ms);
        }
        fclose(csv);
        printf("[OUTPUT] Results written to %s\n", csv_file);
    } else {
        fprintf(stderr, "[OUTPUT] WARNING: could not open %s for writing\n", csv_file);
    }

    printf("\n[MASTER] Benchmark complete.\n");
    MPI_Finalize();
    return 0;
}
