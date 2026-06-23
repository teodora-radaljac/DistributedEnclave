/*
 * worker_npb.c – NPB-kernel worker for MPI + SEV-SNP star topology.
 *
 * Connects to master_npb, performs EA/aTLS attestation + ECDH key exchange,
 * then executes NPB-derived compute kernels (EP or CG) upon command.
 *
 * Workloads:
 *   EP  — Box-Muller Gaussian deviate generation + annular bin counting.
 *   CG  — Sparse Matrix-Vector multiplication kernel (y = A*x).
 *
 * Compile (production):
 *   mpicc -O2 -Wall -Wextra -o worker_npb worker_npb.c -lsodium -lm
 *
 * Compile (skip real SNP):
 *   mpicc -DSKIP_ATTESTATION -O2 -Wall -Wextra -o worker_npb worker_npb.c -lsodium -lm
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
#include <unistd.h>

/* ── MPI message tags: EA attestation ── */
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
    TAG_NPB_CMD      = 130,
    TAG_NPB_EP_RESULT= 131,
    TAG_NPB_CG_X     = 132,
    TAG_NPB_CG_Y     = 133,
    TAG_NPB_CG_MATRIX= 134,
    TAG_NPB_TIME     = 135
};

/* ── NPB workload types ── */
#define WORKLOAD_EP   1
#define WORKLOAD_CG   2

/* ── NPB command codes ── */
#define CMD_NPB_START  1
#define CMD_NPB_ITER   2
#define CMD_NPB_DONE   3

/* ── Crypto constants ── */
#define KEYB   crypto_aead_chacha20poly1305_ietf_KEYBYTES
#define NPUB   crypto_aead_chacha20poly1305_ietf_NPUBBYTES
#define ABYTES crypto_aead_chacha20poly1305_ietf_ABYTES

#define HASH_LEN         32
#define BINDING_LEN      32
#define REPORT_DATA_SIZE 64
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
    int32_t cmd;
    int32_t workload;
    int32_t encrypt_data;
    int32_t num_runs;
    int64_t ep_pairs;
    int32_t cg_rows;
    int32_t cg_row_start;
    int32_t cg_row_count;
    int32_t cg_n;
    int32_t cg_nzpc;
    int32_t cg_iters;
};

/* ── EP result struct ── */
#define EP_BINS 10
struct ep_result {
    int64_t counts[EP_BINS];
    double  sx;
    double  sy;
};

/* ── Session state ── */
static unsigned char g_session_key[KEYB];
static uint64_t send_nonce_ctr = 0;
static uint64_t recv_nonce_ctr = 0;

/* ──────────────────────────────────────────────────────────────────────
 *  Utility helpers
 * ────────────────────────────────────────────────────────────────────── */

static void die_mpi(const char *msg, int rc)
{
    char es[256]; int n = 0;
    MPI_Error_string(rc, es, &n);
    fprintf(stderr, "[WORKER] FATAL: %s rc=%d (%s)\n", msg, rc, es);
    fflush(stderr);
    MPI_Abort(MPI_COMM_WORLD, 1);
    exit(1);
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

/* ── Generate SNP attestation report ── */

static int generate_snp_report(const uint8_t report_data[REPORT_DATA_SIZE],
                               unsigned char **out_report, int *out_len)
{
    char rd_hex[REPORT_DATA_SIZE * 2 + 1];
    bytes_to_hex(report_data, REPORT_DATA_SIZE, rd_hex, sizeof rd_hex);

    char cmd[512];
    /* NE koristiti --random: snpguest tada ignorise request-data.bin i upise
     * random report_data, pa master odbije ("Report Data did not match").
     * Report_data MORA biti EA binding zapisan u request-data.bin ispod. */
    snprintf(cmd, sizeof cmd,
             "snpguest report attestation-report.bin request-data.bin "
             "> snpguest_report.log 2>&1");

    /* Write report_data to request-data.bin */
    FILE *f = fopen("request-data.bin", "wb");
    if (!f) return -1;
    fwrite(report_data, 1, REPORT_DATA_SIZE, f);
    fclose(f);

    int status = system(cmd);
    if (status == -1 || !WIFEXITED(status) || WEXITSTATUS(status) != 0)
        return -1;

    f = fopen("attestation-report.bin", "rb");
    if (!f) return -1;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0 || sz > MAX_REPORT_LEN) { fclose(f); return -1; }
    *out_report = (unsigned char *)malloc((size_t)sz);
    *out_len = (int)fread(*out_report, 1, (size_t)sz, f);
    fclose(f);
    return 0;
}

/* ──────────────────────────────────────────────────────────────────────
 *  AEAD secure send / recv — SMALL messages (≤ 256 B)
 * ────────────────────────────────────────────────────────────────────── */

static void secure_send(MPI_Comm comm,
                        const void *plaintext, int plain_len,
                        int dest, int tag, const char *ctx)
{
    if (plain_len < 0 || plain_len > SECURE_MAX_PLAIN) {
        fprintf(stderr, "[WORKER] secure_send: plain_len %d out of range\n", plain_len);
        MPI_Abort(MPI_COMM_WORLD, 1);
    }
    unsigned char nonce[NPUB];
    memset(nonce, 0, NPUB);
    memcpy(nonce, &send_nonce_ctr, sizeof(uint64_t));
    send_nonce_ctr++;

    unsigned char buf[NPUB + SECURE_MAX_PLAIN + ABYTES];
    unsigned long long clen = 0;
    crypto_aead_chacha20poly1305_ietf_encrypt(
        buf + NPUB, &clen,
        (const unsigned char *)plaintext, (unsigned long long)plain_len,
        NULL, 0, NULL, nonce, g_session_key);
    memcpy(buf, nonce, NPUB);
    int total = NPUB + plain_len + (int)ABYTES;
    mpi_send_f(buf, total, MPI_UNSIGNED_CHAR, dest, tag, comm, ctx);
}

static int secure_recv(MPI_Comm comm,
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
    if (received_ctr < recv_nonce_ctr) {
        fprintf(stderr, "[WORKER] REPLAY detected [%s]\n", ctx);
        return -1;
    }
    unsigned long long mlen = 0;
    if (crypto_aead_chacha20poly1305_ietf_decrypt(
            (unsigned char *)plaintext, &mlen, NULL,
            buf + NPUB, (unsigned long long)(plain_len + (int)ABYTES),
            NULL, 0, buf, g_session_key) != 0) {
        fprintf(stderr, "[WORKER] AEAD decryption FAILED [%s]\n", ctx);
        return -1;
    }
    recv_nonce_ctr = received_ctr + 1;
    return 0;
}

/* ── AEAD bulk send / recv — LARGE messages ── */

static void send_bulk(MPI_Comm comm,
                      const void *data, size_t data_bytes,
                      int dest, int tag, int encrypt, const char *ctx)
{
    if (!encrypt) {
        mpi_send_f(data, (int)data_bytes, MPI_UNSIGNED_CHAR, dest, tag, comm, ctx);
        return;
    }
    size_t total_bytes = NPUB + data_bytes + ABYTES;
    unsigned char *buf = (unsigned char *)malloc(total_bytes);
    if (!buf) { fprintf(stderr, "malloc failed\n"); MPI_Abort(MPI_COMM_WORLD, 1); }

    unsigned char nonce[NPUB];
    memset(nonce, 0, NPUB);
    memcpy(nonce, &send_nonce_ctr, sizeof(uint64_t));
    send_nonce_ctr++;

    unsigned long long clen = 0;
    crypto_aead_chacha20poly1305_ietf_encrypt(
        buf + NPUB, &clen,
        (const unsigned char *)data, (unsigned long long)data_bytes,
        NULL, 0, NULL, nonce, g_session_key);
    memcpy(buf, nonce, NPUB);
    mpi_send_f(buf, (int)total_bytes, MPI_UNSIGNED_CHAR, dest, tag, comm, ctx);
    free(buf);
}

static int recv_bulk(MPI_Comm comm,
                     void *data, size_t data_bytes,
                     int src, int tag, int encrypt, const char *ctx)
{
    if (!encrypt) {
        MPI_Status st;
        mpi_recv_f(data, (int)data_bytes, MPI_UNSIGNED_CHAR, src, tag, comm, &st, ctx);
        return 0;
    }
    size_t total_bytes = NPUB + data_bytes + ABYTES;
    unsigned char *buf = (unsigned char *)malloc(total_bytes);
    if (!buf) return -1;

    MPI_Status st;
    mpi_recv_f(buf, (int)total_bytes, MPI_UNSIGNED_CHAR, src, tag, comm, &st, ctx);

    uint64_t received_ctr = 0;
    memcpy(&received_ctr, buf, sizeof(uint64_t));
    if (received_ctr < recv_nonce_ctr) { free(buf); return -1; }

    unsigned long long mlen = 0;
    if (crypto_aead_chacha20poly1305_ietf_decrypt(
            (unsigned char *)data, &mlen, NULL,
            buf + NPUB, (unsigned long long)(data_bytes + ABYTES),
            NULL, 0, buf, g_session_key) != 0) {
        free(buf); return -1;
    }
    recv_nonce_ctr = received_ctr + 1;
    free(buf);
    return 0;
}

/* ──────────────────────────────────────────────────────────────────────
 *  NPB EP Kernel — Gaussian Random Deviates via Box-Muller
 *
 *  Uses a simple linear congruential generator (NPB-style):
 *    x_{n+1} = a * x_n mod 2^46
 *  where a = 5^13 = 1220703125
 *
 *  Each pair of uniform randoms u1,u2 is transformed:
 *    x = sqrt(-2*ln(u1)) * cos(2*pi*u2)
 *    y = sqrt(-2*ln(u1)) * sin(2*pi*u2)
 *
 *  Pairs are classified into annular bins based on
 *    l = max(|x|, |y|) truncated to int, bin = min(l, 9)
 * ────────────────────────────────────────────────────────────────────── */

#define NPB_R46  ((double)(1L << 46))
#define NPB_A    1220703125LL   /* 5^13 */
#define NPB_TWO_PI 6.283185307179586

static inline double npb_rand(int64_t *state)
{
    *state = (NPB_A * (*state)) % (1LL << 46);
    return (double)(*state) / NPB_R46;
}

static void ep_compute(int64_t num_pairs, int64_t seed_val,
                       struct ep_result *result)
{
    memset(result, 0, sizeof(*result));
    int64_t state = seed_val;
    if (state <= 0) state = 271828183LL;

    for (int64_t i = 0; i < num_pairs; i++) {
        double u1 = npb_rand(&state);
        double u2 = npb_rand(&state);
        if (u1 < 1.0e-15) u1 = 1.0e-15;

        double t = sqrt(-2.0 * log(u1));
        double x = t * cos(NPB_TWO_PI * u2);
        double y = t * sin(NPB_TWO_PI * u2);

        result->sx += x;
        result->sy += y;

        double lmax = fabs(x) > fabs(y) ? fabs(x) : fabs(y);
        int bin = (int)lmax;
        if (bin >= EP_BINS) bin = EP_BINS - 1;
        result->counts[bin]++;
    }
}

/* ──────────────────────────────────────────────────────────────────────
 *  NPB CG Kernel — Sparse Matrix-Vector Multiply (y = A*x)
 *  CSR format: row_ptr, col_idx, val
 * ────────────────────────────────────────────────────────────────────── */

static void spmv_kernel(int nrows, const int *row_ptr,
                        const int *col_idx, const double *val,
                        const double *x, double *y)
{
    for (int i = 0; i < nrows; i++) {
        double sum = 0.0;
        for (int j = row_ptr[i]; j < row_ptr[i + 1]; j++)
            sum += val[j] * x[col_idx[j]];
        y[i] = sum;
    }
}

/* ══════════════════════════════════════════════════════════════════════
 *  main()
 * ══════════════════════════════════════════════════════════════════════ */

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    MPI_Init(&argc, &argv);
    if (sodium_init() < 0) { fprintf(stderr, "sodium_init failed\n"); MPI_Abort(MPI_COMM_WORLD, 1); }

    /* ── Read port name ── */
    const char *port_file = "port.txt";
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--port-file") == 0 && i + 1 < argc)
            port_file = argv[++i];
    }

    char port_name[MPI_MAX_PORT_NAME];
    memset(port_name, 0, sizeof port_name);
    for (int try = 0; try < 60; try++) {
        FILE *pf = fopen(port_file, "r");
        if (pf) {
            if (fgets(port_name, sizeof port_name, pf)) {
                char *nl = strchr(port_name, '\n');
                if (nl) *nl = '\0';
            }
            fclose(pf);
            if (strlen(port_name) > 0) break;
        }
        sleep(1);
    }
    if (strlen(port_name) == 0) {
        fprintf(stderr, "[WORKER] Could not read port from %s\n", port_file);
        MPI_Finalize(); return 1;
    }

    printf("[WORKER] Connecting to %s\n", port_name);

    MPI_Comm inter = MPI_COMM_NULL;
    int rc = MPI_Comm_connect(port_name, MPI_INFO_NULL, 0, MPI_COMM_SELF, &inter);
    if (rc != MPI_SUCCESS) die_mpi("MPI_Comm_connect", rc);
    MPI_Barrier(inter);
    printf("[WORKER] Connected.\n");

    /* ════════════════════════════════════════════════════════════════
     *  EA ATTESTATION PHASE
     * ════════════════════════════════════════════════════════════════ */

    /* Receive AuthenticatorRequest */
    struct ea_request ea_req;
    mpi_recv_f(&ea_req, sizeof(ea_req), MPI_UNSIGNED_CHAR, 0,
               TAG_EA_REQUEST, inter, MPI_STATUS_IGNORE, "Recv(EA_REQUEST)");

    /* Generate ECDH client keypair */
    unsigned char client_pk[crypto_kx_PUBLICKEYBYTES];
    unsigned char client_sk[crypto_kx_SECRETKEYBYTES];
    crypto_kx_keypair(client_pk, client_sk);

    /* Compute binding chain */
    uint8_t exported_value[HASH_LEN], aik_hash[HASH_LEN], binding[BINDING_LEN];
    ea_compute_binding(ea_req.context, client_pk, crypto_kx_PUBLICKEYBYTES,
                       exported_value, aik_hash, binding);
    uint8_t report_data[REPORT_DATA_SIZE];
    ea_derive_report_data(binding, report_data);

    /* Generate SNP attestation evidence */
    unsigned char *evidence = NULL;
    int evidence_len = 0;
#ifndef SKIP_ATTESTATION
    if (generate_snp_report(report_data, &evidence, &evidence_len) != 0) {
        fprintf(stderr, "[WORKER] WARNING: snpguest report generation failed\n");
        evidence_len = 0;
    }
#endif

    /* Build and send Authenticator */
    struct ea_auth_hdr auth_hdr;
    memset(&auth_hdr, 0, sizeof auth_hdr);
    memcpy(auth_hdr.client_pk, client_pk, crypto_kx_PUBLICKEYBYTES);
    auth_hdr.payload_hdr.version = EA_PAYLOAD_VERSION;
    strncpy(auth_hdr.payload_hdr.media_type, EA_MEDIA_TYPE,
            sizeof(auth_hdr.payload_hdr.media_type) - 1);
    auth_hdr.payload_hdr.evidence_len = (uint32_t)evidence_len;
    memcpy(auth_hdr.payload_hdr.binder.aik_pub_hash, aik_hash, HASH_LEN);
    memcpy(auth_hdr.payload_hdr.binder.binding, binding, BINDING_LEN);
    strncpy(auth_hdr.payload_hdr.binder.exporter_label, EA_EXPORTER_LABEL,
            sizeof(auth_hdr.payload_hdr.binder.exporter_label) - 1);

    mpi_send_f(&auth_hdr, sizeof(auth_hdr), MPI_UNSIGNED_CHAR, 0,
               TAG_EA_AUTH_HDR, inter, "Send(EA_AUTH_HDR)");
    if (evidence_len > 0)
        mpi_send_f(evidence, evidence_len, MPI_UNSIGNED_CHAR, 0,
                   TAG_EA_EVIDENCE_DATA, inter, "Send(EVIDENCE)");

    /* Compute and send Finished */
    uint8_t finished[HASH_LEN];
    ea_compute_finished(ea_req.context, client_pk, crypto_kx_PUBLICKEYBYTES,
                        &auth_hdr.payload_hdr, evidence, (uint32_t)evidence_len,
                        finished);
    mpi_send_f(finished, HASH_LEN, MPI_UNSIGNED_CHAR, 0,
               TAG_EA_FINISHED, inter, "Send(FINISHED)");
    free(evidence);

    /* Check attestation result */
    int attest_ok = 0;
    mpi_recv_f(&attest_ok, 1, MPI_INT, 0, TAG_EA_RESULT, inter,
               MPI_STATUS_IGNORE, "Recv(EA_RESULT)");
    if (!attest_ok) {
        fprintf(stderr, "[WORKER] Attestation REJECTED by master\n");
        MPI_Comm_disconnect(&inter); MPI_Finalize(); return 1;
    }
    printf("[WORKER] Attestation accepted.\n");

    /* ECDH Key Derivation */
    unsigned char server_pk[crypto_kx_PUBLICKEYBYTES];
    mpi_recv_f(server_pk, crypto_kx_PUBLICKEYBYTES, MPI_UNSIGNED_CHAR, 0,
               TAG_KX_SERVER_PK, inter, MPI_STATUS_IGNORE, "Recv(KX_SERVER_PK)");

    unsigned char rx[KEYB], tx[KEYB];
    if (crypto_kx_client_session_keys(rx, tx, client_pk, client_sk, server_pk) != 0)
        die_mpi("crypto_kx_client failed", 0);

    crypto_generichash_state hst;
    crypto_generichash_init(&hst, NULL, 0, KEYB);
    crypto_generichash_update(&hst, rx, KEYB);
    const char *label = "app_key";
    crypto_generichash_update(&hst, (const unsigned char *)label, strlen(label));
    crypto_generichash_final(&hst, g_session_key, KEYB);

    sodium_memzero(client_sk, sizeof client_sk);
    sodium_memzero(rx, sizeof rx);
    sodium_memzero(tx, sizeof tx);
    printf("[WORKER] Session key established.\n");

    /* ════════════════════════════════════════════════════════════════
     *  NPB BENCHMARK LOOP
     * ════════════════════════════════════════════════════════════════ */

    while (1)
    {
        struct npb_cmd cmd;
        if (secure_recv(inter, &cmd, sizeof(cmd), 0, TAG_NPB_CMD,
                        "Recv(NPB_CMD)") != 0) {
            fprintf(stderr, "[WORKER] CMD recv failed\n"); break;
        }

        if (cmd.cmd == CMD_NPB_DONE) {
            printf("[WORKER] Received NPB_DONE. Exiting.\n");
            break;
        }

        if (cmd.cmd == CMD_NPB_START && cmd.workload == WORKLOAD_EP)
        {
            /* ── EP Workload ── */
            printf("[WORKER] EP workload: %" PRId64 " pairs, %d runs\n",
                   cmd.ep_pairs, cmd.num_runs);

            for (int run = 1; run <= cmd.num_runs; run++)
            {
                /* Receive seed for this run */
                int64_t seed = 0;
                if (secure_recv(inter, &seed, sizeof(seed), 0, TAG_NPB_CMD,
                                "Recv(EP_seed)") != 0) {
                    fprintf(stderr, "[WORKER] EP seed recv failed\n"); break;
                }

                /* Compute */
                double t0 = MPI_Wtime();
                struct ep_result result;
                ep_compute(cmd.ep_pairs, seed, &result);
                double t_compute = (MPI_Wtime() - t0) * 1000.0;

                /* Send result + time */
                secure_send(inter, &result, sizeof(result), 0,
                            TAG_NPB_EP_RESULT, "Send(EP_RESULT)");
                secure_send(inter, &t_compute, sizeof(t_compute), 0,
                            TAG_NPB_TIME, "Send(EP_TIME)");
            }
            printf("[WORKER] EP workload complete.\n");
        }
        else if (cmd.cmd == CMD_NPB_START && cmd.workload == WORKLOAD_CG)
        {
            /* ── CG Workload ── */
            int nrows = cmd.cg_row_count;
            int cg_n  = cmd.cg_n;
            int cg_iters = cmd.cg_iters;
            int enc = cmd.encrypt_data;
            printf("[WORKER] CG workload: rows=%d, n=%d, iters=%d, runs=%d\n",
                   nrows, cg_n, cg_iters, cmd.num_runs);

            /* Receive sparse matrix (CSR) */
            int *row_ptr = (int *)malloc((size_t)(nrows + 1) * sizeof(int));
            if (recv_bulk(inter, row_ptr, (size_t)(nrows + 1) * sizeof(int),
                          0, TAG_NPB_CG_MATRIX, enc, "Recv(CG_rowptr)") != 0)
                break;

            int nnz = row_ptr[nrows];
            int *col_idx = (int *)malloc((size_t)nnz * sizeof(int));
            double *val  = (double *)malloc((size_t)nnz * sizeof(double));

            if (recv_bulk(inter, col_idx, (size_t)nnz * sizeof(int),
                          0, TAG_NPB_CG_MATRIX, enc, "Recv(CG_colidx)") != 0)
                break;
            if (recv_bulk(inter, val, (size_t)nnz * sizeof(double),
                          0, TAG_NPB_CG_MATRIX, enc, "Recv(CG_val)") != 0)
                break;

            /* Allocate working vectors */
            double *x = (double *)malloc((size_t)cg_n * sizeof(double));
            double *y = (double *)malloc((size_t)nrows * sizeof(double));

            for (int run = 1; run <= cmd.num_runs; run++)
            {
                for (int iter = 0; iter < cg_iters; iter++)
                {
                    /* Receive x vector */
                    if (recv_bulk(inter, x, (size_t)cg_n * sizeof(double),
                                  0, TAG_NPB_CG_X, enc, "Recv(CG_x)") != 0)
                        goto cg_done;

                    /* Compute SpMV */
                    double t0 = MPI_Wtime();
                    spmv_kernel(nrows, row_ptr, col_idx, val, x, y);
                    double t_compute = (MPI_Wtime() - t0) * 1000.0;

                    /* Send partial y + time */
                    send_bulk(inter, y, (size_t)nrows * sizeof(double),
                              0, TAG_NPB_CG_Y, enc, "Send(CG_y)");
                    secure_send(inter, &t_compute, sizeof(t_compute), 0,
                                TAG_NPB_TIME, "Send(CG_TIME)");
                }
            }
cg_done:
            free(row_ptr); free(col_idx); free(val);
            free(x); free(y);
            printf("[WORKER] CG workload complete.\n");
        }
    }

    /* ═══════════════════════ CLEANUP ═══════════════════════ */
    sodium_memzero(g_session_key, KEYB);
    MPI_Comm_disconnect(&inter);
    printf("[WORKER] Disconnected.\n");
    MPI_Finalize();
    return 0;
}
