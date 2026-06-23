/*
 * worker_bench.c – Matrix-multiply benchmark worker for MPI + SEV-SNP star topology.
 *
 * Uses the same EA/aTLS attestation protocol as worker_attest.c, then
 * enters a benchmark loop: receive matrix data, compute C = A × B,
 * send results + timing back to master.
 *
 * Usage:
 *   ./worker_bench <PORT_STRING>
 *
 * Compile (production):
 *   mpicc -O2 -Wall -Wextra -o worker_bench worker_bench.c -lsodium -lm
 *
 * Compile (skip real SNP — for testing on non-CVM hosts):
 *   mpicc -DSKIP_ATTESTATION -O2 -Wall -Wextra -o worker_bench worker_bench.c -lsodium -lm
 */

#include <mpi.h>
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <time.h>

/* ── MPI message tags: EA attestation protocol (must match master) ── */
enum {
    TAG_EA_REQUEST       = 70,
    TAG_EA_AUTH_HDR      = 71,
    TAG_EA_EVIDENCE_DATA = 72,
    TAG_EA_FINISHED      = 73,
    TAG_EA_RESULT        = 74,
    TAG_KX_SERVER_PK     = 91
};

/* ── MPI message tags: benchmark data plane (must match master) ── */
enum {
    TAG_BENCH_CMD  = 120,
    TAG_BENCH_A    = 121,
    TAG_BENCH_B    = 122,
    TAG_BENCH_C    = 123,
    TAG_BENCH_TIME = 124
};

/* ── Benchmark command codes (must match master) ── */
#define CMD_BENCH_SIZE  1
#define CMD_BENCH_DONE  2

/* ── Crypto constants ── */
#define KEYB   crypto_aead_chacha20poly1305_ietf_KEYBYTES
#define NPUB   crypto_aead_chacha20poly1305_ietf_NPUBBYTES
#define ABYTES crypto_aead_chacha20poly1305_ietf_ABYTES

#define HASH_LEN         32
#define BINDING_LEN      32
#define REPORT_DATA_SIZE 64

#define SNP_REPORT_DATA_FILE   "report_data.bin"
#define SNP_REPORT_OUTPUT_FILE "attestation-report.bin"

#define SECURE_MAX_PLAIN 256

_Static_assert(crypto_kx_SESSIONKEYBYTES == KEYB,
               "kx session key size must match AEAD key size");

/* ── EA / CMW Attestation types (must match master) ── */

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

/* ── Benchmark command struct (must match master) ── */
struct bench_cmd {
    int32_t cmd;
    int32_t matrix_size;
    int32_t row_start;
    int32_t row_count;
    int32_t encrypt_data;
    int32_t num_runs;
};

/* ── Globals ── */
static unsigned char g_session_key[KEYB];
static uint64_t send_nonce_ctr = 0;
static uint64_t recv_nonce_ctr = 0;

/* ──────────────────────────────────────────────────────────────────────
 *  Utility helpers
 * ────────────────────────────────────────────────────────────────────── */

static void die_mpi(const char *msg, int rc)
{
    char es[256];
    int n = 0;
    MPI_Error_string(rc, es, &n);
    fprintf(stderr, "[WORKER] FATAL: %s rc=%d (%s)\n", msg, rc, es);
    fflush(stderr);
    MPI_Abort(MPI_COMM_WORLD, 1);
    exit(1);
}

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
 *  EA Attestation Binding (identical to worker_attest.c)
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

/* ── SEV-SNP report generation ── */

static int get_sev_snp_report(const unsigned char report_data[REPORT_DATA_SIZE],
                              unsigned char **out_report, int *out_len)
{
    FILE *f = fopen(SNP_REPORT_DATA_FILE, "wb");
    if (!f) return -1;
    if (fwrite(report_data, 1, REPORT_DATA_SIZE, f) != REPORT_DATA_SIZE) {
        fclose(f); return -1;
    }
    fclose(f);

    char cmd[512];
    snprintf(cmd, sizeof cmd,
             "snpguest report %s %s > snpguest_report.log 2>&1",
             SNP_REPORT_OUTPUT_FILE, SNP_REPORT_DATA_FILE);
    int status = system(cmd);
    if (status != 0) return -1;

    FILE *rf = fopen(SNP_REPORT_OUTPUT_FILE, "rb");
    if (!rf) return -1;
    if (fseek(rf, 0, SEEK_END) != 0) { fclose(rf); return -1; }
    long sz = ftell(rf);
    if (sz <= 0) { fclose(rf); return -1; }
    rewind(rf);

    *out_len = (int)sz;
    *out_report = (unsigned char *)malloc((size_t)*out_len);
    if (!*out_report) { fclose(rf); return -1; }
    size_t rd = fread(*out_report, 1, (size_t)*out_len, rf);
    fclose(rf);
    if ((int)rd != *out_len) {
        free(*out_report); *out_report = NULL; *out_len = 0;
        return -1;
    }
    return 0;
}

/* ──────────────────────────────────────────────────────────────────────
 *  AEAD secure send / recv — SMALL messages (control, ≤ 256 B)
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
    mpi_send(buf, total, MPI_UNSIGNED_CHAR, dest, tag, comm, ctx);
}

static int secure_recv(MPI_Comm comm,
                       void *plaintext, int plain_len,
                       int src, int tag, const char *ctx)
{
    if (plain_len < 0 || plain_len > SECURE_MAX_PLAIN) {
        fprintf(stderr, "[WORKER] secure_recv: plain_len %d out of range\n", plain_len);
        return -1;
    }
    unsigned char buf[NPUB + SECURE_MAX_PLAIN + ABYTES];
    int total = NPUB + plain_len + (int)ABYTES;
    MPI_Status st;
    mpi_recv(buf, total, MPI_UNSIGNED_CHAR, src, tag, comm, &st, ctx);

    uint64_t received_ctr = 0;
    memcpy(&received_ctr, buf, sizeof(uint64_t));
    if (received_ctr < recv_nonce_ctr) {
        fprintf(stderr, "[WORKER] REPLAY detected (nonce %" PRIu64
                        " < %" PRIu64 ") [%s]\n",
                received_ctr, recv_nonce_ctr, ctx);
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
    if ((int)mlen != plain_len) return -1;
    recv_nonce_ctr = received_ctr + 1;
    return 0;
}

/* ──────────────────────────────────────────────────────────────────────
 *  AEAD bulk send / recv — LARGE messages (matrix data)
 * ────────────────────────────────────────────────────────────────────── */

static void send_matrix(MPI_Comm comm,
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
        fprintf(stderr, "[WORKER] malloc(%zu) failed in send_matrix\n", total);
        MPI_Abort(MPI_COMM_WORLD, 1);
    }

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

    mpi_send(buf, (int)total, MPI_UNSIGNED_CHAR, dest, tag, comm, ctx);
    free(buf);
}

static int recv_matrix(MPI_Comm comm,
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
        fprintf(stderr, "[WORKER] malloc(%zu) failed in recv_matrix\n", total);
        return -1;
    }

    MPI_Status st;
    mpi_recv(buf, (int)total, MPI_UNSIGNED_CHAR, src, tag, comm, &st, ctx);

    uint64_t received_ctr = 0;
    memcpy(&received_ctr, buf, sizeof(uint64_t));
    if (received_ctr < recv_nonce_ctr) {
        fprintf(stderr, "[WORKER] REPLAY detected in recv_matrix [%s]\n", ctx);
        free(buf);
        return -1;
    }

    unsigned long long mlen = 0;
    if (crypto_aead_chacha20poly1305_ietf_decrypt(
            (unsigned char *)data, &mlen, NULL,
            buf + NPUB, (unsigned long long)(data_bytes + ABYTES),
            NULL, 0, buf, g_session_key) != 0) {
        fprintf(stderr, "[WORKER] AEAD decryption FAILED in recv_matrix [%s]\n", ctx);
        free(buf);
        return -1;
    }

    recv_nonce_ctr = received_ctr + 1;
    free(buf);
    return 0;
}

/* ──────────────────────────────────────────────────────────────────────
 *  Matrix multiplication: C[m×n] = A[m×k] × B[k×n]
 *  ikj loop order for cache-friendly access on B and C.
 * ────────────────────────────────────────────────────────────────────── */

static void matmul(const double *A, const double *B, double *C,
                   int m, int k, int n)
{
    memset(C, 0, (size_t)m * n * sizeof(double));
    for (int i = 0; i < m; i++)
        for (int p = 0; p < k; p++) {
            double a_ip = A[i * k + p];
            for (int j = 0; j < n; j++)
                C[i * n + j] += a_ip * B[p * n + j];
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

    if (argc < 2) {
        fprintf(stderr, "usage: %s <PORT_STRING>\n", argv[0]);
        MPI_Abort(MPI_COMM_WORLD, 1);
    }
    char *PORT = argv[1];

    if (sodium_init() < 0) {
        fprintf(stderr, "[WORKER] sodium_init failed\n");
        MPI_Abort(MPI_COMM_WORLD, 1);
    }

    /* ── Connect to master ── */
    MPI_Comm inter = MPI_COMM_NULL;
    int rc = MPI_Comm_connect(PORT, MPI_INFO_NULL, 0, MPI_COMM_SELF, &inter);
    if (rc != MPI_SUCCESS) die_mpi("MPI_Comm_connect failed", rc);
    MPI_Barrier(inter);

    /* ════════════════════════════════════════════════════════════════
     *  EA ATTESTATION HANDSHAKE (identical to worker_attest.c)
     * ════════════════════════════════════════════════════════════════ */

    /* Receive EA request */
    struct ea_request ea_req;
    mpi_recv(&ea_req, sizeof(ea_req), MPI_UNSIGNED_CHAR, 0,
             TAG_EA_REQUEST, inter, MPI_STATUS_IGNORE, "Recv(EA_REQUEST)");
    printf("[WORKER] received EA AuthenticatorRequest (offer=%u)\n",
           ea_req.attestation_offer);

    /* Generate ECDH keypair */
    unsigned char client_pk[crypto_kx_PUBLICKEYBYTES];
    unsigned char client_sk[crypto_kx_SECRETKEYBYTES];
    crypto_kx_keypair(client_pk, client_sk);

    /* Compute binding */
    uint8_t exported_value[HASH_LEN];
    uint8_t aik_hash[HASH_LEN];
    uint8_t binding[BINDING_LEN];
    ea_compute_binding(ea_req.context, client_pk, crypto_kx_PUBLICKEYBYTES,
                       exported_value, aik_hash, binding);

    /* Derive REPORT_DATA */
    uint8_t report_data[REPORT_DATA_SIZE];
    ea_derive_report_data(binding, report_data);

    /* Fetch SNP evidence */
    unsigned char *evidence = NULL;
    int evidence_len = 0;
#ifndef SKIP_ATTESTATION
    if (ea_req.attestation_offer) {
        if (get_sev_snp_report(report_data, &evidence, &evidence_len) != 0) {
            fprintf(stderr, "[WORKER] get_sev_snp_report failed\n");
            MPI_Abort(MPI_COMM_WORLD, 1);
        }
        printf("[WORKER] fetched SNP evidence: %d bytes\n", evidence_len);
    }
#endif

    /* Build and send EA Authenticator */
    struct ea_auth_hdr auth_hdr;
    memset(&auth_hdr, 0, sizeof(auth_hdr));
    memcpy(auth_hdr.client_pk, client_pk, crypto_kx_PUBLICKEYBYTES);
    auth_hdr.payload_hdr.version = EA_PAYLOAD_VERSION;
    strncpy(auth_hdr.payload_hdr.media_type, EA_MEDIA_TYPE,
            sizeof(auth_hdr.payload_hdr.media_type) - 1);
    auth_hdr.payload_hdr.evidence_len = (uint32_t)evidence_len;
    memcpy(auth_hdr.payload_hdr.binder.aik_pub_hash, aik_hash, HASH_LEN);
    memcpy(auth_hdr.payload_hdr.binder.binding, binding, BINDING_LEN);
    strncpy(auth_hdr.payload_hdr.binder.exporter_label, EA_EXPORTER_LABEL,
            sizeof(auth_hdr.payload_hdr.binder.exporter_label) - 1);

    uint8_t finished[HASH_LEN];
    ea_compute_finished(ea_req.context, client_pk, crypto_kx_PUBLICKEYBYTES,
                        &auth_hdr.payload_hdr,
                        evidence, (uint32_t)evidence_len, finished);

    mpi_send(&auth_hdr, sizeof(auth_hdr), MPI_UNSIGNED_CHAR, 0,
             TAG_EA_AUTH_HDR, inter, "Send(EA_AUTH_HDR)");
    if (evidence_len > 0)
        mpi_send(evidence, evidence_len, MPI_UNSIGNED_CHAR, 0,
                 TAG_EA_EVIDENCE_DATA, inter, "Send(EA_EVIDENCE_DATA)");
    mpi_send(finished, HASH_LEN, MPI_UNSIGNED_CHAR, 0,
             TAG_EA_FINISHED, inter, "Send(EA_FINISHED)");
    free(evidence);

    printf("[WORKER] sent EA Authenticator (%d B evidence)\n", evidence_len);

    /* Receive EA result */
    int attest_ok = 0;
    mpi_recv(&attest_ok, 1, MPI_INT, 0,
             TAG_EA_RESULT, inter, MPI_STATUS_IGNORE, "Recv(EA_RESULT)");
    if (!attest_ok) {
        fprintf(stderr, "[WORKER] EA attestation rejected\n");
        sodium_memzero(client_sk, sizeof client_sk);
        MPI_Comm_disconnect(&inter);
        MPI_Finalize();
        return 0;
    }
    printf("[WORKER] EA attestation ACCEPTED\n");

    /* ECDH key exchange */
    unsigned char server_pk[crypto_kx_PUBLICKEYBYTES];
    mpi_recv(server_pk, crypto_kx_PUBLICKEYBYTES, MPI_UNSIGNED_CHAR, 0,
             TAG_KX_SERVER_PK, inter, MPI_STATUS_IGNORE, "Recv(KX_SERVER_PK)");

    unsigned char rx[KEYB], tx[KEYB], app_key[KEYB];
    if (crypto_kx_client_session_keys(rx, tx, client_pk, client_sk, server_pk) != 0) {
        fprintf(stderr, "[WORKER] crypto_kx failed\n");
        MPI_Abort(MPI_COMM_WORLD, 1);
    }

    crypto_generichash_state hst;
    crypto_generichash_init(&hst, NULL, 0, KEYB);
    crypto_generichash_update(&hst, rx, KEYB);
    const char *label = "app_key";
    crypto_generichash_update(&hst, (const unsigned char *)label, strlen(label));
    crypto_generichash_final(&hst, app_key, KEYB);
    memcpy(g_session_key, app_key, KEYB);

    sodium_memzero(client_sk, sizeof client_sk);
    sodium_memzero(rx, sizeof rx);
    sodium_memzero(tx, sizeof tx);
    sodium_memzero(app_key, sizeof app_key);
    sodium_memzero(exported_value, sizeof exported_value);
    sodium_memzero(binding, sizeof binding);

    printf("[WORKER] session key derived, entering benchmark loop\n");

    /* ════════════════════════════════════════════════════════════════
     *  BENCHMARK LOOP
     * ════════════════════════════════════════════════════════════════ */

    while (1)
    {
        /* Receive benchmark command */
        struct bench_cmd cmd;
        if (secure_recv(inter, &cmd, sizeof(cmd), 0, TAG_BENCH_CMD,
                        "Recv(BENCH_CMD)") != 0) {
            fprintf(stderr, "[WORKER] failed to decrypt bench_cmd\n");
            break;
        }

        if (cmd.cmd == CMD_BENCH_DONE) {
            printf("[WORKER] received BENCH_DONE, exiting\n");
            break;
        }

        if (cmd.cmd != CMD_BENCH_SIZE) {
            fprintf(stderr, "[WORKER] unknown bench_cmd %d\n", cmd.cmd);
            break;
        }

        int M         = cmd.matrix_size;
        int row_count = cmd.row_count;
        int enc       = cmd.encrypt_data;
        int runs      = cmd.num_runs;

        printf("[WORKER] benchmark: M=%d rows=%d encrypt=%d runs=%d\n",
               M, row_count, enc, runs);

        /* Allocate buffers */
        int a_elems = row_count * M;
        int b_elems = M * M;
        int c_elems = row_count * M;

        double *A_block = (double *)malloc((size_t)a_elems * sizeof(double));
        double *B       = (double *)malloc((size_t)b_elems * sizeof(double));
        double *C_block = (double *)malloc((size_t)c_elems * sizeof(double));

        if (!A_block || !B || !C_block) {
            fprintf(stderr, "[WORKER] malloc failed for M=%d\n", M);
            MPI_Abort(MPI_COMM_WORLD, 1);
        }

        for (int run = 1; run <= runs; run++)
        {
            /* Receive A_block */
            if (recv_matrix(inter, A_block, a_elems, 0, TAG_BENCH_A, enc,
                            "Recv(A_block)") != 0) {
                fprintf(stderr, "[WORKER] recv A_block FAILED run %d\n", run);
                MPI_Abort(MPI_COMM_WORLD, 1);
            }

            /* Receive B */
            if (recv_matrix(inter, B, b_elems, 0, TAG_BENCH_B, enc,
                            "Recv(B)") != 0) {
                fprintf(stderr, "[WORKER] recv B FAILED run %d\n", run);
                MPI_Abort(MPI_COMM_WORLD, 1);
            }

            /* Compute C_block = A_block × B (timed) */
            double t0 = MPI_Wtime();
            matmul(A_block, B, C_block, row_count, M, M);
            double t_compute_ms = (MPI_Wtime() - t0) * 1000.0;

            /* Send C_block back */
            send_matrix(inter, C_block, c_elems, 0, TAG_BENCH_C, enc,
                        "Send(C_block)");

            /* Send compute time (always encrypted) */
            secure_send(inter, &t_compute_ms, sizeof(double), 0, TAG_BENCH_TIME,
                        "Send(compute_time)");

            printf("[WORKER] M=%d run %d/%d: compute=%.1f ms\n",
                   M, run, runs, t_compute_ms);
        }

        free(A_block);
        free(B);
        free(C_block);
    }

    /* ── Cleanup ── */
    sodium_memzero(g_session_key, sizeof g_session_key);
    MPI_Comm_disconnect(&inter);
    MPI_Finalize();
    return 0;
}
