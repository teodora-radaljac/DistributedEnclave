/*
 * worker_bench.c – Matrix-multiply benchmark worker for MPI + SEV-SNP star topology.
 *
 * Uses the same EA/aTLS attestation protocol as worker_attest.c, then
 * enters a benchmark loop: receive matrix data, compute C = A × B,
 * send results + timing back to master.
 *
 * Usage:
 *   ./worker_bench
 *
 * Compile (production):
 *   mpicc -O2 -Wall -Wextra -o worker_bench worker_bench.c dgemm_kernel.c npb_timeout.c bench_rendezvous.c -lsodium -lm
 *
 * Compile (skip real SNP — for testing on non-CVM hosts):
 *   mpicc -DSKIP_ATTESTATION -O2 -Wall -Wextra -o worker_bench worker_bench.c dgemm_kernel.c npb_timeout.c bench_rendezvous.c -lsodium -lm
 */

#include <mpi.h>
#include "npb_receive.h"
#include "npb_mpi_wait.h"
#include "bench_rendezvous.h"
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <stdint.h>
#include <inttypes.h>
#include <limits.h>
#include <string.h>
#include <time.h>
#include <sys/wait.h>
#include <unistd.h>

#include "dgemm_kernel.h"

/* ── MPI message tags: EA attestation protocol (must match master) ── */
enum {
    TAG_EA_REQUEST       = 70,
    TAG_EA_AUTH_HDR      = 71,
    TAG_EA_EVIDENCE_DATA = 72,
    TAG_EA_RESULT        = 74,
    TAG_KX_SERVER_AUTH   = 91,
    TAG_KX_CLIENT_FINISH = 92,
    TAG_KX_SERVER_FINISH = 93
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
#define MAX_BENCH_MATRIX_DIM 8192
#define MAX_BENCH_RUNS       1000

/* ── Crypto constants ── */
#define KEYB   crypto_aead_chacha20poly1305_ietf_KEYBYTES
#define NPUB   crypto_aead_chacha20poly1305_ietf_NPUBBYTES
#define ABYTES crypto_aead_chacha20poly1305_ietf_ABYTES

#define HASH_LEN         32
#define REPORT_DATA_SIZE 64
#define BINDING_LEN      REPORT_DATA_SIZE
#define MAX_REPORT_LEN   16384

#define SECURE_MAX_PLAIN 256

#ifndef PPDPC_OWNER_SIGN_PK_FILE
#define PPDPC_OWNER_SIGN_PK_FILE "/etc/ppdpc/owner_sign.pk"
#endif
#define KX_TRANSCRIPT_DOMAIN "PPDPC-OPENMPI-KX-V3"
#define SECURE_PROTOCOL_VERSION 2
#define DIRECTION_CENTRAL_TO_WORKER 1
#define DIRECTION_WORKER_TO_CENTRAL 2
#define SECURE_AAD_SIZE (HASH_LEN + 22)

_Static_assert(crypto_kx_SESSIONKEYBYTES == KEYB,
               "kx session key size must match AEAD key size");

/* ── EA / CMW Attestation types (must match master) ── */

#define EA_CONTEXT_LEN     32
#define EA_MEDIA_TYPE      "application/eat+cwt"
#define EA_EXPORTER_LABEL  "Attestation"
#define EA_PAYLOAD_VERSION 2

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

struct kx_server_auth {
    uint8_t server_pk[crypto_kx_PUBLICKEYBYTES];
    uint8_t signature[crypto_sign_BYTES];
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
/* Directional keys: g_session_key = worker->master (send, tx),
 * g_recv_key = master->worker (recv, rx). Distinct keys per direction
 * prevent AEAD nonce reuse. */
static unsigned char g_session_key[KEYB];
static unsigned char g_recv_key[KEYB];
static unsigned char g_channel_binding[HASH_LEN];
static uint64_t send_nonce_ctr = 0;
static uint64_t recv_nonce_ctr = 0;

/* ──────────────────────────────────────────────────────────────────────
 *  Utility helpers
 * ────────────────────────────────────────────────────────────────────── */

static void die_mpi(const char *msg, int rc)
{
    npb_wait_begin(NPB_WAIT_SHUTDOWN);
    char es[MPI_MAX_ERROR_STRING];
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
    npb_wait_begin(NPB_WAIT_IO);
    int rc = MPI_Send(buf, count, dt, dest, tag, comm);
    if (rc != MPI_SUCCESS) die_mpi(ctx, rc);
    npb_wait_end();
}

static void mpi_recv(void *buf, int count, MPI_Datatype dt,
                     int src, int tag, MPI_Comm comm, MPI_Status *st,
                     const char *ctx)
{
    npb_wait_begin(NPB_WAIT_IO);
    int rc = npb_recv_exact(buf, count, dt, src, tag, comm, st);
    if (rc != MPI_SUCCESS) die_mpi(ctx, rc);
    npb_wait_end();
}

static int load_public_key(unsigned char *key, size_t key_len)
{
    FILE *file = fopen(PPDPC_OWNER_SIGN_PK_FILE, "rb");
    if (!file) {
        fprintf(stderr, "[WORKER] cannot open pinned owner public key %s\n",
                PPDPC_OWNER_SIGN_PK_FILE);
        return -1;
    }
    size_t count = fread(key, 1, key_len, file);
    int trailing = fgetc(file);
    int failed = ferror(file);
    fclose(file);
    if (failed || count != key_len || trailing != EOF) {
        fprintf(stderr, "[WORKER] pinned owner public key %s must contain "
                "exactly %zu bytes\n",
            PPDPC_OWNER_SIGN_PK_FILE, key_len);
        return -1;
    }
    return 0;
}

static void hash_evidence(const unsigned char *evidence, size_t evidence_len,
                          unsigned char out[HASH_LEN])
{
    static const unsigned char empty = 0;
    const unsigned char *input = evidence_len > 0 ? evidence : &empty;
    crypto_generichash(out, HASH_LEN, input, evidence_len, NULL, 0);
}

static void compute_kx_transcript(
    const uint8_t context[EA_CONTEXT_LEN],
    const uint8_t client_pk[crypto_kx_PUBLICKEYBYTES],
    const uint8_t server_pk[crypto_kx_PUBLICKEYBYTES],
    const uint8_t binding[BINDING_LEN],
    const uint8_t evidence_hash[HASH_LEN],
    uint8_t transcript_hash[HASH_LEN])
{
    static const unsigned char domain[] = KX_TRANSCRIPT_DOMAIN;
    crypto_generichash_state state;
    crypto_generichash_init(&state, NULL, 0, HASH_LEN);
    crypto_generichash_update(&state, domain, sizeof domain - 1);
    crypto_generichash_update(&state, context, EA_CONTEXT_LEN);
    crypto_generichash_update(&state, client_pk, crypto_kx_PUBLICKEYBYTES);
    crypto_generichash_update(&state, server_pk, crypto_kx_PUBLICKEYBYTES);
    crypto_generichash_update(&state, binding, BINDING_LEN);
    crypto_generichash_update(&state, evidence_hash, HASH_LEN);
    crypto_generichash_final(&state, transcript_hash, HASH_LEN);
}

static void derive_bound_key(const uint8_t raw_key[KEYB],
                             const uint8_t transcript_hash[HASH_LEN],
                             const char *label,
                             uint8_t out[KEYB])
{
    static const unsigned char domain[] = "PPDPC-OPENMPI-KDF-V2";
    crypto_generichash_state state;
    crypto_generichash_init(&state, raw_key, KEYB, KEYB);
    crypto_generichash_update(&state, domain, sizeof domain - 1);
    crypto_generichash_update(&state, (const unsigned char *)label, strlen(label));
    crypto_generichash_update(&state, transcript_hash, HASH_LEN);
    crypto_generichash_final(&state, out, KEYB);
}

static void compute_key_confirmation(const uint8_t key[KEYB],
                                     const uint8_t transcript_hash[HASH_LEN],
                                     const char *role,
                                     uint8_t confirmation[HASH_LEN])
{
    static const unsigned char domain[] = "PPDPC-OPENMPI-FINISHED-V2";
    crypto_generichash_state state;
    crypto_generichash_init(&state, key, KEYB, HASH_LEN);
    crypto_generichash_update(&state, domain, sizeof domain - 1);
    crypto_generichash_update(&state, (const unsigned char *)role, strlen(role));
    crypto_generichash_update(&state, transcript_hash, HASH_LEN);
    crypto_generichash_final(&state, confirmation, HASH_LEN);
}

/* ──────────────────────────────────────────────────────────────────────
 *  EA Attestation Binding
 * ────────────────────────────────────────────────────────────────────── */

static void ea_aik_pub_hash(const uint8_t *pub_key, size_t pub_key_len,
                            uint8_t out[HASH_LEN])
{
    crypto_generichash(out, HASH_LEN, pub_key, pub_key_len, NULL, 0);
}

static void ea_binding_value(const uint8_t *pub_key, size_t pub_key_len,
                             const uint8_t context[EA_CONTEXT_LEN],
                             uint8_t out[BINDING_LEN])
{
    crypto_generichash_state st;
    crypto_generichash_init(&st, NULL, 0, BINDING_LEN);
    crypto_generichash_update(&st, pub_key, pub_key_len);
    crypto_generichash_update(&st, context, EA_CONTEXT_LEN);
    crypto_generichash_final(&st, out, BINDING_LEN);
}

static void ea_compute_binding(const uint8_t context[EA_CONTEXT_LEN],
                               const uint8_t *pub_key, size_t pub_key_len,
                               uint8_t aik_hash[HASH_LEN],
                               uint8_t binding[BINDING_LEN])
{
    ea_aik_pub_hash(pub_key, pub_key_len, aik_hash);
    ea_binding_value(pub_key, pub_key_len, context, binding);
}

/* ── SEV-SNP report generation ── */

static int run_process(char *const argv[])
{
    pid_t parent = getpid();
    pid_t child = fork();
    if (child < 0) {
        fprintf(stderr, "[WORKER] fork failed: %s\n", strerror(errno));
        return -1;
    }
    if (child == 0) {
        if (npb_bind_child_to_parent(parent) != 0) _exit(127);
        execvp(argv[0], argv);
        fprintf(stderr, "[WORKER] execvp(%s) failed: %s\n",
                argv[0], strerror(errno));
        _exit(127);
    }

    int status = 0;
    while (waitpid(child, &status, 0) < 0) {
        if (errno == EINTR) continue;
        fprintf(stderr, "[WORKER] waitpid failed: %s\n", strerror(errno));
        return -1;
    }
    if (!WIFEXITED(status)) return -1;
    return WEXITSTATUS(status);
}

static int get_sev_snp_report(const unsigned char report_data[REPORT_DATA_SIZE],
                              unsigned char **out_report, int *out_len)
{
    *out_report = NULL;
    *out_len = 0;

    char temp_dir[] = "/tmp/ppdpc-snp-report-XXXXXX";
    if (!mkdtemp(temp_dir)) {
        fprintf(stderr, "[WORKER] mkdtemp failed: %s\n", strerror(errno));
        return -1;
    }
    char data_path[sizeof temp_dir + 24];
    char report_path[sizeof temp_dir + 24];
    snprintf(data_path, sizeof data_path, "%s/report-data.bin", temp_dir);
    snprintf(report_path, sizeof report_path, "%s/report.bin", temp_dir);

    int result = -1;
    FILE *data_file = fopen(data_path, "wb");
    if (!data_file) goto cleanup;
    int write_ok = fwrite(report_data, 1, REPORT_DATA_SIZE, data_file) ==
                   REPORT_DATA_SIZE;
    int flush_result = fflush(data_file);
    int sync_result = fsync(fileno(data_file));
    int close_result = fclose(data_file);
    if (!write_ok || flush_result != 0 || sync_result != 0 || close_result != 0)
        goto cleanup;

    char *report_argv[] = {
        "snpguest", "report", report_path, data_path, NULL
    };
    if (run_process(report_argv) != 0) goto cleanup;

    FILE *rf = fopen(report_path, "rb");
    if (!rf) goto cleanup;
    if (fseek(rf, 0, SEEK_END) != 0) { fclose(rf); goto cleanup; }
    long sz = ftell(rf);
    if (sz <= 0 || sz > MAX_REPORT_LEN) { fclose(rf); goto cleanup; }
    rewind(rf);

    *out_len = (int)sz;
    *out_report = (unsigned char *)malloc((size_t)*out_len);
    if (!*out_report) { fclose(rf); *out_len = 0; goto cleanup; }
    size_t rd = fread(*out_report, 1, (size_t)*out_len, rf);
    fclose(rf);
    if ((int)rd != *out_len) {
        free(*out_report); *out_report = NULL; *out_len = 0;
        goto cleanup;
    }
    result = 0;

cleanup:
    unlink(data_path);
    unlink(report_path);
    rmdir(temp_dir);
    return result;
}

static void store_u32_be(unsigned char out[4], uint32_t value)
{
    out[0] = (unsigned char)(value >> 24);
    out[1] = (unsigned char)(value >> 16);
    out[2] = (unsigned char)(value >> 8);
    out[3] = (unsigned char)value;
}

static void store_u64_be_bytes(unsigned char out[8], uint64_t value)
{
    for (int i = 7; i >= 0; i--) {
        out[i] = (unsigned char)value;
        value >>= 8;
    }
}

static uint64_t load_u64_be_bytes(const unsigned char in[8])
{
    uint64_t value = 0;
    for (size_t i = 0; i < 8; i++)
        value = (value << 8) | in[i];
    return value;
}

static void make_nonce(unsigned char nonce[NPUB], uint64_t counter)
{
    memset(nonce, 0, NPUB);
    store_u64_be_bytes(nonce + NPUB - 8, counter);
}

static int parse_nonce(const unsigned char nonce[NPUB], uint64_t *counter)
{
    for (size_t i = 0; i < NPUB - 8; i++)
        if (nonce[i] != 0) return -1;
    *counter = load_u64_be_bytes(nonce + NPUB - 8);
    return 0;
}

static void build_aad(unsigned char aad[SECURE_AAD_SIZE],
                      unsigned char direction, int tag,
                      uint64_t plaintext_len, uint64_t counter)
{
    size_t offset = 0;
    memcpy(aad + offset, g_channel_binding, HASH_LEN);
    offset += HASH_LEN;
    aad[offset++] = SECURE_PROTOCOL_VERSION;
    aad[offset++] = direction;
    store_u32_be(aad + offset, (uint32_t)tag);
    offset += 4;
    store_u64_be_bytes(aad + offset, plaintext_len);
    offset += 8;
    store_u64_be_bytes(aad + offset, counter);
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
    if (send_nonce_ctr == UINT64_MAX) {
        fprintf(stderr, "[WORKER] AEAD nonce space exhausted [%s]\n", ctx);
        MPI_Abort(MPI_COMM_WORLD, 1);
    }
    uint64_t counter = send_nonce_ctr;
    unsigned char nonce[NPUB];
    unsigned char aad[SECURE_AAD_SIZE];
    make_nonce(nonce, counter);
    build_aad(aad, DIRECTION_WORKER_TO_CENTRAL,
              tag, (uint64_t)plain_len, counter);

    unsigned char buf[NPUB + SECURE_MAX_PLAIN + ABYTES];
    unsigned long long clen = 0;
    if (crypto_aead_chacha20poly1305_ietf_encrypt(
        buf + NPUB, &clen,
        (const unsigned char *)plaintext, (unsigned long long)plain_len,
        aad, sizeof aad, NULL, nonce, g_session_key) != 0 ||
        clen != (unsigned long long)plain_len + ABYTES) {
        fprintf(stderr, "[WORKER] AEAD encryption failed [%s]\n", ctx);
        MPI_Abort(MPI_COMM_WORLD, 1);
    }
    memcpy(buf, nonce, NPUB);
    int total = NPUB + plain_len + (int)ABYTES;
    mpi_send(buf, total, MPI_UNSIGNED_CHAR, dest, tag, comm, ctx);
    send_nonce_ctr = counter + 1;
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

    int received_count = 0;
    MPI_Get_count(&st, MPI_UNSIGNED_CHAR, &received_count);
    if (received_count != total) {
        fprintf(stderr, "[WORKER] invalid ciphertext length [%s]\n", ctx);
        return -1;
    }

    uint64_t received_ctr = 0;
    if (parse_nonce(buf, &received_ctr) != 0 || received_ctr != recv_nonce_ctr) {
        fprintf(stderr, "[WORKER] invalid AEAD sequence (received %" PRIu64
                        ", expected %" PRIu64 ") [%s]\n",
                received_ctr, recv_nonce_ctr, ctx);
        return -1;
    }
    unsigned char aad[SECURE_AAD_SIZE];
    build_aad(aad, DIRECTION_CENTRAL_TO_WORKER,
              tag, (uint64_t)plain_len, received_ctr);
    unsigned long long mlen = 0;
    if (crypto_aead_chacha20poly1305_ietf_decrypt(
            (unsigned char *)plaintext, &mlen, NULL,
            buf + NPUB, (unsigned long long)(plain_len + (int)ABYTES),
            aad, sizeof aad, buf, g_recv_key) != 0) {
        fprintf(stderr, "[WORKER] AEAD decryption FAILED [%s]\n", ctx);
        return -1;
    }
    if ((int)mlen != plain_len) return -1;
    recv_nonce_ctr = received_ctr + 1;
    return 0;
}

static void workload_send_small(MPI_Comm comm,
                                const void *data, int data_bytes,
                                int dest, int tag, int encrypt,
                                const char *ctx)
{
    if (encrypt) {
        secure_send(comm, data, data_bytes, dest, tag, ctx);
        return;
    }
    if (data_bytes < 0 || data_bytes > SECURE_MAX_PLAIN) {
        fprintf(stderr, "[WORKER] workload_send_small: data_bytes %d out of range\n",
                data_bytes);
        MPI_Abort(MPI_COMM_WORLD, 1);
    }
    mpi_send(data, data_bytes, MPI_UNSIGNED_CHAR, dest, tag, comm, ctx);
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

    if (num_doubles < 0 ||
        (size_t)num_doubles > ((size_t)INT_MAX - NPUB - ABYTES) / sizeof(double)) {
        fprintf(stderr, "[WORKER] matrix message is too large [%s]\n", ctx);
        MPI_Abort(MPI_COMM_WORLD, 1);
    }
    if (send_nonce_ctr == UINT64_MAX) {
        fprintf(stderr, "[WORKER] AEAD nonce space exhausted [%s]\n", ctx);
        MPI_Abort(MPI_COMM_WORLD, 1);
    }
    size_t data_bytes = (size_t)num_doubles * sizeof(double);
    size_t total = NPUB + data_bytes + ABYTES;
    unsigned char *buf = (unsigned char *)malloc(total);
    if (!buf) {
        fprintf(stderr, "[WORKER] malloc(%zu) failed in send_matrix\n", total);
        MPI_Abort(MPI_COMM_WORLD, 1);
    }

    uint64_t counter = send_nonce_ctr;
    unsigned char nonce[NPUB];
    unsigned char aad[SECURE_AAD_SIZE];
    make_nonce(nonce, counter);
    build_aad(aad, DIRECTION_WORKER_TO_CENTRAL,
              tag, (uint64_t)data_bytes, counter);

    unsigned long long clen = 0;
    if (crypto_aead_chacha20poly1305_ietf_encrypt(
        buf + NPUB, &clen,
        (const unsigned char *)data, (unsigned long long)data_bytes,
        aad, sizeof aad, NULL, nonce, g_session_key) != 0 ||
        clen != (unsigned long long)data_bytes + ABYTES) {
        fprintf(stderr, "[WORKER] matrix AEAD encryption failed [%s]\n", ctx);
        free(buf);
        MPI_Abort(MPI_COMM_WORLD, 1);
    }
    memcpy(buf, nonce, NPUB);

    mpi_send(buf, (int)total, MPI_UNSIGNED_CHAR, dest, tag, comm, ctx);
    send_nonce_ctr = counter + 1;
    free(buf);
}

static int recv_matrix(MPI_Comm comm,
                       double *data, int num_doubles,
                       int src, int tag, int encrypt, const char *ctx)
{
    if (num_doubles < 0) {
        fprintf(stderr, "[WORKER] negative matrix length [%s]\n", ctx);
        return -1;
    }
    if (!encrypt) {
        MPI_Status st;
        mpi_recv(data, num_doubles, MPI_DOUBLE, src, tag, comm, &st, ctx);
        int received_count = 0;
        MPI_Get_count(&st, MPI_DOUBLE, &received_count);
        if (received_count != num_doubles) {
            fprintf(stderr, "[WORKER] invalid plaintext matrix length [%s]\n", ctx);
            return -1;
        }
        return 0;
    }

    if ((size_t)num_doubles >
        ((size_t)INT_MAX - NPUB - ABYTES) / sizeof(double)) {
        fprintf(stderr, "[WORKER] matrix message is too large [%s]\n", ctx);
        return -1;
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

    int received_count = 0;
    MPI_Get_count(&st, MPI_UNSIGNED_CHAR, &received_count);
    if (received_count != (int)total) {
        fprintf(stderr, "[WORKER] invalid matrix ciphertext length [%s]\n", ctx);
        free(buf);
        return -1;
    }

    uint64_t received_ctr = 0;
    if (parse_nonce(buf, &received_ctr) != 0 || received_ctr != recv_nonce_ctr) {
        fprintf(stderr, "[WORKER] invalid matrix AEAD sequence [%s]\n", ctx);
        free(buf);
        return -1;
    }

    unsigned char aad[SECURE_AAD_SIZE];
    build_aad(aad, DIRECTION_CENTRAL_TO_WORKER,
              tag, (uint64_t)data_bytes, received_ctr);

    unsigned long long mlen = 0;
    if (crypto_aead_chacha20poly1305_ietf_decrypt(
            (unsigned char *)data, &mlen, NULL,
            buf + NPUB, (unsigned long long)(data_bytes + ABYTES),
            aad, sizeof aad, buf, g_recv_key) != 0 ||
        mlen != (unsigned long long)data_bytes) {
        fprintf(stderr, "[WORKER] AEAD decryption FAILED in recv_matrix [%s]\n", ctx);
        free(buf);
        return -1;
    }

    recv_nonce_ctr = received_ctr + 1;
    free(buf);
    return 0;
}

static double *allocate_matrix(size_t elements)
{
    if (elements > SIZE_MAX / sizeof(double)) return NULL;
    void *memory = NULL;
    if (posix_memalign(&memory, 2U * 1024U * 1024U,
                       elements * sizeof(double)) != 0)
        return NULL;
    return memory;
}

/* ══════════════════════════════════════════════════════════════════════
 *  main()
 * ══════════════════════════════════════════════════════════════════════ */

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    npb_mpi_init(&argc, &argv);

    if (argc != 1) {
        fprintf(stderr, "usage: %s\n", argv[0]);
        die_mpi("unexpected worker arguments", MPI_ERR_ARG);
    }

    if (sodium_init() < 0) {
        fprintf(stderr, "[WORKER] sodium_init failed\n");
        MPI_Abort(MPI_COMM_WORLD, 1);
    }

    unsigned char owner_sign_pk[crypto_sign_PUBLICKEYBYTES];
    if (load_public_key(owner_sign_pk, sizeof owner_sign_pk) != 0) {
        MPI_Abort(MPI_COMM_WORLD, 1);
    }

    /* ── Connect to master ── */
    npb_wait_begin(NPB_WAIT_ENROLLMENT);
    MPI_Comm inter = MPI_COMM_NULL;
    int rc = bench_connect_worker(&inter);
    if (rc != MPI_SUCCESS) die_mpi("central-node rendezvous", rc);

    /* ════════════════════════════════════════════════════════════════
    *  EA ATTESTATION HANDSHAKE
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
    uint8_t aik_hash[HASH_LEN];
    uint8_t binding[BINDING_LEN];
    ea_compute_binding(ea_req.context, client_pk, crypto_kx_PUBLICKEYBYTES,
                       aik_hash, binding);

    /* Fetch SNP evidence */
    unsigned char *evidence = NULL;
    int evidence_len = 0;
#ifndef SKIP_ATTESTATION
    if (ea_req.attestation_offer) {
        if (get_sev_snp_report(binding, &evidence, &evidence_len) != 0) {
            fprintf(stderr, "[WORKER] get_sev_snp_report failed\n");
            MPI_Abort(MPI_COMM_WORLD, 1);
        }
        printf("[WORKER] fetched SNP evidence: %d bytes\n", evidence_len);
    }
#endif

    unsigned char evidence_hash[HASH_LEN];
    hash_evidence(evidence, (size_t)evidence_len, evidence_hash);

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

    mpi_send(&auth_hdr, sizeof(auth_hdr), MPI_UNSIGNED_CHAR, 0,
             TAG_EA_AUTH_HDR, inter, "Send(EA_AUTH_HDR)");
    if (evidence_len > 0)
        mpi_send(evidence, evidence_len, MPI_UNSIGNED_CHAR, 0,
                 TAG_EA_EVIDENCE_DATA, inter, "Send(EA_EVIDENCE_DATA)");
    free(evidence);

    printf("[WORKER] sent EA Authenticator (%d B evidence)\n", evidence_len);

    /* Receive EA result */
    int attest_ok = 0;
    mpi_recv(&attest_ok, 1, MPI_INT, 0,
             TAG_EA_RESULT, inter, MPI_STATUS_IGNORE, "Recv(EA_RESULT)");
    if (!attest_ok) {
        fprintf(stderr, "[WORKER] EA attestation rejected\n");
        sodium_memzero(client_sk, sizeof client_sk);
        npb_mpi_disconnect(&inter);
        npb_mpi_finalize();
        return 1;
    }
    printf("[WORKER] EA attestation ACCEPTED\n");

    /* Owner-authenticated ECDH + transcript-bound key confirmation */
    struct kx_server_auth server_auth;
    mpi_recv(&server_auth, sizeof server_auth, MPI_UNSIGNED_CHAR, 0,
             TAG_KX_SERVER_AUTH, inter, MPI_STATUS_IGNORE,
             "Recv(KX_SERVER_AUTH)");

    unsigned char transcript_hash[HASH_LEN];
    compute_kx_transcript(ea_req.context, client_pk, server_auth.server_pk,
                          binding, evidence_hash, transcript_hash);
    if (crypto_sign_verify_detached(server_auth.signature,
                                    transcript_hash, HASH_LEN,
                                    owner_sign_pk) != 0) {
        fprintf(stderr, "[WORKER] central-node identity verification failed\n");
        sodium_memzero(client_sk, sizeof client_sk);
        npb_mpi_disconnect(&inter);
        npb_mpi_finalize();
        return 1;
    }

    unsigned char raw_rx[KEYB], raw_tx[KEYB];
    unsigned char traffic_rx[KEYB], traffic_tx[KEYB];
    unsigned char confirm_rx[KEYB], confirm_tx[KEYB];
    if (crypto_kx_client_session_keys(raw_rx, raw_tx,
                                      client_pk, client_sk,
                                      server_auth.server_pk) != 0) {
        fprintf(stderr, "[WORKER] crypto_kx failed\n");
        sodium_memzero(client_sk, sizeof client_sk);
        npb_mpi_disconnect(&inter);
        npb_mpi_finalize();
        return 1;
    }

    derive_bound_key(raw_rx, transcript_hash, "traffic:c2w", traffic_rx);
    derive_bound_key(raw_tx, transcript_hash, "traffic:w2c", traffic_tx);
    derive_bound_key(raw_rx, transcript_hash, "confirm:c2w", confirm_rx);
    derive_bound_key(raw_tx, transcript_hash, "confirm:w2c", confirm_tx);

    unsigned char client_finish[HASH_LEN];
    compute_key_confirmation(confirm_tx, transcript_hash, "worker",
                             client_finish);
    mpi_send(client_finish, HASH_LEN, MPI_UNSIGNED_CHAR, 0,
             TAG_KX_CLIENT_FINISH, inter, "Send(KX_CLIENT_FINISH)");

    unsigned char server_finish[HASH_LEN];
    unsigned char expected_server_finish[HASH_LEN];
    mpi_recv(server_finish, HASH_LEN, MPI_UNSIGNED_CHAR, 0,
             TAG_KX_SERVER_FINISH, inter, MPI_STATUS_IGNORE,
             "Recv(KX_SERVER_FINISH)");
    compute_key_confirmation(confirm_rx, transcript_hash, "central-node",
                             expected_server_finish);
    if (sodium_memcmp(server_finish, expected_server_finish, HASH_LEN) != 0) {
        fprintf(stderr, "[WORKER] central-node key confirmation failed\n");
        sodium_memzero(client_sk, sizeof client_sk);
        sodium_memzero(raw_rx, sizeof raw_rx);
        sodium_memzero(raw_tx, sizeof raw_tx);
        sodium_memzero(traffic_rx, sizeof traffic_rx);
        sodium_memzero(traffic_tx, sizeof traffic_tx);
        sodium_memzero(confirm_rx, sizeof confirm_rx);
        sodium_memzero(confirm_tx, sizeof confirm_tx);
        npb_mpi_disconnect(&inter);
        npb_mpi_finalize();
        return 1;
    }

    memcpy(g_session_key, traffic_tx, KEYB);
    memcpy(g_recv_key, traffic_rx, KEYB);
    memcpy(g_channel_binding, transcript_hash, HASH_LEN);

    sodium_memzero(client_sk, sizeof client_sk);
    sodium_memzero(raw_rx, sizeof raw_rx);
    sodium_memzero(raw_tx, sizeof raw_tx);
    sodium_memzero(traffic_rx, sizeof traffic_rx);
    sodium_memzero(traffic_tx, sizeof traffic_tx);
    sodium_memzero(confirm_rx, sizeof confirm_rx);
    sodium_memzero(confirm_tx, sizeof confirm_tx);
    sodium_memzero(binding, sizeof binding);
    npb_wait_end();

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

        if (M <= 0 || M > MAX_BENCH_MATRIX_DIM ||
            cmd.row_start < 0 || row_count <= 0 || row_count > M ||
            cmd.row_start > M - row_count ||
            (enc != 0 && enc != 1) ||
            runs <= 0 || runs > MAX_BENCH_RUNS) {
            fprintf(stderr, "[WORKER] invalid benchmark command\n");
            break;
        }

        size_t a_elems_size = (size_t)row_count * (size_t)M;
        size_t b_elems_size = (size_t)M * (size_t)M;
        if (a_elems_size > (size_t)INT_MAX ||
            b_elems_size > (size_t)INT_MAX) {
            fprintf(stderr, "[WORKER] benchmark buffers exceed MPI count limit\n");
            break;
        }

        printf("[WORKER] benchmark: M=%d rows=%d encrypt=%d runs=%d\n",
               M, row_count, enc, runs);

        /* Allocate buffers */
        int a_elems = (int)a_elems_size;
        int b_elems = (int)b_elems_size;
        int c_elems = (int)a_elems_size;

        double *A_block = allocate_matrix((size_t)a_elems);
        double *B       = allocate_matrix((size_t)b_elems);
        double *C_block = allocate_matrix((size_t)c_elems);

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
            ppdpc_dgemm(A_block, B, C_block, row_count, M, M);
            double t_compute_ms = (MPI_Wtime() - t0) * 1000.0;

            /* Send C_block back */
            send_matrix(inter, C_block, c_elems, 0, TAG_BENCH_C, enc,
                        "Send(C_block)");

            workload_send_small(inter, &t_compute_ms, sizeof(double), 0,
                                TAG_BENCH_TIME, enc, "Send(compute_time)");

            printf("[WORKER] M=%d run %d/%d: compute=%.1f ms\n",
                   M, run, runs, t_compute_ms);
        }

        free(A_block);
        free(B);
        free(C_block);
    }

    /* ── Cleanup ── */
    sodium_memzero(g_session_key, sizeof g_session_key);
    sodium_memzero(g_recv_key, sizeof g_recv_key);
    sodium_memzero(g_channel_binding, sizeof g_channel_binding);
    npb_mpi_disconnect(&inter);
    npb_mpi_finalize();
    return 0;
}
