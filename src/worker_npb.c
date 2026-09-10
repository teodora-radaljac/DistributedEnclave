/*
 * worker_npb.c – NPB-kernel worker for MPI + SEV-SNP star topology.
 *
 * Connects to master_npb, performs EA/aTLS attestation + ECDH key exchange,
 * then executes compute and communication workloads upon command.
 *
 * Workloads:
 *   EP  — Box-Muller Gaussian deviate generation + annular bin counting.
 *   CG  — Sparse Matrix-Vector multiplication kernel (y = A*x).
 *   STREAM — memory-bandwidth triad over three worker-local arrays.
 *   RANDOM — dependent random pointer chasing over worker-local memory.
 *   VMAP — protected full-block vector input, compute, and output.
 *   TASKQ — dynamically self-scheduled authenticated tasks.
 *
 * Compile (production):
 *   mpicc -O2 -Wall -Wextra -o worker_npb worker_npb.c npb_timeout.c bench_rendezvous.c -lsodium -lm
 *
 * Compile (skip real SNP):
 *   mpicc -DSKIP_ATTESTATION -O2 -Wall -Wextra -o worker_npb worker_npb.c npb_timeout.c bench_rendezvous.c -lsodium -lm
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
#include <math.h>
#include <time.h>
#include <sys/wait.h>
#include <unistd.h>

/* ── MPI message tags: EA attestation ── */
enum {
    TAG_EA_REQUEST       = 70,
    TAG_EA_AUTH_HDR      = 71,
    TAG_EA_EVIDENCE_DATA = 72,
    TAG_EA_RESULT        = 74,
    TAG_KX_SERVER_AUTH   = 91,
    TAG_KX_CLIENT_FINISH = 92,
    TAG_KX_SERVER_FINISH = 93
};

/* ── MPI message tags: NPB data plane ── */
enum {
    TAG_NPB_CMD      = 130,
    TAG_NPB_EP_RESULT= 131,
    TAG_NPB_CG_X     = 132,
    TAG_NPB_CG_Y     = 133,
    TAG_NPB_CG_MATRIX= 134,
    TAG_NPB_TIME     = 135,
    TAG_STREAM_READY = 136,
    TAG_STREAM_RUN   = 137,
    TAG_STREAM_RESULT= 138,
    TAG_RANDOM_READY = 139,
    TAG_RANDOM_RUN   = 140,
    TAG_RANDOM_RESULT= 141,
    TAG_VMAP_READY   = 142,
    TAG_VMAP_INPUT   = 143,
    TAG_VMAP_OUTPUT  = 144,
    TAG_VMAP_RESULT  = 145,
    TAG_TASKQ_READY  = 146,
    TAG_TASKQ_CONTROL= 147,
    TAG_TASKQ_TASK   = 148,
    TAG_TASKQ_INPUT  = 149,
    TAG_TASKQ_RESULT = 150,
    TAG_TASKQ_OUTPUT = 151
};

/* ── NPB workload types ── */
#define WORKLOAD_EP   1
#define WORKLOAD_CG   2
#define WORKLOAD_STREAM 3
#define WORKLOAD_RANDOM 4
#define WORKLOAD_VMAP   5
#define WORKLOAD_TASKQ  6

/* ── NPB command codes ── */
#define CMD_NPB_START  1
#define CMD_NPB_ITER   2
#define CMD_NPB_DONE   3

#define TASKQ_CONTROL_START 1
#define TASKQ_TASK_WORK     1
#define TASKQ_TASK_END      2

/* ── Crypto constants ── */
#define KEYB   crypto_aead_chacha20poly1305_ietf_KEYBYTES
#define NPUB   crypto_aead_chacha20poly1305_ietf_NPUBBYTES
#define ABYTES crypto_aead_chacha20poly1305_ietf_ABYTES

#define HASH_LEN         32
#define REPORT_DATA_SIZE 64
#define BINDING_LEN      REPORT_DATA_SIZE
#define MAX_REPORT_LEN   16384

#define SECURE_MAX_PLAIN 256

#define MIB_BYTES          (1024ULL * 1024ULL)
#define STREAM_MIN_MIB     1U
#define STREAM_MAX_MIB     128U
#define RANDOM_MIN_MIB     32U
#define RANDOM_MAX_MIB     256U
#define VMAP_MIN_MIB       1U
#define VMAP_MAX_MIB       128U
#define TASKQ_MIN_BYTES    1U
#define TASKQ_MAX_BYTES    1048576U

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

/* ── EA / CMW Attestation types ── */

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
    uint32_t stream_array_mib;
    uint32_t stream_warmup;
    uint32_t random_mib;
    uint32_t reserved0;
    uint64_t random_accesses;
    uint64_t random_warmup_accesses;
    uint32_t vmap_mib;
    uint32_t task_bytes;
    uint64_t task_count;
    uint64_t task_iters;
};

_Static_assert(sizeof(struct npb_cmd) <= SECURE_MAX_PLAIN,
               "npb_cmd must fit in an authenticated small message");

/* ── EP result struct ── */
#define EP_BINS 10
struct ep_result {
    int64_t counts[EP_BINS];
    double  sx;
    double  sy;
};

struct workload_ready {
    int32_t workload;
    int32_t ok;
    uint64_t element_count;
};

struct run_trigger {
    int32_t run;
    int32_t reserved;
};

struct stream_result {
    int32_t run;
    int32_t verified;
    double compute_ms;
    double checksum;
};

struct random_result {
    int32_t run;
    int32_t verified;
    uint32_t final_token;
    uint32_t reserved;
    double compute_ms;
};

struct vmap_result {
    int32_t run;
    int32_t verified;
    double compute_ms;
    double checksum;
};

struct taskq_control {
    int32_t command;
    int32_t run;
};

struct taskq_task {
    int32_t command;
    int32_t run;
    uint64_t task_id;
    uint64_t iterations;
    uint32_t payload_bytes;
    uint32_t reserved;
};

struct taskq_result {
    int32_t run;
    int32_t verified;
    uint64_t task_id;
    uint64_t token;
    uint32_t payload_bytes;
    uint32_t reserved;
    double compute_ms;
};

_Static_assert(sizeof(struct workload_ready) <= SECURE_MAX_PLAIN,
               "workload_ready must fit in an authenticated small message");
_Static_assert(sizeof(struct run_trigger) <= SECURE_MAX_PLAIN,
               "run_trigger must fit in an authenticated small message");
_Static_assert(sizeof(struct stream_result) <= SECURE_MAX_PLAIN,
               "stream_result must fit in an authenticated small message");
_Static_assert(sizeof(struct random_result) <= SECURE_MAX_PLAIN,
               "random_result must fit in an authenticated small message");
_Static_assert(sizeof(struct vmap_result) <= SECURE_MAX_PLAIN,
               "vmap_result must fit in an authenticated small message");
_Static_assert(sizeof(struct taskq_control) <= SECURE_MAX_PLAIN,
               "taskq_control must fit in an authenticated small message");
_Static_assert(sizeof(struct taskq_task) <= SECURE_MAX_PLAIN,
               "taskq_task must fit in an authenticated small message");
_Static_assert(sizeof(struct taskq_result) <= SECURE_MAX_PLAIN,
               "taskq_result must fit in an authenticated small message");

/* ── Session state ── */
/* Directional keys: g_session_key = worker->master (send, tx),
 * g_recv_key = master->worker (recv, rx). */
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
    char es[MPI_MAX_ERROR_STRING]; int n = 0;
    MPI_Error_string(rc, es, &n);
    fprintf(stderr, "[WORKER] FATAL: %s rc=%d (%s)\n", msg, rc, es);
    fflush(stderr);
    MPI_Abort(MPI_COMM_WORLD, 1);
    exit(1);
}

static void mpi_send_f(const void *buf, int count, MPI_Datatype dt,
                       int dest, int tag, MPI_Comm comm, const char *ctx)
{
    npb_wait_begin(NPB_WAIT_IO);
    int rc = MPI_Send(buf, count, dt, dest, tag, comm);
    if (rc != MPI_SUCCESS) die_mpi(ctx, rc);
    npb_wait_end();
}

static void mpi_recv_f(void *buf, int count, MPI_Datatype dt,
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

/* ── Generate SNP attestation report ── */

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
    mpi_send_f(buf, total, MPI_UNSIGNED_CHAR, dest, tag, comm, ctx);
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
    mpi_recv_f(buf, total, MPI_UNSIGNED_CHAR, src, tag, comm, &st, ctx);

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

static void workload_send_small(MPI_Comm comm, const void *data, int data_bytes,
                                int dest, int tag, int encrypt, const char *ctx)
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
    mpi_send_f(data, data_bytes, MPI_UNSIGNED_CHAR, dest, tag, comm, ctx);
}

static int workload_recv_small(MPI_Comm comm, void *data, int data_bytes,
                               int src, int tag, int encrypt, const char *ctx)
{
    if (encrypt)
        return secure_recv(comm, data, data_bytes, src, tag, ctx);
    if (data_bytes < 0 || data_bytes > SECURE_MAX_PLAIN) {
        fprintf(stderr, "[WORKER] workload_recv_small: data_bytes %d out of range\n",
                data_bytes);
        return -1;
    }

    MPI_Status status;
    mpi_recv_f(data, data_bytes, MPI_UNSIGNED_CHAR, src, tag, comm, &status, ctx);
    int received_count = 0;
    MPI_Get_count(&status, MPI_UNSIGNED_CHAR, &received_count);
    if (received_count != data_bytes) {
        fprintf(stderr, "[WORKER] invalid plaintext workload length [%s]\n", ctx);
        return -1;
    }
    return 0;
}

/* ── AEAD bulk send / recv — LARGE messages ── */

static void send_bulk(MPI_Comm comm,
                      const void *data, size_t data_bytes,
                      int dest, int tag, int encrypt, const char *ctx)
{
    if (data_bytes > (size_t)INT_MAX) {
        fprintf(stderr, "[WORKER] bulk message is too large [%s]\n", ctx);
        MPI_Abort(MPI_COMM_WORLD, 1);
    }
    if (!encrypt) {
        mpi_send_f(data, (int)data_bytes, MPI_UNSIGNED_CHAR, dest, tag, comm, ctx);
        return;
    }
    if (data_bytes > (size_t)INT_MAX - NPUB - ABYTES) {
        fprintf(stderr, "[WORKER] bulk message is too large [%s]\n", ctx);
        MPI_Abort(MPI_COMM_WORLD, 1);
    }
    if (send_nonce_ctr == UINT64_MAX) {
        fprintf(stderr, "[WORKER] AEAD nonce space exhausted [%s]\n", ctx);
        MPI_Abort(MPI_COMM_WORLD, 1);
    }
    size_t total_bytes = NPUB + data_bytes + ABYTES;
    unsigned char *buf = (unsigned char *)malloc(total_bytes);
    if (!buf) {
        fprintf(stderr, "[WORKER] malloc(%zu) failed in send_bulk\n", total_bytes);
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
        fprintf(stderr, "[WORKER] bulk AEAD encryption failed [%s]\n", ctx);
        free(buf);
        MPI_Abort(MPI_COMM_WORLD, 1);
    }
    memcpy(buf, nonce, NPUB);
    mpi_send_f(buf, (int)total_bytes, MPI_UNSIGNED_CHAR, dest, tag, comm, ctx);
    send_nonce_ctr = counter + 1;
    free(buf);
}

static int recv_bulk(MPI_Comm comm,
                     void *data, size_t data_bytes,
                     int src, int tag, int encrypt, const char *ctx)
{
    if (data_bytes > (size_t)INT_MAX) {
        fprintf(stderr, "[WORKER] bulk message is too large [%s]\n", ctx);
        return -1;
    }
    if (!encrypt) {
        MPI_Status st;
        mpi_recv_f(data, (int)data_bytes, MPI_UNSIGNED_CHAR, src, tag, comm, &st, ctx);
        int received_count = 0;
        MPI_Get_count(&st, MPI_UNSIGNED_CHAR, &received_count);
        return received_count == (int)data_bytes ? 0 : -1;
    }
    if (data_bytes > (size_t)INT_MAX - NPUB - ABYTES) {
        fprintf(stderr, "[WORKER] bulk message is too large [%s]\n", ctx);
        return -1;
    }
    size_t total_bytes = NPUB + data_bytes + ABYTES;
    unsigned char *buf = (unsigned char *)malloc(total_bytes);
    if (!buf) {
        fprintf(stderr, "[WORKER] malloc(%zu) failed in recv_bulk\n", total_bytes);
        return -1;
    }

    MPI_Status st;
    mpi_recv_f(buf, (int)total_bytes, MPI_UNSIGNED_CHAR, src, tag, comm, &st, ctx);

    int received_count = 0;
    MPI_Get_count(&st, MPI_UNSIGNED_CHAR, &received_count);
    if (received_count != (int)total_bytes) {
        fprintf(stderr, "[WORKER] invalid bulk ciphertext length [%s]\n", ctx);
        free(buf);
        return -1;
    }

    uint64_t received_ctr = 0;
    if (parse_nonce(buf, &received_ctr) != 0 || received_ctr != recv_nonce_ctr) {
        fprintf(stderr, "[WORKER] invalid bulk AEAD sequence [%s]\n", ctx);
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
        fprintf(stderr, "[WORKER] AEAD decryption FAILED in recv_bulk [%s]\n", ctx);
        free(buf);
        return -1;
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

#define NPB_MODULUS (UINT64_C(1) << 46)
#define NPB_MASK    (NPB_MODULUS - UINT64_C(1))
#define NPB_R46     ((double)NPB_MODULUS)
#define NPB_A       UINT64_C(1220703125)   /* 5^13 */
#define NPB_TWO_PI 6.283185307179586

static inline double npb_rand(uint64_t *state)
{
    *state = (NPB_A * *state) & NPB_MASK;
    return (double)(*state) / NPB_R46;
}

static void ep_compute(int64_t num_pairs, int64_t seed_val,
                       struct ep_result *result)
{
    memset(result, 0, sizeof(*result));
    uint64_t state = seed_val > 0 ? (uint64_t)seed_val & NPB_MASK : 0;
    if (state == 0) state = UINT64_C(271828183);

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

static const char *workload_name(int workload)
{
    switch (workload) {
    case WORKLOAD_EP: return "EP";
    case WORKLOAD_CG: return "CG";
    case WORKLOAD_STREAM: return "STREAM";
    case WORKLOAD_RANDOM: return "RANDOM";
    case WORKLOAD_VMAP: return "VMAP";
    case WORKLOAD_TASKQ: return "TASKQ";
    default: return "UNKNOWN";
    }
}

static int checked_mib_bytes(uint32_t mib, size_t *bytes)
{
    if ((uint64_t)mib > (uint64_t)SIZE_MAX / MIB_BYTES) return -1;
    *bytes = (size_t)((uint64_t)mib * MIB_BYTES);
    return 0;
}

static uint64_t xorshift64_step(uint64_t value)
{
    value ^= value << 13;
    value ^= value >> 7;
    value ^= value << 17;
    return value;
}

static double vmap_transform(double value)
{
    return value * 1.25 + 0.5;
}

static uint64_t task_initial_token(uint64_t task_id, int run)
{
    uint64_t token = UINT64_C(0x9e3779b97f4a7c15) ^
                     (task_id * UINT64_C(0xbf58476d1ce4e5b9)) ^
                     ((uint64_t)(uint32_t)run << 32);
    return token ? token : UINT64_C(0xd1b54a32d192ed03);
}

static uint8_t task_input_byte(uint64_t task_id, int run, size_t index)
{
    uint64_t value = task_id * UINT64_C(131) +
                     (uint64_t)(uint32_t)run * UINT64_C(17) +
                     (uint64_t)index;
    return (uint8_t)value;
}

static uint8_t task_output_byte(uint8_t input, uint64_t token,
                                uint64_t task_id, size_t index)
{
    unsigned shift = (unsigned)(index & 7U) * 8U;
    uint8_t mask = (uint8_t)(token >> shift);
    uint8_t lane = (uint8_t)((uint64_t)index * UINT64_C(29) + task_id);
    return (uint8_t)(input ^ mask ^ lane);
}

static void send_workload_ready(MPI_Comm inter, int workload, int ok,
                                uint64_t element_count, int tag)
{
    struct workload_ready ready = {
        .workload = workload,
        .ok = ok,
        .element_count = element_count
    };
    secure_send(inter, &ready, sizeof ready, 0, tag, "Send(WORKLOAD_READY)");
}

static int run_stream_workload(MPI_Comm inter, const struct npb_cmd *cmd)
{
    size_t array_bytes = 0;
    if (cmd->stream_array_mib < STREAM_MIN_MIB ||
        cmd->stream_array_mib > STREAM_MAX_MIB ||
        checked_mib_bytes(cmd->stream_array_mib, &array_bytes) != 0 ||
        array_bytes % sizeof(double) != 0) {
        send_workload_ready(inter, WORKLOAD_STREAM, 0, 0, TAG_STREAM_READY);
        return -1;
    }

    size_t element_count = array_bytes / sizeof(double);
    double *a = (double *)malloc(array_bytes);
    double *b = (double *)malloc(array_bytes);
    double *c = (double *)malloc(array_bytes);
    if (!a || !b || !c) {
        free(a); free(b); free(c);
        send_workload_ready(inter, WORKLOAD_STREAM, 0, 0, TAG_STREAM_READY);
        return -1;
    }

    for (size_t i = 0; i < element_count; i++) {
        a[i] = 0.0;
        b[i] = 1.0;
        c[i] = 2.0;
    }
    const double scalar = 3.0;
    for (uint32_t pass = 0; pass < cmd->stream_warmup; pass++)
        for (size_t i = 0; i < element_count; i++)
            a[i] = b[i] + scalar * c[i];

    send_workload_ready(inter, WORKLOAD_STREAM, 1,
                        (uint64_t)element_count, TAG_STREAM_READY);

    int status = 0;
    for (int run = 1; run <= cmd->num_runs; run++) {
        struct run_trigger trigger;
        if (workload_recv_small(inter, &trigger, sizeof trigger, 0,
                    TAG_STREAM_RUN, cmd->encrypt_data,
                    "Recv(STREAM_RUN)") != 0 ||
            trigger.run != run) {
            status = -1;
            break;
        }

        double started = MPI_Wtime();
        for (size_t i = 0; i < element_count; i++)
            a[i] = b[i] + scalar * c[i];
        double compute_ms = (MPI_Wtime() - started) * 1000.0;

        double checksum = 0.0;
        for (size_t i = 0; i < element_count; i++) checksum += a[i];
        double expected = 7.0 * (double)element_count;
        struct stream_result result = {
            .run = run,
            .verified = isfinite(checksum) && checksum == expected,
            .compute_ms = compute_ms,
            .checksum = checksum
        };
        workload_send_small(inter, &result, sizeof result, 0,
                            TAG_STREAM_RESULT, cmd->encrypt_data,
                            "Send(STREAM_RESULT)");
    }

    free(a); free(b); free(c);
    return status;
}

static int run_random_workload(MPI_Comm inter, const struct npb_cmd *cmd)
{
    size_t link_bytes = 0;
    if (cmd->random_mib < RANDOM_MIN_MIB ||
        cmd->random_mib > RANDOM_MAX_MIB ||
        cmd->random_accesses == 0 ||
        checked_mib_bytes(cmd->random_mib, &link_bytes) != 0 ||
        link_bytes % sizeof(uint32_t) != 0) {
        send_workload_ready(inter, WORKLOAD_RANDOM, 0, 0, TAG_RANDOM_READY);
        return -1;
    }

    size_t element_count = link_bytes / sizeof(uint32_t);
    if (element_count == 0 || element_count > UINT32_MAX) {
        send_workload_ready(inter, WORKLOAD_RANDOM, 0, 0, TAG_RANDOM_READY);
        return -1;
    }

    uint32_t *links = (uint32_t *)malloc(link_bytes);
    uint32_t *order = (uint32_t *)malloc(link_bytes);
    if (!links || !order) {
        free(links); free(order);
        send_workload_ready(inter, WORKLOAD_RANDOM, 0, 0, TAG_RANDOM_READY);
        return -1;
    }

    for (size_t i = 0; i < element_count; i++) order[i] = (uint32_t)i;
    uint64_t rng = UINT64_C(0x4d595df4d0f33173);
    for (size_t i = element_count - 1; i > 0; i--) {
        rng = xorshift64_step(rng);
        size_t other = (size_t)(rng % (uint64_t)(i + 1));
        uint32_t temp = order[i];
        order[i] = order[other];
        order[other] = temp;
    }

    size_t zero_position = 0;
    for (size_t i = 0; i < element_count; i++) {
        size_t next = i + 1 == element_count ? 0 : i + 1;
        links[order[i]] = order[next];
        if (order[i] == 0) zero_position = i;
    }

    uint32_t warm_token = 0;
    for (uint64_t access = 0; access < cmd->random_warmup_accesses; access++)
        warm_token = links[warm_token];
    size_t warm_position =
        (zero_position + (size_t)(cmd->random_warmup_accesses % element_count)) %
        element_count;
    uint32_t expected_warm_token = order[warm_position];
    size_t final_position =
        (warm_position + (size_t)(cmd->random_accesses % element_count)) %
        element_count;
    uint32_t expected_final_token = order[final_position];
    free(order);

    if (warm_token != expected_warm_token) {
        free(links);
        send_workload_ready(inter, WORKLOAD_RANDOM, 0, 0, TAG_RANDOM_READY);
        return -1;
    }
    send_workload_ready(inter, WORKLOAD_RANDOM, 1,
                        (uint64_t)element_count, TAG_RANDOM_READY);

    int status = 0;
    for (int run = 1; run <= cmd->num_runs; run++) {
        struct run_trigger trigger;
        if (workload_recv_small(inter, &trigger, sizeof trigger, 0,
                    TAG_RANDOM_RUN, cmd->encrypt_data,
                    "Recv(RANDOM_RUN)") != 0 ||
            trigger.run != run) {
            status = -1;
            break;
        }

        uint32_t token = warm_token;
        double started = MPI_Wtime();
        for (uint64_t access = 0; access < cmd->random_accesses; access++)
            token = links[token];
        double compute_ms = (MPI_Wtime() - started) * 1000.0;

        struct random_result result = {
            .run = run,
            .verified = token == expected_final_token,
            .final_token = token,
            .reserved = 0,
            .compute_ms = compute_ms
        };
        workload_send_small(inter, &result, sizeof result, 0,
                            TAG_RANDOM_RESULT, cmd->encrypt_data,
                            "Send(RANDOM_RESULT)");
    }

    free(links);
    return status;
}

static int run_vmap_workload(MPI_Comm inter, const struct npb_cmd *cmd)
{
    size_t block_bytes = 0;
    if (cmd->vmap_mib < VMAP_MIN_MIB || cmd->vmap_mib > VMAP_MAX_MIB ||
        checked_mib_bytes(cmd->vmap_mib, &block_bytes) != 0 ||
        block_bytes % sizeof(double) != 0) {
        send_workload_ready(inter, WORKLOAD_VMAP, 0, 0, TAG_VMAP_READY);
        return -1;
    }

    size_t element_count = block_bytes / sizeof(double);
    double *input = (double *)malloc(block_bytes);
    double *output = (double *)malloc(block_bytes);
    if (!input || !output) {
        free(input); free(output);
        send_workload_ready(inter, WORKLOAD_VMAP, 0, 0, TAG_VMAP_READY);
        return -1;
    }
    memset(input, 0, block_bytes);
    memset(output, 0, block_bytes);
    send_workload_ready(inter, WORKLOAD_VMAP, 1,
                        (uint64_t)element_count, TAG_VMAP_READY);

    int status = 0;
    for (int run = 1; run <= cmd->num_runs; run++) {
        if (recv_bulk(inter, input, block_bytes, 0, TAG_VMAP_INPUT,
                      cmd->encrypt_data, "Recv(VMAP_INPUT)") != 0) {
            status = -1;
            break;
        }

        double started = MPI_Wtime();
        for (size_t i = 0; i < element_count; i++)
            output[i] = vmap_transform(input[i]);
        double compute_ms = (MPI_Wtime() - started) * 1000.0;

        double checksum = 0.0;
        for (size_t i = 0; i < element_count; i++) checksum += output[i];
        size_t samples[3] = {0, element_count / 2, element_count - 1};
        int verified = isfinite(checksum);
        for (size_t sample = 0; sample < 3; sample++) {
            size_t index = samples[sample];
            if (output[index] != vmap_transform(input[index])) verified = 0;
        }

        send_bulk(inter, output, block_bytes, 0, TAG_VMAP_OUTPUT,
                  cmd->encrypt_data, "Send(VMAP_OUTPUT)");
        struct vmap_result result = {
            .run = run,
            .verified = verified,
            .compute_ms = compute_ms,
            .checksum = checksum
        };
        workload_send_small(inter, &result, sizeof result, 0, TAG_VMAP_RESULT,
                            cmd->encrypt_data, "Send(VMAP_RESULT)");
    }

    free(input); free(output);
    return status;
}

static int run_taskq_workload(MPI_Comm inter, const struct npb_cmd *cmd)
{
    if (cmd->task_bytes < TASKQ_MIN_BYTES ||
        cmd->task_bytes > TASKQ_MAX_BYTES || cmd->task_count == 0 ||
        cmd->task_iters == 0) {
        send_workload_ready(inter, WORKLOAD_TASKQ, 0, 0, TAG_TASKQ_READY);
        return -1;
    }

    size_t payload_bytes = cmd->task_bytes;
    uint8_t *input = (uint8_t *)malloc(payload_bytes);
    uint8_t *output = (uint8_t *)malloc(payload_bytes);
    if (!input || !output) {
        free(input); free(output);
        send_workload_ready(inter, WORKLOAD_TASKQ, 0, 0, TAG_TASKQ_READY);
        return -1;
    }
    memset(input, 0, payload_bytes);
    memset(output, 0, payload_bytes);
    send_workload_ready(inter, WORKLOAD_TASKQ, 1,
                        (uint64_t)payload_bytes, TAG_TASKQ_READY);

    int status = 0;
    for (int run = 1; run <= cmd->num_runs && status == 0; run++) {
        struct taskq_control control;
        if (workload_recv_small(inter, &control, sizeof control, 0,
                                TAG_TASKQ_CONTROL, cmd->encrypt_data,
                                "Recv(TASKQ_CONTROL)") != 0 ||
            control.command != TASKQ_CONTROL_START || control.run != run) {
            status = -1;
            break;
        }

        while (1) {
            struct taskq_task task;
            if (workload_recv_small(inter, &task, sizeof task, 0,
                                    TAG_TASKQ_TASK, cmd->encrypt_data,
                                    "Recv(TASKQ_TASK)") != 0) {
                status = -1;
                break;
            }
            if (task.command == TASKQ_TASK_END) {
                if (task.run != run) status = -1;
                break;
            }
            if (task.command != TASKQ_TASK_WORK || task.run != run ||
                task.task_id >= cmd->task_count ||
                task.payload_bytes != cmd->task_bytes ||
                task.iterations != cmd->task_iters) {
                status = -1;
                break;
            }
            if (recv_bulk(inter, input, payload_bytes, 0, TAG_TASKQ_INPUT,
                          cmd->encrypt_data, "Recv(TASKQ_INPUT)") != 0) {
                status = -1;
                break;
            }

            size_t samples[3] = {0, payload_bytes / 2, payload_bytes - 1};
            int verified = 1;
            for (size_t sample = 0; sample < 3; sample++) {
                size_t index = samples[sample];
                if (input[index] != task_input_byte(task.task_id, run, index))
                    verified = 0;
            }

            uint64_t token = task_initial_token(task.task_id, run);
            double started = MPI_Wtime();
            for (uint64_t iteration = 0; iteration < task.iterations; iteration++)
                token = xorshift64_step(token);
            for (size_t i = 0; i < payload_bytes; i++)
                output[i] = task_output_byte(input[i], token, task.task_id, i);
            double compute_ms = (MPI_Wtime() - started) * 1000.0;

            for (size_t sample = 0; sample < 3; sample++) {
                size_t index = samples[sample];
                uint8_t expected = task_output_byte(
                    task_input_byte(task.task_id, run, index), token,
                    task.task_id, index);
                if (output[index] != expected) verified = 0;
            }

            struct taskq_result result = {
                .run = run,
                .verified = verified,
                .task_id = task.task_id,
                .token = token,
                .payload_bytes = task.payload_bytes,
                .reserved = 0,
                .compute_ms = compute_ms
            };
            workload_send_small(inter, &result, sizeof result, 0,
                                TAG_TASKQ_RESULT, cmd->encrypt_data,
                                "Send(TASKQ_RESULT)");
            send_bulk(inter, output, payload_bytes, 0, TAG_TASKQ_OUTPUT,
                      cmd->encrypt_data, "Send(TASKQ_OUTPUT)");
        }
    }

    free(input); free(output);
    return status;
}

/* ══════════════════════════════════════════════════════════════════════
 *  main()
 * ══════════════════════════════════════════════════════════════════════ */

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    npb_mpi_init(&argc, &argv);
    if (sodium_init() < 0) { fprintf(stderr, "sodium_init failed\n"); MPI_Abort(MPI_COMM_WORLD, 1); }

    unsigned char owner_sign_pk[crypto_sign_PUBLICKEYBYTES];
    if (load_public_key(owner_sign_pk, sizeof owner_sign_pk) != 0) {
        MPI_Abort(MPI_COMM_WORLD, 1);
    }

    /* ── Discover the central endpoint ── */
    npb_wait_begin(NPB_WAIT_ENROLLMENT);
    if (argc != 1) {
        fprintf(stderr, "usage: %s\n", argv[0]);
        die_mpi("unexpected worker arguments", MPI_ERR_ARG);
    }

    MPI_Comm inter = MPI_COMM_NULL;
    int rc = bench_connect_worker(&inter);
    if (rc != MPI_SUCCESS) die_mpi("central-node rendezvous", rc);
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

    /* Compute the report-data binding. */
    uint8_t aik_hash[HASH_LEN], binding[BINDING_LEN];
    ea_compute_binding(ea_req.context, client_pk, crypto_kx_PUBLICKEYBYTES,
                       aik_hash, binding);

    /* Generate SNP attestation evidence */
    unsigned char *evidence = NULL;
    int evidence_len = 0;
#ifndef SKIP_ATTESTATION
    if (ea_req.attestation_offer) {
        if (get_sev_snp_report(binding, &evidence, &evidence_len) != 0) {
            fprintf(stderr, "[WORKER] get_sev_snp_report failed\n");
            MPI_Abort(MPI_COMM_WORLD, 1);
        }
    }
#endif

    unsigned char evidence_hash[HASH_LEN];
    hash_evidence(evidence, (size_t)evidence_len, evidence_hash);

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
                   TAG_EA_EVIDENCE_DATA, inter, "Send(EA_EVIDENCE_DATA)");
    free(evidence);

    /* Check attestation result */
    int attest_ok = 0;
    mpi_recv_f(&attest_ok, 1, MPI_INT, 0, TAG_EA_RESULT, inter,
               MPI_STATUS_IGNORE, "Recv(EA_RESULT)");
    if (!attest_ok) {
        fprintf(stderr, "[WORKER] Attestation REJECTED by master\n");
        sodium_memzero(client_sk, sizeof client_sk);
        sodium_memzero(owner_sign_pk, sizeof owner_sign_pk);
        npb_mpi_disconnect(&inter); npb_mpi_finalize(); return 1;
    }
    printf("[WORKER] Attestation accepted.\n");

    /* Owner-authenticated ECDH + transcript-bound key confirmation */
    struct kx_server_auth server_auth;
    mpi_recv_f(&server_auth, sizeof server_auth, MPI_UNSIGNED_CHAR, 0,
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
        sodium_memzero(owner_sign_pk, sizeof owner_sign_pk);
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
        sodium_memzero(owner_sign_pk, sizeof owner_sign_pk);
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
    mpi_send_f(client_finish, HASH_LEN, MPI_UNSIGNED_CHAR, 0,
               TAG_KX_CLIENT_FINISH, inter, "Send(KX_CLIENT_FINISH)");

    unsigned char server_finish[HASH_LEN];
    unsigned char expected_server_finish[HASH_LEN];
    mpi_recv_f(server_finish, HASH_LEN, MPI_UNSIGNED_CHAR, 0,
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
        sodium_memzero(owner_sign_pk, sizeof owner_sign_pk);
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

#ifndef SKIP_ATTESTATION
        if (cmd.cmd == CMD_NPB_START && !cmd.encrypt_data) {
            fprintf(stderr, "[WORKER] --no-encrypt is permitted only in the "
                            "explicit SKIP_ATTESTATION baseline build\n");
            break;
        }
#endif

        if (cmd.cmd == CMD_NPB_START && cmd.workload == WORKLOAD_EP)
        {
            /* ── EP Workload ── */
            printf("[WORKER] EP workload: %" PRId64 " pairs, %d runs\n",
                   cmd.ep_pairs, cmd.num_runs);

            for (int run = 1; run <= cmd.num_runs; run++)
            {
                /* Receive seed for this run */
                int64_t seed = 0;
                if (workload_recv_small(inter, &seed, sizeof(seed), 0,
                                        TAG_NPB_CMD, cmd.encrypt_data,
                                        "Recv(EP_seed)") != 0) {
                    fprintf(stderr, "[WORKER] EP seed recv failed\n"); break;
                }

                /* Compute */
                double t0 = MPI_Wtime();
                struct ep_result result;
                ep_compute(cmd.ep_pairs, seed, &result);
                double t_compute = (MPI_Wtime() - t0) * 1000.0;

                /* Send result + time */
                workload_send_small(inter, &result, sizeof(result), 0,
                                    TAG_NPB_EP_RESULT, cmd.encrypt_data,
                                    "Send(EP_RESULT)");
                workload_send_small(inter, &t_compute, sizeof(t_compute), 0,
                                    TAG_NPB_TIME, cmd.encrypt_data,
                                    "Send(EP_TIME)");
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
            int cg_failed = 0;
            int *row_ptr = NULL;
            int *col_idx = NULL;
            double *val = NULL;
            double *x = NULL;
            double *y = NULL;
            printf("[WORKER] CG workload: rows=%d, n=%d, iters=%d, runs=%d\n",
                   nrows, cg_n, cg_iters, cmd.num_runs);

            if (nrows < 0 || cg_n <= 0 || cg_iters <= 0 || cmd.num_runs <= 0 ||
                (size_t)nrows > SIZE_MAX / sizeof(double) ||
                (size_t)cg_n > SIZE_MAX / sizeof(double) ||
                (size_t)nrows + 1 > SIZE_MAX / sizeof(int)) {
                fprintf(stderr, "[WORKER] invalid CG dimensions\n");
                break;
            }

            /* Receive sparse matrix (CSR) */
            row_ptr = (int *)malloc(((size_t)nrows + 1) * sizeof(int));
            if (!row_ptr) {
                fprintf(stderr, "[WORKER] CG row_ptr allocation failed\n");
                break;
            }
            if (recv_bulk(inter, row_ptr, (size_t)(nrows + 1) * sizeof(int),
                          0, TAG_NPB_CG_MATRIX, enc, "Recv(CG_rowptr)") != 0) {
                cg_failed = 1;
                goto cg_done;
            }

            int nnz = row_ptr[nrows];
            if (nnz < 0 || (size_t)nnz > SIZE_MAX / sizeof(double)) {
                cg_failed = 1;
                goto cg_done;
            }
            col_idx = (int *)malloc(nnz > 0 ? (size_t)nnz * sizeof(int) : 1);
            val = (double *)malloc(nnz > 0 ? (size_t)nnz * sizeof(double) : 1);
            if (!col_idx || !val) {
                fprintf(stderr, "[WORKER] CG matrix allocation failed\n");
                cg_failed = 1;
                goto cg_done;
            }

            if (recv_bulk(inter, col_idx, (size_t)nnz * sizeof(int),
                          0, TAG_NPB_CG_MATRIX, enc, "Recv(CG_colidx)") != 0) {
                cg_failed = 1;
                goto cg_done;
            }
            if (recv_bulk(inter, val, (size_t)nnz * sizeof(double),
                          0, TAG_NPB_CG_MATRIX, enc, "Recv(CG_val)") != 0) {
                cg_failed = 1;
                goto cg_done;
            }

            /* Allocate working vectors */
            x = (double *)malloc((size_t)cg_n * sizeof(double));
            y = (double *)malloc(nrows > 0 ? (size_t)nrows * sizeof(double) : 1);
            if (!x || !y) {
                fprintf(stderr, "[WORKER] CG vector allocation failed\n");
                cg_failed = 1;
                goto cg_done;
            }

            for (int run = 1; run <= cmd.num_runs; run++)
            {
                for (int iter = 0; iter < cg_iters; iter++)
                {
                    /* Receive x vector */
                    if (recv_bulk(inter, x, (size_t)cg_n * sizeof(double),
                                  0, TAG_NPB_CG_X, enc, "Recv(CG_x)") != 0) {
                        cg_failed = 1;
                        goto cg_done;
                    }

                    /* Compute SpMV */
                    double t0 = MPI_Wtime();
                    spmv_kernel(nrows, row_ptr, col_idx, val, x, y);
                    double t_compute = (MPI_Wtime() - t0) * 1000.0;

                    /* Send partial y + time */
                    send_bulk(inter, y, (size_t)nrows * sizeof(double),
                              0, TAG_NPB_CG_Y, enc, "Send(CG_y)");
                    workload_send_small(inter, &t_compute, sizeof(t_compute),
                                        0, TAG_NPB_TIME, enc,
                                        "Send(CG_TIME)");
                }
            }
cg_done:
            free(row_ptr); free(col_idx); free(val);
            free(x); free(y);
            if (cg_failed) break;
            printf("[WORKER] CG workload complete.\n");
        }
        else if (cmd.cmd == CMD_NPB_START && cmd.workload == WORKLOAD_STREAM)
        {
            printf("[WORKER] %s workload: %u MiB/array, warmup=%u, runs=%d\n",
                   workload_name(cmd.workload), cmd.stream_array_mib,
                   cmd.stream_warmup, cmd.num_runs);
            if (run_stream_workload(inter, &cmd) != 0) break;
            printf("[WORKER] STREAM workload complete.\n");
        }
        else if (cmd.cmd == CMD_NPB_START && cmd.workload == WORKLOAD_RANDOM)
        {
            printf("[WORKER] %s workload: %u MiB, accesses=%" PRIu64
                   ", warmup=%" PRIu64 ", runs=%d\n",
                   workload_name(cmd.workload), cmd.random_mib,
                   cmd.random_accesses, cmd.random_warmup_accesses,
                   cmd.num_runs);
            if (run_random_workload(inter, &cmd) != 0) break;
            printf("[WORKER] RANDOM workload complete.\n");
        }
        else if (cmd.cmd == CMD_NPB_START && cmd.workload == WORKLOAD_VMAP)
        {
            printf("[WORKER] %s workload: %u MiB, runs=%d\n",
                   workload_name(cmd.workload), cmd.vmap_mib, cmd.num_runs);
            if (run_vmap_workload(inter, &cmd) != 0) break;
            printf("[WORKER] VMAP workload complete.\n");
        }
        else if (cmd.cmd == CMD_NPB_START && cmd.workload == WORKLOAD_TASKQ)
        {
            printf("[WORKER] %s workload: tasks=%" PRIu64
                   ", bytes=%u, iters=%" PRIu64 ", runs=%d\n",
                   workload_name(cmd.workload), cmd.task_count,
                   cmd.task_bytes, cmd.task_iters, cmd.num_runs);
            if (run_taskq_workload(inter, &cmd) != 0) break;
            printf("[WORKER] TASKQ workload complete.\n");
        }
        else {
            fprintf(stderr, "[WORKER] invalid workload command %d/%d\n",
                    cmd.cmd, cmd.workload);
            break;
        }
    }

    /* ═══════════════════════ CLEANUP ═══════════════════════ */
    sodium_memzero(g_session_key, KEYB);
    sodium_memzero(g_recv_key, KEYB);
    sodium_memzero(g_channel_binding, sizeof g_channel_binding);
    sodium_memzero(owner_sign_pk, sizeof owner_sign_pk);
    npb_mpi_disconnect(&inter);
    printf("[WORKER] Disconnected.\n");
    npb_mpi_finalize();
    return 0;
}
