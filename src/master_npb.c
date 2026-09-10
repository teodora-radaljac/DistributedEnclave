/*
 * master_npb.c – NPB-kernel benchmark for MPI + SEV-SNP star topology.
 *
 * Uses the same EA/aTLS attestation protocol as master_attest.c, then
 * distributes compute and communication workloads through the encrypted
 * star-topology framework.
 *
 * Workloads:
 *   EP  — Embarrassingly Parallel: Gaussian random deviate generation
 *          and bin counting. Minimal communication, pure compute.
 *   CG  — Conjugate Gradient (SpMV kernel): Sparse matrix-vector
 *          multiply with iterative communication. Tests frequent
 *          small message exchange overhead.
 *   STREAM — memory-bandwidth triad over three worker-local arrays.
 *   RANDOM — dependent random pointer chasing over worker-local memory.
 *   VMAP — protected full-block vector input, compute, and output.
 *   TASKQ — dynamically self-scheduled authenticated tasks.
 *
 * Usage:
 *   ./master_npb --master <N> --workload ep  [--ep-n <2^M pairs>] [--runs R]
 *   ./master_npb --master <N> --workload cg  [--cg-n <rows>] [--cg-iters <I>] [--runs R]
 *   ./master_npb --master <N> --workload stream [--stream-array-mib N]
 *                [--stream-warmup W] [--runs R]
 *   ./master_npb --master <N> --workload random [--random-mib N]
 *                [--random-accesses K] [--random-warmup-accesses K] [--runs R]
 *   ./master_npb --master <N> --workload vmap [--vmap-mib N] [--runs R]
 *   ./master_npb --master <N> --workload taskq [--task-count TOTAL]
 *                [--task-bytes B] [--task-iters I] [--runs R]
 *                [--no-encrypt] [--output FILE]
 *
 * Compile (production):
 *   mpicc -O2 -Wall -Wextra -o master_npb master_npb.c npb_timeout.c bench_rendezvous.c -lsodium -lm
 *
 * Compile (skip real SNP):
 *   mpicc -DSKIP_ATTESTATION -O2 -Wall -Wextra -o master_npb master_npb.c npb_timeout.c bench_rendezvous.c -lsodium -lm
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
#include <sys/stat.h>
#include <unistd.h>

#ifndef PPDPC_BUILD_ID
#define PPDPC_BUILD_ID "unversioned"
#endif

#define ARTIFACT_ID_ENV "PPDPC_ARTIFACT_ID"
#define PLACEMENT_ID_ENV "PPDPC_PLACEMENT_ID"

/* ── MPI message tags: EA attestation protocol ── */
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
    TAG_NPB_CMD      = 130,   /* npb_cmd struct */
    TAG_NPB_EP_RESULT= 131,   /* EP bin counts + sums */
    TAG_NPB_CG_X     = 132,   /* CG: vector x */
    TAG_NPB_CG_Y     = 133,   /* CG: partial result y */
    TAG_NPB_CG_MATRIX= 134,   /* CG: sparse matrix data */
    TAG_NPB_TIME     = 135,   /* worker compute time */
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
#define MAX_WORKERS  128
#define KEYB   crypto_aead_chacha20poly1305_ietf_KEYBYTES
#define NPUB   crypto_aead_chacha20poly1305_ietf_NPUBBYTES
#define ABYTES crypto_aead_chacha20poly1305_ietf_ABYTES

#define HASH_LEN         32
#define REPORT_DATA_SIZE 64
#define BINDING_LEN      REPORT_DATA_SIZE
#define MAX_REPORT_LEN   16384

/* AMD SEV-SNP attestation report ABI offsets (specification 56860). */
#define SNP_POLICY_OFFSET       0x08
#define SNP_MEASUREMENT_OFFSET  0x90
#define SNP_MEASUREMENT_SIZE    48
#define SNP_REPORTED_TCB_OFFSET 0x180
#define SNP_REPORTED_TCB_SIZE   8
#define SNP_CHIP_ID_OFFSET      0x1A0
#define SNP_CHIP_ID_SIZE        64

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

#define OWNER_SIGN_SK_ENV "PPDPC_OWNER_SIGN_SK_FILE"
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
    /* STREAM-specific */
    uint32_t stream_array_mib;
    uint32_t stream_warmup;
    /* Random pointer-chase-specific */
    uint32_t random_mib;
    uint32_t reserved0;
    uint64_t random_accesses;
    uint64_t random_warmup_accesses;
    /* Vector-map-specific */
    uint32_t vmap_mib;
    uint32_t task_bytes;
    /* Dynamic-task-queue-specific */
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
    npb_wait_begin(NPB_WAIT_SHUTDOWN);
    char es[MPI_MAX_ERROR_STRING]; int n = 0;
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

static int hex_nibble(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int parse_hex_exact(const char *text, unsigned char *out, size_t out_len)
{
    if (!text || !out) return -1;
    if (text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) text += 2;
    if (strlen(text) != out_len * 2) return -1;

    for (size_t i = 0; i < out_len; i++) {
        int high = hex_nibble(text[2 * i]);
        int low = hex_nibble(text[2 * i + 1]);
        if (high < 0 || low < 0) return -1;
        out[i] = (unsigned char)((high << 4) | low);
    }
    return 0;
}

static uint64_t load_u64_le(const unsigned char bytes[8])
{
    uint64_t value = 0;
    for (size_t i = 0; i < 8; i++)
        value |= ((uint64_t)bytes[i]) << (8 * i);
    return value;
}

static uint64_t load_u64_be(const unsigned char bytes[8])
{
    uint64_t value = 0;
    for (size_t i = 0; i < 8; i++)
        value = (value << 8) | bytes[i];
    return value;
}

static int verify_expected_snp_claims(const unsigned char *report, int report_len)
{
    const char *measurement_hex = getenv("SNP_EXPECTED_MEASUREMENT");
    const char *policy_hex = getenv("SNP_EXPECTED_POLICY");
    unsigned char expected_measurement[SNP_MEASUREMENT_SIZE];
    unsigned char expected_policy_bytes[8];

    if (!measurement_hex || !*measurement_hex || !policy_hex || !*policy_hex) {
        fprintf(stderr, "[MASTER] SNP_EXPECTED_MEASUREMENT and "
                        "SNP_EXPECTED_POLICY are required\n");
        return -1;
    }
    if (parse_hex_exact(measurement_hex, expected_measurement,
                        sizeof expected_measurement) != 0) {
        fprintf(stderr, "[MASTER] SNP_EXPECTED_MEASUREMENT must contain "
                        "%zu hexadecimal bytes\n",
                sizeof expected_measurement);
        return -1;
    }
    if (parse_hex_exact(policy_hex, expected_policy_bytes,
                        sizeof expected_policy_bytes) != 0) {
        fprintf(stderr, "[MASTER] SNP_EXPECTED_POLICY must contain exactly "
                        "8 hexadecimal bytes\n");
        return -1;
    }
    if (!report || report_len < SNP_MEASUREMENT_OFFSET + SNP_MEASUREMENT_SIZE) {
        fprintf(stderr, "[MASTER] SNP report is too short for policy/measurement\n");
        return -1;
    }

    uint64_t actual_policy = load_u64_le(report + SNP_POLICY_OFFSET);
    uint64_t expected_policy = load_u64_be(expected_policy_bytes);
    if (actual_policy != expected_policy) {
        fprintf(stderr, "[MASTER] SNP guest policy mismatch "
                        "(actual=0x%016" PRIx64 ", expected=0x%016" PRIx64 ")\n",
                actual_policy, expected_policy);
        return -1;
    }
    if (sodium_memcmp(report + SNP_MEASUREMENT_OFFSET,
                      expected_measurement, sizeof expected_measurement) != 0) {
        fprintf(stderr, "[MASTER] SNP launch measurement mismatch\n");
        return -1;
    }
    return 0;
}

static int load_secret_key(const char *env_name, unsigned char *key, size_t key_len)
{
    const char *path = getenv(env_name);
    struct stat st;
    if (!path || !*path) {
        fprintf(stderr, "[MASTER] %s is required\n", env_name);
        return -1;
    }
    if (stat(path, &st) != 0 || !S_ISREG(st.st_mode)) {
        fprintf(stderr, "[MASTER] cannot stat signing-key file %s\n", path);
        return -1;
    }
    if ((st.st_mode & (S_IRWXG | S_IRWXO)) != 0) {
        fprintf(stderr, "[MASTER] signing-key file %s must have mode 0600\n", path);
        return -1;
    }

    FILE *file = fopen(path, "rb");
    if (!file) {
        fprintf(stderr, "[MASTER] cannot open signing-key file %s\n", path);
        return -1;
    }
    size_t count = fread(key, 1, key_len, file);
    int trailing = fgetc(file);
    int failed = ferror(file);
    fclose(file);
    if (failed || count != key_len || trailing != EOF) {
        sodium_memzero(key, key_len);
        fprintf(stderr, "[MASTER] signing-key file %s must contain exactly %zu bytes\n",
                path, key_len);
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

static int mpi_iprobe_f(int src, int tag, MPI_Comm comm, MPI_Status *st,
                        const char *ctx)
{
    int flag = 0;
    int rc = MPI_Iprobe(src, tag, comm, &flag, st);
    if (rc != MPI_SUCCESS) die_mpi(ctx, rc);
    return flag;
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

static int ea_verify_payload(const struct ea_payload_hdr *hdr,
                             const uint8_t context[EA_CONTEXT_LEN],
                             const uint8_t *pub_key, size_t pub_key_len)
{
    if (hdr->version != EA_PAYLOAD_VERSION) return -1;
    if (strncmp(hdr->media_type, EA_MEDIA_TYPE, sizeof(hdr->media_type)) != 0) return -1;
    if (strncmp(hdr->binder.exporter_label, EA_EXPORTER_LABEL,
                sizeof(hdr->binder.exporter_label)) != 0) return -1;

    uint8_t expected_aik[HASH_LEN], expected_binding[BINDING_LEN];
    ea_compute_binding(context, pub_key, pub_key_len,
                       expected_aik, expected_binding);
    if (sodium_memcmp(expected_aik, hdr->binder.aik_pub_hash, HASH_LEN) != 0) return -1;
    if (sodium_memcmp(expected_binding, hdr->binder.binding, BINDING_LEN) != 0) return -1;
    return 0;
}

/* ── SEV-SNP evidence verification ── */

static int run_process(char *const argv[])
{
    pid_t parent = getpid();
    pid_t child = fork();
    if (child < 0) {
        fprintf(stderr, "[MASTER] fork failed: %s\n", strerror(errno));
        return -1;
    }
    if (child == 0) {
        if (npb_bind_child_to_parent(parent) != 0) _exit(127);
        execvp(argv[0], argv);
        fprintf(stderr, "[MASTER] execvp(%s) failed: %s\n",
                argv[0], strerror(errno));
        _exit(127);
    }

    int status = 0;
    while (waitpid(child, &status, 0) < 0) {
        if (errno == EINTR) continue;
        fprintf(stderr, "[MASTER] waitpid failed: %s\n", strerror(errno));
        return -1;
    }
    if (!WIFEXITED(status)) return -1;
    return WEXITSTATUS(status);
}

static int verify_snp_with_certs(const char *certs_dir,
                                 const char *report_path,
                                 const char *report_data_arg)
{
    char *cert_argv[] = {
        "snpguest", "verify", "certs", (char *)certs_dir, NULL
    };
    if (run_process(cert_argv) != 0) return -1;

    char *verify_argv[] = {
        "snpguest", "verify", "attestation",
        (char *)certs_dir, (char *)report_path,
        "--report-data", (char *)report_data_arg, NULL
    };
    return run_process(verify_argv) == 0 ? 0 : -1;
}

static int join_path(char *output, size_t output_size,
                     const char *directory, const char *name)
{
    int written = snprintf(output, output_size, "%s/%s", directory, name);
    return written < 0 || (size_t)written >= output_size ? -1 : 0;
}

static int verify_sev_snp_report(const unsigned char *report, int report_len,
                                 const unsigned char expected_report_data[REPORT_DATA_SIZE])
{
    if (!report || report_len <= 0) return -1;
    if (verify_expected_snp_claims(report, report_len) != 0) return -1;

    char temp_dir[] = "/tmp/ppdpc-snp-verify-XXXXXX";
    if (!mkdtemp(temp_dir)) {
        fprintf(stderr, "[MASTER] mkdtemp failed: %s\n", strerror(errno));
        return -1;
    }
    char report_path[sizeof temp_dir + 24];
    snprintf(report_path, sizeof report_path, "%s/report.bin", temp_dir);

    int result = -1;
    FILE *f = fopen(report_path, "wb");
    if (!f) goto cleanup;
    if ((int)fwrite(report, 1, (size_t)report_len, f) != report_len) {
        fclose(f);
        goto cleanup;
    }
    int flush_result = fflush(f);
    int sync_result = fsync(fileno(f));
    int close_result = fclose(f);
    if (flush_result != 0 || sync_result != 0 || close_result != 0)
        goto cleanup;

    char rd_hex[REPORT_DATA_SIZE * 2 + 1];
    bytes_to_hex(expected_report_data, REPORT_DATA_SIZE, rd_hex, sizeof rd_hex);
    char rd_arg[sizeof rd_hex + 2];
    snprintf(rd_arg, sizeof rd_arg, "0x%s", rd_hex);

    const char *certs_dir = getenv("SNP_CERTS_DIR");
    if (!certs_dir || !*certs_dir) certs_dir = "certs";
    if ((size_t)report_len < SNP_CHIP_ID_OFFSET + SNP_CHIP_ID_SIZE) {
        fprintf(stderr, "[MASTER] SNP report lacks chip/TCB identity fields\n");
        goto cleanup;
    }

    unsigned char cache_input[SNP_CHIP_ID_SIZE + SNP_REPORTED_TCB_SIZE];
    unsigned char cache_hash[HASH_LEN];
    char cache_key[HASH_LEN * 2 + 1];
    memcpy(cache_input, report + SNP_CHIP_ID_OFFSET, SNP_CHIP_ID_SIZE);
    memcpy(cache_input + SNP_CHIP_ID_SIZE,
           report + SNP_REPORTED_TCB_OFFSET, SNP_REPORTED_TCB_SIZE);
    crypto_generichash(cache_hash, sizeof cache_hash,
                       cache_input, sizeof cache_input, NULL, 0);
    bytes_to_hex(cache_hash, sizeof cache_hash, cache_key, sizeof cache_key);
    sodium_memzero(cache_input, sizeof cache_input);
    sodium_memzero(cache_hash, sizeof cache_hash);

    char resolved_certs[PATH_MAX];
    char cache_root[PATH_MAX], worker_certs[PATH_MAX];
    char ark_source[PATH_MAX], ask_source[PATH_MAX];
    char ark_link[PATH_MAX], ask_link[PATH_MAX], vcek_path[PATH_MAX];
    if (!realpath(certs_dir, resolved_certs) ||
        join_path(cache_root, sizeof cache_root,
                  resolved_certs, "vcek-cache") != 0 ||
        join_path(worker_certs, sizeof worker_certs,
                  cache_root, cache_key) != 0 ||
        join_path(ark_source, sizeof ark_source,
                  resolved_certs, "ark.pem") != 0 ||
        join_path(ask_source, sizeof ask_source,
                  resolved_certs, "ask.pem") != 0 ||
        join_path(ark_link, sizeof ark_link, worker_certs, "ark.pem") != 0 ||
        join_path(ask_link, sizeof ask_link, worker_certs, "ask.pem") != 0 ||
        join_path(vcek_path, sizeof vcek_path, worker_certs, "vcek.pem") != 0) {
        fprintf(stderr, "[MASTER] cannot construct VCEK cache paths\n");
        goto cleanup;
    }
    if ((mkdir(cache_root, 0700) != 0 && errno != EEXIST) ||
        (mkdir(worker_certs, 0700) != 0 && errno != EEXIST)) {
        fprintf(stderr, "[MASTER] cannot create VCEK cache: %s\n", strerror(errno));
        goto cleanup;
    }
    unlink(ark_link);
    unlink(ask_link);
    if (symlink(ark_source, ark_link) != 0 || symlink(ask_source, ask_link) != 0) {
        fprintf(stderr, "[MASTER] cannot link AMD CA certificates: %s\n",
                strerror(errno));
        goto cleanup;
    }

    for (int attempt = 0; attempt < 2; attempt++) {
        struct stat vst;
        int fetched_now = 0;
        if (stat(vcek_path, &vst) != 0 || vst.st_size <= 0) {
            unlink(vcek_path);
            char *fetch_argv[] = {
                "snpguest", "fetch", "vcek", "pem",
                worker_certs, report_path,
                "--processor-model", "milan", NULL
            };
            int fetch_rc = run_process(fetch_argv);
            if (fetch_rc != 0) {
                fprintf(stderr, "[MASTER] VCEK fetch returned %d\n", fetch_rc);
                break;
            }
            fetched_now = 1;
        } else {
            fprintf(stderr, "[MASTER] using cached VCEK (%s)\n", vcek_path);
        }

        if (verify_snp_with_certs(worker_certs, report_path, rd_arg) == 0) {
            result = 0;
            break;
        }
        if (fetched_now) {
            fprintf(stderr, "[MASTER] SNP Evidence verification failed\n");
            break;
        }
        fprintf(stderr, "[MASTER] cached VCEK did not match report; refetching\n");
        unlink(vcek_path);
    }

cleanup:
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
                      const unsigned char channel_binding[HASH_LEN],
                      unsigned char direction, int tag,
                      uint64_t plaintext_len, uint64_t counter)
{
    size_t offset = 0;
    memcpy(aad + offset, channel_binding, HASH_LEN);
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

static void secure_send(MPI_Comm comm, const unsigned char key[KEYB],
                        const unsigned char channel_binding[HASH_LEN],
                        uint64_t *nonce_ctr,
                        const void *plaintext, int plain_len,
                        int dest, int tag, const char *ctx)
{
    if (plain_len < 0 || plain_len > SECURE_MAX_PLAIN) {
        fprintf(stderr, "[MASTER] secure_send: plain_len %d out of range\n", plain_len);
        MPI_Abort(MPI_COMM_WORLD, 1);
    }
    if (*nonce_ctr == UINT64_MAX) {
        fprintf(stderr, "[MASTER] AEAD nonce space exhausted [%s]\n", ctx);
        MPI_Abort(MPI_COMM_WORLD, 1);
    }
    uint64_t counter = *nonce_ctr;
    unsigned char nonce[NPUB];
    unsigned char aad[SECURE_AAD_SIZE];
    make_nonce(nonce, counter);
    build_aad(aad, channel_binding, DIRECTION_CENTRAL_TO_WORKER,
              tag, (uint64_t)plain_len, counter);

    unsigned char buf[NPUB + SECURE_MAX_PLAIN + ABYTES];
    unsigned long long clen = 0;
    if (crypto_aead_chacha20poly1305_ietf_encrypt(
        buf + NPUB, &clen,
        (const unsigned char *)plaintext, (unsigned long long)plain_len,
        aad, sizeof aad, NULL, nonce, key) != 0 ||
        clen != (unsigned long long)plain_len + ABYTES) {
        fprintf(stderr, "[MASTER] AEAD encryption failed [%s]\n", ctx);
        MPI_Abort(MPI_COMM_WORLD, 1);
    }
    memcpy(buf, nonce, NPUB);
    int total = NPUB + plain_len + (int)ABYTES;
    mpi_send_f(buf, total, MPI_UNSIGNED_CHAR, dest, tag, comm, ctx);
    *nonce_ctr = counter + 1;
}

static int secure_recv(MPI_Comm comm, const unsigned char key[KEYB],
                       const unsigned char channel_binding[HASH_LEN],
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
    mpi_recv_f(buf, total, MPI_UNSIGNED_CHAR, src, tag, comm, &st, ctx);

    int received_count = 0;
    MPI_Get_count(&st, MPI_UNSIGNED_CHAR, &received_count);
    if (received_count != total) {
        fprintf(stderr, "[MASTER] invalid ciphertext length [%s]\n", ctx);
        return -1;
    }

    uint64_t received_ctr = 0;
    if (parse_nonce(buf, &received_ctr) != 0 || received_ctr != *nonce_ctr) {
        fprintf(stderr, "[MASTER] invalid AEAD sequence (received %" PRIu64
                        ", expected %" PRIu64 ") [%s]\n",
                received_ctr, *nonce_ctr, ctx);
        return -1;
    }
    unsigned char aad[SECURE_AAD_SIZE];
    build_aad(aad, channel_binding, DIRECTION_WORKER_TO_CENTRAL,
              tag, (uint64_t)plain_len, received_ctr);
    unsigned long long mlen = 0;
    if (crypto_aead_chacha20poly1305_ietf_decrypt(
            (unsigned char *)plaintext, &mlen, NULL,
            buf + NPUB, (unsigned long long)(plain_len + (int)ABYTES),
            aad, sizeof aad, buf, key) != 0) {
        fprintf(stderr, "[MASTER] AEAD decryption FAILED [%s]\n", ctx);
        return -1;
    }
    if ((int)mlen != plain_len) return -1;
    *nonce_ctr = received_ctr + 1;
    return 0;
}

static void workload_send_small(
    MPI_Comm comm, const unsigned char key[KEYB],
    const unsigned char channel_binding[HASH_LEN], uint64_t *nonce_ctr,
    const void *data, int data_bytes, int dest, int tag, int encrypt,
    const char *ctx)
{
    if (encrypt) {
        secure_send(comm, key, channel_binding, nonce_ctr,
                    data, data_bytes, dest, tag, ctx);
        return;
    }
    if (data_bytes < 0 || data_bytes > SECURE_MAX_PLAIN) {
        fprintf(stderr, "[MASTER] workload_send_small: data_bytes %d out of range\n",
                data_bytes);
        MPI_Abort(MPI_COMM_WORLD, 1);
    }
    mpi_send_f(data, data_bytes, MPI_UNSIGNED_CHAR, dest, tag, comm, ctx);
}

static int workload_recv_small(
    MPI_Comm comm, const unsigned char key[KEYB],
    const unsigned char channel_binding[HASH_LEN], uint64_t *nonce_ctr,
    void *data, int data_bytes, int src, int tag, int encrypt,
    const char *ctx)
{
    if (encrypt)
        return secure_recv(comm, key, channel_binding, nonce_ctr,
                           data, data_bytes, src, tag, ctx);
    if (data_bytes < 0 || data_bytes > SECURE_MAX_PLAIN) {
        fprintf(stderr, "[MASTER] workload_recv_small: data_bytes %d out of range\n",
                data_bytes);
        return -1;
    }

    MPI_Status status;
    mpi_recv_f(data, data_bytes, MPI_UNSIGNED_CHAR, src, tag, comm, &status, ctx);
    int received_count = 0;
    MPI_Get_count(&status, MPI_UNSIGNED_CHAR, &received_count);
    if (received_count != data_bytes) {
        fprintf(stderr, "[MASTER] invalid plaintext workload length [%s]\n", ctx);
        return -1;
    }
    return 0;
}

/* ── AEAD bulk send / recv — LARGE messages ── */

static void send_bulk(MPI_Comm comm, const unsigned char key[KEYB],
                      const unsigned char channel_binding[HASH_LEN],
                      uint64_t *nonce_ctr,
                      const void *data, size_t data_bytes,
                      int dest, int tag, int encrypt, const char *ctx)
{
    if (data_bytes > (size_t)INT_MAX) {
        fprintf(stderr, "[MASTER] bulk message is too large [%s]\n", ctx);
        MPI_Abort(MPI_COMM_WORLD, 1);
    }
    if (!encrypt) {
        mpi_send_f(data, (int)data_bytes, MPI_UNSIGNED_CHAR, dest, tag, comm, ctx);
        return;
    }
    if (data_bytes > (size_t)INT_MAX - NPUB - ABYTES) {
        fprintf(stderr, "[MASTER] bulk message is too large [%s]\n", ctx);
        MPI_Abort(MPI_COMM_WORLD, 1);
    }
    if (*nonce_ctr == UINT64_MAX) {
        fprintf(stderr, "[MASTER] AEAD nonce space exhausted [%s]\n", ctx);
        MPI_Abort(MPI_COMM_WORLD, 1);
    }
    size_t total = NPUB + data_bytes + ABYTES;
    unsigned char *buf = (unsigned char *)malloc(total);
    if (!buf) {
        fprintf(stderr, "[MASTER] malloc(%zu) failed in send_bulk\n", total);
        MPI_Abort(MPI_COMM_WORLD, 1);
    }

    uint64_t counter = *nonce_ctr;
    unsigned char nonce[NPUB];
    unsigned char aad[SECURE_AAD_SIZE];
    make_nonce(nonce, counter);
    build_aad(aad, channel_binding, DIRECTION_CENTRAL_TO_WORKER,
              tag, (uint64_t)data_bytes, counter);

    unsigned long long clen = 0;
    if (crypto_aead_chacha20poly1305_ietf_encrypt(
        buf + NPUB, &clen,
        (const unsigned char *)data, (unsigned long long)data_bytes,
        aad, sizeof aad, NULL, nonce, key) != 0 ||
        clen != (unsigned long long)data_bytes + ABYTES) {
        fprintf(stderr, "[MASTER] bulk AEAD encryption failed [%s]\n", ctx);
        free(buf);
        MPI_Abort(MPI_COMM_WORLD, 1);
    }
    memcpy(buf, nonce, NPUB);
    mpi_send_f(buf, (int)total, MPI_UNSIGNED_CHAR, dest, tag, comm, ctx);
    *nonce_ctr = counter + 1;
    free(buf);
}

static int recv_bulk(MPI_Comm comm, const unsigned char key[KEYB],
                     const unsigned char channel_binding[HASH_LEN],
                     uint64_t *nonce_ctr,
                     void *data, size_t data_bytes,
                     int src, int tag, int encrypt, const char *ctx)
{
    if (data_bytes > (size_t)INT_MAX) {
        fprintf(stderr, "[MASTER] bulk message is too large [%s]\n", ctx);
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
        fprintf(stderr, "[MASTER] bulk message is too large [%s]\n", ctx);
        return -1;
    }
    size_t total = NPUB + data_bytes + ABYTES;
    unsigned char *buf = (unsigned char *)malloc(total);
    if (!buf) {
        fprintf(stderr, "[MASTER] malloc(%zu) failed in recv_bulk\n", total);
        return -1;
    }

    MPI_Status st;
    mpi_recv_f(buf, (int)total, MPI_UNSIGNED_CHAR, src, tag, comm, &st, ctx);

    int received_count = 0;
    MPI_Get_count(&st, MPI_UNSIGNED_CHAR, &received_count);
    if (received_count != (int)total) {
        fprintf(stderr, "[MASTER] invalid bulk ciphertext length [%s]\n", ctx);
        free(buf);
        return -1;
    }

    uint64_t received_ctr = 0;
    if (parse_nonce(buf, &received_ctr) != 0 || received_ctr != *nonce_ctr) {
        fprintf(stderr, "[MASTER] invalid bulk AEAD sequence [%s]\n", ctx);
        free(buf);
        return -1;
    }

    unsigned char aad[SECURE_AAD_SIZE];
    build_aad(aad, channel_binding, DIRECTION_WORKER_TO_CENTRAL,
              tag, (uint64_t)data_bytes, received_ctr);

    unsigned long long mlen = 0;
    if (crypto_aead_chacha20poly1305_ietf_decrypt(
            (unsigned char *)data, &mlen, NULL,
            buf + NPUB, (unsigned long long)(data_bytes + ABYTES),
            aad, sizeof aad, buf, key) != 0 ||
        mlen != (unsigned long long)data_bytes) {
        fprintf(stderr, "[MASTER] AEAD decryption FAILED in recv_bulk [%s]\n", ctx);
        free(buf);
        return -1;
    }
    *nonce_ctr = received_ctr + 1;
    free(buf);
    return 0;
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

static int parse_u64_arg(const char *text, uint64_t min_value,
                         uint64_t max_value, uint64_t *out)
{
    if (!text || !*text || text[0] == '-') return -1;
    errno = 0;
    char *end = NULL;
    unsigned long long value = strtoull(text, &end, 10);
    if (errno == ERANGE || !end || *end != '\0' ||
        value < min_value || value > max_value)
        return -1;
    *out = (uint64_t)value;
    return 0;
}

static int parse_next_u64(int argc, char **argv, int *index,
                          uint64_t min_value, uint64_t max_value,
                          uint64_t *out)
{
    if (*index + 1 >= argc ||
        parse_u64_arg(argv[*index + 1], min_value, max_value, out) != 0) {
        fprintf(stderr, "[MASTER] invalid or missing value for %s\n", argv[*index]);
        return -1;
    }
    (*index)++;
    return 0;
}

static int checked_mib_bytes(uint32_t mib, size_t *bytes)
{
    if ((uint64_t)mib > (uint64_t)SIZE_MAX / MIB_BYTES) return -1;
    *bytes = (size_t)((uint64_t)mib * MIB_BYTES);
    return 0;
}

static double vmap_input_value(size_t index)
{
    return (double)(index % 4096U) / 128.0 - 8.0;
}

static double vmap_transform(double value)
{
    return value * 1.25 + 0.5;
}

static uint64_t xorshift64_step(uint64_t value)
{
    value ^= value << 13;
    value ^= value >> 7;
    value ^= value << 17;
    return value;
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

static uint64_t linear_map_apply(const uint64_t map[64], uint64_t value)
{
    uint64_t result = 0;
    for (unsigned bit = 0; bit < 64; bit++)
        if ((value >> bit) & 1U) result ^= map[bit];
    return result;
}

static void linear_map_compose(const uint64_t outer[64],
                               const uint64_t inner[64], uint64_t out[64])
{
    for (unsigned bit = 0; bit < 64; bit++)
        out[bit] = linear_map_apply(outer, inner[bit]);
}

static void build_xorshift_jump(uint64_t iterations, uint64_t jump[64])
{
    uint64_t base[64], temp[64];
    for (unsigned bit = 0; bit < 64; bit++) {
        jump[bit] = UINT64_C(1) << bit;
        base[bit] = xorshift64_step(UINT64_C(1) << bit);
    }
    while (iterations != 0) {
        if (iterations & 1U) {
            linear_map_compose(base, jump, temp);
            memcpy(jump, temp, sizeof temp);
        }
        iterations >>= 1;
        if (iterations != 0) {
            linear_map_compose(base, base, temp);
            memcpy(base, temp, sizeof temp);
        }
    }
}

/* ──────────────────────────────────────────────────────────────────────
 *  CG: Generate a regular sparse matrix (like NPB CG Class A/B)
 *  Each row has exactly `nzpc` nonzero entries at random column positions.
 *  Values are random in [-1, 1].  Stored in CSR format.
 * ────────────────────────────────────────────────────────────────────── */

static int generate_sparse_matrix(int n, int nzpc, int seed,
                                  int **out_row_ptr, int **out_col_idx,
                                  double **out_val)
{
    *out_row_ptr = NULL;
    *out_col_idx = NULL;
    *out_val = NULL;
    if (n <= 0 || nzpc <= 0 || n > INT_MAX / nzpc ||
        (size_t)n + 1 > SIZE_MAX / sizeof(int))
        return -1;
    int nnz = n * nzpc;
    if ((size_t)nnz > SIZE_MAX / sizeof(double)) return -1;
    int *row_ptr = (int *)malloc(((size_t)n + 1) * sizeof(int));
    int *col_idx = (int *)malloc((size_t)nnz * sizeof(int));
    double *val  = (double *)malloc((size_t)nnz * sizeof(double));
    if (!row_ptr || !col_idx || !val) {
        free(row_ptr); free(col_idx); free(val);
        return -1;
    }

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
    return 0;
}

static void record_generic_result(int workload, int nworkers, int encrypt,
                                  int run, double scatter_ms,
                                  double compute_max_ms, double gather_ms,
                                  double round_ms)
{
    if (g_nresults >= MAX_RESULTS) {
        fprintf(stderr, "[MASTER] result storage exhausted\n");
        MPI_Abort(MPI_COMM_WORLD, 1);
    }
    struct npb_result *result = &g_results[g_nresults++];
    memset(result, 0, sizeof *result);
    result->workload = workload;
    result->num_workers = nworkers;
    result->encrypted = encrypt;
    result->run = run;
    result->t_scatter_ms = scatter_ms;
    result->t_compute_max_ms = compute_max_ms;
    result->t_gather_ms = gather_ms;
    result->t_round_ms = round_ms;
}

static int wait_for_workload_ready(
    int nworkers, MPI_Comm workers[MAX_WORKERS],
    const unsigned char rx_keys[MAX_WORKERS][KEYB],
    const unsigned char bindings[MAX_WORKERS][HASH_LEN],
    int workload, int tag, uint64_t expected_count)
{
    for (int worker = 0; worker < nworkers; worker++) {
        struct workload_ready ready;
        if (secure_recv(workers[worker], rx_keys[worker], bindings[worker],
                        &recv_nonce_ctr[worker], &ready, sizeof ready, 0, tag,
                        "Recv(WORKLOAD_READY)") != 0 ||
            ready.workload != workload || !ready.ok ||
            ready.element_count != expected_count) {
            fprintf(stderr, "[MASTER] worker %d failed %s setup\n",
                    worker + 1, workload_name(workload));
            return -1;
        }
    }
    return 0;
}

static int run_stream_master(
    int nworkers, MPI_Comm workers[MAX_WORKERS],
    const unsigned char tx_keys[MAX_WORKERS][KEYB],
    const unsigned char rx_keys[MAX_WORKERS][KEYB],
    const unsigned char bindings[MAX_WORKERS][HASH_LEN],
    int encrypt, int num_runs, uint32_t array_mib, uint32_t warmup)
{
    size_t array_bytes = 0;
    if (checked_mib_bytes(array_mib, &array_bytes) != 0) return -1;
    uint64_t element_count = (uint64_t)(array_bytes / sizeof(double));
    const char *timing_probe = getenv("PPDPC_WORKER_TIMINGS");
    int log_worker_timings = timing_probe && strcmp(timing_probe, "1") == 0;

    for (int worker = 0; worker < nworkers; worker++) {
        struct npb_cmd cmd = {0};
        cmd.cmd = CMD_NPB_START;
        cmd.workload = WORKLOAD_STREAM;
        cmd.encrypt_data = encrypt;
        cmd.num_runs = num_runs;
        cmd.stream_array_mib = array_mib;
        cmd.stream_warmup = warmup;
        secure_send(workers[worker], tx_keys[worker], bindings[worker],
                    &send_nonce_ctr[worker], &cmd, sizeof cmd, 0, TAG_NPB_CMD,
                    "Send(NPB_CMD_STREAM)");
    }
    if (wait_for_workload_ready(nworkers, workers, rx_keys, bindings,
                                WORKLOAD_STREAM, TAG_STREAM_READY,
                                element_count) != 0)
        return -1;

    printf("[STREAM] workers ready; working set/worker=%u MiB (%u MiB x 3)\n",
           array_mib * 3U, array_mib);
    double expected_checksum = 7.0 * (double)element_count;
    for (int run = 1; run <= num_runs; run++) {
        struct run_trigger trigger = {.run = run, .reserved = 0};
        double started = MPI_Wtime();
        for (int worker = 0; worker < nworkers; worker++)
            workload_send_small(workers[worker], tx_keys[worker],
                                bindings[worker], &send_nonce_ctr[worker],
                                &trigger, sizeof trigger, 0, TAG_STREAM_RUN,
                                encrypt, "Send(STREAM_RUN)");
        double scatter_done = MPI_Wtime();

        double compute_max_ms = 0.0;
        double worker_compute_ms[MAX_WORKERS] = {0};
        for (int worker = 0; worker < nworkers; worker++) {
            struct stream_result result;
            if (workload_recv_small(
                    workers[worker], rx_keys[worker], bindings[worker],
                    &recv_nonce_ctr[worker], &result, sizeof result, 0,
                    TAG_STREAM_RESULT, encrypt, "Recv(STREAM_RESULT)") != 0 ||
                result.run != run || !result.verified ||
                !isfinite(result.compute_ms) || result.compute_ms < 0.0 ||
                result.checksum != expected_checksum) {
                fprintf(stderr, "[MASTER] invalid STREAM result from worker %d\n",
                        worker + 1);
                return -1;
            }
            worker_compute_ms[worker] = result.compute_ms;
            if (result.compute_ms > compute_max_ms)
                compute_max_ms = result.compute_ms;
        }
        if (log_worker_timings)
            for (int worker = 0; worker < nworkers; worker++)
                printf("[WORKER_TIMING] workload=STREAM run=%d worker=%d compute_ms=%.6f\n",
                       run, worker + 1, worker_compute_ms[worker]);
        double finished = MPI_Wtime();
        double scatter_ms = (scatter_done - started) * 1000.0;
        double gather_ms = (finished - scatter_done) * 1000.0;
        double round_ms = (finished - started) * 1000.0;
        record_generic_result(WORKLOAD_STREAM, nworkers, encrypt, run,
                              scatter_ms, compute_max_ms, gather_ms, round_ms);
        printf("[STREAM] run %d/%d: scatter=%.2f compute=%.2f "
               "gather=%.2f round=%.2f ms\n",
               run, num_runs, scatter_ms, compute_max_ms, gather_ms, round_ms);
    }
    return 0;
}

static int run_random_master(
    int nworkers, MPI_Comm workers[MAX_WORKERS],
    const unsigned char tx_keys[MAX_WORKERS][KEYB],
    const unsigned char rx_keys[MAX_WORKERS][KEYB],
    const unsigned char bindings[MAX_WORKERS][HASH_LEN],
    int encrypt, int num_runs, uint32_t random_mib,
    uint64_t accesses, uint64_t warmup_accesses)
{
    size_t link_bytes = 0;
    if (checked_mib_bytes(random_mib, &link_bytes) != 0) return -1;
    uint64_t element_count = (uint64_t)(link_bytes / sizeof(uint32_t));
    const char *timing_probe = getenv("PPDPC_WORKER_TIMINGS");
    int log_worker_timings = timing_probe && strcmp(timing_probe, "1") == 0;

    for (int worker = 0; worker < nworkers; worker++) {
        struct npb_cmd cmd = {0};
        cmd.cmd = CMD_NPB_START;
        cmd.workload = WORKLOAD_RANDOM;
        cmd.encrypt_data = encrypt;
        cmd.num_runs = num_runs;
        cmd.random_mib = random_mib;
        cmd.random_accesses = accesses;
        cmd.random_warmup_accesses = warmup_accesses;
        secure_send(workers[worker], tx_keys[worker], bindings[worker],
                    &send_nonce_ctr[worker], &cmd, sizeof cmd, 0, TAG_NPB_CMD,
                    "Send(NPB_CMD_RANDOM)");
    }
    if (wait_for_workload_ready(nworkers, workers, rx_keys, bindings,
                                WORKLOAD_RANDOM, TAG_RANDOM_READY,
                                element_count) != 0)
        return -1;

    printf("[RANDOM] workers ready; links/worker=%u MiB\n", random_mib);
    for (int run = 1; run <= num_runs; run++) {
        struct run_trigger trigger = {.run = run, .reserved = 0};
        double started = MPI_Wtime();
        for (int worker = 0; worker < nworkers; worker++)
            workload_send_small(workers[worker], tx_keys[worker],
                                bindings[worker], &send_nonce_ctr[worker],
                                &trigger, sizeof trigger, 0, TAG_RANDOM_RUN,
                                encrypt, "Send(RANDOM_RUN)");
        double scatter_done = MPI_Wtime();

        double compute_max_ms = 0.0;
        double worker_compute_ms[MAX_WORKERS] = {0};
        uint32_t expected_token = 0;
        for (int worker = 0; worker < nworkers; worker++) {
            struct random_result result;
            if (workload_recv_small(
                    workers[worker], rx_keys[worker], bindings[worker],
                    &recv_nonce_ctr[worker], &result, sizeof result, 0,
                    TAG_RANDOM_RESULT, encrypt, "Recv(RANDOM_RESULT)") != 0 ||
                result.run != run || !result.verified ||
                !isfinite(result.compute_ms) || result.compute_ms < 0.0 ||
                (worker > 0 && result.final_token != expected_token)) {
                fprintf(stderr, "[MASTER] invalid RANDOM result from worker %d\n",
                        worker + 1);
                return -1;
            }
            if (worker == 0) expected_token = result.final_token;
            worker_compute_ms[worker] = result.compute_ms;
            if (result.compute_ms > compute_max_ms)
                compute_max_ms = result.compute_ms;
        }
        if (log_worker_timings)
            for (int worker = 0; worker < nworkers; worker++)
                printf("[WORKER_TIMING] workload=RANDOM run=%d worker=%d compute_ms=%.6f\n",
                       run, worker + 1, worker_compute_ms[worker]);
        double finished = MPI_Wtime();
        double scatter_ms = (scatter_done - started) * 1000.0;
        double gather_ms = (finished - scatter_done) * 1000.0;
        double round_ms = (finished - started) * 1000.0;
        record_generic_result(WORKLOAD_RANDOM, nworkers, encrypt, run,
                              scatter_ms, compute_max_ms, gather_ms, round_ms);
        printf("[RANDOM] run %d/%d: scatter=%.2f compute=%.2f "
               "gather=%.2f round=%.2f ms token=%" PRIu32 "\n",
               run, num_runs, scatter_ms, compute_max_ms, gather_ms,
               round_ms, expected_token);
    }
    return 0;
}

static int run_vmap_master(
    int nworkers, MPI_Comm workers[MAX_WORKERS],
    const unsigned char tx_keys[MAX_WORKERS][KEYB],
    const unsigned char rx_keys[MAX_WORKERS][KEYB],
    const unsigned char bindings[MAX_WORKERS][HASH_LEN],
    int encrypt, int num_runs, uint32_t vmap_mib)
{
    size_t block_bytes = 0;
    if (checked_mib_bytes(vmap_mib, &block_bytes) != 0 ||
        block_bytes % sizeof(double) != 0)
        return -1;
    size_t element_count = block_bytes / sizeof(double);

    for (int worker = 0; worker < nworkers; worker++) {
        struct npb_cmd cmd = {0};
        cmd.cmd = CMD_NPB_START;
        cmd.workload = WORKLOAD_VMAP;
        cmd.encrypt_data = encrypt;
        cmd.num_runs = num_runs;
        cmd.vmap_mib = vmap_mib;
        secure_send(workers[worker], tx_keys[worker], bindings[worker],
                    &send_nonce_ctr[worker], &cmd, sizeof cmd, 0, TAG_NPB_CMD,
                    "Send(NPB_CMD_VMAP)");
    }
    if (wait_for_workload_ready(nworkers, workers, rx_keys, bindings,
                                WORKLOAD_VMAP, TAG_VMAP_READY,
                                (uint64_t)element_count) != 0)
        return -1;

    double *input = (double *)malloc(block_bytes);
    double *output = (double *)malloc(block_bytes);
    if (!input || !output) {
        fprintf(stderr, "[MASTER] VMAP buffer allocation failed\n");
        free(input); free(output);
        return -1;
    }
    double expected_checksum = 0.0;
    for (size_t i = 0; i < element_count; i++) {
        input[i] = vmap_input_value(i);
        output[i] = 0.0;
        expected_checksum += vmap_transform(input[i]);
    }

    printf("[VMAP] workers ready; protected block=%u MiB each direction\n",
           vmap_mib);
    int status = 0;
    for (int run = 1; run <= num_runs; run++) {
        double started = MPI_Wtime();
        for (int worker = 0; worker < nworkers; worker++)
            send_bulk(workers[worker], tx_keys[worker], bindings[worker],
                      &send_nonce_ctr[worker], input, block_bytes, 0,
                      TAG_VMAP_INPUT, encrypt, "Send(VMAP_INPUT)");
        double scatter_done = MPI_Wtime();

        double compute_max_ms = 0.0;
        for (int worker = 0; worker < nworkers; worker++) {
            if (recv_bulk(workers[worker], rx_keys[worker], bindings[worker],
                          &recv_nonce_ctr[worker], output, block_bytes, 0,
                          TAG_VMAP_OUTPUT, encrypt, "Recv(VMAP_OUTPUT)") != 0) {
                status = -1;
                break;
            }
            struct vmap_result result;
                if (workload_recv_small(
                    workers[worker], rx_keys[worker], bindings[worker],
                    &recv_nonce_ctr[worker], &result, sizeof result, 0,
                    TAG_VMAP_RESULT, encrypt, "Recv(VMAP_RESULT)") != 0 ||
                result.run != run || !result.verified ||
                !isfinite(result.compute_ms) || result.compute_ms < 0.0 ||
                !isfinite(result.checksum) ||
                fabs(result.checksum - expected_checksum) >
                    1.0e-9 * fmax(1.0, fabs(expected_checksum))) {
                status = -1;
                break;
            }
            size_t samples[3] = {0, element_count / 2, element_count - 1};
            for (size_t sample = 0; sample < 3; sample++) {
                size_t index = samples[sample];
                if (output[index] != vmap_transform(input[index])) status = -1;
            }
            if (status != 0) break;
            if (result.compute_ms > compute_max_ms)
                compute_max_ms = result.compute_ms;
        }
        if (status != 0) {
            fprintf(stderr, "[MASTER] VMAP verification failed in run %d\n", run);
            break;
        }
        double finished = MPI_Wtime();
        double scatter_ms = (scatter_done - started) * 1000.0;
        double gather_ms = (finished - scatter_done) * 1000.0;
        double round_ms = (finished - started) * 1000.0;
        record_generic_result(WORKLOAD_VMAP, nworkers, encrypt, run,
                              scatter_ms, compute_max_ms, gather_ms, round_ms);
        printf("[VMAP] run %d/%d: scatter=%.2f compute=%.2f "
               "gather=%.2f round=%.2f ms\n",
               run, num_runs, scatter_ms, compute_max_ms, gather_ms, round_ms);
    }

    free(input); free(output);
    return status;
}

static void send_taskq_work(
    int worker, int run, uint64_t task_id, uint64_t iterations,
    uint32_t payload_bytes, uint8_t *input,
    MPI_Comm workers[MAX_WORKERS],
    const unsigned char tx_keys[MAX_WORKERS][KEYB],
    const unsigned char bindings[MAX_WORKERS][HASH_LEN], int encrypt)
{
    struct taskq_task task = {
        .command = TASKQ_TASK_WORK,
        .run = run,
        .task_id = task_id,
        .iterations = iterations,
        .payload_bytes = payload_bytes,
        .reserved = 0
    };
    for (size_t i = 0; i < payload_bytes; i++)
        input[i] = task_input_byte(task_id, run, i);
    workload_send_small(workers[worker], tx_keys[worker], bindings[worker],
                        &send_nonce_ctr[worker], &task, sizeof task, 0,
                        TAG_TASKQ_TASK, encrypt, "Send(TASKQ_TASK)");
    send_bulk(workers[worker], tx_keys[worker], bindings[worker],
              &send_nonce_ctr[worker], input, payload_bytes, 0,
              TAG_TASKQ_INPUT, encrypt, "Send(TASKQ_INPUT)");
}

static void send_taskq_end(
    int worker, int run, MPI_Comm workers[MAX_WORKERS],
    const unsigned char tx_keys[MAX_WORKERS][KEYB],
    const unsigned char bindings[MAX_WORKERS][HASH_LEN], int encrypt)
{
    struct taskq_task end = {
        .command = TASKQ_TASK_END,
        .run = run,
        .task_id = UINT64_MAX,
        .iterations = 0,
        .payload_bytes = 0,
        .reserved = 0
    };
    workload_send_small(workers[worker], tx_keys[worker], bindings[worker],
                        &send_nonce_ctr[worker], &end, sizeof end, 0,
                        TAG_TASKQ_TASK, encrypt, "Send(TASKQ_END)");
}

static int run_taskq_master(
    int nworkers, MPI_Comm workers[MAX_WORKERS],
    const unsigned char tx_keys[MAX_WORKERS][KEYB],
    const unsigned char rx_keys[MAX_WORKERS][KEYB],
    const unsigned char bindings[MAX_WORKERS][HASH_LEN],
    int encrypt, int num_runs, uint64_t task_count,
    uint32_t payload_bytes, uint64_t iterations)
{
    uint8_t *input = (uint8_t *)malloc(payload_bytes);
    uint8_t *output = (uint8_t *)malloc(payload_bytes);
    if (!input || !output) {
        fprintf(stderr, "[MASTER] TASKQ buffer allocation failed\n");
        free(input); free(output);
        return -1;
    }

    uint64_t jump[64];
    build_xorshift_jump(iterations, jump);
    for (int worker = 0; worker < nworkers; worker++) {
        struct npb_cmd cmd = {0};
        cmd.cmd = CMD_NPB_START;
        cmd.workload = WORKLOAD_TASKQ;
        cmd.encrypt_data = encrypt;
        cmd.num_runs = num_runs;
        cmd.task_count = task_count;
        cmd.task_bytes = payload_bytes;
        cmd.task_iters = iterations;
        secure_send(workers[worker], tx_keys[worker], bindings[worker],
                    &send_nonce_ctr[worker], &cmd, sizeof cmd, 0, TAG_NPB_CMD,
                    "Send(NPB_CMD_TASKQ)");
    }
    if (wait_for_workload_ready(nworkers, workers, rx_keys, bindings,
                                WORKLOAD_TASKQ, TAG_TASKQ_READY,
                                payload_bytes) != 0) {
        free(input); free(output);
        return -1;
    }

    printf("[TASKQ] workers ready; tasks=%" PRIu64 " bytes=%u iters=%" PRIu64 "\n",
           task_count, payload_bytes, iterations);
    int status = 0;
    for (int run = 1; run <= num_runs; run++) {
        int busy[MAX_WORKERS] = {0};
        uint64_t assigned_task[MAX_WORKERS] = {0};
        double worker_compute_ms[MAX_WORKERS] = {0};
        uint64_t next_task = 0;
        uint64_t completed = 0;

        struct taskq_control control = {
            .command = TASKQ_CONTROL_START,
            .run = run
        };
        double started = MPI_Wtime();
        for (int worker = 0; worker < nworkers; worker++)
            workload_send_small(workers[worker], tx_keys[worker],
                                bindings[worker], &send_nonce_ctr[worker],
                                &control, sizeof control, 0, TAG_TASKQ_CONTROL,
                                encrypt, "Send(TASKQ_START)");

        for (int worker = 0; worker < nworkers; worker++) {
            if (next_task < task_count) {
                assigned_task[worker] = next_task;
                send_taskq_work(worker, run, next_task, iterations,
                                payload_bytes, input, workers, tx_keys,
                                bindings, encrypt);
                next_task++;
                busy[worker] = 1;
            }
        }
        double scatter_done = MPI_Wtime();

        while (completed < task_count && status == 0) {
            for (int worker = 0; worker < nworkers; worker++) {
                if (!busy[worker]) continue;
                MPI_Status probe_status;
                if (!mpi_iprobe_f(0, TAG_TASKQ_RESULT, workers[worker],
                                  &probe_status, "Iprobe(TASKQ_RESULT)"))
                    continue;

                struct taskq_result result;
        if (workload_recv_small(
            workers[worker], rx_keys[worker], bindings[worker],
            &recv_nonce_ctr[worker], &result, sizeof result, 0,
            TAG_TASKQ_RESULT, encrypt, "Recv(TASKQ_RESULT)") != 0 ||
                    result.run != run || !result.verified ||
                    result.task_id != assigned_task[worker] ||
                    result.payload_bytes != payload_bytes ||
                    !isfinite(result.compute_ms) || result.compute_ms < 0.0) {
                    status = -1;
                    break;
                }
                if (recv_bulk(workers[worker], rx_keys[worker],
                              bindings[worker], &recv_nonce_ctr[worker],
                              output, payload_bytes, 0, TAG_TASKQ_OUTPUT,
                              encrypt, "Recv(TASKQ_OUTPUT)") != 0) {
                    status = -1;
                    break;
                }

                uint64_t expected_token = linear_map_apply(
                    jump, task_initial_token(result.task_id, run));
                if (result.token != expected_token) {
                    status = -1;
                    break;
                }
                size_t samples[3] = {0, payload_bytes / 2, payload_bytes - 1};
                for (size_t sample = 0; sample < 3; sample++) {
                    size_t index = samples[sample];
                    uint8_t expected = task_output_byte(
                        task_input_byte(result.task_id, run, index),
                        expected_token, result.task_id, index);
                    if (output[index] != expected) status = -1;
                }
                if (status != 0) break;

                worker_compute_ms[worker] += result.compute_ms;
                completed++;
                busy[worker] = 0;
                if (next_task < task_count) {
                    assigned_task[worker] = next_task;
                    send_taskq_work(worker, run, next_task, iterations,
                                    payload_bytes, input, workers, tx_keys,
                                    bindings, encrypt);
                    next_task++;
                    busy[worker] = 1;
                }
            }
        }
        if (status != 0) {
            fprintf(stderr, "[MASTER] TASKQ verification failed in run %d\n", run);
            break;
        }

        double finished = MPI_Wtime();
        for (int worker = 0; worker < nworkers; worker++)
            send_taskq_end(worker, run, workers, tx_keys, bindings, encrypt);

        double compute_max_ms = 0.0;
        for (int worker = 0; worker < nworkers; worker++)
            if (worker_compute_ms[worker] > compute_max_ms)
                compute_max_ms = worker_compute_ms[worker];
        double scatter_ms = (scatter_done - started) * 1000.0;
        double gather_ms = (finished - scatter_done) * 1000.0;
        double round_ms = (finished - started) * 1000.0;
        record_generic_result(WORKLOAD_TASKQ, nworkers, encrypt, run,
                              scatter_ms, compute_max_ms, gather_ms, round_ms);
        printf("[TASKQ] run %d/%d: tasks=%" PRIu64
               " scatter=%.2f compute=%.2f gather=%.2f round=%.2f ms\n",
               run, num_runs, completed, scatter_ms, compute_max_ms,
               gather_ms, round_ms);
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

    /* ── Parse command-line arguments ── */
    int target    = 2;
    int num_runs  = 10;
    int encrypt   = 1;
    int workload  = WORKLOAD_EP;
    int64_t ep_n  = (int64_t)1 << 26;   /* 2^26 pairs per worker (default) */
    int cg_n      = 14000;              /* NPB CG Class A size */
    int cg_nzpc   = 11;                 /* nonzeros per row (Class A) */
    int cg_iters  = 15;                 /* CG iterations (Class A) */
    uint32_t stream_array_mib = 128;
    uint32_t stream_warmup = 2;
    uint32_t random_mib = 256;
    uint64_t random_accesses = UINT64_C(50000000);
    uint64_t random_warmup_accesses = UINT64_C(5000000);
    uint32_t vmap_mib = 64;
    uint64_t task_count = 0;
    uint32_t task_bytes = 64;
    uint64_t task_iters = UINT64_C(100000);
    const char *csv_file = "npb_results.csv";

    for (int i = 1; i < argc; i++) {
        uint64_t parsed = 0;
        if (strcmp(argv[i], "--master") == 0) {
            if (parse_next_u64(argc, argv, &i, 1, MAX_WORKERS, &parsed) != 0)
                return 2;
            target = (int)parsed;
        }
        else if (strcmp(argv[i], "--workload") == 0) {
            if (++i >= argc) {
                fprintf(stderr, "[MASTER] missing value for --workload\n");
                return 2;
            }
            if (strcmp(argv[i], "ep") == 0) workload = WORKLOAD_EP;
            else if (strcmp(argv[i], "cg") == 0) workload = WORKLOAD_CG;
            else if (strcmp(argv[i], "stream") == 0) workload = WORKLOAD_STREAM;
            else if (strcmp(argv[i], "random") == 0) workload = WORKLOAD_RANDOM;
            else if (strcmp(argv[i], "vmap") == 0) workload = WORKLOAD_VMAP;
            else if (strcmp(argv[i], "taskq") == 0) workload = WORKLOAD_TASKQ;
            else { fprintf(stderr, "Unknown workload: %s\n", argv[i]); return 1; }
        }
        else if (strcmp(argv[i], "--ep-n") == 0) {
            if (parse_next_u64(argc, argv, &i, 1, INT64_MAX, &parsed) != 0)
                return 2;
            ep_n = (int64_t)parsed;
        }
        else if (strcmp(argv[i], "--cg-n") == 0) {
            if (parse_next_u64(argc, argv, &i, 1, INT_MAX - 1, &parsed) != 0)
                return 2;
            cg_n = (int)parsed;
        }
        else if (strcmp(argv[i], "--cg-nzpc") == 0) {
            if (parse_next_u64(argc, argv, &i, 1, INT_MAX, &parsed) != 0)
                return 2;
            cg_nzpc = (int)parsed;
        }
        else if (strcmp(argv[i], "--cg-iters") == 0) {
            if (parse_next_u64(argc, argv, &i, 1, INT_MAX, &parsed) != 0)
                return 2;
            cg_iters = (int)parsed;
        }
        else if (strcmp(argv[i], "--stream-array-mib") == 0) {
            if (parse_next_u64(argc, argv, &i, STREAM_MIN_MIB,
                               STREAM_MAX_MIB, &parsed) != 0)
                return 2;
            stream_array_mib = (uint32_t)parsed;
        }
        else if (strcmp(argv[i], "--stream-warmup") == 0) {
            if (parse_next_u64(argc, argv, &i, 0, UINT32_MAX, &parsed) != 0)
                return 2;
            stream_warmup = (uint32_t)parsed;
        }
        else if (strcmp(argv[i], "--random-mib") == 0) {
            if (parse_next_u64(argc, argv, &i, RANDOM_MIN_MIB,
                               RANDOM_MAX_MIB, &parsed) != 0)
                return 2;
            random_mib = (uint32_t)parsed;
        }
        else if (strcmp(argv[i], "--random-accesses") == 0) {
            if (parse_next_u64(argc, argv, &i, 1, UINT64_MAX, &parsed) != 0)
                return 2;
            random_accesses = parsed;
        }
        else if (strcmp(argv[i], "--random-warmup-accesses") == 0) {
            if (parse_next_u64(argc, argv, &i, 0, UINT64_MAX, &parsed) != 0)
                return 2;
            random_warmup_accesses = parsed;
        }
        else if (strcmp(argv[i], "--vmap-mib") == 0) {
            if (parse_next_u64(argc, argv, &i, VMAP_MIN_MIB,
                               VMAP_MAX_MIB, &parsed) != 0)
                return 2;
            vmap_mib = (uint32_t)parsed;
        }
        else if (strcmp(argv[i], "--task-count") == 0) {
            if (parse_next_u64(argc, argv, &i, 0, UINT64_MAX, &parsed) != 0)
                return 2;
            task_count = parsed;
        }
        else if (strcmp(argv[i], "--task-bytes") == 0) {
            if (parse_next_u64(argc, argv, &i, TASKQ_MIN_BYTES,
                               TASKQ_MAX_BYTES, &parsed) != 0)
                return 2;
            task_bytes = (uint32_t)parsed;
        }
        else if (strcmp(argv[i], "--task-iters") == 0) {
            if (parse_next_u64(argc, argv, &i, 1, UINT64_MAX, &parsed) != 0)
                return 2;
            task_iters = parsed;
        }
        else if (strcmp(argv[i], "--runs") == 0) {
            if (parse_next_u64(argc, argv, &i, 1, MAX_RUNS, &parsed) != 0)
                return 2;
            num_runs = (int)parsed;
        }
        else if (strcmp(argv[i], "--no-encrypt") == 0)
            encrypt = 0;
        else if (strcmp(argv[i], "--output") == 0) {
            if (++i >= argc || argv[i][0] == '\0') {
                fprintf(stderr, "[MASTER] invalid or missing value for --output\n");
                return 2;
            }
            csv_file = argv[i];
        }
        else {
            fprintf(stderr, "[MASTER] unknown option: %s\n", argv[i]);
            return 2;
        }
    }
    if ((uint64_t)cg_n * (uint64_t)cg_nzpc > INT_MAX) {
        fprintf(stderr, "[MASTER] cg-n * cg-nzpc exceeds supported index range\n");
        return 2;
    }
    if (ep_n > INT64_MAX / target) {
        fprintf(stderr, "[MASTER] ep-n * worker count exceeds INT64_MAX\n");
        return 2;
    }
#ifndef SKIP_ATTESTATION
    if (!encrypt) {
        fprintf(stderr, "[MASTER] --no-encrypt is permitted only in the "
                        "explicit SKIP_ATTESTATION baseline build\n");
        return 2;
    }
#endif

    /* ── MPI + libsodium init ── */
    npb_mpi_init(&argc, &argv);
    if (sodium_init() < 0) { fprintf(stderr, "sodium_init failed\n"); MPI_Abort(MPI_COMM_WORLD, 1); }

    unsigned char owner_sign_sk[crypto_sign_SECRETKEYBYTES];
    if (load_secret_key(OWNER_SIGN_SK_ENV, owner_sign_sk,
                        sizeof owner_sign_sk) != 0) {
        MPI_Abort(MPI_COMM_WORLD, 1);
    }

    MPI_Comm workers[MAX_WORKERS];
    /* Directional AEAD keys (crypto_kx): wkey = master->worker (tx),
     * wkey_rx = worker->master (rx). Distinct keys per direction prevent
     * AEAD nonce reuse across the two directions. */
    unsigned char wkey[MAX_WORKERS][KEYB];
    unsigned char wkey_rx[MAX_WORKERS][KEYB];
    unsigned char channel_binding[MAX_WORKERS][HASH_LEN];
    int nworkers = 0;
    memset(send_nonce_ctr, 0, sizeof send_nonce_ctr);
    memset(recv_nonce_ctr, 0, sizeof recv_nonce_ctr);

    printf("============================================================\n");
    printf("  MPI + SEV-SNP Star Topology — NPB Kernel Benchmark\n");
    printf("============================================================\n");
    printf("  target_workers = %d\n", target);
    printf("  workload       = %s\n", workload_name(workload));
    if (workload == WORKLOAD_EP)
        printf("  ep_pairs/worker= %" PRId64 " (2^%.0f)\n", ep_n, log2((double)ep_n));
    else if (workload == WORKLOAD_CG)
        printf("  cg_n=%d  nzpc=%d  iters=%d\n", cg_n, cg_nzpc, cg_iters);
    else if (workload == WORKLOAD_STREAM)
        printf("  array/worker   = %u MiB x 3  warmup=%u\n",
               stream_array_mib, stream_warmup);
    else if (workload == WORKLOAD_RANDOM)
        printf("  links/worker   = %u MiB  accesses=%" PRIu64
               "  warmup=%" PRIu64 "\n",
               random_mib, random_accesses, random_warmup_accesses);
    else if (workload == WORKLOAD_VMAP)
        printf("  vector/worker  = %u MiB each direction\n", vmap_mib);
    else
        printf("  tasks          = %" PRIu64 " (0 => 100/worker)  bytes=%u"
               "  iters=%" PRIu64 "\n",
               task_count, task_bytes, task_iters);
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
        npb_wait_begin(NPB_WAIT_ENROLLMENT);
        double t_worker_start = MPI_Wtime();

        printf("[ENROLL] round %d/%d: waiting for worker...\n", round, target);

        MPI_Comm inter = MPI_COMM_NULL;
        int rc = bench_accept_worker(&inter);
        if (rc != MPI_SUCCESS) die_mpi("worker rendezvous", rc);

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
            fprintf(stderr, "[ENROLL] round %d: evidence too large, rejecting\n", round);
            npb_mpi_disconnect(&inter);
            npb_wait_end();
            continue;
        }
        if (evidence_len > 0) {
            evidence = (unsigned char *)malloc(evidence_len);
            if (!evidence) {
                fprintf(stderr, "malloc evidence failed\n");
                MPI_Abort(MPI_COMM_WORLD, 1);
            }
            mpi_recv_f(evidence, (int)evidence_len, MPI_UNSIGNED_CHAR, 0,
                       TAG_EA_EVIDENCE_DATA, inter, MPI_STATUS_IGNORE,
                       "Recv(EA_EVIDENCE_DATA)");
        }

        unsigned char evidence_hash[HASH_LEN];
        hash_evidence(evidence, evidence_len, evidence_hash);

        /* Validate EA Authenticator */
        int attest_ok = 1;
        if (ea_verify_payload(&auth_hdr.payload_hdr, ea_req.context,
                              auth_hdr.client_pk, crypto_kx_PUBLICKEYBYTES) != 0) {
            fprintf(stderr, "[ENROLL] round %d: binding verification FAILED\n", round);
            attest_ok = 0;
        }

        if (attest_ok && evidence_len > 0) {
            if (verify_sev_snp_report(
                    evidence, (int)evidence_len,
                    auth_hdr.payload_hdr.binder.binding) != 0) {
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
        mpi_send_f(&attest_ok, 1, MPI_INT, 0, TAG_EA_RESULT, inter, "Send(EA_RESULT)");
        if (!attest_ok) {
            fprintf(stderr, "[ENROLL] round %d: REJECTED\n", round);
            npb_mpi_disconnect(&inter);
            npb_wait_end();
            continue;
        }

        /* Owner-authenticated ECDH + transcript-bound key confirmation */
        struct kx_server_auth server_auth;
        unsigned char server_sk[crypto_kx_SECRETKEYBYTES];
        unsigned char raw_rx[KEYB], raw_tx[KEYB];
        unsigned char traffic_rx[KEYB], traffic_tx[KEYB];
        unsigned char confirm_rx[KEYB], confirm_tx[KEYB];
        unsigned char transcript_hash[HASH_LEN];

        crypto_kx_keypair(server_auth.server_pk, server_sk);
        compute_kx_transcript(ea_req.context, auth_hdr.client_pk,
                              server_auth.server_pk,
                              auth_hdr.payload_hdr.binder.binding,
                              evidence_hash, transcript_hash);
        if (crypto_sign_detached(server_auth.signature, NULL,
                                 transcript_hash, HASH_LEN,
                                 owner_sign_sk) != 0) {
            fprintf(stderr, "[MASTER] owner signature generation failed\n");
            sodium_memzero(server_sk, sizeof server_sk);
            npb_mpi_disconnect(&inter);
            npb_wait_end();
            continue;
        }
        mpi_send_f(&server_auth, sizeof server_auth, MPI_UNSIGNED_CHAR, 0,
                   TAG_KX_SERVER_AUTH, inter, "Send(KX_SERVER_AUTH)");

        if (crypto_kx_server_session_keys(raw_rx, raw_tx,
                                          server_auth.server_pk, server_sk,
                                          auth_hdr.client_pk) != 0) {
            fprintf(stderr, "[MASTER] crypto_kx failed\n");
            sodium_memzero(server_sk, sizeof server_sk);
            npb_mpi_disconnect(&inter);
            npb_wait_end();
            continue;
        }

        derive_bound_key(raw_tx, transcript_hash, "traffic:c2w", traffic_tx);
        derive_bound_key(raw_rx, transcript_hash, "traffic:w2c", traffic_rx);
        derive_bound_key(raw_tx, transcript_hash, "confirm:c2w", confirm_tx);
        derive_bound_key(raw_rx, transcript_hash, "confirm:w2c", confirm_rx);

        unsigned char client_finish[HASH_LEN];
        unsigned char expected_client_finish[HASH_LEN];
        mpi_recv_f(client_finish, HASH_LEN, MPI_UNSIGNED_CHAR, 0,
                   TAG_KX_CLIENT_FINISH, inter, MPI_STATUS_IGNORE,
                   "Recv(KX_CLIENT_FINISH)");
        compute_key_confirmation(confirm_rx, transcript_hash, "worker",
                                 expected_client_finish);
        if (sodium_memcmp(client_finish, expected_client_finish, HASH_LEN) != 0) {
            fprintf(stderr, "[MASTER] worker key confirmation failed\n");
            sodium_memzero(server_sk, sizeof server_sk);
            sodium_memzero(raw_rx, sizeof raw_rx);
            sodium_memzero(raw_tx, sizeof raw_tx);
            sodium_memzero(traffic_rx, sizeof traffic_rx);
            sodium_memzero(traffic_tx, sizeof traffic_tx);
            sodium_memzero(confirm_rx, sizeof confirm_rx);
            sodium_memzero(confirm_tx, sizeof confirm_tx);
            npb_mpi_disconnect(&inter);
            npb_wait_end();
            continue;
        }

        unsigned char server_finish[HASH_LEN];
        compute_key_confirmation(confirm_tx, transcript_hash, "central-node",
                                 server_finish);
        mpi_send_f(server_finish, HASH_LEN, MPI_UNSIGNED_CHAR, 0,
                   TAG_KX_SERVER_FINISH, inter, "Send(KX_SERVER_FINISH)");

        workers[nworkers] = inter;
        memcpy(wkey[nworkers], traffic_tx, KEYB);
        memcpy(wkey_rx[nworkers], traffic_rx, KEYB);
        memcpy(channel_binding[nworkers], transcript_hash, HASH_LEN);

        sodium_memzero(server_sk, sizeof server_sk);
        sodium_memzero(raw_rx, sizeof raw_rx);
        sodium_memzero(raw_tx, sizeof raw_tx);
        sodium_memzero(traffic_rx, sizeof traffic_rx);
        sodium_memzero(traffic_tx, sizeof traffic_tx);
        sodium_memzero(confirm_rx, sizeof confirm_rx);
        sodium_memzero(confirm_tx, sizeof confirm_tx);

        t_enroll_per_worker[nworkers] = (MPI_Wtime() - t_worker_start) * 1000.0;
        printf("[ENROLL] round %d: worker #%d enrolled in %.1f ms\n",
               round, nworkers + 1, t_enroll_per_worker[nworkers]);
        nworkers++;
         npb_wait_end();
    }

    double t_enroll_total = (MPI_Wtime() - t_enroll_start) * 1000.0;
    if (nworkers != target) {
        fprintf(stderr, "[MASTER] requested %d workers but enrolled %d; "
                        "aborting benchmark point\n", target, nworkers);
        for (int w = 0; w < nworkers; w++) {
            struct npb_cmd cmd = {0};
            cmd.cmd = CMD_NPB_DONE;
            secure_send(workers[w], wkey[w], channel_binding[w],
                        &send_nonce_ctr[w], &cmd, sizeof cmd, 0, TAG_NPB_CMD,
                        "Send(NPB_DONE_AFTER_PARTIAL_ENROLLMENT)");
            npb_mpi_disconnect(&workers[w]);
        }
        sodium_memzero(wkey, sizeof wkey);
        sodium_memzero(wkey_rx, sizeof wkey_rx);
        sodium_memzero(channel_binding, sizeof channel_binding);
        sodium_memzero(owner_sign_sk, sizeof owner_sign_sk);
        npb_mpi_finalize();
        return 1;
    }

    printf("\n[ENROLL] Total: %.1f ms (%d workers)\n\n", t_enroll_total, nworkers);

    if (workload == WORKLOAD_TASKQ && task_count == 0)
        task_count = UINT64_C(100) * (uint64_t)nworkers;

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
            secure_send(workers[w], wkey[w], channel_binding[w], &send_nonce_ctr[w],
                        &cmd, sizeof(cmd), 0, TAG_NPB_CMD, "Send(NPB_CMD_EP)");
        }

        double t_scatter_arr[MAX_RUNS], t_gather_arr[MAX_RUNS];
        double t_round_arr[MAX_RUNS], t_compute_max_arr[MAX_RUNS];

        for (int run = 1; run <= num_runs; run++)
        {
            /* Scatter: send seed per worker. */
            double t0 = MPI_Wtime();
            for (int w = 0; w < nworkers; w++) {
                int64_t seed = (int64_t)run * nworkers + w;
                workload_send_small(
                    workers[w], wkey[w], channel_binding[w], &send_nonce_ctr[w],
                    &seed, sizeof(seed), 0, TAG_NPB_CMD, encrypt,
                    "Send(EP_seed)");
            }
            double t1 = MPI_Wtime();

            /* Gather: receive results from each worker */
            struct ep_result total_result = {0};
            double t_compute_max = 0.0;

            for (int w = 0; w < nworkers; w++) {
                struct ep_result wr;
                if (workload_recv_small(
                        workers[w], wkey_rx[w], channel_binding[w],
                        &recv_nonce_ctr[w], &wr, sizeof(wr), 0,
                        TAG_NPB_EP_RESULT, encrypt, "Recv(EP_RESULT)") != 0) {
                    fprintf(stderr, "EP result recv failed from worker %d\n", w);
                    MPI_Abort(MPI_COMM_WORLD, 1);
                }
                int64_t worker_pairs = 0;
                for (int b = 0; b < EP_BINS; b++) {
                    if (wr.counts[b] < 0 || wr.counts[b] > ep_n - worker_pairs) {
                        fprintf(stderr, "EP invalid bin counts from worker %d\n", w);
                        MPI_Abort(MPI_COMM_WORLD, 1);
                    }
                    worker_pairs += wr.counts[b];
                    total_result.counts[b] += wr.counts[b];
                }
                if (worker_pairs != ep_n || !isfinite(wr.sx) || !isfinite(wr.sy)) {
                    fprintf(stderr, "EP invalid result from worker %d\n", w);
                    MPI_Abort(MPI_COMM_WORLD, 1);
                }
                total_result.sx += wr.sx;
                total_result.sy += wr.sy;

                double tw = 0.0;
        if (workload_recv_small(
            workers[w], wkey_rx[w], channel_binding[w],
            &recv_nonce_ctr[w], &tw, sizeof(tw), 0, TAG_NPB_TIME,
            encrypt, "Recv(EP_TIME)") != 0) {
                    fprintf(stderr, "EP time recv failed from worker %d\n", w);
                    MPI_Abort(MPI_COMM_WORLD, 1);
                }
                if (!isfinite(tw) || tw < 0.0) {
                    fprintf(stderr, "EP invalid compute time from worker %d\n", w);
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
    else if (workload == WORKLOAD_CG)
    {
        /* ── CG: Sparse Matrix-Vector Multiply (iterative) ──
         * Master generates sparse matrix, distributes row blocks.
         * Each iteration: master sends vector x → workers compute y=Ax → return y.
         * Tests frequent message exchange overhead.
         */
        printf("[NPB-CG] n=%d  nzpc=%d  iters=%d\n\n", cg_n, cg_nzpc, cg_iters);

        /* Generate sparse matrix */
        int *row_ptr, *col_idx;
        double *val;
        if (generate_sparse_matrix(cg_n, cg_nzpc, 42,
                       &row_ptr, &col_idx, &val) != 0) {
            fprintf(stderr, "[MASTER] CG matrix allocation failed\n");
            MPI_Abort(MPI_COMM_WORLD, 1);
        }

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
            secure_send(workers[w], wkey[w], channel_binding[w], &send_nonce_ctr[w],
                        &cmd, sizeof(cmd), 0, TAG_NPB_CMD, "Send(NPB_CMD_CG)");

            /* Send this worker's slice of the sparse matrix (CSR data) */
            int rs = row_starts[w];
            int rc_w = row_counts_arr[w];
            int nnz_w = row_ptr[rs + rc_w] - row_ptr[rs];

            /* Send: local row_ptr (rc_w+1 ints), col_idx (nnz_w ints), val (nnz_w doubles) */
            int *local_rp = (int *)malloc((size_t)(rc_w + 1) * sizeof(int));
            if (!local_rp) {
                fprintf(stderr, "[MASTER] CG local row_ptr allocation failed\n");
                MPI_Abort(MPI_COMM_WORLD, 1);
            }
            for (int r = 0; r <= rc_w; r++)
                local_rp[r] = row_ptr[rs + r] - row_ptr[rs];

            send_bulk(workers[w], wkey[w], channel_binding[w], &send_nonce_ctr[w],
                      local_rp, (size_t)(rc_w + 1) * sizeof(int),
                      0, TAG_NPB_CG_MATRIX, encrypt, "Send(CG_rowptr)");
            send_bulk(workers[w], wkey[w], channel_binding[w], &send_nonce_ctr[w],
                      col_idx + row_ptr[rs], (size_t)nnz_w * sizeof(int),
                      0, TAG_NPB_CG_MATRIX, encrypt, "Send(CG_colidx)");
            send_bulk(workers[w], wkey[w], channel_binding[w], &send_nonce_ctr[w],
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
        if (!x || !y) {
            fprintf(stderr, "[MASTER] CG vector allocation failed\n");
            free(x); free(y);
            free(row_ptr); free(col_idx); free(val);
            MPI_Abort(MPI_COMM_WORLD, 1);
        }
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
                    send_bulk(workers[w], wkey[w], channel_binding[w], &send_nonce_ctr[w],
                              x, (size_t)cg_n * sizeof(double),
                              0, TAG_NPB_CG_X, encrypt, "Send(CG_x)");
                }
                double t1 = MPI_Wtime();

                /* Gather: receive partial y from each worker */
                double t_compute_max = 0.0;
                for (int w = 0; w < nworkers; w++) {
                    int rc_w = row_counts_arr[w];
                    if (recv_bulk(workers[w], wkey_rx[w], channel_binding[w], &recv_nonce_ctr[w],
                                  y + row_starts[w], (size_t)rc_w * sizeof(double),
                                  0, TAG_NPB_CG_Y, encrypt, "Recv(CG_y)") != 0) {
                        fprintf(stderr, "CG y recv failed\n");
                        MPI_Abort(MPI_COMM_WORLD, 1);
                    }
                    double tw = 0.0;
                        if (workload_recv_small(
                            workers[w], wkey_rx[w], channel_binding[w],
                            &recv_nonce_ctr[w], &tw, sizeof(tw), 0,
                            TAG_NPB_TIME, encrypt, "Recv(CG_TIME)") != 0) {
                        fprintf(stderr, "CG time recv failed\n");
                        MPI_Abort(MPI_COMM_WORLD, 1);
                    }
                    if (!isfinite(tw) || tw < 0.0) {
                        fprintf(stderr, "CG invalid compute time\n");
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
    else if (workload == WORKLOAD_STREAM)
    {
        if (run_stream_master(nworkers, workers, wkey, wkey_rx,
                              channel_binding, encrypt, num_runs,
                              stream_array_mib, stream_warmup) != 0)
            MPI_Abort(MPI_COMM_WORLD, 1);
    }
    else if (workload == WORKLOAD_RANDOM)
    {
        if (run_random_master(nworkers, workers, wkey, wkey_rx,
                              channel_binding, encrypt, num_runs, random_mib,
                              random_accesses, random_warmup_accesses) != 0)
            MPI_Abort(MPI_COMM_WORLD, 1);
    }
    else if (workload == WORKLOAD_VMAP)
    {
        if (run_vmap_master(nworkers, workers, wkey, wkey_rx,
                            channel_binding, encrypt, num_runs,
                            vmap_mib) != 0)
            MPI_Abort(MPI_COMM_WORLD, 1);
    }
    else if (workload == WORKLOAD_TASKQ)
    {
        if (run_taskq_master(nworkers, workers, wkey, wkey_rx,
                             channel_binding, encrypt, num_runs, task_count,
                             task_bytes, task_iters) != 0)
            MPI_Abort(MPI_COMM_WORLD, 1);
    }

    /* ════════════════════════════════════════════════════════════════
     *  SHUTDOWN
     * ════════════════════════════════════════════════════════════════ */

    for (int w = 0; w < nworkers; w++) {
        struct npb_cmd cmd = {0};
        cmd.cmd = CMD_NPB_DONE;
        secure_send(workers[w], wkey[w], channel_binding[w], &send_nonce_ctr[w],
                    &cmd, sizeof(cmd), 0, TAG_NPB_CMD, "Send(NPB_DONE)");
        npb_mpi_disconnect(&workers[w]);
    }
    sodium_memzero(wkey, sizeof wkey);
    sodium_memzero(wkey_rx, sizeof wkey_rx);
    sodium_memzero(channel_binding, sizeof channel_binding);
    sodium_memzero(owner_sign_sk, sizeof owner_sign_sk);

    /* ════════════════════════════════════════════════════════════════
     *  OUTPUT CSV
     * ════════════════════════════════════════════════════════════════ */

    char csv_tmp[PATH_MAX];
    int csv_tmp_len = snprintf(csv_tmp, sizeof csv_tmp, "%s.tmp.%ld",
                               csv_file, (long)getpid());
    if (csv_tmp_len < 0 || (size_t)csv_tmp_len >= sizeof csv_tmp) {
        fprintf(stderr, "[OUTPUT] path is too long: %s\n", csv_file);
        npb_mpi_finalize();
        return 1;
    }

    int output_ok = 0;
    FILE *csv = fopen(csv_tmp, "w");
    if (csv) {
        const char *artifact_id = getenv(ARTIFACT_ID_ENV);
        if (!artifact_id || !*artifact_id) artifact_id = "unversioned";
        const char *placement_id = getenv(PLACEMENT_ID_ENV);
        if (!placement_id || !*placement_id) placement_id = "unverified";
        fprintf(csv, "# MPI+SEV-SNP Star Topology — NPB Kernel Benchmark\n");
        fprintf(csv, "# build_id: %s\n", PPDPC_BUILD_ID);
        fprintf(csv, "# artifact_id: %s\n", artifact_id);
        fprintf(csv, "# placement_id: %s\n", placement_id);
        fprintf(csv, "# workload: %s\n", workload_name(workload));
#ifdef SKIP_ATTESTATION
        fprintf(csv, "# attestation: skipped\n");
#else
        fprintf(csv, "# attestation: enabled\n");
#endif
        fprintf(csv, "# data_encryption: %s\n", encrypt ? "AEAD" : "plaintext");
        fprintf(csv, "# result_verification: workload-specific-every-run\n");
        fprintf(csv, "# runs: %d\n", num_runs);
        if (workload == WORKLOAD_EP)
            fprintf(csv, "# ep_pairs_per_worker: %" PRId64 "\n", ep_n);
        else if (workload == WORKLOAD_CG) {
            fprintf(csv, "# cg_n: %d\n", cg_n);
            fprintf(csv, "# cg_nzpc: %d\n", cg_nzpc);
            fprintf(csv, "# cg_iters: %d\n", cg_iters);
        }
        else if (workload == WORKLOAD_STREAM) {
            fprintf(csv, "# stream_array_mib: %u\n", stream_array_mib);
            fprintf(csv, "# stream_working_set_mib: %u\n", stream_array_mib * 3U);
            fprintf(csv, "# stream_warmup: %u\n", stream_warmup);
        }
        else if (workload == WORKLOAD_RANDOM) {
            fprintf(csv, "# random_mib: %u\n", random_mib);
            fprintf(csv, "# random_accesses: %" PRIu64 "\n", random_accesses);
            fprintf(csv, "# random_warmup_accesses: %" PRIu64 "\n",
                    random_warmup_accesses);
        }
        else if (workload == WORKLOAD_VMAP)
            fprintf(csv, "# vmap_mib: %u\n", vmap_mib);
        else if (workload == WORKLOAD_TASKQ) {
            fprintf(csv, "# task_count: %" PRIu64 "\n", task_count);
            fprintf(csv, "# task_bytes: %u\n", task_bytes);
            fprintf(csv, "# task_iters: %" PRIu64 "\n", task_iters);
        }
        fprintf(csv, "# enrollment_total_ms: %.1f\n", t_enroll_total);
        for (int w = 0; w < nworkers; w++)
            fprintf(csv, "# enrollment_worker%d_ms: %.1f\n", w+1, t_enroll_per_worker[w]);
        fprintf(csv, "#\n");
        fprintf(csv, "workload,num_workers,encryption,run,"
                     "t_scatter_ms,t_compute_max_ms,t_gather_ms,t_round_ms\n");
        for (int i = 0; i < g_nresults; i++) {
            struct npb_result *r = &g_results[i];
            fprintf(csv, "%s,%d,%s,%d,%.3f,%.3f,%.3f,%.3f\n",
                    workload_name(r->workload),
                    r->num_workers, r->encrypted ? "encrypted" : "plaintext",
                    r->run, r->t_scatter_ms, r->t_compute_max_ms,
                    r->t_gather_ms, r->t_round_ms);
        }
        int output_error = ferror(csv);
        if (fflush(csv) != 0) output_error = 1;
        if (!output_error && fsync(fileno(csv)) != 0) output_error = 1;
        if (fclose(csv) != 0) output_error = 1;
        if (!output_error && rename(csv_tmp, csv_file) == 0) {
            output_ok = 1;
            printf("[OUTPUT] Results written to %s\n", csv_file);
        } else {
            if (!output_error)
                fprintf(stderr, "[OUTPUT] rename failed for %s: %s\n",
                        csv_file, strerror(errno));
            else
                fprintf(stderr, "[OUTPUT] failed while writing %s\n", csv_file);
            remove(csv_tmp);
        }
    } else {
        fprintf(stderr, "[OUTPUT] could not open %s for writing: %s\n",
                csv_tmp, strerror(errno));
    }

    printf("\n[MASTER] benchmark complete.\n");
    npb_mpi_finalize();
    return output_ok ? 0 : 1;
}
