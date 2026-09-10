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
 *   mpicc -O2 -Wall -Wextra -o master_bench master_bench.c npb_timeout.c bench_rendezvous.c -lsodium -lm
 *
 * Compile (skip real SNP — for testing on non-CVM hosts):
 *   mpicc -DSKIP_ATTESTATION -O2 -Wall -Wextra -o master_bench master_bench.c npb_timeout.c bench_rendezvous.c -lsodium -lm
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

/* ── MPI message tags: benchmark data plane ── */
enum {
    TAG_BENCH_CMD  = 120,   /* bench_cmd struct (small, always encrypted)  */
    TAG_BENCH_A    = 121,   /* A_block matrix data (encrypted or plaintext)*/
    TAG_BENCH_B    = 122,   /* B matrix data (encrypted or plaintext)      */
    TAG_BENCH_C    = 123,   /* C_block result data (encrypted or plaintext)*/
    TAG_BENCH_TIME = 124    /* worker compute time (double, workload mode)   */
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

/* ── Benchmark command struct (fits in SECURE_MAX_PLAIN) ── */
struct bench_cmd {
    int32_t cmd;           /* CMD_BENCH_SIZE or CMD_BENCH_DONE */
    int32_t matrix_size;   /* M (square matrix dimension)      */
    int32_t row_start;     /* this worker's first row           */
    int32_t row_count;     /* number of rows for this worker    */
    int32_t encrypt_data;  /* 1 = AEAD, 0 = plaintext data plane */
    int32_t num_runs;      /* iterations for this size          */
};

/* ── Per-worker nonce counters for AEAD ── */
static uint64_t send_nonce_ctr[MAX_WORKERS];
static uint64_t recv_nonce_ctr[MAX_WORKERS];

/* ── Benchmark result storage ── */
#define MAX_SIZES   32
#define MAX_RUNS    1000
#define MAX_BENCH_MATRIX_DIM 8192
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
    npb_wait_begin(NPB_WAIT_SHUTDOWN);
    char es[MPI_MAX_ERROR_STRING];
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

/* ── Checked MPI wrappers ── */

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

    uint8_t expected_aik[HASH_LEN];
    uint8_t expected_binding[BINDING_LEN];
    ea_compute_binding(context, pub_key, pub_key_len,
                       expected_aik, expected_binding);

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
    mpi_send(buf, total, MPI_UNSIGNED_CHAR, dest, tag, comm, ctx);
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
    mpi_recv(buf, total, MPI_UNSIGNED_CHAR, src, tag, comm, &st, ctx);

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
    mpi_recv(data, data_bytes, MPI_UNSIGNED_CHAR, src, tag, comm, &status, ctx);
    int received_count = 0;
    MPI_Get_count(&status, MPI_UNSIGNED_CHAR, &received_count);
    if (received_count != data_bytes) {
        fprintf(stderr, "[MASTER] invalid plaintext workload length [%s]\n", ctx);
        return -1;
    }
    return 0;
}

/* ──────────────────────────────────────────────────────────────────────
 *  AEAD bulk send / recv — LARGE messages (matrix data)
 *  Single AEAD call over the full buffer.  ChaCha20-Poly1305 supports
 *  up to ~256 GB per message, so even large matrices are fine.
 * ────────────────────────────────────────────────────────────────────── */

static void send_matrix(MPI_Comm comm, const unsigned char key[KEYB],
                        const unsigned char channel_binding[HASH_LEN],
                        uint64_t *nonce_ctr,
                        const double *data, int num_doubles,
                        int dest, int tag, int encrypt, const char *ctx)
{
    if (!encrypt) {
        mpi_send(data, num_doubles, MPI_DOUBLE, dest, tag, comm, ctx);
        return;
    }

    if (num_doubles < 0 ||
        (size_t)num_doubles > ((size_t)INT_MAX - NPUB - ABYTES) / sizeof(double)) {
        fprintf(stderr, "[MASTER] matrix message is too large [%s]\n", ctx);
        MPI_Abort(MPI_COMM_WORLD, 1);
    }
    if (*nonce_ctr == UINT64_MAX) {
        fprintf(stderr, "[MASTER] AEAD nonce space exhausted [%s]\n", ctx);
        MPI_Abort(MPI_COMM_WORLD, 1);
    }
    size_t data_bytes = (size_t)num_doubles * sizeof(double);
    size_t total = NPUB + data_bytes + ABYTES;
    unsigned char *buf = (unsigned char *)malloc(total);
    if (!buf) {
        fprintf(stderr, "[MASTER] malloc(%zu) failed in send_matrix\n", total);
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
        fprintf(stderr, "[MASTER] matrix AEAD encryption failed [%s]\n", ctx);
        free(buf);
        MPI_Abort(MPI_COMM_WORLD, 1);
    }
    memcpy(buf, nonce, NPUB);

    mpi_send(buf, (int)total, MPI_UNSIGNED_CHAR, dest, tag, comm, ctx);
    *nonce_ctr = counter + 1;
    free(buf);
}

static int recv_matrix(MPI_Comm comm, const unsigned char key[KEYB],
                       const unsigned char channel_binding[HASH_LEN],
                       uint64_t *nonce_ctr,
                       double *data, int num_doubles,
                       int src, int tag, int encrypt, const char *ctx)
{
    if (num_doubles < 0) {
        fprintf(stderr, "[MASTER] negative matrix length [%s]\n", ctx);
        return -1;
    }
    if (!encrypt) {
        MPI_Status st;
        mpi_recv(data, num_doubles, MPI_DOUBLE, src, tag, comm, &st, ctx);
        int received_count = 0;
        MPI_Get_count(&st, MPI_DOUBLE, &received_count);
        if (received_count != num_doubles) {
            fprintf(stderr, "[MASTER] invalid plaintext matrix length [%s]\n", ctx);
            return -1;
        }
        return 0;
    }

    if ((size_t)num_doubles >
        ((size_t)INT_MAX - NPUB - ABYTES) / sizeof(double)) {
        fprintf(stderr, "[MASTER] matrix message is too large [%s]\n", ctx);
        return -1;
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

    int received_count = 0;
    MPI_Get_count(&st, MPI_UNSIGNED_CHAR, &received_count);
    if (received_count != (int)total) {
        fprintf(stderr, "[MASTER] invalid matrix ciphertext length [%s]\n", ctx);
        free(buf);
        return -1;
    }

    uint64_t received_ctr = 0;
    if (parse_nonce(buf, &received_ctr) != 0 || received_ctr != *nonce_ctr) {
        fprintf(stderr, "[MASTER] invalid matrix AEAD sequence [%s]\n", ctx);
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
        fprintf(stderr, "[MASTER] AEAD decryption FAILED in recv_matrix [%s]\n", ctx);
        free(buf);
        return -1;
    }

    *nonce_ctr = received_ctr + 1;
    free(buf);
    return 0;
}

/* ── Verification outside the measured interval ── */

static int verify_row(const double *A, const double *B,
                      const double *C, int M, int row)
{
    for (int j = 0; j < M; j++) {
        double expected = 0.0;
        for (int k = 0; k < M; k++)
            expected += A[(size_t)row * M + k] * B[(size_t)k * M + j];
        double actual = C[(size_t)row * M + j];
        double diff = fabs(expected - actual);
        double scale = fabs(expected) > 1.0 ? fabs(expected) : 1.0;
        if (diff / scale > 1e-9) {
            fprintf(stderr, "[MASTER] VERIFY FAIL: C[%d][%d] expected %.6e got %.6e\n",
                    row, j, expected, actual);
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

    if (target > MAX_WORKERS) {
        fprintf(stderr, "[MASTER] worker count %d exceeds limit %d\n",
                target, MAX_WORKERS);
        return 2;
    }
    if (num_runs > MAX_RUNS) {
        fprintf(stderr, "[MASTER] run count %d exceeds limit %d\n",
                num_runs, MAX_RUNS);
        return 2;
    }
    for (int i = 0; i < num_sizes; i++) {
        if (sizes[i] <= 0 || sizes[i] > MAX_BENCH_MATRIX_DIM) {
            fprintf(stderr, "[MASTER] matrix dimension %d is outside 1..%d\n",
                    sizes[i], MAX_BENCH_MATRIX_DIM);
            return 2;
        }
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
    if (sodium_init() < 0) {
        fprintf(stderr, "[MASTER] sodium_init failed\n");
        MPI_Abort(MPI_COMM_WORLD, 1);
    }

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
        npb_wait_begin(NPB_WAIT_ENROLLMENT);
        double t_worker_start = MPI_Wtime();

        printf("[ENROLL] round %d/%d: waiting for worker...\n", round, target);

        MPI_Comm inter = MPI_COMM_NULL;
        int rc = bench_accept_worker(&inter);
        if (rc != MPI_SUCCESS) die_mpi("worker rendezvous", rc);

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
            npb_mpi_disconnect(&inter);
            npb_wait_end();
            continue;
        }
        if (evidence_len > 0) {
            evidence = (unsigned char *)malloc(evidence_len);
            if (!evidence) { fprintf(stderr, "malloc evidence failed\n"); MPI_Abort(MPI_COMM_WORLD, 1); }
            mpi_recv(evidence, (int)evidence_len, MPI_UNSIGNED_CHAR, 0,
                     TAG_EA_EVIDENCE_DATA, inter, MPI_STATUS_IGNORE, "Recv(EA_EVIDENCE_DATA)");
        }

                unsigned char evidence_hash[HASH_LEN];
                hash_evidence(evidence, evidence_len, evidence_hash);

        /* ── Validate EA Authenticator ── */
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

        mpi_send(&attest_ok, 1, MPI_INT, 0, TAG_EA_RESULT, inter, "Send(EA_RESULT)");
        if (!attest_ok) {
            fprintf(stderr, "[ENROLL] round %d: REJECTED\n", round);
            npb_mpi_disconnect(&inter);
            npb_wait_end();
            continue;
        }

        /* ── Owner-authenticated ECDH + transcript-bound key confirmation ── */
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
        mpi_send(&server_auth, sizeof server_auth, MPI_UNSIGNED_CHAR, 0,
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
        mpi_recv(client_finish, HASH_LEN, MPI_UNSIGNED_CHAR, 0,
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
        mpi_send(server_finish, HASH_LEN, MPI_UNSIGNED_CHAR, 0,
                 TAG_KX_SERVER_FINISH, inter, "Send(KX_SERVER_FINISH)");

        if (nworkers >= MAX_WORKERS) {
            fprintf(stderr, "[MASTER] too many workers\n");
            MPI_Abort(MPI_COMM_WORLD, 1);
        }
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
            struct bench_cmd cmd;
            memset(&cmd, 0, sizeof cmd);
            cmd.cmd = CMD_BENCH_DONE;
            secure_send(workers[w], wkey[w], channel_binding[w],
                        &send_nonce_ctr[w], &cmd, sizeof cmd, 0, TAG_BENCH_CMD,
                        "Send(BENCH_DONE_AFTER_PARTIAL_ENROLLMENT)");
            npb_mpi_disconnect(&workers[w]);
        }
        sodium_memzero(wkey, sizeof wkey);
        sodium_memzero(wkey_rx, sizeof wkey_rx);
        sodium_memzero(channel_binding, sizeof channel_binding);
        sodium_memzero(owner_sign_sk, sizeof owner_sign_sk);
        npb_mpi_finalize();
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
        size_t mat_elems = (size_t)M * (size_t)M;
        if (mat_elems > (size_t)INT_MAX) {
            fprintf(stderr, "[BENCH] matrix element count exceeds MPI limit\n");
            continue;
        }
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
            secure_send(workers[w], wkey[w], channel_binding[w],
                        &send_nonce_ctr[w],
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

                send_matrix(workers[w], wkey[w], channel_binding[w],
                            &send_nonce_ctr[w],
                            A + (size_t)rs * M, a_elems,
                            0, TAG_BENCH_A, encrypt, "Send(A_block)");
                send_matrix(workers[w], wkey[w], channel_binding[w],
                            &send_nonce_ctr[w],
                            B, (int)mat_elems,
                            0, TAG_BENCH_B, encrypt, "Send(B)");
            }

            double t1 = MPI_Wtime();

            /* Gather: receive C_blocks + compute times */
            double t_compute_max = 0.0;

            for (int w = 0; w < nworkers; w++) {
                int c_elems = row_counts[w] * M;
                double *C_block = C + (size_t)row_starts[w] * M;

                if (recv_matrix(workers[w], wkey_rx[w], channel_binding[w],
                                &recv_nonce_ctr[w],
                                C_block, c_elems,
                                0, TAG_BENCH_C, encrypt, "Recv(C_block)") != 0) {
                    fprintf(stderr, "[BENCH] recv C_block FAILED from worker #%d\n", w + 1);
                    MPI_Abort(MPI_COMM_WORLD, 1);
                }

                double t_compute_w = 0.0;
                if (workload_recv_small(
                    workers[w], wkey_rx[w], channel_binding[w],
                    &recv_nonce_ctr[w], &t_compute_w, sizeof(double),
                    0, TAG_BENCH_TIME, encrypt,
                    "Recv(compute_time)") != 0 ||
                    !isfinite(t_compute_w) || t_compute_w < 0.0) {
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

            if (verify && run == num_runs) {
                for (int w = 0; w < nworkers; w++) {
                    int row = row_starts[w] + row_counts[w] / 2;
                    if (verify_row(A, B, C, M, row) != 0) {
                        fprintf(stderr, "[BENCH] run %d: verification FAILED "
                                        "for worker #%d\n", run, w + 1);
                        MPI_Abort(MPI_COMM_WORLD, 1);
                    }
                }
                printf("[BENCH] run %d: verification PASSED for all workers\n",
                       run);
            }

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
        secure_send(workers[w], wkey[w], channel_binding[w],
                &send_nonce_ctr[w],
                    &cmd, sizeof(cmd), 0, TAG_BENCH_CMD, "Send(BENCH_DONE)");
        npb_mpi_disconnect(&workers[w]);
    }

    sodium_memzero(wkey, sizeof wkey);
    sodium_memzero(wkey_rx, sizeof wkey_rx);
    sodium_memzero(channel_binding, sizeof channel_binding);
    sodium_memzero(owner_sign_sk, sizeof owner_sign_sk);

    /* ════════════════════════════════════════════════════════════════
     *  OUTPUT — write CSV results file
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
        fprintf(csv, "# MPI+SEV-SNP Star Topology — DGEMM Benchmark\n");
        fprintf(csv, "# build_id: %s\n", PPDPC_BUILD_ID);
        fprintf(csv, "# artifact_id: %s\n", artifact_id);
        fprintf(csv, "# placement_id: %s\n", placement_id);
#ifdef SKIP_ATTESTATION
        fprintf(csv, "# attestation: skipped\n");
#else
        fprintf(csv, "# attestation: enabled\n");
#endif
        fprintf(csv, "# data_encryption: %s\n", encrypt ? "AEAD" : "plaintext");
        fprintf(csv, "# result_verification: %s\n",
            verify ? "one-row-per-partition-final-run" : "disabled");
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

    printf("\n[MASTER] Benchmark complete.\n");
    npb_mpi_finalize();
    return output_ok ? 0 : 1;
}
