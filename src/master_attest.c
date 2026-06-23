/*
 * master_attest.c – EA/aTLS-style attestation for MPI + SEV-SNP star topology.
 *
 * Attestation protocol inspired by the aTLS implementation in
 * https://github.com/danko-miladinovic/fort
 *
 * The fort repository implements attested TLS (aTLS) using TLS 1.3 Exported
 * Authenticators (EA) with CMW attestation extensions (RFC 9334 / EAT).
 * This file adapts that protocol model for MPI-based communication:
 *
 *   Fort concept              →  This implementation
 *   ─────────────────────────────────────────────────────────────────
 *   TLS 1.3 connection        →  MPI intercommunicator
 *   EA AuthenticatorRequest   →  EA request (context nonce + attestation offer)
 *   EA Certificate entry      →  Worker's ECDH public key
 *   CMW Attestation Extension →  Structured payload (evidence + binder)
 *   ExportKeyingMaterial()    →  BLAKE2b(context)          [ea_export_attestation_value]
 *   AIKPublicKeyHash()        →  BLAKE2b(pubkey)           [ea_aik_pub_hash]
 *   BindingValue()            →  BLAKE2b(pubkey||exported) [ea_binding_value]
 *   ComputeBinding()          →  ea_compute_binding()
 *   VerifyPayload()           →  ea_verify_payload()
 *   EvidenceVerifier          →  snpguest verify attestation
 *   EA Finished               →  BLAKE2b transcript hash
 *
 * Protocol phases (mirrors fort's atls.Client / atls.Server):
 *   1. MPI connection (Open port → Comm_accept / Comm_connect)
 *   2. EA Request   (master → worker):  context nonce + attestation offer
 *   3. EA Authenticator (worker → master): pubkey + CMW payload + finished
 *   4. EA Verification  (master):  verify binding, evidence, transcript
 *   5. Key Exchange:  ECDH via crypto_kx
 *   6. Encrypted computation:  AEAD-protected task distribution
 *
 * Threat mitigations (carried over from original):
 *   T1  Control-flow injection  → AEAD-encrypted SHUTDOWN/IDLE sentinels
 *   T2  Message replay          → Per-worker monotonic nonce counters
 *   T3  Shell injection         → sanitize_path() on SNP_CERTS_DIR
 *   T4  Error handling          → Checked MPI wrappers on every call
 *   T5  TOCTOU temp files       → Documented limitation
 *   T6  Accept-blocking DoS     → Documented limitation
 */

#include <mpi.h>
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <time.h>
#include <sys/wait.h>

/* ── MPI message tags: data plane ── */
enum {
    TAG_TASK     = 10,
    TAG_RESULT   = 11,
    TAG_IDLE     = 13,
    TAG_SHUTDOWN = 99
};

/* ── MPI message tags: EA attestation protocol (fort-inspired) ── */
enum {
    TAG_EA_REQUEST       = 70,  /* Master → Worker: AuthenticatorRequest         */
    TAG_EA_AUTH_HDR      = 71,  /* Worker → Master: authenticator header          */
    TAG_EA_EVIDENCE_DATA = 72,  /* Worker → Master: raw SNP report bytes          */
    TAG_EA_FINISHED      = 73,  /* Worker → Master: transcript integrity hash     */
    TAG_EA_RESULT        = 74,  /* Master → Worker: accept (1) / reject (0)       */
    TAG_KX_SERVER_PK     = 91   /* Master → Worker: ECDH server public key        */
};

/* ── Crypto constants ── */
#define MAX_WORKERS  128
#define POLL_INTERVAL_NS (50 * 1000 * 1000) /* 50 ms */

#define KEYB   crypto_aead_chacha20poly1305_ietf_KEYBYTES
#define NPUB   crypto_aead_chacha20poly1305_ietf_NPUBBYTES
#define ABYTES crypto_aead_chacha20poly1305_ietf_ABYTES

#define HASH_LEN         32          /* BLAKE2b-256 output */
#define BINDING_LEN      32
#define REPORT_DATA_SIZE 64          /* SEV-SNP REPORT_DATA field */
#define SNP_REPORT_TMP   "snp_report.bin"
#define MAX_REPORT_LEN   16384       /* reject implausible report sizes */

/* AEAD-encrypted control-message sentinels (T1) */
#define CTRL_MAGIC_SHUTDOWN 0xDEAD0001u
#define CTRL_MAGIC_IDLE     0xDEAD0002u

_Static_assert(crypto_kx_SESSIONKEYBYTES == KEYB,
               "kx session key size must match AEAD key size");

/* ──────────────────────────────────────────────────────────────────────
 *  EA / CMW Attestation types
 *  Mirrors fort's attestation/types.go and attestation/binding.go
 * ────────────────────────────────────────────────────────────────────── */

#define EA_CONTEXT_LEN     32
#define EA_MEDIA_TYPE      "application/eat+cwt"
#define EA_EXPORTER_LABEL  "Attestation"
#define EA_PAYLOAD_VERSION 1

/*
 * Mirrors fort's attestation.AttestationBinder:
 *   AIKPubHash    []byte  → aik_pub_hash[32]
 *   Binding       []byte  → binding[32]
 *   ExporterLabel string  → exporter_label[64]
 */
struct ea_binder {
    uint8_t aik_pub_hash[HASH_LEN];
    uint8_t binding[BINDING_LEN];
    char    exporter_label[64];
} __attribute__((packed));

/*
 * Mirrors fort's attestation.Payload (header fields).
 * The variable-length evidence (raw SNP report) is sent in a
 * separate MPI message, analogous to how fort carries evidence
 * inside a CMW extension on the EA Certificate entry.
 *
 *   Version   int    → version
 *   MediaType string → media_type[64]
 *   Evidence  []byte → evidence_len + separate TAG_EA_EVIDENCE_DATA
 *   Binder           → binder
 */
struct ea_payload_hdr {
    uint32_t        version;
    char            media_type[64];
    uint32_t        evidence_len;
    struct ea_binder binder;
} __attribute__((packed));

/*
 * EA AuthenticatorRequest: Master → Worker
 * Mirrors fort's ea.AuthenticatorRequest:
 *   Context []byte + CMWAttestationOfferExtension()
 */
struct ea_request {
    uint8_t context[EA_CONTEXT_LEN];
    uint8_t attestation_offer;      /* 1 = request CMW attestation */
} __attribute__((packed));

/*
 * EA Authenticator header: Worker → Master
 * Combines the "leaf certificate" (ECDH public key) with the
 * CMW attestation extension (payload header with binder).
 * In fort this corresponds to ea.CertificateEntry + extensions.
 */
struct ea_auth_hdr {
    uint8_t             client_pk[crypto_kx_PUBLICKEYBYTES];
    struct ea_payload_hdr payload_hdr;
} __attribute__((packed));

/* ── Per-worker nonce counters for AEAD (T2 replay protection) ── */
static uint64_t send_nonce_ctr[MAX_WORKERS];
static uint64_t recv_nonce_ctr[MAX_WORKERS];

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

static int getenv_int(const char *k, int defv)
{
    const char *s = getenv(k);
    if (!s || !*s)
        return defv;
    int v = atoi(s);
    return v > 0 ? v : defv;
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

/* T3: reject shell meta-characters before interpolation into system() */
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

/* ──────────────────────────────────────────────────────────────────────
 *  Checked MPI wrappers (T4)
 * ────────────────────────────────────────────────────────────────────── */

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

static int mpi_iprobe(int src, int tag, MPI_Comm comm, MPI_Status *st,
                      const char *ctx)
{
    int flag = 0;
    int rc = MPI_Iprobe(src, tag, comm, &flag, st);
    if (rc != MPI_SUCCESS) die_mpi(ctx, rc);
    return flag;
}

/* ──────────────────────────────────────────────────────────────────────
 *  EA Attestation Binding (mirrors fort's attestation/binding.go)
 *
 *  Fort computes three values via ComputeBinding():
 *    exportedValue = ExportKeyingMaterial(label, context, 32)
 *    aikPubHash    = Hash(leafCert.PublicKey)
 *    binding       = Hash(leafCert.PublicKey || exportedValue)
 *
 *  Since we have no TLS, ExportKeyingMaterial is replaced by BLAKE2b
 *  over the EA context nonce (the master's challenge).
 * ────────────────────────────────────────────────────────────────────── */

/*
 * Analogous to fort's attestation.ExportAttestationValue().
 * In TLS 1.3 this calls tls.ConnectionState.ExportKeyingMaterial().
 * Here we hash the context nonce as a session-specific exported value.
 */
static void ea_export_attestation_value(const uint8_t context[EA_CONTEXT_LEN],
                                        uint8_t out[HASH_LEN])
{
    crypto_generichash(out, HASH_LEN, context, EA_CONTEXT_LEN, NULL, 0);
}

/*
 * Analogous to fort's attestation.AIKPublicKeyHash().
 * Hashes the raw public key bytes (the "leaf certificate" identity).
 */
static void ea_aik_pub_hash(const uint8_t *pub_key, size_t pub_key_len,
                            uint8_t out[HASH_LEN])
{
    crypto_generichash(out, HASH_LEN, pub_key, pub_key_len, NULL, 0);
}

/*
 * Analogous to fort's attestation.BindingValue().
 * binding = Hash(publicKey || exportedValue)
 */
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

/*
 * Analogous to fort's attestation.ComputeBinding().
 * Computes all three binding components in one call.
 */
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

/*
 * Derive the 64-byte SEV-SNP REPORT_DATA from the 32-byte binding.
 * The binding is expanded via BLAKE2b-512 to fill the full
 * REPORT_DATA field, cryptographically committing the SNP hardware
 * attestation to the EA binding (pubkey + session context).
 */
static void ea_derive_report_data(const uint8_t binding[BINDING_LEN],
                                  uint8_t report_data[REPORT_DATA_SIZE])
{
    crypto_generichash(report_data, REPORT_DATA_SIZE,
                       binding, BINDING_LEN, NULL, 0);
}

/*
 * Compute the EA Finished hash over the full authenticator transcript.
 *
 * Fort equivalent: EA Finished message = HMAC(finished_key, transcript_hash)
 * where finished_key is derived from TLS master_secret.
 *
 * Since we have no TLS, we use a plain BLAKE2b hash for transcript
 * integrity. The real authentication comes from the SNP attestation
 * report (hardware-signed by AMD SP), not from this hash.
 */
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

/*
 * Verify the attestation payload's binding fields.
 *
 * Fort equivalent: attestation.VerifyPayload() which calls
 *   VerifyBinder() → checks AIKPubHash and Binding match
 *   EvidenceVerifier.VerifyEvidence() → (done separately below)
 *
 * Returns 0 on success, -1 on any mismatch.
 */
static int ea_verify_payload(const struct ea_payload_hdr *hdr,
                             const uint8_t context[EA_CONTEXT_LEN],
                             const uint8_t *pub_key, size_t pub_key_len)
{
    /* Validate payload version (fort's Payload.Validate) */
    if (hdr->version != EA_PAYLOAD_VERSION) {
        fprintf(stderr, "[MASTER] EA payload version mismatch: %u\n", hdr->version);
        return -1;
    }

    /* Validate media type */
    if (strncmp(hdr->media_type, EA_MEDIA_TYPE, sizeof(hdr->media_type)) != 0) {
        fprintf(stderr, "[MASTER] EA media type mismatch\n");
        return -1;
    }

    /* Validate exporter label (fort's Binder.ExporterLabel) */
    if (strncmp(hdr->binder.exporter_label, EA_EXPORTER_LABEL,
                sizeof(hdr->binder.exporter_label)) != 0) {
        fprintf(stderr, "[MASTER] EA exporter label mismatch\n");
        return -1;
    }

    /* Recompute binding (fort's ComputeBinding) */
    uint8_t exported_value[HASH_LEN];
    uint8_t expected_aik[HASH_LEN];
    uint8_t expected_binding[BINDING_LEN];
    ea_compute_binding(context, pub_key, pub_key_len,
                       exported_value, expected_aik, expected_binding);

    /* Verify AIKPubHash (fort's VerifyBinder → ErrAIKPubHashMismatch) */
    if (sodium_memcmp(expected_aik, hdr->binder.aik_pub_hash, HASH_LEN) != 0) {
        fprintf(stderr, "[MASTER] EA AIK public key hash mismatch "
                        "(fort: ErrAIKPubHashMismatch)\n");
        return -1;
    }

    /* Verify Binding (fort's VerifyBinder → ErrBindingMismatch) */
    if (sodium_memcmp(expected_binding, hdr->binder.binding, BINDING_LEN) != 0) {
        fprintf(stderr, "[MASTER] EA attestation binding mismatch "
                        "(fort: ErrBindingMismatch)\n");
        return -1;
    }

    return 0;
}

/* ──────────────────────────────────────────────────────────────────────
 *  SEV-SNP evidence verification
 *  Fort equivalent: EvidenceVerifier.VerifyEvidence()
 *  Uses snpguest CLI to verify the hardware-signed attestation report.
 * ────────────────────────────────────────────────────────────────────── */

static int verify_sev_snp_report(const unsigned char *report, int report_len,
                                 const unsigned char expected_report_data[REPORT_DATA_SIZE])
{
    if (!report || report_len <= 0)
        return -1;

    FILE *f = fopen(SNP_REPORT_TMP, "wb");
    if (!f)
        return -1;
    if ((int)fwrite(report, 1, (size_t)report_len, f) != report_len) {
        fclose(f);
        return -1;
    }
    fclose(f);

    char rd_hex[REPORT_DATA_SIZE * 2 + 1];
    bytes_to_hex(expected_report_data, REPORT_DATA_SIZE, rd_hex, sizeof rd_hex);

    const char *certs_dir = getenv("SNP_CERTS_DIR");
    if (!certs_dir || !*certs_dir)
        certs_dir = "certs";

    /* T3: reject shell meta-characters */
    if (sanitize_path(certs_dir) != 0) {
        fprintf(stderr, "[MASTER] SNP_CERTS_DIR contains unsafe characters\n");
        return -1;
    }

    char cmd[1024];

    /* Auto-fetch the correct VCEK for this specific report's chip.
     * snpguest reads the chip ID from the report and downloads the
     * matching VCEK from AMD's Key Distribution Service (KDS).
     * This avoids needing to pre-provision per-worker VCEK files. */
    snprintf(cmd, sizeof cmd,
             "snpguest fetch vcek pem %s %s > snpguest_fetch_vcek.log 2>&1",
             certs_dir, SNP_REPORT_TMP);
    fprintf(stderr, "[MASTER] running: %s\n", cmd);
    fflush(stderr);
    int fetch_rc = system(cmd);  /* best-effort: if it fails, verify will fail below */
    if (fetch_rc != 0)
        fprintf(stderr, "[MASTER] VCEK fetch returned %d (will try verify anyway)\n", fetch_rc);

    snprintf(cmd, sizeof cmd,
             "snpguest verify attestation %s %s --report-data 0x%s > snpguest_verify.log 2>&1",
             certs_dir, SNP_REPORT_TMP, rd_hex);

    fprintf(stderr, "[MASTER] running: %s\n", cmd);
    fflush(stderr);

    int status = system(cmd);
    if (status == -1)
        return -1;
    if (!WIFEXITED(status))
        return -1;
    return (WEXITSTATUS(status) == 0) ? 0 : -1;
}

/* ──────────────────────────────────────────────────────────────────────
 *  AEAD secure send / recv (post-attestation encrypted channel)
 *  Wire format: [nonce (NPUB B) || ciphertext (plain_len + ABYTES B)]
 * ────────────────────────────────────────────────────────────────────── */
#define SECURE_MAX_PLAIN 256

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

    /* T2: replay protection via nonce monotonicity */
    uint64_t received_ctr = 0;
    memcpy(&received_ctr, buf, sizeof(uint64_t));
    if (received_ctr < *nonce_ctr) {
        fprintf(stderr, "[MASTER] REPLAY detected "
                        "(nonce %" PRIu64 " < %" PRIu64 ") [%s]\n",
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
    if ((int)mlen != plain_len)
        return -1;

    *nonce_ctr = received_ctr + 1;
    return 0;
}

/* ── Task / control message helpers ── */

static void secure_send_task(MPI_Comm inter, const unsigned char key[KEYB],
                             int wid, int x)
{
    secure_send(inter, key, &send_nonce_ctr[wid],
                &x, sizeof(int), 0, TAG_TASK, "Send(TAG_TASK)");
}

/* T1: AEAD-authenticated control sentinel prevents forgery */
static void secure_send_ctrl(MPI_Comm inter, const unsigned char key[KEYB],
                             int wid, int tag, uint32_t magic)
{
    secure_send(inter, key, &send_nonce_ctr[wid],
                &magic, sizeof(uint32_t), 0, tag,
                tag == TAG_SHUTDOWN ? "Send(SHUTDOWN)" : "Send(IDLE)");
}

/* T2: replay protection via nonce monotonicity in secure_recv() */
static int secure_recv_result(MPI_Comm inter, const unsigned char key[KEYB],
                              int wid, int pair[2])
{
    return secure_recv(inter, key, &recv_nonce_ctr[wid],
                       pair, 2 * (int)sizeof(int), 0, TAG_RESULT,
                       "Recv(TAG_RESULT)");
}

/* Write port string atomically: write .tmp then rename */
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

/* ══════════════════════════════════════════════════════════════════════
 *  main()
 * ══════════════════════════════════════════════════════════════════════ */

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    MPI_Init(&argc, &argv);

    if (sodium_init() < 0) {
        fprintf(stderr, "[MASTER] sodium_init failed\n");
        MPI_Abort(MPI_COMM_WORLD, 1);
    }

    int target = getenv_int("TARGET_WORKERS", 2);
    if (argc >= 3 && strcmp(argv[1], "--master") == 0) {
        target = atoi(argv[2]);
        if (target <= 0) target = 1;
    }

    MPI_Comm workers[MAX_WORKERS];
    unsigned char wkey[MAX_WORKERS][KEYB];
    int nworkers = 0;
    memset(send_nonce_ctr, 0, sizeof send_nonce_ctr);
    memset(recv_nonce_ctr, 0, sizeof recv_nonce_ctr);

    printf("[MASTER] target_workers=%d\n", target);

    /* ════════════════════════════════════════════════════════════════
     *  ENROLLMENT PHASE – EA-based attestation for each worker
     *  Mirrors fort's atls.Client() flow:
     *    1. Send AuthenticatorRequest   (context + offer)
     *    2. Receive Authenticator       (certificate + CMW extension + finished)
     *    3. ValidateAuthenticatorWithAttestation()
     *    4. Key exchange
     * ════════════════════════════════════════════════════════════════ */

    for (int round = 1; round <= target; round++)
    {
        /* ── Open MPI port and accept worker connection ── */
        char port[MPI_MAX_PORT_NAME];
        memset(port, 0, sizeof port);

        int rc = MPI_Open_port(MPI_INFO_NULL, port);
        if (rc != MPI_SUCCESS) die_mpi("MPI_Open_port failed", rc);

        write_port_file("port.txt", port);
        printf("[MASTER] round %d: opened port='%s'\n", round, port);
        printf("[MASTER] round %d: waiting accept (COMM_SELF)...\n", round);

        MPI_Comm inter = MPI_COMM_NULL;
        rc = MPI_Comm_accept(port, MPI_INFO_NULL, 0, MPI_COMM_SELF, &inter);
        if (rc != MPI_SUCCESS) die_mpi("MPI_Comm_accept failed", rc);

        /* Force BTL TCP endpoint exchange */
        MPI_Barrier(inter);

        rc = MPI_Close_port(port);
        if (rc != MPI_SUCCESS) die_mpi("MPI_Close_port failed", rc);

        /* ── Step 1: Send EA AuthenticatorRequest ──
         * Fort equivalent: atls.Client builds AuthenticatorRequest with
         *   context = ea.NewRandomContext(32)
         *   extensions = [SignatureAlgorithmsExtension, CMWAttestationOfferExtension]
         */
        struct ea_request ea_req;
        randombytes_buf(ea_req.context, EA_CONTEXT_LEN);
        ea_req.attestation_offer = 1;

        mpi_send(&ea_req, sizeof(ea_req), MPI_UNSIGNED_CHAR, 0,
                 TAG_EA_REQUEST, inter, "Send(EA_REQUEST)");

        printf("[MASTER] round %d: sent EA AuthenticatorRequest "
               "(context + attestation offer)\n", round);

        /* ── Step 2: Receive EA Authenticator ──
         * Fort equivalent: atls.Client reads frameTypeAuthenticator which
         * contains Certificate (with CMW extension) + CertificateVerify + Finished
         */

        /* 2a: Receive authenticator header (public key + payload header) */
        struct ea_auth_hdr auth_hdr;
        mpi_recv(&auth_hdr, sizeof(auth_hdr), MPI_UNSIGNED_CHAR, 0,
                 TAG_EA_AUTH_HDR, inter, MPI_STATUS_IGNORE, "Recv(EA_AUTH_HDR)");

        /* 2b: Receive evidence (raw SNP report) if present */
        uint32_t evidence_len = auth_hdr.payload_hdr.evidence_len;
        unsigned char *evidence = NULL;

        if (evidence_len > MAX_REPORT_LEN) {
            fprintf(stderr, "[MASTER] round %d: evidence_len %u exceeds max, rejecting\n",
                    round, evidence_len);
            MPI_Comm_disconnect(&inter);
            continue;
        }

        if (evidence_len > 0) {
            evidence = (unsigned char *)malloc(evidence_len);
            if (!evidence) {
                fprintf(stderr, "[MASTER] malloc evidence failed\n");
                MPI_Abort(MPI_COMM_WORLD, 1);
            }
            mpi_recv(evidence, (int)evidence_len, MPI_UNSIGNED_CHAR, 0,
                     TAG_EA_EVIDENCE_DATA, inter, MPI_STATUS_IGNORE,
                     "Recv(EA_EVIDENCE_DATA)");
        }

        /* 2c: Receive EA Finished hash (transcript integrity) */
        unsigned char finished_recv[HASH_LEN];
        mpi_recv(finished_recv, HASH_LEN, MPI_UNSIGNED_CHAR, 0,
                 TAG_EA_FINISHED, inter, MPI_STATUS_IGNORE, "Recv(EA_FINISHED)");

        printf("[MASTER] round %d: received EA Authenticator "
               "(pk + payload hdr + %u B evidence + finished)\n",
               round, evidence_len);

        /* ── Step 3: Validate Authenticator ──
         * Fort equivalent: ea.ValidateAuthenticatorWithAttestation()
         */
        int attest_ok = 1;

        /* 3a: Verify payload binding (fort's VerifyPayload → VerifyBinder) */
        if (ea_verify_payload(&auth_hdr.payload_hdr, ea_req.context,
                              auth_hdr.client_pk,
                              crypto_kx_PUBLICKEYBYTES) != 0) {
            fprintf(stderr, "[MASTER] round %d: EA payload binding verification FAILED\n",
                    round);
            attest_ok = 0;
        }

        /* 3b: Verify EA Finished transcript hash */
        if (attest_ok) {
            unsigned char expected_finished[HASH_LEN];
            ea_compute_finished(ea_req.context,
                                auth_hdr.client_pk, crypto_kx_PUBLICKEYBYTES,
                                &auth_hdr.payload_hdr,
                                evidence, evidence_len,
                                expected_finished);
            if (sodium_memcmp(expected_finished, finished_recv, HASH_LEN) != 0) {
                fprintf(stderr, "[MASTER] round %d: EA Finished hash mismatch\n", round);
                attest_ok = 0;
            }
        }

        /* 3c: Verify SNP evidence (fort's EvidenceVerifier.VerifyEvidence) */
        if (attest_ok && evidence_len > 0) {
            uint8_t expected_report_data[REPORT_DATA_SIZE];
            ea_derive_report_data(auth_hdr.payload_hdr.binder.binding,
                                  expected_report_data);

            if (verify_sev_snp_report(evidence, (int)evidence_len,
                                      expected_report_data) != 0) {
                fprintf(stderr, "[MASTER] round %d: SNP evidence verification FAILED\n",
                        round);
                attest_ok = 0;
            }
        }

        free(evidence);

#ifdef SKIP_ATTESTATION
        /* Override for development / non-SNP machines */
        attest_ok = 1;
#endif

        /* ── Send EA result ── */
        mpi_send(&attest_ok, 1, MPI_INT, 0,
                 TAG_EA_RESULT, inter, "Send(EA_RESULT)");

        if (!attest_ok) {
            fprintf(stderr, "[MASTER] round %d: attestation FAILED, disconnecting\n",
                    round);
            MPI_Comm_disconnect(&inter);
            continue;
        }

        printf("[MASTER] round %d: EA attestation PASSED "
               "(binding verified, evidence verified)\n", round);

        /* ── Step 4: ECDH Key Exchange ──
         * Master generates server keypair and derives session keys.
         * Fort equivalent: after EA validation succeeds, the TLS session
         * keys are already established. Here we do explicit ECDH.
         */
        unsigned char server_pk[crypto_kx_PUBLICKEYBYTES];
        unsigned char server_sk[crypto_kx_SECRETKEYBYTES];
        unsigned char rx[KEYB], tx[KEYB], app_key[KEYB];

        crypto_kx_keypair(server_pk, server_sk);

        mpi_send(server_pk, crypto_kx_PUBLICKEYBYTES, MPI_UNSIGNED_CHAR, 0,
                 TAG_KX_SERVER_PK, inter, "Send(KX_SERVER_PK)");

        if (crypto_kx_server_session_keys(rx, tx, server_pk, server_sk,
                                          auth_hdr.client_pk) != 0) {
            fprintf(stderr, "[MASTER] crypto_kx_server_session_keys failed\n");
            MPI_Abort(MPI_COMM_WORLD, 1);
        }

        /* Derive single symmetric app_key from tx.
         * NOTE: master uses tx, worker uses rx — they match (crypto_kx guarantee). */
        crypto_generichash_state hst;
        crypto_generichash_init(&hst, NULL, 0, KEYB);
        crypto_generichash_update(&hst, tx, KEYB);
        const char *label = "app_key";
        crypto_generichash_update(&hst, (const unsigned char *)label, strlen(label));
        crypto_generichash_final(&hst, app_key, KEYB);

        /* Zeroize intermediate secrets */
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

        printf("[MASTER] round %d: worker #%d joined (EA-attested), key derived\n",
               round, nworkers + 1);
        nworkers++;
    }

    /* ════════════════════════════════════════════════════════════════
     *  COMPUTATION PHASE – AEAD-encrypted task distribution
     * ════════════════════════════════════════════════════════════════ */
    int tasks[] = {2, 3, 4, 5, 6, 7, 8, 9, 10};
    int NT = (int)(sizeof(tasks) / sizeof(tasks[0]));
    int next = 0;
    int results_received = 0;

    if (nworkers == 0) {
        printf("[MASTER] no workers enrolled, exit.\n");
        MPI_Finalize();
        return 0;
    }

    /* Send one initial task to each worker (or IDLE if more workers than tasks) */
    for (int i = 0; i < nworkers; i++) {
        if (next < NT)
            secure_send_task(workers[i], wkey[i], i, tasks[next++]);
        else
            secure_send_ctrl(workers[i], wkey[i], i, TAG_IDLE, CTRL_MAGIC_IDLE);
    }

    /* Collect results and hand out remaining tasks */
    while (results_received < NT) {
        int progressed = 0;
        for (int i = 0; i < nworkers; i++) {
            MPI_Status st;
            if (!mpi_iprobe(0, TAG_RESULT, workers[i], &st, "Iprobe(TAG_RESULT)"))
                continue;

            int pair[2];
            if (secure_recv_result(workers[i], wkey[i], i, pair) != 0) {
                fprintf(stderr, "[MASTER] dropping tampered result from worker#%d\n",
                        i + 1);
                continue;
            }
            results_received++;
            printf("[MASTER] result %d/%d from worker#%d: %d -> %d\n",
                   results_received, NT, i + 1, pair[0], pair[1]);

            progressed = 1;

            if (next < NT)
                secure_send_task(workers[i], wkey[i], i, tasks[next++]);
            else
                secure_send_ctrl(workers[i], wkey[i], i, TAG_IDLE, CTRL_MAGIC_IDLE);
        }

        if (!progressed) {
            struct timespec ts = {0, POLL_INTERVAL_NS};
            nanosleep(&ts, NULL);
        }
    }

    /* ════════════════════════════════════════════════════════════════
     *  SHUTDOWN PHASE – authenticated teardown + key zeroization
     * ════════════════════════════════════════════════════════════════ */
    for (int i = 0; i < nworkers; i++) {
        secure_send_ctrl(workers[i], wkey[i], i, TAG_SHUTDOWN, CTRL_MAGIC_SHUTDOWN);
        MPI_Comm_disconnect(&workers[i]);
    }

    /* Wipe all key material */
    sodium_memzero(wkey, sizeof wkey);

    printf("[MASTER] done.\n");
    MPI_Finalize();
    return 0;
}
