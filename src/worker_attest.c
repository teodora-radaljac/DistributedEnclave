/*
 * worker_attest.c – EA/aTLS-style attestation for MPI worker in SEV-SNP CVM.
 *
 * Attestation protocol inspired by the aTLS implementation in
 * https://github.com/danko-miladinovic/fort
 *
 * This is the worker (server-side) counterpart to master_attest.c.
 * In fort's aTLS model, this corresponds to atls.Server():
 *
 *   Fort concept                  →  This implementation
 *   ─────────────────────────────────────────────────────────────────
 *   TLS 1.3 server                →  MPI worker connecting to master's port
 *   Read AuthenticatorRequest     →  Receive EA request over MPI
 *   BuildLeafExtensions()         →  Compute binder + fetch SNP evidence
 *   CMWAttestationDataExtension() →  Build ea_payload_hdr + raw evidence
 *   CreateAuthenticator()         →  Send auth header + evidence + finished
 *   EA Certificate public key     →  Worker's ECDH public key (client_pk)
 *   EA Finished                   →  BLAKE2b transcript hash
 *
 * The worker constructs an EA Authenticator with CMW attestation extension
 * following the same binding model as fort's attestation/binding.go:
 *   exportedValue = BLAKE2b(context)           [≈ ExportKeyingMaterial]
 *   aikPubHash    = BLAKE2b(pubkey)            [≈ AIKPublicKeyHash]
 *   binding       = BLAKE2b(pubkey||exported)  [≈ BindingValue]
 *   report_data   = BLAKE2b(binding)           [for SEV-SNP REPORT_DATA]
 *
 * Threat mitigations:
 *   T1  Control-flow injection  → SHUTDOWN/IDLE decrypted & verified
 *   T2  Message replay          → Incoming nonce monotonicity enforced
 *   T4  Error handling          → Checked MPI wrappers on every call
 */

#include <mpi.h>
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <time.h>

/* ── MPI message tags: data plane (must match master) ── */
enum {
    TAG_TASK     = 10,
    TAG_RESULT   = 11,
    TAG_IDLE     = 13,
    TAG_SHUTDOWN = 99
};

/* ── MPI message tags: EA attestation protocol (must match master) ── */
enum {
    TAG_EA_REQUEST       = 70,
    TAG_EA_AUTH_HDR      = 71,
    TAG_EA_EVIDENCE_DATA = 72,
    TAG_EA_FINISHED      = 73,
    TAG_EA_RESULT        = 74,
    TAG_KX_SERVER_PK     = 91
};

/* ── Crypto constants ── */
#define KEYB   crypto_aead_chacha20poly1305_ietf_KEYBYTES
#define NPUB   crypto_aead_chacha20poly1305_ietf_NPUBBYTES
#define ABYTES crypto_aead_chacha20poly1305_ietf_ABYTES

#define HASH_LEN         32
#define BINDING_LEN      32
#define REPORT_DATA_SIZE 64

#define SNP_REPORT_DATA_FILE   "report_data.bin"
#define SNP_REPORT_OUTPUT_FILE "attestation-report.bin"

/* AEAD-encrypted control sentinels (must match master) */
#define CTRL_MAGIC_SHUTDOWN 0xDEAD0001u
#define CTRL_MAGIC_IDLE     0xDEAD0002u

_Static_assert(crypto_kx_SESSIONKEYBYTES == KEYB,
               "kx session key size must match AEAD key size");

/* ──────────────────────────────────────────────────────────────────────
 *  EA / CMW Attestation types (must match master_attest.c)
 *  Mirrors fort's attestation/types.go
 * ────────────────────────────────────────────────────────────────────── */

#define EA_CONTEXT_LEN     32
#define EA_MEDIA_TYPE      "application/eat+cwt"
#define EA_EXPORTER_LABEL  "Attestation"
#define EA_PAYLOAD_VERSION 1

/* fort's attestation.AttestationBinder */
struct ea_binder {
    uint8_t aik_pub_hash[HASH_LEN];
    uint8_t binding[BINDING_LEN];
    char    exporter_label[64];
} __attribute__((packed));

/* fort's attestation.Payload (header portion) */
struct ea_payload_hdr {
    uint32_t        version;
    char            media_type[64];
    uint32_t        evidence_len;
    struct ea_binder binder;
} __attribute__((packed));

/* EA AuthenticatorRequest (received from master) */
struct ea_request {
    uint8_t context[EA_CONTEXT_LEN];
    uint8_t attestation_offer;
} __attribute__((packed));

/* EA Authenticator header (sent to master) */
struct ea_auth_hdr {
    uint8_t             client_pk[crypto_kx_PUBLICKEYBYTES];
    struct ea_payload_hdr payload_hdr;
} __attribute__((packed));

/* ── Globals ── */
static unsigned char g_session_key_bytes[KEYB];
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

/* ── Checked MPI wrappers (T4) ── */

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

static void mpi_probe(int src, int tag, MPI_Comm comm, MPI_Status *st,
                      const char *ctx)
{
    int rc = MPI_Probe(src, tag, comm, st);
    if (rc != MPI_SUCCESS) die_mpi(ctx, rc);
}

/* ──────────────────────────────────────────────────────────────────────
 *  EA Attestation Binding (mirrors fort's attestation/binding.go)
 *
 *  These functions compute the same binding values as fort's
 *  ComputeBinding(), adapted for our MPI context where we don't
 *  have TLS ExportKeyingMaterial.
 * ────────────────────────────────────────────────────────────────────── */

/*
 * Fort's attestation.ExportAttestationValue()
 * In TLS 1.3: tls.ConnectionState.ExportKeyingMaterial(label, context, 32)
 * Here: BLAKE2b-256(context_nonce)
 */
static void ea_export_attestation_value(const uint8_t context[EA_CONTEXT_LEN],
                                        uint8_t out[HASH_LEN])
{
    crypto_generichash(out, HASH_LEN, context, EA_CONTEXT_LEN, NULL, 0);
}

/*
 * Fort's attestation.AIKPublicKeyHash()
 * aikPubHash = Hash(leafCert.RawSubjectPublicKeyInfo)
 * Here: BLAKE2b-256(ecdh_public_key)
 */
static void ea_aik_pub_hash(const uint8_t *pub_key, size_t pub_key_len,
                            uint8_t out[HASH_LEN])
{
    crypto_generichash(out, HASH_LEN, pub_key, pub_key_len, NULL, 0);
}

/*
 * Fort's attestation.BindingValue()
 * binding = Hash(pubKeyBytes || exportedValue)
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
 * Fort's attestation.ComputeBinding()
 * Computes exportedValue, aikPubHash, and binding in one call.
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
 * Derive 64-byte SEV-SNP REPORT_DATA from the 32-byte binding.
 */
static void ea_derive_report_data(const uint8_t binding[BINDING_LEN],
                                  uint8_t report_data[REPORT_DATA_SIZE])
{
    crypto_generichash(report_data, REPORT_DATA_SIZE,
                       binding, BINDING_LEN, NULL, 0);
}

/*
 * Compute the EA Finished hash (transcript integrity).
 * Fort equivalent: EA Finished = HMAC(finished_key, transcript_hash)
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

/* ──────────────────────────────────────────────────────────────────────
 *  SEV-SNP report generation
 *  Fort equivalent: the TEE-side evidence collection that produces
 *  the raw attestation report embedded as CMW evidence.
 * ────────────────────────────────────────────────────────────────────── */

static int get_sev_snp_report(const unsigned char report_data[REPORT_DATA_SIZE],
                              unsigned char **out_report,
                              int *out_len)
{
    FILE *f = fopen(SNP_REPORT_DATA_FILE, "wb");
    if (!f)
        return -1;
    if (fwrite(report_data, 1, REPORT_DATA_SIZE, f) != REPORT_DATA_SIZE) {
        fclose(f);
        return -1;
    }
    fclose(f);

    char cmd[512];
    snprintf(cmd, sizeof cmd,
             "snpguest report %s %s > snpguest_report.log 2>&1",
             SNP_REPORT_OUTPUT_FILE, SNP_REPORT_DATA_FILE);

    int status = system(cmd);
    if (status != 0)
        return -1;

    FILE *rf = fopen(SNP_REPORT_OUTPUT_FILE, "rb");
    if (!rf)
        return -1;

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
        free(*out_report);
        *out_report = NULL;
        *out_len = 0;
        return -1;
    }
    return 0;
}

/* ──────────────────────────────────────────────────────────────────────
 *  AEAD secure send / recv (post-attestation encrypted channel)
 * ────────────────────────────────────────────────────────────────────── */
#define SECURE_MAX_PLAIN 256

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
        NULL, 0, NULL, nonce, g_session_key_bytes);

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

    /* T2: replay protection */
    uint64_t received_ctr = 0;
    memcpy(&received_ctr, buf, sizeof(uint64_t));
    if (received_ctr < recv_nonce_ctr) {
        fprintf(stderr, "[WORKER] REPLAY detected "
                        "(nonce %" PRIu64 " < %" PRIu64 ") [%s]\n",
                received_ctr, recv_nonce_ctr, ctx);
        return -1;
    }

    unsigned long long mlen = 0;
    if (crypto_aead_chacha20poly1305_ietf_decrypt(
            (unsigned char *)plaintext, &mlen, NULL,
            buf + NPUB, (unsigned long long)(plain_len + (int)ABYTES),
            NULL, 0, buf, g_session_key_bytes) != 0) {
        fprintf(stderr, "[WORKER] AEAD decryption FAILED [%s]\n", ctx);
        return -1;
    }
    if ((int)mlen != plain_len)
        return -1;

    recv_nonce_ctr = received_ctr + 1;
    return 0;
}

/* ── Task / control message helpers ── */

static int secure_recv_task(MPI_Comm inter, int *x)
{
    return secure_recv(inter, x, sizeof(int), 0, TAG_TASK, "Recv(TAG_TASK)");
}

static void secure_send_result(MPI_Comm inter, const int pair[2])
{
    secure_send(inter, pair, 2 * (int)sizeof(int), 0, TAG_RESULT, "Send(TAG_RESULT)");
}

/* T1+T2: rejects forgeries and replays on control messages */
static int secure_recv_ctrl(MPI_Comm inter, int tag, uint32_t expected_magic)
{
    uint32_t magic = 0;
    if (secure_recv(inter, &magic, sizeof(uint32_t), 0, tag,
                    tag == TAG_SHUTDOWN ? "Recv(SHUTDOWN)" : "Recv(IDLE)") != 0)
        return -1;
    if (magic != expected_magic) {
        fprintf(stderr, "[WORKER] ctrl magic mismatch (expected 0x%08X, got 0x%08X)\n",
                expected_magic, magic);
        return -1;
    }
    return 0;
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

    /* ── Connect to master's MPI port ── */
    MPI_Comm inter = MPI_COMM_NULL;
    int rc = MPI_Comm_connect(PORT, MPI_INFO_NULL, 0, MPI_COMM_SELF, &inter);
    if (rc != MPI_SUCCESS)
        die_mpi("MPI_Comm_connect failed", rc);

    /* Force BTL TCP endpoint exchange */
    MPI_Barrier(inter);

    /* ════════════════════════════════════════════════════════════════
     *  EA ATTESTATION HANDSHAKE
     *  Mirrors fort's atls.Server() flow:
     *    1. Receive AuthenticatorRequest   (context + offer)
     *    2. Build EA Authenticator         (cert/pk + CMW extension + finished)
     *    3. Send Authenticator
     *    4. Receive validation result
     *    5. Key exchange
     * ════════════════════════════════════════════════════════════════ */

    /* ── Step 1: Receive EA AuthenticatorRequest ──
     * Fort equivalent: atls.Server reads frameTypeRequest, then
     * ea.UnmarshalAuthenticatorRequest() extracts context + extensions.
     * The CMWAttestationOfferExtension indicates attestation is requested.
     */
    struct ea_request ea_req;
    mpi_recv(&ea_req, sizeof(ea_req), MPI_UNSIGNED_CHAR, 0,
             TAG_EA_REQUEST, inter, MPI_STATUS_IGNORE, "Recv(EA_REQUEST)");

    printf("[WORKER] received EA AuthenticatorRequest "
           "(context received, attestation_offer=%u)\n",
           ea_req.attestation_offer);

    /* ── Step 2: Build EA Authenticator ──
     * Fort equivalent: atls.Server calls:
     *   1. resolveIdentity()           → generate ECDH keypair
     *   2. buildServerExtensions()     → compute binding + attestation payload
     *   3. ea.CreateAuthenticator()    → assemble Certificate + Finished
     */

    /* 2a: Generate ECDH keypair (the "leaf certificate" identity)
     * Fort: resolveIdentity() returns a tls.Certificate */
    unsigned char client_pk[crypto_kx_PUBLICKEYBYTES];
    unsigned char client_sk[crypto_kx_SECRETKEYBYTES];
    crypto_kx_keypair(client_pk, client_sk);

    /* 2b: Compute attestation binding (fort's ComputeBinding)
     * Fort's ExampleServerLeafExtensions() calls:
     *   attestation.ComputeBinding(st, label, req.Context, leaf)
     * which returns (exportedValue, aikPubHash, binding) */
    uint8_t exported_value[HASH_LEN];
    uint8_t aik_hash[HASH_LEN];
    uint8_t binding[BINDING_LEN];
    ea_compute_binding(ea_req.context, client_pk, crypto_kx_PUBLICKEYBYTES,
                       exported_value, aik_hash, binding);

    /* 2c: Derive SEV-SNP REPORT_DATA from the binding.
     * This cryptographically ties the hardware attestation to the
     * EA binding (which embeds the pubkey + session context). */
    uint8_t report_data[REPORT_DATA_SIZE];
    ea_derive_report_data(binding, report_data);

    /* 2d: Fetch SEV-SNP attestation report (the "evidence" in CMW).
     * Fort equivalent: the evidence bytes that get embedded in
     * attestation.Payload.Evidence via CMWAttestationDataExtension().
     */
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

    /* 2e: Build the attestation payload header (CMW extension).
     * Fort equivalent: attestation.MarshalPayload(attestation.Payload{
     *   Version:   1,
     *   MediaType: "application/eat+cwt",
     *   Evidence:  snp_report_bytes,
     *   Binder:    {ExporterLabel, AIKPubHash, Binding},
     * })
     */
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

    /* 2f: Compute EA Finished hash over entire transcript.
     * Fort equivalent: EA Finished = HMAC(finished_key, transcript_hash) */
    uint8_t finished[HASH_LEN];
    ea_compute_finished(ea_req.context, client_pk, crypto_kx_PUBLICKEYBYTES,
                        &auth_hdr.payload_hdr,
                        evidence, (uint32_t)evidence_len,
                        finished);

    /* ── Step 3: Send EA Authenticator ──
     * Fort equivalent: atls.Server calls writeFrame(conn, frameTypeAuthenticator, authBytes)
     * We send the authenticator in parts: header, evidence, finished.
     */

    /* 3a: Send authenticator header (public key + payload metadata + binder) */
    mpi_send(&auth_hdr, sizeof(auth_hdr), MPI_UNSIGNED_CHAR, 0,
             TAG_EA_AUTH_HDR, inter, "Send(EA_AUTH_HDR)");

    /* 3b: Send evidence data (raw SNP report) if present */
    if (evidence_len > 0) {
        mpi_send(evidence, evidence_len, MPI_UNSIGNED_CHAR, 0,
                 TAG_EA_EVIDENCE_DATA, inter, "Send(EA_EVIDENCE_DATA)");
    }

    /* 3c: Send EA Finished hash */
    mpi_send(finished, HASH_LEN, MPI_UNSIGNED_CHAR, 0,
             TAG_EA_FINISHED, inter, "Send(EA_FINISHED)");

    free(evidence);

    printf("[WORKER] sent EA Authenticator "
           "(pk + CMW payload + %d B evidence + finished)\n", evidence_len);

    /* ── Step 4: Receive EA validation result ──
     * Fort equivalent: the TLS connection continues if validation passes;
     * here the master sends an explicit accept/reject.
     */
    int attest_ok = 0;
    mpi_recv(&attest_ok, 1, MPI_INT, 0,
             TAG_EA_RESULT, inter, MPI_STATUS_IGNORE, "Recv(EA_RESULT)");

    if (!attest_ok) {
        fprintf(stderr, "[WORKER] EA attestation rejected by master\n");
        sodium_memzero(client_sk, sizeof client_sk);
        MPI_Comm_disconnect(&inter);
        MPI_Finalize();
        return 0;
    }

    printf("[WORKER] EA attestation ACCEPTED by master\n");

    /* ── Step 5: ECDH Key Exchange ──
     * Derives the session key used for all subsequent AEAD communication.
     * Fort equivalent: TLS session keys are already available; here we
     * do explicit ECDH since our "certificate" is an ECDH keypair.
     */
    unsigned char server_pk[crypto_kx_PUBLICKEYBYTES];
    mpi_recv(server_pk, crypto_kx_PUBLICKEYBYTES, MPI_UNSIGNED_CHAR, 0,
             TAG_KX_SERVER_PK, inter, MPI_STATUS_IGNORE, "Recv(KX_SERVER_PK)");

    unsigned char rx[KEYB], tx[KEYB];
    if (crypto_kx_client_session_keys(rx, tx, client_pk, client_sk, server_pk) != 0) {
        fprintf(stderr, "[WORKER] crypto_kx_client_session_keys failed\n");
        MPI_Abort(MPI_COMM_WORLD, 1);
    }

    /* Derive app_key from rx (matches master's derivation from tx).
     * NOTE: crypto_kx guarantees master_tx == worker_rx. */
    unsigned char app_key[KEYB];
    crypto_generichash_state hst;
    crypto_generichash_init(&hst, NULL, 0, KEYB);
    crypto_generichash_update(&hst, rx, KEYB);
    const char *label = "app_key";
    crypto_generichash_update(&hst, (const unsigned char *)label, strlen(label));
    crypto_generichash_final(&hst, app_key, KEYB);

    memcpy(g_session_key_bytes, app_key, KEYB);

    /* Zeroize all intermediate secrets */
    sodium_memzero(client_sk, sizeof client_sk);
    sodium_memzero(rx, sizeof rx);
    sodium_memzero(tx, sizeof tx);
    sodium_memzero(app_key, sizeof app_key);
    sodium_memzero(exported_value, sizeof exported_value);
    sodium_memzero(binding, sizeof binding);

    printf("[WORKER] handshake OK — session key derived, entering work loop\n");

    /* ════════════════════════════════════════════════════════════════
     *  WORK LOOP – AEAD-encrypted task processing
     * ════════════════════════════════════════════════════════════════ */
    while (1)
    {
        MPI_Status st;
        mpi_probe(0, MPI_ANY_TAG, inter, &st, "Probe");

        if (st.MPI_TAG == TAG_SHUTDOWN) {
            if (secure_recv_ctrl(inter, TAG_SHUTDOWN, CTRL_MAGIC_SHUTDOWN) != 0) {
                fprintf(stderr, "[WORKER] SHUTDOWN forgery detected, ignoring\n");
                continue;
            }
            printf("[WORKER] received authenticated SHUTDOWN, exiting work loop\n");
            break;
        }

        if (st.MPI_TAG == TAG_IDLE) {
            if (secure_recv_ctrl(inter, TAG_IDLE, CTRL_MAGIC_IDLE) != 0) {
                fprintf(stderr, "[WORKER] IDLE forgery detected, ignoring\n");
                continue;
            }
            continue;
        }

        if (st.MPI_TAG == TAG_TASK) {
            int x = 0;
            if (secure_recv_task(inter, &x) != 0) {
                fprintf(stderr, "[WORKER] failed to decrypt task, skipping\n");
                continue;
            }
            int y = x * x;
            int pair[2] = {x, y};
            secure_send_result(inter, pair);
            continue;
        }

        /* Consume unknown tags (cap at 64 KB to prevent OOM) */
        {
            int msg_count = 0;
            MPI_Get_count(&st, MPI_UNSIGNED_CHAR, &msg_count);
            if (msg_count < 0 || msg_count == MPI_UNDEFINED)
                msg_count = 0;
            if (msg_count > 65536)
                msg_count = 65536;
            fprintf(stderr, "[WORKER] unknown tag %d (%d bytes), discarding\n",
                    st.MPI_TAG, msg_count);
            unsigned char *discard = (unsigned char *)malloc(
                (size_t)(msg_count > 0 ? msg_count : 1));
            if (discard) {
                mpi_recv(discard, msg_count, MPI_UNSIGNED_CHAR, 0, st.MPI_TAG,
                         inter, MPI_STATUS_IGNORE, "Recv(unknown tag)");
                free(discard);
            } else {
                fprintf(stderr, "[WORKER] malloc failed for discard buffer, aborting\n");
                break;
            }
        }
    }

    /* ── Cleanup: wipe session key and disconnect ── */
    sodium_memzero(g_session_key_bytes, sizeof g_session_key_bytes);

    MPI_Comm_disconnect(&inter);
    MPI_Finalize();
    return 0;
}
