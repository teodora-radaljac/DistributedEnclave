
/*
 * worker_star.c – Compute node running inside an AMD SEV-SNP CVM.
 *
 * SECURITY HARDENING (threat mitigations):
 *   T1  Control-flow injection -> SHUTDOWN / IDLE decrypted & verified before acting.
 *   T2  Message replay         -> Incoming nonce monotonicity enforced.
 *   T4  Inconsistent errors    -> Every MPI_Send / MPI_Recv routed through wrappers.
 */
#include <mpi.h>
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <time.h>

/* ── MPI message tags (must match master) ── */
enum
{
    TAG_TASK = 10,
    TAG_RESULT = 11,
    TAG_IDLE = 13,
    TAG_SHUTDOWN = 99
};

enum
{
    TAG_ATTEST_NONCE = 80,
    TAG_ATTEST_REPORT_LEN = 81,
    TAG_ATTEST_REPORT_DATA = 82,
    TAG_ATTEST_RESULT = 83,

    TAG_KX_CLIENT_PK = 90,
    TAG_KX_SERVER_PK = 91
};

#define REPORT_DATA_SIZE 64
#define KEYB crypto_aead_chacha20poly1305_ietf_KEYBYTES
#define NPUB crypto_aead_chacha20poly1305_ietf_NPUBBYTES
#define ABYTES crypto_aead_chacha20poly1305_ietf_ABYTES

#define SNP_REPORT_DATA_FILE "report_data.bin"
#define SNP_REPORT_OUTPUT_FILE "attestation-report.bin"

/* Authenticated control-message sentinels (must match master) */
#define CTRL_MAGIC_SHUTDOWN 0xDEAD0001u
#define CTRL_MAGIC_IDLE     0xDEAD0002u

_Static_assert(crypto_kx_SESSIONKEYBYTES == KEYB, "kx session key size must match AEAD key size");

static unsigned char g_session_key_bytes[KEYB];

/* Monotonic nonce counter for outgoing AEAD messages */
static uint64_t send_nonce_ctr = 0;
static uint64_t recv_nonce_ctr = 0; /* replay protection on incoming */

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

/* ──────────────────────────────────────────────────────────────────────
 *  Checked MPI wrappers – uniform error handling for every call.
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

static void mpi_probe(int src, int tag, MPI_Comm comm, MPI_Status *st,
                      const char *ctx)
{
    int rc = MPI_Probe(src, tag, comm, st);
    if (rc != MPI_SUCCESS) die_mpi(ctx, rc);
}

/* ──────────────────────────────────────────────────────────────────────
 *  Generic AEAD secure send / recv wrappers
 *  All post-handshake ("mini-TLS") traffic goes through these two
 *  functions so that nonce management and replay logic live in one place.
 *
 *  Wire format: [nonce (NPUB B) || ciphertext (plain_len + ABYTES B)]
 * ────────────────────────────────────────────────────────────────────── */
#define SECURE_MAX_PLAIN 256

static void secure_send(MPI_Comm comm,
                        const void *plaintext, int plain_len,
                        int dest, int tag, const char *ctx)
{
    if (plain_len < 0 || plain_len > SECURE_MAX_PLAIN)
    {
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
        NULL, 0, NULL,
        nonce, g_session_key_bytes);

    memcpy(buf, nonce, NPUB);

    int total = NPUB + plain_len + (int)ABYTES;
    mpi_send(buf, total, MPI_UNSIGNED_CHAR, dest, tag, comm, ctx);
}

static int secure_recv(MPI_Comm comm,
                       void *plaintext, int plain_len,
                       int src, int tag, const char *ctx)
{
    if (plain_len < 0 || plain_len > SECURE_MAX_PLAIN)
    {
        fprintf(stderr, "[WORKER] secure_recv: plain_len %d out of range\n", plain_len);
        return -1;
    }

    unsigned char buf[NPUB + SECURE_MAX_PLAIN + ABYTES];
    int total = NPUB + plain_len + (int)ABYTES;
    MPI_Status st;
    mpi_recv(buf, total, MPI_UNSIGNED_CHAR, src, tag, comm, &st, ctx);

    /* Replay protection */
    uint64_t received_ctr = 0;
    memcpy(&received_ctr, buf, sizeof(uint64_t));
    if (received_ctr < recv_nonce_ctr)
    {
        fprintf(stderr, "[WORKER] REPLAY detected "
                        "(nonce %" PRIu64 " < %" PRIu64 ") [%s]\n",
                received_ctr, recv_nonce_ctr, ctx);
        return -1;
    }

    unsigned long long mlen = 0;
    if (crypto_aead_chacha20poly1305_ietf_decrypt(
            (unsigned char *)plaintext, &mlen, NULL,
            buf + NPUB, (unsigned long long)(plain_len + (int)ABYTES),
            NULL, 0,
            buf, g_session_key_bytes) != 0)
    {
        fprintf(stderr, "[WORKER] AEAD decryption FAILED [%s]\n", ctx);
        return -1;
    }
    if ((int)mlen != plain_len)
        return -1;

    recv_nonce_ctr = received_ctr + 1;
    return 0;
}

static int get_sev_snp_report(const unsigned char report_data[REPORT_DATA_SIZE],
                              unsigned char **out_report,
                              int *out_len)
{
    FILE *f = fopen(SNP_REPORT_DATA_FILE, "wb");
    if (!f)
        return -1;
    if (fwrite(report_data, 1, REPORT_DATA_SIZE, f) != REPORT_DATA_SIZE)
    {
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

    if (fseek(rf, 0, SEEK_END) != 0)
    {
        fclose(rf);
        return -1;
    }
    long sz = ftell(rf);
    if (sz <= 0)
    {
        fclose(rf);
        return -1;
    }
    rewind(rf);

    *out_len = (int)sz;
    *out_report = (unsigned char *)malloc((size_t)*out_len);
    if (!*out_report)
    {
        fclose(rf);
        return -1;
    }

    size_t rd = fread(*out_report, 1, (size_t)*out_len, rf);
    fclose(rf);
    if ((int)rd != *out_len)
    {
        free(*out_report);
        *out_report = NULL;
        *out_len = 0;
        return -1;
    }
    return 0;
}

/* Decrypt incoming task.  Replay protection via secure_recv(). */
static int secure_recv_task(MPI_Comm inter, int *x)
{
    return secure_recv(inter, x, sizeof(int), 0, TAG_TASK, "Recv(TAG_TASK)");
}

/* Send AEAD-encrypted result pair to master. */
static void secure_send_result(MPI_Comm inter, const int pair[2])
{
    secure_send(inter, pair, 2 * (int)sizeof(int), 0, TAG_RESULT, "Send(TAG_RESULT)");
}

/* AEAD-authenticated control message receiver.
   Threat T1+T2: rejects forgeries and replays.
   Returns 0 on success, -1 on forgery / replay. */
static int secure_recv_ctrl(MPI_Comm inter, int tag, uint32_t expected_magic)
{
    uint32_t magic = 0;
    if (secure_recv(inter, &magic, sizeof(uint32_t), 0, tag,
                    tag == TAG_SHUTDOWN ? "Recv(SHUTDOWN)" : "Recv(IDLE)") != 0)
        return -1;
    if (magic != expected_magic)
    {
        fprintf(stderr, "[WORKER] ctrl magic mismatch (expected 0x%08X, got 0x%08X)\n",
                expected_magic, magic);
        return -1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    MPI_Init(&argc, &argv);

    if (argc < 2)
    {
        fprintf(stderr, "usage: %s <PORT_STRING>\n", argv[0]);
        MPI_Abort(MPI_COMM_WORLD, 1);
    }
    char *PORT = argv[1];

    if (sodium_init() < 0)
    {
        fprintf(stderr, "[WORKER] sodium_init failed\n");
        MPI_Abort(MPI_COMM_WORLD, 1);
    }

    MPI_Comm inter = MPI_COMM_NULL;
    int rc = MPI_Comm_connect(PORT, MPI_INFO_NULL, 0, MPI_COMM_SELF, &inter);
    if (rc != MPI_SUCCESS)
        die_mpi("MPI_Comm_connect failed", rc);

    /* Force BTL TCP endpoint exchange before any point-to-point */
    MPI_Barrier(inter);

    /* ── Attestation + ECDH ── */
    unsigned char nonceM[REPORT_DATA_SIZE];
    mpi_recv(nonceM, REPORT_DATA_SIZE, MPI_UNSIGNED_CHAR, 0,
             TAG_ATTEST_NONCE, inter, MPI_STATUS_IGNORE, "Recv(ATTEST_NONCE)");

    unsigned char client_pk[crypto_kx_PUBLICKEYBYTES];
    unsigned char client_sk[crypto_kx_SECRETKEYBYTES];
    crypto_kx_keypair(client_pk, client_sk);

    unsigned char report_data[REPORT_DATA_SIZE];
    crypto_generichash_state hst;
    crypto_generichash_init(&hst, NULL, 0, REPORT_DATA_SIZE);
    crypto_generichash_update(&hst, nonceM, REPORT_DATA_SIZE);
    crypto_generichash_update(&hst, client_pk, crypto_kx_PUBLICKEYBYTES);
    crypto_generichash_final(&hst, report_data, REPORT_DATA_SIZE);

    unsigned char *report_buf = NULL;
    int report_len = 0;

#ifndef SKIP_ATTESTATION
    if (get_sev_snp_report(report_data, &report_buf, &report_len) != 0)
    {
        fprintf(stderr, "[WORKER] get_sev_snp_report failed\n");
        MPI_Abort(MPI_COMM_WORLD, 1);
    }
#endif

    mpi_send(client_pk, crypto_kx_PUBLICKEYBYTES, MPI_UNSIGNED_CHAR, 0,
             TAG_KX_CLIENT_PK, inter, "Send(KX_CLIENT_PK)");

    mpi_send(&report_len, 1, MPI_INT, 0,
             TAG_ATTEST_REPORT_LEN, inter, "Send(ATTEST_REPORT_LEN)");

    if (report_len > 0)
    {
        mpi_send(report_buf, report_len, MPI_UNSIGNED_CHAR, 0,
                 TAG_ATTEST_REPORT_DATA, inter, "Send(ATTEST_REPORT_DATA)");
    }

    free(report_buf);

    int attest_ok = 0;
    mpi_recv(&attest_ok, 1, MPI_INT, 0,
             TAG_ATTEST_RESULT, inter, MPI_STATUS_IGNORE, "Recv(ATTEST_RESULT)");

    if (!attest_ok)
    {
        fprintf(stderr, "[WORKER] attestation rejected by master\n");
        MPI_Comm_disconnect(&inter);
        MPI_Finalize();
        return 0;
    }

    unsigned char server_pk[crypto_kx_PUBLICKEYBYTES];
    mpi_recv(server_pk, crypto_kx_PUBLICKEYBYTES, MPI_UNSIGNED_CHAR, 0,
             TAG_KX_SERVER_PK, inter, MPI_STATUS_IGNORE, "Recv(KX_SERVER_PK)");

    unsigned char rx[KEYB], tx[KEYB];
    if (crypto_kx_client_session_keys(rx, tx, client_pk, client_sk, server_pk) != 0)
    {
        fprintf(stderr, "[WORKER] crypto_kx_client_session_keys failed\n");
        MPI_Abort(MPI_COMM_WORLD, 1);
    }

    /* Derive app_key from rx (matches master's derivation from tx).
       NOTE: crypto_kx guarantees master_tx == worker_rx. */
    unsigned char app_key[KEYB];
    crypto_generichash_state hst2;
    crypto_generichash_init(&hst2, NULL, 0, KEYB);
    crypto_generichash_update(&hst2, rx, KEYB);
    const char *label = "app_key";
    crypto_generichash_update(&hst2, (const unsigned char *)label, strlen(label));
    crypto_generichash_final(&hst2, app_key, KEYB);

    memcpy(g_session_key_bytes, app_key, KEYB);

    /* Zeroize intermediate secrets */
    sodium_memzero(client_sk, sizeof client_sk);
    sodium_memzero(rx, sizeof rx);
    sodium_memzero(tx, sizeof tx);
    sodium_memzero(app_key, sizeof app_key);

    printf("[WORKER] handshake OK \u2014 entering work loop\n");

    /* ── Main work loop ── */
    while (1)
    {
        MPI_Status st;
        mpi_probe(0, MPI_ANY_TAG, inter, &st, "Probe");

        if (st.MPI_TAG == TAG_SHUTDOWN)
        {
            if (secure_recv_ctrl(inter, TAG_SHUTDOWN, CTRL_MAGIC_SHUTDOWN) != 0)
            {
                fprintf(stderr, "[WORKER] SHUTDOWN forgery detected, ignoring\n");
                continue;
            }
            printf("[WORKER] received authenticated SHUTDOWN, exiting work loop\n");
            break;
        }

        if (st.MPI_TAG == TAG_IDLE)
        {
            if (secure_recv_ctrl(inter, TAG_IDLE, CTRL_MAGIC_IDLE) != 0)
            {
                fprintf(stderr, "[WORKER] IDLE forgery detected, ignoring\n");
                continue;
            }
            continue;
        }

        if (st.MPI_TAG == TAG_TASK)
        {
            int x = 0;
            if (secure_recv_task(inter, &x) != 0)
            {
                fprintf(stderr, "[WORKER] failed to decrypt task, skipping\n");
                continue;
            }
            int y = x * x;
            int pair[2] = {x, y};
            secure_send_result(inter, pair);
            continue;
        }

        /* Consume any unknown tag so we don't loop forever.
         * Allocate exactly the reported size so MPI_Recv does not
         * return MPI_ERR_TRUNCATE (which would abort via die_mpi).
         * Cap at 64 KB to prevent an OOM from a malicious sender. */
        {
            int msg_count = 0;
            MPI_Get_count(&st, MPI_UNSIGNED_CHAR, &msg_count);
            if (msg_count < 0 || msg_count == MPI_UNDEFINED)
                msg_count = 0;
            if (msg_count > 65536)
                msg_count = 65536;
            fprintf(stderr, "[WORKER] unknown tag %d (%d bytes), discarding\n",
                    st.MPI_TAG, msg_count);
            unsigned char *discard = (unsigned char *)malloc((size_t)(msg_count > 0 ? msg_count : 1));
            if (discard)
            {
                mpi_recv(discard, msg_count, MPI_UNSIGNED_CHAR, 0, st.MPI_TAG,
                         inter, MPI_STATUS_IGNORE, "Recv(unknown tag)");
                free(discard);
            }
            else
            {
                fprintf(stderr, "[WORKER] malloc failed for discard buffer, aborting\n");
                break;
            }
        }
    }

    /* Wipe session key and disconnect */
    sodium_memzero(g_session_key_bytes, sizeof g_session_key_bytes);

    MPI_Comm_disconnect(&inter);
    MPI_Finalize();
    return 0;
}