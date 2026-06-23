
/*
 * master_star.c – Trust anchor / coordinator for MPI + SEV-SNP star topology.
 *
 * SECURITY HARDENING (threat mitigations):
 *   T1  Unauthenticated control-flow injection
 *       -> SHUTDOWN / IDLE are now AEAD-encrypted with a sentinel magic value.
 *   T2  Message replay
 *       -> Per-worker recv_nonce_ctr rejects out-of-order / replayed ciphertexts.
 *   T3  Shell command injection via SNP_CERTS_DIR
 *       -> sanitize_path() rejects meta-characters before interpolation.
 *   T4  Inconsistent error handling
 *       -> Every MPI_Send / MPI_Recv goes through checked mpi_send / mpi_recv.
 *   T5  TOCTOU on attestation temp files (documented, not fully mitigated).
 *   T6  Unbounded MPI_Comm_accept blocking (documented, DoS surface).
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

/* ── MPI message tags ── */
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

#define MAX_WORKERS 128
#define POLL_INTERVAL_NS (50 * 1000 * 1000) /* 50 ms */

#define KEYB crypto_aead_chacha20poly1305_ietf_KEYBYTES
#define NPUB crypto_aead_chacha20poly1305_ietf_NPUBBYTES
#define ABYTES crypto_aead_chacha20poly1305_ietf_ABYTES
#define REPORT_DATA_SIZE 64
#define SNP_REPORT_TMP "snp_report.bin"
#define MAX_REPORT_LEN  16384   /* SNP reports are ~1184 B; reject implausible sizes */

/* Authenticated control-message sentinels (AEAD-encrypted to prevent forgery) */
#define CTRL_MAGIC_SHUTDOWN 0xDEAD0001u
#define CTRL_MAGIC_IDLE     0xDEAD0002u

_Static_assert(crypto_kx_SESSIONKEYBYTES == KEYB, "kx session key size must match AEAD key size");

/* Per-worker nonce counters for AEAD (monotonic, no reuse risk). */
static uint64_t send_nonce_ctr[MAX_WORKERS];
static uint64_t recv_nonce_ctr[MAX_WORKERS]; /* replay protection */

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

/* ──────────────────────────────────────────────────────────────────────
 *  Checked MPI wrappers – every send / receive goes through these
 *  so that error handling is uniform and auditable.
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
 *  Generic AEAD secure send / recv wrappers
 *  All post-handshake ("mini-TLS") traffic goes through these two
 *  functions so that nonce management and replay logic live in one place.
 *
 *  Wire format: [nonce (NPUB B) || ciphertext (plain_len + ABYTES B)]
 * ────────────────────────────────────────────────────────────────────── */
#define SECURE_MAX_PLAIN 256

static void secure_send(MPI_Comm comm, const unsigned char key[KEYB],
                        uint64_t *nonce_ctr,
                        const void *plaintext, int plain_len,
                        int dest, int tag, const char *ctx)
{
    if (plain_len < 0 || plain_len > SECURE_MAX_PLAIN)
    {
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
        NULL, 0, NULL,
        nonce, key);

    memcpy(buf, nonce, NPUB);

    int total = NPUB + plain_len + (int)ABYTES;
    mpi_send(buf, total, MPI_UNSIGNED_CHAR, dest, tag, comm, ctx);
}

static int secure_recv(MPI_Comm comm, const unsigned char key[KEYB],
                       uint64_t *nonce_ctr,
                       void *plaintext, int plain_len,
                       int src, int tag, const char *ctx)
{
    if (plain_len < 0 || plain_len > SECURE_MAX_PLAIN)
    {
        fprintf(stderr, "[MASTER] secure_recv: plain_len %d out of range\n", plain_len);
        return -1;
    }

    unsigned char buf[NPUB + SECURE_MAX_PLAIN + ABYTES];
    int total = NPUB + plain_len + (int)ABYTES;
    MPI_Status st;
    mpi_recv(buf, total, MPI_UNSIGNED_CHAR, src, tag, comm, &st, ctx);

    /* Replay protection: verify nonce monotonicity */
    uint64_t received_ctr = 0;
    memcpy(&received_ctr, buf, sizeof(uint64_t));
    if (received_ctr < *nonce_ctr)
    {
        fprintf(stderr, "[MASTER] REPLAY detected "
                        "(nonce %" PRIu64 " < %" PRIu64 ") [%s]\n",
                received_ctr, *nonce_ctr, ctx);
        return -1;
    }

    unsigned long long mlen = 0;
    if (crypto_aead_chacha20poly1305_ietf_decrypt(
            (unsigned char *)plaintext, &mlen, NULL,
            buf + NPUB, (unsigned long long)(plain_len + (int)ABYTES),
            NULL, 0,
            buf, key) != 0)
    {
        fprintf(stderr, "[MASTER] AEAD decryption FAILED [%s]\n", ctx);
        return -1;
    }
    if ((int)mlen != plain_len)
        return -1;

    *nonce_ctr = received_ctr + 1;
    return 0;
}

/* Reject paths that could enable shell injection in system() calls.
 * Threat T3: SNP_CERTS_DIR is interpolated into a system() command. */
static int sanitize_path(const char *p)
{
    for (; *p; p++)
    {
        unsigned char c = (unsigned char)*p;
        if (c < 0x20 || c == ';' || c == '&' || c == '|' ||
            c == '$' || c == '`' || c == '\'' || c == '"' ||
            c == '(' || c == ')' || c == '{' || c == '}' ||
            c == '<' || c == '>' || c == '!' || c == '\n')
            return -1;
    }
    return 0;
}

static int getenv_int(const char *k, int defv)
{
    const char *s = getenv(k);
    if (!s || !*s)
        return defv;
    int v = atoi(s);
    return v > 0 ? v : defv;
}

static void bytes_to_hex(const unsigned char *in, size_t len, char *out, size_t out_len)
{
    static const char hex_chars[] = "0123456789abcdef";
    if (out_len < 2 * len + 1)
    {
        if (out_len)
            out[0] = '\0';
        return;
    }
    for (size_t i = 0; i < len; i++)
    {
        out[2 * i] = hex_chars[(in[i] >> 4) & 0xF];
        out[2 * i + 1] = hex_chars[in[i] & 0xF];
    }
    out[2 * len] = '\0';
}

static int verify_sev_snp_report(const unsigned char *report, int report_len,
                                 const unsigned char expected_report_data[REPORT_DATA_SIZE])
{
    if (!report || report_len <= 0)
        return -1;

    FILE *f = fopen(SNP_REPORT_TMP, "wb");
    if (!f)
        return -1;
    if ((int)fwrite(report, 1, (size_t)report_len, f) != report_len)
    {
        fclose(f);
        return -1;
    }
    fclose(f);

    char rd_hex[REPORT_DATA_SIZE * 2 + 1];
    bytes_to_hex(expected_report_data, REPORT_DATA_SIZE, rd_hex, sizeof rd_hex);

    const char *certs_dir = getenv("SNP_CERTS_DIR");
    if (!certs_dir || !*certs_dir)
        certs_dir = "certs";

    /* Threat T3: reject shell meta-characters */
    if (sanitize_path(certs_dir) != 0)
    {
        fprintf(stderr, "[MASTER] SNP_CERTS_DIR contains unsafe characters\n");
        return -1;
    }

    char cmd[1024];
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

/* Send a single AEAD-encrypted int task to worker wid. */
static void secure_send_task(MPI_Comm inter, const unsigned char key[KEYB], int wid, int x)
{
    secure_send(inter, key, &send_nonce_ctr[wid],
                &x, sizeof(int), 0, TAG_TASK, "Send(TAG_TASK)");
}

/* AEAD-authenticated control message (SHUTDOWN / IDLE).
 * Threat T1: prevents unauthenticated control-flow injection. */
static void secure_send_ctrl(MPI_Comm inter, const unsigned char key[KEYB],
                             int wid, int tag, uint32_t magic)
{
    secure_send(inter, key, &send_nonce_ctr[wid],
                &magic, sizeof(uint32_t), 0, tag,
                tag == TAG_SHUTDOWN ? "Send(SHUTDOWN)" : "Send(IDLE)");
}

/* Receive and decrypt result pair from worker.
   Threat T2: replay protection via nonce monotonicity in secure_recv(). */
static int secure_recv_result(MPI_Comm inter, const unsigned char key[KEYB],
                              int wid, int pair[2])
{
    return secure_recv(inter, key, &recv_nonce_ctr[wid],
                       pair, 2 * (int)sizeof(int), 0, TAG_RESULT,
                       "Recv(TAG_RESULT)");
}

/* Write port string atomically: write to .tmp then rename. */
static void write_port_file(const char *path, const char *port_name)
{
    char tmp[256];
    snprintf(tmp, sizeof tmp, "%s.tmp", path);
    FILE *f = fopen(tmp, "w");
    if (!f)
    {
        perror("fopen(port.txt.tmp)");
        exit(1);
    }
    fprintf(f, "%s\n", port_name);
    fclose(f);
    if (rename(tmp, path) != 0)
    {
        perror("rename(port.txt)");
        exit(1);
    }
}

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    MPI_Init(&argc, &argv);

    if (sodium_init() < 0)
    {
        fprintf(stderr, "[MASTER] sodium_init failed\n");
        MPI_Abort(MPI_COMM_WORLD, 1);
    }

    int target = getenv_int("TARGET_WORKERS", 2);
    if (argc >= 3 && strcmp(argv[1], "--master") == 0)
    {
        target = atoi(argv[2]);
        if (target <= 0)
            target = 1;
    }

    MPI_Comm workers[MAX_WORKERS];
    unsigned char wkey[MAX_WORKERS][KEYB];
    int nworkers = 0;
    memset(send_nonce_ctr, 0, sizeof send_nonce_ctr);
    memset(recv_nonce_ctr, 0, sizeof recv_nonce_ctr);

    printf("[MASTER] target_workers=%d\n", target);

    for (int round = 1; round <= target; round++)
    {
        char port[MPI_MAX_PORT_NAME];
        memset(port, 0, sizeof port);

        int rc = MPI_Open_port(MPI_INFO_NULL, port);
        if (rc != MPI_SUCCESS)
            die_mpi("MPI_Open_port failed", rc);

        /* New port each round */
        write_port_file("port.txt", port);

        printf("[MASTER] round %d: opened port='%s'\n", round, port);
        printf("[MASTER] round %d: waiting accept (COMM_SELF)...\n", round);

        MPI_Comm inter = MPI_COMM_NULL;
        rc = MPI_Comm_accept(port, MPI_INFO_NULL, 0, MPI_COMM_SELF, &inter);
        if (rc != MPI_SUCCESS)
            die_mpi("MPI_Comm_accept failed", rc);

        /* Force BTL TCP endpoint exchange before any point-to-point */
        MPI_Barrier(inter);

        rc = MPI_Close_port(port);
        if (rc != MPI_SUCCESS)
            die_mpi("MPI_Close_port failed", rc);

        /* ── Attestation + ECDH (peer is rank 0 on the remote side) ── */
        unsigned char nonceM[REPORT_DATA_SIZE];
        randombytes_buf(nonceM, sizeof nonceM);

        mpi_send(nonceM, REPORT_DATA_SIZE, MPI_UNSIGNED_CHAR, 0,
                 TAG_ATTEST_NONCE, inter, "Send(ATTEST_NONCE)");

        unsigned char client_pk[crypto_kx_PUBLICKEYBYTES];
        mpi_recv(client_pk, crypto_kx_PUBLICKEYBYTES, MPI_UNSIGNED_CHAR, 0,
                 TAG_KX_CLIENT_PK, inter, MPI_STATUS_IGNORE, "Recv(KX_CLIENT_PK)");

        int report_len = 0;
        mpi_recv(&report_len, 1, MPI_INT, 0,
                 TAG_ATTEST_REPORT_LEN, inter, MPI_STATUS_IGNORE, "Recv(ATTEST_REPORT_LEN)");

        unsigned char *report_buf = NULL;
        if (report_len < 0 || report_len > MAX_REPORT_LEN)
        {
            fprintf(stderr, "[MASTER] round %d: report_len %d out of bounds, rejecting\n",
                    round, report_len);
            MPI_Comm_disconnect(&inter);
            continue;
        }
        if (report_len > 0)
        {
            report_buf = (unsigned char *)malloc((size_t)report_len);
            if (!report_buf)
            {
                fprintf(stderr, "[MASTER] malloc report_buf failed\n");
                MPI_Abort(MPI_COMM_WORLD, 1);
            }
            mpi_recv(report_buf, report_len, MPI_UNSIGNED_CHAR, 0,
                     TAG_ATTEST_REPORT_DATA, inter, MPI_STATUS_IGNORE, "Recv(ATTEST_REPORT_DATA)");
        }

        unsigned char expected_report_data[REPORT_DATA_SIZE];
        crypto_generichash_state hst;
        crypto_generichash_init(&hst, NULL, 0, REPORT_DATA_SIZE);
        crypto_generichash_update(&hst, nonceM, REPORT_DATA_SIZE);
        crypto_generichash_update(&hst, client_pk, crypto_kx_PUBLICKEYBYTES);
        crypto_generichash_final(&hst, expected_report_data, REPORT_DATA_SIZE);

        int attest_ok = (verify_sev_snp_report(report_buf, report_len, expected_report_data) == 0) ? 1 : 0;
        free(report_buf);

#ifdef SKIP_ATTESTATION
        /* Override for development / non-SNP machines */
        attest_ok = 1;
#endif

        mpi_send(&attest_ok, 1, MPI_INT, 0,
                 TAG_ATTEST_RESULT, inter, "Send(ATTEST_RESULT)");

        if (!attest_ok)
        {
            fprintf(stderr, "[MASTER] round %d: attestation FAILED, disconnecting\n", round);
            MPI_Comm_disconnect(&inter);
            continue;
        }

        unsigned char server_pk[crypto_kx_PUBLICKEYBYTES];
        unsigned char server_sk[crypto_kx_SECRETKEYBYTES];
        unsigned char rx[KEYB], tx[KEYB], app_key[KEYB];

        crypto_kx_keypair(server_pk, server_sk);

        mpi_send(server_pk, crypto_kx_PUBLICKEYBYTES, MPI_UNSIGNED_CHAR, 0,
                 TAG_KX_SERVER_PK, inter, "Send(KX_SERVER_PK)");

        if (crypto_kx_server_session_keys(rx, tx, server_pk, server_sk, client_pk) != 0)
        {
            fprintf(stderr, "[MASTER] crypto_kx_server_session_keys failed\n");
            MPI_Abort(MPI_COMM_WORLD, 1);
        }

        /* Derive a single symmetric app_key from the tx key.
           NOTE: master uses tx, worker uses rx — they match (crypto_kx guarantee). */
        crypto_generichash_state hst2;
        crypto_generichash_init(&hst2, NULL, 0, KEYB);
        crypto_generichash_update(&hst2, tx, KEYB);
        const char *label = "app_key";
        crypto_generichash_update(&hst2, (const unsigned char *)label, strlen(label));
        crypto_generichash_final(&hst2, app_key, KEYB);

        /* Zeroize intermediate secrets */
        sodium_memzero(server_sk, sizeof server_sk);
        sodium_memzero(rx, sizeof rx);
        sodium_memzero(tx, sizeof tx);

        if (nworkers >= MAX_WORKERS)
        {
            fprintf(stderr, "[MASTER] too many workers\n");
            MPI_Abort(MPI_COMM_WORLD, 1);
        }
        workers[nworkers] = inter;
        memcpy(wkey[nworkers], app_key, KEYB);
        sodium_memzero(app_key, KEYB);

        printf("[MASTER] round %d: worker #%d joined (STAR), key ok\n", round, nworkers + 1);

        nworkers++;
    }

    /* ── Task distribution ── */
    int tasks[] = {2, 3, 4, 5, 6, 7, 8, 9, 10};
    int NT = (int)(sizeof(tasks) / sizeof(tasks[0]));
    int next = 0;
    int results_received = 0;

    if (nworkers == 0)
    {
        printf("[MASTER] no workers, exit.\n");
        MPI_Finalize();
        return 0;
    }

    /* Send one initial task to each worker (or IDLE if more workers than tasks) */
    for (int i = 0; i < nworkers; i++)
    {
        if (next < NT)
            secure_send_task(workers[i], wkey[i], i, tasks[next++]);
        else
            secure_send_ctrl(workers[i], wkey[i], i, TAG_IDLE, CTRL_MAGIC_IDLE);
    }

    /* Collect results and hand out remaining tasks */
    while (results_received < NT)
    {
        int progressed = 0;
        for (int i = 0; i < nworkers; i++)
        {
            MPI_Status st;
            if (!mpi_iprobe(0, TAG_RESULT, workers[i], &st, "Iprobe(TAG_RESULT)"))
                continue;

            int pair[2];
            if (secure_recv_result(workers[i], wkey[i], i, pair) != 0)
            {
                fprintf(stderr, "[MASTER] dropping tampered result from worker#%d\n", i + 1);
                continue;
            }
            results_received++;
            printf("[MASTER] result %d/%d from worker#%d: %d -> %d\n",
                   results_received, NT, i + 1, pair[0], pair[1]);

            progressed = 1;

            if (next < NT)
            {
                secure_send_task(workers[i], wkey[i], i, tasks[next++]);
            }
            else
                secure_send_ctrl(workers[i], wkey[i], i, TAG_IDLE, CTRL_MAGIC_IDLE);
        }

        if (!progressed)
        {
            /* All tasks dispatched but results still pending; brief sleep to avoid busy-spin */
            struct timespec ts = {0, POLL_INTERVAL_NS};
            nanosleep(&ts, NULL);
        }
    }

    /* Tell every worker to shut down, then disconnect */
    for (int i = 0; i < nworkers; i++)
    {
        secure_send_ctrl(workers[i], wkey[i], i, TAG_SHUTDOWN, CTRL_MAGIC_SHUTDOWN);
        MPI_Comm_disconnect(&workers[i]);
    }

    /* Wipe key material */
    sodium_memzero(wkey, sizeof wkey);

    printf("[MASTER] done.\n");
    MPI_Finalize();
    return 0;
}