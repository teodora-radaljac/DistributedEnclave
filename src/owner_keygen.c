#include <sodium.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int write_new_file(const char *path, const unsigned char *data,
                          size_t data_len, mode_t mode)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, mode);
    if (fd < 0) {
        fprintf(stderr, "cannot create %s: %s\n", path, strerror(errno));
        return -1;
    }

    size_t written = 0;
    while (written < data_len) {
        ssize_t count = write(fd, data + written, data_len - written);
        if (count < 0) {
            if (errno == EINTR) continue;
            fprintf(stderr, "cannot write %s: %s\n", path, strerror(errno));
            close(fd);
            unlink(path);
            return -1;
        }
        written += (size_t)count;
    }
    int sync_result = fsync(fd);
    int close_result = close(fd);
    if (sync_result != 0 || close_result != 0) {
        fprintf(stderr, "cannot finalize %s: %s\n", path, strerror(errno));
        unlink(path);
        return -1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 3) {
        fprintf(stderr, "usage: %s <public-key-file> <secret-key-file>\n", argv[0]);
        return 2;
    }
    if (sodium_init() < 0) {
        fprintf(stderr, "libsodium initialization failed\n");
        return 1;
    }

    unsigned char public_key[crypto_sign_PUBLICKEYBYTES];
    unsigned char secret_key[crypto_sign_SECRETKEYBYTES];
    crypto_sign_keypair(public_key, secret_key);

    if (write_new_file(argv[2], secret_key, sizeof secret_key, 0600) != 0) {
        sodium_memzero(secret_key, sizeof secret_key);
        return 1;
    }
    if (write_new_file(argv[1], public_key, sizeof public_key, 0644) != 0) {
        unlink(argv[2]);
        sodium_memzero(secret_key, sizeof secret_key);
        return 1;
    }

    unsigned char fingerprint[16];
    char fingerprint_hex[sizeof fingerprint * 2 + 1];
    crypto_generichash(fingerprint, sizeof fingerprint,
                       public_key, sizeof public_key, NULL, 0);
    sodium_bin2hex(fingerprint_hex, sizeof fingerprint_hex,
                   fingerprint, sizeof fingerprint);

    printf("owner public key: %s\n", argv[1]);
    printf("owner secret key: %s (keep only on the central node)\n", argv[2]);
    printf("public-key fingerprint: %s\n", fingerprint_hex);

    sodium_memzero(secret_key, sizeof secret_key);
    sodium_memzero(fingerprint, sizeof fingerprint);
    return 0;
}