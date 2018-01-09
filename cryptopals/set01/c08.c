#include <assert.h>
#include <float.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cryptopals/block.h"
#include "cryptopals/error.h"
#include "cryptopals/file.h"
#include "cryptopals/hex.h"

/**
 * Detect AES in ECB mode
 *
 * In this file are a bunch of hex-encoded ciphertexts.
 *
 * One of them has been encrypted with ECB.
 *
 * Detect it.
 *
 * Remember that the problem with ECB is that it is stateless and
 * deterministic; the same 16 byte plaintext block will always produce the same
 * 16 byte ciphertext.
 */

error_t challenge_08(const char *file, uint8_t **dst, size_t *dstlen) {
    FILE *fp = fopen(file, "rb");
    uint8_t *buf = NULL;
    uint8_t *line = NULL;
    uint8_t *aes = NULL;
    float global_min_dist = FLT_MAX;
    size_t buflen = 0;
    size_t linelen = 0;
    size_t aeslen = 0;
    long read = 0;
    error_t err = 0;

    while (((err = file_getline(fp, &buf, &buflen, &read)) == 0) && ((read - 1) > 0)) {
        err = hex_decode(&line, &linelen, buf, read - 1);
        if (err) {
            goto end;
        }

        size_t local_max_keysize = linelen / 2;
        float local_min_dist = 0.0;
        size_t local_keysize = 0;

        err = block_get_keysize(line, linelen, &local_min_dist, &local_keysize, local_max_keysize);
        if (err) {
            goto end;
        }

        if (local_min_dist < global_min_dist) {
            global_min_dist = local_min_dist;
            if ((aes == NULL) && (aeslen == 0)) {
                aeslen = read - 1;
                aes = (uint8_t *) calloc(aeslen + 1, sizeof (uint8_t));
                if (aes == NULL) {
                    err = EMALLOC;
                    goto end;
                }
            } else if ((size_t) read > aeslen) {
                aeslen = read - 1;
                aes = (uint8_t *) realloc(aes, sizeof (uint8_t) * (aeslen + 1));
                if (aes == NULL) {
                    err = EMALLOC;
                    goto end;
                }
            }
            if (aes != NULL) {
                memcpy(aes, buf, read);
            }
        }
    }

    if (err) {
        goto end;
    }

    if (aes != NULL) {
        *dstlen = aeslen;
        *dst = (uint8_t *) calloc(*dstlen + 1, sizeof (uint8_t));
        memcpy(*dst, aes, *dstlen);
    }

end:
    if (fp != NULL) {
        fclose(fp);
    }
    if (buf != NULL) {
        free((void *) buf);
    }
    if (line != NULL) {
        free((void *) line);
    }
    if (aes != NULL) {
        free((void *) aes);
    }

    return err;
}

int main() {
    const uint8_t expected[] = "d880619740a8a19b7840a8a31c810a3d08649af70"
        "dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4"
        "fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d"
        "69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744"
        "cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a";
    uint8_t *output = NULL;
    size_t len = 0;
    error_t err = 0;

    err = challenge_08("data/c08.txt", &output, &len);
    if (err) {
        error(err);
        goto end;
    }

    if (len != 320) {
        error(ESIZE);
        goto end;
    }

    error_expect((const char *) expected, (const char *) output);

end:
    free((void *) output);

    return (int) err;
}
