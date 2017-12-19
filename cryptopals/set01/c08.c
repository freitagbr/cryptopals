#include <assert.h>
#include <float.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cryptopals/block.h"
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

int challenge_08(const char *file, uint8_t **dst, size_t *dstlen) {
    uint8_t *buf = NULL;
    uint8_t *line = NULL;
    file_line *lines = NULL;
    file_line *curr = NULL;
    file_line *aes = NULL;
    float global_min_dist = FLT_MAX;
    size_t linelen = 0;
    int status = -1;

    if (!file_getlines(file, &buf, &lines)) {
        goto end;
    }

    curr = lines;

    while (curr != NULL) {
        if (!hex_decode(&line, &linelen, curr->line, curr->len)) {
            goto end;
        }

        size_t local_max_keysize = linelen / 2;
        float local_min_dist = 0.0;
        size_t local_keysize = 0;

        if (!block_get_keysize(line, linelen, &local_min_dist, &local_keysize, local_max_keysize)) {
            goto end;
        }

        if (local_min_dist < global_min_dist) {
            global_min_dist = local_min_dist;
            aes = curr;
        }

        curr = curr->next;
    }

    *dstlen = aes->len;
    *dst = (uint8_t *) calloc(*dstlen + 1, sizeof (uint8_t));
    memcpy(*dst, aes->line, *dstlen);
    status = 0;

end:
    if (buf != NULL) {
        free((void *) buf);
    }
    if (line != NULL) {
        free((void *) line);
    }
    file_line_delete(lines);

    return status;
}

int main() {
    const uint8_t expected[] = "d880619740a8a19b7840a8a31c810a3d08649af70"
        "dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4"
        "fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d"
        "69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744"
        "cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a";
    uint8_t *output = NULL;
    size_t len = 0;

    assert(challenge_08("data/c08.txt", &output, &len) == 0);
    assert(strcmp((const char *) output, (const char *) expected) == 0);
    assert(len == 320);

    free((void *) output);
}
