#include "cryptopals/block.h"

#include <float.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "cryptopals/error.h"
#include "cryptopals/hamming.h"
#include "cryptopals/xor.h"

error_t block_get_keysize(uint8_t *buf, size_t len, float *min_dist, size_t *keysize, size_t max_keysize) {
    uint8_t *block_a = (uint8_t *) calloc(max_keysize + 1, sizeof (uint8_t));
    uint8_t *block_b = (uint8_t *) calloc(max_keysize + 1, sizeof (uint8_t));
    error_t err = 0;

    if ((block_a == NULL) || (block_b == NULL)) {
        err = EMALLOC;
        goto end;
    }

    *min_dist = FLT_MAX;
    *keysize = 0;

    // check keysizes between 2 and max_keysize
    for (size_t k = 2; k <= max_keysize; k++) {
        // break the data into blocks of size of the key,
        // but ignore the trailing block, which may be
        // smaller than the other blocks, preventing
        // out-of-bounds memory access
        const size_t nblocks = (len / k) - 1;
        float dist = 0;

        // sum the hamming distances, normalized
        // by the keysize, between adjacent blocks
        for (size_t b = 0; b < nblocks; b++) {
            const size_t offset_a = b * k;
            const size_t offset_b = offset_a + k;
            memcpy(block_a, &buf[offset_a], k);
            memcpy(block_b, &buf[offset_b], k);
            float hd = (float) hamming_distance(block_a, block_b, k);
            dist += (float) (hd / (float) k);
        }

        // average the hamming distances
        dist /= (float) nblocks;

        if (dist < *min_dist) {
            *min_dist = dist;
            *keysize = (size_t) k;
        }
    }

end:
    if (block_a != NULL) {
        free((void *) block_a);
    }
    if (block_b != NULL) {
        free((void *) block_b);
    }

    return err;
}

error_t block_transpose_get_key(uint8_t *buf, size_t len, uint8_t **key, size_t *keysize, size_t max_keysize) {
    uint8_t *block = NULL;
    uint8_t *k = NULL;
    float min_dist = 0;
    error_t err = 0;

    err = block_get_keysize(buf, len, &min_dist, keysize, max_keysize);
    if (err) {
        *keysize = 0;
        goto end;
    }

    const size_t blocklen = len / *keysize;

    block = (uint8_t *) calloc(blocklen + 1, sizeof (uint8_t));
    if (block == NULL) {
        err = EMALLOC;
        goto end;
    }

    k = *key = (uint8_t *) calloc(*keysize + 1, sizeof (uint8_t));
    if (k == NULL) {
        err = EMALLOC;
        goto end;
    }

    // transpose blocks
    for (size_t b = 0; b < *keysize; b++) {
        for (size_t i = 0, j = b; (i < blocklen) && (j < len); i++, j += *keysize) {
            block[i] = buf[j];
        }

        int max_score = 0;
        *k++ = xor_find_cipher(block, blocklen, &max_score);
    }

end:
    if (block != NULL) {
        free((void *) block);
    }

    return err;
}