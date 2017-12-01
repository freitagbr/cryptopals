#include "block.h"
#include "hamming.h"
#include "xor.h"

#include <float.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int block_get_keysize(uint8_t *buf, size_t len, float *min_dist, size_t *keysize, size_t max_keysize) {
    uint8_t *block_a = NULL;
    uint8_t *block_b = NULL;

    *min_dist = FLT_MAX;
    *keysize = 0;
    block_a = (uint8_t *) calloc(max_keysize + 1, sizeof (uint8_t));
    block_b = (uint8_t *) calloc(max_keysize + 1, sizeof (uint8_t));

    if ((block_a == NULL) || (block_b == NULL)) {
        return 0;
    }

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

    free((void *) block_a);
    free((void *) block_b);

    return 1;
}

int block_transpose_get_key(uint8_t *buf, size_t len, uint8_t **key, size_t *keysize, size_t max_keysize) {
    uint8_t *block = NULL;
    uint8_t *k = NULL;
    float min_dist = 0;
    int status = 0;

    if (!block_get_keysize(buf, len, &min_dist, keysize, max_keysize)) {
        *keysize = 0;
        goto end;
    }

    const size_t blocklen = len / *keysize;

    block = (uint8_t *) calloc(blocklen + 1, sizeof (uint8_t));
    if (block == NULL) {
        goto end;
    }

    k = *key = (uint8_t *) calloc(*keysize + 1, sizeof (uint8_t));
    if (k == NULL) {
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

    status = 1;

end:
    if (block != NULL) {
        free((void *) block);
    }

    return status;
}
