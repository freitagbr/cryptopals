#include "base64.h"
#include "file.h"
#include "hamming.h"
#include "xor.h"

#include <assert.h>
#include <float.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_KEYSIZE 40

/** Break repeating-key XOR
 *
 * There's a file here. It's been base64'd after being encrypted with
 * repeating-key XOR.
 *
 * Decrypt it.
 *
 * Here's how:
 *
 * 1. Let KEYSIZE be the guessed length of the key; try values from 2 to (say)
 *    40.
 *
 * 2. Write a function to compute the edit distance/Hamming distance between two
 *    strings. The Hamming distance is just the number of differing bits. The
 *    distance between:
 *
 *    this is a test
 *
 *    and
 *
 *    wokka wokka!!!
 *
 *    is 37. Make sure your code agrees before you proceed.
 *
 * 3. For each KEYSIZE, take the first KEYSIZE worth of bytes, and the second
 *    KEYSIZE worth of bytes, and find the edit distance between them. Normalize
 *    this result by dividing by KEYSIZE.
 *
 * 4. The KEYSIZE with the smallest normalized edit distance is probably the
 *    key. You could proceed perhaps with the smallest 2-3 KEYSIZE values. Or
 *    take 4 KEYSIZE blocks instead of 2 and average the distances.
 *
 * 5. Now that you probably know the KEYSIZE: break the ciphertext into blocks
 *    of KEYSIZE length.
 *
 * 6. Now transpose the blocks: make a block that is the first byte of every
 *    block, and a block that is the second byte of every block, and so on.
 *
 * 7. Solve each block as if it was single-character XOR. You already have code
 *    to do this.
 *
 * 8. For each block, the single-byte XOR key that produces the best looking
 *    histogram is the repeating-key XOR key byte for that block. Put them
 *    together and you have the key.
 *
 * This code is going to turn out to be surprisingly useful later on. Breaking
 * repeating-key XOR ("Vigenere") statistically is obviously an academic
 * exercise, a "Crypto 101" thing. But more people "know how" to break it than
 * can actually break it, and a similar technique breaks something much more
 * important.
 */

int challenge_06(const char *file, unsigned char **dst) {
    unsigned char *decoded = NULL;
    unsigned char *block = NULL;
    unsigned char *key = NULL;
    size_t len = 0;
    int status = -1;

    if (!base64_decode_file(file, &decoded, &len)) {
        goto end;
    }

    unsigned char block_a[MAX_KEYSIZE + 1];
    unsigned char block_b[MAX_KEYSIZE + 1];
    float min_dist = FLT_MAX;
    size_t keysize = 0;

    // check keysizes between 2 and MAX_KEYSIZE (default 40)
    for (size_t k = 2; k <= MAX_KEYSIZE; k++) {
        // break the data into blocks of size of the key,
        // but ignore the trailing block, which may be
        // smaller than the other blocks, preventing
        // out-of-bounds memory access
        const size_t nblocks = (len / k) - 1;
        float dist = 0;

        // clear the blocks
        memset(block_a, '\0', MAX_KEYSIZE);
        memset(block_b, '\0', MAX_KEYSIZE);

        // sum the hamming distances, normalized
        // by the keysize, between adjacent blocks
        for (size_t b = 0; b < nblocks; b++) {
            const size_t offset_a = b * k;
            const size_t offset_b = offset_a + k;
            memcpy(block_a, &decoded[offset_a], k);
            memcpy(block_b, &decoded[offset_b], k);
            float hd = (float) hamming_distance(block_a, block_b, k);
            dist += (float) (hd / (float) k);
        }

        // average the hamming distances
        dist /= (float) nblocks;

        if (dist < min_dist) {
            min_dist = dist;
            keysize = (size_t) k;
        }
    }

    const size_t blocklen = len / keysize;
    block = (unsigned char *) malloc((sizeof (unsigned char) * blocklen) + 1);
    if (block == NULL) {
        goto end;
    }

    key = (unsigned char *) malloc((sizeof (unsigned char) * keysize) + 1);
    if (key == NULL) {
        goto end;
    }
    key[keysize] = '\0';

    // transpose blocks
    for (size_t b = 0; b < keysize; b++) {
        for (size_t i = 0, j = b; (i < blocklen) && (j < len); i++, j += keysize) {
            block[i] = decoded[j];
        }

        int max_score = 0;
        unsigned char block_key = xor_find_cipher(block, blocklen, &max_score);

        key[b] = block_key;
    }

    *dst = (unsigned char *) malloc((sizeof (unsigned char) * len) + 1);
    if (*dst == NULL) {
        goto end;
    }
    (*dst)[len] = '\0';

    if (!xor_repeating(decoded, len, dst, (const char *) key, keysize)) {
        goto end;
    }

    status = 0;

end:

    // the C standard says that free(NULL) is a no-op,
    // but it causes trouble on certain platforms,
    // so it is best to be defensive here
    if (key != NULL) {
        free((void *) key);
    }
    if (block != NULL) {
        free((void *) block);
    }
    if (decoded != NULL) {
        free((void *) decoded);
    }

    return status;
}

int main() {
    const unsigned char a[15] = "this is a test";
    const unsigned char b[15] = "wokka wokka!!!";

    assert(hamming_distance(a, b, 15) == 37);

    unsigned char *expected = NULL;
    size_t read = 0;

    assert(file_read("data/c06_test.txt", &expected, &read));

    unsigned char *output = NULL;

    assert(challenge_06("data/c06.txt", &output) == 0);
    assert(strcmp((const char *) output, (const char *) expected) == 0);

    free((void *) expected);
    free((void *) output);
}
