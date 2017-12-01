#include "base64.h"
#include "block.h"
#include "file.h"
#include "xor.h"

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_KEYSIZE 40

/**
 * Break repeating-key XOR
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

int challenge_06(const char *file, uint8_t **dst) {
    uint8_t *buf = NULL;
    uint8_t *block = NULL;
    uint8_t *key = NULL;
    size_t buflen = 0;
    size_t keysize = 0;
    int status = -1;

    if (!base64_decode_file(file, &buf, &buflen)) {
        goto end;
    }

    if (!block_transpose_get_key(buf, buflen, &key, &keysize, MAX_KEYSIZE)) {
        goto end;
    }

    if (!xor_repeating(dst, buf, buflen, (const uint8_t *) key, keysize)) {
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
    if (buf != NULL) {
        free((void *) buf);
    }

    return status;
}

int main() {
    uint8_t *expected = NULL;
    size_t read = 0;

    assert(file_read("data/c06_test.txt", &expected, &read));

    uint8_t *output = NULL;

    assert(challenge_06("data/c06.txt", &output) == 0);
    assert(strcmp((const char *) output, (const char *) expected) == 0);

    free((void *) expected);
    free((void *) output);
}
