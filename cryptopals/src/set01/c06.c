#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "base64.h"
#include "hamming.h"

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

int challenge_06(const char *file) {
    unsigned char *decoded = NULL;
    size_t len = 0;

    if (!base64_decode_file(file, &decoded, &len)) {
        return -1;
    }

    unsigned char block_a[MAX_KEYSIZE + 1];
    unsigned char block_b[MAX_KEYSIZE + 1];

    for (int k = 2; k <= MAX_KEYSIZE; k++) {
        memcpy(block_a, decoded, k);
        memcpy(block_b, &decoded[k], k);
        float dist = (float) ((float) hamming_distance(block_a, block_b, k) / (float) k);
        printf("keysize: %d\tdistance: %f\n", k, dist);
    }

    return 0;
}

int main() {
    const unsigned char a[15] = "this is a test";
    const unsigned char b[15] = "wokka wokka!!!";
    assert(hamming_distance(a, b, 15) == 37);
    challenge_06("data/c06.txt");
}
