#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "cryptopals/pad.h"

#define IV 0x04

/**
 * Implement PKCS#7 padding
 *
 * A block cipher transforms a fixed-sized block (usually 8 or 16 bytes) of
 * plaintext into ciphertext. But we almost never want to transform a single
 * block; we encrypt irregularly-sized messages.
 *
 * One way we account for irregularly-sized messages is by padding, creating a
 * plaintext that is an even multiple of the blocksize. The most popular
 * padding scheme is called PKCS#7.
 *
 * So: pad any block to a specific block length, by appending the number of
 * bytes of padding to the end of the block. For instance,
 *
 * "YELLOW SUBMARINE"
 *
 * ... padded to 20 bytes would be:
 *
 * "YELLOW SUBMARINE\x04\x04\x04\x04"
 */

int challenge_09(const uint8_t *src, const size_t srclen, uint8_t **dst, const size_t dstlen) {
    if (!pad_bytes(dst, dstlen, src, srclen, IV)) {
        return -1;
    }
    return 0;
}

int main() {
    const uint8_t input[] = "YELLOW SUBMARINE";
    const uint8_t expected[] = "YELLOW SUBMARINE\x04\x04\x04\04";
    uint8_t *output = NULL;

    assert(challenge_09(input, 16, &output, 20) == 0);
    assert(strcmp((const char *) output, (const char *) expected) == 0);

    free((void *) output);
}
