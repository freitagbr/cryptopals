#include <assert.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

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

int challenge_09(const unsigned char *src, const size_t srclen, unsigned char **dst, size_t dstlen) {
    int status = -1;

    if (dstlen < srclen) {
        goto end;
    }

    *dst = (unsigned char *) malloc((sizeof (unsigned char) * dstlen) + 1);
    if (*dst == NULL) {
        goto end;
    }

    memset(*dst, IV, dstlen);
    memcpy(*dst, src, srclen);
    (*dst)[dstlen] = '\0';
    status = 0;

end:
    return status;
}

int main() {
    const unsigned char input[] = "YELLOW SUBMARINE";
    const unsigned char expected[] = "YELLOW SUBMARINE\x04\x04\x04\04";
    unsigned char *output = NULL;

    assert(challenge_09(input, 16, &output, 20) == 0);
    assert(strcmp((const char *) output, (const char *) expected) == 0);

    free((void *) output);
}
