#include "base64.h"
#include "hex.h"

#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/**
 * Convert hex to base64
 *
 * The string:
 *
 * 49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d
 *
 * Should produce:
 *
 * SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t
 *
 * So go ahead and make that happen. You'll need to use this code for the rest
 * of the exercises.
 */

int challenge_01(const unsigned char *src, const size_t srclen, unsigned char **dst) {
    size_t hexlen = 0;
    unsigned char *hex = NULL;

    if (!hex_decode(src, srclen, &hex, &hexlen)) {
        return -1;
    }

    const size_t dstlen = base64_encoded_length(hexlen);
    *dst = (unsigned char *) malloc((sizeof (unsigned char) * dstlen) + 1);

    if (*dst == NULL) {
        free((void *) hex);
        return -1;
    }

    if (!base64_encode(hex, hexlen, *dst, dstlen)) {
        return -1;
    }

    free((void *) hex);

    return 0;
}

int main() {
    const unsigned char input[] = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    const unsigned char expected[] = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
    unsigned char *output = NULL;

    assert(challenge_01(input, 96, &output) == 0);
    assert(strcmp((const char *) output, (const char *) expected) == 0);

    free((void *) output);
}
