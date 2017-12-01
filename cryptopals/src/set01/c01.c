#include "base64.h"
#include "hex.h"

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
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

int challenge_01(const uint8_t *src, const size_t srclen, uint8_t **dst) {
    size_t hexlen = 0;
    uint8_t *hex = NULL;
    int status = -1;

    if (!hex_decode(&hex, &hexlen, src, srclen)) {
        goto end;
    }

    size_t dstlen = 0;

    if (!base64_encode(dst, &dstlen, hex, hexlen)) {
        goto end;
    }

    status = 0;

end:
    if (hex != NULL) {
        free((void *) hex);
    }

    return status;
}

int main() {
    const uint8_t input[] = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    const uint8_t expected[] = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
    uint8_t *output = NULL;

    assert(challenge_01(input, 96, &output) == 0);
    assert(strcmp((const char *) output, (const char *) expected) == 0);

    free((void *) output);
}
