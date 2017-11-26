#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "base64.h"
#include "hex.h"
#include "error.h"

int challenge_01(const unsigned char *src, const size_t srclen, unsigned char **dst) {
    const size_t hexlen = hex_decoded_length(srclen);
    unsigned char *hex = (unsigned char *) malloc(sizeof (unsigned char) * hexlen);

    if (!hex_decode(src, srclen, hex, hexlen)) {
        return -1;
    }

    const int dstlen = encoded_length(hexlen);
    *dst = (unsigned char *) malloc(sizeof (unsigned char) * dstlen);

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
}
