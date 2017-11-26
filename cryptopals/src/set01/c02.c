#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "hex.h"

/**
 * Fixed XOR
 *
 * Write a function that takes two equal-length buffers and produces their
 * XOR combination.
 *
 * If your function works properly, then when you feed it the string:
 *
 * 1c0111001f010100061a024b53535009181c
 *
 * ... after hex decoding, and when XOR'd against:
 *
 * 686974207468652062756c6c277320657965
 *
 * ... should produce:
 *
 * 746865206b696420646f6e277420706c6179
 */

int challenge_02(const unsigned char *ahex, const size_t alen, const unsigned char *bhex, const size_t blen, unsigned char **dst) {
    if (alen != blen) {
        return -1;
    }
    if (((alen % 2) != 0) || ((blen % 2) != 0)) {
        return -1;
    }

    const size_t len = hex_decoded_length(alen);
    unsigned char *a = (unsigned char *) malloc(sizeof (unsigned char) * len);
    unsigned char *b = (unsigned char *) malloc(sizeof (unsigned char) * len);

    if (!hex_decode(ahex, alen, a, len) || !hex_decode(bhex, blen, b, len)) {
        return -1;
    }

    for (size_t i = 0; i < len; i++) {
        a[i] = a[i] ^ b[i];
    }

    const size_t dstlen = hex_encoded_length(len);
    *dst = (unsigned char *) malloc(sizeof (unsigned char) * dstlen);

    hex_encode(a, len, *dst, dstlen);
    free((void *) a);
    free((void *) b);

    return 0;
}

int main() {
    const unsigned char input_a[] = "1c0111001f010100061a024b53535009181c";
    const unsigned char input_b[] = "686974207468652062756c6c277320657965";
    const unsigned char expected[] = "746865206b696420646f6e277420706c6179";
    unsigned char *output = NULL;

    assert(challenge_02(input_a, 36, input_b, 36, &output) == 0);
    assert(strcmp((const char *) output, (const char *) expected) == 0);
}
