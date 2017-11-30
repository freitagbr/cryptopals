#include "hex.h"
#include "xor.h"

#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

int challenge_02(const unsigned char *ahex, const size_t ahexlen, const unsigned char *bhex, const size_t bhexlen, unsigned char **dst) {
    unsigned char *a = NULL;
    unsigned char *b = NULL;
    size_t alen = 0;
    size_t blen = 0;
    size_t dstlen = 0;
    int status = -1;

    if (ahexlen != bhexlen) {
        goto end;
    }
    if (((ahexlen % 2) != 0) || ((bhexlen % 2) != 0)) {
        goto end;
    }

    if (!hex_decode(&a, &alen, ahex, ahexlen) || !hex_decode(&b, &blen, bhex, bhexlen)) {
        goto end;
    }

    if (alen != blen) {
        goto end;
    }

    if (!xor_fixed(a, alen, b, blen)) {
        goto end;
    }

    if (!hex_encode(dst, &dstlen, a, alen)) {
        goto end;
    }

    status = 0;

end:
    if (a != NULL) {
        free((void *) a);
    }
    if (b != NULL) {
        free((void *) b);
    }

    return status;
}

int main() {
    const unsigned char input_a[] = "1c0111001f010100061a024b53535009181c";
    const unsigned char input_b[] = "686974207468652062756c6c277320657965";
    const unsigned char expected[] = "746865206b696420646f6e277420706c6179";
    unsigned char *output = NULL;

    assert(challenge_02(input_a, 36, input_b, 36, &output) == 0);
    assert(strcmp((const char *) output, (const char *) expected) == 0);

    free((void *) output);
}
