#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "cryptopals/error.h"
#include "cryptopals/hex.h"
#include "cryptopals/xor.h"

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

error_t challenge_02(const uint8_t *ahex, const size_t ahexlen, const uint8_t *bhex, const size_t bhexlen, uint8_t **dst) {
    uint8_t *a = NULL;
    uint8_t *b = NULL;
    size_t alen = 0;
    size_t blen = 0;
    size_t dstlen = 0;
    error_t err = 0;

    if (ahexlen != bhexlen) {
        err = ESIZE;
        goto end;
    }

    err = hex_decode(&a, &alen, ahex, ahexlen);
    if (err) {
        goto end;
    }

    err = hex_decode(&b, &blen, bhex, bhexlen);
    if (err) {
        goto end;
    }

    if (alen != blen) {
        err = ESIZE;
        goto end;
    }

    err = xor_fixed(a, alen, b, blen);
    if (err) {
        goto end;
    }

    err = hex_encode(dst, &dstlen, a, alen);
    if (err) {
        goto end;
    }

end:
    if (a != NULL) {
        free((void *) a);
    }
    if (b != NULL) {
        free((void *) b);
    }

    return err;
}

int main() {
    const uint8_t input_a[] = "1c0111001f010100061a024b53535009181c";
    const uint8_t input_b[] = "686974207468652062756c6c277320657965";
    const uint8_t expected[] = "746865206b696420646f6e277420706c6179";
    uint8_t *output = NULL;
    error_t err = 0;

    err = challenge_02(input_a, 36, input_b, 36, &output);
    if (err) {
        error(err);
        goto end;
    }

    error_expect((const char *) expected, (const char *) output);

end:
    free((void *) output);

    return (int) err;
}
