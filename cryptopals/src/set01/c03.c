#include "hex.h"
#include "xor.h"

#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/**
 * Single-byte XOR cipher
 * The hex encoded string:
 *
 * 1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736
 *
 * ... has been XOR'd against a single character. Find the key, decrypt the
 * message.
 *
 * You can do this by hand. But don't: write code to do it for you.
 *
 * How? Devise some method for "scoring" a piece of English plaintext.
 * Character frequency is a good metric. Evaluate each output and choose the
 * one with the best score.
 */

int challenge_03(const unsigned char *hex, const size_t hexlen, unsigned char **dst) {
    if ((hexlen % 2) != 0) {
        return -1;
    }

    size_t len = 0;
    unsigned char *src = NULL;

    if (!hex_decode(hex, hexlen, &src, &len)) {
        return -1;
    }

    int max_score = 0;
    unsigned char key = xor_find_cipher(src, len, &max_score);

    if (!xor_single_byte(src, len, dst, key)) {
        free((void *) src);
        return -1;
    }

    free((void *) src);

    return 0;
}

int main() {
    const unsigned char input[] = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    const unsigned char expected[] = "Cooking MC's like a pound of bacon";
    unsigned char *output = NULL;

    assert(challenge_03(input, 68, &output) == 0);
    assert(strcmp((const char *) output, (const char *) expected) == 0);

    free((void *) output);
}
