#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "hex.h"
#include "score.h"
#include "error.h"

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

    const size_t len = hex_decoded_length(hexlen);
    unsigned char *src = (unsigned char *) malloc(sizeof (unsigned char) * len);

    if (!hex_decode(hex, hexlen, src, len)) {
        return -1;
    }

    int max_score = 0;
    unsigned char key = 0;

    for (int k = 0; k <= 0xFF; ++k) {
        int s = score(src, len, (unsigned char) k);
        if (s > max_score) {
            max_score = s;
            key = (unsigned char) k;
        }
    }

    *dst = (unsigned char *) malloc(sizeof (unsigned char) * len);

    for (size_t i = 0; i < len; i++) {
        (*dst)[i] = src[i] ^ key;
    }

    return 0;
}

int main() {
    const unsigned char input[] = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    const unsigned char expected[] = "Cooking MC's like a pound of bacon";
    unsigned char *output = NULL;

    assert(challenge_03(input, 68, &output) == 0);
    assert(strcmp((const char *) output, (const char *) expected) == 0);
}
