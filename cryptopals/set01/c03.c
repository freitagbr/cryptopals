#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cryptopals/hex.h"
#include "cryptopals/xor.h"

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

int challenge_03(const uint8_t *hex, const size_t hexlen, uint8_t **dst) {
    uint8_t *src = NULL;
    size_t len = 0;
    int status = -1;

    if ((hexlen % 2) != 0) {
        goto end;
    }

    if (!hex_decode(&src, &len, hex, hexlen)) {
        goto end;
    }

    int max_score = 0;
    uint8_t key = xor_find_cipher(src, len, &max_score);

    if (!xor_single_byte(dst, src, len, key)) {
        goto end;
    }

    status = 0;

end:
    if (src != NULL) {
        free((void *) src);
    }

    return status;
}

int main() {
    const uint8_t input[] = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    const uint8_t expected[] = "Cooking MC's like a pound of bacon";
    uint8_t *output = NULL;

    assert(challenge_03(input, 68, &output) == 0);
    assert(strcmp((const char *) output, (const char *) expected) == 0);

    free((void *) output);
}
