#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "cryptopals/buffer.h"
#include "cryptopals/error.h"
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

error_t challenge_03(buffer *dst, const buffer src) {
    buffer hex = buffer_init();
    error_t err = 0;

    err = hex_decode(&hex, src);
    if (err) {
        goto end;
    }

    int max_score = 0;
    uint8_t key = xor_find_cipher(hex, &max_score);

    err = xor_single_byte(dst, hex, key);
    if (err) {
        goto end;
    }

end:
    buffer_delete(hex);

    return err;
}

int main() {
    const uint8_t expected[] = "Cooking MC's like a pound of bacon";
    const buffer input = buffer_new("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736", 68);
    buffer output = buffer_init();
    error_t err = 0;

    err = challenge_03(&output, input);
    if (err) {
        error(err);
        goto end;
    }

    error_expect((const char *) expected, (const char *) output.ptr);

end:
    buffer_delete(output);

    return (int) err;
}
