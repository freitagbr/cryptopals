#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cryptopals/error.h"
#include "cryptopals/hex.h"
#include "cryptopals/xor.h"

/**
 * Implement repeating-key XOR
 *
 * Here is the opening stanza of an important work of the English language:
 *
 * Burning 'em, if you ain't quick and nimble
 * I go crazy when I hear a cymbal
 *
 * Encrypt it, under the key "ICE", using repeating-key XOR.
 *
 * In repeating-key XOR, you'll sequentially apply each byte of the key; the
 * first byte of plaintext will be XOR'd against I, the next C, the next E,
 * then I again for the 4th byte, and so on.
 *
 * It should come out to:
 *
 * 0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272
 * a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f
 *
 * Encrypt a bunch of stuff using your repeating-key XOR function. Encrypt your
 * mail. Encrypt your password file. Your .sig file. Get a feel for it. I
 * promise, we aren't wasting your time with this.
 */

error_t challenge_05(const uint8_t *src, const size_t srclen, uint8_t **dst) {
    uint8_t *tmp = NULL;
    size_t dstlen = 0;
    error_t err = 0;

    err = xor_repeating(&tmp, src, srclen, (const uint8_t *) "ICE", 3);
    if (err) {
        goto end;
    }

    err = hex_encode(dst, &dstlen, tmp, srclen);
    if (err) {
        goto end;
    }

end:
    if (tmp != NULL) {
        free((void *) tmp);
    }

    return err;
}

int main() {
    const uint8_t input[] =
        "Burning 'em, if you ain't quick and nimble\n"
        "I go crazy when I hear a cymbal";
    const uint8_t expected[] =
        "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272"
        "a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
    uint8_t *output = NULL;
    error_t err = 0;

    err = challenge_05(input, 74, &output);
    if (err) {
        error(err);
        goto end;
    }

    error_expect((const char *) expected, (const char *) output);

end:
    free((void *) output);

    return (int) err;
}