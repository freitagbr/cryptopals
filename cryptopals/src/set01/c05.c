#include "hex.h"
#include "xor.h"

#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

int challenge_05(const unsigned char *src, const size_t srclen, unsigned char **dst) {
    unsigned char *tmp = NULL;

    repeating_xor(src, srclen, &tmp, "ICE", 3);

    size_t dstlen = 0;

    hex_encode(tmp, srclen, dst, &dstlen);

    free((void *) tmp);

    return 0;
}

int main() {
    const unsigned char input[] =
        "Burning 'em, if you ain't quick and nimble\n"
        "I go crazy when I hear a cymbal";
    const unsigned char expected[] =
        "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272"
        "a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
    unsigned char *output = NULL;

    assert(challenge_05(input, 74, &output) == 0);
    assert(strcmp((const char *) output, (const char *) expected) == 0);

    free((void *) output);
}
