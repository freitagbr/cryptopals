#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "error.h"

static const unsigned char key[] = "ICE";

int challenge_05(const unsigned char *src, const size_t srclen, unsigned char **dst) {
    *dst = (unsigned char *) malloc(sizeof (unsigned char) * srclen * 2);

    for (size_t i = 0, s = 0, k = 0; i < srclen; i += 1, s += 2, k = (k + 1) % 3) {
        sprintf((char *) &(*dst)[s], "%02x", src[i] ^ key[k]);
    }

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
}
