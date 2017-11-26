#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "hex.h"
#include "score.h"
#include "../error.h"

int main(int argc, char **argv) {
    if (argc != 2) {
        return error("one argument required");
    }

    const unsigned char *inp = (unsigned char *) argv[1];
    const size_t inplen = strlen((const char *) inp);

    if ((inplen % 2) != 0) {
        return error("inputs must be valid hex strings");
    }

    const size_t len = hex_decoded_length(inplen);
    unsigned char *src = (unsigned char *) malloc(sizeof (unsigned char) * len);

    if (!hex_decode(inp, inplen, src, len)) {
        return error("input must be a valid hex string");
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

    unsigned char *dst = (unsigned char *) malloc(sizeof (unsigned char) * len);

    for (size_t i = 0; i < len; i++) {
        dst[i] = src[i] ^ key;
    }

    printf("%s\n", dst);
    free((void *) src);
    free((void *) dst);

    return EXIT_SUCCESS;
}
