#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "base64.h"
#include "hex.h"
#include "../error.h"

int main(int argc, char **argv) {
    if (argc != 2) {
        return error("one argument required");
    }

    const unsigned char *inp = (unsigned char *) argv[1];
    const int inplen = strlen((const char *) inp);

    if ((inplen % 2) != 0) {
        return error("input must be a valid hex string");
    }

    const int srclen = hex_decoded_length(inplen);
    unsigned char *src = (unsigned char *) malloc(sizeof (unsigned char) * srclen);

    if (!hex_decode(inp, inplen, src, srclen)) {
        return error("input must be a valid hex string");
    }

    const int dstlen = encoded_length(srclen);
    unsigned char *dst = (unsigned char *) malloc(sizeof (unsigned char) * dstlen);

    if (!base64_encode(src, srclen, dst, dstlen)) {
        return error("failed to encode in base64");
    }

    printf("%s\n", dst);
    free((void *) src);
    free((void *) dst);

    return EXIT_SUCCESS;
}
