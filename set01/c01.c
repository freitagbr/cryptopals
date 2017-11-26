#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "base64.h"
#include "../error.h"

int main(int argc, char **argv) {
    if (argc != 2) {
        return error("one argument required");
    }

    const unsigned char *inp = (unsigned char *) argv[1];
    const int inplen = strlen((const char *) inp);
    const int srclen = (inplen + (inplen % 2)) / 2;
    const unsigned char *src = (unsigned char *) malloc(sizeof (unsigned char) * srclen);

    if ((inplen % 2) != 0) {
        return error("input must be a valid hex string");
    }

    for (int i = 0, s = 0; i < inplen; i += 2, s += 1) {
        int r = sscanf((const char *) &inp[i], "%2hhx", (unsigned char *) &src[s]);
        if (r != 1) {
            return error("input must be a valid hex string");
        }
    }

    const int dstlen = encoded_length(srclen);
    unsigned char *dst = (unsigned char *) malloc(sizeof (unsigned char) * dstlen);

    base64_encode(src, srclen, dst, dstlen);

    printf("%s\n", dst);
    free((void *) src);
    free((void *) dst);

    return EXIT_SUCCESS;
}
