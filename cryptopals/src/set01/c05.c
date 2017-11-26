#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "error.h"

static const unsigned char key[] = "ICE";

int main(int argc, char **argv) {
    if (argc != 2) {
        return error("one argument required");
    }

    const unsigned char *src = (const unsigned char *) argv[1];
    const int len = strlen((const char *) src);
    const unsigned char *dst = (unsigned char *) malloc(sizeof (unsigned char) * len * 2);

    for (int i = 0, s = 0, k = 0; i < len; i += 1, s += 2, k = (k + 1) % 3) {
        sprintf((char *) &dst[s], "%02x", src[i] ^ key[k]);
    }

    printf("%s\n", dst);
    free((void *) dst);

    return EXIT_SUCCESS;
}
