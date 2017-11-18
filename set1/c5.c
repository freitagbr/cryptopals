#include <stdlib.h>
#include <stdio.h>
#include <string.h>

static const unsigned char key[] = "ICE";

void error(const char *msg) {
    fprintf(stderr, "%s\n", msg);
    exit(EXIT_FAILURE);
}

int main(int argc, char **argv) {
    if (argc != 2) {
        error("one argument required");
    }

    const unsigned char *src = (const unsigned char *) argv[1];
    const int len = strlen((const char *) src);
    const unsigned char *dst = (unsigned char *) malloc(sizeof (unsigned char) * len * 2);

    for (int i = 0, s = 0, k = 0; i < len; i += 1, s += 2, k = (k + 1) % 3) {
        sprintf((char *) &dst[s], "%02x", src[i] ^ key[k]);
    }

    printf("%s\n", dst);
    free((void *) dst);

    exit(EXIT_SUCCESS);
}
