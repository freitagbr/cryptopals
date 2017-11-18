#include <stdlib.h>
#include <stdio.h>
#include <string.h>

void error(const char *msg) {
    fprintf(stderr, "%s\n", msg);
    exit(EXIT_FAILURE);
}

int main(int argc, char **argv) {
    if (argc != 3) {
        error("two arguments required");
    }

    const unsigned char *a_inp = (unsigned char *) argv[1];
    const unsigned char *b_inp = (unsigned char *) argv[2];
    const int alen = strlen((const char *) a_inp);
    const int blen = strlen((const char *) b_inp);

    if (alen != blen) {
        error("inputs must the same length");
    }

    if ((alen % 2) != 0) {
        error("inputs must be valid hex strings");
    }

    const int len = (alen + (alen % 2)) / 2;
    const unsigned char *a = (unsigned char *) malloc(sizeof (unsigned char) * len);
    const unsigned char *b = (unsigned char *) malloc(sizeof (unsigned char) * len);

    for (int i = 0, s = 0; i < alen; i += 2, s += 1) {
        int ra = sscanf((const char *) &a_inp[i], "%2hhx", (unsigned char *) &a[s]);
        int rb = sscanf((const char *) &b_inp[i], "%2hhx", (unsigned char *) &b[s]);
        if ((ra != 1) || (rb != 1)) {
            error("inputs must be valid hex strings");
        }
    }

    unsigned char *c = (unsigned char *) malloc(sizeof (unsigned char) * len);

    for (int i = 0, s = 0; i < len; i += 1, s += 2) {
        sprintf((char *) &c[s], "%02x", a[i] ^ b[i]);
    }

    printf("%s\n", c);
    free((void *) a);
    free((void *) b);
    free((void *) c);

    exit(EXIT_SUCCESS);
}
