#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "../error.h"

static const unsigned char freq[] = "etaoin shrdlu";

int score(const unsigned char *str, const int len, unsigned char key) {
    int s = 0;
    for (int i = 0; i < 13; ++i) {
        unsigned char c = freq[i];
        for (int l = 0; l < len; ++l) {
            if ((str[l] ^ key) == c) {
                ++s;
            }
        }
    }
    return s;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        return error("one argument required");
    }

    const unsigned char *inp = (unsigned char *) argv[1];
    const int inplen = strlen((const char *) inp);

    if ((inplen % 2) != 0) {
        return error("inputs must be valid hex strings");
    }

    const int len = (inplen + (inplen % 2)) / 2;
    const unsigned char *src = (unsigned char *) malloc(sizeof (unsigned char) * len);

    for (int i = 0, s = 0; i < inplen; i += 2, s += 1) {
        int r = sscanf((const char *) &inp[i], "%2hhx", (unsigned char *) &src[s]);
        if (r != 1) {
            return error("input must be a valid hex string");
        }
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

    for (int i = 0, s = 0; i < len; i += 1, s += 2) {
        dst[i] = src[i] ^ key;
    }

    printf("%s\n", dst);
    free((void *) src);
    free((void *) dst);

    return EXIT_SUCCESS;
}
