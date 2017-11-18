#include <stdlib.h>
#include <stdio.h>
#include <string.h>

static const unsigned char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

void base64decode(const unsigned char *src, unsigned char *dst, int len) {
    dst[0] =             b64[(int) (  src[0]         >> 2)                            ];
    dst[1] =             b64[(int) (((src[0] & 0x03) << 4) | (((src[1] & 0xF0) >> 4)))];
    dst[2] = (len > 1) ? b64[(int) (((src[1] & 0x0F) << 2) | (((src[2] & 0xC0) >> 6)))] : '=';
    dst[3] = (len > 2) ? b64[(int) (  src[2] & 0x3F)                                  ] : '=';
}

void error(const char *msg) {
    fprintf(stderr, "%s\n", msg);
    exit(EXIT_FAILURE);
}

int main(int argc, char **argv) {
    if (argc != 2) {
        error("one argument required");
    }

    const unsigned char *inp = (unsigned char *) argv[1];
    const int inplen = strlen((const char *) inp);
    const int srclen = (inplen + (inplen % 2)) / 2;
    const unsigned char *src = (unsigned char *) malloc(sizeof (unsigned char) * srclen);

    if ((inplen % 2) != 0) {
        error("input must be a valid hex string");
    }

    for (int i = 0, s = 0; i < inplen; i += 2, s += 1) {
        int r = sscanf((const char *) &inp[i], "%2hhx", (unsigned char *) &src[s]);
        if (r != 1) {
            error("input must be a valid hex string");
        }
    }

    const int dstlen = ((srclen + (srclen % 3)) / 3) * 4;
    unsigned char *dst = (unsigned char *) malloc(sizeof (unsigned char) * dstlen);

    for (int s = 0, d = 0; s < srclen; s += 3, d += 4) {
        base64decode(&src[s], &dst[d], srclen - s);
    }

    printf("%s\n", dst);

    exit(EXIT_SUCCESS);
}
