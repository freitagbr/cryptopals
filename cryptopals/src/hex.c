#include "hex.h"

int hex_decode(const unsigned char *src, const size_t srclen, unsigned char *dst, const size_t dstlen) {
    char a;
    char b;
    for (size_t i = 0, j = 0; (i < srclen) && (j < dstlen); i += 2, j += 1) {
        a = htob(src[i]);
        b = htob(src[i + 1]);
        if ((a == -1) || (b == -1)) {
            return 0;
        }
        dst[j] = (unsigned char) ((a << 4) | b);
    }
    return 1;
}

int hex_encode(const unsigned char *src, const size_t srclen, unsigned char *dst, const size_t dstlen) {
    if (dstlen != hex_encoded_length(srclen)) {
        return 0;
    }
    for (size_t i = 0, j = 0; (i < srclen) && (j < dstlen); i += 1, j += 2) {
        btoh(src[i], &dst[j]);
    }
    return 1;
}
