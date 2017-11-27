#include "hex.h"

#include <stdlib.h>

int hex_decode(const unsigned char *src, const size_t srclen, unsigned char **dst, size_t *dstlen) {
    *dstlen = hex_decoded_length(srclen);
    unsigned char *d = *dst = (unsigned char *) malloc((sizeof (unsigned char) * *dstlen) + 1);

    for (size_t i = 0; i < srclen; i += 2) {
        char a = htob(src[i]);
        char b = htob(src[i + 1]);
        if ((a == -1) || (b == -1)) {
            return 0;
        }
        *d++ = (unsigned char) ((a << 4) | b);
    }

    *d = '\0';

    return 1;
}

int hex_encode(const unsigned char *src, const size_t srclen, unsigned char **dst, size_t *dstlen) {
    *dstlen = hex_encoded_length(srclen);
    unsigned char *d = *dst = (unsigned char *) malloc((sizeof (unsigned char) * *dstlen) + 1);

    for (size_t i = 0; i < srclen; i++) {
        btoh(src[i], d);
        d += 2;
    }

    *d = '\0';

    return 1;
}
