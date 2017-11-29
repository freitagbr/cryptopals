#include "hex.h"

#include <stddef.h>
#include <stdlib.h>

int hex_decode(const unsigned char *src, const size_t srclen, unsigned char **dst, size_t *dstlen) {
    unsigned char *d = NULL;
    size_t declen = hex_decoded_length(srclen);

    // reuse old memory if possible
    if (*dst != NULL) {
        if (*dstlen < declen) {
            *dstlen = declen;
            *dst = (unsigned char *) realloc(*dst, (sizeof (unsigned char) * declen) + 1);
        }
    }
    else {
        *dstlen = declen;
        *dst = (unsigned char *) malloc((sizeof (unsigned char) * declen) + 1);
    }

    d = *dst;
    if (d == NULL) {
        *dstlen = 0;
        return 0;
    }

    for (size_t i = 0; i < srclen; i += 2) {
        char a = htob(src[i]);
        char b = htob(src[i + 1]);
        if ((a == -1) || (b == -1)) {
            *dstlen = 0;
            return 0;
        }
        *d++ = (unsigned char) ((a << 4) | b);
    }

    *d = '\0';

    return 1;
}

int hex_encode(const unsigned char *src, const size_t srclen, unsigned char **dst, size_t *dstlen) {
    unsigned char *d = NULL;
    size_t enclen = hex_encoded_length(srclen);

    // reuse old memory if possible
    if (*dst != NULL) {
        if (*dstlen < enclen) {
            *dstlen = enclen;
            *dst = (unsigned char *) realloc(*dst, (sizeof (unsigned char) * enclen) + 1);
        }
    }
    else {
        *dstlen = enclen;
        *dst = (unsigned char *) malloc((sizeof (unsigned char) * enclen) + 1);
    }

    d = *dst;
    if (d == NULL) {
        *dstlen = 0;
        return 0;
    }

    for (size_t i = 0; i < srclen; i++) {
        btoh(src[i], d);
        d += 2;
    }

    *d = '\0';

    return 1;
}
