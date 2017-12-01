#include "hex.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

int hex_decode(uint8_t **dst, size_t *dstlen, const uint8_t *src, const size_t srclen) {
    uint8_t *d = NULL;
    size_t declen = hex_decoded_length(srclen);

    // reuse old memory if possible
    if (*dst != NULL) {
        if (*dstlen < declen) {
            *dstlen = declen;
            *dst = (uint8_t *) realloc(*dst, sizeof (uint8_t) * (declen + 1));
        }
    }
    else {
        *dstlen = declen;
        *dst = (uint8_t *) calloc(declen + 1, sizeof (uint8_t));
    }

    d = *dst;
    if (d == NULL) {
        *dstlen = 0;
        return 0;
    }

    for (size_t i = 0; i < srclen; i += 2) {
        int8_t a = htob(src[i]);
        int8_t b = htob(src[i + 1]);
        if ((a == -1) || (b == -1)) {
            *dstlen = 0;
            return 0;
        }
        *d++ = (uint8_t) ((a << 4) | b);
    }

    *d = '\0';

    return 1;
}

int hex_encode(uint8_t **dst, size_t *dstlen, const uint8_t *src, const size_t srclen) {
    uint8_t *d = NULL;
    size_t enclen = hex_encoded_length(srclen);

    // reuse old memory if possible
    if (*dst != NULL) {
        if (*dstlen < enclen) {
            *dstlen = enclen;
            *dst = (uint8_t *) realloc(*dst, sizeof (uint8_t) * (enclen + 1));
        }
    }
    else {
        *dstlen = enclen;
        *dst = (uint8_t *) calloc(enclen + 1, sizeof (uint8_t));
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
