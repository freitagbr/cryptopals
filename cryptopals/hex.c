#include "cryptopals/hex.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include "cryptopals/error.h"

error_t hex_decode(uint8_t **dst, size_t *dstlen, const uint8_t *src, const size_t srclen) {
    uint8_t *d = NULL;

    if ((srclen % 2) != 0) {
        return EHEXLEN;
    }

    size_t declen = hex_decoded_length(srclen);

    // reuse old memory if possible
    if (*dst != NULL) {
        if (*dstlen < declen) {
            uint8_t *ndst = (uint8_t *) realloc(*dst, sizeof (uint8_t) * (declen + 1));
            if (ndst == NULL) {
                return EMALLOC;
            }
            *dst = ndst;
            *dstlen = declen;
        }
    }
    else {
        *dst = (uint8_t *) calloc(declen + 1, sizeof (uint8_t));
        *dstlen = declen;
    }

    d = *dst;
    if (d == NULL) {
        *dstlen = 0;
        return EMALLOC;
    }

    for (size_t i = 0; i < srclen; i += 2) {
        int8_t a = htob(src[i]);
        int8_t b = htob(src[i + 1]);
        if ((a == -1) || (b == -1)) {
            *dstlen = 0;
            return EHEXCHAR;
        }
        *d++ = (uint8_t) ((a << 4) | b);
    }

    *d = '\0';

    return 0;
}

error_t hex_encode(uint8_t **dst, size_t *dstlen, const uint8_t *src, const size_t srclen) {
    uint8_t *d = NULL;
    size_t enclen = hex_encoded_length(srclen);

    // reuse old memory if possible
    if (*dst != NULL) {
        if (*dstlen < enclen) {
            uint8_t *ndst = (uint8_t *) realloc(*dst, sizeof (uint8_t) * (enclen + 1));
            if (ndst == NULL) {
                return EMALLOC;
            }
            *dst = ndst;
            *dstlen = enclen;
        }
    }
    else {
        *dst = (uint8_t *) calloc(enclen + 1, sizeof (uint8_t));
        *dstlen = enclen;
    }

    d = *dst;
    if (d == NULL) {
        *dstlen = 0;
        return EMALLOC;
    }

    for (size_t i = 0; i < srclen; i++) {
        btoh(src[i], d);
        d += 2;
    }

    *d = '\0';

    return 0;
}
