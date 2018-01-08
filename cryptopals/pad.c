#include "cryptopals/pad.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "cryptopals/error.h"

error_t pad_bytes(uint8_t **dst, const size_t dstlen, const uint8_t *src, const size_t srclen, const uint8_t iv) {
    if (dstlen < srclen) {
        return EDSTBUF;
    }

    *dst = (uint8_t *) calloc(dstlen + 1, sizeof (uint8_t));
    if (*dst == NULL) {
        return EMALLOC;
    }

    memset(*dst, iv, dstlen);
    memcpy(*dst, src, srclen);

    return 0;
}
