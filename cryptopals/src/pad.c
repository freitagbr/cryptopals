#include "pad.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

int pad_bytes(unsigned char **dst, const size_t dstlen, const unsigned char *src, const size_t srclen, const unsigned char iv) {
    if (dstlen < srclen) {
        return 0;
    }

    *dst = (unsigned char *) malloc((sizeof (unsigned char) * dstlen) + 1);
    if (*dst == NULL) {
        return 0;
    }

    memset(*dst, iv, dstlen);
    memcpy(*dst, src, srclen);
    (*dst)[dstlen] = '\0';

    return 1;
}
