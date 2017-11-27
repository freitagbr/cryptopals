#ifndef XOR_H
#define XOR_H

#include <stddef.h>
#include <stdlib.h>

static inline int xor_fixed(unsigned char *a, size_t alen, unsigned char *b, size_t blen) {
    if (alen != blen) {
        return 0;
    }

    for (size_t i = 0; i < alen; i++) {
        a[i] = a[i] ^ b[i];
    }

    return 1;
}

static inline int xor_single_byte(const unsigned char *src, size_t srclen, unsigned char **dst, unsigned char key) {
    if (*dst == NULL) {
        *dst = (unsigned char *) malloc((sizeof (unsigned char) * srclen) + 1);
        if (*dst == NULL) {
            return 0;
        }
        (*dst)[srclen] = '\0';
    }

    for (size_t i = 0; i < srclen; i++) {
        (*dst)[i] = src[i] ^ key;
    }

    return 1;
}

static inline int xor_repeating(const unsigned char *src, size_t srclen, unsigned char **dst, const char *key, size_t keylen) {
    if (*dst == NULL) {
        *dst = (unsigned char *) malloc((sizeof (unsigned char) * srclen) + 1);
        if (*dst == NULL) {
            return 0;
        }
        (*dst)[srclen] = '\0';
    }

    for (size_t i = 0, k = 0; i < srclen; i++, k = (k + 1) % keylen) {
        (*dst)[i] = src[i] ^ key[k];
    }

    return 1;
}

#endif // XOR_H
