#include "xor.h"

#include <stddef.h>
#include <stdlib.h>

int xor_fixed(unsigned char *a, size_t alen, unsigned char *b, size_t blen) {
    if (alen != blen) {
        return 0;
    }

    for (size_t i = 0; i < alen; i++) {
        a[i] = a[i] ^ b[i];
    }

    return 1;
}

int xor_single_byte(const unsigned char *src, size_t srclen, unsigned char **dst, unsigned char key) {
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

int xor_repeating(const unsigned char *src, size_t srclen, unsigned char **dst, const char *key, size_t keylen) {
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

unsigned char xor_find_cipher(const unsigned char *str, const size_t len, int *max) {
    int max_score = 0;
    unsigned char key = 0;

    for (int k = 0; k <= 0xFF; k++) {
        int s = 0;
        for (int i = 0; i < 13; i++) {
            unsigned char c = xor_english_cipher_chars[i];
            for (size_t l = 0; l < len; l++) {
                if ((str[l] ^ (unsigned char) k) == c) {
                    s++;
                }
            }
        }
        if (s > max_score) {
            max_score = s;
            key = (unsigned char) k;
        }
    }

    *max = max_score;

    return key;
}
