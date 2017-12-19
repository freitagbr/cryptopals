#include "cryptopals/xor.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

int xor_fixed(uint8_t *a, size_t alen, uint8_t *b, size_t blen) {
    if (alen != blen) {
        return 0;
    }

    for (size_t i = 0; i < alen; i++) {
        a[i] = a[i] ^ b[i];
    }

    return 1;
}

int xor_single_byte(uint8_t **dst, const uint8_t *src, size_t srclen, uint8_t key) {
    uint8_t *d = *dst;

    if (d == NULL) {
        d = *dst = (uint8_t *) calloc(srclen + 1, sizeof (uint8_t));
        if (d == NULL) {
            return 0;
        }
    }

    for (size_t i = 0; i < srclen; i++) {
        *d++ = src[i] ^ key;
    }

    return 1;
}

int xor_repeating(uint8_t **dst, const uint8_t *src, size_t srclen, const uint8_t *key, size_t keylen) {
    uint8_t *d = *dst;

    if (d == NULL) {
        d = *dst = (uint8_t *) calloc(srclen + 1, sizeof (uint8_t));
        if (d == NULL) {
            return 0;
        }
    }

    for (size_t i = 0, k = 0; i < srclen; i++, k = (k + 1) % keylen) {
        *d++ = src[i] ^ key[k];
    }

    return 1;
}

uint8_t xor_find_cipher(const uint8_t *buf, const size_t len, int *max) {
    int max_score = 0;
    uint8_t key = 0;

    for (int k = 0; k <= 0xFF; k++) {
        int s = 0;
        for (int i = 0; i < 13; i++) {
            uint8_t c = xor_english_cipher_chars[i];
            for (size_t l = 0; l < len; l++) {
                if ((buf[l] ^ (uint8_t) k) == c) {
                    s++;
                }
            }
        }
        if (s > max_score) {
            max_score = s;
            key = (uint8_t) k;
        }
    }

    *max = max_score;

    return key;
}
