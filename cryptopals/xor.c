#include "cryptopals/xor.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include "cryptopals/buffer.h"
#include "cryptopals/error.h"

error_t xor_fixed(buffer a, const buffer b) {
    if (a.len != b.len) {
        return ESIZE;
    }

    for (size_t i = 0; i < a.len; i++) {
        a.ptr[i] = a.ptr[i] ^ b.ptr[i];
    }

    return 0;
}

error_t xor_single_byte(buffer *dst, const buffer src, uint8_t key) {
    if (dst->ptr == NULL) {
        error_t err = buffer_alloc(dst, src.len);
        if (err) {
            return err;
        }
    }

    uint8_t *dptr = dst->ptr;

    for (size_t i = 0; i < src.len; i++) {
        *dptr++ = src.ptr[i] ^ key;
    }

    return 0;
}

error_t xor_repeating(buffer *dst, const buffer src, const buffer key) {
    if (dst->ptr == NULL) {
        error_t err = buffer_alloc(dst, src.len);
        if (err) {
            return err;
        }
    }

    uint8_t *dptr = dst->ptr;

    for (size_t i = 0, k = 0; i < src.len; i++, k = (k + 1) % key.len) {
        *dptr++ = src.ptr[i] ^ key.ptr[k];
    }

    return 0;
}

uint8_t xor_find_cipher(const buffer buf, int *max) {
    int max_score = 0;
    uint8_t key = 0;

    for (int k = 0; k <= 0xFF; k++) {
        int s = 0;
        for (int i = 0; i < 13; i++) {
            uint8_t c = xor_english_cipher_chars[i];
            for (size_t l = 0; l < buf.len; l++) {
                if ((buf.ptr[l] ^ (uint8_t) k) == c) {
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
