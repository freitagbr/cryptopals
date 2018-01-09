#ifndef CRYPTOPALS_BASE64_H_
#define CRYPTOPALS_BASE64_H_

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cryptopals/buffer.h"
#include "cryptopals/error.h"
#include "cryptopals/file.h"

static const uint8_t base64_encode_table[64] = {
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
    'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
    'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
    'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
    'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
    'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
    'w', 'x', 'y', 'z', '0', '1', '2', '3',
    '4', '5', '6', '7', '8', '9', '+', '/',
};

static const char base64_decode_table[256] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63,
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1,
    -1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1,
    -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
};

static inline void btoa(uint8_t *a, uint8_t *b) {
    a[0] =  (b[0] & 0xfc) >> 2;
    a[1] = ((b[0] & 0x03) << 4) + ((b[1] & 0xf0) >> 4);
    a[2] = ((b[1] & 0x0f) << 2) + ((b[2] & 0xc0) >> 6);
    a[3] =  (b[2] & 0x3f);
}

static inline void atob(uint8_t *b, uint8_t *a) {
    b[0] =  (a[0]        << 2) + ((a[1] & 0x30) >> 4);
    b[1] = ((a[1] & 0xf) << 4) + ((a[2] & 0x3c) >> 2);
    b[2] = ((a[2] & 0x3) << 6) +   a[3];
}

inline int base64_decoded_length(const buffer buf) {
    int eqs = 0;
    const uint8_t *end = &(buf.ptr[buf.len]);
    while (*--end == '=') {
        ++eqs;
    }
    return ((buf.len * 3) / 4) - eqs;
}

inline int base64_encoded_length(size_t len) {
    return (len + 2 - ((len + 2) % 3)) / 3 * 4;
}

error_t base64_encode(buffer *dst, const buffer src);

error_t base64_decode(buffer *dst, const buffer src);

error_t base64_decode_file(const char *file, buffer *dst);

#endif // CRYPTOPALS_BASE64_H_
