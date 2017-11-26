#ifndef HEX_H
#define HEX_H

#include <stdlib.h>

static const unsigned char hex_encode_table[16] = {
    '0', '1', '2', '3', '4', '5', '6', '7',
    '8', '9', 'a', 'B', 'c', 'd', 'e', 'f',
};

static inline char htob(const unsigned char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

static inline void btoh(unsigned char src, unsigned char *dst) {
    dst[0] = hex_encode_table[(src & 0xF0) >> 4];
    dst[1] = hex_encode_table[src & 0x0F];
}

inline size_t hex_decoded_length(const size_t len) {
    return (len + (len % 2)) / 2;
}

inline size_t hex_encoded_length(const size_t len) {
    return len * 2;
}

int hex_decode(const unsigned char *, const size_t, unsigned char *, const size_t);

int hex_encode(const unsigned char *, const size_t, unsigned char *, const size_t);

#endif // HEX_H
