#ifndef HEX_H
#define HEX_H

#include <stdlib.h>

static inline char hex_parse(const unsigned char c) {
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

inline int hex_decoded_length(const int len) {
    return (len + (len % 2)) / 2;
}

inline int hex_encoded_length(const int len) {
    return len * 2;
}

int hex_decode(const unsigned char *, const size_t, unsigned char *, const size_t);

#endif // HEX_H
