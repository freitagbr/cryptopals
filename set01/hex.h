#ifndef HEX_H
#define HEX_H

inline int hex_decoded_length(const int len) {
    return (len + (len % 2)) / 2;
}

inline int hex_encoded_length(const int len) {
    return len * 2;
}

inline char hex_parse(const unsigned char c) {
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

int hex_decode(const unsigned char *src, const size_t srclen, unsigned char *dst, const size_t dstlen) {
    char a;
    char b;
    for (size_t i = 0, j = 0; (i < srclen) && (j < dstlen); i += 2, j += 1) {
        a = hex_parse(src[i]);
        b = hex_parse(src[i + 1]);
        if ((a == -1) || (b == -1)) {
            return 0;
        }
        dst[j] = (unsigned char) ((a << 4) | b);
    }
    return 1;
}

#endif // HEX_H
