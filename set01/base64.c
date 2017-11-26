#include "base64.h"

int base64_encode(const unsigned char *src, size_t srclen, unsigned char *dst, size_t dstlen) {
    int i = 0, j = 0;
    unsigned char *dst_begin = dst;
    unsigned char b[3];
    unsigned char a[4];

    size_t encoded_len = encoded_length(srclen);

    if (dstlen < encoded_len) {
        return 0;
    }

    while (srclen--) {
        b[i++] = *src++;
        if (i == 3) {
            btoa(a, b);

            *dst++ = encode_table[a[0]];
            *dst++ = encode_table[a[1]];
            *dst++ = encode_table[a[2]];
            *dst++ = encode_table[a[3]];

            i = 0;
        }
    }

    if (i) {
        for (j = i; j < 3; j++) {
            b[j] = '\0';
        }

        btoa(a, b);

        for (j = 0; j < i + 1; j++) {
            *dst++ = encode_table[a[j]];
        }

        while ((i++ < 3)) {
            *dst++ = '=';
        }
    }

    return (dst == (dst_begin + encoded_len));
}

int base64_decode(const unsigned char *src, size_t srclen, unsigned char *dst, size_t dstlen) {
    int i = 0, j = 0;
    unsigned char *dst_begin = dst;
    unsigned char b[3];
    unsigned char a[4];

    size_t decoded_len = decoded_length(src, srclen);

    if (dstlen < decoded_len) {
        return 0;
    }

    while (srclen--) {
        if (*src == '=') {
            break;
        }

        a[i++] = *(src++);
        if (i == 4) {
            a[0] = decode_table[a[0]];
            a[1] = decode_table[a[1]];
            a[2] = decode_table[a[2]];
            a[3] = decode_table[a[3]];

            atob(b, a);

            *dst++ = b[0];
            *dst++ = b[1];
            *dst++ = b[2];

            i = 0;
        }
    }

    if (i) {
        for (j = i; j < 4; j++) {
            a[j] = '\0';
        }

        a[0] = decode_table[a[0]];
        a[1] = decode_table[a[1]];
        a[2] = decode_table[a[2]];
        a[3] = decode_table[a[3]];

        atob(b, a);

        for (j = 0; j < i - 1; j++) {
            *dst++ = b[j];
        }
    }

    return (dst == (dst_begin + decoded_len));
}
