#include "base64.h"
#include "file.h"

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int base64_encode(const unsigned char *src, size_t srclen, unsigned char *dst, size_t dstlen) {
    int i = 0, j = 0;
    unsigned char *dst_begin = dst;
    unsigned char b[3] = {0, 0, 0};
    unsigned char a[4] = {0, 0, 0, 0};

    size_t encoded_len = base64_encoded_length(srclen);

    if (dstlen < encoded_len) {
        return 0;
    }

    while (srclen--) {
        b[i++] = *src++;
        if (i == 3) {
            btoa(a, b);

            *dst++ = base64_encode_table[a[0]];
            *dst++ = base64_encode_table[a[1]];
            *dst++ = base64_encode_table[a[2]];
            *dst++ = base64_encode_table[a[3]];

            i = 0;
        }
    }

    if (i) {
        for (j = i; j < 3; j++) {
            b[j] = '\0';
        }

        btoa(a, b);

        for (j = 0; j < i + 1; j++) {
            *dst++ = base64_encode_table[a[j]];
        }

        while ((i++ < 3)) {
            *dst++ = '=';
        }
    }

    *dst = '\0';

    return (dst == (dst_begin + encoded_len));
}

int base64_decode(const unsigned char *src, size_t srclen, unsigned char *dst, size_t dstlen) {
    int i = 0, j = 0;
    unsigned char *dst_begin = dst;
    unsigned char b[3] = {0, 0, 0};
    unsigned char a[4] = {0, 0, 0, 0};

    size_t decoded_len = base64_decoded_length(src, srclen);

    if (dstlen < decoded_len) {
        return 0;
    }

    while (srclen--) {
        if (*src == '=') {
            break;
        }

        a[i++] = *(src++);
        if (i == 4) {
            a[0] = base64_decode_table[a[0]];
            a[1] = base64_decode_table[a[1]];
            a[2] = base64_decode_table[a[2]];
            a[3] = base64_decode_table[a[3]];

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

        a[0] = base64_decode_table[a[0]];
        a[1] = base64_decode_table[a[1]];
        a[2] = base64_decode_table[a[2]];
        a[3] = base64_decode_table[a[3]];

        atob(b, a);

        for (j = 0; j < i - 1; j++) {
            *dst++ = b[j];
        }
    }

    return (dst == (dst_begin + decoded_len));
}

int base64_decode_file(const char *file, unsigned char **dst, size_t *dstlen) {
    unsigned char *src = NULL;
    size_t read = 0;

    if (!file_read(file, &src, &read)) {
        return 0;
    }

    unsigned char *base64 = (unsigned char *) malloc(sizeof (unsigned char) * read);

    if (base64 == NULL) {
        free((void *) src);
        return 0;
    }

    size_t i = 0;
    size_t j = 0;
    size_t b = 0;

    while (i < read) {
        while ((base64_decode_table[src[i]] != -1) || (src[i] == '=')) {
            i++;
        }
        size_t t = i - j;
        memcpy(&base64[b], &src[j], t);
        b += t;
        j = ++i;
    }

    base64[b] = '\0';

    free((void *) src);

    const size_t len = base64_decoded_length(base64, b);
    *dst = (unsigned char *) malloc(sizeof (unsigned char) * len);

    if (*dst == NULL) {
        free((void *) base64);
        return 0;
    }

    int r = base64_decode(base64, b, *dst, len);

    free((void *) base64);

    if (!r) {
        free((void *) *dst);
        *dst = NULL;
        return 0;
    }

    *dstlen = len;

    return 1;
}
