#include "base64.h"
#include "file.h"

#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int base64_encode(uint8_t **dst, size_t *dstlen, const uint8_t *src, size_t srclen) {
    *dstlen = base64_encoded_length(srclen);

    uint8_t *dst_begin = *dst = (uint8_t *) calloc(*dstlen + 1, sizeof (uint8_t));
    uint8_t *d = dst_begin;
    if (d == NULL) {
        *dstlen = 0;
        return 0;
    }

    uint8_t b[3] = {0, 0, 0};
    uint8_t a[4] = {0, 0, 0, 0};
    int i = 0;

    while (srclen--) {
        b[i++] = *src++;
        if (i == 3) {
            btoa(a, b);

            *d++ = base64_encode_table[a[0]];
            *d++ = base64_encode_table[a[1]];
            *d++ = base64_encode_table[a[2]];
            *d++ = base64_encode_table[a[3]];

            i = 0;
        }
    }

    if (i) {
        for (int j = i; j < 3; j++) {
            b[j] = '\0';
        }

        btoa(a, b);

        for (int j = 0; j < i + 1; j++) {
            *d++ = base64_encode_table[a[j]];
        }

        while ((i++ < 3)) {
            *d++ = '=';
        }
    }

    return (d == (dst_begin + *dstlen));
}

int base64_decode(uint8_t **dst, size_t *dstlen, const uint8_t *src, size_t srclen) {
    *dstlen = base64_decoded_length(src, srclen);

    uint8_t *dst_begin = *dst = (uint8_t *) calloc(*dstlen + 1, sizeof (uint8_t));
    uint8_t *d = dst_begin;
    if (d == NULL) {
        *dstlen = 0;
        return 0;
    }

    uint8_t b[3] = {0, 0, 0};
    uint8_t a[4] = {0, 0, 0, 0};
    int i = 0;

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

            *d++ = b[0];
            *d++ = b[1];
            *d++ = b[2];

            i = 0;
        }
    }

    if (i) {
        for (int j = i; j < 4; j++) {
            a[j] = '\0';
        }

        a[0] = base64_decode_table[a[0]];
        a[1] = base64_decode_table[a[1]];
        a[2] = base64_decode_table[a[2]];
        a[3] = base64_decode_table[a[3]];

        atob(b, a);

        for (int j = 0; j < i - 1; j++) {
            *d++ = b[j];
        }
    }

    return (d == (dst_begin + *dstlen));
}

int base64_decode_file(const char *file, uint8_t **dst, size_t *dstlen) {
    uint8_t *src = NULL;
    uint8_t *base64 = NULL;
    size_t read = 0;
    int status = 0;

    if (!file_read(file, &src, &read)) {
        goto end;
    }

    base64 = (uint8_t *) calloc(read + 1, sizeof (uint8_t));
    if (base64 == NULL) {
        goto end;
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

    if (!base64_decode(dst, dstlen, base64, b)) {
        goto end;
    }

    status = 1;

end:
    if (src != NULL) {
        free((void *) src);
    }
    if (base64 != NULL) {
        free((void *) base64);
    }

    return status;
}
