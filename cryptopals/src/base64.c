#include "base64.h"
#include "file.h"

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int base64_encode(const unsigned char *src, size_t srclen, unsigned char **dst, size_t *dstlen) {
    int i = 0;
    int j = 0;
    unsigned char b[3] = {0, 0, 0};
    unsigned char a[4] = {0, 0, 0, 0};
    unsigned char *dst_begin = NULL;
    unsigned char *d = NULL;

    *dstlen = base64_encoded_length(srclen);
    d = dst_begin = *dst = (unsigned char *) malloc((sizeof (unsigned char) * *dstlen) + 1);

    if (d == NULL) {
        *dstlen = 0;
        return 0;
    }

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
        for (j = i; j < 3; j++) {
            b[j] = '\0';
        }

        btoa(a, b);

        for (j = 0; j < i + 1; j++) {
            *d++ = base64_encode_table[a[j]];
        }

        while ((i++ < 3)) {
            *d++ = '=';
        }
    }

    *d = '\0';

    return (d == (dst_begin + *dstlen));
}

int base64_decode(const unsigned char *src, size_t srclen, unsigned char **dst, size_t *dstlen) {
    int i = 0;
    int j = 0;
    unsigned char b[3] = {0, 0, 0};
    unsigned char a[4] = {0, 0, 0, 0};
    unsigned char *dst_begin = NULL;
    unsigned char *d = NULL;

    *dstlen = base64_decoded_length(src, srclen);
    d = dst_begin = *dst = (unsigned char *) malloc((sizeof (unsigned char) * *dstlen) + 1);

    if (d == NULL) {
        *dstlen = 0;
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

            *d++ = b[0];
            *d++ = b[1];
            *d++ = b[2];

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
            *d++ = b[j];
        }
    }

    *d = '\0';

    return (d == (dst_begin + *dstlen));
}

int base64_decode_file(const char *file, unsigned char **dst, size_t *dstlen) {
    unsigned char *src = NULL;
    unsigned char *base64 = NULL;
    size_t read = 0;
    int status = 0;

    if (!file_read(file, &src, &read)) {
        goto end;
    }

    base64 = (unsigned char *) malloc(sizeof (unsigned char) * read);

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

    base64[b] = '\0';

    if (!base64_decode(base64, b, dst, dstlen)) {
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
