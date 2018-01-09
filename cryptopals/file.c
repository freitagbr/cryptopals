#include "cryptopals/file.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "cryptopals/error.h"

error_t file_read(const char *file, uint8_t **buf, size_t *read) {
    FILE *fp = fopen(file, "rb");
    error_t err = 0;

    if (fp == NULL) {
        err = EFOPEN;
        goto end;
    }

    *read = 0;

    if (fseek(fp, 0, SEEK_END) == 0) {
        long buflen = ftell(fp);
        if (buflen == -1) {
            err = EFTELL;
            goto end;
        }

        *buf = (uint8_t *) calloc(buflen + 1, sizeof (uint8_t));
        if (*buf == NULL) {
            err = EMALLOC;
            goto end;
        }

        if (fseek(fp, 0, SEEK_SET) != 0) {
            err = EFSEEK;
            free((void *) *buf);
            goto end;
        }

        *read = fread(*buf, sizeof (uint8_t), buflen, fp);

        if (ferror(fp) != 0) {
            err = EFREAD;
            free((void *) *buf);
            *read = 0;
            goto end;
        }
    }

end:
    if (fp != NULL) {
        fclose(fp);
    }

    return err;
}

// based on the getdelim implementation from NetBSD
/*-
 * Copyright (c) 2011 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Christos Zoulas.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
error_t file_getline(FILE *fp, uint8_t **buf, size_t *buflen, long *read) {
    if ((fp == NULL) ||
            (buf == NULL) ||
            (buflen == NULL) ||
            (read == NULL)) {
        return ENULLPTR;
    }

    uint8_t *ptr = NULL;
    uint8_t *endptr = NULL;

    if (*buf == NULL || *buflen == 0) {
        *buf = (uint8_t *) calloc(FILE_BUFLEN, sizeof (uint8_t));
        if (*buf == NULL) {
            *read = -1;
            return EMALLOC;
        }
        *buflen = FILE_BUFLEN;
    }

    ptr = *buf;
    endptr = *buf + *buflen;

    for (;;) {
        int c = fgetc(fp);
        if (c == EOF) {
            if (feof(fp)) {
                *ptr = '\0';
                *read = (long) (ptr - *buf);
                return 0;
            }
            *read = -1L;
            return EFREAD;
        }

        *ptr++ = (uint8_t) c;

        if (c == '\n') {
            *ptr = '\0';
            *read = (long) (ptr - *buf);
            return 0;
        }

        if (ptr + 2 >= endptr) {
            size_t nbuflen = *buflen * 2;
            ptrdiff_t diff = (ptrdiff_t) (ptr - *buf);
            uint8_t *nbuf = (uint8_t *) realloc(*buf, sizeof (uint8_t) * (nbuflen + 1));
            if (nbuf == NULL) {
                *read = (long) diff;
                return EMALLOC;
            }
            *buf = nbuf;
            *buflen = nbuflen;
            endptr = nbuf + nbuflen;
            ptr = nbuf + diff;
        }
    }
}
