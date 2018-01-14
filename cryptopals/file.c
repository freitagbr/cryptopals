/* Copyright (c) 2018 Brandon Freitag <freitagbr@gmail.com> */

#include "cryptopals/file.h"

#include <stddef.h>
#include <stdio.h>

#include "cryptopals/buffer.h"
#include "cryptopals/error.h"

error_t file_read(const char *file, buffer *buf) {
  FILE *fp = fopen(file, "rb");
  error_t err = 0;

  if (fp == NULL) {
    err = EFOPEN;
    goto end;
  }

  if (fseek(fp, 0, SEEK_END) == 0) {
    long buflen = ftell(fp);
    if (buflen == -1) {
      err = EFTELL;
      goto end;
    }

    err = buffer_alloc(buf, buflen);
    if (err) {
      goto end;
    }

    if (fseek(fp, 0, SEEK_SET) != 0) {
      err = EFSEEK;
      goto end;
    }

    buf->len = fread(buf->ptr, sizeof(unsigned char), buf->len, fp);

    if (ferror(fp) != 0) {
      err = EFREAD;
      goto end;
    }
  }

end:
  if (fp != NULL) {
    fclose(fp);
  }

  return err;
}

/* based on the getdelim implementation from NetBSD */
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
error_t file_getline(FILE *fp, buffer *buf, long *read) {
  unsigned char *ptr;
  unsigned char *endptr;
  int c;

  if ((fp == NULL) || (buf == NULL) || (read == NULL)) {
    return ENULLPTR;
  }

  if (buf->ptr == NULL || buf->len == 0) {
    error_t err = buffer_alloc(buf, FILE_BUFLEN);
    if (err) {
      *read = -1L;
      return err;
    }
  }

  ptr = buf->ptr;
  endptr = &(buf->ptr[buf->len]);

  while ((c = fgetc(fp)) != EOF) {
    *(ptr++) = (unsigned char)c;

    if (c == '\n') {
      *ptr = '\0';
      *read = (long)(ptr - buf->ptr);
      return 0;
    }

    if (ptr + 2 >= endptr) {
      size_t diff = ptr - buf->ptr;
      error_t err;

      err = buffer_resize(buf, buf->len * 2);
      if (err) {
        *read = (long)(diff);
        return err;
      }

      endptr = &(buf->ptr[buf->len]);
      ptr = &(buf->ptr[diff]);
    }
  }

  if (feof(fp)) {
    *ptr = '\0';
    *read = (long)(ptr - buf->ptr);
    return 0;
  }

  *read = -1L;

  return EFREAD;
}
