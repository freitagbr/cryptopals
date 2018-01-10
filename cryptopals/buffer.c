/* Copyright (c) 2018 Brandon Freitag <freitagbr@gmail.com> */

#include "cryptopals/buffer.h"

#include <stddef.h>
#include <stdlib.h>

#include "cryptopals/error.h"

error_t buffer_alloc(buffer *buf, size_t len) {
  unsigned char *ptr = (unsigned char *)calloc(len + 1, sizeof(unsigned char));
  if (ptr == NULL) {
    return EMALLOC;
  }
  buf->ptr = ptr;
  buf->len = len;
  return 0;
}

error_t buffer_resize(buffer *buf, size_t len) {
  unsigned char *ptr =
      (unsigned char *)realloc(buf->ptr, sizeof(unsigned char) * (len + 1));
  if (ptr == NULL) {
    return EMALLOC;
  }
  buf->ptr = ptr;
  buf->len = len;
  return 0;
}
