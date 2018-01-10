/* Copyright (c) 2018 Brandon Freitag <freitagbr@gmail.com> */

#ifndef CRYPTOPALS_BUFFER_H_
#define CRYPTOPALS_BUFFER_H_

#include <stddef.h>
#include <stdlib.h>

#include "cryptopals/error.h"

typedef struct buffer {
  unsigned char *ptr;
  size_t len;
} buffer;

#define buffer_init()                                                          \
  { NULL, 0 }

#define buffer_new(p, l)                                                       \
  { (unsigned char *)p, l }

#define buffer_set(b, p, l)                                                    \
  b.ptr = p;                                                                   \
  b.len = l;

#define buffer_delete(buf)                                                     \
  if (buf.ptr != NULL) {                                                       \
    free((void *)buf.ptr);                                                     \
  }

error_t buffer_alloc(buffer *buf, size_t len);

error_t buffer_resize(buffer *buf, size_t len);

#endif
