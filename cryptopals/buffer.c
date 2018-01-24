/* Copyright (c) 2018 Brandon Freitag <freitagbr@gmail.com> */

#include "cryptopals/buffer.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "cryptopals/error.h"

static size_t nextpow2(size_t n) {
  size_t s = 1;
  while (s < sizeof(size_t) * 4) {
    n |= n >> s;
    s <<= 1;
  }
  return ++n;
}

error_t buffer_alloc(buffer *buf, size_t len) {
  size_t bytes;
  unsigned char *ptr;
  if (buf->ptr != NULL) {
    /* resize if buffer is already allocated */
    return buffer_resize(buf, len);
  }
  bytes = nextpow2(len);
  ptr = (unsigned char *)calloc(bytes, sizeof(unsigned char));
  if (ptr == NULL) {
    return EMALLOC;
  }
  buf->ptr = ptr;
  buf->len = len;
  return 0;
}

error_t buffer_resize(buffer *buf, size_t len) {
  size_t bytes;
  unsigned char *ptr;
  if (buf->ptr == NULL) {
    /* allocate if buffer is not yet allocated */
    return buffer_alloc(buf, len);
  }
  if (buf->len == len) {
    /* nothing to do */
    return 0;
  }
  bytes = nextpow2(len);
  if (bytes > nextpow2(buf->len)) {
    /* only realloc if more space is needed than is available */
    ptr = (unsigned char *)realloc(buf->ptr, sizeof(unsigned char) * bytes);
    if (ptr == NULL) {
      return EMALLOC;
    }
  } else {
    ptr = buf->ptr;
  }
  ptr[len] = '\0';
  buf->ptr = ptr;
  buf->len = len;
  return 0;
}

error_t buffer_append(buffer *head, buffer tail) {
  const size_t len = head->len + tail.len;
  error_t err;

  err = buffer_resize(head, len);
  if (err) {
    return err;
  }

  memcpy(&(head->ptr[head->len]), tail.ptr, tail.len);

  return 0;
}

error_t buffer_concat(buffer *dst, const buffer a, const buffer b) {
  const size_t len = a.len + b.len;
  error_t err;

  err = buffer_alloc(dst, len);
  if (err) {
    return err;
  }

  memcpy(dst->ptr, a.ptr, a.len);
  memcpy(&(dst->ptr[a.len]), b.ptr, b.len);

  return 0;
}

error_t buffer_dup(buffer *dst, const buffer src) {
  error_t err;

  err = buffer_alloc(dst, src.len);
  if (err) {
    return err;
  }

  memcpy(dst->ptr, src.ptr, src.len);

  return 0;
}

int buffer_cmp(const buffer lhs, const buffer rhs) {
  if (lhs.len < rhs.len) {
    return -1;
  }
  if (rhs.len > lhs.len) {
    return 1;
  }
  return memcmp(lhs.ptr, rhs.ptr, lhs.len);
}
