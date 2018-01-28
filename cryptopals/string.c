/* Copyright (c) 2018 Brandon Freitag <freitagbr@gmail.com> */

#include "cryptopals/string.h"

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

error_t string_alloc(string *str, size_t len) {
  size_t bytes;
  unsigned char *ptr;
  if (str->ptr != NULL) {
    /* resize if string is already allocated */
    return string_resize(str, len);
  }
  bytes = nextpow2(len);
  ptr = (unsigned char *)calloc(bytes, sizeof(unsigned char));
  if (ptr == NULL) {
    return EMALLOC;
  }
  str->ptr = ptr;
  str->len = len;
  return 0;
}

error_t string_resize(string *str, size_t len) {
  size_t bytes;
  unsigned char *ptr;
  if (str->ptr == NULL) {
    /* allocate if string is not yet allocated */
    return string_alloc(str, len);
  }
  if (str->len == len) {
    /* nothing to do */
    return 0;
  }
  bytes = nextpow2(len);
  if (bytes > nextpow2(str->len)) {
    /* only realloc if more space is needed than is available */
    ptr = (unsigned char *)realloc(str->ptr, sizeof(unsigned char) * bytes);
    if (ptr == NULL) {
      return EMALLOC;
    }
  } else {
    ptr = str->ptr;
  }
  ptr[len] = '\0';
  str->ptr = ptr;
  str->len = len;
  return 0;
}

error_t string_append(string *head, string tail) {
  const size_t headlen = head->len;
  const size_t len = headlen + tail.len;
  error_t err;

  err = string_resize(head, len);
  if (err) {
    return err;
  }

  memcpy(&(head->ptr[headlen]), tail.ptr, tail.len);

  return 0;
}

error_t string_concat(string *dst, const string a, const string b) {
  const size_t len = a.len + b.len;
  error_t err;

  err = string_alloc(dst, len);
  if (err) {
    return err;
  }

  memcpy(dst->ptr, a.ptr, a.len);
  memcpy(&(dst->ptr[a.len]), b.ptr, b.len);

  return 0;
}

error_t string_copy(string *dst, const string src) {
  error_t err;

  err = string_alloc(dst, src.len);
  if (err) {
    return err;
  }

  memcpy(dst->ptr, src.ptr, src.len);

  return 0;
}

int string_cmp(const string lhs, const string rhs) {
  if (lhs.len < rhs.len) {
    return -1;
  }
  if (rhs.len > lhs.len) {
    return 1;
  }
  return memcmp(lhs.ptr, rhs.ptr, lhs.len);
}
