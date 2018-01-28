/* Copyright (c) 2018 Brandon Freitag <freitagbr@gmail.com> */

#ifndef CRYPTOPALS_BUFFER_H_
#define CRYPTOPALS_BUFFER_H_

#include <stddef.h>
#include <stdlib.h>

#include "cryptopals/error.h"

typedef struct string {
  unsigned char *ptr;
  size_t len;
} string;

#define string_init()                                                          \
  { NULL, 0 }

#define string_new(p, l)                                                       \
  { (unsigned char *)p, l }

#define string_set(s, p, l)                                                    \
  s.ptr = p;                                                                   \
  s.len = l

#define string_delete(str)                                                     \
  if (str.ptr != NULL) {                                                       \
    free((void *)str.ptr);                                                     \
  }

error_t string_alloc(string *str, size_t len);

error_t string_resize(string *str, size_t len);

error_t string_append(string *head, string tail);

error_t string_concat(string *dst, const string a, const string b);

error_t string_copy(string *dst, const string src);

int string_cmp(const string lhs, const string rhs);

#endif /* CRYPTOPALS_BUFFER_H_ */
