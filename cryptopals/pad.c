/* Copyright (c) 2018 Brandon Freitag <freitagbr@gmail.com> */

#include "cryptopals/pad.h"

#include <stddef.h>
#include <string.h>

#include "cryptopals/error.h"
#include "cryptopals/string.h"

error_t pad_bytes(string *dst, const string src, const size_t len,
                  const unsigned char iv) {
  error_t err;

  if (len < src.len) {
    return EDSTBUF;
  }

  err = string_alloc(dst, len);
  if (err) {
    return err;
  }

  memset(dst->ptr, (int)iv, dst->len);
  memcpy(dst->ptr, src.ptr, src.len);

  return 0;
}
