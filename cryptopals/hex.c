/* Copyright (c) 2018 Brandon Freitag <freitagbr@gmail.com> */

#include "cryptopals/hex.h"

#include <stddef.h>

#include "cryptopals/buffer.h"
#include "cryptopals/error.h"

static char htob(const unsigned char c) { return hex_decode_table[c]; }

static void btoh(unsigned char src, unsigned char *dst) {
  dst[0] = hex_encode_table[(src & 0xF0) >> 4];
  dst[1] = hex_encode_table[src & 0x0F];
}

static size_t hex_decoded_length(const size_t len) {
  return (len + (len % 2)) / 2;
}

static size_t hex_encoded_length(const size_t len) { return len * 2; }

error_t hex_decode(buffer *dst, const buffer src) {
  unsigned char *dptr;
  const size_t srclen = src.len;
  size_t declen;
  size_t i;
  error_t err = 0;

  if ((srclen % 2) != 0) {
    return EHEXLEN;
  }

  declen = hex_decoded_length(srclen);

  /* reuse old memory if possible */
  if (dst->ptr != NULL) {
    if (dst->len < declen) {
      err = buffer_resize(dst, declen);
    }
  } else {
    err = buffer_alloc(dst, declen);
  }

  if (err) {
    return err;
  }

  dptr = dst->ptr;

  for (i = 0; i < srclen; i += 2) {
    char a = htob(src.ptr[i]);
    char b = htob(src.ptr[i + 1]);
    if ((a == -1) || (b == -1)) {
      return EHEXCHAR;
    }
    *dptr++ = (unsigned char)((a << 4) | b);
  }

  *dptr = '\0';

  return 0;
}

error_t hex_encode(buffer *dst, const buffer src) {
  unsigned char *dptr;
  const size_t srclen = src.len;
  size_t enclen = hex_encoded_length(srclen);
  size_t i;
  error_t err = 0;

  /* reuse old memory if possible */
  if (dst->ptr != NULL) {
    if (dst->len < enclen) {
      err = buffer_resize(dst, enclen);
    }
  } else {
    err = buffer_alloc(dst, enclen);
  }

  if (err) {
    return err;
  }

  dptr = dst->ptr;

  for (i = 0; i < srclen; i++) {
    btoh(src.ptr[i], dptr);
    dptr += 2;
  }

  *dptr = '\0';

  return 0;
}
