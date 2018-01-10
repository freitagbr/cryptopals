/* Copyright (c) 2018 Brandon Freitag <freitagbr@gmail.com> */

#include "cryptopals/xor.h"

#include <stddef.h>

#include "cryptopals/buffer.h"
#include "cryptopals/error.h"

error_t xor_fixed(buffer a, const buffer b) {
  size_t i;

  if (a.len != b.len) {
    return ESIZE;
  }

  for (i = 0; i < a.len; i++) {
    a.ptr[i] = a.ptr[i] ^ b.ptr[i];
  }

  return 0;
}

error_t xor_single_byte(buffer *dst, const buffer src, unsigned char key) {
  unsigned char *dptr;
  size_t i;

  if (dst->ptr == NULL) {
    error_t err = buffer_alloc(dst, src.len);
    if (err) {
      return err;
    }
  }

  dptr = dst->ptr;

  for (i = 0; i < src.len; i++) {
    *dptr++ = src.ptr[i] ^ key;
  }

  return 0;
}

error_t xor_repeating(buffer *dst, const buffer src, const buffer key) {
  unsigned char *dptr;
  size_t i, k;

  if (dst->ptr == NULL) {
    error_t err = buffer_alloc(dst, src.len);
    if (err) {
      return err;
    }
  }

  dptr = dst->ptr;

  for (i = 0, k = 0; i < src.len; i++, k = (k + 1) % key.len) {
    *dptr++ = src.ptr[i] ^ key.ptr[k];
  }

  return 0;
}

unsigned char xor_find_cipher(const buffer buf, int *max) {
  int max_score = 0;
  unsigned char key = 0;
  int k;

  for (k = 0; k <= 0xFF; k++) {
    int s = 0;
    int i;
    for (i = 0; i < 13; i++) {
      unsigned char c = xor_english_cipher_chars[i];
      size_t l;
      for (l = 0; l < buf.len; l++) {
        if ((buf.ptr[l] ^ (unsigned char)k) == c) {
          s++;
        }
      }
    }
    if (s > max_score) {
      max_score = s;
      key = (unsigned char)k;
    }
  }

  *max = max_score;

  return key;
}
