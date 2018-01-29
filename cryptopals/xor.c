/* Copyright (c) 2018 Brandon Freitag <freitagbr@gmail.com> */

#include "cryptopals/xor.h"

#include <stddef.h>

#include "cryptopals/error.h"
#include "cryptopals/string.h"

void xor_bytes(unsigned char *dst, const unsigned char *a,
               const unsigned char *b, const size_t len) {
  size_t i;

  for (i = 0; i < len; i++) {
    dst[i] = a[i] ^ b[i];
  }
}

error_t xor_fixed(string a, const string b) {
  if (a.len != b.len) {
    return ESIZE;
  }

  xor_bytes(a.ptr, a.ptr, b.ptr, a.len);

  return 0;
}

error_t xor_single_byte(string *dst, const string src, unsigned char key) {
  unsigned char *dptr;
  size_t i;

  if (dst->ptr == NULL) {
    error_t err = string_alloc(dst, src.len);
    if (err) {
      return err;
    }
  }

  dptr = dst->ptr;

  for (i = 0; i < src.len; i++) {
    *(dptr++) = src.ptr[i] ^ key;
  }

  return 0;
}

error_t xor_repeating(string *dst, const string src, const string key) {
  unsigned char *dptr;
  size_t i, k;

  if (dst->ptr == NULL) {
    error_t err = string_alloc(dst, src.len);
    if (err) {
      return err;
    }
  }

  dptr = dst->ptr;

  for (i = 0, k = 0; i < src.len; i++, k = (k + 1) % key.len) {
    *(dptr++) = src.ptr[i] ^ key.ptr[k];
  }

  return 0;
}

unsigned char xor_find_cipher(const string str, int *max) {
  int max_score = 0;
  unsigned char key = 0;
  int k;

  for (k = 0; k <= 0xFF; k++) {
    int s = 0;
    int i;
    for (i = 0; i < 13; i++) {
      unsigned char c = xor_english_cipher_chars[i];
      size_t l;
      for (l = 0; l < str.len; l++) {
        if ((str.ptr[l] ^ (unsigned char)k) == c) {
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
