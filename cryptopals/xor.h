/* Copyright (c) 2018 Brandon Freitag <freitagbr@gmail.com> */

#ifndef CRYPTOPALS_XOR_H_
#define CRYPTOPALS_XOR_H_

#include <stddef.h>

#include "cryptopals/buffer.h"
#include "cryptopals/error.h"

static const unsigned char xor_english_cipher_chars[13] = "etaoin shrdlu";

#define xor_inplace(a, b, l) \
  xor_bytes(a, a, b, l)

void xor_bytes(unsigned char *dst, const unsigned char *a, const unsigned char *b, const size_t len);

error_t xor_fixed(buffer a, const buffer b);

error_t xor_single_byte(buffer *dst, const buffer src, unsigned char key);

error_t xor_repeating(buffer *dst, const buffer src, const buffer key);

unsigned char xor_find_cipher(const buffer buf, int *max);

#endif /* CRYPTOPALS_XOR_H_ */
