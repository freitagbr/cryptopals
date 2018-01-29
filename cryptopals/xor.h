/* Copyright (c) 2018 Brandon Freitag <freitagbr@gmail.com> */

#ifndef CRYPTOPALS_XOR_H_
#define CRYPTOPALS_XOR_H_

#include <stddef.h>

#include "cryptopals/error.h"
#include "cryptopals/string.h"

static const unsigned char xor_english_cipher_chars[13] = "etaoin shrdlu";

#define xor_inplace(a, b, l) xor_bytes(a, a, b, l)

void xor_bytes(unsigned char *dst, const unsigned char *a,
               const unsigned char *b, const size_t len);

error_t xor_fixed(string a, const string b);

error_t xor_single_byte(string *dst, const string src, unsigned char key);

error_t xor_repeating(string *dst, const string src, const string key);

unsigned char xor_find_cipher(const string str, int *max);

#endif /* CRYPTOPALS_XOR_H_ */
