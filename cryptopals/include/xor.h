#ifndef XOR_H
#define XOR_H

#include <stddef.h>
#include <stdlib.h>

static const unsigned char xor_english_cipher_chars[13] = "etaoin shrdlu";

int xor_fixed(unsigned char *a, size_t alen, unsigned char *b, size_t blen);

int xor_single_byte(unsigned char **dst, const unsigned char *src, size_t srclen, unsigned char key);

int xor_repeating(unsigned char **dst, const unsigned char *src, size_t srclen, const char *key, size_t keylen);

unsigned char xor_find_cipher(const unsigned char *buf, const size_t len, int *max);

#endif // XOR_H
