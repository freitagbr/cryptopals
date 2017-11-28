#ifndef XOR_H
#define XOR_H

#include <stddef.h>
#include <stdlib.h>

static const unsigned char xor_english_cipher_chars[13] = "etaoin shrdlu";

int xor_fixed(unsigned char *, size_t, unsigned char *, size_t);

int xor_single_byte(const unsigned char *, size_t, unsigned char **, unsigned char);

int xor_repeating(const unsigned char *, size_t, unsigned char **, const char *, size_t);

unsigned char xor_find_cipher(const unsigned char *, const size_t, int *);

#endif // XOR_H
