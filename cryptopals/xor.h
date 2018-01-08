#ifndef CRYPTOPALS_XOR_H_
#define CRYPTOPALS_XOR_H_

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include "cryptopals/error.h"

static const uint8_t xor_english_cipher_chars[13] = "etaoin shrdlu";

error_t xor_fixed(uint8_t *a, size_t alen, uint8_t *b, size_t blen);

error_t xor_single_byte(uint8_t **dst, const uint8_t *src, size_t srclen, uint8_t key);

error_t xor_repeating(uint8_t **dst, const uint8_t *src, size_t srclen, const uint8_t *key, size_t keylen);

uint8_t xor_find_cipher(const uint8_t *buf, const size_t len, int *max);

#endif // CRYPTOPALS_XOR_H_
