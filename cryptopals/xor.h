#ifndef CRYPTOPALS_XOR_H_
#define CRYPTOPALS_XOR_H_

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include "cryptopals/buffer.h"
#include "cryptopals/error.h"

static const uint8_t xor_english_cipher_chars[13] = "etaoin shrdlu";

error_t xor_fixed(buffer a, const buffer b);

error_t xor_single_byte(buffer *dst, const buffer src, uint8_t key);

error_t xor_repeating(buffer *dst, const buffer src, const buffer key);

uint8_t xor_find_cipher(const buffer buf, int *max);

#endif // CRYPTOPALS_XOR_H_
