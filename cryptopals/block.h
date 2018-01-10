/* Copyright (c) 2018 Brandon Freitag <freitagbr@gmail.com> */

#ifndef CRYPTOPALS_BLOCK_H_
#define CRYPTOPALS_BLOCK_H_

#include <float.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "cryptopals/buffer.h"
#include "cryptopals/error.h"
#include "cryptopals/hamming.h"
#include "cryptopals/xor.h"

error_t block_get_keysize(buffer buf, float *min_dist, size_t *keysize,
                          size_t max_keysize);

error_t block_transpose_get_key(buffer *key, buffer buf, size_t max_keysize);

#endif
