/* Copyright (c) 2018 Brandon Freitag <freitagbr@gmail.com> */

#ifndef CRYPTOPALS_BLOCK_H_
#define CRYPTOPALS_BLOCK_H_

#include <stddef.h>

#include "cryptopals/buffer.h"
#include "cryptopals/error.h"

size_t block_keysize(buffer buf, float *min_dist, size_t max_keysize);

error_t block_transpose_get_key(buffer *key, buffer buf, size_t max_keysize);

#endif /* CRYPTOPALS_BLOCK_H_ */
