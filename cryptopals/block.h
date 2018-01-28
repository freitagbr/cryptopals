/* Copyright (c) 2018 Brandon Freitag <freitagbr@gmail.com> */

#ifndef CRYPTOPALS_BLOCK_H_
#define CRYPTOPALS_BLOCK_H_

#include <stddef.h>

#include "cryptopals/string.h"
#include "cryptopals/error.h"

size_t block_keysize(string str, float *min_dist, size_t max_keysize);

error_t block_transpose_get_key(string *key, string str, size_t max_keysize);

#endif /* CRYPTOPALS_BLOCK_H_ */
