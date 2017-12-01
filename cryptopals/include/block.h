#ifndef BLOCK_H
#define BLOCK_H

#include "hamming.h"
#include "xor.h"

#include <float.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int block_get_keysize(uint8_t *buf, size_t len, float *min_dist, size_t *keysize, size_t max_keysize);

int block_transpose_get_key(uint8_t *buf, size_t len, uint8_t **key, size_t *keysize, size_t max_keysize);

#endif
