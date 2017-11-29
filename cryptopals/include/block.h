#ifndef BLOCK_H
#define BLOCK_H

#include "hamming.h"
#include "xor.h"

#include <float.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

int block_get_keysize(unsigned char *buf, size_t len, float *min_dist, size_t *keysize, size_t max_keysize);

int block_transpose_get_key(unsigned char *buf, size_t len, unsigned char **key, size_t *keysize, size_t max_keysize);

#endif
