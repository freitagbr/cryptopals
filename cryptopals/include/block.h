#ifndef BLOCK_H
#define BLOCK_H

#include "hamming.h"
#include "xor.h"

#include <float.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

int block_get_keysize(unsigned char *, size_t, size_t *, size_t);

int block_transpose_get_key(unsigned char *, size_t, unsigned char **, size_t *, size_t);

#endif
