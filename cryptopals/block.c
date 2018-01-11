/* Copyright (c) 2018 Brandon Freitag <freitagbr@gmail.com> */

#include "cryptopals/block.h"

#include <float.h>
#include <stddef.h>

#include "cryptopals/buffer.h"
#include "cryptopals/error.h"
#include "cryptopals/hamming.h"
#include "cryptopals/xor.h"

size_t block_keysize(buffer buf, float *min_dist, size_t max_keysize) {
  size_t keysize = 0;
  size_t k;

  *min_dist = FLT_MAX;

  /* check keysizes between 2 and max_keysize */
  for (k = 2; k <= max_keysize; k++) {
    /**
     * break the data into blocks of size of the key,
     * but ignore the trailing block, which may be
     * smaller than the other blocks, preventing
     * out-of-bounds memory access
     */
    const size_t nblocks = (buf.len / k) - 1;
    float dist = 0;
    size_t b;

    /**
     * sum the hamming distances, normalized
     * by the keysize, between adjacent blocks
     */
    for (b = 0; b < nblocks; b++) {
      const unsigned char *aptr = &(buf.ptr[b * k]);
      const unsigned char *bptr = &(aptr[k]);
      float hd = (float)hamming_distance(aptr, bptr, k);
      dist += (float)(hd / (float)k);
    }

    /* average the hamming distances */
    dist /= (float)nblocks;

    if (dist < *min_dist) {
      *min_dist = dist;
      keysize = (size_t)k;
    }
  }

  return keysize;
}

error_t block_transpose_get_key(buffer *key, buffer buf, size_t max_keysize) {
  buffer block = buffer_init();
  unsigned char *kptr;
  float min_dist = 0;
  size_t keysize;
  size_t blocklen;
  size_t b;
  error_t err;

  keysize = block_keysize(buf, &min_dist, max_keysize);
  blocklen = buf.len / keysize;

  err = buffer_alloc(&block, blocklen) || buffer_alloc(key, keysize);
  if (err) {
    goto end;
  }

  kptr = key->ptr;

  /* transpose blocks */
  for (b = 0; b < keysize; b++) {
    int max_score = 0;
    size_t i, j;
    for (i = 0, j = b; (i < blocklen) && (j < buf.len); i++, j += keysize) {
      block.ptr[i] = buf.ptr[j];
    }
    *(kptr++) = xor_find_cipher(block, &max_score);
  }

end:
  buffer_delete(block);

  return err;
}
