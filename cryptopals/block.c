/* Copyright (c) 2018 Brandon Freitag <freitagbr@gmail.com> */

#include "cryptopals/block.h"

#include <float.h>
#include <stddef.h>

#include "cryptopals/error.h"
#include "cryptopals/hamming.h"
#include "cryptopals/string.h"
#include "cryptopals/xor.h"

size_t block_keysize(string str, float *min_dist, size_t max_keysize) {
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
    const size_t nblocks = (str.len / k) - 1;
    float dist = 0;
    size_t b;

    /**
     * sum the hamming distances, normalized
     * by the keysize, between adjacent blocks
     */
    for (b = 0; b < nblocks; b++) {
      const unsigned char *aptr = &(str.ptr[b * k]);
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

error_t block_transpose_get_key(string *key, string str, size_t max_keysize) {
  string block = string_init();
  unsigned char *kptr;
  float min_dist = 0;
  size_t keysize;
  size_t blocklen;
  size_t b;
  error_t err;

  keysize = block_keysize(str, &min_dist, max_keysize);
  blocklen = str.len / keysize;

  err = string_alloc(&block, blocklen) ||
        string_alloc(key, keysize);
  if (err) {
    goto end;
  }

  kptr = key->ptr;

  /* transpose blocks */
  for (b = 0; b < keysize; b++) {
    int max_score = 0;
    size_t i, j;
    for (i = 0, j = b; (i < blocklen) && (j < str.len); i++, j += keysize) {
      block.ptr[i] = str.ptr[j];
    }
    *(kptr++) = xor_find_cipher(block, &max_score);
  }

end:
  string_delete(block);

  return err;
}
