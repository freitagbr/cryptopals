#include "cryptopals/block.h"

#include <float.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "cryptopals/buffer.h"
#include "cryptopals/error.h"
#include "cryptopals/hamming.h"
#include "cryptopals/xor.h"

error_t block_get_keysize(buffer buf, float *min_dist, size_t *keysize,
                          size_t max_keysize) {
  buffer block_a = buffer_init();
  buffer block_b = buffer_init();
  error_t err = 0;

  err = buffer_alloc(&block_a, max_keysize) ||
        buffer_alloc(&block_b, max_keysize);
  if (err) {
    goto end;
  }

  *min_dist = FLT_MAX;
  *keysize = 0;

  // check keysizes between 2 and max_keysize
  for (size_t k = 2; k <= max_keysize; k++) {
    // break the data into blocks of size of the key,
    // but ignore the trailing block, which may be
    // smaller than the other blocks, preventing
    // out-of-bounds memory access
    const size_t nblocks = (buf.len / k) - 1;
    float dist = 0;

    // sum the hamming distances, normalized
    // by the keysize, between adjacent blocks
    for (size_t b = 0; b < nblocks; b++) {
      const size_t offset_a = b * k;
      const size_t offset_b = offset_a + k;
      memcpy(block_a.ptr, &(buf.ptr[offset_a]), k);
      memcpy(block_b.ptr, &(buf.ptr[offset_b]), k);
      float hd = (float)hamming_distance(block_a.ptr, block_b.ptr, k);
      dist += (float)(hd / (float)k);
    }

    // average the hamming distances
    dist /= (float)nblocks;

    if (dist < *min_dist) {
      *min_dist = dist;
      *keysize = (size_t)k;
    }
  }

end:
  buffer_delete(block_a);
  buffer_delete(block_b);

  return err;
}

error_t block_transpose_get_key(buffer *key, buffer buf, size_t max_keysize) {
  buffer block = buffer_init();
  unsigned char *kptr = NULL;
  float min_dist = 0;
  size_t keysize = 0;
  error_t err = 0;

  err = block_get_keysize(buf, &min_dist, &keysize, max_keysize);
  if (err) {
    goto end;
  }

  const size_t blocklen = buf.len / keysize;
  err = buffer_alloc(&block, blocklen) || buffer_alloc(key, keysize);
  if (err) {
    goto end;
  }

  kptr = key->ptr;

  // transpose blocks
  for (size_t b = 0; b < keysize; b++) {
    for (size_t i = 0, j = b; (i < blocklen) && (j < buf.len);
         i++, j += keysize) {
      block.ptr[i] = buf.ptr[j];
    }

    int max_score = 0;
    *kptr++ = xor_find_cipher(block, &max_score);
  }

end:
  buffer_delete(block);

  return err;
}
