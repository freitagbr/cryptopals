#include "cryptopals/hamming.h"

#include <stddef.h>
#include <stdint.h>

int hamming_distance(const uint8_t *a, const uint8_t *b, const size_t len) {
  int dist = 0;
  for (size_t i = 0; i < len; i++) {
    dist += popcount(a[i] ^ b[i]);
  }
  return dist;
}
