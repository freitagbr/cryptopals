#include "cryptopals/hamming.h"

#include <stddef.h>

static int popcount(unsigned char n) {
  int count = 0;
  while (n) {
    n &= n - 1;
    count++;
  }
  return count;
}

int hamming_distance(const unsigned char *a, const unsigned char *b,
                     const size_t len) {
  int dist = 0;
  size_t i;
  for (i = 0; i < len; i++) {
    dist += popcount(a[i] ^ b[i]);
  }
  return dist;
}
