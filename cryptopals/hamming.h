#ifndef CRYPTOPALS_HAMMING_H_
#define CRYPTOPALS_HAMMING_H_

#include <stddef.h>

static inline int popcount(unsigned char n) {
  int count = 0;
  while (n) {
    n &= n - 1;
    count++;
  }
  return count;
}

int hamming_distance(const unsigned char *a, const unsigned char *b,
                     const size_t len);

#endif // CRYPTOPALS_HAMMING_H_
