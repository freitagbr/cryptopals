#ifndef HAMMING_H
#define HAMMING_H

#include <stddef.h>
#include <stdint.h>

static inline int popcount(uint8_t n) {
    int count = 0;
    while (n) {
        n &= n - 1;
        count++;
    }
    return count;
}

int hamming_distance(const uint8_t *a, const uint8_t *b, const size_t len);

#endif
