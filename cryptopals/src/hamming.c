#include "hamming.h"

int hamming_distance(const unsigned char *a, const unsigned char *b, const size_t len) {
    int dist = 0;
    for (size_t i = 0; i < len; i++) {
        dist += popcount(a[i] ^ b[i]);
    }
    return dist;
}
