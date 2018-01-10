/* Copyright (c) 2018 Brandon Freitag <freitagbr@gmail.com> */

#ifndef CRYPTOPALS_HAMMING_H_
#define CRYPTOPALS_HAMMING_H_

#include <stddef.h>

int hamming_distance(const unsigned char *a, const unsigned char *b,
                     const size_t len);

#endif
