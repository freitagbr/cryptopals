// Copyright (c) 2018 Brandon Freitag <freitagbr@gmail.com>

#ifndef CRYPTOPALS_HAMMING_H_
#define CRYPTOPALS_HAMMING_H_

#include <string>

namespace cryptopals {
namespace hamming {

static inline size_t popcount(unsigned char n);

size_t distance(const std::string &str, const size_t pos, const size_t len);

} // namespace hamming
} // namespace cryptopals
#endif // CRYPTOPALS_HAMMING_H_
