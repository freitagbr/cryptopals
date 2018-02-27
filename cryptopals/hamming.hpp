// Copyright (c) 2018 Brandon Freitag <freitagbr@gmail.com>

#ifndef CRYPTOPALS_HAMMING_HPP_
#define CRYPTOPALS_HAMMING_HPP_

#include <string>

namespace cryptopals {
namespace hamming {

inline size_t popcount(unsigned char n) {
  size_t count = 0;
  while (n) {
    n &= n - 1;
    count++;
  }
  return count;
}

size_t distance(const std::string &str, const size_t pos, const size_t len);

} // namespace hamming
} // namespace cryptopals

#endif // CRYPTOPALS_HAMMING_HPP_
