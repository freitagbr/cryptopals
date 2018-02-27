// Copyright (c) 2018 Brandon Freitag <freitagbr@gmail.com>

#include "cryptopals/hamming.hpp"

#include <string>

namespace cryptopals {

size_t hamming::distance(const std::string &str, const size_t pos,
                         const size_t len) {
  size_t end = pos + len;
  size_t dist = 0;
  for (size_t i = pos; i < end; i++) {
    dist += hamming::popcount(str[i] ^ str[i + len]);
  }
  return dist;
}

} // namespace cryptopals
