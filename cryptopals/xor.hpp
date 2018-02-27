// Copyright (c) 2018 Brandon Freitag <freitagbr@gmail.com>

#ifndef CRYPTOPALS_XOR_HPP_
#define CRYPTOPALS_XOR_HPP_

#include <string>

namespace cryptopals {

std::string operator^(const std::string &lhs, const std::string &rhs);

std::string operator^(const std::string &lhs, const unsigned char rhs);

std::string &operator^=(const std::string &lhs, const std::string &rhs);

namespace xor_ {

static const unsigned char english_cipher_chars[14] = "etaoin shrdlu";

inline void bytes(unsigned char *val, const unsigned char *a,
                  const unsigned char *b, const size_t len) {
  for (size_t i = 0; i < len; i++) {
    *val++ = *a++ ^ *b++;
  }
}

inline void inplace(unsigned char *a, const unsigned char *b,
                    const size_t len) {
  for (size_t i = 0; i < len; i++) {
    *a = *a ^ *b++;
    a++;
  }
}

inline void inplace(std::string::iterator a, const unsigned char *b,
                    const size_t len) {
  for (size_t i = 0; i < len; i++) {
    *a = *a ^ *b++;
    ++a;
  }
}

unsigned char find_key(const std::string &str, int &max);

unsigned char find_key(const std::string &str);

} // namespace xor_
} // namespace cryptopals

#endif // CRYPTOPALS_XOR_HPP_
