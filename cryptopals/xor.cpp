// Copyright (c) 2018 Brandon Freitag <freitagbr@gmail.com>

#include "cryptopals/xor.hpp"

#include <string>

namespace cryptopals {

std::string operator^(const std::string &lhs, const std::string &rhs) {
  std::string dst;
  std::string::iterator d;
  std::string::const_iterator l = lhs.cbegin();
  std::string::const_iterator r = rhs.cbegin();
  dst.resize(lhs.length());
  d = dst.begin();
  if (lhs.length() == rhs.length()) {
    while (d != dst.end()) {
      *d++ = *l++ ^ *r++;
    }
  } else {
    while (d != dst.end()) {
      // rhs is repeating key
      *d++ = *l++ ^ *r++;
      if (r == rhs.cend()) {
        r = rhs.cbegin();
      }
    }
  }
  return dst;
}

std::string operator^(const std::string &lhs, const unsigned char rhs) {
  std::string dst;
  std::string::iterator d;
  std::string::const_iterator l = lhs.cbegin();
  dst.resize(lhs.length());
  d = dst.begin();
  while (d != dst.end()) {
    *d++ = *l++ ^ rhs;
  }
  return dst;
}

std::string &operator^=(std::string &lhs, const std::string &rhs) {
  std::string::iterator l = lhs.begin();
  std::string::const_iterator r = rhs.cbegin();
  while (l < lhs.end() && r < rhs.cend()) {
    *l = *l ^ *r;
    ++l;
    ++r;
  }
  return lhs;
}

unsigned char xor_::find_key(const std::string &str, int &max) {
  unsigned char key = 0;

  for (int k = 0; k <= 0xFF; k++) {
    int hits = 0;
    for (size_t i = 0; i < 13; i++) {
      unsigned char c = xor_::english_cipher_chars[i];
      std::string::const_iterator s = str.cbegin();
      while (s != str.cend()) {
        if ((*s++ ^ static_cast<unsigned char>(k)) == c) {
          hits++;
        }
      }
    }
    if (hits > max) {
      max = hits;
      key = static_cast<unsigned char>(k);
    }
  }

  return key;
}

unsigned char xor_::find_key(const std::string &str) {
  int max = 0;
  return xor_::find_key(str, max);
}

} // namespace cryptopals
