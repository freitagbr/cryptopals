/* Copyright (c) 2018 Brandon Freitag <freitagbr@gmail.com> */

#include "cryptopals/hex.hpp"

#include <string>

namespace cryptopals {

inline size_t hex::decoded_length(const std::string &str) {
  size_t len = str.length();
  return (len + (len % 2)) / 2;
}

inline size_t hex::encoded_length(const std::string &str) {
  return str.length() * 2;
}

std::string hex::encode(const std::string &src) {
  std::string encoded;
  std::string::const_iterator s;
  const size_t len = hex::encoded_length(src);
  unsigned char h[2] = {0, 0};

  encoded.reserve(len);

  for (s = src.cbegin(); s != src.cend(); ++s) {
    hex::btoh(h, *s);
    encoded.append(reinterpret_cast<const char *>(h), 2);
  }

  return encoded;
}

std::string hex::decode(const std::string &src) {
  std::string decoded;
  std::string::const_iterator s = src.cbegin();
  const size_t len = hex::decoded_length(src);

  decoded.reserve(len);

  // one character short because 2 characters are needed at a time
  while (s < (src.cend() - 1)) {
    unsigned char a;
    unsigned char b;
    // ugly way to ignore non-hex characters
    do {
      a = hex::htob(*s++);
    } while (static_cast<char>(a) == -1 && s < (src.cend() - 1));
    do {
      b = hex::htob(*s++);
    } while (static_cast<char>(b) == -1 && s < src.cend());
    decoded += (a << 4) | b;
  }

  return decoded;
}

} // namespace cryptopals
