// Copyright (c) 2018 Brandon Freitag <freitagbr@gmail.com>

#include "cryptopals/hex.hpp"

#include <string>

namespace cryptopals {

std::string hex::encode(const std::string &str) {
  std::string encoded;
  std::string::const_iterator s;
  const size_t len = hex::encoded_length(str);
  unsigned char h[2] = {0, 0};

  encoded.reserve(len);

  for (s = str.cbegin(); s != str.cend(); ++s) {
    hex::btoh(h, *s);
    encoded.append(reinterpret_cast<const char *>(h), 2);
  }

  return encoded;
}

std::string hex::decode(const std::string &str) {
  std::string decoded;
  std::string::const_iterator s = str.cbegin();
  const size_t len = hex::decoded_length(str);

  decoded.reserve(len);

  // one character short because 2 characters are needed at a time
  while (s < (str.cend() - 1)) {
    int a;
    int b;
    // ugly way to ignore non-hex characters
    do {
      a = hex::htob(*s++);
    } while (a == -1 && s < (str.cend() - 1));
    do {
      b = hex::htob(*s++);
    } while (b == -1 && s < str.cend());
    if (a != -1 && b != -1) {
      unsigned char upper = static_cast<unsigned char>(a) << 4;
      unsigned char lower = static_cast<unsigned char>(b);
      decoded += upper | lower;
    }
  }

  return decoded;
}

} // namespace cryptopals
