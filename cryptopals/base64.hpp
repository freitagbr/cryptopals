// Copyright (c) 2018 Brandon Freitag <freitagbr@gmail.com>

#ifndef CRYPTOPALS_BASE64_HPP_
#define CRYPTOPALS_BASE64_HPP_

#include <string>

namespace cryptopals {
namespace base64 {

static const unsigned char encode_table[64] = {
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
    'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
    'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/',
};

static const char decode_table[256] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, 62, -1, -1, -1, 63, 52, 53, 54, 55, 56, 57, 58, 59, 60,
    61, -1, -1, -1, -1, -1, -1, -1, 0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10,
    11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1,
    -1, -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42,
    43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1,
};

inline size_t decoded_length(const std::string &str) {
  std::string::const_reverse_iterator end = str.crbegin();
  size_t eqs = 0;
  while (*end-- == '=') {
    ++eqs;
  }
  return ((str.length() * 3) / 4) - eqs;
}

inline size_t encoded_length(const std::string &str) {
  const size_t len = str.length();
  return (len + 2 - ((len + 2) % 3)) / 3 * 4;
}

inline void btoa(unsigned char *a, unsigned char *b) {
  a[0] = encode_table[(b[0] & 0xfc) >> 2];
  a[1] = encode_table[((b[0] & 0x03) << 4) + ((b[1] & 0xf0) >> 4)];
  a[2] = encode_table[((b[1] & 0x0f) << 2) + ((b[2] & 0xc0) >> 6)];
  a[3] = encode_table[b[2] & 0x3f];
}

inline void atob(unsigned char *b, unsigned char *a) {
  b[0] = (a[0] << 2) + ((a[1] & 0x30) >> 4);
  b[1] = ((a[1] & 0xf) << 4) + ((a[2] & 0x3c) >> 2);
  b[2] = ((a[2] & 0x3) << 6) + a[3];
}

std::string encode(const std::string &src);

std::string decode(const std::string &src);

std::string decode_file(const char *file);

} // namespace base64
} // namespace cryptopals

#endif // CRYPTOPALS_BASE64_HPP_
