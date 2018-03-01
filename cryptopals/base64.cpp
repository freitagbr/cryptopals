// Copyright (c) 2018 Brandon Freitag <freitagbr@gmail.com>

#include "cryptopals/base64.hpp"

#include <fstream>
#include <iostream>
#include <string>

namespace cryptopals {

std::string base64::encode(const std::string &src) {
  std::string encoded;
  std::string::const_iterator s;
  const size_t len = base64::encoded_length(src);
  unsigned char a[4] = {0, 0, 0, 0};
  unsigned char b[3] = {0, 0, 0};
  int i = 0;

  encoded.reserve(len);

  for (s = src.cbegin(); s != src.cend(); ++s) {
    b[i++] = static_cast<unsigned char>(*s);

    if (i == 3) {
      base64::btoa(a, b);
      encoded.append(reinterpret_cast<const char *>(a), 4);
      i = 0;
    }
  }

  if (i) {
    for (int j = i; j < 3; j++) {
      b[j] = '\0';
    }

    base64::btoa(a, b);
    encoded.append(reinterpret_cast<const char *>(a), i + 1);

    while (i++ < 3) {
      encoded += '=';
    }
  }

  return encoded;
}

std::string base64::decode(const std::string &src) {
  std::string decoded;
  std::string::const_iterator s;
  unsigned char a[4] = {0, 0, 0, 0};
  unsigned char b[3] = {0, 0, 0};
  const size_t len = base64::decoded_length(src);
  int i = 0;

  decoded.reserve(len);

  for (s = src.cbegin(); s != src.cend(); ++s) {
    if (*s == '=') {
      break;
    }

    unsigned char c = static_cast<unsigned char>(*s);
    c = static_cast<unsigned char>(
        base64::decode_table[static_cast<size_t>(c)]);
    // skip this character if it was not a base64 character
    if (static_cast<char>(c) == -1) {
      continue;
    }
    a[i++] = c;

    if (i == 4) {
      base64::atob(b, a);
      decoded.append(reinterpret_cast<const char *>(b), 3);
      i = 0;
    }
  }

  if (i) {
    for (int j = i; j < 4; j++) {
      a[j] = base64::decode_table[0];
    }

    base64::atob(b, a);
    decoded.append(reinterpret_cast<const char *>(b), i - 1);
  }

  return decoded;
}

std::string base64::decode_file(const char *file) {
  std::ifstream f(file);
  std::string decoded;
  unsigned char a[4] = {0, 0, 0, 0};
  unsigned char b[3] = {0, 0, 0};
  unsigned char c;
  int i = 0;

  while (f >> c) {
    if (c == '=') {
      break;
    }

    c = static_cast<unsigned char>(
        base64::decode_table[static_cast<size_t>(c)]);
    // skip this character if it was not a base64 character
    if (static_cast<char>(c) == -1) {
      continue;
    }
    a[i++] = c;

    if (i == 4) {
      base64::atob(b, a);
      decoded.append(reinterpret_cast<const char *>(b), 3);
      i = 0;
    }
  }

  if (i) {
    for (int j = i; j < 4; j++) {
      a[j] = static_cast<unsigned char>(base64::decode_table[0]);
    }

    base64::atob(b, a);
    decoded.append(reinterpret_cast<const char *>(b), i - 1);
  }

  return decoded;
}

} // namespace cryptopals
