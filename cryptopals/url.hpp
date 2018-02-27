// Copyright (c) 2018 Brandon Freitag <freitagbr@gmail.com>

#ifndef CRYPTOPALS_URL_HPP_
#define CRYPTOPALS_URL_HPP_

#include <string>
#include <unordered_map>

namespace cryptopals {
namespace url {

namespace qs {

typedef std::unordered_map<std::string, std::string> map;

inline bool should_escape(unsigned char c) {
  if (('A' <= c && c <= 'Z') || ('a' <= c && c <= 'z') ||
      ('0' <= c && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~') {
    return false;
  }
  return true;
}

std::string unescape(const std::string &escaped);

std::string escape(const std::string &unescaped);

std::string encode(map &qsmap);

map decode(const std::string &qs);

} // namespace qs

} // namespace url
} // namespace cryptopals

#endif // CRYPTOPALS_URL_HPP_
