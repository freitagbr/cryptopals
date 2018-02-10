// Copyright (c) 2018 Brandon Freitag <freitagbr@gmail.com>

#ifndef CRYPTOPALS_URL_HPP_
#define CRYPTOPALS_URL_HPP_

#include <string>
#include <unordered_map>

namespace cryptopals {
namespace url {

namespace qs {

typedef std::unordered_map<std::string, std::string> map;

static inline bool should_escape(unsigned char c);

std::string unescape(const std::string &escaped);

std::string escape(const std::string &unescaped);

std::string encode(map &qsmap);

map decode(const std::string &qs);

} // namespace qs

} // namespace url
} // namespace cryptopals

#endif // CRYPTOPALS_URL_HPP_
