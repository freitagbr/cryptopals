// Copyright (c) 2018 Brandon Freitag <freitagbr@gmail.com>

#ifndef CRYPTOPALS_URL_H_
#define CRYPTOPALS_URL_H_

#include <string>
#include <unordered_map>

namespace cryptopals {
namespace url {

namespace qs {

static const std::string EMPTY("");

typedef std::unordered_map<std::string, std::string> map;

static inline bool should_escape(unsigned char c);

std::string unescape(const std::string &src);

std::string escape(const std::string &src);

std::string encode(map &m);

map decode(const std::string &qs);

} // namespace qs

} // namespace url
} // namespace cryptopals

#endif // CRYPTOPALS_URL_H_
