// Copyright (c) 2018 Brandon Freitag <freitagbr@gmail.com>

#include "cryptopals/url.hpp"

#include <string>
#include <unordered_map>

#include "cryptopals/error.hpp"
#include "cryptopals/hex.hpp"

#define SEP '&'
#define EQ '='

namespace cryptopals {

inline bool url::qs::should_escape(unsigned char c) {
  if (('A' <= c && c <= 'Z') || ('a' <= c && c <= 'z') ||
      ('0' <= c && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~') {
    return false;
  }
  return true;
}

std::string url::qs::unescape(const std::string &src) {
  std::string::const_iterator s = src.cbegin();
  size_t percents = 0;
  bool hasplus = false;

  while (s < src.cend()) {
    switch (*s) {
    case '%':
      percents++;
      if (s + 2 >= src.cend() || hex::htob(s[1]) == 255 ||
          hex::htob(s[2]) == 255) {
        throw error::Error("URL contains invalid character sequence");
      }
      break;
    case '+':
      hasplus = true;
      break;
    default:
      break;
    }
    ++s;
  }

  if (percents == 0 && !hasplus) {
    return src;
  }

  std::string dst;
  std::string::iterator d;

  dst.resize(src.length());
  d = dst.begin();
  s = src.cbegin();

  while (s < src.cend()) {
    switch (*s) {
    case '%':
      *d++ =
          static_cast<unsigned char>((hex::htob(s[1]) << 4) | hex::htob(s[2]));
      s += 3;
      break;
    case '+':
      *d++ = ' ';
      ++s;
      break;
    default:
      *d++ = *s++;
      break;
    }
  }

  dst.shrink_to_fit();

  return dst;
}

std::string url::qs::escape(const std::string &src) {
  std::string::const_iterator s = src.cbegin();
  size_t spaces = 0;
  size_t hexes = 0;

  while (s < src.cend()) {
    if (url::qs::should_escape(*s)) {
      if (*s == ' ') {
        spaces++;
      } else {
        hexes++;
      }
    }
    ++s;
  }

  if (spaces == 0 && hexes == 0) {
    return src;
  }

  std::string dst;
  std::string::iterator d;
  unsigned char h[2];

  dst.resize(src.length() + (hexes * 2));
  d = dst.begin();
  s = src.cbegin();

  while (s < src.cend()) {
    if (*s == ' ') {
      *d++ = '+';
      ++s;
    } else if (url::qs::should_escape(*s)) {
      hex::btoh(h, *s++);
      *d++ = '%';
      *d++ = h[0];
      *d++ = h[1];
    } else {
      *d++ = *s++;
    }
  }

  dst.shrink_to_fit();

  return dst;
}

std::string url::qs::encode(url::qs::map &qsmap) {
  std::string dst;
  url::qs::map::const_iterator m = qsmap.cbegin();

  while (m != qsmap.cend()) {
    std::string key = url::qs::escape(m->first);
    std::string val = url::qs::escape(m->second);

    dst += key;
    if (val.length() > 0) {
      dst += EQ;
      dst += val;
    }

    ++m;

    if (m != qsmap.cend()) {
      dst += SEP;
    }
  }

  return dst;
}

url::qs::map url::qs::decode(const std::string &qs) {
  url::qs::map qsmap;
  size_t keypos = 0;
  size_t valpos = 0;

  if (qs.length() == 0) {
    return qsmap;
  }

  while (keypos < qs.length()) {
    size_t valend = qs.find(SEP, valpos);

    if (keypos == valend) {
      qsmap[EMPTY] = EMPTY;
      break;
    }

    size_t keyend = qs.find(EQ, keypos);

    if (keyend == std::string::npos) {
      std::string key = url::qs::unescape(qs.substr(keypos, keyend - keypos));
      qsmap[key] = EMPTY;
      break;
    }

    valpos = keyend + 1 < valend ? keyend + 1 : keyend;

    std::string key = url::qs::unescape(qs.substr(keypos, keyend - keypos));
    std::string val = url::qs::unescape(qs.substr(valpos, valend - valpos));

    qsmap[key] = val;

    keypos = keyend = valpos = ++valend;
  }

  return qsmap;
}

} // namespace cryptopals
