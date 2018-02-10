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

std::string url::qs::unescape(const std::string &escaped) {
  std::string::const_iterator e = escaped.cbegin();
  size_t percents = 0;
  bool hasplus = false;

  while (e < escaped.cend()) {
    switch (*e) {
    case '%':
      percents++;
      if (e + 2 >= escaped.cend() || hex::htob(e[1]) == -1 ||
          hex::htob(e[2]) == -1) {
        throw error::Error("URL contains invalid character sequence");
      }
      break;
    case '+':
      hasplus = true;
      break;
    default:
      break;
    }
    ++e;
  }

  if (percents == 0 && !hasplus) {
    return escaped;
  }

  std::string unescaped;
  std::string::iterator u;

  unescaped.resize(escaped.length());
  u = unescaped.begin();
  e = escaped.cbegin();

  while (e < escaped.cend()) {
    unsigned char upper;
    unsigned char lower;

    switch (*e) {
    case '%':
      upper = static_cast<unsigned char>(hex::htob(e[1])) << 4;
      lower = static_cast<unsigned char>(hex::htob(e[2]));
      *u++ = upper | lower;
      e += 3;
      break;
    case '+':
      *u++ = ' ';
      ++e;
      break;
    default:
      *u++ = *e++;
      break;
    }
  }

  unescaped.shrink_to_fit();

  return unescaped;
}

std::string url::qs::escape(const std::string &unescaped) {
  std::string::const_iterator u = unescaped.cbegin();
  size_t spaces = 0;
  size_t hexes = 0;

  while (u < unescaped.cend()) {
    if (url::qs::should_escape(*u)) {
      if (*u == ' ') {
        spaces++;
      } else {
        hexes++;
      }
    }
    ++u;
  }

  if (spaces == 0 && hexes == 0) {
    return unescaped;
  }

  std::string escaped;
  std::string::iterator e;
  unsigned char h[2];

  escaped.resize(unescaped.length() + (hexes * 2));
  e = escaped.begin();
  u = unescaped.cbegin();

  while (u < unescaped.cend()) {
    if (*u == ' ') {
      *e++ = '+';
      ++u;
    } else if (url::qs::should_escape(*u)) {
      hex::btoh(h, *u++);
      *e++ = '%';
      *e++ = h[0];
      *e++ = h[1];
    } else {
      *e++ = *u++;
    }
  }

  escaped.shrink_to_fit();

  return escaped;
}

std::string url::qs::encode(url::qs::map &qsmap) {
  std::string encoded;
  url::qs::map::const_iterator m = qsmap.cbegin();

  while (m != qsmap.cend()) {
    std::string key = url::qs::escape(m->first);
    std::string val = url::qs::escape(m->second);

    encoded += key;
    if (val.length() > 0) {
      encoded += EQ;
      encoded += val;
    }

    ++m;

    if (m != qsmap.cend()) {
      encoded += SEP;
    }
  }

  return encoded;
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
      qsmap[""] = "";
      break;
    }

    size_t keyend = qs.find(EQ, keypos);

    if (keyend == std::string::npos) {
      std::string key = url::qs::unescape(qs.substr(keypos, keyend - keypos));
      qsmap[key] = "";
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
