/* Copyright (c) 2018 Brandon Freitag <freitagbr@gmail.com> */

#ifndef CRYPTOPALS_URL_H_
#define CRYPTOPALS_URL_H_

#include "cryptopals/string.h"
#include "cryptopals/error.h"
#include "cryptopals/map.h"

error_t url_qs_unescape(string *dst, const string src);

error_t url_qs_escape(string *dst, const string src);

error_t url_qs_encode(string *dst, map *m);

error_t url_qs_decode(map *m, const string qs);

#endif /* CRYPTOPALS_URL_H_ */
