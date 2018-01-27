/* Copyright (c) 2018 Brandon Freitag <freitagbr@gmail.com> */

#ifndef CRYPTOPALS_URL_H_
#define CRYPTOPALS_URL_H_

#include "cryptopals/buffer.h"
#include "cryptopals/error.h"
#include "cryptopals/map.h"

error_t url_qs_unescape(buffer *dst, const buffer src);

error_t url_qs_escape(buffer *dst, const buffer src);

error_t url_qs_encode(buffer *dst, map *m);

error_t url_qs_decode(map *m, const buffer qs);

#endif /* CRYPTOPALS_URL_H_ */
