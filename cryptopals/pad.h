/* Copyright (c) 2018 Brandon Freitag <freitagbr@gmail.com> */

#ifndef CRYPTOPALS_PAD_H_
#define CRYPTOPALS_PAD_H_

#include <stddef.h>

#include "cryptopals/string.h"
#include "cryptopals/error.h"

error_t pad_bytes(string *dst, const string src, const size_t len,
                  const unsigned char iv);

#endif /* CRYPTOPALS_PAD_H_ */
