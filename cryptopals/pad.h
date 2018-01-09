#ifndef CRYPTOPALS_PAD_H_
#define CRYPTOPALS_PAD_H_

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "cryptopals/buffer.h"
#include "cryptopals/error.h"

error_t pad_bytes(buffer *dst, const buffer src, const size_t len, const uint8_t iv);

#endif // CRYPTOPALS_PAD_H_
