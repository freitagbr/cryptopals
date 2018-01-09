#include "cryptopals/pad.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "cryptopals/buffer.h"
#include "cryptopals/error.h"

error_t pad_bytes(buffer *dst, const buffer src, const size_t len,
                  const uint8_t iv) {
  if (len < src.len) {
    return EDSTBUF;
  }

  error_t err = buffer_alloc(dst, len);
  if (err) {
    return err;
  }

  memset(dst->ptr, iv, dst->len);
  memcpy(dst->ptr, src.ptr, src.len);

  return 0;
}
