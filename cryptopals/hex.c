#include "cryptopals/hex.h"

#include <stddef.h>
#include <stdlib.h>

#include "cryptopals/buffer.h"
#include "cryptopals/error.h"

error_t hex_decode(buffer *dst, const buffer src) {
  const size_t srclen = src.len;

  if ((srclen % 2) != 0) {
    return EHEXLEN;
  }

  size_t declen = hex_decoded_length(srclen);

  // reuse old memory if possible
  if (dst->ptr != NULL) {
    if (dst->len < declen) {
      error_t err = buffer_resize(dst, declen);
      if (err) {
        return err;
      }
    }
  } else {
    error_t err = buffer_alloc(dst, declen);
    if (err) {
      return err;
    }
  }

  unsigned char *dptr = dst->ptr;

  for (size_t i = 0; i < srclen; i += 2) {
    char a = htob(src.ptr[i]);
    char b = htob(src.ptr[i + 1]);
    if ((a == -1) || (b == -1)) {
      return EHEXCHAR;
    }
    *dptr++ = (unsigned char)((a << 4) | b);
  }

  *dptr = '\0';

  return 0;
}

error_t hex_encode(buffer *dst, const buffer src) {
  const size_t srclen = src.len;
  size_t enclen = hex_encoded_length(srclen);
  error_t err = 0;

  // reuse old memory if possible
  if (dst->ptr != NULL) {
    if (dst->len < enclen) {
      err = buffer_resize(dst, enclen);
    }
  } else {
    err = buffer_alloc(dst, enclen);
  }

  if (err) {
    return err;
  }

  unsigned char *dptr = dst->ptr;

  for (size_t i = 0; i < srclen; i++) {
    btoh(src.ptr[i], dptr);
    dptr += 2;
  }

  *dptr = '\0';

  return 0;
}
