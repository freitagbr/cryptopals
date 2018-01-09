#include "cryptopals/buffer.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include "cryptopals/error.h"

error_t buffer_alloc(buffer *buf, size_t len) {
  uint8_t *ptr = (uint8_t *)calloc(len + 1, sizeof(uint8_t));
  if (ptr == NULL) {
    return EMALLOC;
  }
  buf->ptr = ptr;
  buf->len = len;
  return 0;
}

error_t buffer_resize(buffer *buf, size_t len) {
  uint8_t *ptr = (uint8_t *)realloc(buf->ptr, sizeof(uint8_t) * (len + 1));
  if (ptr == NULL) {
    return EMALLOC;
  }
  buf->ptr = ptr;
  buf->len = len;
  return 0;
}
