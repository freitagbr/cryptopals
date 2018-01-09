#include "cryptopals/base64.h"

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cryptopals/buffer.h"
#include "cryptopals/error.h"
#include "cryptopals/file.h"

error_t base64_encode(buffer *dst, const buffer src) {
  unsigned char *sptr = src.ptr;
  size_t srclen = src.len;
  const size_t dstlen = base64_encoded_length(srclen);

  error_t err = buffer_alloc(dst, dstlen);
  if (err) {
    return err;
  }

  unsigned char *dstptr = dst->ptr;
  unsigned char *dptr = dstptr;
  unsigned char b[3] = {0, 0, 0};
  unsigned char a[4] = {0, 0, 0, 0};
  int i = 0;

  while (srclen--) {
    b[i++] = *sptr++;
    if (i == 3) {
      btoa(a, b);

      *dptr++ = base64_encode_table[a[0]];
      *dptr++ = base64_encode_table[a[1]];
      *dptr++ = base64_encode_table[a[2]];
      *dptr++ = base64_encode_table[a[3]];

      i = 0;
    }
  }

  if (i) {
    for (int j = i; j < 3; j++) {
      b[j] = '\0';
    }

    btoa(a, b);

    for (int j = 0; j < i + 1; j++) {
      *dptr++ = base64_encode_table[a[j]];
    }

    while ((i++ < 3)) {
      *dptr++ = '=';
    }
  }

  if (dptr != (dstptr + dstlen)) {
    return EBASE64E;
  }

  return 0;
}

error_t base64_decode(buffer *dst, const buffer src) {
  unsigned char *sptr = src.ptr;
  size_t srclen = src.len;
  const size_t dstlen = base64_decoded_length(src);

  error_t err = buffer_alloc(dst, dstlen);
  if (err) {
    return err;
  }

  unsigned char *dstptr = dst->ptr;
  unsigned char *dptr = dstptr;
  unsigned char b[3] = {0, 0, 0};
  unsigned char a[4] = {0, 0, 0, 0};
  int i = 0;

  while (srclen--) {
    if (*sptr == '=') {
      break;
    }

    a[i++] = *(sptr++);
    if (i == 4) {
      a[0] = base64_decode_table[a[0]];
      a[1] = base64_decode_table[a[1]];
      a[2] = base64_decode_table[a[2]];
      a[3] = base64_decode_table[a[3]];

      atob(b, a);

      *dptr++ = b[0];
      *dptr++ = b[1];
      *dptr++ = b[2];

      i = 0;
    }
  }

  if (i) {
    for (int j = i; j < 4; j++) {
      a[j] = '\0';
    }

    a[0] = base64_decode_table[a[0]];
    a[1] = base64_decode_table[a[1]];
    a[2] = base64_decode_table[a[2]];
    a[3] = base64_decode_table[a[3]];

    atob(b, a);

    for (int j = 0; j < i - 1; j++) {
      *dptr++ = b[j];
    }
  }

  if (dptr != (dstptr + dstlen)) {
    return EBASE64D;
  }

  return 0;
}

error_t base64_decode_file(const char *file, buffer *dst) {
  buffer tmp = buffer_init();
  buffer b64 = buffer_init();
  error_t err = 0;

  err = file_read(file, &tmp);
  if (err) {
    goto end;
  }

  err = buffer_alloc(&b64, tmp.len);
  if (err) {
    goto end;
  }

  size_t i = 0;
  size_t j = 0;
  b64.len = 0;

  while (i < tmp.len) {
    while ((base64_decode_table[tmp.ptr[i]] != -1) || (tmp.ptr[i] == '=')) {
      i++;
    }
    size_t t = i - j;
    memcpy(&(b64.ptr[b64.len]), &(tmp.ptr[j]), t);
    b64.len += t;
    j = ++i;
  }

  err = base64_decode(dst, b64);
  if (err) {
    goto end;
  }

end:
  buffer_delete(tmp);
  buffer_delete(b64);

  return err;
}
