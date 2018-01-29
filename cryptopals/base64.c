/* Copyright (c) 2018 Brandon Freitag <freitagbr@gmail.com> */

#include "cryptopals/base64.h"

#include <stddef.h>
#include <string.h>

#include "cryptopals/error.h"
#include "cryptopals/file.h"
#include "cryptopals/string.h"

int base64_decoded_length(const string str) {
  const unsigned char *end = &(str.ptr[str.len]);
  int eqs = 0;
  while (*(--end) == '=') {
    ++eqs;
  }
  return ((str.len * 3) / 4) - eqs;
}

int base64_encoded_length(size_t len) {
  return (len + 2 - ((len + 2) % 3)) / 3 * 4;
}

static void btoa(unsigned char *a, unsigned char *b) {
  a[0] = (b[0] & 0xfc) >> 2;
  a[1] = ((b[0] & 0x03) << 4) + ((b[1] & 0xf0) >> 4);
  a[2] = ((b[1] & 0x0f) << 2) + ((b[2] & 0xc0) >> 6);
  a[3] = (b[2] & 0x3f);
}

static void atob(unsigned char *b, unsigned char *a) {
  b[0] = (a[0] << 2) + ((a[1] & 0x30) >> 4);
  b[1] = ((a[1] & 0xf) << 4) + ((a[2] & 0x3c) >> 2);
  b[2] = ((a[2] & 0x3) << 6) + a[3];
}

error_t base64_encode(string *dst, const string src) {
  unsigned char *sptr = src.ptr;
  unsigned char b[3] = {0, 0, 0};
  unsigned char a[4] = {0, 0, 0, 0};
  unsigned char *dstptr;
  unsigned char *dptr;
  size_t srclen = src.len;
  const size_t dstlen = base64_encoded_length(srclen);
  int i = 0;
  error_t err;

  err = string_alloc(dst, dstlen);
  if (err) {
    return err;
  }

  dptr = dstptr = dst->ptr;

  while (srclen--) {
    b[i++] = *(sptr++);

    if (i == 3) {
      btoa(a, b);

      *(dptr++) = base64_encode_table[a[0]];
      *(dptr++) = base64_encode_table[a[1]];
      *(dptr++) = base64_encode_table[a[2]];
      *(dptr++) = base64_encode_table[a[3]];

      i = 0;
    }
  }

  if (i) {
    int j;

    for (j = i; j < 3; j++) {
      b[j] = '\0';
    }

    btoa(a, b);

    for (j = 0; j < i + 1; j++) {
      *(dptr++) = base64_encode_table[a[j]];
    }

    while ((i++ < 3)) {
      *(dptr++) = '=';
    }
  }

  if (dptr != (dstptr + dstlen)) {
    return EBASE64E;
  }

  return 0;
}

error_t base64_decode(string *dst, const string src) {
  unsigned char *sptr = src.ptr;
  unsigned char b[3] = {0, 0, 0};
  unsigned char a[4] = {0, 0, 0, 0};
  unsigned char *dstptr;
  unsigned char *dptr;
  size_t srclen = src.len;
  const size_t dstlen = base64_decoded_length(src);
  int i = 0;
  error_t err;

  err = string_alloc(dst, dstlen);
  if (err) {
    return err;
  }

  dptr = dstptr = dst->ptr;

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

      *(dptr++) = b[0];
      *(dptr++) = b[1];
      *(dptr++) = b[2];

      i = 0;
    }
  }

  if (i) {
    int j;

    for (j = i; j < 4; j++) {
      a[j] = '\0';
    }

    a[0] = base64_decode_table[a[0]];
    a[1] = base64_decode_table[a[1]];
    a[2] = base64_decode_table[a[2]];
    a[3] = base64_decode_table[a[3]];

    atob(b, a);

    for (j = 0; j < i - 1; j++) {
      *(dptr++) = b[j];
    }
  }

  if (dptr != (dstptr + dstlen)) {
    return EBASE64D;
  }

  return 0;
}

error_t base64_decode_file(const char *file, string *dst) {
  string tmp = string_init();
  string b64 = string_init();
  size_t i = 0;
  size_t j = 0;
  error_t err;

  err = file_read(file, &tmp) ||
        string_alloc(&b64, tmp.len);
  if (err) {
    goto end;
  }

  b64.len = 0;

  while (i < tmp.len) {
    size_t t;
    while ((base64_decode_table[tmp.ptr[i]] != -1) || (tmp.ptr[i] == '=')) {
      i++;
    }
    t = i - j;
    memcpy(&(b64.ptr[b64.len]), &(tmp.ptr[j]), t);
    b64.len += t;
    j = ++i;
  }

  err = base64_decode(dst, b64);

end:
  string_delete(tmp);
  string_delete(b64);

  return err;
}
