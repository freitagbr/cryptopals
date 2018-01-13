/* Copyright (c) 2018 Brandon Freitag <freitagbr@gmail.com> */

#include "cryptopals/aes.h"

#include <openssl/aes.h>

#include "cryptopals/buffer.h"
#include "cryptopals/error.h"

error_t aes_ecb_decrypt(buffer *dec, const buffer enc, const buffer key) {
  AES_KEY aes_key;
  unsigned char *eptr;
  unsigned char *dptr;
  size_t len;
  error_t err;

  err = buffer_alloc(dec, enc.len);
  if (err) {
    return err;
  }

  if (0 != AES_set_decrypt_key(key.ptr, key.len * 8, &aes_key)) {
    return EAESKEY;
  }

  eptr = enc.ptr;
  dptr = dec->ptr;

  for (len = 0; len < dec->len; len += AES_BLOCK_SIZE) {
    AES_ecb_encrypt(&(eptr[len]), &(dptr[len]), &aes_key, AES_BLOCK_SIZE);
  }

  return aes_pkcs7_strip(dec);
}

error_t aes_pkcs7_strip(buffer *buf) {
  unsigned char *ptr = buf->ptr;
  size_t padlen = buf->len;
  size_t padding = (size_t)ptr[padlen - 1];
  size_t len;
  size_t i;

  if (ptr[padlen - padding] != padding) {
    return EAESPKCS7;
  }

  len = padlen - padding;

  for (i = len; i < padlen; i++) {
    if (ptr[i] != padding) {
      return EAESPKCS7;
    }
  }

  buffer_resize(buf, len);

  return 0;
}
