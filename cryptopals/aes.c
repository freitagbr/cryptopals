/* Copyright (c) 2018 Brandon Freitag <freitagbr@gmail.com> */

#include "cryptopals/aes.h"

#include <stdio.h>

#include <openssl/aes.h>

#include "cryptopals/buffer.h"
#include "cryptopals/error.h"
#include "cryptopals/xor.h"

error_t aes_ecb_decrypt(buffer *dec, const buffer enc, const buffer key) {
  AES_KEY aes_key;
  unsigned char *eptr;
  unsigned char *dptr;
  size_t len;
  error_t err;

  if (0 != AES_set_decrypt_key(key.ptr, key.len * 8, &aes_key)) {
    return EAESKEY;
  }

  err = buffer_alloc(dec, enc.len);
  if (err) {
    return err;
  }

  eptr = enc.ptr;
  dptr = dec->ptr;

  for (len = 0; len < dec->len; len += AES_BLOCK_SIZE) {
    AES_ecb_encrypt(&(eptr[len]), &(dptr[len]), &aes_key, AES_BLOCK_SIZE);
  }

  return aes_pkcs7_strip(dec);
}

error_t aes_cbc_decrypt(buffer *dec, const buffer enc, const buffer key,
                        const buffer iv) {
  buffer ivblock = buffer_init();
  buffer decblock = buffer_init();
  AES_KEY aes_key;
  size_t len;
  error_t err;

  if (0 != AES_set_decrypt_key(key.ptr, key.len * 8, &aes_key)) {
    return EAESKEY;
  }

  err = buffer_alloc(dec, enc.len) || buffer_alloc(&ivblock, iv.len);
  if (err) {
    goto end;
  }

  memcpy(ivblock.ptr, iv.ptr, ivblock.len);

  for (len = 0; len < dec->len; len += AES_BLOCK_SIZE) {
    unsigned char *eptr = &(enc.ptr[len]);
    unsigned char *dptr = &(dec->ptr[len]);
    buffer_set(decblock, dptr, AES_BLOCK_SIZE);
    AES_ecb_encrypt(eptr, dptr, &aes_key, AES_BLOCK_SIZE);
    xor_fixed(decblock, ivblock);
    memcpy(ivblock.ptr, eptr, ivblock.len);
  }

  err = aes_pkcs7_strip(dec);

end:
  buffer_delete(ivblock);

  return err;
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
