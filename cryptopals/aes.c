/* Copyright (c) 2018 Brandon Freitag <freitagbr@gmail.com> */

#include "cryptopals/aes.h"

#include <stdio.h>

#include <openssl/aes.h>

#include "cryptopals/buffer.h"
#include "cryptopals/error.h"
#include "cryptopals/xor.h"

error_t aes_ecb_decrypt(buffer *dst, const buffer src, const buffer key) {
  AES_KEY aes_key;
  size_t len;
  int ret;
  error_t err;

  ret = AES_set_decrypt_key(key.ptr, key.len * 8, &aes_key);
  if (ret < 0) {
    return EAESKEY;
  }

  err = buffer_alloc(dst, src.len);
  if (err) {
    return err;
  }

  for (len = 0; len < dst->len; len += AES_BLOCK_SIZE) {
    unsigned char *dptr = &(dst->ptr[len]);
    unsigned char *sptr = &(src.ptr[len]);
    AES_ecb_encrypt(sptr, dptr, &aes_key, AES_BLOCK_SIZE);
  }

  return aes_pkcs7_strip(dst);
}

error_t aes_cbc_decrypt(buffer *dst, const buffer src, const buffer key,
                        const buffer iv) {
  buffer ivblock = buffer_init();
  buffer decblock = buffer_init();
  AES_KEY aes_key;
  size_t len;
  int ret;
  error_t err;

  ret = AES_set_decrypt_key(key.ptr, key.len * 8, &aes_key);
  if (ret < 0) {
    return EAESKEY;
  }

  err = buffer_alloc(dst, src.len) || buffer_alloc(&ivblock, iv.len);
  if (err) {
    goto end;
  }

  memcpy(ivblock.ptr, iv.ptr, ivblock.len);

  for (len = 0; len < dst->len; len += AES_BLOCK_SIZE) {
    unsigned char *dptr = &(dst->ptr[len]);
    unsigned char *sptr = &(src.ptr[len]);
    AES_ecb_encrypt(sptr, dptr, &aes_key, AES_BLOCK_SIZE);
    buffer_set(decblock, dptr, AES_BLOCK_SIZE);
    xor_fixed(decblock, ivblock);
    memcpy(ivblock.ptr, sptr, ivblock.len);
  }

  err = aes_pkcs7_strip(dst);

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

  /* a full resize could be expensive, so fake it */
  buf->ptr[len] = '\0';
  buf->len = len;

  return 0;
}
