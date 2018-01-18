/* Copyright (c) 2018 Brandon Freitag <freitagbr@gmail.com> */

#include "cryptopals/aes.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/aes.h>

#include "cryptopals/buffer.h"
#include "cryptopals/error.h"
#include "cryptopals/xor.h"

static int aes_rand_seeded = 0;

error_t aes_ecb_decrypt(buffer *dst, const buffer src, const buffer key) {
  AES_KEY aes_key;
  unsigned char *sptr = src.ptr;
  unsigned char *dptr;
  unsigned char *endptr;
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

  dptr = dst->ptr;
  endptr = &(dst->ptr[dst->len]);

  while (dptr < endptr) {
    AES_decrypt(sptr, dptr, &aes_key);
    dptr += AES_BLOCK_SIZE;
    sptr += AES_BLOCK_SIZE;
  }

  return aes_pkcs7_strip(dst);
}

error_t aes_ecb_encrypt(buffer *dst, const buffer src, const buffer key) {
  AES_KEY aes_key;
  unsigned char *sptr = src.ptr;
  unsigned char *dptr;
  unsigned char *endptr;
  size_t padding;
  int ret;
  error_t err;

  ret = AES_set_encrypt_key(key.ptr, key.len * 8, &aes_key);
  if (ret < 0) {
    return EAESKEY;
  }

  err = aes_pkcs7_pad(dst, src.len, &padding);
  if (err) {
    return err;
  }

  dptr = dst->ptr;
  endptr = &(dst->ptr[dst->len - AES_BLOCK_SIZE]);

  while (dptr < endptr) {
    AES_encrypt(sptr, dptr, &aes_key);
    dptr += AES_BLOCK_SIZE;
    sptr += AES_BLOCK_SIZE;
  }

  memcpy(dptr, sptr, AES_BLOCK_SIZE - padding);
  AES_encrypt(dptr, dptr, &aes_key);

  return 0;
}

error_t aes_cbc_decrypt(buffer *dst, const buffer src, const buffer key,
                        const buffer iv) {
  buffer ivblock = buffer_init();
  buffer decblock = buffer_init();
  AES_KEY aes_key;
  unsigned char *sptr = src.ptr;
  unsigned char *dptr;
  unsigned char *endptr;
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
  dptr = dst->ptr;
  endptr = &(dst->ptr[dst->len]);

  while (dptr < endptr) {
    AES_decrypt(sptr, dptr, &aes_key);
    buffer_set(decblock, dptr, AES_BLOCK_SIZE);
    xor_fixed(decblock, ivblock);
    memcpy(ivblock.ptr, sptr, ivblock.len);
    dptr += AES_BLOCK_SIZE;
    sptr += AES_BLOCK_SIZE;
  }

  err = aes_pkcs7_strip(dst);

end:
  buffer_delete(ivblock);

  return err;
}

error_t aes_cbc_encrypt(buffer *dst, const buffer src, const buffer key,
                        const buffer iv) {
  buffer ivblock = buffer_init();
  buffer encblock = buffer_init();
  AES_KEY aes_key;
  unsigned char *sptr = src.ptr;
  unsigned char *dptr;
  unsigned char *endptr;
  size_t padding;
  int ret;
  error_t err;

  ret = AES_set_encrypt_key(key.ptr, key.len * 8, &aes_key);
  if (ret < 0) {
    return EAESKEY;
  }

  err = aes_pkcs7_pad(dst, src.len, &padding) || buffer_alloc(&ivblock, iv.len);
  if (err) {
    goto end;
  }

  memcpy(ivblock.ptr, iv.ptr, ivblock.len);
  dptr = dst->ptr;
  endptr = &(dst->ptr[dst->len - AES_BLOCK_SIZE]);

  while (dptr < endptr) {
    memcpy(dptr, sptr, AES_BLOCK_SIZE);
    buffer_set(encblock, dptr, AES_BLOCK_SIZE);
    xor_fixed(encblock, ivblock);
    AES_encrypt(dptr, dptr, &aes_key);
    memcpy(ivblock.ptr, dptr, AES_BLOCK_SIZE);
    dptr += AES_BLOCK_SIZE;
    sptr += AES_BLOCK_SIZE;
  }

  memcpy(dptr, sptr, AES_BLOCK_SIZE - padding);
  buffer_set(encblock, dptr, AES_BLOCK_SIZE);
  xor_fixed(encblock, ivblock);
  AES_encrypt(dptr, dptr, &aes_key);

end:
  buffer_delete(ivblock);

  return err;
}

error_t aes_pkcs7_pad(buffer *buf, size_t len, size_t *padding) {
  size_t buflen = len + (AES_BLOCK_SIZE - (len % AES_BLOCK_SIZE));
  error_t err;

  err = buffer_alloc(buf, buflen);
  if (err) {
    return err;
  }

  *padding = buflen - len;

  if (*padding > AES_BLOCK_SIZE) {
    return ESIZE;
  }

  if (*padding) {
    memset(&(buf->ptr[buf->len - *padding]), (int)*padding, *padding);
  }

  return 0;
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

error_t aes_random_key(buffer *key) {
  unsigned char *ptr;
  unsigned char *end;
  error_t err;

  if (!aes_rand_seeded) {
    /* seed rand with the time * a pointer */
    int tmp = 0;
    srand((unsigned int)((long)time(NULL) * (long)&tmp));
    aes_rand_seeded = 1;
  }

  err = buffer_alloc(key, AES_BLOCK_SIZE);
  if (err) {
    return err;
  }

  ptr = key->ptr;
  end = &(ptr[AES_BLOCK_SIZE]);

  while (ptr < end) {
    int r = rand();
    size_t i;
    for (i = 0; (i < sizeof(int)) && (ptr < end); i++) {
      *(ptr++) = (unsigned char)((r >> (i * 8)) & 0xff);
    }
  }

  return 0;
}
