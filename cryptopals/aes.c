/* Copyright (c) 2018 Brandon Freitag <freitagbr@gmail.com> */

#include "cryptopals/aes.h"

#include <string.h>

#include <openssl/aes.h>
#include <openssl/rand.h>

#include "cryptopals/buffer.h"
#include "cryptopals/error.h"
#include "cryptopals/xor.h"

static error_t aes_seed_rand() {
  static int aes_rand_seeded = 0;
  if (!aes_rand_seeded) {
    if (RAND_load_file(AES_RAND_SOURCE, AES_RAND_SIZE) != AES_RAND_SIZE) {
      return ERAND;
    }
    aes_rand_seeded = 1;
  }
  return 0;
}

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
  AES_KEY aes_key;
  unsigned char *ivptr = iv.ptr;
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
    xor_inplace(dptr, ivptr, AES_BLOCK_SIZE);
    ivptr = sptr;
    dptr += AES_BLOCK_SIZE;
    sptr += AES_BLOCK_SIZE;
  }

  return aes_pkcs7_strip(dst);
}

error_t aes_cbc_encrypt(buffer *dst, const buffer src, const buffer key,
                        const buffer iv) {
  AES_KEY aes_key;
  unsigned char *ivptr = iv.ptr;
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
    xor_bytes(dptr, sptr, ivptr, AES_BLOCK_SIZE);
    AES_encrypt(dptr, dptr, &aes_key);
    ivptr = dptr;
    dptr += AES_BLOCK_SIZE;
    sptr += AES_BLOCK_SIZE;
  }

  memcpy(dptr, sptr, AES_BLOCK_SIZE - padding);
  xor_inplace(dptr, ivptr, AES_BLOCK_SIZE);
  AES_encrypt(dptr, dptr, &aes_key);

  return 0;
}

error_t aes_encrypt_oracle(buffer *dst, const buffer src, aes_mode_t *mode) {
  buffer key = buffer_init();
  buffer buf = buffer_init();
  unsigned int a;
  unsigned int b;
  unsigned int c;
  size_t padding;
  error_t err;

  err = buffer_alloc(&buf, src.len + 20) ||
        aes_random_bytes(&key) ||
        aes_rand(&a) ||
        aes_rand(&b) ||
        aes_rand(&c);
  if (err) {
    goto end;
  }

  /* pad beginning of buffer with 5-10 bytes */
  padding = (a % 6) + 5;
  if (RAND_bytes(buf.ptr, padding) != 1) {
    err = ERAND;
    goto end;
  }
  memcpy(&(buf.ptr[padding]), src.ptr, src.len);
  buf.len = src.len + padding;

  /* pad end of buffer with 5-10 bytes */
  padding = (b % 6) + 5;
  if (RAND_bytes(&(buf.ptr[buf.len]), padding) != 1) {
    err = ERAND;
    goto end;
  }
  buf.len += padding;

  if (c & 1) {
    /* encrypt using cbc */
    buffer iv = buffer_init();
    *mode = AES_128_CBC;
    err = aes_random_bytes(&iv) ||
          aes_cbc_encrypt(dst, buf, key, iv);
    buffer_delete(iv);
  } else {
    /* encrypt using ecb */
    *mode = AES_128_ECB;
    err = aes_ecb_encrypt(dst, buf, key);
  }

end:
  buffer_delete(key);
  buffer_delete(buf);

  return err;
}

aes_mode_t aes_encrypt_detect(const buffer buf) {
  const unsigned char *block_a = &(buf.ptr[AES_BLOCK_SIZE]);
  const unsigned char *block_b = &(buf.ptr[AES_BLOCK_SIZE * 2]);
  return memcmp(block_a, block_b, AES_BLOCK_SIZE) == 0 ? AES_128_ECB
                                                       : AES_128_CBC;
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
  unsigned char *ptr = &(buf->ptr[buf->len - 1]);
  size_t padding = (size_t)*ptr;
  size_t len = buf->len - padding;
  unsigned char *end = &(buf->ptr[len]);

  while (--ptr >= end) {
    if (*ptr != padding) {
      return EAESPKCS7;
    }
  }

  /* a full resize could be expensive, so fake it */
  *end = '\0';
  buf->len = len;

  return 0;
}

error_t aes_rand(unsigned int *n) {
  error_t err;

  err = aes_seed_rand();
  if (err) {
    return err;
  }

  if (RAND_bytes((unsigned char *)n, sizeof(unsigned int)) != 1) {
    return ERAND;
  }

  return 0;
}

error_t aes_random_bytes(buffer *buf) {
  error_t err;

  err = buffer_alloc(buf, AES_BLOCK_SIZE) ||
        aes_seed_rand();
  if (err) {
    return err;
  }

  if (RAND_bytes(buf->ptr, buf->len) != 1) {
    return ERAND;
  }

  return 0;
}
