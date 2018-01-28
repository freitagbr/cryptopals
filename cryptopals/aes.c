/* Copyright (c) 2018 Brandon Freitag <freitagbr@gmail.com> */

#include "cryptopals/aes.h"

#include <string.h>

#include <openssl/aes.h>
#include <openssl/rand.h>

#include "cryptopals/string.h"
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

error_t aes_ecb_decrypt(string *dst, const string src, const string key) {
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

  err = string_alloc(dst, src.len);
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

error_t aes_ecb_encrypt(string *dst, const string src, const string key) {
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

error_t aes_cbc_decrypt(string *dst, const string src, const string key,
                        const string iv) {
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

  err = string_alloc(dst, src.len);
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

error_t aes_cbc_encrypt(string *dst, const string src, const string key,
                        const string iv) {
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

error_t aes_encrypt_oracle(string *dst, const string src, aes_mode_t *mode) {
  string key = string_init();
  string str = string_init();
  unsigned int a = 0;
  unsigned int b = 0;
  unsigned int c = 0;
  size_t padding;
  error_t err;

  err = string_alloc(&str, src.len + 20) ||
        aes_random_bytes(&key) ||
        aes_rand(&a) ||
        aes_rand(&b) ||
        aes_rand(&c);
  if (err) {
    goto end;
  }

  /* pad beginning of string with 5-10 bytes */
  padding = (a % 6) + 5;
  if (RAND_bytes(str.ptr, padding) != 1) {
    err = ERAND;
    goto end;
  }
  memcpy(&(str.ptr[padding]), src.ptr, src.len);
  str.len = src.len + padding;

  /* pad end of string with 5-10 bytes */
  padding = (b % 6) + 5;
  if (RAND_bytes(&(str.ptr[str.len]), padding) != 1) {
    err = ERAND;
    goto end;
  }
  str.len += padding;

  if (c & 1) {
    /* encrypt using cbc */
    string iv = string_init();
    *mode = AES_128_CBC;
    err = aes_random_bytes(&iv) ||
          aes_cbc_encrypt(dst, str, key, iv);
    string_delete(iv);
  } else {
    /* encrypt using ecb */
    *mode = AES_128_ECB;
    err = aes_ecb_encrypt(dst, str, key);
  }

end:
  string_delete(key);
  string_delete(str);

  return err;
}

aes_mode_t aes_encrypt_detect(const string str) {
  const unsigned char *block_a = &(str.ptr[AES_BLOCK_SIZE]);
  const unsigned char *block_b = &(str.ptr[AES_BLOCK_SIZE * 2]);
  return memcmp(block_a, block_b, AES_BLOCK_SIZE) == 0 ? AES_128_ECB
                                                       : AES_128_CBC;
}

error_t aes_pkcs7_pad(string *str, size_t len, size_t *padding) {
  size_t slen = len + (AES_BLOCK_SIZE - (len % AES_BLOCK_SIZE));
  error_t err;

  err = string_alloc(str, slen);
  if (err) {
    return err;
  }

  *padding = slen - len;

  if (*padding > AES_BLOCK_SIZE) {
    return ESIZE;
  }

  if (*padding) {
    memset(&(str->ptr[str->len - *padding]), (int)*padding, *padding);
  }

  return 0;
}

error_t aes_pkcs7_strip(string *str) {
  unsigned char *ptr = &(str->ptr[str->len - 1]);
  size_t padding = (size_t)*ptr;
  size_t len = str->len - padding;
  unsigned char *end = &(str->ptr[len]);

  while (--ptr >= end) {
    if (*ptr != padding) {
      return EAESPKCS7;
    }
  }

  /* a full resize could be expensive, so fake it */
  *end = '\0';
  str->len = len;

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

error_t aes_random_bytes(string *str) {
  error_t err;

  err = string_alloc(str, AES_BLOCK_SIZE) ||
        aes_seed_rand();
  if (err) {
    return err;
  }

  if (RAND_bytes(str->ptr, str->len) != 1) {
    return ERAND;
  }

  return 0;
}
