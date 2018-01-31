/* Copyright (c) 2018 Brandon Freitag <freitagbr@gmail.com> */

#ifndef CRYPTOPALS_AES_H_
#define CRYPTOPALS_AES_H_

#include "cryptopals/error.h"
#include "cryptopals/string.h"

#define AES_RAND_SOURCE "/dev/urandom"
#define AES_RAND_SIZE 32

typedef enum {
  AES_128_ECB = 1, /* aes-128-ecb */
  AES_128_CBC      /* aes-128-cbc */
} aes_mode_t;

error_t aes_ecb_decrypt(string *dst, const string src, const string key);

error_t aes_ecb_encrypt(string *dst, const string src, const string key);

error_t aes_cbc_decrypt(string *dst, const string src, const string key,
                        const string iv);

error_t aes_cbc_encrypt(string *dst, const string src, const string key,
                        const string iv);

error_t aes_encrypt_oracle(string *dst, const string src, aes_mode_t *mode);

aes_mode_t aes_encrypt_detect(const string str);

error_t aes_pkcs7_pad(string *str, size_t len, size_t *padding);

error_t aes_pkcs7_strip(string *str);

error_t aes_rand(unsigned int *n);

error_t aes_random_nbytes(string *str, size_t len);

error_t aes_random_bytes(string *str);

#endif /* CRYPTOPALS_AES_H_ */
