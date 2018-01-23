/* Copyright (c) 2018 Brandon Freitag <freitagbr@gmail.com> */

#ifndef CRYPTOPALS_AES_H_
#define CRYPTOPALS_AES_H_

#include <string.h>
#include <time.h>

#include <openssl/aes.h>
#include <openssl/rand.h>

#include "cryptopals/buffer.h"
#include "cryptopals/error.h"
#include "cryptopals/xor.h"

#define AES_RAND_SOURCE "/dev/urandom"
#define AES_RAND_SIZE 32

typedef enum {
  AES_128_ECB = 0, /* aes-128-ecb */
  AES_128_CBC      /* aes-128-cbc */
} aes_mode_t;

error_t aes_ecb_decrypt(buffer *dst, const buffer src, const buffer key);

error_t aes_ecb_encrypt(buffer *dst, const buffer src, const buffer key);

error_t aes_cbc_decrypt(buffer *dst, const buffer src, const buffer key,
                        const buffer iv);

error_t aes_cbc_encrypt(buffer *dst, const buffer src, const buffer key,
                        const buffer iv);

error_t aes_encrypt_oracle(buffer *dst, const buffer src, aes_mode_t *mode);

aes_mode_t aes_encrypt_detect(const buffer buf);

error_t aes_pkcs7_pad(buffer *buf, size_t len, size_t *padding);

error_t aes_pkcs7_strip(buffer *buf);

error_t aes_rand(unsigned int *n);

error_t aes_random_bytes(buffer *buf);

#endif /* CRYPTOPALS_AES_H_ */
