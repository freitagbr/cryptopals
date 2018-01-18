/* Copyright (c) 2018 Brandon Freitag <freitagbr@gmail.com> */

#ifndef CRYPTOPALS_AES_H_
#define CRYPTOPALS_AES_H_

#include <openssl/aes.h>

#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "cryptopals/buffer.h"
#include "cryptopals/error.h"
#include "cryptopals/xor.h"

error_t aes_ecb_decrypt(buffer *dst, const buffer src, const buffer key);

error_t aes_ecb_encrypt(buffer *dst, const buffer src, const buffer key);

error_t aes_cbc_decrypt(buffer *dst, const buffer src, const buffer key,
                        const buffer iv);

error_t aes_cbc_encrypt(buffer *dst, const buffer src, const buffer key,
                        const buffer iv);

error_t aes_pkcs7_pad(buffer *buf, size_t len, size_t *padding);

error_t aes_pkcs7_strip(buffer *buf);

error_t aes_random_key(buffer *key);

#endif /* CRYPTOPALS_AES_H_ */
