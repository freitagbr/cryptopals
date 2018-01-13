/* Copyright (c) 2018 Brandon Freitag <freitagbr@gmail.com> */

#ifndef CRYPTOPALS_AES_H_
#define CRYPTOPALS_AES_H_

#include <openssl/aes.h>

#include <stdio.h>

#include "cryptopals/buffer.h"
#include "cryptopals/error.h"
#include "cryptopals/xor.h"

error_t aes_ecb_decrypt(buffer *dec, const buffer enc, const buffer key);

error_t aes_cbc_decrypt(buffer *dec, const buffer enc, const buffer key, const buffer iv);

error_t aes_pkcs7_strip(buffer *buf);

#endif /* CRYPTOPALS_AES_H_ */
