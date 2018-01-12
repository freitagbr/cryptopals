/* Copyright (c) 2018 Brandon Freitag <freitagbr@gmail.com> */

#include <stdio.h>

#include <openssl/err.h>
#include <openssl/evp.h>

#include "cryptopals/base64.h"
#include "cryptopals/buffer.h"
#include "cryptopals/error.h"
#include "cryptopals/file.h"
#include "cryptopals/xor.h"

/**
 * AES in ECB mode
 *
 * The Base64-encoded content in this file has been encrypted via AES-128 in ECB
 * mode under the key
 *
 * "YELLOW SUBMARINE".
 *
 * (case-sensitive, without the quotes; exactly 16 characters; I like "YELLOW
 * SUBMARINE" because it's exactly 16 bytes long, and now you do too).
 *
 * Decrypt it. You know the key, after all.
 *
 * Easiest way: use OpenSSL::Cipher and give it AES-128-ECB as the cipher.
 */

error_t challenge_10(const char *file, buffer *plaintext, const buffer key, const buffer iv) {
  buffer ciphertext = buffer_init();
  buffer cblock = buffer_init();
  buffer pblock = buffer_init();
  unsigned char *cptr = iv.ptr;
  EVP_CIPHER_CTX *ctx = NULL;
  size_t blocklen = key.len;
  size_t nblocks;
  size_t i;
  int len = 0;
  int remaining;
  error_t err;

  ERR_load_ERR_strings();
  ERR_load_crypto_strings();

  err = base64_decode_file(file, &ciphertext);
  if (err) {
    goto end;
  }

  ctx = EVP_CIPHER_CTX_new();
  if (ctx == NULL) {
    err = EMALLOC;
    goto end;
  }

  if (EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key.ptr, NULL) != 1) {
    err = EOPENSSL;
    fprintf(stderr, "EVP_DecryptInit_ex: %s\n",
        ERR_error_string(ERR_get_error(), NULL));
    goto end;
  }

  err = buffer_alloc(plaintext, ciphertext.len);
  if (err) {
    goto end;
  }

  err = buffer_alloc(&cblock, iv.len);
  if (err) {
    goto end;
  }

  nblocks = ciphertext.len / blocklen;

  for (i = 0; i < nblocks; i++) {
    const size_t offset = i * blocklen;
    memcpy(cblock.ptr, cptr, cblock.len);
    cptr = &(ciphertext.ptr[offset]);
    buffer_set(pblock, &(plaintext->ptr[offset]), cblock.len);
    if (EVP_DecryptUpdate(ctx, pblock.ptr, &len, cptr, cblock.len) != 1) {
      err = EOPENSSL;
      fprintf(stderr, "EVP_DecryptUpdate: %s\n",
          ERR_error_string(ERR_get_error(), NULL));
      goto end;
    }
    xor_fixed(pblock, cblock);
    plaintext->len += len;
  }

  len = plaintext->len;
  remaining = ciphertext.len - len;
  buffer_set(pblock, &(plaintext->ptr[len]), remaining);
  memcpy(cblock.ptr, cptr, remaining);

  if (EVP_DecryptFinal_ex(ctx, pblock.ptr, &len) != 1) {
    err = EOPENSSL;
    fprintf(stderr, "EVP_DecryptFinal_ex: %s\n",
        ERR_error_string(ERR_get_error(), NULL));
    goto end;
  }

  xor_fixed(pblock, cblock);
  plaintext->len += len;
  plaintext->ptr[plaintext->len] = '\0';

end:
  buffer_delete(ciphertext);
  buffer_delete(cblock);
  if (ctx != NULL) {
    EVP_CIPHER_CTX_free(ctx);
  }
  ERR_free_strings();

  return err;
}

int main() {
  const buffer key = buffer_new("YELLOW SUBMARINE", 16);
  const buffer iv = buffer_new("\x00\x00\x00\x00\x00\x00\x00\x00"
                               "\x00\x00\x00\x00\x00\x00\x00\x00", 16);
  buffer expected = buffer_init();
  buffer output = buffer_init();

  error_t err;

  err = file_read("data/c10_test.txt", &expected);
  if (err) {
    error(err);
    goto end;
  }

  err = challenge_10("data/c10.txt", &output, key, iv);
  if (err) {
    error(err);
    goto end;
  }

  error_expect((const char *)expected.ptr, (const char *)output.ptr);

end:
  buffer_delete(expected);
  buffer_delete(output);

  return (int)err;
}
