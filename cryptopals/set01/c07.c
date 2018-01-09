#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <openssl/err.h>
#include <openssl/evp.h>

#include "cryptopals/base64.h"
#include "cryptopals/buffer.h"
#include "cryptopals/error.h"
#include "cryptopals/file.h"

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

error_t challenge_07(const char *file, buffer *plaintext, const buffer key) {
  ERR_load_ERR_strings();
  ERR_load_crypto_strings();
  EVP_CIPHER_CTX *ctx = NULL;
  buffer ciphertext = buffer_init();
  int len = 0;
  error_t err = 0;

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

  uint8_t *p = plaintext->ptr;

  if (EVP_DecryptUpdate(ctx, p, &len, ciphertext.ptr, ciphertext.len) != 1) {
    err = EOPENSSL;
    fprintf(stderr, "EVP_DecryptUpdate: %s\n",
            ERR_error_string(ERR_get_error(), NULL));
    goto end;
  }

  plaintext->len = len;

  if (EVP_DecryptFinal_ex(ctx, &(p[len]), &len) != 1) {
    err = EOPENSSL;
    fprintf(stderr, "EVP_DecryptFinal_ex: %s\n",
            ERR_error_string(ERR_get_error(), NULL));
    goto end;
  }

  plaintext->len += len;
  p[plaintext->len] = '\0';

end:
  buffer_delete(ciphertext);
  if (ctx != NULL) {
    EVP_CIPHER_CTX_free(ctx);
  }
  ERR_free_strings();

  return err;
}

int main() {
  buffer expected = buffer_init();
  const buffer key = buffer_new("YELLOW SUBMARINE", 16);
  buffer output = buffer_init();
  error_t err = 0;

  err = file_read("data/c07_test.txt", &expected);
  if (err) {
    error(err);
    goto end;
  }

  err = challenge_07("data/c07.txt", &output, key);
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
