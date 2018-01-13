/* Copyright (c) 2018 Brandon Freitag <freitagbr@gmail.com> */

#include "cryptopals/aes.h"
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

error_t challenge_10(const char *file, buffer *plaintext, const buffer key,
                     const buffer iv) {
  buffer ciphertext = buffer_init();
  error_t err;

  err = base64_decode_file(file, &ciphertext);
  if (err) {
    goto end;
  }

  err = aes_cbc_decrypt(plaintext, ciphertext, key, iv);
  if (err) {
    goto end;
  }

end:
  buffer_delete(ciphertext);

  return err;
}

int main() {
  const buffer key = buffer_new("YELLOW SUBMARINE", 16);
  const buffer iv = buffer_new("\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 16);
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
