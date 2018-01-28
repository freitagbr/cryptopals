/* Copyright (c) 2018 Brandon Freitag <freitagbr@gmail.com> */

#include "cryptopals/aes.h"
#include "cryptopals/base64.h"
#include "cryptopals/string.h"
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

error_t challenge_07(const char *file, string *plaintext, const string key) {
  string ciphertext = string_init();
  error_t err;

  err = base64_decode_file(file, &ciphertext) ||
        aes_ecb_decrypt(plaintext, ciphertext, key);

  string_delete(ciphertext);

  return err;
}

int main() {
  const string key = string_new("YELLOW SUBMARINE", 16);
  string expected = string_init();
  string output = string_init();
  error_t err;

  err = file_read("data/c07_test.txt", &expected) ||
        challenge_07("data/c07.txt", &output, key);
  if (err) {
    error(err);
    goto end;
  }

  error_expect((const char *)expected.ptr, (const char *)output.ptr);

end:
  string_delete(expected);
  string_delete(output);

  return (int)err;
}
