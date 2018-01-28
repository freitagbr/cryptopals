/* Copyright (c) 2018 Brandon Freitag <freitagbr@gmail.com> */

#include "cryptopals/string.h"
#include "cryptopals/error.h"
#include "cryptopals/hex.h"
#include "cryptopals/xor.h"

/**
 * Single-byte XOR cipher
 * The hex encoded string:
 *
 * 1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736
 *
 * ... has been XOR'd against a single character. Find the key, decrypt the
 * message.
 *
 * You can do this by hand. But don't: write code to do it for you.
 *
 * How? Devise some method for "scoring" a piece of English plaintext.
 * Character frequency is a good metric. Evaluate each output and choose the
 * one with the best score.
 */

error_t challenge_03(string *dst, const string src) {
  string hex = string_init();
  unsigned char key;
  int max_score = 0;
  error_t err;

  err = hex_decode(&hex, src);
  if (err) {
    goto end;
  }

  key = xor_find_cipher(hex, &max_score);
  err = xor_single_byte(dst, hex, key);

end:
  string_delete(hex);

  return err;
}

int main() {
  const char expected[] = "Cooking MC's like a pound of bacon";
  const string input = string_new(
      "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736",
      68);
  string output = string_init();
  error_t err;

  err = challenge_03(&output, input);
  if (err) {
    error(err);
    goto end;
  }

  error_expect(expected, (const char *)output.ptr);

end:
  string_delete(output);

  return (int)err;
}
