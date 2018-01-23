/* Copyright (c) 2018 Brandon Freitag <freitagbr@gmail.com> */

#include <stdio.h>

#include "cryptopals/aes.h"
#include "cryptopals/buffer.h"
#include "cryptopals/error.h"

/**
 * An ECB/CBC detection oracle
 *
 * Now that you have ECB and CBC working:
 *
 * Write a function to generate a random AES key; that's just 16 random bytes.
 *
 * Write a function that encrypts data under an unknown key --- that is, a
 * function that generates a random key and encrypts under it.
 *
 * The function should look like:
 *
 * encryption_oracle(your-input)
 * => [MEANINGLESS JIBBER JABBER]
 *
 * Under the hood, have the function append 5-10 bytes (count chosen randomly)
 * before the plaintext and 5-10 bytes after the plaintext.
 *
 * Now, have the function choose to encrypt under ECB 1/2 the time, and under
 * CBC the other half (just use random IVs each time for CBC). Use rand(2) to
 * decide which to use.
 *
 * Detect the block cipher mode the function is using each time. You should end
 * up with a piece of code that, pointed at a block box that might be
 * encrypting ECB or CBC, tells you which one is happening.
 */

error_t challenge_11(aes_mode_t *mode, aes_mode_t *guess) {
  buffer src = buffer_new("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 43);
  buffer enc = buffer_init();
  error_t err;

  err = aes_encrypt_oracle(&enc, src, mode);
  if (err) {
    goto end;
  }

  *guess = aes_encrypt_detect(enc);

end:
  buffer_delete(enc);

  return 0;
}

int main() {
  aes_mode_t mode;
  aes_mode_t guess;
  error_t err;

  err = challenge_11(&mode, &guess);
  if (err) {
    error(err);
    return err;
  }

  if (mode != guess) {
    char ecb[12] = "aes-128-ecb";
    char cbc[12] = "aes-128-cbc";
    char *expected;
    char *result;
    switch (mode) {
    case AES_128_ECB:
      expected = ecb;
      break;
    case AES_128_CBC:
      expected = cbc;
      break;
    default:
      return 1;
    }
    switch (guess) {
    case AES_128_ECB:
      result = ecb;
      break;
    case AES_128_CBC:
      result = cbc;
      break;
    default:
      return 1;
    }
    fprintf(stderr, "Expected %s, got %s\n", expected, result);
    return 1;
  }

  return 0;
}
