/* Copyright (c) 2018 Brandon Freitag <freitagbr@gmail.com> */

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

#include "cryptopals/base64.h"
#include "cryptopals/buffer.h"
#include "cryptopals/error.h"
#include "cryptopals/hex.h"

/**
 * Convert hex to base64
 *
 * The string:
 *
 * 49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d
 *
 * Should produce:
 *
 * SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t
 *
 * So go ahead and make that happen. You'll need to use this code for the rest
 * of the exercises.
 */

error_t challenge_01(buffer *dst, const buffer src) {
  buffer hex = buffer_init();
  error_t err;

  err = hex_decode(&hex, src);
  if (err) {
    goto end;
  }

  err = base64_encode(dst, hex);
  if (err) {
    goto end;
  }

end:
  buffer_delete(hex);

  return err;
}

int main() {
  const unsigned char expected[] =
      "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
  const buffer input =
      buffer_new("49276d206b696c6c696e6720796f757220627261696e206c696b652061207"
                 "06f69736f6e6f7573206d757368726f6f6d",
                 96);
  buffer output = buffer_init();
  error_t err;

  err = challenge_01(&output, input);
  if (err) {
    error(err);
    goto end;
  }

  error_expect((const char *)expected, (const char *)output.ptr);

end:
  buffer_delete(output);

  return (int)err;
}
