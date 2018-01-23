/* Copyright (c) 2018 Brandon Freitag <freitagbr@gmail.com> */

#include <stdio.h>
#include <string.h>

#include "cryptopals/aes.h"
#include "cryptopals/buffer.h"
#include "cryptopals/error.h"

/**
 * PKCS#7 padding validation
 *
 * Write a function that takes a plaintext, determines if it has valid PKCS#7
 * padding, and strips the padding off.
 *
 * The string:
 *
 * "ICE ICE BABY\x04\x04\x04\x04"
 *
 * ... has valid padding, and produces the result "ICE ICE BABY".
 *
 * The string:
 *
 * "ICE ICE BABY\x05\x05\x05\x05"
 *
 * ... does not have valid padding, nor does:
 *
 * "ICE ICE BABY\x01\x02\x03\x04"
 *
 * If you are writing in a language with exceptions, like Python or Ruby, make
 * your function throw an exception on bad padding.
 *
 * Crypto nerds know where we're going with this. Bear with us.
 */

error_t challenge_15(buffer *buf) {
  return aes_pkcs7_strip(buf);
}

int main() {
  const char expected[] = "ICE ICE BABY";
  buffer a = buffer_init();
  buffer b = buffer_init();
  buffer c = buffer_init();
  error_t err;

  /* avoid writing to read-only memory */
  err = buffer_alloc(&a, 16) ||
        buffer_alloc(&b, 16) ||
        buffer_alloc(&c, 16);
  if (err) {
    error(err);
    goto end;
  }
  memcpy(a.ptr, "ICE ICE BABY\x04\x04\x04\x04", 16);
  memcpy(b.ptr, "ICE ICE BABY\x05\x05\x05\x05", 16);
  memcpy(c.ptr, "ICE ICE BABY\x01\x02\x03\x04", 16);

  err = challenge_15(&a);
  if (err) {
    error(err);
    goto end;
  }

  error_expect(expected, (const char *)a.ptr);

  if (challenge_15(&b) != EAESPKCS7) {
    error_log("Expected invalid padding in buffer");
    err = 1;
    goto end;
  }

  if (challenge_15(&c) != EAESPKCS7) {
    error_log("Expected invalid padding in buffer");
    err = 1;
  }

end:
  buffer_delete(a);
  buffer_delete(b);
  buffer_delete(c);

  return (int)err;
}
