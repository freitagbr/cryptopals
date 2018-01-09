#include <stddef.h>
#include <stdlib.h>

#include "cryptopals/buffer.h"
#include "cryptopals/error.h"
#include "cryptopals/pad.h"

#define IV 0x04

/**
 * Implement PKCS#7 padding
 *
 * A block cipher transforms a fixed-sized block (usually 8 or 16 bytes) of
 * plaintext into ciphertext. But we almost never want to transform a single
 * block; we encrypt irregularly-sized messages.
 *
 * One way we account for irregularly-sized messages is by padding, creating a
 * plaintext that is an even multiple of the blocksize. The most popular
 * padding scheme is called PKCS#7.
 *
 * So: pad any block to a specific block length, by appending the number of
 * bytes of padding to the end of the block. For instance,
 *
 * "YELLOW SUBMARINE"
 *
 * ... padded to 20 bytes would be:
 *
 * "YELLOW SUBMARINE\x04\x04\x04\x04"
 */

error_t challenge_09(buffer *dst, const buffer src, const size_t len) {
  return pad_bytes(dst, src, len, IV);
}

int main() {
  const unsigned char expected[] = "YELLOW SUBMARINE\x04\x04\x04\04";
  const buffer input = buffer_new("YELLOW SUBMARINE", 16);
  buffer output = buffer_init();
  error_t err;

  err = challenge_09(&output, input, 20);
  if (err) {
    error(err);
    goto end;
  }

  error_expect((const char *)expected, (const char *)output.ptr);

end:
  buffer_delete(output);

  return (int)err;
}
