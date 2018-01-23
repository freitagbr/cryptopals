/* Copyright (c) 2018 Brandon Freitag <freitagbr@gmail.com> */

#include "cryptopals/error.h"
#include "cryptopals/hex.h"
#include "cryptopals/xor.h"

/**
 * Fixed XOR
 *
 * Write a function that takes two equal-length buffers and produces their
 * XOR combination.
 *
 * If your function works properly, then when you feed it the string:
 *
 * 1c0111001f010100061a024b53535009181c
 *
 * ... after hex decoding, and when XOR'd against:
 *
 * 686974207468652062756c6c277320657965
 *
 * ... should produce:
 *
 * 746865206b696420646f6e277420706c6179
 */

error_t challenge_02(buffer *dst, const buffer hex_a, const buffer hex_b) {
  buffer a = buffer_init();
  buffer b = buffer_init();
  error_t err;

  if (hex_a.len != hex_b.len) {
    return ESIZE;
  }

  err = hex_decode(&a, hex_a) ||
        hex_decode(&b, hex_b);
  if (err) {
    goto end;
  }

  if (a.len != b.len) {
    err = ESIZE;
    goto end;
  }

  err = xor_fixed(a, b) ||
        hex_encode(dst, a);

end:
  buffer_delete(a);
  buffer_delete(b);

  return err;
}

int main() {
  const char expected[] = "746865206b696420646f6e277420706c6179";
  const buffer input_a = buffer_new("1c0111001f010100061a024b53535009181c", 36);
  const buffer input_b = buffer_new("686974207468652062756c6c277320657965", 36);
  buffer output = buffer_init();
  error_t err;

  err = challenge_02(&output, input_a, input_b);
  if (err) {
    error(err);
    goto end;
  }

  error_expect(expected, (const char *)output.ptr);

end:
  buffer_delete(output);

  return (int)err;
}
