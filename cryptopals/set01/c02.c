/* Copyright (c) 2018 Brandon Freitag <freitagbr@gmail.com> */

#include "cryptopals/error.h"
#include "cryptopals/hex.h"
#include "cryptopals/xor.h"

/**
 * Fixed XOR
 *
 * Write a function that takes two equal-length strings and produces their
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

error_t challenge_02(string *dst, const string hex_a, const string hex_b) {
  string a = string_init();
  string b = string_init();
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
  string_delete(a);
  string_delete(b);

  return err;
}

int main() {
  const char expected[] = "746865206b696420646f6e277420706c6179";
  const string input_a = string_new("1c0111001f010100061a024b53535009181c", 36);
  const string input_b = string_new("686974207468652062756c6c277320657965", 36);
  string output = string_init();
  error_t err;

  err = challenge_02(&output, input_a, input_b);
  if (err) {
    error(err);
    goto end;
  }

  error_expect(expected, (const char *)output.ptr);

end:
  string_delete(output);

  return (int)err;
}
