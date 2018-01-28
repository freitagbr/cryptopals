/* Copyright (c) 2018 Brandon Freitag <freitagbr@gmail.com> */

#include "cryptopals/string.h"
#include "cryptopals/error.h"
#include "cryptopals/hex.h"
#include "cryptopals/xor.h"

/**
 * Implement repeating-key XOR
 *
 * Here is the opening stanza of an important work of the English language:
 *
 * Burning 'em, if you ain't quick and nimble
 * I go crazy when I hear a cymbal
 *
 * Encrypt it, under the key "ICE", using repeating-key XOR.
 *
 * In repeating-key XOR, you'll sequentially apply each byte of the key; the
 * first byte of plaintext will be XOR'd against I, the next C, the next E,
 * then I again for the 4th byte, and so on.
 *
 * It should come out to:
 *
 * 0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272
 * a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f
 *
 * Encrypt a bunch of stuff using your repeating-key XOR function. Encrypt your
 * mail. Encrypt your password file. Your .sig file. Get a feel for it. I
 * promise, we aren't wasting your time with this.
 */

error_t challenge_05(string *dst, const string src) {
  string tmp = string_init();
  string key = string_new("ICE", 3);
  error_t err;

  err = xor_repeating(&tmp, src, key) ||
        hex_encode(dst, tmp);

  string_delete(tmp);

  return err;
}

int main() {
  const char expected[] =
      "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623"
      "d63343c2a26226324272765272"
      "a282b2f20430a652e2c652a3124333a653e2b2027630c692b"
      "20283165286326302e27282f";
  const string input = string_new("Burning 'em, if you ain't quick and nimble\n"
                                  "I go crazy when I hear a cymbal",
                                  74);
  string output = string_init();
  error_t err;

  err = challenge_05(&output, input);
  if (err) {
    error(err);
    goto end;
  }

  error_expect(expected, (const char *)output.ptr);

end:
  string_delete(output);

  return (int)err;
}
