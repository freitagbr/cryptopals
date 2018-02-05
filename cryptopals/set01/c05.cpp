// Copyright (c) 2018 Brandon Freitag <freitagbr@gmail.com>

#include <exception>
#include <iostream>
#include <string>

#include <cstdlib>

#include "cryptopals/assert.hpp"
#include "cryptopals/error.hpp"
#include "cryptopals/hex.hpp"
#include "cryptopals/xor.hpp"

namespace cryptopals {

// Implement repeating-key XOR
//
// Here is the opening stanza of an important work of the English language:
//
// Burning 'em, if you ain't quick and nimble
// I go crazy when I hear a cymbal
//
// Encrypt it, under the key "ICE", using repeating-key XOR.
//
// In repeating-key XOR, you'll sequentially apply each byte of the key; the
// first byte of plaintext will be XOR'd against I, the next C, the next E,
// then I again for the 4th byte, and so on.
//
// It should come out to:
//
// 0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272
// a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f
//
// Encrypt a bunch of stuff using your repeating-key XOR function. Encrypt your
// mail. Encrypt your password file. Your .sig file. Get a feel for it. I
// promise, we aren't wasting your time with this.

std::string challenge_05(const std::string &src) {
  const std::string key("ICE");
  const std::string cipher = src ^ key;
  const std::string encoded = hex::encode(cipher);

  return encoded;
}

} // namespace cryptopals

int main() {
  const std::string input("Burning 'em, if you ain't quick and nimble\nI go "
                          "crazy when I hear a cymbal");
  const std::string expected("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623"
                             "d63343c2a26226324272765272a282b2f20430a652e2c652a"
                             "3124333a653e2b2027630c692b20283165286326302e27282"
                             "f");

  try {
    const std::string output = cryptopals::challenge_05(input);
    cryptopals::assert::equal(output, expected);
  } catch (std::exception &e) {
    std::cerr << e.what() << std::endl;
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}
