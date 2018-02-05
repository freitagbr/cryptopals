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

// Single-byte XOR cipher
// The hex encoded string:
//
// 1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736
//
// ... has been XOR'd against a single character. Find the key, decrypt the
// message.
//
// You can do this by hand. But don't: write code to do it for you.
//
// How? Devise some method for "scoring" a piece of English plaintext.
// Character frequency is a good metric. Evaluate each output and choose the
// one with the best score.

std::string challenge_03(const std::string &src) {
  const std::string cipher = hex::decode(src);
  const unsigned char key = xor_::find_key(cipher);
  const std::string decoded = cipher ^ key;

  return decoded;
}

} // namespace cryptopals

int main() {
  const std::string input(
      "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");
  const std::string expected("Cooking MC's like a pound of bacon");

  try {
    const std::string output = cryptopals::challenge_03(input);
    cryptopals::assert::equal(output, expected);
  } catch (std::exception &e) {
    std::cerr << e.what() << std::endl;
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}
