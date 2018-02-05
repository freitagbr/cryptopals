// Copyright (c) 2018 Brandon Freitag <freitagbr@gmail.com>

#include <exception>
#include <iostream>
#include <string>

#include <cstdlib>

#include "cryptopals/assert.hpp"
#include "cryptopals/base64.hpp"
#include "cryptopals/error.hpp"
#include "cryptopals/hex.hpp"

namespace cryptopals {

// Convert hex to base64
//
// The string:
//
// 49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d
//
// Should produce:
//
// SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t
//
// So go ahead and make that happen. You'll need to use this code for the rest
// of the exercises.

std::string challenge_01(const std::string &src) {
  const std::string hexstr = hex::decode(src);
  return base64::encode(hexstr);
}

} // namespace cryptopals

int main() {
  const std::string input("49276d206b696c6c696e6720796f757220627261696e206c696b"
                          "65206120706f69736f6e6f7573206d757368726f6f6d");
  const std::string expected(
      "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t");

  try {
    const std::string output = cryptopals::challenge_01(input);
    cryptopals::assert::equal(output, expected);
  } catch (std::exception &e) {
    std::cerr << e.what() << std::endl;
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}
