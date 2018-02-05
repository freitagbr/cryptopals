// Copyright (c) 2018 Brandon Freitag <freitagbr@gmail.com>

#include <exception>
#include <iostream>
#include <string>

#include <cstdlib>

#include "cryptopals/aes.hpp"
#include "cryptopals/assert.hpp"

namespace cryptopals {

// PKCS#7 padding validation
//
// Write a function that takes a plaintext, determines if it has valid PKCS#7
// padding, and strips the padding off.
//
// The string:
//
// "ICE ICE BABY\x04\x04\x04\x04"
//
// ... has valid padding, and produces the result "ICE ICE BABY".
//
// The string:
//
// "ICE ICE BABY\x05\x05\x05\x05"
//
// ... does not have valid padding, nor does:
//
// "ICE ICE BABY\x01\x02\x03\x04"
//
// If you are writing in a language with exceptions, like Python or Ruby, make
// your function throw an exception on bad padding.
//
// Crypto nerds know where we're going with this. Bear with us.

void challenge_15(std::string &str) { aes::pkcs7::strip(str); }

} // namespace cryptopals

int main() {
  std::string a("ICE ICE BABY\x04\x04\x04\x04");
  std::string b("ICE ICE BABY\x05\x05\x05\x05");
  std::string c("ICE ICE BABY\x01\x02\x03\x04");
  const std::string expected("ICE ICE BABY");
  bool failed = false;

  try {
    // valid PKCS7 padding
    cryptopals::challenge_15(a);
    cryptopals::assert::equal(a, expected);
  } catch (std::exception &e) {
    std::cerr << e.what() << std::endl;
    failed = true;
  }

  try {
    cryptopals::challenge_15(b);
    std::cerr << "Expected invalid padding in string" << std::endl;
    failed = true;
  } catch (std::exception &e) {
  }

  try {
    cryptopals::challenge_15(c);
    std::cerr << "Expected invalid padding in string" << std::endl;
    failed = true;
  } catch (std::exception &e) {
  }

  return failed ? EXIT_FAILURE : EXIT_SUCCESS;
}
