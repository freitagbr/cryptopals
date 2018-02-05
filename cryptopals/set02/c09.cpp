// Copyright (c) 2018 Brandon Freitag <freitagbr@gmail.com>

#include <exception>
#include <iostream>
#include <string>

#include <cstdlib>

#include "cryptopals/aes.hpp"
#include "cryptopals/assert.hpp"

namespace cryptopals {

// Implement PKCS#7 padding
//
// A block cipher transforms a fixed-sized block (usually 8 or 16 bytes) of
// plaintext into ciphertext. But we almost never want to transform a single
// block; we encrypt irregularly-sized messages.
//
// One way we account for irregularly-sized messages is by padding, creating a
// plaintext that is an even multiple of the blocksize. The most popular
// padding scheme is called PKCS#7.
//
// So: pad any block to a specific block length, by appending the number of
// bytes of padding to the end of the block. For instance,
//
// "YELLOW SUBMARINE"
//
// ... padded to 20 bytes would be:
//
// "YELLOW SUBMARINE\x04\x04\x04\x04"

std::string challenge_09(const std::string &src, const size_t len) {
  std::string dst = src;
  aes::pkcs7::pad(dst, dst.length(), len);
  return dst;
}

} // namespace cryptopals

int main() {
  const std::string input("YELLOW SUBMARINE");
  const std::string expected("YELLOW SUBMARINE\x04\x04\x04\04");

  try {
    const std::string output = cryptopals::challenge_09(input, 20);
    cryptopals::assert::equal(output, expected);
  } catch (std::exception &e) {
    std::cerr << e.what() << std::endl;
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}
