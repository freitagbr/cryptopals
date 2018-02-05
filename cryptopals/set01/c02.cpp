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

// Fixed XOR
//
// Write a function that takes two equal-length strings and produces their
// XOR combination.
//
// If your function works properly, then when you feed it the string:
//
// 1c0111001f010100061a024b53535009181c
//
// ... after hex decoding, and when XOR'd against:
//
// 686974207468652062756c6c277320657965
//
// ... should produce:
//
// 746865206b696420646f6e277420706c6179

std::string challenge_02(const std::string &hex_a, const std::string &hex_b) {
  const std::string a = hex::decode(hex_a);
  const std::string b = hex::decode(hex_b);

  if (a.length() != b.length()) {
    throw error::Error("Strings are not the same length");
  }

  const std::string xord = a ^ b;
  const std::string encoded = hex::encode(xord);

  return encoded;
}

} // namespace cryptopals

int main() {
  const std::string input_a("1c0111001f010100061a024b53535009181c");
  const std::string input_b("686974207468652062756c6c277320657965");
  const std::string expected("746865206b696420646f6e277420706c6179");

  try {
    const std::string output = cryptopals::challenge_02(input_a, input_b);
    cryptopals::assert::equal(output, expected);
  } catch (std::exception &e) {
    std::cerr << e.what() << std::endl;
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}
