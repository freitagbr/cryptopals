// Copyright (c) 2018 Brandon Freitag <freitagbr@gmail.com>

#include <exception>
#include <fstream>
#include <iostream>
#include <string>

#include <cstdlib>

#include "cryptopals/assert.hpp"
#include "cryptopals/error.hpp"
#include "cryptopals/hex.hpp"
#include "cryptopals/xor.hpp"

namespace cryptopals {

// Detect single-character XOR
//
// One of the 60-character strings in this file has been encrypted by single-
// character XOR.
//
// Find it.
//
// (Your code from #3 should help.)

std::string challenge_04(const char *file) {
  std::ifstream f(file);
  std::string line;
  std::string plain;
  int global_max = 0;

  while (std::getline(f, line)) {
    int local_max = 0;
    const std::string cipher = hex::decode(line);
    const unsigned char key = xor_::find_key(cipher, local_max);

    if (local_max > global_max) {
      global_max = local_max;
      plain = cipher ^ key;
    }
  }

  return plain;
}

} // namespace cryptopals

int main() {
  const std::string expected("Now that the party is jumping\n");

  try {
    const std::string output = cryptopals::challenge_04("data/c04.txt");
    cryptopals::assert::equal(output, expected);
  } catch (std::exception &e) {
    std::cerr << e.what() << std::endl;
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}
