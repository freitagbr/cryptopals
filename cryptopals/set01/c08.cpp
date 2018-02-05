// Copyright (c) 2018 Brandon Freitag <freitagbr@gmail.com>

#include <exception>
#include <fstream>
#include <iostream>
#include <string>

#include <cfloat>
#include <cstdlib>

#include "cryptopals/assert.hpp"
#include "cryptopals/block.hpp"
#include "cryptopals/hex.hpp"

namespace cryptopals {

// Detect AES in ECB mode
//
// In this file are a bunch of hex-encoded ciphertexts.
//
// One of them has been encrypted with ECB.
//
// Detect it.
//
// Remember that the problem with ECB is that it is stateless and
// deterministic; the same 16 byte plaintext block will always produce the same
// 16 byte ciphertext.

std::string challenge_08(const char *file) {
  std::ifstream f(file);
  std::string line;
  std::string cipher;
  float global_min_dist = FLT_MAX;

  while (std::getline(f, line)) {
    const std::string decoded = hex::decode(line);
    const size_t local_max_keysize = line.length() / 2;
    float local_min_dist = 0.0;

    block::keysize(decoded, local_min_dist, local_max_keysize);

    if (local_min_dist < global_min_dist) {
      global_min_dist = local_min_dist;
      cipher = line;
    }
  }

  return cipher;
}

} // namespace cryptopals

int main() {
  const std::string expected(
      "d880619740a8a19b7840a8a31c810a3d08649af70"
      "dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4"
      "fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d"
      "69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744"
      "cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a");

  try {
    const std::string output = cryptopals::challenge_08("data/c08.txt");
    cryptopals::assert::equal(output, expected);
    cryptopals::assert::equal(output.length(), 320UL);
  } catch (std::exception &e) {
    std::cerr << e.what() << std::endl;
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}
