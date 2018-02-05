// Copyright (c) 2018 Brandon Freitag <freitagbr@gmail.com>

#include <exception>
#include <fstream>
#include <iostream>
#include <streambuf>
#include <string>

#include <cstdlib>

#include "cryptopals/aes.hpp"
#include "cryptopals/assert.hpp"
#include "cryptopals/base64.hpp"

namespace cryptopals {

// AES in ECB mode
//
// The Base64-encoded content in this file has been encrypted via AES-128 in ECB
// mode under the key
//
// "YELLOW SUBMARINE".
//
// (case-sensitive, without the quotes; exactly 16 characters; I like "YELLOW
// SUBMARINE" because it's exactly 16 bytes long, and now you do too).
//
// Decrypt it. You know the key, after all.
//
// Easiest way: use OpenSSL::Cipher and give it AES-128-ECB as the cipher.

std::string challenge_07(const char *file, const std::string &key) {
  const std::string cipher = base64::decode_file(file);
  const std::string plain = aes::ecb::decrypt(cipher, key);

  return plain;
}

} // namespace cryptopals

int main() {
  const std::string key("YELLOW SUBMARINE");

  try {
    std::ifstream f("data/c07_test.txt");
    const std::string expected((std::istreambuf_iterator<char>(f)),
                               std::istreambuf_iterator<char>());
    const std::string output = cryptopals::challenge_07("data/c07.txt", key);
    cryptopals::assert::equal(output, expected);
  } catch (std::exception &e) {
    std::cerr << e.what() << std::endl;
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}
