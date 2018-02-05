// Copyright (c) 2018 Brandon Freitag <freitagbr@gmail.com>

#include <exception>
#include <fstream>
#include <iostream>
#include <streambuf>
#include <string>

#include <cstdlib>

#include "cryptopals/assert.hpp"
#include "cryptopals/base64.hpp"
#include "cryptopals/block.hpp"
#include "cryptopals/xor.hpp"

#define MAX_KEYSIZE 40

namespace cryptopals {

// Break repeating-key XOR
//
// There's a file here. It's been base64'd after being encrypted with
// repeating-key XOR.
//
// Decrypt it.
//
// Here's how:
//
// 1. Let KEYSIZE be the guessed length of the key; try values from 2 to (say)
//    40.
//
// 2. Write a function to compute the edit distance/Hamming distance between two
//    strings. The Hamming distance is just the number of differing bits. The
//    distance between:
//
//    this is a test
//
//    and
//
//    wokka wokka!!!
//
//    is 37. Make sure your code agrees before you proceed.
//
// 3. For each KEYSIZE, take the first KEYSIZE worth of bytes, and the second
//    KEYSIZE worth of bytes, and find the edit distance between them. Normalize
//    this result by dividing by KEYSIZE.
//
// 4. The KEYSIZE with the smallest normalized edit distance is probably the
//    key. You could proceed perhaps with the smallest 2-3 KEYSIZE values. Or
//    take 4 KEYSIZE blocks instead of 2 and average the distances.
//
// 5. Now that you probably know the KEYSIZE: break the ciphertext into blocks
//    of KEYSIZE length.
//
// 6. Now transpose the blocks: make a block that is the first byte of every
//    block, and a block that is the second byte of every block, and so on.
//
// 7. Solve each block as if it was single-character XOR. You already have code
//    to do this.
//
// 8. For each block, the single-byte XOR key that produces the best looking
//    histogram is the repeating-key XOR key byte for that block. Put them
//    together and you have the key.
//
// This code is going to turn out to be surprisingly useful later on. Breaking
// repeating-key XOR ("Vigenere") statistically is obviously an academic
// exercise, a "Crypto 101" thing. But more people "know how" to break it than
// can actually break it, and a similar technique breaks something much more
// important.

std::string challenge_06(const char *file) {
  const std::string cipher = base64::decode_file(file);
  const std::string key = block::transpose_get_key(cipher, MAX_KEYSIZE);
  const std::string plain = cipher ^ key;

  return plain;
}

} // namespace cryptopals

int main() {
  try {
    std::ifstream f("data/c06_test.txt");
    const std::string expected((std::istreambuf_iterator<char>(f)),
                               std::istreambuf_iterator<char>());
    const std::string output = cryptopals::challenge_06("data/c06.txt");
    cryptopals::assert::equal(output, expected);
  } catch (std::exception &e) {
    std::cerr << e.what() << std::endl;
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}
