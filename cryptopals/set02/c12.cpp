// Copyright (c) 2018 Brandon Freitag <freitagbr@gmail.com>

#include <algorithm>
#include <exception>
#include <fstream>
#include <iostream>
#include <streambuf>
#include <string>

#include <climits>
#include <cstdlib>

#include "cryptopals/aes.hpp"
#include "cryptopals/assert.hpp"
#include "cryptopals/base64.hpp"
#include "cryptopals/error.hpp"

#define CHAR 'a' // this value is arbitrary

namespace cryptopals {

static std::string encrypt_oracle(const std::string &src) {
  static bool init = false;
  static std::string b64(
      "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
      "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
      "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
      "YnkK");
  static std::string txt;
  static std::string key;

  if (!init) {
    txt = base64::decode(b64);
    key = aes::rand::bytes();
    init = true;
  }

  const std::string plain = src + txt;
  const std::string cipher = aes::ecb::encrypt(plain, key);

  return cipher;
}

// Byte-at-a-time ECB decryption (Simple)
//
// Copy your oracle function to a new function that encrypts strings under ECB
// mode using a consistent but unknown key (for instance, assign a single
// random key, once, to a global variable).
//
// Now take that same function and have it append to the plaintext, BEFORE
// ENCRYPTING, the following string:
//
// Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
// aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
// dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg YnkK
//
// Base64 decode the string before appending it. Do not base64 decode the
// string by hand; make your code do it. The point is that you don't know its
// contents.
//
// What you have now is a function that produces:
//
// AES-128-ECB(your-string || unknown-string, random-key)
//
// It turns out: you can decrypt "unknown-string" with repeated calls to the
// oracle function!
//
// Here's roughly how:
//
// 1. Feed identical bytes of your-string to the function 1 at a time --- start
//    with 1 byte ("A"), then "AA", then "AAA" and so on. Discover the block
//    size of the cipher. You know it, but do this step anyway.
// 2. Detect that the function is using ECB. You already know, but do this step
//    anyways.
// 3. Knowing the block size, craft an input block that is exactly 1 byte short
//    (for instance, if the block size is 8 bytes, make "AAAAAAA"). Think about
//    what the oracle function is going to put in that last byte position.
// 4. Make a dictionary of every possible last byte by feeding different strings
//    to the oracle; for instance, "AAAAAAAA", "AAAAAAAB", "AAAAAAAC",
//    remembering the first block of each invocation.
// 5. Match the output of the one-byte-short input to one of the entries in your
//    dictionary. You've now discovered the first byte of unknown-string.
// 6. Repeat for the next byte.

std::string challenge_12() {
  std::string plain;
  std::string scratch(1, CHAR);
  std::string cipher = encrypt_oracle(scratch);
  std::string::iterator p;
  size_t cipherlen = cipher.length();
  size_t decoded = 0;
  size_t keylen;
  size_t declen;

  // increase scratch size until ciphertext bumps, providing the key length
  while (cipherlen == cipher.length()) {
    scratch.push_back(CHAR);
    cipher = encrypt_oracle(scratch);
  }
  keylen = cipher.length() - cipherlen;

  // length of the plaintext is the length of the cipher, minus the length of
  // the scratch, minus the pkcs7 padding which is a full keylength now
  plain.resize(cipher.length() - scratch.length() - keylen);
  p = plain.begin();

  // detect the encryption method being used
  scratch.resize(keylen * 3, CHAR);
  cipher = encrypt_oracle(scratch);

  aes::mode mode = aes::oracle::detect(cipher);
  if (mode != aes::mode::AES_128_ECB) {
    throw error::Error("Detected AES CBC instead of AES ECB");
  }

  // use a 1-byte short string to help guess the bytes
  declen = keylen - 1;
  std::string dec(declen, CHAR);
  scratch.resize(keylen, CHAR);

  while (p < plain.end()) {
    std::string enc = encrypt_oracle(dec);
    int byte = -1;

    // mimic encrypting the one byte short string, switching out the last
    // byte until it matches the encrypted string
    for (int c = 0; c <= UCHAR_MAX; c++) {
      scratch.back() = static_cast<char>(c);
      cipher = encrypt_oracle(scratch);
      if (0 == cipher.compare(0, scratch.length(), enc, 0, scratch.length())) {
        byte = c;
        break;
      }
    }

    if (byte == -1) {
      // fail if we couldn't decode a byte, and we haven't reached the end of
      // the message
      if (p != plain.end()) {
        throw error::Error("Failed to decrypt target message");
      }
      break;
    }

    *p++ = scratch.back() = static_cast<char>(byte);
    decoded++;

    if (decoded % keylen == 0) {
      // a keylength has been decoded, so scratch needs to be resized up by
      // one keylength, the bits need to be shifted to the right to match what
      // will be encrypted, and the decoding length needs to be reset to one
      // less than the keylength
      scratch.insert(0, declen, CHAR);
      scratch.push_back(CHAR);
      dec.resize(declen, CHAR);
    } else {
      // shift the bytes to the left to make room for the next byte, and
      // decrease the dec length to actually get the next byte
      std::rotate(scratch.begin(), scratch.begin() + 1, scratch.end());
      dec.pop_back();
    }
  }

  return plain;
}

} // namespace cryptopals

int main() {
  try {
    std::ifstream f("data/c12_test.txt");
    const std::string expected((std::istreambuf_iterator<char>(f)),
                               std::istreambuf_iterator<char>());
    const std::string output = cryptopals::challenge_12();
    cryptopals::assert::equal(output, expected);
  } catch (std::exception &e) {
    std::cerr << e.what() << std::endl;
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}
