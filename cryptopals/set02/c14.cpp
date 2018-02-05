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

#define MAXBYTES 64 // max number of bytes in prefix
#define CHAR 'a'    // this value is arbitrary

namespace cryptopals {

static std::string
    b64("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
        "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
        "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
        "YnkK");

std::string encrypt_oracle(const std::string &src) {
  static bool init = false;
  static std::string pre;
  static std::string txt;
  static std::string key;

  if (!init) {
    unsigned int prefixlen = aes::rand::uint();
    prefixlen = (prefixlen % MAXBYTES) + 1; // 1 - MAXBYTES random bytes
    pre = aes::rand::bytes(static_cast<size_t>(prefixlen));
    txt = base64::decode(b64);
    key = aes::rand::bytes();
    init = true;
  }

  return aes::ecb::encrypt(pre + src + txt, key);
}

// Byte-at-a-time ECB decryption (Harder)
//
// Take your oracle function from #12. Now generate a random count of random
// bytes and prepend this string to every plaintext. You are now doing:
//
// AES-128-ECB(random-prefix || attacker-controlled || target-bytes, random-key)
//
// Same goal: decrypt the target-bytes.

std::string challenge_14() {
  std::string plain;
  std::string scratch(1, CHAR);
  std::string cipher = encrypt_oracle(scratch);
  std::string::iterator p;
  size_t prefix_offset = 0;
  size_t cipherlen = cipher.length();
  size_t decoded = 0;
  size_t prefixlen;
  size_t plainlen;
  size_t keylen;
  aes::mode mode = aes::mode::AES_128_CBC;

  // increase scratch size until ciphertext bumps, providing the key length
  while (cipherlen == cipher.length()) {
    scratch.push_back(CHAR);
    cipher = encrypt_oracle(scratch);
  }
  keylen = cipher.length() - cipherlen;
  plainlen = cipherlen - scratch.length();

  // use the method for determining the encryption method to determine the
  // number of random bytes in the prefix, i.e. the position that has two
  // repeating keylengths ahead of it is the start of our text
  scratch.resize(keylen * 3, CHAR);
  cipher = encrypt_oracle(scratch);

  while (prefix_offset <= cipher.length() - (keylen * 2)) {
    if (0 == cipher.compare(prefix_offset, keylen, cipher,
                            prefix_offset + keylen, keylen)) {
      mode = aes::mode::AES_128_ECB;
      break;
    }
    prefix_offset++;
  }

  if (mode != aes::mode::AES_128_ECB) {
    throw error::Error("Detected AES CBC instead of AES ECB");
  }

  // find the minimum viable decoder length, which will be greater than
  // keylength - 1 because some of the bytes will occupy the remaining bytes in
  // the last block occupied by the random prefix
  do {
    scratch.pop_back();
    cipher = encrypt_oracle(scratch);
  } while (0 == cipher.compare(prefix_offset, keylen, cipher,
                               prefix_offset + keylen, keylen));
  prefixlen = prefix_offset - (scratch.length() - (keylen * 2) + 1);
  plainlen -= prefixlen;

  // length of the plaintext is the length of the cipher, minus the length of
  // the scratch, minus the length of minus the pkcs7 padding which is a full
  // keylength now
  plain.resize(plainlen);
  p = plain.begin();

  // the scratch length is now:
  //   keylength + (keylength - 1) + (random bytes % keylength)
  // e.g. it occupies the remaining bytes of the last block occupied by the
  // random prefix, plus the next full block, plus 1 less than the next full
  // block. the full block is not needed, so we can subtract a keylength from
  // the scratch length and use that for the decoder length. however, the
  // scratch needs to be resized back up again
  size_t declen = scratch.length() - keylen;
  std::string dec(declen, CHAR);
  scratch.resize(dec.length() + 1);

  while (p < plain.end()) {
    std::string enc = encrypt_oracle(dec);
    size_t comparelen = scratch.length() + prefixlen;
    int byte = -1;

    // mimic encrypting the one byte short string, switching out the last
    // byte until it matches the encrypted string
    for (int c = 0; c <= UCHAR_MAX; c++) {
      scratch.back() = static_cast<unsigned char>(c);
      cipher = encrypt_oracle(scratch);
      if (0 == cipher.compare(0, comparelen, enc, 0, comparelen)) {
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

    *p++ = scratch.back() = static_cast<unsigned char>(byte);
    decoded++;

    if (decoded % keylen == 0) {
      // a keylength has been decoded, so scratch needs to be resized up by
      // one keylength, the bits need to be shifted to the right to match what
      // will be encrypted, and the decoding length needs to be reset to one
      // less than the keylength
      scratch.insert(0, keylen - 1, CHAR);
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
    std::ifstream f("data/c14_test.txt");
    const std::string expected((std::istreambuf_iterator<char>(f)),
                               std::istreambuf_iterator<char>());
    const std::string output = cryptopals::challenge_14();
    cryptopals::assert::equal(output, expected);
  } catch (std::exception &e) {
    std::cerr << e.what() << std::endl;
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}
