// Copyright (c) 2018 Brandon Freitag <freitagbr@gmail.com>

#include <openssl/aes.h>

#include <exception>
#include <future>
#include <iostream>
#include <queue>
#include <sstream>
#include <string>
#include <vector>

#include <climits>
#include <cstdlib>

#include "cryptopals/aes.hpp"
#include "cryptopals/assert.hpp"
#include "cryptopals/error.hpp"
#include "cryptopals/xor.hpp"

namespace cryptopals {

namespace {

std::string &get_key() {
  static bool init = false;
  static std::string key;
  if (!init) {
    key = aes::rand::bytes();
    init = true;
  }
  return key;
}

std::string &get_iv() {
  static bool init = false;
  static std::string iv;
  if (!init) {
    iv = aes::rand::bytes();
    init = true;
  }
  return iv;
}

} // namespace

static const char *plaintexts[10] = {
    "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
    "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbi"
    "c=",
    "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
    "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
    "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
    "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
    "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
    "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
    "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
    "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
};

std::string encrypt_plaintext(const std::string &plain) {
  return aes::cbc::encrypt(plain, get_key(), get_iv());
}

bool cipher_padding_is_valid(std::string &cipher) {
  try {
    aes::cbc::decrypt(cipher, get_key(), get_iv());
    return true;
  } catch (std::exception &e) {
    return false;
  }
}

// The CBC padding oracle
//
// This is the best-known attack on modern block-cipher cryptography.
//
// Combine your padding code and your CBC code to write two functions.
//
// The first function should select at random one of the following 10 strings:
//
// MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=
// MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=
// MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==
// MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==
// MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl
// MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==
// MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==
// MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=
// MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=
// MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93
//
// ... generate a random AES key (which it should save for all future
// encryptions), pad the string out to the 16-byte AES block size and
// CBC-encrypt it under that key, providing the caller the ciphertext and IV.
//
// The second function should consume the ciphertext produced by the first
// function, decrypt it, check its padding, and return true or false depending
// on whether the padding is valid.
//
// What you're doing here.
//
// This pair of functions approximates AES-CBC
// encryption as its deployed serverside in web applications; the second
// function models the server's consumption of an encrypted session token, as
// if it was a cookie.
//
// It turns out that it's possible to decrypt the ciphertexts provided by the
// first function.
//
// The decryption here depends on a side-channel leak by the decryption
// function. The leak is the error message that the padding is valid or not.
//
// You can find 100 web pages on how this attack works, so I won't re-explain
// it. What I'll say is this:
//
// The fundamental insight behind this attack is that the byte 01h is valid
// padding, and occur in 1/256 trials of "randomized" plaintexts produced by
// decrypting a tampered ciphertext.
//
// 02h in isolation is not valid padding.
//
// 02h 02h is valid padding, but is much less likely to occur randomly than
// 01h.
//
// 03h 03h 03h is even less likely.
//
// So you can assume that if you corrupt a decryption AND it had valid padding,
// you know what that padding byte is.
//
// It is easy to get tripped up on the fact that CBC plaintexts are "padded".
// Padding oracles have nothing to do with the actual padding on a CBC
// plaintext. It's an attack that targets a specific bit of code that handles
// decryption. You can mount a padding oracle on any CBC block, whether it's
// padded or not.

std::string challenge_17(const std::string &ciphertext) {
  size_t num_blocks = (ciphertext.length() / AES_BLOCK_SIZE) - 1;
  std::vector<std::future<std::string>> blocks(num_blocks);

  // decrypting a block depends on modifying the ciphertext of the block before
  // it, so loop over every pair of blocks. the first block cannot be decrypted
  // without knowing the iv, however
  for (size_t i = 0; i < blocks.size(); i++) {
    blocks[i] = std::async(std::launch::async, [i, &ciphertext] {
      size_t count = (i + 2) * AES_BLOCK_SIZE;
      std::string cipher = ciphertext.substr(0, count);
      std::queue<std::string> guesses;
      guesses.push("");

      // increasing the padding allows subsequent bytes to be decrypted, so
      // start with a padding of 0x01 (last byte in the block) and iterate up to
      // the blocks size (first byte in the block)
      for (size_t pad = 1; pad <= AES_BLOCK_SIZE; pad++) {
        size_t pos = cipher.length() - AES_BLOCK_SIZE - pad;
        size_t num_guesses = guesses.size();
        std::string cipher_slice = cipher.substr(pos, pad);

        // check every possible byte in the first position of the guess.
        // multiple guess bytes may map to a valid padding (especially when the
        // padding is just [0x01] or [0x02 0x02]), so keep all of the guesses
        // in a queue and loop over the queue
        for (size_t j = 0; j < num_guesses; j++) {
          std::string guess = guesses.front();
          guesses.pop();
          guess.insert(0, 1, '\0');

          for (int g = 0; g <= UCHAR_MAX; g++) {
            guess.at(0) = static_cast<char>(g);
            // performing the following modification to the ciphertext:
            //   cipher slice XOR guess XOR padding
            // and check if the cipher is valid. if it is, our guess is
            // probably correct, because it cancelled out the same byte in the
            // next cipher block, leaving just the valid padding
            std::string mod = cipher_slice ^ guess ^ pad;
            cipher.replace(pos, pad, mod);
            if (cipher_padding_is_valid(cipher)) {
              guesses.push(guess);
            }
          }
        }

        cipher.replace(pos, pad, cipher_slice);
      }

      // there should be exactly 1 guess at this point, otherwise something went
      // terribly wrong
      if (guesses.size() != 1) {
        throw error::Error("Failed to decrypt cipher");
      }

      std::string plain = guesses.front();
      guesses.pop();

      if (count == ciphertext.size()) {
        // strip padding on the last block
        aes::pkcs7::strip(plain);
      }

      return plain;
    });
  }

  std::stringstream plain;
  std::vector<std::future<std::string>>::iterator b = blocks.begin();

  while (b != blocks.end()) {
    plain << b->get();
    ++b;
  }

  return plain.str();
}

} // namespace cryptopals

int main() {
  try {
    for (size_t i = 0; i < 10; i++) {
      std::string plain(cryptopals::plaintexts[i]);
      std::string cipher = cryptopals::encrypt_plaintext(plain);
      std::string output = cryptopals::challenge_17(cipher);
      cryptopals::assert::equal(output, plain.substr(AES_BLOCK_SIZE));
    }
  } catch (std::exception &e) {
    std::cerr << e.what() << std::endl;
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}
