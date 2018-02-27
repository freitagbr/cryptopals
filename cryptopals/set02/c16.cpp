// Copyright (c) 2018 Brandon Freitag <freitagbr@gmail.com>

#include <exception>
#include <iostream>
#include <streambuf>
#include <string>

#include <cstdlib>

#include "cryptopals/aes.hpp"
#include "cryptopals/assert.hpp"
#include "cryptopals/error.hpp"

#define CHAR 'a' // this value is arbitrary

namespace cryptopals {

namespace {

static std::string prefix("comment1=cooking%20MCs;userdata=");
static std::string suffix(";comment2=%20like%20a%20pound%20of%20bacon");

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

std::string escape_delimiters(std::string &str) {
  std::string escaped = str;
  size_t i = 0;

  while ((i = escaped.find(';', i)) != std::string::npos) {
    escaped.replace(i, 1, "%3B");
    i += 2;
  }

  i = 0;

  while ((i = escaped.find('=', i)) != std::string::npos) {
    escaped.replace(i, 1, "%3D");
    i += 2;
  }

  return escaped;
}

std::string encrypt_userdata(std::string &userdata) {
  std::string escaped = escape_delimiters(userdata);
  std::string str = prefix + escaped + suffix;
  std::string cipher = aes::cbc::encrypt(str, get_key(), get_iv());
  return cipher;
}

std::string decrypt_userdata(std::string &cipher) {
  std::string userdata = aes::cbc::decrypt(cipher, get_key(), get_iv());
  return userdata;
}

bool is_admin(std::string &str) {
  return str.find(";admin=true;") != std::string::npos;
}

// CBC bitflipping attacks
//
// Generate a random AES key.
//
// Combine your padding code and CBC code to write two functions.
//
// The first function should take an arbitrary input string, prepend the
// string:
//
// "comment1=cooking%20MCs;userdata="
//
// .. and append the string:
//
// ";comment2=%20like%20a%20pound%20of%20bacon"
//
// The function should quote out the ";" and "=" characters.
//
// The function should then pad out the input to the 16-byte AES block length
// and encrypt it under the random AES key.
//
// The second function should decrypt the string and look for the characters
// ";admin=true;" (or, equivalently, decrypt, split the string on ";", convert
// each resulting string into 2-tuples, and look for the "admin" tuple).
//
// Return true or false based on whether the string exists.
//
// If you've written the first function properly, it should not be possible to
// provide user input to it that will generate the string the second function is
// looking for. We'll have to break the crypto to do that.
//
// Instead, modify the ciphertext (without knowledge of the AES key) to
// accomplish this.
//
// You're relying on the fact that in CBC mode, a 1-bit error in a ciphertext
// block:
//
// - Completely scrambles the block the error occurs in
// - Produces the identical 1-bit error(/edit) in the next ciphertext block.

std::string challenge_16() {
  std::string userdata(1, CHAR);
  std::string cipher = encrypt_userdata(userdata);
  size_t cipherlen = cipher.length();
  // TODO: the prefix is known to be 32 characters long, but there is probably
  // a way to determine its length without knowing it beforehand
  size_t prefixlen = 32;
  size_t keylen;

  // increase userdata size until ciphertext bumps, providing the key length
  while (cipherlen == cipher.length()) {
    userdata.push_back(CHAR);
    cipher = encrypt_userdata(userdata);
  }
  keylen = cipher.length() - cipherlen;

  // flipping the bits in the ciphertext will also flip the bits in the next
  // block, so by flipping the bits in the first half of the userdata, we
  // can flip ":" to ";" and "<" to "="
  userdata.resize(keylen, CHAR);
  userdata.append(":admin<true:");
  userdata.resize(keylen * 2, CHAR);
  cipher = encrypt_userdata(userdata);
  cipher[prefixlen + 0] ^= 1;  // flip the ":" to ";"
  cipher[prefixlen + 6] ^= 1;  // flip the "<" to "="
  cipher[prefixlen + 11] ^= 1; // flip the ":" to ";"

  return cipher;
}

} // namespace cryptopals

int main() {
  bool failed = false;

  try {
    std::string userdata("foo");
    std::string cipher = cryptopals::encrypt_userdata(userdata);
    std::string plain = cryptopals::decrypt_userdata(cipher);
    bool admin = cryptopals::is_admin(plain);
    cryptopals::assert::equal(admin, false);
  } catch (std::exception &e) {
    std::cerr << e.what() << std::endl;
    failed = true;
  }

  try {
    std::string userdata(";admin=true;");
    std::string cipher = cryptopals::encrypt_userdata(userdata);
    std::string plain = cryptopals::decrypt_userdata(cipher);
    bool admin = cryptopals::is_admin(plain);
    cryptopals::assert::equal(admin, false);
  } catch (std::exception &e) {
    std::cerr << e.what() << std::endl;
    failed = true;
  }

  try {
    std::string cipher = cryptopals::challenge_16();
    std::string plain = cryptopals::decrypt_userdata(cipher);
    bool admin = cryptopals::is_admin(plain);
    cryptopals::assert::equal(admin, true);
  } catch (std::exception &e) {
    std::cerr << e.what() << std::endl;
    failed = true;
  }

  return failed ? EXIT_FAILURE : EXIT_SUCCESS;
}
