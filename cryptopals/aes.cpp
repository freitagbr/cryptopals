// Copyright (c) 2018 Brandon Freitag <freitagbr@gmail.com>

#include "cryptopals/aes.hpp"

#include <openssl/aes.h>
#include <openssl/rand.h>

#include <algorithm>
#include <cstring>
#include <string>

#include "cryptopals/error.hpp"
#include "cryptopals/xor.hpp"

namespace cryptopals {

inline void aes::decrypt(std::string::const_iterator c, std::string::iterator p,
                         AES_KEY &aes_key) {
  AES_decrypt(reinterpret_cast<const unsigned char *>(&(*c)),
              reinterpret_cast<unsigned char *>(&(*p)), &aes_key);
}

inline void aes::encrypt(std::string::iterator p, std::string::iterator c,
                         AES_KEY &aes_key) {
  AES_encrypt(reinterpret_cast<unsigned char *>(&(*p)),
              reinterpret_cast<unsigned char *>(&(*c)), &aes_key);
}

unsigned int aes::rand::uint() {
  unsigned char bytes[sizeof(unsigned int)];
  unsigned int n = 0;

  aes::rand::seed();

  if (1 != RAND_bytes(bytes, sizeof(unsigned int))) {
    throw error::Error("Could not get random bytes");
  }

  for (size_t i = 0; i < sizeof(unsigned int); i++) {
    n |= (bytes[i] << (i * 8));
  }

  return n;
}

std::string aes::rand::bytes(size_t len /* = AES_BLOCK_SIZE */) {
  std::string str(len, '\0');

  aes::rand::seed();

  if (1 !=
      RAND_bytes(reinterpret_cast<unsigned char *>(&str[0]), str.length())) {
    throw error::Error("Could not get random bytes");
  }

  return str;
}

std::string aes::ecb::decrypt(const std::string &cipher,
                              const std::string &key) {
  AES_KEY aes_key;

  if (0 > AES_set_decrypt_key(reinterpret_cast<const unsigned char *>(&key[0]),
                              key.length() * 8, &aes_key)) {
    throw error::Error("Failed to set AES ECB decrypt key");
  }

  std::string plain(cipher.length(), '\0');
  std::string::iterator p = plain.begin();
  std::string::const_iterator c = cipher.cbegin();

  while (p < plain.end()) {
    aes::decrypt(c, p, aes_key);
    c += AES_BLOCK_SIZE;
    p += AES_BLOCK_SIZE;
  }

  aes::pkcs7::strip(plain);

  return plain;
}

std::string aes::ecb::encrypt(const std::string &plain,
                              const std::string &key) {
  AES_KEY aes_key;

  if (0 > AES_set_encrypt_key(reinterpret_cast<const unsigned char *>(&key[0]),
                              key.length() * 8, &aes_key)) {
    throw error::Error("Failed to set AES ECB encrypt key");
  }

  std::string cipher = aes::pkcs7::pad(plain);
  std::string::iterator c = cipher.begin();

  while (c < cipher.end()) {
    aes::encrypt(c, c, aes_key);
    c += AES_BLOCK_SIZE;
  }

  return cipher;
}

std::string aes::cbc::decrypt(const std::string &cipher, const std::string &key,
                              const std::string &iv) {
  AES_KEY aes_key;

  if (0 > AES_set_decrypt_key(reinterpret_cast<const unsigned char *>(&key[0]),
                              key.length() * 8, &aes_key)) {
    throw error::Error("Failed to set AES CBC decrypt key");
  }

  std::string plain(cipher.length(), '\0');
  std::string::iterator p = plain.begin();
  std::string::const_iterator c = cipher.cbegin();
  const unsigned char *ivptr = reinterpret_cast<const unsigned char *>(&iv[0]);

  while (p < plain.end()) {
    aes::decrypt(c, p, aes_key);
    xor_::inplace(p, ivptr, AES_BLOCK_SIZE);
    ivptr = reinterpret_cast<const unsigned char *>(&(*c));
    p += AES_BLOCK_SIZE;
    c += AES_BLOCK_SIZE;
  }

  aes::pkcs7::strip(plain);

  return plain;
}

std::string aes::cbc::encrypt(const std::string &plain, const std::string &key,
                              const std::string &iv) {
  AES_KEY aes_key;

  if (0 > AES_set_encrypt_key(reinterpret_cast<const unsigned char *>(&key[0]),
                              key.length() * 8, &aes_key)) {
    throw error::Error("Failed to set AES CBC encrypt key");
  }

  std::string cipher = aes::pkcs7::pad(plain);
  std::string::iterator c = cipher.begin();
  const unsigned char *ivptr = reinterpret_cast<const unsigned char *>(&iv[0]);

  while (c < cipher.end()) {
    xor_::inplace(c, ivptr, AES_BLOCK_SIZE);
    aes::encrypt(c, c, aes_key);
    ivptr = reinterpret_cast<const unsigned char *>(&(*c));
    c += AES_BLOCK_SIZE;
  }

  return cipher;
}

std::string aes::oracle::encrypt(const std::string &body, aes::mode &mode) {
  // pad front and back of string with 5-10 random bytes
  std::string prefix = aes::rand::bytes((aes::rand::uint() % 6) + 5);
  std::string suffix = aes::rand::bytes((aes::rand::uint() % 6) + 5);
  std::string plain = prefix + body + suffix;
  std::string key = aes::rand::bytes();

  // c will be odd 50% of the time
  if (aes::rand::uint() & 1) {
    // encrypt using cbc
    std::string iv = aes::rand::bytes();
    mode = aes::mode::AES_128_CBC;
    return aes::cbc::encrypt(plain, key, iv);
  }

  // encrypt using ecb
  mode = aes::mode::AES_128_ECB;
  return aes::ecb::encrypt(plain, key);
}

aes::mode aes::oracle::detect(const std::string &cipher) {
  std::string::const_iterator a = cipher.cbegin() + AES_BLOCK_SIZE;
  std::string::const_iterator b = a + AES_BLOCK_SIZE;

  return std::equal(a, b, b) ? aes::mode::AES_128_ECB : aes::mode::AES_128_CBC;
}

std::string aes::pkcs7::pad(const std::string &str,
                            size_t boundary /* = AES_BLOCK_SIZE */) {
  std::string padded = str;
  size_t len = str.length();
  size_t padding = boundary - (len % boundary);
  size_t padlen = len + padding;

  padded.resize(padlen, static_cast<char>(padding));

  return padded;
}

void aes::pkcs7::strip(std::string &str) {
  std::string::const_reverse_iterator s = str.crbegin();
  size_t padding = static_cast<size_t>(*s);

  for (size_t i = 0; i < padding; i++) {
    if (*s++ != static_cast<char>(padding)) {
      throw error::Error("Invalid PKCS7 padding");
    }
  }

  str.resize(str.length() - padding);
}

} // namespace cryptopals
