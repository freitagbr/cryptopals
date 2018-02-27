// Copyright (c) 2018 Brandon Freitag <freitagbr@gmail.com>

#include "cryptopals/aes.hpp"

#include <openssl/aes.h>
#include <openssl/rand.h>

#include <cstring>
#include <string>

#include "cryptopals/error.hpp"
#include "cryptopals/xor.hpp"

namespace cryptopals {

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
  std::string str;

  aes::rand::seed();
  str.resize(len);

  if (1 !=
      RAND_bytes(reinterpret_cast<unsigned char *>(&str[0]), str.length())) {
    throw error::Error("Could not get random bytes");
  }

  return str;
}

std::string aes::ecb::decrypt(const std::string &cipher,
                              const std::string &key) {
  AES_KEY aes_key;
  std::string plain;
  const unsigned char *cptr =
      reinterpret_cast<const unsigned char *>(&cipher[0]);
  unsigned char *pptr;
  unsigned char *end;

  if (0 > AES_set_decrypt_key(reinterpret_cast<const unsigned char *>(&key[0]),
                              key.length() * 8, &aes_key)) {
    throw error::Error("Failed to set AES ECB decrypt key");
  }

  plain.resize(cipher.length());
  pptr = reinterpret_cast<unsigned char *>(&plain[0]);
  end = reinterpret_cast<unsigned char *>(&plain[plain.length()]);

  while (pptr < end) {
    AES_decrypt(cptr, pptr, &aes_key);
    pptr += AES_BLOCK_SIZE;
    cptr += AES_BLOCK_SIZE;
  }

  aes::pkcs7::strip(plain);

  return plain;
}

std::string aes::ecb::encrypt(const std::string &plain,
                              const std::string &key) {
  AES_KEY aes_key;
  std::string cipher;
  const unsigned char *pptr =
      reinterpret_cast<const unsigned char *>(&plain[0]);
  unsigned char *cptr;
  unsigned char *end;
  size_t padding;

  if (0 > AES_set_encrypt_key(reinterpret_cast<const unsigned char *>(&key[0]),
                              key.length() * 8, &aes_key)) {
    throw error::Error("Failed to set AES ECB encrypt key");
  }

  padding = aes::pkcs7::pad(cipher, plain.length());
  cptr = reinterpret_cast<unsigned char *>(&cipher[0]);
  end = reinterpret_cast<unsigned char *>(
      &cipher[cipher.length() - AES_BLOCK_SIZE]);

  while (cptr < end) {
    AES_encrypt(pptr, cptr, &aes_key);
    cptr += AES_BLOCK_SIZE;
    pptr += AES_BLOCK_SIZE;
  }

  std::memcpy(cptr, pptr, AES_BLOCK_SIZE - padding);
  AES_encrypt(cptr, cptr, &aes_key);

  return cipher;
}

std::string aes::cbc::decrypt(const std::string &cipher, const std::string &key,
                              const std::string &iv) {
  AES_KEY aes_key;
  std::string plain;
  const unsigned char *ivptr = reinterpret_cast<const unsigned char *>(&iv[0]);
  const unsigned char *cptr =
      reinterpret_cast<const unsigned char *>(&cipher[0]);
  unsigned char *pptr;
  unsigned char *end;

  if (0 > AES_set_decrypt_key(reinterpret_cast<const unsigned char *>(&key[0]),
                              key.length() * 8, &aes_key)) {
    throw error::Error("Failed to set AES CBC decrypt key");
  }

  plain.resize(cipher.length());
  pptr = reinterpret_cast<unsigned char *>(&plain[0]);
  end = reinterpret_cast<unsigned char *>(&plain[plain.length()]);

  while (pptr < end) {
    AES_decrypt(cptr, pptr, &aes_key);
    xor_::inplace(pptr, ivptr, AES_BLOCK_SIZE);
    ivptr = cptr;
    pptr += AES_BLOCK_SIZE;
    cptr += AES_BLOCK_SIZE;
  }

  aes::pkcs7::strip(plain);

  return plain;
}

std::string aes::cbc::encrypt(const std::string &plain, const std::string &key,
                              const std::string &iv) {
  AES_KEY aes_key;
  std::string cipher;
  const unsigned char *ivptr = reinterpret_cast<const unsigned char *>(&iv[0]);
  const unsigned char *pptr =
      reinterpret_cast<const unsigned char *>(&plain[0]);
  unsigned char *cptr;
  unsigned char *end;
  size_t padding;

  if (0 > AES_set_encrypt_key(reinterpret_cast<const unsigned char *>(&key[0]),
                              key.length() * 8, &aes_key)) {
    throw error::Error("Failed to set AES CBC encrypt key");
  }

  padding = aes::pkcs7::pad(cipher, plain.length());
  cptr = reinterpret_cast<unsigned char *>(&cipher[0]);
  end = reinterpret_cast<unsigned char *>(
      &cipher[cipher.length() - AES_BLOCK_SIZE]);

  while (cptr < end) {
    xor_::bytes(cptr, pptr, ivptr, AES_BLOCK_SIZE);
    AES_encrypt(cptr, cptr, &aes_key);
    ivptr = cptr;
    cptr += AES_BLOCK_SIZE;
    pptr += AES_BLOCK_SIZE;
  }

  std::memcpy(cptr, pptr, AES_BLOCK_SIZE - padding);
  xor_::inplace(cptr, ivptr, AES_BLOCK_SIZE);
  AES_encrypt(cptr, cptr, &aes_key);

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
  const unsigned char *block_a =
      reinterpret_cast<const unsigned char *>(&cipher[AES_BLOCK_SIZE]);
  const unsigned char *block_b =
      reinterpret_cast<const unsigned char *>(&cipher[AES_BLOCK_SIZE * 2]);
  return std::memcmp(block_a, block_b, AES_BLOCK_SIZE) == 0
             ? aes::mode::AES_128_ECB
             : aes::mode::AES_128_CBC;
}

size_t aes::pkcs7::pad(std::string &str, size_t len,
                       size_t boundary /* = AES_BLOCK_SIZE */) {
  size_t padding = boundary - (len % boundary);
  size_t padlen = len + padding;

  str.resize(padlen);
  std::memset(&str[str.length() - padding], static_cast<int>(padding), padding);

  return padding;
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
