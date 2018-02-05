// Copyright (c) 2018 Brandon Freitag <freitagbr@gmail.com>

#include "cryptopals/aes.hpp"

#include <openssl/aes.h>
#include <openssl/rand.h>

#include <cstring>
#include <string>

#include "cryptopals/error.hpp"
#include "cryptopals/xor.hpp"

namespace cryptopals {

inline void aes::rand::seed() {
  static bool seeded = false;
  if (!seeded) {
    if (RAND_load_file(AES_RAND_SOURCE, AES_RAND_SIZE) != AES_RAND_SIZE) {
      throw error::Error("Failed to seed from " AES_RAND_SOURCE);
    }
    seeded = true;
  }
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
  std::string str;

  aes::rand::seed();
  str.resize(len);

  if (1 !=
      RAND_bytes(reinterpret_cast<unsigned char *>(&str[0]), str.length())) {
    throw error::Error("Could not get random bytes");
  }

  return str;
}

std::string aes::ecb::decrypt(const std::string &src, const std::string &key) {
  AES_KEY aes_key;
  std::string dst;
  const unsigned char *sptr = reinterpret_cast<const unsigned char *>(&src[0]);
  unsigned char *dptr;
  unsigned char *end;

  if (0 > AES_set_decrypt_key(reinterpret_cast<const unsigned char *>(&key[0]),
                              key.length() * 8, &aes_key)) {
    throw error::Error("Failed to set AES ECB decrypt key");
  }

  dst.resize(src.length());
  dptr = reinterpret_cast<unsigned char *>(&dst[0]);
  end = reinterpret_cast<unsigned char *>(&dst[dst.length()]);

  while (dptr < end) {
    AES_decrypt(sptr, dptr, &aes_key);
    dptr += AES_BLOCK_SIZE;
    sptr += AES_BLOCK_SIZE;
  }

  aes::pkcs7::strip(dst);

  return dst;
}

std::string aes::ecb::encrypt(const std::string &src, const std::string &key) {
  AES_KEY aes_key;
  std::string dst;
  const unsigned char *sptr = reinterpret_cast<const unsigned char *>(&src[0]);
  unsigned char *dptr;
  unsigned char *end;
  size_t padding;

  if (0 > AES_set_encrypt_key(reinterpret_cast<const unsigned char *>(&key[0]),
                              key.length() * 8, &aes_key)) {
    throw error::Error("Failed to set AES ECB encrypt key");
  }

  padding = aes::pkcs7::pad(dst, src.length());
  dptr = reinterpret_cast<unsigned char *>(&dst[0]);
  end = reinterpret_cast<unsigned char *>(&dst[dst.length() - AES_BLOCK_SIZE]);

  while (dptr < end) {
    AES_encrypt(sptr, dptr, &aes_key);
    dptr += AES_BLOCK_SIZE;
    sptr += AES_BLOCK_SIZE;
  }

  std::memcpy(dptr, sptr, AES_BLOCK_SIZE - padding);
  AES_encrypt(dptr, dptr, &aes_key);

  return dst;
}

std::string aes::cbc::decrypt(const std::string &src, const std::string &key,
                              const std::string &iv) {
  AES_KEY aes_key;
  std::string dst;
  const unsigned char *ivptr = reinterpret_cast<const unsigned char *>(&iv[0]);
  const unsigned char *sptr = reinterpret_cast<const unsigned char *>(&src[0]);
  unsigned char *dptr;
  unsigned char *end;

  if (0 > AES_set_decrypt_key(reinterpret_cast<const unsigned char *>(&key[0]),
                              key.length() * 8, &aes_key)) {
    throw error::Error("Failed to set AES CBC decrypt key");
  }

  dst.resize(src.length());
  dptr = reinterpret_cast<unsigned char *>(&dst[0]);
  end = reinterpret_cast<unsigned char *>(&dst[dst.length()]);

  while (dptr < end) {
    AES_decrypt(sptr, dptr, &aes_key);
    xor_::inplace(dptr, ivptr, AES_BLOCK_SIZE);
    ivptr = sptr;
    dptr += AES_BLOCK_SIZE;
    sptr += AES_BLOCK_SIZE;
  }

  aes::pkcs7::strip(dst);

  return dst;
}

std::string aes::cbc::encrypt(const std::string &src, const std::string &key,
                              const std::string &iv) {
  AES_KEY aes_key;
  std::string dst;
  const unsigned char *ivptr = reinterpret_cast<const unsigned char *>(&iv[0]);
  const unsigned char *sptr = reinterpret_cast<const unsigned char *>(&src[0]);
  unsigned char *dptr;
  unsigned char *end;
  size_t padding;

  if (0 > AES_set_encrypt_key(reinterpret_cast<const unsigned char *>(&key[0]),
                              key.length() * 8, &aes_key)) {
    throw error::Error("Failed to set AES CBC encrypt key");
  }

  padding = aes::pkcs7::pad(dst, src.length());
  dptr = reinterpret_cast<unsigned char *>(&dst[0]);
  end = reinterpret_cast<unsigned char *>(&dst[dst.length() - AES_BLOCK_SIZE]);

  while (dptr < end) {
    xor_::bytes(dptr, sptr, ivptr, AES_BLOCK_SIZE);
    AES_encrypt(dptr, dptr, &aes_key);
    ivptr = dptr;
    dptr += AES_BLOCK_SIZE;
    sptr += AES_BLOCK_SIZE;
  }

  std::memcpy(dptr, sptr, AES_BLOCK_SIZE - padding);
  xor_::inplace(dptr, ivptr, AES_BLOCK_SIZE);
  AES_encrypt(dptr, dptr, &aes_key);

  return dst;
}

std::string aes::oracle::encrypt(const std::string &src, aes::mode &mode) {
  std::string str;
  std::string key = aes::rand::bytes();

  unsigned int a = aes::rand::uint();
  unsigned int b = aes::rand::uint();
  unsigned int c = aes::rand::uint();

  // pad front and back of string with 5-10 bytes
  std::string front = aes::rand::bytes((a % 6) + 5);
  std::string back = aes::rand::bytes((b % 6) + 5);

  str = front + src + back;

  // c will be odd 50% of the time
  if (c & 1) {
    // encrypt using cbc
    std::string iv = aes::rand::bytes();
    mode = aes::mode::AES_128_CBC;
    return aes::cbc::encrypt(str, key, iv);
  }

  // encrypt using ecb
  mode = aes::mode::AES_128_ECB;
  return aes::ecb::encrypt(str, key);
}

aes::mode aes::oracle::detect(const std::string &str) {
  const unsigned char *block_a =
      reinterpret_cast<const unsigned char *>(&str[AES_BLOCK_SIZE]);
  const unsigned char *block_b =
      reinterpret_cast<const unsigned char *>(&str[AES_BLOCK_SIZE * 2]);
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
