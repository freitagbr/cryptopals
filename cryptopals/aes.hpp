// Copyright (c) 2018 Brandon Freitag <freitagbr@gmail.com>

#ifndef CRYPTOPALS_AES_HPP_
#define CRYPTOPALS_AES_HPP_

#include <openssl/aes.h>
#include <openssl/rand.h>

#include <string>

#include "cryptopals/error.hpp"

#define AES_RAND_SOURCE "/dev/urandom"
#define AES_RAND_SIZE 32

namespace cryptopals {
namespace aes {

enum class mode {
  AES_128_ECB, // aes-128-ecb
  AES_128_CBC  // aes-128-cbc
};

inline void decrypt(std::string::const_iterator c, std::string::iterator p,
                    AES_KEY &aes_key);

inline void encrypt(std::string::iterator p, std::string::iterator c,
                    AES_KEY &aes_key);

namespace rand {

inline void seed() {
  static bool seeded = false;
  if (!seeded) {
    if (AES_RAND_SIZE != RAND_load_file(AES_RAND_SOURCE, AES_RAND_SIZE)) {
      throw error::Error("Failed to seed from " AES_RAND_SOURCE);
    }
    seeded = true;
  }
}

unsigned int uint();

std::string bytes(size_t len = AES_BLOCK_SIZE);

} // namespace rand

namespace ecb {

std::string decrypt(const std::string &cipher, const std::string &key);

std::string encrypt(const std::string &plain, const std::string &key);

} // namespace ecb

namespace cbc {

std::string decrypt(const std::string &cipher, const std::string &key,
                    const std::string &iv);

std::string encrypt(const std::string &plain, const std::string &key,
                    const std::string &iv);

} // namespace cbc

namespace ctr {

std::string decrypt(const std::string &cipher, const std::string &key,
                    const uint64_t nonce = 0);

std::string encrypt(const std::string &cipher, const std::string &key,
                    const uint64_t nonce = 0);

} // namespace ctr

namespace oracle {

std::string encrypt(const std::string &body, aes::mode &mode);

aes::mode detect(const std::string &cipher);

} // namespace oracle

namespace pkcs7 {

std::string pad(const std::string &str, const size_t boundary = AES_BLOCK_SIZE);

void strip(std::string &str);

} // namespace pkcs7

} // namespace aes
} // namespace cryptopals

#endif // CRYPTOPALS_AES_HPP_
