// Copyright (c) 2018 Brandon Freitag <freitagbr@gmail.com>

#ifndef CRYPTOPALS_AES_H_
#define CRYPTOPALS_AES_H_

#include <openssl/aes.h>

#include <string>

#define AES_RAND_SOURCE "/dev/urandom"
#define AES_RAND_SIZE 32

namespace cryptopals {
namespace aes {

enum class mode {
  AES_128_ECB, // aes-128-ecb
  AES_128_CBC  // aes-128-cbc
};

namespace rand {

static inline void seed();

unsigned int uint();

std::string bytes(size_t len = AES_BLOCK_SIZE);

} // namespace rand

namespace ecb {

std::string decrypt(const std::string &src, const std::string &key);

std::string encrypt(const std::string &src, const std::string &key);

} // namespace ecb

namespace cbc {

std::string decrypt(const std::string &src, const std::string &key,
                    const std::string &iv);

std::string encrypt(const std::string &src, const std::string &key,
                    const std::string &iv);

} // namespace cbc

namespace oracle {

std::string encrypt(const std::string &src, aes::mode &mode);

aes::mode detect(const std::string &str);

} // namespace oracle

namespace pkcs7 {

size_t pad(std::string &str, size_t len, size_t boundary = AES_BLOCK_SIZE);

void strip(std::string &str);

} // namespace pkcs7

} // namespace aes
} // namespace cryptopals

#endif // CRYPTOPALS_AES_H_
