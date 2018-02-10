// Copyright (c) 2018 Brandon Freitag <freitagbr@gmail.com>

#ifndef CRYPTOPALS_BLOCK_HPP_
#define CRYPTOPALS_BLOCK_HPP_

#include <string>

namespace cryptopals {
namespace block {

size_t keysize(const std::string &str, float &min_dist, size_t max_keysize);

size_t keysize(const std::string &str, size_t max_keysize);

std::string transpose_get_key(const std::string &str, size_t max_keysize);

} // namespace block
} // namespace cryptopals

#endif // CRYPTOPALS_BLOCK_HPP_
