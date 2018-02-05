// Copyright (c) 2018 Brandon Freitag <freitagbr@gmail.com>

#include "cryptopals/error.hpp"

#include <string>

namespace cryptopals {

error::Error::Error(const std::string &message) : message(message) {}

error::Error::Error(const char *message) : message(std::string(message)) {}

const char *error::Error::what() const noexcept { return message.c_str(); }

} // namespace cryptopals
