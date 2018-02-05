// Copyright (c) 2018 Brandon Freitag <freitagbr@gmail.com>

#ifndef CRYPTOPALS_ERROR_H_
#define CRYPTOPALS_ERROR_H_

#include <exception>
#include <string>

namespace cryptopals {
namespace error {

class Error : public std::exception {
  const std::string message;

public:
  Error(const std::string &message);
  Error(const char *message);
  const char *what() const noexcept;
};

} // namespace error
} // namespace cryptopals

#endif // CRYPTOPALS_ERROR_H_
