// Copyright (c) 2018 Brandon Freitag <freitagbr@gmail.com>

#ifndef CRYPTOPALS_ASSERT_H_
#define CRYPTOPALS_ASSERT_H_

#include <ostream>
#include <sstream>
#include <string>

#include "cryptopals/error.hpp"

namespace cryptopals {
namespace assert {

template <typename T> void equal(const T &actual, const T &expected) {
  if (actual != expected) {
    std::ostringstream message;
    message << "Expected:" << std::endl;
    message << expected << std::endl << std::endl;
    message << "Actual:" << std::endl;
    message << actual << std::endl;
    throw error::Error(message.str());
  }
}

} // namespace assert
} // namespace cryptopals

#endif // CRYPTOPALS_ASSERT_H_
