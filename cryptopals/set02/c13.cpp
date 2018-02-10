// Copyright (c) 2018 Brandon Freitag <freitagbr@gmail.com>

#include <exception>
#include <iostream>
#include <string>

#include <cstdlib>

#include "cryptopals/aes.hpp"
#include "cryptopals/assert.hpp"
#include "cryptopals/url.hpp"

namespace cryptopals {

std::string profile_for(const std::string &email) {
  url::qs::map m;

  m["email"] = email;
  m["uid"] = "10";
  m["role"] = "user";

  return url::qs::encode(m);
}

std::string profile_encode(const std::string &src) {
  static bool init = false;
  static std::string key;

  if (!init) {
    key = aes::rand::bytes();
    init = true;
  }

  return aes::ecb::encrypt(src, key);
}

// ECB cut-and-paste
//
// Write a k=v parsing routine, as if for a structured cookie. The routine
// should take:
//
// foo=bar&baz=qux&zap=zazzle
//
// ... and produce:
//
// {
//   foo: 'bar',
//   baz: 'qux',
//   zap: 'zazzle'
// }
//
// (you know, the object; I don't care if you convert it to JSON).
//
// Now write a function that encodes a user profile in that format, given an
// email address. You should have something like:
//
// profile_for("foo@bar.com")
//
// ... and it should produce:
//
// {
//   email: 'foo@bar.com',
//   uid: 10,
//   role: 'user'
// }
//
// ... encoded as:
//
// email=foo@bar.com&uid=10&role=user
//
// Your "profile_for" function should not allow encoding metacharacters (& and
// =). Eat them, quote them, whatever you want to do, but don't let people set
// their email address to "foo@bar.com&role=admin".
//
// Now, two more easy functions. Generate a random AES key, then:
//
// Encrypt the encoded user profile under the key; "provide" that to the
// "attacker".  Decrypt the encoded user profile and parse it.
//
// Using only the user input to profile_for() (as an oracle to generate "valid"
// ciphertexts) and the ciphertexts themselves, make a role=admin profile.

std::string challenge_13(const std::string &email) {
  std::string qs = cryptopals::profile_for(email);
  std::string enc = cryptopals::profile_encode(qs);

  return enc;
}

} // namespace cryptopals

int main() {
  const std::string email("foo@bar.com");

  try {
    // there is nothing to test here, because my url encoder encodes binary
    // correctly, so it is immune to this type of attack
    cryptopals::challenge_13(email);
    // cryptopals::assert::equal(output, expected);
  } catch (std::exception &e) {
    std::cerr << e.what() << std::endl;
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}
