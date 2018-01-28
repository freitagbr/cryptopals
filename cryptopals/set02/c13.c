/* Copyright (c) 2018 Brandon Freitag <freitagbr@gmail.com> */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "cryptopals/aes.h"
#include "cryptopals/string.h"
#include "cryptopals/error.h"
#include "cryptopals/map.h"
#include "cryptopals/url.h"


static const string EMAIL = string_new("email", 5);
static const string UID = string_new("uid", 3);
static const string ROLE = string_new("role", 4);
static const string USER = string_new("user", 4);
static string key = string_init();

static error_t init() {
  if (key.ptr == NULL) {
    return aes_random_bytes(&key);
  }
  return 0;
}

error_t profile_for(string *qs, const string email) {
  map m = map_init();
  string uid;
  unsigned char hashstr[sizeof(size_t) * 8];
  size_t hash = map_hash(email, SIZE_MAX);
  int len;
  error_t err;

  err = map_new(&m);
  if (err) {
    goto end;
  }

  len = sprintf((char *)hashstr, "%lu", hash);
  if (len <= 0) {
    err = ESIZE;
    goto end;
  }

  uid.ptr = hashstr;
  uid.len = (size_t)len;

  err = map_set(&m, EMAIL, email) ||
        map_set(&m, UID, uid) ||
        map_set(&m, ROLE, USER) ||
        url_qs_encode(qs, &m);

end:
  map_delete(m);

  return err;
}

error_t profile_encode(string *dst, const string src) {
  return aes_ecb_encrypt(dst, src, key);
}

/**
 * ECB cut-and-paste
 *
 * Write a k=v parsing routine, as if for a structured cookie. The routine
 * should take:
 *
 * foo=bar&baz=qux&zap=zazzle
 *
 * ... and produce:
 * 
 * {
 *   foo: 'bar',
 *   baz: 'qux',
 *   zap: 'zazzle'
 * }
 *
 * (you know, the object; I don't care if you convert it to JSON).
 * 
 * Now write a function that encodes a user profile in that format, given an
 * email address. You should have something like:
 * 
 * profile_for("foo@bar.com")
 *
 * ... and it should produce:
 * 
 * {
 *   email: 'foo@bar.com',
 *   uid: 10,
 *   role: 'user'
 * }
 *
 * ... encoded as:
 * 
 * email=foo@bar.com&uid=10&role=user
 *
 * Your "profile_for" function should not allow encoding metacharacters (& and
 * =). Eat them, quote them, whatever you want to do, but don't let people set
 * their email address to "foo@bar.com&role=admin".
 * 
 * Now, two more easy functions. Generate a random AES key, then:
 * 
 * Encrypt the encoded user profile under the key; "provide" that to the
 * "attacker".  Decrypt the encoded user profile and parse it.
 *
 * Using only the user input to profile_for() (as an oracle to generate "valid"
 * ciphertexts) and the ciphertexts themselves, make a role=admin profile.
 */

error_t challenge_13(const string email) {
  string qs = string_init();
  string enc = string_init();
  error_t err;

  err = profile_for(&qs, email) ||
        profile_encode(&enc, qs);
  if (err) {
    return err;
  }

  return 0;
}

int main() {
  const string email = string_new("foo@bar.com", 11);
  error_t err;

  err = init();
  if (err) {
    return err;
  }

  err = challenge_13(email);
  if (err) {
    return err;
  }

  return 0;
}
