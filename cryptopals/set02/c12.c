/* Copyright (c) 2018 Brandon Freitag <freitagbr@gmail.com> */

#include <limits.h>
#include <string.h>

#include "cryptopals/aes.h"
#include "cryptopals/base64.h"
#include "cryptopals/string.h"
#include "cryptopals/error.h"
#include "cryptopals/file.h"

static string b64 =
    string_new("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
               "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
               "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
               "YnkK",
               185);
static string key = string_init();
static string txt = string_init();
static string tmp = string_init();

static error_t init() {
  error_t err;

  if (txt.ptr == NULL) {
    err = base64_decode(&txt, b64);
    if (err) {
      return err;
    }
  }

  if (key.ptr == NULL) {
    err = aes_random_bytes(&key);
    if (err) {
      return err;
    }
  }

  return 0;
}

static error_t encrypt_oracle(string *dst, const string src) {
  return string_concat(&tmp, src, txt) ||
         aes_ecb_encrypt(dst, tmp, key);
}

/**
 * Byte-at-a-time ECB decryption (Simple)
 *
 * Copy your oracle function to a new function that encrypts strings under ECB
 * mode using a consistent but unknown key (for instance, assign a single
 * random key, once, to a global variable).
 *
 * Now take that same function and have it append to the plaintext, BEFORE
 * ENCRYPTING, the following string:
 *
 * Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
 * aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
 * dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg YnkK
 *
 * Base64 decode the string before appending it. Do not base64 decode the
 * string by hand; make your code do it. The point is that you don't know its
 * contents.
 *
 * What you have now is a function that produces:
 *
 * AES-128-ECB(your-string || unknown-string, random-key)
 *
 * It turns out: you can decrypt "unknown-string" with repeated calls to the
 * oracle function!
 *
 * Here's roughly how:
 *
 * 1. Feed identical bytes of your-string to the function 1 at a time --- start
 *    with 1 byte ("A"), then "AA", then "AAA" and so on. Discover the block
 *    size of the cipher. You know it, but do this step anyway.
 * 2. Detect that the function is using ECB. You already know, but do this step
 *    anyways.
 * 3. Knowing the block size, craft an input block that is exactly 1 byte short
 *    (for instance, if the block size is 8 bytes, make "AAAAAAA"). Think about
 *    what the oracle function is going to put in that last byte position.
 * 4. Make a dictionary of every possible last byte by feeding different strings
 *    to the oracle; for instance, "AAAAAAAA", "AAAAAAAB", "AAAAAAAC",
 *    remembering the first block of each invocation.
 * 5. Match the output of the one-byte-short input to one of the entries in your
 *    dictionary. You've now discovered the first byte of unknown-string.
 * 6. Repeat for the next byte.
 */

error_t challenge_12(string *plain) {
  string scratch = string_init();
  string cipher = string_init();
  string enc = string_init();
  string dec = string_init();
  unsigned char *plainptr;
  size_t decoded = 0;
  size_t cipherlen;
  size_t keylen;
  int byte;
  aes_mode_t mode;
  error_t err;

  err = string_alloc(&scratch, 1);
  if (err) {
    goto end;
  }

  scratch.ptr[0] = 'a';

  err = encrypt_oracle(&cipher, scratch);
  if (err) {
    goto end;
  }

  cipherlen = cipher.len;

  err = string_alloc(plain, cipherlen);
  if (err) {
    goto end;
  }
  plainptr = plain->ptr;

  /* increase scratch size until ciphertext bumps, providing the key length */
  while (cipherlen == cipher.len) {
    err = string_resize(&scratch, scratch.len + 1);
    if (err) {
      goto end;
    }
    scratch.ptr[scratch.len - 1] = 'a';
    err = encrypt_oracle(&cipher, scratch);
    if (err) {
      goto end;
    }
  }
  keylen = cipher.len - cipherlen;

  /* detect the encryption method being used */
  err = string_resize(&scratch, keylen * 3);
  if (err) {
    goto end;
  }

  memset(scratch.ptr, (int)'a', keylen * 3);

  err = encrypt_oracle(&cipher, scratch);
  if (err) {
    goto end;
  }

  mode = aes_encrypt_detect(cipher);
  if (mode != AES_128_ECB) {
    err = EAESMODE;
    goto end;
  }

  err = string_resize(&scratch, keylen);
  if (err) {
    goto end;
  }

  /* use a 1-byte short string to help guess the bytes */
  err = string_alloc(&dec, keylen - 1);
  if (err) {
    goto end;
  }

  memset(dec.ptr, 'a', dec.len);

  while (scratch.len <= cipherlen) {
    size_t i;

    err = encrypt_oracle(&enc, dec);
    if (err) {
      goto end;
    }

    byte = -1;

    /**
     * mimic encrypting the one byte short string, switching out the last
     * byte until it matches the encrypted string
     */
    for (i = 0; i < UCHAR_MAX + 1; i++) {
      scratch.ptr[scratch.len - 1] = (unsigned char)i;
      err = encrypt_oracle(&cipher, scratch);
      if (err) {
        goto end;
      }
      if (memcmp(cipher.ptr, enc.ptr, scratch.len) == 0) {
        byte = (int)i;
        break;
      }
    }

    if (byte == -1) {
      /**
       * this is probably the end of the message, so fix the length of the
       * decoded plaintext, but fail if there's more than a keylength left to
       * decrypt
       */
      plain->len = (plainptr - plain->ptr) - 1;
      if (cipherlen - plain->len > keylen) {
        err = EDECRYPT;
      }
      goto end;
    }

    *plainptr++ = scratch.ptr[scratch.len - 1] = (unsigned char)byte;
    decoded++;

    if (decoded % keylen == 0) {
      /**
       * a keylength has been decoded, so scratch needs to be resized up by
       * one keylength, the bits need to be shifted to the right to match what
       * will be encrypted, and the decoding length needs to be reset to one
       * less than the keylength
       */
      unsigned char *from;
      unsigned char *to;
      err = string_resize(&scratch, scratch.len + keylen);
      if (err) {
        goto end;
      }
      from = &(scratch.ptr[scratch.len - keylen - 1]);
      to = &(scratch.ptr[scratch.len - 2]);
      while (from >= scratch.ptr) {
        *(to--) = *(from--);
      }
      while (to >= scratch.ptr) {
        *(to--) = 'a';
      }
      dec.len = keylen - 1;
    } else {
      /**
       * shift the bytes to the left to make room for the next byte, and
       * decrease the dec length to actually get the next byte
       */
      unsigned char *end = &(scratch.ptr[scratch.len]);
      unsigned char *from = end - decoded;
      unsigned char *to = from - 1;
      while (from < end) {
        *(to++) = *(from++);
      }
      dec.len--;
    }
  }

end:
  string_delete(scratch);
  string_delete(cipher);
  string_delete(enc);
  string_delete(dec);

  return err;
}

int main() {
  string expected = string_init();
  string output = string_init();
  error_t err;

  err = init() ||
        file_read("data/c12_test.txt", &expected) ||
        challenge_12(&output);
  if (err) {
    error(err);
    goto end;
  }

  error_expect((const char *)expected.ptr, (const char *)output.ptr);

end:
  string_delete(expected);
  string_delete(output);
  string_delete(key);
  string_delete(txt);
  string_delete(tmp);

  return err;
}
