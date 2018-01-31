/* Copyright (c) 2018 Brandon Freitag <freitagbr@gmail.com> */

#include <limits.h>
#include <string.h>

#include "cryptopals/aes.h"
#include "cryptopals/base64.h"
#include "cryptopals/string.h"
#include "cryptopals/error.h"
#include "cryptopals/file.h"

#define NBYTES 64 /* max number of bytes in prefix */

static string b64 =
    string_new("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
               "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
               "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
               "YnkK",
               185);
static string txt = string_init();
static string key = string_init();
static string pre = string_init();
static string tmpa = string_init();
static string tmpb = string_init();

static error_t init() {
  unsigned int prefixlen = 0;
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

  if (prefixlen == 0 && pre.ptr == NULL) {
    err = aes_rand(&prefixlen);
    if (err) {
      return err;
    }
    prefixlen = (prefixlen % NBYTES) + 1; /* 1-NBYTES random bytes */
    err = aes_random_nbytes(&pre, (size_t)prefixlen);
    if (err) {
      return err;
    }
  }

  return 0;
}

static error_t encrypt_oracle(string *dst, const string src) {
  return string_concat(&tmpa, pre, src) ||
         string_concat(&tmpb, tmpa, txt) ||
         aes_ecb_encrypt(dst, tmpb, key);
}

/**
 * Byte-at-a-time ECB decryption (Harder)
 *
 * Take your oracle function from #12. Now generate a random count of random
 * bytes and prepend this string to every plaintext. You are now doing:
 *
 * AES-128-ECB(random-prefix || attacker-controlled || target-bytes, random-key)
 *
 * Same goal: decrypt the target-bytes.
 */

error_t challenge_14(string *plain) {
  string scratch = string_init();
  string cipher = string_init();
  string enc = string_init();
  string dec = string_init();
  unsigned char *plainptr;
  unsigned char *plainend;
  unsigned char *block_a;
  unsigned char *block_b;
  size_t prefix_offset = 0;
  size_t decoded = 0;
  size_t cipherlen;
  size_t plainlen;
  size_t prefixlen;
  size_t keylen;
  size_t declen;
  aes_mode_t mode = 0;
  error_t err;

  err = string_alloc(&scratch, 1);
  if (err) {
    error(err);
    goto end;
  }
  scratch.ptr[0] = 'a';

  err = encrypt_oracle(&cipher, scratch);
  if (err) {
    error(err);
    goto end;
  }
  cipherlen = cipher.len;

  /* increase scratch size until ciphertext bumps, providing the key length */
  while (cipherlen == cipher.len) {
    err = string_resize(&scratch, scratch.len + 1);
    if (err) {
      error(err);
      goto end;
    }
    scratch.ptr[scratch.len - 1] = 'a';
    err = encrypt_oracle(&cipher, scratch);
    if (err) {
      error(err);
      goto end;
    }
  }
  keylen = cipher.len - cipherlen;
  plainlen = cipherlen - scratch.len;

  /**
   * use the method for determining the encryption method to determine the
   * number of random bytes in the prefix, i.e. the position that has two
   * repeating keylengths ahead of it is the start of our text
   */
  err = string_resize(&scratch, keylen * 3);
  if (err) {
    error(err);
    goto end;
  }
  memset(scratch.ptr, (int)'a', scratch.len);

  err = encrypt_oracle(&cipher, scratch);
  if (err) {
    error(err);
    goto end;
  }

  while (prefix_offset <= cipher.len - (keylen * 2)) {
    block_a = &(cipher.ptr[prefix_offset]);
    block_b = &(block_a[keylen]);
    if (memcmp(block_a, block_b, keylen) == 0) {
      mode = AES_128_ECB;
      break;
    }
    prefix_offset++;
  }

  if (mode != AES_128_ECB) {
    err = EAESMODE;
    error(err);
    goto end;
  }

  /**
   * find the minimum viable decoder length, which will be greater than
   * keylength - 1 because some of the bytes will occupy the remaining bytes in
   * the last block occupied by the random prefix
   */
  memset(scratch.ptr, (int)'a', scratch.len);
  do {
    scratch.len--;
    err = encrypt_oracle(&cipher, scratch);
    if (err) {
      error(err);
      goto end;
    }
    block_a = &(cipher.ptr[prefix_offset]);
    block_b = &(block_a[keylen]);
  } while (memcmp(block_a, block_b, keylen) == 0);
  prefixlen = prefix_offset - (scratch.len - (keylen * 2) + 1);
  plainlen -= prefixlen;

  /**
   * length of the plaintext is the length of the cipher, minus the length of
   * the scratch, minus the length of minus the pkcs7 padding which is a full keylength now
   */
  err = string_alloc(plain, plainlen);
  if (err) {
    goto end;
  }
  plainptr = plain->ptr;
  plainend = &(plain->ptr[plain->len]);

  /**
   * the scratch length is now:
   *   keylength + (keylength - 1) + (random bytes % keylength)
   * e.g. it occupies the remaining bytes of the last block occupied by the
   * random prefix, plus the next full block, plus 1 less than the next full
   * block. the full block is not needed, so we can subtract a keylength from
   * the scratch length and use that for the decoder length. however, the
   * scratch needs to be resized back up again
   */
  declen = scratch.len - keylen;
  err = string_alloc(&dec, declen);
  if (err) {
    goto end;
  }
  memset(dec.ptr, 'a', dec.len);

  err = string_resize(&scratch, dec.len + 1);
  if (err) {
    goto end;
  }

  while (plainptr < plainend) {
    int byte = -1;
    int c;

    err = encrypt_oracle(&enc, dec);
    if (err) {
      goto end;
    }

    /**
     * mimic encrypting the one byte short string, switching out the last
     * byte until it matches the encrypted string
     */
    for (c = 0; c <= UCHAR_MAX; c++) {
      scratch.ptr[scratch.len - 1] = (unsigned char)c;
      err = encrypt_oracle(&cipher, scratch);
      if (err) {
        goto end;
      }
      if (memcmp(cipher.ptr, enc.ptr, scratch.len + prefixlen) == 0) {
        byte = c;
        break;
      }
    }

    if (byte == -1) {
      /**
       * fail if we couldn't decode a byte, and we haven't reached the end of
       * the message
       */
      if (plainptr < plainend) {
        err = EDECRYPT;
      }
      break;
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
      dec.len = declen;
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

  err = init();
  if (err) {
    error(err);
    goto end;
  }

  err = file_read("data/c14_test.txt", &expected);
  if (err) {
    error(err);
    goto end;
  }

  err = challenge_14(&output);
  if (err) {
    error(err);
    goto end;
  }

  error_expect((const char *)expected.ptr, (const char *)output.ptr);

end:
  string_delete(expected);
  string_delete(output);
  string_delete(txt);
  string_delete(key);
  string_delete(pre);
  string_delete(tmpa);
  string_delete(tmpb);

  return err;
}
