/* Copyright (c) 2018 Brandon Freitag <freitagbr@gmail.com> */

#include <float.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "cryptopals/block.h"
#include "cryptopals/string.h"
#include "cryptopals/error.h"
#include "cryptopals/file.h"
#include "cryptopals/hex.h"

/**
 * Detect AES in ECB mode
 *
 * In this file are a bunch of hex-encoded ciphertexts.
 *
 * One of them has been encrypted with ECB.
 *
 * Detect it.
 *
 * Remember that the problem with ECB is that it is stateless and
 * deterministic; the same 16 byte plaintext block will always produce the same
 * 16 byte ciphertext.
 */

error_t challenge_08(const char *file, string *dst) {
  FILE *fp = fopen(file, "rb");
  string str = string_init();
  string line = string_init();
  string aes = string_init();
  string tmp = string_init();
  float global_min_dist = FLT_MAX;
  long read = 0;
  error_t err;

  while (((err = file_getline(fp, &str, &read)) == 0) && ((read - 1) > 0)) {
    float local_min_dist = 0.0;
    size_t local_max_keysize;

    string_set(tmp, str.ptr, read - 1);

    err = hex_decode(&line, tmp);
    if (err) {
      goto end;
    }

    local_max_keysize = line.len / 2;
    block_keysize(line, &local_min_dist, local_max_keysize);

    if (local_min_dist < global_min_dist) {
      global_min_dist = local_min_dist;
      if ((aes.ptr == NULL) && (aes.len == 0)) {
        err = string_alloc(&aes, read - 1);
        if (err) {
          goto end;
        }
      } else if ((size_t)read > aes.len) {
        err = string_resize(&aes, read - 1);
        if (err) {
          goto end;
        }
      }
      if (aes.ptr != NULL) {
        memcpy(aes.ptr, str.ptr, aes.len);
      }
    }
  }

  if (err) {
    goto end;
  }

  if (aes.ptr != NULL) {
    err = string_alloc(dst, aes.len);
    if (err) {
      goto end;
    }
    memcpy(dst->ptr, aes.ptr, dst->len);
  }

end:
  if (fp != NULL) {
    fclose(fp);
  }
  string_delete(str);
  string_delete(line);
  string_delete(aes);

  return err;
}

int main() {
  const char expected[] =
      "d880619740a8a19b7840a8a31c810a3d08649af70"
      "dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4"
      "fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d"
      "69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744"
      "cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a";
  string output = string_init();
  error_t err;

  err = challenge_08("data/c08.txt", &output);
  if (err) {
    error(err);
    goto end;
  }

  if (output.len != 320) {
    error(ESIZE);
    goto end;
  }

  error_expect(expected, (const char *)output.ptr);

end:
  string_delete(output);

  return (int)err;
}
