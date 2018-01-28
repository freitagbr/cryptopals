/* Copyright (c) 2018 Brandon Freitag <freitagbr@gmail.com> */

#include <stdio.h>

#include "cryptopals/string.h"
#include "cryptopals/error.h"
#include "cryptopals/file.h"
#include "cryptopals/hex.h"
#include "cryptopals/xor.h"

/**
 * Detect single-character XOR
 *
 * One of the 60-character strings in this file has been encrypted by single-
 * character XOR.
 *
 * Find it.
 *
 * (Your code from #3 should help.)
 */

error_t challenge_04(const char *file, string *dst) {
  FILE *fp = fopen(file, "rb");
  string str = string_init();
  string line = string_init();
  string tmp = string_init();
  long read = 0;
  int global_max = 0;
  error_t err;

  while (((err = file_getline(fp, &str, &read)) == 0) && ((read - 1) > 0)) {
    int local_max = 0;
    unsigned char key;

    string_set(tmp, str.ptr, read - 1);

    err = hex_decode(&line, tmp);
    if (err) {
      goto end;
    }

    key = xor_find_cipher(line, &local_max);

    if (local_max > global_max) {
      global_max = local_max;
      err = xor_single_byte(dst, line, key);
      if (err) {
        goto end;
      }
    }
  }

end:
  if (fp != NULL) {
    fclose(fp);
  }
  string_delete(str);
  string_delete(line);

  return err;
}

int main() {
  const char expected[] = "Now that the party is jumping\n";
  string output = string_init();
  error_t err;

  err = challenge_04("data/c04.txt", &output);
  if (err) {
    error(err);
    goto end;
  }

  error_expect(expected, (const char *)output.ptr);

end:
  string_delete(output);

  return (int)err;
}
