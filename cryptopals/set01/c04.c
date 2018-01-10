/* Copyright (c) 2018 Brandon Freitag <freitagbr@gmail.com> */

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

#include "cryptopals/buffer.h"
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

error_t challenge_04(const char *file, buffer *dst) {
  FILE *fp = fopen(file, "rb");
  buffer buf = buffer_init();
  buffer line = buffer_init();
  buffer tmp = buffer_init();
  long read = 0;
  int global_max = 0;
  error_t err;

  while (((err = file_getline(fp, &buf, &read)) == 0) && ((read - 1) > 0)) {
    int local_max = 0;
    unsigned char key;

    buffer_set(tmp, buf.ptr, read - 1);

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
  buffer_delete(buf);
  buffer_delete(line);

  return err;
}

int main() {
  const unsigned char expected[] = "Now that the party is jumping\n";
  buffer output = buffer_init();
  error_t err;

  err = challenge_04("data/c04.txt", &output);
  if (err) {
    error(err);
    goto end;
  }

  error_expect((const char *)expected, (const char *)output.ptr);

end:
  buffer_delete(output);

  return (int)err;
}
