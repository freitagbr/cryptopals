#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

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

error_t challenge_04(const char *file, uint8_t **dst) {
    FILE *fp = fopen(file, "rb");
    uint8_t *buf = NULL;
    uint8_t *line = NULL;
    size_t buflen = 0;
    size_t linelen = 0;
    long read = 0;
    int global_max = 0;
    error_t err = 0;

    while (((err = file_getline(fp, &buf, &buflen, &read)) == 0) && ((read - 1) > 0)) {
        err = hex_decode(&line, &linelen, buf, read - 1);
        if (err) {
            goto end;
        }

        int local_max = 0;
        uint8_t key = xor_find_cipher(line, linelen, &local_max);

        if (local_max > global_max) {
            global_max = local_max;
            err = xor_single_byte(dst, line, linelen, key);
            if (err) {
                goto end;
            }
        }
    }

end:
    if (fp != NULL) {
        fclose(fp);
    }
    if (buf != NULL) {
        free((void *) buf);
    }
    if (line != NULL) {
        free((void *) line);
    }

    return err;
}

int main() {
    const uint8_t expected[] = "Now that the party is jumping\n";
    uint8_t *output = NULL;
    error_t err = 0;

    err = challenge_04("data/c04.txt", &output);
    if (err) {
        error(err);
        goto end;
    }

    error_expect((const char *) expected, (const char *) output);

end:
    free((void *) output);

    return (int) err;
}
