#include "file.h"
#include "hex.h"
#include "xor.h"

#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

int challenge_04(const char *file, unsigned char **dst) {
    unsigned char *buf = NULL;
    file_line *lines = NULL;
    file_line *curr = NULL;
    int global_max = 0;
    int status = -1;

    if (!file_getlines(file, &buf, &lines)) {
        goto end;
    }

    curr = lines;

    while (curr != NULL) {
        unsigned char *line = NULL;
        size_t linelen = 0;

        if (!hex_decode(curr->line, curr->len, &line, &linelen)) {
            goto end;
        }

        int local_max = 0;
        unsigned char key = xor_find_cipher(line, linelen, &local_max);

        if (local_max > global_max) {
            global_max = local_max;
            if (!xor_single_byte(line, linelen, dst, key)) {
                free((void *) line);
                goto end;
            }
        }

        free((void *) line);
        curr = curr->next;
    }

    status = 0;

end:
    if (buf != NULL) {
        free((void *) buf);
    }
    file_line_delete(lines);

    return status;
}

int main() {
    const unsigned char expected[] = "Now that the party is jumping\n";
    unsigned char *output = NULL;

    assert(challenge_04("data/c04.txt", &output) == 0);
    assert(strcmp((const char *) output, (const char *) expected) == 0);

    free((void *) output);
}
