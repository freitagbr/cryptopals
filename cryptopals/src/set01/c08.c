#include "file.h"
#include "hex.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

int challenge_08(const char *file) {
    unsigned char *buf = NULL;
    file_line *lines = NULL;
    file_line *curr = NULL;
    int nline = 0;
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

        printf("line: %d\tlength: %zu\taddr: %p\n", ++nline, curr->len, curr->line);
        for (size_t i = 0; i < linelen; i++) {
            printf("%x", line[i]);
        }
        printf("\n");

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
    assert(challenge_08("data/c08.txt") == 0);
}
