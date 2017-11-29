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

int handle_line(unsigned char *line, size_t len) {
    unsigned char *buf = NULL;
    size_t buflen = 0;

    if (!hex_decode(line, len, &buf, &buflen)) {
        return 0;
    }

    printf("line: ");
    for (size_t i = 0; i < buflen; i++) {
        printf("%x", buf[i]);
    }
    printf("\n");

    free((void *) buf);

    return 1;
}


int challenge_08(const char *file) {
    file_eachline_cb_t cb = &handle_line;

    if (!file_eachline(file, &cb)) {
        return -1;
    }

    return 0;
}

int main() {
    assert(challenge_08("data/c08.txt") == 0);
}
