#include "cryptopals/error.h"

#include <stdio.h>
#include <string.h>

static const char *error_messages[12] = {
    "Failed to allocate memory",
    "Destination buffer is shorter than source buffer",
    "Buffer lengths do not match",
    "Failed to decode from base64",
    "Failed to encode to base64",
    "Failed to open file",
    "Failed to determine position in file",
    "Failed to seek in file",
    "Failed to read file",
    "Hex buffer contains invalid characters",
    "Buffer contains incomplete hex code point",
    "OpenSSL error",
};

void error_print(error_t e, const char *file, int line) {
    size_t err = (size_t) e;
    if (err && err <= E_) {
        const char *message = error_messages[err - 1];
        fprintf(stderr, "Error in \"%s\" on line %d:\n\t%s\n", file, line, message);
    }
}

void error_expect(const char *expected, const char *found) {
    if (strcmp(expected, found) != 0) {
        fprintf(stderr, "Expected:\n\t%s\nFound:\n\t%s\n", expected, found);
    }
}
