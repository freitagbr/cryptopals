#include "cryptopals/error.h"

#include <stdio.h>
#include <string.h>

static const char *error_messages[14] = {
    "Failed to allocate memory",                        // EMALLOC
    "Null pointer passed as argument",                  // ENULLPTR
    "Destination buffer is shorter than source buffer", // EDSTBUF
    "Buffer lengths do not match",                      // ESIZE
    "Failed to decode from base64",                     // EBASE64D
    "Failed to encode to base64",                       // EBASE64E
    "Failed to read past end of file",                  // EFEOF
    "Failed to open file",                              // EFOPEN
    "Failed to determine position in file",             // EFTELL
    "Failed to seek in file",                           // EFSEEK
    "Failed to read file",                              // EFREAD
    "Hex buffer contains invalid characters",           // EHEXCHAR
    "Buffer contains incomplete hex code point",        // EHEXLEN
    "OpenSSL error",                                    // EOPENSSL
};

void error_print(error_t e, const char *file, int line) {
    size_t err = (size_t) e;
    if (err && err <= __E__) {
        const char *message = error_messages[err - 1];
        fprintf(stderr, "Error in \"%s\" on line %d:\n\t%s\n", file, line, message);
    }
}

void error_expect(const char *expected, const char *found) {
    if (strcmp(expected, found) != 0) {
        fprintf(stderr, "Expected:\n\t%s\nFound:\n\t%s\n", expected, found);
    }
}
