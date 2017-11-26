#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "hex.h"
#include "../error.h"

int main(int argc, char **argv) {
    if (argc != 3) {
        return error("two arguments required");
    }

    const unsigned char *a_inp = (unsigned char *) argv[1];
    const unsigned char *b_inp = (unsigned char *) argv[2];
    const size_t alen = strlen((const char *) a_inp);
    const size_t blen = strlen((const char *) b_inp);

    if (alen != blen) {
        return error("inputs must the same length");
    }

    if (((alen % 2) != 0) || ((blen % 2) != 0)) {
        return error("inputs must be valid hex strings");
    }

    const size_t len = hex_decoded_length(alen);
    unsigned char *a = (unsigned char *) malloc(sizeof (unsigned char) * len);
    unsigned char *b = (unsigned char *) malloc(sizeof (unsigned char) * len);

    if (!hex_decode(a_inp, alen, a, len) || !hex_decode(b_inp, blen, b, len)) {
        return error("inputs must be valid hex strings");
    }

    for (size_t i = 0; i < len; i++) {
        a[i] = a[i] ^ b[i];
    }

    const size_t clen = hex_encoded_length(len);
    unsigned char *c = (unsigned char *) malloc(sizeof (unsigned char) * clen);

    hex_encode(a, len, c, clen);

    printf("%s\n", c);
    free((void *) a);
    free((void *) b);
    free((void *) c);

    return EXIT_SUCCESS;
}
