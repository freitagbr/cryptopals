#define _GNU_SOURCE

#include "hex.h"
#include "xor.h"

#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LINE_LENGTH 30

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
    FILE *fp;
    char *line = NULL;
    size_t len = 0;
    ssize_t read;

    fp = fopen(file, "r");

    if (fp == NULL) {
        return -1;
    }

    int global_max = 0;
    unsigned char src[LINE_LENGTH];

    while ((read = getline(&line, &len, fp)) != -1) {
        for (int i = 0, s = 0; i < 60; i += 2, s += 1) {
            int r = sscanf((const char *) &line[i], "%2hhx", (unsigned char *) &src[s]);
            if (r != 1) {
                fclose(fp);
                return -1;
            }
        }

        int local_max = 0;
        unsigned char key = xor_find_english_cipher(src, LINE_LENGTH, &local_max);

        if (local_max > global_max) {
            global_max = local_max;
            if (!xor_single_byte(src, LINE_LENGTH, dst, key)) {
                fclose(fp);
                if (line) {
                    free((void *) line);
                }
                return -1;
            }
        }
    }

    fclose(fp);

    if (line) {
        free((void *) line);
    }

    return 0;
}

int main() {
    const unsigned char expected[] = "Now that the party is jumping\n";
    unsigned char *output = NULL;

    assert(challenge_04("data/c04.txt", &output) == 0);
    assert(strcmp((const char *) output, (const char *) expected) == 0);

    free((void *) output);
}
