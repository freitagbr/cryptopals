#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "hex.h"
#include "score.h"

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
    unsigned char src[30];
    *dst = (unsigned char *) malloc(sizeof (unsigned char) * 30);

    while ((read = getline(&line, &len, fp)) != -1) {
        for (int i = 0, s = 0; i < 60; i += 2, s += 1) {
            int r = sscanf((const char *) &line[i], "%2hhx", (unsigned char *) &src[s]);
            if (r != 1) {
                fclose(fp);
                return -1;
            }
        }

        int local_max = 0;
        unsigned char key = 0;

        for (int k = 0; k <= 0xFF; ++k) {
            int s = score_english(src, 30, (unsigned char) k);
            if (s > local_max) {
                local_max = s;
                key = (unsigned char) k;
            }
        }

        if (local_max > global_max) {
            global_max = local_max;
            for (int i = 0; i < 30; ++i) {
                (*dst)[i] = src[i] ^ key;
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
}
