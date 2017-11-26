#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "hex.h"
#include "score.h"
#include "error.h"

int main(int argc, char **argv) {
    if (argc != 2) {
        return error("one argument required");
    }

    FILE *fp;
    char *line = NULL;
    size_t len = 0;
    ssize_t read;

    fp = fopen(argv[1], "r");

    if (fp == NULL) {
        return error("file error");
    }

    int global_max = 0;
    unsigned char src[30];
    unsigned char dst[30];

    while ((read = getline(&line, &len, fp)) != -1) {
        for (int i = 0, s = 0; i < 60; i += 2, s += 1) {
            int r = sscanf((const char *) &line[i], "%2hhx", (unsigned char *) &src[s]);
            if (r != 1) {
                fclose(fp);
                return error("input must be a valid hex string");
            }
        }

        int local_max = 0;
        unsigned char key = 0;

        for (int k = 0; k <= 0xFF; ++k) {
            int s = score(src, 30, (unsigned char) k);
            if (s > local_max) {
                local_max = s;
                key = (unsigned char) k;
            }
        }

        if (local_max > global_max) {
            global_max = local_max;
            for (int i = 0; i < 30; ++i) {
                dst[i] = src[i] ^ key;
            }
        }
    }

    printf("%s\n", dst);

    fclose(fp);

    if (line) {
        free((void *) line);
    }

    return EXIT_SUCCESS;
}