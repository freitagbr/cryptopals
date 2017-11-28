#include "file.h"

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

int file_read(const char *file, unsigned char **buf, size_t *read) {
    FILE *fp = fopen(file, "rb");

    if (fp == NULL) {
        return 0;
    }

    if (fseek(fp, 0, SEEK_END) == 0) {
        long buflen = ftell(fp);
        if (buflen == -1) {
            fclose(fp);
            return 0;
        }

        *buf = (unsigned char *) malloc((sizeof (unsigned char) * buflen) + 1);

        if (*buf == NULL) {
            fclose(fp);
            return 0;
        }

        if (fseek(fp, 0, SEEK_SET) != 0) {
            free((void *) *buf);
            fclose(fp);
            return 0;
        }

        *read = fread(*buf, sizeof (unsigned char), buflen, fp);

        if (ferror(fp) != 0) {
            free((void *) *buf);
            fclose(fp);
            return 0;
        }
    }

    fclose(fp);
    (*buf)[*read] = '\0';

    return 1;
}
