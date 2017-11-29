#include "file.h"

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int file_read(const char *file, unsigned char **buf, size_t *read) {
    FILE *fp = NULL;
    unsigned char *b = NULL;
    int status = 0;

    *read = 0;

    fp = fopen(file, "rb");
    if (fp == NULL) {
        goto end;
    }

    if (fseek(fp, 0, SEEK_END) == 0) {
        long buflen = ftell(fp);
        if (buflen == -1) {
            goto end;
        }

        b = *buf = (unsigned char *) malloc((sizeof (unsigned char) * buflen) + 1);
        if (b == NULL) {
            goto end;
        }

        if (fseek(fp, 0, SEEK_SET) != 0) {
            free((void *) b);
            goto end;
        }

        *read = fread(b, sizeof (unsigned char), buflen, fp);

        if (ferror(fp) != 0) {
            free((void *) b);
            *read = 0;
            goto end;
        }
    }

    b[*read] = '\0';
    status = 1;

end:
    if (fp != NULL) {
        fclose(fp);
    }

    return status;
}

int file_eachline(const char *file, file_eachline_cb_t *cb) {
    unsigned char *buf = NULL;
    unsigned char *line = NULL;
    size_t read = 0;
    int status = 0;

    if (!file_read(file, &buf, &read)) {
        goto end;
    }

    size_t i = 0;
    size_t j = 0;
    size_t len = 0;
    size_t allocated = 0;

    while (i < read) {
        while (buf[i] != '\n') {
            i++;
        }
        len = i - j;
        if (line == NULL) {
            allocated = (sizeof (unsigned char) * len) + 1;
            line = (unsigned char *) malloc(allocated);
            if (line == NULL) {
                goto end;
            }
            line[allocated] = '\0';
        }
        else if (len > allocated) {
            allocated = (sizeof (unsigned char) * len) + 1;
            line = (unsigned char *) realloc(line, allocated);
            if (line == NULL) {
                goto end;
            }
            line[allocated] = '\0';
        }
        memcpy(line, &buf[j], len);
        if (!(*cb)(line, len)) {
            goto end;
        }
        j = ++i;
    }

    status = 1;

end:
    if (buf != NULL) {
        free((void *) buf);
    }
    if (line != NULL) {
        free((void *) line);
    }

    return status;
}
