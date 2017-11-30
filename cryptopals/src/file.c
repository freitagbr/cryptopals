#include "file.h"

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

void file_line_delete(file_line *lines) {
    file_line *next = NULL;
    while (lines != NULL) {
        next = lines->next;
        free((void *) lines);
        lines = next;
    }
}

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

int file_getlines(const char *file, unsigned char **buf, file_line **lines) {
    file_line **pp = &(*lines);
    size_t read = 0;
    int status = 0;

    if (!file_read(file, buf, &read)) {
        goto end;
    }

    size_t len = 0;
    size_t i = 0;
    size_t j = 0;

    // use forward-chaining to create a linked list of
    // structures that contain a pointer to the beginning
    // of each line and the length of the line
    while (i < read) {
        while ((*buf)[i] != '\n') {
            i++;
        }
        len = i - j;
        *pp = file_line_new();
        if (*pp == NULL) {
            goto end;
        }
        (*pp)->line = &(*buf)[j];
        (*pp)->len = len;
        pp = &(*pp)->next;
        j = ++i;
    }

    // end list
    *pp = NULL;
    status = 1;

end:
    return status;
}
