#ifndef FILE_H
#define FILE_H

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

typedef struct file_line {
    struct file_line *next;
    unsigned char *line;
    size_t len;
} file_line;

static inline file_line *file_line_new() {
    file_line *line = (file_line *) calloc(1, sizeof (file_line));
    if (line == NULL) {
        return NULL;
    }
    line->next = NULL;
    line->line = NULL;
    line->len = 0;
    return line;
}

void file_line_delete(file_line *lines);

int file_read(const char *file, unsigned char **buf, size_t *read);

int file_getlines(const char *file, unsigned char **buf, file_line **lines);

#endif
