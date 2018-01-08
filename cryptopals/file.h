#ifndef CRYPTOPALS_FILE_H_
#define CRYPTOPALS_FILE_H_

#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#include "cryptopals/error.h"

typedef struct file_line {
    struct file_line *next;
    uint8_t *line;
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

error_t file_read(const char *file, uint8_t **buf, size_t *read);

error_t file_getlines(const char *file, uint8_t **buf, file_line **lines);

#endif // CRYPTOPALS_FILE_H_
