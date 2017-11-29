#ifndef FILE_H
#define FILE_H

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef int (*file_eachline_cb_t)(unsigned char *line, size_t len);

int file_read(const char *file, unsigned char **buf, size_t *read);

int file_eachline(const char *file, file_eachline_cb_t *cb);

#endif
