#ifndef FILE_H
#define FILE_H

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

int file_read(const char *file, unsigned char **buf, size_t *read);

#endif
