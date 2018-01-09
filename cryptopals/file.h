#ifndef CRYPTOPALS_FILE_H_
#define CRYPTOPALS_FILE_H_

#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#include "cryptopals/error.h"

#define FILE_BUFLEN 512

error_t file_read(const char *file, uint8_t **buf, size_t *read);

error_t file_getline(FILE *fp, uint8_t **line, size_t *len, long *read);

#endif // CRYPTOPALS_FILE_H_
