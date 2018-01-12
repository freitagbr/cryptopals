/* Copyright (c) 2018 Brandon Freitag <freitagbr@gmail.com> */

#ifndef CRYPTOPALS_FILE_H_
#define CRYPTOPALS_FILE_H_

#include <stddef.h>
#include <stdio.h>

#include "cryptopals/buffer.h"
#include "cryptopals/error.h"

#define FILE_BUFLEN 512

error_t file_read(const char *file, buffer *buf);

error_t file_getline(FILE *fp, buffer *buf, long *read);

#endif /* CRYPTOPALS_FILE_H_ */
