/* Copyright (c) 2018 Brandon Freitag <freitagbr@gmail.com> */

#ifndef CRYPTOPALS_FILE_H_
#define CRYPTOPALS_FILE_H_

#include <stdio.h>

#include "cryptopals/error.h"
#include "cryptopals/string.h"

#define FILE_BUFLEN 512

error_t file_read(const char *file, string *str);

error_t file_getline(FILE *fp, string *str, long *read);

#endif /* CRYPTOPALS_FILE_H_ */
