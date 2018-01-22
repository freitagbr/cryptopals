/* Copyright (c) 2018 Brandon Freitag <freitagbr@gmail.com> */

#ifndef CRYPTOPALS_ERROR_H_
#define CRYPTOPALS_ERROR_H_

#include <stdio.h>
#include <string.h>

typedef enum {
  EMALLOC = 1, /* Failed to allocate memory */
  ENULLPTR,    /* Null pointer passed as argument */
  EDSTBUF,     /* Destination buffer is shorter than source buffer */
  ESIZE,       /* Buffer lengths do not match */
  EBASE64D,    /* Failed to decode from base64 */
  EBASE64E,    /* Failed to encode to base64 */
  EFEOF,       /* Failed to read past end of file */
  EFOPEN,      /* Failed to open file */
  EFTELL,      /* Failed to determine position in file */
  EFSEEK,      /* Failed to seek in file */
  EFREAD,      /* Failed to read file */
  EHEXCHAR,    /* Hex buffer contains invalid characters */
  EHEXLEN,     /* Buffer contains incomplete hex code point */
  EAESKEY,     /* AES Key could not be set */
  EAESPKCS7,   /* Invalid PKCS7 padding */
  ERAND,       /* Could not get random bytes */
  __E__
} error_t;

#define error(e) error_print(e, __FILE__, __LINE__)

void error_print(error_t e, const char *file, int line);

void error_expect(const char *expected, const char *found);

#endif /* CRYPTOPALS_ERROR_H_ */
