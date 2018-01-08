#ifndef CRYPTOPALS_ERROR_H_
#define CRYPTOPALS_ERROR_H_

#include <stdio.h>

typedef enum {
    EMALLOC = 1,
    EDSTBUF,
    ESIZE,
    EBASE64D,
    EBASE64E,
    EFOPEN,
    EFTELL,
    EFSEEK,
    EFREAD,
    EHEXCHAR,
    EHEXLEN,
    EOPENSSL,
    E_,
} error_t;

#define error(e) error_print(e, __FILE__, __LINE__)

void error_print(error_t e, const char *file, int line);

void error_expect(const char *expected, const char *found);

#endif // CRYPTOPALS_ERROR_H_
