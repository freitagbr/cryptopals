#ifndef PAD_H
#define PAD_H

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

int pad_bytes(unsigned char **dst, const size_t dstlen, const unsigned char *src, const size_t srclen, const unsigned char iv);

#endif // PAD_H
