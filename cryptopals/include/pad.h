#ifndef PAD_H
#define PAD_H

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int pad_bytes(uint8_t **dst, const size_t dstlen, const uint8_t *src, const size_t srclen, const uint8_t iv);

#endif // PAD_H
