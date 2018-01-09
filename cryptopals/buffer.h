#ifndef CRYPTOPALS_BUFFER_H_
#define CRYPTOPALS_BUFFER_H_

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include "cryptopals/error.h"

typedef struct buffer {
    uint8_t *ptr;
    size_t len;
} buffer;

#define buffer_init() \
    (buffer) {NULL, 0}

#define buffer_new(p, l) \
    (buffer) {(uint8_t *) p, l}

#define buffer_delete(buf) \
    if (buf.ptr != NULL) { \
        free((void *) buf.ptr); \
    }

error_t buffer_alloc(buffer *buf, size_t len);

error_t buffer_resize(buffer *buf, size_t len);

#endif // CRYPTOPALS_BUFFER_H_
