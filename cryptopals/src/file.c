#include "file.h"

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

int file_read(const char *file, unsigned char **buf, size_t *read) {
    FILE *fp = NULL;
    unsigned char *b = NULL;
    int status = 0;

    *read = 0;

    fp = fopen(file, "rb");
    if (fp == NULL) {
        goto end;
    }

    if (fseek(fp, 0, SEEK_END) == 0) {
        long buflen = ftell(fp);
        if (buflen == -1) {
            goto end;
        }

        b = *buf = (unsigned char *) malloc((sizeof (unsigned char) * buflen) + 1);
        if (b == NULL) {
            goto end;
        }

        if (fseek(fp, 0, SEEK_SET) != 0) {
            free((void *) b);
            goto end;
        }

        *read = fread(b, sizeof (unsigned char), buflen, fp);

        if (ferror(fp) != 0) {
            free((void *) b);
            *read = 0;
            goto end;
        }
    }

    b[*read] = '\0';
    status = 1;

end:
    if (fp != NULL) {
        fclose(fp);
    }

    return status;
}
