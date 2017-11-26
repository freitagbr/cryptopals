#ifndef ERROR_H
#define ERROR_H

#include <stdlib.h>
#include <stdio.h>

int error(const char *msg) {
    fprintf(stderr, "%s\n", msg);
    return EXIT_FAILURE;
}

#endif // ERROR_H
