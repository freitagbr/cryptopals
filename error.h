#ifndef ERROR_H
#define ERROR_H

#include <iostream>
#include <cstdlib>

inline int error(const char *msg) {
    std::cerr << msg << std::endl;
    return EXIT_FAILURE;
}

#endif // ERROR_H
