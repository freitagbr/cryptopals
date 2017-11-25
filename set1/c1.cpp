#include <iostream>
#include <string>
#include <vector>

#include "base64.h"
#include "../error.h"

int main(int argc, char **argv) {
    if (argc != 2) {
        return error("one argument required");
    }

    std::string hex(argv[1]);
    std::vector<uint8_t> bytes;
    size_t i = 0;

    while (i < hex.length()) {
        const char *chars = hex.substr(i, 2).c_str();
        const uint8_t byte = (uint8_t) strtol(chars, nullptr, 16);
        bytes.push_back(byte);
        i += 2;
    }

    std::string dst;

    if (!base64::encode(bytes, &dst)) {
        return error("encoding error");
    }

    std::cout << dst << std::endl;
}
