#include <iostream>
#include <string>
#include <vector>

#include "base64.h"
#include "hex.h"
#include "../error.h"

int main(int argc, char **argv) {
    if (argc != 2) {
        return error("one argument required");
    }

    const std::string src(argv[1]);
    const std::vector<uint8_t> bytes = hex::parse(src);
    std::string dst;

    if (!base64::encode(bytes, &dst)) {
        return error("encoding error");
    }

    std::cout << dst << std::endl;
}
