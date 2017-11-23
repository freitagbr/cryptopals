#include <iostream>
#include <string>
#include <vector>

#include "hex.h"
#include "../error.h"

int main(int argc, char **argv) {
    if (argc != 3) {
        return error("two arguments required");
    }

    const std::string a(argv[1]);
    const std::string b(argv[2]);

    if (a.length() != b.length()) {
        return error("inputs must be the same length");
    }

    const std::vector<uint8_t> va = hex::parse(a);
    const std::vector<uint8_t> vb = hex::parse(b);

    for (size_t i = 0; i < va.size(); i++) {
        std::cout << std::hex << ((int) (va[i] ^ vb[i]));
    }

    std::cout << std::endl;
}
