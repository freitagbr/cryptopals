#include <iomanip>
#include <iostream>
#include <string>

#include "../error.h"

static const std::string key("ICE");

int main(int argc, char **argv) {
    if (argc != 2) {
        return error("one argument required");
    }

    const std::string src(argv[1]);
    int k = 0;

    std::cout << std::setw(2) << std::setfill('0');

    for (const uint8_t &c : src) {
        std::cout << std::hex << static_cast<int>(c ^ static_cast<uint8_t>(key[k]));
        k = (k + 1) % 3;
    }

    std::cout << std::endl;
}
