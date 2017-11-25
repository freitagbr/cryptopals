#include <iostream>
#include <string>
#include <vector>

#include "hex.h"
#include "../error.h"

static const std::string freq("etaoin shrdlu");

inline int score(const std::vector<uint8_t> &vec, uint8_t key) {
    int s = 0;
    for (const uint8_t &c : freq) {
        for (const uint8_t &v : vec) {
            if ((v ^ key) == c) {
                s++;
            }
        }
    }
    return s;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        return error("one argument required");
    }

    const std::string src(argv[1]);
    const std::vector<uint8_t> bytes = hex::parse(src);

    int max_score = 0;
    uint8_t key = 0;

    for (int k = 0; k <= 0xFF; k++) {
        int s = score(bytes, static_cast<uint8_t>(k));
        if (s > max_score) {
            max_score = s;
            key = static_cast<uint8_t>(k);
        }
    }

    for (const uint8_t &b : bytes) {
        std::cout << static_cast<uint8_t>(b ^ key);
    }

    std::cout << std::endl;
}
