#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#include "hex.h"
#include "score.h"
#include "../error.h"

int main(int argc, char **argv) {
    if (argc != 2) {
        return error("one argument required");
    }

    std::ifstream file(argv[1]);
    std::string line;
    std::vector<uint8_t> global_bytes;
    int global_max = 0;
    uint8_t global_key = 0;

    while (std::getline(file, line)) {
        const std::vector<uint8_t> local_bytes = hex::parse(line);
        int local_max = 0;
        uint8_t local_key = 0;

        for (int k = 0; k <= 0xFF; k++) {
            int s = score(local_bytes, static_cast<uint8_t>(k));
            if (s > local_max) {
                local_max = s;
                local_key = static_cast<uint8_t>(k);
            }
        }

        if (local_max > global_max) {
            global_bytes = local_bytes;
            global_max = local_max;
            global_key = local_key;
        }
    }

    for (const uint8_t &b : global_bytes) {
        std::cout << static_cast<uint8_t>(b ^ global_key);
    }

    std::cout << std::endl;
}
