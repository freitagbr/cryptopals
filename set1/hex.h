#ifndef HEX_H
#define HEX_H

#include <vector>

namespace hex {
    inline std::vector<uint8_t> parse(const std::string &src) {
        std::vector<uint8_t> bytes;
        size_t i = 0;

        while (i < src.length()) {
            const char *chars = src.substr(i, 2).c_str();
            const uint8_t byte = (uint8_t) strtol(chars, nullptr, 16);
            bytes.push_back(byte);
            i += 2;
        }

        return bytes;
    }
}; // namespace hex

#endif // HEX_H
