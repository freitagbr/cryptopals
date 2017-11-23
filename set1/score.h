#ifndef SCORE_H
#define SCORE_H

#include <string>

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

#endif // SCORE_H
