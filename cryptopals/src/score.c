#include "score.h"

int score(const unsigned char *str, const size_t len, unsigned char key) {
    int s = 0;
    for (int i = 0; i < 13; i++) {
        unsigned char c = score_freq[i];
        for (size_t l = 0; l < len; l++) {
            if ((str[l] ^ key) == c) {
                s++;
            }
        }
    }
    return s;
}
