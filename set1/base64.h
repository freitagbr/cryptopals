#ifndef BASE64_H
#define BASE64_H

#include <string>
#include <vector>

namespace base64 {
    static const char encode_table[] = {
        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
        'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
        'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
        'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
        'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
        'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
        'w', 'x', 'y', 'z', '0', '1', '2', '3',
        '4', '5', '6', '7', '8', '9', '+', '/',
    };

    static const char decode_table[] = {
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63,
        52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1,
        -1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
        15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1,
        -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
        41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    };

    static int decoded_length(const char *in, size_t in_length) {
        int eqs = 0;
        const char *in_end = in + in_length;

        while (*--in_end == '=') {
            ++eqs;
        }

        return ((in_length * 6) / 8) - eqs;
    }

    static int decoded_length(const std::string &in) {
        int eqs = 0;
        int n = in.size();

        for (std::string::const_reverse_iterator it = in.rbegin(); *it == '='; ++it) {
            ++eqs;
        }

        return ((n * 6) / 8) - eqs;
    }

    inline static int encoded_length(size_t length) {
        return (length + 2 - ((length + 2) % 3)) / 3 * 4;
    }

    inline static int encoded_length(const std::vector<uint8_t> &in) {
        return encoded_length(in.size());
    }

    inline static int encoded_length(const std::string &in) {
        return encoded_length(in.size());
    }

    static inline void btoa(uint8_t *a, uint8_t *b) {
        a[0] =  (b[0] & 0xfc) >> 2;
        a[1] = ((b[0] & 0x03) << 4) + ((b[1] & 0xf0) >> 4);
        a[2] = ((b[1] & 0x0f) << 2) + ((b[2] & 0xc0) >> 6);
        a[3] =  (b[2] & 0x3f);
    }

    static inline void atob(uint8_t *b, uint8_t *a) {
        b[0] =  (a[0]        << 2) + ((a[1] & 0x30) >> 4);
        b[1] = ((a[1] & 0xf) << 4) + ((a[2] & 0x3c) >> 2);
        b[2] = ((a[2] & 0x3) << 6) +   a[3];
    }

    static bool encode(const std::vector<uint8_t> &in, std::string *out) {
        int i = 0;
        int j = 0;
        size_t enc_len = 0;
        uint8_t b[3];
        uint8_t a[4];

        out->resize(encoded_length(in));

        int input_len = in.size();
        std::vector<uint8_t>::const_iterator input = in.begin();

        while (input_len--) {
            b[i++] = *(input++);
            if (i == 3) {
                btoa(a, b);

                (*out)[enc_len++] = encode_table[a[0]];
                (*out)[enc_len++] = encode_table[a[1]];
                (*out)[enc_len++] = encode_table[a[2]];
                (*out)[enc_len++] = encode_table[a[3]];

                i = 0;
            }
        }

        if (i) {
            for (j = i; j < 3; j++) {
                b[j] = '\0';
            }

            btoa(a, b);

            for (j = 0; j < i + 1; j++) {
                (*out)[enc_len++] = encode_table[a[j]];
            }

            while ((i++ < 3)) {
                (*out)[enc_len++] = '=';
            }
        }

        return (enc_len == out->size());
    }

    static bool encode(const std::string &in, std::string *out) {
        int i = 0;
        int j = 0;
        size_t enc_len = 0;
        uint8_t b[3];
        uint8_t a[4];

        out->resize(encoded_length(in));

        int input_len = in.size();
        std::string::const_iterator input = in.begin();

        while (input_len--) {
            b[i++] = *(input++);
            if (i == 3) {
                btoa(a, b);

                (*out)[enc_len++] = encode_table[a[0]];
                (*out)[enc_len++] = encode_table[a[1]];
                (*out)[enc_len++] = encode_table[a[2]];
                (*out)[enc_len++] = encode_table[a[3]];

                i = 0;
            }
        }

        if (i) {
            for (j = i; j < 3; j++) {
                b[j] = '\0';
            }

            btoa(a, b);

            for (j = 0; j < i + 1; j++) {
                (*out)[enc_len++] = encode_table[a[j]];
            }

            while ((i++ < 3)) {
                (*out)[enc_len++] = '=';
            }
        }

        return (enc_len == out->size());
    }

    static bool encode(const char *input, size_t input_length, char *out, size_t out_length) {
        int i = 0, j = 0;
        char *out_begin = out;
        uint8_t b[3];
        uint8_t a[4];

        size_t encoded_len = encoded_length(input_length);

        if (out_length < encoded_len) {
            return false;
        }

        while (input_length--) {
            b[i++] = *input++;
            if (i == 3) {
                btoa(a, b);

                *out++ = encode_table[a[0]];
                *out++ = encode_table[a[1]];
                *out++ = encode_table[a[2]];
                *out++ = encode_table[a[3]];

                i = 0;
            }
        }

        if (i) {
            for (j = i; j < 3; j++) {
                b[j] = '\0';
            }

            btoa(a, b);

            for (j = 0; j < i + 1; j++) {
                *out++ = encode_table[a[j]];
            }

            while ((i++ < 3)) {
                *out++ = '=';
            }
        }

        return (out == (out_begin + encoded_len));
    }

    static bool decode(const std::string &in, std::string *out) {
        int i = 0, j = 0;
        size_t dec_len = 0;
        uint8_t b[3];
        uint8_t a[4];

        int input_len = in.size();
        std::string::const_iterator input = in.begin();

        out->resize(decoded_length(in));

        while (input_len--) {
            if (*input == '=') {
                break;
            }

            a[i++] = *(input++);
            if (i == 4) {
                a[0] = decode_table[a[0]];
                a[1] = decode_table[a[1]];
                a[2] = decode_table[a[2]];
                a[3] = decode_table[a[3]];

                atob(b, a);

                (*out)[dec_len++] = b[0];
                (*out)[dec_len++] = b[1];
                (*out)[dec_len++] = b[2];

                i = 0;
            }
        }

        if (i) {
            for (j = i; j < 4; j++) {
                a[j] = '\0';
            }

            a[0] = decode_table[a[0]];
            a[1] = decode_table[a[1]];
            a[2] = decode_table[a[2]];
            a[3] = decode_table[a[3]];

            atob(b, a);

            for (j = 0; j < i - 1; j++) {
                (*out)[dec_len++] = b[j];
            }
        }

        return (dec_len == out->size());
    }

    static bool decode(const char *input, size_t input_length, char *out, size_t out_length) {
        int i = 0, j = 0;
        char *out_begin = out;
        uint8_t b[3];
        uint8_t a[4];

        size_t decoded_len = decoded_length(input, input_length);

        if (out_length < decoded_len) {
            return false;
        }

        while (input_length--) {
            if (*input == '=') {
                break;
            }

            a[i++] = *(input++);
            if (i == 4) {
                a[0] = decode_table[a[0]];
                a[1] = decode_table[a[1]];
                a[2] = decode_table[a[2]];
                a[3] = decode_table[a[3]];

                atob(b, a);

                *out++ = b[0];
                *out++ = b[1];
                *out++ = b[2];

                i = 0;
            }
        }

        if (i) {
            for (j = i; j < 4; j++) {
                a[j] = '\0';
            }

            a[0] = decode_table[a[0]];
            a[1] = decode_table[a[1]];
            a[2] = decode_table[a[2]];
            a[3] = decode_table[a[3]];

            atob(b, a);

            for (j = 0; j < i - 1; j++) {
                *out++ = b[j];
            }
        }

        return (out == (out_begin + decoded_len));
    }
}; // namespace base64

#endif // BASE64_H
