#include "base64.h"
#include "file.h"

#include <openssl/evp.h>

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/**
 * AES in ECB mode
 *
 * The Base64-encoded content in this file has been encrypted via AES-128 in ECB
 * mode under the key
 *
 * "YELLOW SUBMARINE".
 *
 * (case-sensitive, without the quotes; exactly 16 characters; I like "YELLOW
 * SUBMARINE" because it's exactly 16 bytes long, and now you do too).
 *
 * Decrypt it. You know the key, after all.
 *
 * Easiest way: use OpenSSL::Cipher and give it AES-128-ECB as the cipher.
 */

int challenge_07(const char *file, const uint8_t *key, uint8_t **plaintext, int *plaintextlen) {
    EVP_CIPHER_CTX *ctx = NULL;
    uint8_t *ciphertext = NULL;
    size_t ciphertextlen = 0;
    int len = 0;
    int status = -1;

    if (!base64_decode_file(file, &ciphertext, &ciphertextlen)) {
        goto end;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        goto end;
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL) != 1) {
        goto end;
    }

    uint8_t *p = *plaintext = (uint8_t *) calloc(ciphertextlen + 1, sizeof (uint8_t));
    if (p == NULL) {
        goto end;
    }

    if (EVP_DecryptUpdate(ctx, p, &len, ciphertext, ciphertextlen) != 1) {
        goto end;
    }

    *plaintextlen = len;

    if (EVP_DecryptFinal_ex(ctx, &p[len], &len) != 1) {
        goto end;
    }

    *plaintextlen += len;
    p[*plaintextlen] = '\0';
    status = 0;

end:
    if (ciphertext != NULL) {
        free((void *) ciphertext);
    }
    if (ctx != NULL) {
        EVP_CIPHER_CTX_free(ctx);
    }

    return status;
}

int main() {
    uint8_t *expected = NULL;
    size_t read = 0;

    assert(file_read("data/c07_test.txt", &expected, &read));

    const uint8_t key[16] = "YELLOW SUBMARINE";
    uint8_t *output = NULL;
    int len = 0;

    assert(challenge_07("data/c07.txt", key, &output, &len) == 0);
    assert(strcmp((const char *) output, (const char *) expected) == 0);

    free((void *) expected);
    free((void *) output);
}
