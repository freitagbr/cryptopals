#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/err.h>
#include <openssl/evp.h>

#include "cryptopals/base64.h"
#include "cryptopals/error.h"
#include "cryptopals/file.h"

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

error_t challenge_07(const char *file, uint8_t **plaintext, int *plaintextlen, const uint8_t *key) {
    EVP_CIPHER_CTX *ctx = NULL;
    uint8_t *ciphertext = NULL;
    size_t ciphertextlen = 0;
    int len = 0;
    error_t err = 0;

    err = base64_decode_file(file, &ciphertext, &ciphertextlen);
    if (err) {
        goto end;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        err = EMALLOC;
        goto end;
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL) != 1) {
        err = EOPENSSL;
        fprintf(stderr, "%s\n", ERR_error_string(ERR_get_error(), NULL));
        goto end;
    }

    uint8_t *p = *plaintext = (uint8_t *) calloc(ciphertextlen + 1, sizeof (uint8_t));
    if (p == NULL) {
        err = EMALLOC;
        goto end;
    }

    if (EVP_DecryptUpdate(ctx, p, &len, ciphertext, ciphertextlen) != 1) {
        err = EOPENSSL;
        fprintf(stderr, "%s\n", ERR_error_string(ERR_get_error(), NULL));
        goto end;
    }

    *plaintextlen = len;

    if (EVP_DecryptFinal_ex(ctx, &p[len], &len) != 1) {
        err = EOPENSSL;
        fprintf(stderr, "%s\n", ERR_error_string(ERR_get_error(), NULL));
        goto end;
    }

    *plaintextlen += len;
    p[*plaintextlen] = '\0';

end:
    if (ciphertext != NULL) {
        free((void *) ciphertext);
    }
    if (ctx != NULL) {
        EVP_CIPHER_CTX_free(ctx);
    }

    return err;
}

int main() {
    const uint8_t key[16] = "YELLOW SUBMARINE";
    uint8_t *expected = NULL;
    uint8_t *output = NULL;
    size_t read = 0;
    int len = 0;
    error_t err = 0;

    err = file_read("data/c07_test.txt", &expected, &read);
    if (err) {
        error(err);
        goto end;
    }

    err = challenge_07("data/c07.txt", &output, &len, key);
    if (err) {
        error(err);
        goto end;
    }

    error_expect((const char *) expected, (const char *) output);

end:
    free((void *) expected);
    free((void *) output);

    return (int) err;
}
