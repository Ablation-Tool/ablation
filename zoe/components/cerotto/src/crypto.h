#ifndef AF_CRYPTO_H
#define AF_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

void af_crypto_zero(void *data, size_t length);
int af_crypto_random(void *data, size_t length);
void af_hkdf_sha256(const unsigned char *key, size_t key_length,
                    const unsigned char *salt, size_t salt_length,
                    const unsigned char *info, size_t info_length,
                    unsigned char output[32]);
int af_chacha20_poly1305_encrypt(const unsigned char key[32], const unsigned char nonce[12],
                                 const unsigned char *plaintext, size_t plaintext_length,
                                 const unsigned char *aad, size_t aad_length,
                                 unsigned char *ciphertext, unsigned char tag[16]);
int af_chacha20_poly1305_decrypt(const unsigned char key[32], const unsigned char nonce[12],
                                 const unsigned char *ciphertext, size_t ciphertext_length,
                                 const unsigned char *aad, size_t aad_length,
                                 unsigned char tag[16], unsigned char *plaintext);

#endif
