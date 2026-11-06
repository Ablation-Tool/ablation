#ifndef AF_GEMSEAL_H
#define AF_GEMSEAL_H

#include <stddef.h>
#include <stdint.h>

#define AF_GEMSEAL_KEY_SIZE 32
#define AF_GEMSEAL_HEADER_SIZE 48
#define AF_GEMSEAL_RECORD_SIZE 16
#define AF_GEMSEAL_TAG_SIZE 16
#define AF_GEMSEAL_MAX_CHUNK 65519

typedef struct {
    unsigned char file_header[AF_GEMSEAL_HEADER_SIZE];
    unsigned char record_header[AF_GEMSEAL_RECORD_SIZE];
    unsigned char salt[16];
    unsigned char nonce_prefix[8];
    uint32_t plaintext_size;
    unsigned char *sealed;
} af_gemseal_challenge;

int af_gemseal_load_key(const char *path, unsigned char key[AF_GEMSEAL_KEY_SIZE]);
int af_gemseal_generate_key(const char *path);
int af_gemseal_encrypt_file(const unsigned char key[AF_GEMSEAL_KEY_SIZE],
                            const char *source, const char *destination, uint32_t chunk_size);
int af_gemseal_decrypt_file(const unsigned char key[AF_GEMSEAL_KEY_SIZE],
                            const char *source, const char *destination);
int af_gemseal_load_challenge(const char *source, af_gemseal_challenge *challenge);
int af_gemseal_verify_first(const unsigned char key[AF_GEMSEAL_KEY_SIZE],
                            const af_gemseal_challenge *challenge);
void af_gemseal_challenge_free(af_gemseal_challenge *challenge);

#endif
