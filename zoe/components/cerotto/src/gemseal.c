#include "gemseal.h"
#include "crypto.h"
#include "util.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define DATA_RECORD 1
#define END_RECORD 2
#define SUITE 1
#define KDF 1

static const unsigned char magic[8] = {'G','E','M','S','E','A','L','1'};
static const unsigned char kdf_context[] = {'G','E','M','S','E','A','L','1','/','f','i','l','e','-','k','e','y',0};
static const unsigned char aad_context[] = {'G','E','M','S','E','A','L','1','/','r','e','c','o','r','d',0};

typedef struct {
    int descriptor;
    char *temporary;
    const char *destination;
    int open;
} atomic_output;

static uint16_t read16_le(const unsigned char *data) {
    return (uint16_t)data[0] | (uint16_t)data[1] << 8;
}

static uint32_t read32_le(const unsigned char *data) {
    return (uint32_t)data[0] | (uint32_t)data[1] << 8 |
           (uint32_t)data[2] << 16 | (uint32_t)data[3] << 24;
}

static void write16_le(unsigned char *data, uint16_t value) {
    data[0] = (unsigned char)value;
    data[1] = (unsigned char)(value >> 8);
}

static void write32_le(unsigned char *data, uint32_t value) {
    data[0] = (unsigned char)value;
    data[1] = (unsigned char)(value >> 8);
    data[2] = (unsigned char)(value >> 16);
    data[3] = (unsigned char)(value >> 24);
}

static int write_all(int descriptor, const void *data, size_t length) {
    const unsigned char *cursor = data;
    size_t offset = 0;
    while (offset < length) {
        ssize_t written = write(descriptor, cursor + offset, length - offset);
        if (written < 0 && errno == EINTR) {
            continue;
        }
        if (written <= 0) {
            return -1;
        }
        offset += (size_t)written;
    }
    return 0;
}

static int read_all(int descriptor, void *data, size_t length) {
    unsigned char *cursor = data;
    size_t offset = 0;
    while (offset < length) {
        ssize_t received = read(descriptor, cursor + offset, length - offset);
        if (received < 0 && errno == EINTR) {
            continue;
        }
        if (received <= 0) {
            return -1;
        }
        offset += (size_t)received;
    }
    return 0;
}

static char *temporary_pattern(const char *destination) {
    const char *slash = strrchr(destination, '/');
    const char *name = slash ? slash + 1 : destination;
    size_t directory_length = slash ? (size_t)(slash - destination) : 0;
    size_t length = (slash ? directory_length + 1 : 1) + strlen(name) + 16;
    char *pattern = malloc(length);
    if (!pattern) {
        return NULL;
    }
    if (slash) {
        memcpy(pattern, destination, directory_length + 1);
        pattern[directory_length + 1] = '\0';
    } else {
        strcpy(pattern, "./");
    }
    strcat(pattern, ".");
    strcat(pattern, name);
    strcat(pattern, ".tmp.XXXXXX");
    return pattern;
}

static int atomic_begin(atomic_output *output, const char *destination) {
    struct stat status;
    memset(output, 0, sizeof(*output));
    output->descriptor = -1;
    output->destination = destination;
    if (lstat(destination, &status) == 0 || errno != ENOENT) {
        return -1;
    }
    output->temporary = temporary_pattern(destination);
    if (!output->temporary) {
        return -1;
    }
    output->descriptor = mkstemp(output->temporary);
    if (output->descriptor < 0) {
        free(output->temporary);
        output->temporary = NULL;
        return -1;
    }
    output->open = 1;
    if (fchmod(output->descriptor, 0600) != 0) {
        close(output->descriptor);
        unlink(output->temporary);
        free(output->temporary);
        output->temporary = NULL;
        return -1;
    }
    return 0;
}

static int atomic_write(atomic_output *output, const void *data, size_t length) {
    return output->open && write_all(output->descriptor, data, length) == 0 ? 0 : -1;
}

static int atomic_finish(atomic_output *output) {
    struct stat status;
    int result = -1;
    if (!output->open) {
        return -1;
    }
    if (fsync(output->descriptor) != 0 || close(output->descriptor) != 0) {
        output->descriptor = -1;
        goto cleanup;
    }
    output->descriptor = -1;
    output->open = 0;
    if (link(output->temporary, output->destination) != 0) {
        goto cleanup;
    }
    if (stat(output->destination, &status) != 0 || (status.st_mode & 077) != 0) {
        unlink(output->destination);
        goto cleanup;
    }
    result = 0;
cleanup:
    if (output->open) {
        close(output->descriptor);
    }
    if (unlink(output->temporary) != 0 && result != 0) {
        result = -1;
    }
    free(output->temporary);
    output->temporary = NULL;
    return result;
}

static void atomic_abort(atomic_output *output) {
    if (output->open) {
        close(output->descriptor);
        output->descriptor = -1;
        output->open = 0;
    }
    if (output->temporary) {
        unlink(output->temporary);
        free(output->temporary);
        output->temporary = NULL;
    }
}

static int open_input(const char *path, int *descriptor) {
    *descriptor = open(path, O_RDONLY | O_CLOEXEC);
    return *descriptor < 0 ? -1 : 0;
}

int af_gemseal_load_key(const char *path, unsigned char key[AF_GEMSEAL_KEY_SIZE]) {
    int descriptor = -1;
    struct stat status;
    int result = -1;
    if (!path || !key || open_input(path, &descriptor) != 0 || fstat(descriptor, &status) != 0 ||
        !S_ISREG(status.st_mode) || status.st_size != AF_GEMSEAL_KEY_SIZE || (status.st_mode & 077) != 0) {
        goto cleanup;
    }
    if (read_all(descriptor, key, AF_GEMSEAL_KEY_SIZE) != 0) {
        goto cleanup;
    }
    result = 0;
cleanup:
    if (descriptor >= 0 && close(descriptor) != 0) {
        result = -1;
    }
    if (result != 0) {
        af_crypto_zero(key, AF_GEMSEAL_KEY_SIZE);
    }
    return result;
}

int af_gemseal_generate_key(const char *path) {
    unsigned char key[AF_GEMSEAL_KEY_SIZE];
    atomic_output output;
    int result = -1;
    if (!path || af_crypto_random(key, sizeof(key)) != 0 || atomic_begin(&output, path) != 0) {
        goto cleanup;
    }
    if (atomic_write(&output, key, sizeof(key)) != 0 || atomic_finish(&output) != 0) {
        goto cleanup;
    }
    result = 0;
cleanup:
    if (output.temporary) {
        atomic_abort(&output);
    }
    af_crypto_zero(key, sizeof(key));
    return result;
}

static void derive_file_key(const unsigned char master[32], const unsigned char salt[16], unsigned char output[32]) {
    af_hkdf_sha256(master, 32, salt, 16, kdf_context, sizeof(kdf_context), output);
}

static void record_aad(const unsigned char header[48], const unsigned char previous[16],
                       const unsigned char record[16], unsigned char aad[96]) {
    memcpy(aad, aad_context, sizeof(aad_context));
    memcpy(aad + 16, header, 48);
    memcpy(aad + 64, previous, 16);
    memcpy(aad + 80, record, 16);
}

static void record_nonce(const unsigned char prefix[8], uint32_t index, unsigned char nonce[12]) {
    memcpy(nonce, prefix, 8);
    write32_le(nonce + 8, index);
}

static void make_record(unsigned char record[16], uint16_t type, uint16_t sealed_size,
                        uint32_t index, uint32_t plaintext_size) {
    write16_le(record, type);
    write16_le(record + 2, SUITE);
    write16_le(record + 4, sealed_size);
    write32_le(record + 6, index);
    write32_le(record + 10, plaintext_size);
    write16_le(record + 14, 0);
}

int af_gemseal_encrypt_file(const unsigned char key[AF_GEMSEAL_KEY_SIZE],
                            const char *source, const char *destination, uint32_t chunk_size) {
    int input = -1;
    atomic_output output;
    unsigned char header[48];
    unsigned char salt[16];
    unsigned char nonce_prefix[8];
    unsigned char file_key[32];
    unsigned char previous[16] = {0};
    unsigned char *plaintext = NULL;
    unsigned char *ciphertext = NULL;
    unsigned char record[16];
    unsigned char aad[96];
    unsigned char nonce[12];
    unsigned char tag[16];
    uint32_t index = 0;
    int result = -1;
    memset(&output, 0, sizeof(output));
    output.descriptor = -1;
    if (!key || !source || !destination || chunk_size < 1 || chunk_size > AF_GEMSEAL_MAX_CHUNK ||
        open_input(source, &input) != 0 || af_crypto_random(salt, sizeof(salt)) != 0 ||
        af_crypto_random(nonce_prefix, sizeof(nonce_prefix)) != 0) {
        goto cleanup;
    }
    plaintext = malloc(chunk_size);
    ciphertext = malloc(chunk_size);
    if (!plaintext || !ciphertext) {
        goto cleanup;
    }
    memcpy(header, magic, 8);
    write16_le(header + 8, 1);
    write16_le(header + 10, SUITE);
    write16_le(header + 12, KDF);
    write16_le(header + 14, AF_GEMSEAL_HEADER_SIZE);
    memcpy(header + 16, salt, 16);
    memcpy(header + 32, nonce_prefix, 8);
    write32_le(header + 40, chunk_size);
    write32_le(header + 44, 0);
    derive_file_key(key, salt, file_key);
    if (atomic_begin(&output, destination) != 0 || atomic_write(&output, header, sizeof(header)) != 0) {
        goto cleanup;
    }
    for (;;) {
        ssize_t amount = read(input, plaintext, chunk_size);
        size_t plaintext_size;
        if (amount < 0 && errno == EINTR) {
            continue;
        }
        if (amount < 0) {
            goto cleanup;
        }
        if (amount == 0) {
            break;
        }
        plaintext_size = (size_t)amount;
        if (index == UINT32_MAX) {
            goto cleanup;
        }
        make_record(record, DATA_RECORD, (uint16_t)(plaintext_size + 16), index, (uint32_t)plaintext_size);
        record_aad(header, previous, record, aad);
        record_nonce(nonce_prefix, index, nonce);
        if (af_chacha20_poly1305_encrypt(file_key, nonce, plaintext, plaintext_size,
                                         aad, sizeof(aad), ciphertext, tag) != 0 ||
            atomic_write(&output, record, sizeof(record)) != 0 ||
            atomic_write(&output, ciphertext, plaintext_size) != 0 ||
            atomic_write(&output, tag, sizeof(tag)) != 0) {
            goto cleanup;
        }
        memcpy(previous, tag, sizeof(previous));
        ++index;
    }
    make_record(record, END_RECORD, 16, index, 0);
    record_aad(header, previous, record, aad);
    record_nonce(nonce_prefix, index, nonce);
    if (af_chacha20_poly1305_encrypt(file_key, nonce, plaintext, 0, aad, sizeof(aad), ciphertext, tag) != 0 ||
        atomic_write(&output, record, sizeof(record)) != 0 || atomic_write(&output, tag, sizeof(tag)) != 0 ||
        atomic_finish(&output) != 0) {
        goto cleanup;
    }
    result = 0;
cleanup:
    if (input >= 0) {
        close(input);
    }
    if (output.temporary) {
        atomic_abort(&output);
    }
    if (plaintext) {
        af_crypto_zero(plaintext, chunk_size);
    }
    free(plaintext);
    free(ciphertext);
    af_crypto_zero(file_key, sizeof(file_key));
    af_crypto_zero(previous, sizeof(previous));
    return result;
}

static int read_header(int input, unsigned char header[48], unsigned char salt[16], unsigned char prefix[8], uint32_t *chunk_size) {
    if (read_all(input, header, 48) != 0 || memcmp(header, magic, 8) != 0 || read16_le(header + 8) != 1 ||
        read16_le(header + 10) != SUITE || read16_le(header + 12) != KDF ||
        read16_le(header + 14) != AF_GEMSEAL_HEADER_SIZE || read32_le(header + 44) != 0) {
        return -1;
    }
    *chunk_size = read32_le(header + 40);
    if (*chunk_size < 1 || *chunk_size > AF_GEMSEAL_MAX_CHUNK) {
        return -1;
    }
    memcpy(salt, header + 16, 16);
    memcpy(prefix, header + 32, 8);
    return 0;
}

int af_gemseal_decrypt_file(const unsigned char key[AF_GEMSEAL_KEY_SIZE],
                            const char *source, const char *destination) {
    int input = -1;
    atomic_output output;
    unsigned char header[48];
    unsigned char salt[16];
    unsigned char prefix[8];
    unsigned char file_key[32];
    unsigned char previous[16] = {0};
    unsigned char record[16];
    unsigned char aad[96];
    unsigned char nonce[12];
    unsigned char *sealed = NULL;
    unsigned char *plaintext = NULL;
    uint32_t chunk_size = 0;
    uint32_t index = 0;
    int result = -1;
    memset(&output, 0, sizeof(output));
    output.descriptor = -1;
    if (!key || !source || !destination || open_input(source, &input) != 0 ||
        read_header(input, header, salt, prefix, &chunk_size) != 0) {
        goto cleanup;
    }
    derive_file_key(key, salt, file_key);
    sealed = malloc(AF_GEMSEAL_MAX_CHUNK + 16);
    plaintext = malloc(chunk_size);
    if (!sealed || !plaintext || atomic_begin(&output, destination) != 0) {
        goto cleanup;
    }
    for (;;) {
        uint16_t type;
        uint16_t sealed_size;
        uint32_t plaintext_size;
        if (read_all(input, record, sizeof(record)) != 0) {
            goto cleanup;
        }
        type = read16_le(record);
        sealed_size = read16_le(record + 4);
        plaintext_size = read32_le(record + 10);
        if ((type != DATA_RECORD && type != END_RECORD) || read16_le(record + 2) != SUITE ||
            read16_le(record + 14) != 0 || read32_le(record + 6) != index ||
            plaintext_size > chunk_size || sealed_size != plaintext_size + 16 ||
            (type == DATA_RECORD && (plaintext_size == 0 || index == UINT32_MAX)) ||
            (type == END_RECORD && plaintext_size != 0)) {
            goto cleanup;
        }
        if (read_all(input, sealed, sealed_size) != 0) {
            goto cleanup;
        }
        record_aad(header, previous, record, aad);
        record_nonce(prefix, index, nonce);
        if (af_chacha20_poly1305_decrypt(file_key, nonce, sealed, sealed_size - 16,
                                         aad, sizeof(aad), sealed + sealed_size - 16, plaintext) != 0) {
            goto cleanup;
        }
        if (type == END_RECORD) {
            unsigned char trailing;
            ssize_t amount;
            do {
                amount = read(input, &trailing, 1);
            } while (amount < 0 && errno == EINTR);
            if (amount != 0) {
                goto cleanup;
            }
            if (atomic_finish(&output) != 0) {
                goto cleanup;
            }
            result = 0;
            break;
        }
        if (atomic_write(&output, plaintext, plaintext_size) != 0) {
            goto cleanup;
        }
        memcpy(previous, sealed + sealed_size - 16, 16);
        ++index;
    }
cleanup:
    if (input >= 0) {
        close(input);
    }
    if (output.temporary) {
        atomic_abort(&output);
    }
    if (plaintext) {
        af_crypto_zero(plaintext, chunk_size);
    }
    free(plaintext);
    free(sealed);
    af_crypto_zero(file_key, sizeof(file_key));
    af_crypto_zero(previous, sizeof(previous));
    return result;
}

int af_gemseal_load_challenge(const char *source, af_gemseal_challenge *challenge) {
    int input = -1;
    uint32_t chunk_size = 0;
    uint16_t type;
    uint16_t sealed_size;
    int result = -1;
    memset(challenge, 0, sizeof(*challenge));
    if (!source || open_input(source, &input) != 0 ||
        read_header(input, challenge->file_header, challenge->salt, challenge->nonce_prefix, &chunk_size) != 0 ||
        read_all(input, challenge->record_header, AF_GEMSEAL_RECORD_SIZE) != 0) {
        goto cleanup;
    }
    type = read16_le(challenge->record_header);
    sealed_size = read16_le(challenge->record_header + 4);
    challenge->plaintext_size = read32_le(challenge->record_header + 10);
    if ((type != DATA_RECORD && type != END_RECORD) || read16_le(challenge->record_header + 2) != SUITE ||
        read16_le(challenge->record_header + 14) != 0 || read32_le(challenge->record_header + 6) != 0 ||
        challenge->plaintext_size > chunk_size || sealed_size != challenge->plaintext_size + 16 ||
        (type == DATA_RECORD && challenge->plaintext_size == 0) ||
        (type == END_RECORD && challenge->plaintext_size != 0)) {
        goto cleanup;
    }
    challenge->sealed = malloc(sealed_size);
    if (!challenge->sealed || read_all(input, challenge->sealed, sealed_size) != 0) {
        goto cleanup;
    }
    result = 0;
cleanup:
    if (input >= 0) {
        close(input);
    }
    if (result != 0) {
        af_gemseal_challenge_free(challenge);
    }
    return result;
}

int af_gemseal_verify_first(const unsigned char key[AF_GEMSEAL_KEY_SIZE],
                            const af_gemseal_challenge *challenge) {
    unsigned char file_key[32];
    unsigned char previous[16] = {0};
    unsigned char aad[96];
    unsigned char nonce[12];
    unsigned char *plaintext = NULL;
    uint16_t sealed_size;
    int result;
    if (!key || !challenge || !challenge->sealed) {
        return -1;
    }
    sealed_size = read16_le(challenge->record_header + 4);
    plaintext = malloc(challenge->plaintext_size ? challenge->plaintext_size : 1);
    if (!plaintext) {
        return -1;
    }
    derive_file_key(key, challenge->salt, file_key);
    record_aad(challenge->file_header, previous, challenge->record_header, aad);
    record_nonce(challenge->nonce_prefix, 0, nonce);
    result = af_chacha20_poly1305_decrypt(file_key, nonce, challenge->sealed, sealed_size - 16,
                                          aad, sizeof(aad), challenge->sealed + sealed_size - 16, plaintext) == 0 ? 1 : 0;
    if (plaintext) {
        af_crypto_zero(plaintext, challenge->plaintext_size ? challenge->plaintext_size : 1);
    }
    free(plaintext);
    af_crypto_zero(file_key, sizeof(file_key));
    return result;
}

void af_gemseal_challenge_free(af_gemseal_challenge *challenge) {
    if (challenge && challenge->sealed) {
        free(challenge->sealed);
        challenge->sealed = NULL;
    }
}
