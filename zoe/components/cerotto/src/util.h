#ifndef AF_UTIL_H
#define AF_UTIL_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#define AF_MAX_LINE (1024U * 1024U)
#define AF_MAX_FIELD 4096U
#define AF_TIMESTAMP_SIZE 28U

typedef struct {
    char *data;
    size_t len;
    size_t cap;
} af_buffer;

void af_buf_init(af_buffer *buffer);
int af_buf_reserve(af_buffer *buffer, size_t additional);
int af_buf_append(af_buffer *buffer, const void *data, size_t length);
int af_buf_printf(af_buffer *buffer, const char *format, ...);
char *af_buf_take(af_buffer *buffer);
void af_buf_free(af_buffer *buffer);

char *af_strdup(const char *value);
char *af_path_join(const char *left, const char *right);
int af_now(char output[AF_TIMESTAMP_SIZE]);
int af_timestamp_normalize(const char *input, char output[AF_TIMESTAMP_SIZE]);
int af_sha256_raw(const void *data, size_t length, unsigned char output[32]);
int af_sha256_bytes(const void *data, size_t length, char output[65]);
int af_sha256_file(const char *path, char output[65]);
int af_write_new_file(const char *path, const void *data, size_t length);
int af_file_size(const char *path, int64_t *size);
void af_error(const char *format, ...);

#endif
