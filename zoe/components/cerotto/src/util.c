#include "util.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

void af_error(const char *format, ...) {
    va_list args;
    va_start(args, format);
    fputs("cerotto: ", stderr);
    vfprintf(stderr, format, args);
    fputc('\n', stderr);
    va_end(args);
}

void af_buf_init(af_buffer *buffer) {
    buffer->data = NULL;
    buffer->len = 0;
    buffer->cap = 0;
}

int af_buf_reserve(af_buffer *buffer, size_t additional) {
    size_t needed;
    size_t capacity;
    char *data;
    if (additional > SIZE_MAX - buffer->len - 1) {
        return -1;
    }
    needed = buffer->len + additional + 1;
    if (needed <= buffer->cap) {
        return 0;
    }
    capacity = buffer->cap ? buffer->cap : 256;
    while (capacity < needed) {
        if (capacity > SIZE_MAX / 2) {
            capacity = needed;
            break;
        }
        capacity *= 2;
    }
    data = realloc(buffer->data, capacity);
    if (!data) {
        return -1;
    }
    buffer->data = data;
    buffer->cap = capacity;
    return 0;
}

int af_buf_append(af_buffer *buffer, const void *data, size_t length) {
    if (af_buf_reserve(buffer, length) != 0) {
        return -1;
    }
    if (length) {
        memcpy(buffer->data + buffer->len, data, length);
    }
    buffer->len += length;
    buffer->data[buffer->len] = '\0';
    return 0;
}

int af_buf_printf(af_buffer *buffer, const char *format, ...) {
    va_list args;
    va_list copy;
    int length;
    va_start(args, format);
    va_copy(copy, args);
    length = vsnprintf(NULL, 0, format, copy);
    va_end(copy);
    if (length < 0 || af_buf_reserve(buffer, (size_t)length) != 0) {
        va_end(args);
        return -1;
    }
    if (vsnprintf(buffer->data + buffer->len, buffer->cap - buffer->len, format, args) != length) {
        va_end(args);
        return -1;
    }
    va_end(args);
    buffer->len += (size_t)length;
    return 0;
}

char *af_buf_take(af_buffer *buffer) {
    char *data;
    if (!buffer->data) {
        data = calloc(1, 1);
    } else {
        data = buffer->data;
    }
    buffer->data = NULL;
    buffer->len = 0;
    buffer->cap = 0;
    return data;
}

void af_buf_free(af_buffer *buffer) {
    free(buffer->data);
    af_buf_init(buffer);
}

char *af_strdup(const char *value) {
    size_t length = strlen(value) + 1;
    char *copy = malloc(length);
    if (copy) {
        memcpy(copy, value, length);
    }
    return copy;
}

char *af_path_join(const char *left, const char *right) {
    size_t left_len = strlen(left);
    size_t right_len = strlen(right);
    int slash = left_len > 0 && left[left_len - 1] != '/';
    char *result;
    if (left_len > SIZE_MAX - right_len - (size_t)slash - 1) {
        return NULL;
    }
    result = malloc(left_len + right_len + (size_t)slash + 1);
    if (!result) {
        return NULL;
    }
    memcpy(result, left, left_len);
    if (slash) {
        result[left_len++] = '/';
    }
    memcpy(result + left_len, right, right_len + 1);
    return result;
}

static int parse_digits(const char *value, int count, int *result) {
    int number = 0;
    int i;
    for (i = 0; i < count; ++i) {
        if (!isdigit((unsigned char)value[i])) {
            return -1;
        }
        number = number * 10 + value[i] - '0';
    }
    *result = number;
    return 0;
}

static int64_t days_from_civil(int year, unsigned month, unsigned day) {
    int era;
    unsigned year_of_era;
    unsigned day_of_year;
    unsigned day_of_era;
    year -= month <= 2;
    era = (year >= 0 ? year : year - 399) / 400;
    year_of_era = (unsigned)(year - era * 400);
    day_of_year = (153 * (month + (month > 2 ? (unsigned)-3 : 9)) + 2) / 5 + day - 1;
    day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    return (int64_t)era * 146097 + (int64_t)day_of_era - 719468;
}

int af_timestamp_normalize(const char *input, char output[AF_TIMESTAMP_SIZE]) {
    int year, month, day, hour, minute, second;
    int microsecond = 0;
    int digits = 0;
    int64_t seconds;
    static const int month_days[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    size_t length;
    int max_day;
    if (!input || strlen(input) < 20 || input[4] != '-' || input[7] != '-' ||
        input[10] != 'T' || input[13] != ':' || input[16] != ':' ||
        parse_digits(input, 4, &year) || parse_digits(input + 5, 2, &month) ||
        parse_digits(input + 8, 2, &day) || parse_digits(input + 11, 2, &hour) ||
        parse_digits(input + 14, 2, &minute) || parse_digits(input + 17, 2, &second)) {
        return -1;
    }
    length = 19;
    if (input[length] == '.') {
        ++length;
        while (isdigit((unsigned char)input[length])) {
            if (digits >= 6) {
                return -1;
            }
            microsecond = microsecond * 10 + input[length] - '0';
            ++digits;
            ++length;
        }
        if (digits == 0) {
            return -1;
        }
        while (digits++ < 6) {
            microsecond *= 10;
        }
    }
    if (input[length] != 'Z' || input[length + 1] != '\0' || year < 1970 || year > 9999 ||
        month < 1 || month > 12 || hour > 23 || minute > 59 || second > 59) {
        return -1;
    }
    max_day = month_days[month - 1];
    if (month == 2 && (year % 4 == 0) && (year % 100 != 0 || year % 400 == 0)) {
        ++max_day;
    }
    if (day < 1 || day > max_day) {
        return -1;
    }
    seconds = days_from_civil(year, (unsigned)month, (unsigned)day) * 86400 +
              hour * 3600 + minute * 60 + second;
    if (seconds < 0) {
        return -1;
    }
    if (snprintf(output, AF_TIMESTAMP_SIZE,
                 "%04d-%02d-%02dT%02d:%02d:%02d.%06dZ",
                 year, month, day, hour, minute, second, microsecond) != AF_TIMESTAMP_SIZE - 1) {
        return -1;
    }
    return 0;
}

int af_now(char output[AF_TIMESTAMP_SIZE]) {
    struct timespec now;
    struct tm broken_down;
    char base[32];
    if (clock_gettime(CLOCK_REALTIME, &now) != 0 || !gmtime_r(&now.tv_sec, &broken_down)) {
        return -1;
    }
    if (!strftime(base, sizeof(base), "%Y-%m-%dT%H:%M:%S", &broken_down)) {
        return -1;
    }
    {
        int length = snprintf(output, AF_TIMESTAMP_SIZE, "%s.%06ldZ", base, now.tv_nsec / 1000);
        if (length < 0 || (size_t)length >= AF_TIMESTAMP_SIZE) {
            return -1;
        }
    }
    return 0;
}

typedef struct {
    uint32_t state[8];
    uint64_t length;
    unsigned char block[64];
    size_t block_length;
} sha256_context;

static const uint32_t sha256_constants[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

static uint32_t rotate_right(uint32_t value, unsigned count) {
    return (value >> count) | (value << (32 - count));
}

static void sha256_transform(sha256_context *context, const unsigned char block[64]) {
    uint32_t words[64];
    uint32_t a, b, c, d, e, f, g, h;
    int i;
    for (i = 0; i < 16; ++i) {
        words[i] = (uint32_t)block[i * 4] << 24 | (uint32_t)block[i * 4 + 1] << 16 |
                   (uint32_t)block[i * 4 + 2] << 8 | block[i * 4 + 3];
    }
    for (i = 16; i < 64; ++i) {
        uint32_t s0 = rotate_right(words[i - 15], 7) ^ rotate_right(words[i - 15], 18) ^ (words[i - 15] >> 3);
        uint32_t s1 = rotate_right(words[i - 2], 17) ^ rotate_right(words[i - 2], 19) ^ (words[i - 2] >> 10);
        words[i] = words[i - 16] + s0 + words[i - 7] + s1;
    }
    a = context->state[0]; b = context->state[1]; c = context->state[2]; d = context->state[3];
    e = context->state[4]; f = context->state[5]; g = context->state[6]; h = context->state[7];
    for (i = 0; i < 64; ++i) {
        uint32_t sum1 = rotate_right(e, 6) ^ rotate_right(e, 11) ^ rotate_right(e, 25);
        uint32_t choose = (e & f) ^ (~e & g);
        uint32_t temp1 = h + sum1 + choose + sha256_constants[i] + words[i];
        uint32_t sum0 = rotate_right(a, 2) ^ rotate_right(a, 13) ^ rotate_right(a, 22);
        uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2 = sum0 + majority;
        h = g; g = f; f = e; e = d + temp1;
        d = c; c = b; b = a; a = temp1 + temp2;
    }
    context->state[0] += a; context->state[1] += b; context->state[2] += c; context->state[3] += d;
    context->state[4] += e; context->state[5] += f; context->state[6] += g; context->state[7] += h;
}

static void sha256_init(sha256_context *context) {
    static const uint32_t initial[8] = {
        0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19
    };
    memcpy(context->state, initial, sizeof(initial));
    context->length = 0;
    context->block_length = 0;
}

static void sha256_update(sha256_context *context, const unsigned char *data, size_t length) {
    context->length += length;
    while (length) {
        size_t available = 64 - context->block_length;
        size_t chunk = length < available ? length : available;
        memcpy(context->block + context->block_length, data, chunk);
        context->block_length += chunk;
        data += chunk;
        length -= chunk;
        if (context->block_length == 64) {
            sha256_transform(context, context->block);
            context->block_length = 0;
        }
    }
}

static void sha256_final(sha256_context *context, unsigned char digest[32]) {
    uint64_t bit_length = context->length * 8;
    unsigned char padding[72] = {0x80};
    size_t padding_length = context->block_length < 56 ? 56 - context->block_length : 120 - context->block_length;
    int i;
    sha256_update(context, padding, padding_length);
    for (i = 0; i < 8; ++i) {
        context->block[56 + i] = (unsigned char)(bit_length >> (56 - i * 8));
    }
    sha256_transform(context, context->block);
    for (i = 0; i < 8; ++i) {
        digest[i * 4] = (unsigned char)(context->state[i] >> 24);
        digest[i * 4 + 1] = (unsigned char)(context->state[i] >> 16);
        digest[i * 4 + 2] = (unsigned char)(context->state[i] >> 8);
        digest[i * 4 + 3] = (unsigned char)context->state[i];
    }
}

int af_sha256_file(const char *path, char output[65]) {
    static const char hex[] = "0123456789abcdef";
    unsigned char data[65536];
    unsigned char digest[32];
    sha256_context context;
    FILE *file = fopen(path, "rb");
    size_t length;
    int i;
    if (!file) {
        return -1;
    }
    sha256_init(&context);
    while ((length = fread(data, 1, sizeof(data), file)) > 0) {
        sha256_update(&context, data, length);
    }
    if (ferror(file) || fclose(file) != 0) {
        return -1;
    }
    sha256_final(&context, digest);
    for (i = 0; i < 32; ++i) {
        output[i * 2] = hex[digest[i] >> 4];
        output[i * 2 + 1] = hex[digest[i] & 15];
    }
    output[64] = '\0';
    return 0;
}

int af_sha256_raw(const void *data, size_t length, unsigned char output[32]) {
    sha256_context context;
    if ((!data && length) || !output) {
        return -1;
    }
    sha256_init(&context);
    sha256_update(&context, data, length);
    sha256_final(&context, output);
    return 0;
}

int af_sha256_bytes(const void *data, size_t length, char output[65]) {
    static const char hex[] = "0123456789abcdef";
    unsigned char digest[32];
    int i;
    if (af_sha256_raw(data, length, digest) != 0) {
        return -1;
    }
    for (i = 0; i < 32; ++i) {
        output[i * 2] = hex[digest[i] >> 4];
        output[i * 2 + 1] = hex[digest[i] & 15];
    }
    output[64] = '\0';
    return 0;
}

int af_write_new_file(const char *path, const void *data, size_t length) {
    int descriptor = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    const unsigned char *cursor = data;
    if (descriptor < 0) {
        return -1;
    }
    while (length) {
        ssize_t written = write(descriptor, cursor, length);
        if (written < 0) {
            if (errno == EINTR) {
                continue;
            }
            close(descriptor);
            return -1;
        }
        cursor += written;
        length -= (size_t)written;
    }
    if (close(descriptor) != 0) {
        return -1;
    }
    return 0;
}

int af_file_size(const char *path, int64_t *size) {
    struct stat status;
    if (stat(path, &status) != 0 || !S_ISREG(status.st_mode)) {
        return -1;
    }
    *size = status.st_size;
    return 0;
}
