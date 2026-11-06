#include "artifact.h"
#include "util.h"

#include <cJSON.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static const char base64_alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static char *resolved_path(const char *base, const char *path) {
    if (!base || !base[0] || path[0] == '/') {
        return af_strdup(path);
    }
    return af_path_join(base, path);
}

static char *base64_encode(const unsigned char *data, size_t length) {
    size_t output_length;
    size_t input_index = 0;
    size_t output_index = 0;
    char *output;
    if (length > (SIZE_MAX - 2) / 3) {
        return NULL;
    }
    output_length = ((length + 2) / 3) * 4;
    output = malloc(output_length + 1);
    if (!output) {
        return NULL;
    }
    while (input_index < length) {
        size_t remaining = length - input_index;
        uint32_t a = data[input_index++];
        uint32_t b = remaining > 1 ? data[input_index++] : 0;
        uint32_t c = remaining > 2 ? data[input_index++] : 0;
        uint32_t value = (a << 16) | (b << 8) | c;
        output[output_index++] = base64_alphabet[(value >> 18) & 63];
        output[output_index++] = base64_alphabet[(value >> 12) & 63];
        output[output_index++] = remaining > 1 ? base64_alphabet[(value >> 6) & 63] : '=';
        output[output_index++] = remaining > 2 ? base64_alphabet[value & 63] : '=';
    }
    output[output_index] = '\0';
    return output;
}

static int write_hex(FILE *output, int64_t source_id, const char *hash,
                     const unsigned char *data, size_t length, int64_t size, int truncated) {
    size_t offset;
    if (fprintf(output, "# artifact=%lld\n# sha256=%s\n# size=%lld\n# truncated=%s\n",
                (long long)source_id, hash, (long long)size, truncated ? "true" : "false") < 0) {
        return -1;
    }
    for (offset = 0; offset < length; offset += 16) {
        size_t column;
        if (fprintf(output, "%08zx  ", offset) < 0) {
            return -1;
        }
        for (column = 0; column < 16; ++column) {
            if (offset + column < length) {
                if (fprintf(output, "%02x%s", data[offset + column], column == 15 ? "" : " ") < 0) {
                    return -1;
                }
            } else if (fputs("   ", output) == EOF) {
                return -1;
            }
        }
        if (fputc('\n', output) == EOF) {
            return -1;
        }
    }
    return 0;
}

static int write_json(FILE *output, int64_t source_id, const char *path, const char *hash,
                      const unsigned char *data, size_t length, int64_t size, int truncated) {
    cJSON *root = cJSON_CreateObject();
    char *encoded = base64_encode(data, length);
    char *printed = NULL;
    int result = -1;
    if (!root || !encoded || !cJSON_AddNumberToObject(root, "source_id", (double)source_id) ||
        !cJSON_AddStringToObject(root, "path", path) || !cJSON_AddStringToObject(root, "sha256", hash) ||
        !cJSON_AddNumberToObject(root, "size_bytes", (double)size) ||
        !cJSON_AddNumberToObject(root, "returned_bytes", (double)length) ||
        !cJSON_AddBoolToObject(root, "truncated", truncated) ||
        !cJSON_AddStringToObject(root, "encoding", "base64") ||
        !cJSON_AddStringToObject(root, "data", encoded)) {
        goto cleanup;
    }
    printed = cJSON_PrintUnformatted(root);
    if (printed && fputs(printed, output) != EOF && fputc('\n', output) != EOF) {
        result = 0;
    }
cleanup:
    free(encoded);
    free(printed);
    cJSON_Delete(root);
    return result;
}

int af_artifact_show(af_db *db, const char *case_id, int64_t source_id,
                     const char *format, size_t max_bytes, const char *base_path,
                     FILE *output) {
    sqlite3_stmt *statement = NULL;
    const char *stored_path;
    const char *expected;
    char actual[65];
    char *resolved = NULL;
    unsigned char *data = NULL;
    size_t length = 0;
    int64_t full_size = 0;
    int descriptor = -1;
    int truncated;
    int result = -1;
    if (source_id <= 0 || !max_bytes || max_bytes > 1024U * 1024U ||
        (strcmp(format, "hex") && strcmp(format, "json"))) {
        af_error("artifact inspection requires a positive source ID, hex/json format, and 1-1048576 bytes");
        return -1;
    }
    if (sqlite3_prepare_v2(db->handle,
            "SELECT stored_path,raw_sha256 FROM evidence_sources WHERE id=?1 AND case_id=?2 AND kind='carved_artifact'",
            -1, &statement, NULL) != SQLITE_OK) {
        return -1;
    }
    sqlite3_bind_int64(statement, 1, source_id);
    sqlite3_bind_text(statement, 2, case_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(statement) != SQLITE_ROW) {
        af_error("carved artifact not found in case: %lld", (long long)source_id);
        goto cleanup;
    }
    stored_path = (const char *)sqlite3_column_text(statement, 0);
    expected = (const char *)sqlite3_column_text(statement, 1);
    if (!stored_path || !expected || !stored_path[0] || !expected[0]) {
        goto cleanup;
    }
    resolved = resolved_path(base_path, stored_path);
    if (!resolved || af_sha256_file(resolved, actual) != 0 || strcmp(actual, expected)) {
        af_error("artifact is missing or fails hash verification");
        goto cleanup;
    }
    descriptor = open(resolved, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0) {
        af_error("cannot open verified artifact: %s", strerror(errno));
        goto cleanup;
    }
    {
        struct stat status;
        if (fstat(descriptor, &status) != 0 || !S_ISREG(status.st_mode) || status.st_size < 0) {
            goto cleanup;
        }
        full_size = status.st_size;
        truncated = (uint64_t)full_size > max_bytes;
        data = malloc(max_bytes ? max_bytes : 1);
        if (!data) {
            goto cleanup;
        }
        while (length < max_bytes) {
            ssize_t received = read(descriptor, data + length, max_bytes - length);
            if (received < 0) {
                if (errno == EINTR) continue;
                goto cleanup;
            }
            if (!received) break;
            length += (size_t)received;
        }
        if ((int64_t)length > full_size) {
            goto cleanup;
        }
    }
    if (!strcmp(format, "json")) {
        result = write_json(output, source_id, stored_path, expected, data, length,
                            full_size, truncated);
    } else {
        result = write_hex(output, source_id, expected, data, length, full_size, truncated);
    }
cleanup:
    if (descriptor >= 0) close(descriptor);
    free(resolved);
    free(data);
    sqlite3_finalize(statement);
    return result;
}
