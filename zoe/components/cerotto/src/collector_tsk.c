#include "collector_tsk.h"
#include "process.h"
#include "util.h"

#include <cJSON.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#define TSK_OUTPUT_LIMIT (512U * 1024U * 1024U)

static int epoch_timestamp(int64_t epoch, char output[AF_TIMESTAMP_SIZE]) {
    time_t value;
    struct tm broken_down;
    char base[32];
    if (epoch < 0) {
        return -1;
    }
    value = (time_t)epoch;
    if ((int64_t)value != epoch || !gmtime_r(&value, &broken_down) ||
        !strftime(base, sizeof(base), "%Y-%m-%dT%H:%M:%S", &broken_down)) {
        return -1;
    }
    if (snprintf(output, AF_TIMESTAMP_SIZE, "%s.000000Z", base) != AF_TIMESTAMP_SIZE - 1) {
        return -1;
    }
    return 0;
}

static int parse_integer(const char *value, int64_t *number) {
    char *end;
    intmax_t parsed;
    errno = 0;
    parsed = strtoimax(value, &end, 10);
    if (errno || end == value || *end != '\0' || parsed < 0 || parsed > INT64_MAX) {
        return -1;
    }
    *number = (int64_t)parsed;
    return 0;
}

static int split_body_record(char *line, char **fields) {
    char *cursor = line;
    int index = 0;
    while (index < 11) {
        char *separator;
        fields[index++] = cursor;
        if (index == 11) {
            break;
        }
        separator = strchr(cursor, '|');
        if (!separator) {
            return -1;
        }
        *separator = '\0';
        cursor = separator + 1;
    }
    return strchr(cursor, '|') ? -1 : 0;
}

static int insert_body_event(af_db *db, const char *case_id, int64_t source_id,
                             const char *host_id, char *line, size_t line_number,
                             int deleted_pass) {
    static const char deleted_suffix[] = " (deleted)";
    char *fields[11];
    char event_id[96];
    char timestamp[AF_TIMESTAMP_SIZE];
    char *details = NULL;
    int64_t times[4];
    int64_t ignored;
    int64_t selected = -1;
    int index;
    af_event event;
    cJSON *object = NULL;
    if (split_body_record(line, fields) != 0 || !fields[1][0] || strlen(fields[1]) > AF_MAX_FIELD) {
        af_error("invalid TSK body record at line %zu", line_number);
        return -1;
    }
    if (deleted_pass) {
        size_t path_length = strlen(fields[1]);
        if (path_length >= sizeof(deleted_suffix) - 1 &&
            strcmp(fields[1] + path_length - (sizeof(deleted_suffix) - 1), deleted_suffix) == 0) {
            fields[1][path_length - (sizeof(deleted_suffix) - 1)] = '\0';
        }
    }
    if (parse_integer(fields[5], &ignored) || parse_integer(fields[6], &ignored)) {
        af_error("invalid TSK numeric field at line %zu", line_number);
        return -1;
    }
    for (index = 0; index < 4; ++index) {
        if (parse_integer(fields[7 + index], &times[index]) != 0) {
            af_error("invalid TSK timestamp at line %zu", line_number);
            return -1;
        }
    }
    if (times[1] > 0) selected = times[1];
    else if (times[2] > 0) selected = times[2];
    else if (times[3] > 0) selected = times[3];
    else selected = times[0];
    if (epoch_timestamp(selected, timestamp) != 0) {
        af_error("unsupported TSK timestamp at line %zu", line_number);
        return -1;
    }
    if (snprintf(event_id, sizeof(event_id), "tsk-%" PRId64 "-%zu", source_id, line_number) >= (int)sizeof(event_id)) {
        return -1;
    }
    object = cJSON_CreateObject();
    if (!object ||
        !cJSON_AddStringToObject(object, "inode", fields[2]) ||
        !cJSON_AddStringToObject(object, "mode", fields[3]) ||
        !cJSON_AddNumberToObject(object, "atime", (double)times[0]) ||
        !cJSON_AddNumberToObject(object, "mtime", (double)times[1]) ||
        !cJSON_AddNumberToObject(object, "ctime", (double)times[2]) ||
        !cJSON_AddNumberToObject(object, "crtime", (double)times[3])) {
        cJSON_Delete(object);
        return -1;
    }
    details = cJSON_PrintUnformatted(object);
    cJSON_Delete(object);
    if (!details) {
        return -1;
    }
    memset(&event, 0, sizeof(event));
    event.id = event_id;
    event.case_id = case_id;
    event.source_id = source_id;
    event.observed_at = timestamp;
    event.host_id = host_id;
    event.source_tool = deleted_pass ? "tsk_fls_deleted" : "tsk_fls";
    event.event_type = "filesystem_metadata";
    event.conversation_id = "";
    event.prompt_id = "";
    event.tool_call_id = "";
    event.process_id = -1;
    event.parent_process_id = -1;
    event.path = fields[1];
    event.deleted = deleted_pass;
    event.details_json = details;
    index = af_db_insert_event(db, &event);
    free(details);
    return index;
}

static char *tool_version(void) {
    char *argv[] = {"fls", "-V", NULL};
    af_process_result result;
    char *version = NULL;
    size_t length;
    af_process_result_init(&result);
    if (af_process_run(argv, NULL, 0, 65536, &result) != 0 || result.exit_code != 0 ||
        !result.stdout_data.data) {
        af_error("cannot determine fls version%s%s", result.stderr_data.data ? ": " : "",
                 result.stderr_data.data ? result.stderr_data.data : "");
        af_process_result_free(&result);
        return NULL;
    }
    length = result.stdout_data.len;
    while (length && (result.stdout_data.data[length - 1] == '\n' || result.stdout_data.data[length - 1] == '\r')) {
        --length;
    }
    if (length >= AF_MAX_FIELD) {
        af_process_result_free(&result);
        return NULL;
    }
    result.stdout_data.data[length] = '\0';
    version = af_strdup(result.stdout_data.data);
    af_process_result_free(&result);
    return version;
}

static cJSON *command_array(const char *image_path, int deleted, int ewf) {
    cJSON *array = cJSON_CreateArray();
    if (!array || !cJSON_AddItemToArray(array, cJSON_CreateString("fls")) ||
        !cJSON_AddItemToArray(array, cJSON_CreateString("-i")) ||
        !cJSON_AddItemToArray(array, cJSON_CreateString(ewf ? "ewf" : "raw")) ||
        !cJSON_AddItemToArray(array, cJSON_CreateString("-r")) ||
        (deleted && !cJSON_AddItemToArray(array, cJSON_CreateString("-d"))) ||
        !cJSON_AddItemToArray(array, cJSON_CreateString("-m")) ||
        !cJSON_AddItemToArray(array, cJSON_CreateString("/")) ||
        !cJSON_AddItemToArray(array, cJSON_CreateString(image_path))) {
        cJSON_Delete(array);
        return NULL;
    }
    return array;
}

static char *command_json(const char *image_path, int ewf) {
    cJSON *root = cJSON_CreateObject();
    cJSON *allocated = command_array(image_path, 0, ewf);
    cJSON *deleted = command_array(image_path, 1, ewf);
    char *output = NULL;
    if (!root || !allocated || !deleted ||
        !cJSON_AddItemToObject(root, "allocated", allocated)) {
        cJSON_Delete(root);
        cJSON_Delete(allocated);
        cJSON_Delete(deleted);
        return NULL;
    }
    allocated = NULL;
    if (!cJSON_AddItemToObject(root, "deleted", deleted)) {
        cJSON_Delete(root);
        cJSON_Delete(deleted);
        return NULL;
    }
    output = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    return output;
}

int af_collect_tsk_impl(af_db *db, const char *case_id, const char *image_path,
                        const char *output_dir, const char *host_id, int ewf, size_t *count) {
    struct stat status;
    char image_hash[65];
    char raw_hash[65];
    char acquired_at[AF_TIMESTAMP_SIZE];
    int64_t image_size;
    int64_t source_id = 0;
    char *version = NULL;
    char *command = NULL;
    char *raw_path = NULL;
    char *cursor = NULL;
    char *line;
    size_t line_number = 0;
    size_t allocated_records = 0;
    size_t index;
    int transaction = 0;
    int result = -1;
    af_source source;
    af_process_result process;
    af_process_result deleted_process;
    af_process_result_init(&process);
    af_process_result_init(&deleted_process);
    *count = 0;

    if (stat(image_path, &status) != 0 || !S_ISREG(status.st_mode) ||
        stat(output_dir, &status) != 0 || !S_ISDIR(status.st_mode)) {
        af_error("image must be a regular file and output must be an existing directory");
        goto cleanup;
    }
    if (af_file_size(image_path, &image_size) != 0 || af_sha256_file(image_path, image_hash) != 0 ||
        af_now(acquired_at) != 0) {
        af_error("cannot hash image or record acquisition time: %s", strerror(errno));
        goto cleanup;
    }
    version = tool_version();
    command = command_json(image_path, ewf);
    raw_path = af_path_join(output_dir, "fls.body");
    if (!version || !command || !raw_path) {
        af_error("cannot prepare TSK collection");
        goto cleanup;
    }
    {
        char *format = ewf ? "ewf" : "raw";
        char *allocated_argv[] = {"fls", "-i", format, "-r", "-m", "/", (char *)image_path, NULL};
        char *deleted_argv[] = {"fls", "-i", format, "-r", "-d", "-m", "/", (char *)image_path, NULL};
        if (af_process_run(allocated_argv, NULL, 0, TSK_OUTPUT_LIMIT, &process) != 0 ||
            af_process_run(deleted_argv, NULL, 0, TSK_OUTPUT_LIMIT, &deleted_process) != 0) {
            goto cleanup;
        }
    }
    if (process.exit_code != 0 || deleted_process.exit_code != 0) {
        af_error("fls failed with exit code %d/%d%s%s", process.exit_code, deleted_process.exit_code,
                 process.stderr_data.data ? ": " : "",
                 process.stderr_data.data ? process.stderr_data.data : "");
        goto cleanup;
    }
    for (index = 0; index < process.stdout_data.len; ++index) {
        if (process.stdout_data.data[index] == '\n') {
            ++allocated_records;
        }
    }
    if (process.stdout_data.len && process.stdout_data.data[process.stdout_data.len - 1] != '\n') {
        ++allocated_records;
        if (af_buf_append(&process.stdout_data, "\n", 1) != 0) {
            goto cleanup;
        }
    }
    if (deleted_process.stdout_data.len > TSK_OUTPUT_LIMIT - process.stdout_data.len ||
        af_buf_append(&process.stdout_data, deleted_process.stdout_data.data,
                      deleted_process.stdout_data.len) != 0) {
        af_error("combined TSK output exceeds %u bytes", TSK_OUTPUT_LIMIT);
        goto cleanup;
    }
    if (af_write_new_file(raw_path, process.stdout_data.data, process.stdout_data.len) != 0 ||
        af_sha256_file(raw_path, raw_hash) != 0) {
        af_error("cannot preserve TSK output at %s: %s", raw_path, strerror(errno));
        goto cleanup;
    }
    if (af_db_begin(db) != 0 || af_db_ensure_case(db, case_id) != 0) {
        goto cleanup;
    }
    transaction = 1;
    memset(&source, 0, sizeof(source));
    source.case_id = case_id;
    source.kind = "tsk_fls_body";
    source.origin_path = image_path;
    source.stored_path = raw_path;
    source.sha256 = image_hash;
    source.size_bytes = image_size;
    source.tool_name = "fls";
    source.tool_version = version;
    source.command_json = command;
    source.acquired_at = acquired_at;
    source.status = "completed";
    source.raw_sha256 = raw_hash;
    if (af_db_insert_source(db, &source, &source_id) != 0) {
        goto cleanup;
    }
    cursor = process.stdout_data.data;
    while (cursor && *cursor) {
        size_t length;
        line = cursor;
        cursor = strchr(cursor, '\n');
        if (cursor) {
            *cursor++ = '\0';
        }
        length = strlen(line);
        if (length && line[length - 1] == '\r') {
            line[length - 1] = '\0';
        }
        ++line_number;
        if (!line[0] && !cursor) {
            break;
        }
        if (insert_body_event(db, case_id, source_id, host_id, line, line_number,
                              line_number > allocated_records) != 0) {
            goto cleanup;
        }
        ++*count;
    }
    if (*count == 0) {
        af_error("fls produced no filesystem records");
        goto cleanup;
    }
    if (af_db_commit(db) != 0) {
        goto cleanup;
    }
    transaction = 0;
    result = 0;
cleanup:
    if (transaction) {
        af_db_rollback(db);
    }
    af_process_result_free(&process);
    af_process_result_free(&deleted_process);
    free(version);
    free(command);
    free(raw_path);
    return result;
}
