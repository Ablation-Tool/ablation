#include "collect.h"
#include "collector_tsk.h"
#include "process.h"
#include "util.h"

#include <cJSON.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define EWF_OUTPUT_LIMIT (16U * 1024U * 1024U)

typedef struct {
    char **paths;
    size_t count;
    size_t capacity;
} segment_list;

static void free_segments(segment_list *segments) {
    size_t index;
    for (index = 0; index < segments->count; ++index) {
        free(segments->paths[index]);
    }
    free(segments->paths);
    memset(segments, 0, sizeof(*segments));
}

static int add_segment(segment_list *segments, const char *path) {
    char **expanded;
    char *copy;
    if (segments->count == segments->capacity) {
        size_t capacity = segments->capacity ? segments->capacity * 2 : 8;
        expanded = realloc(segments->paths, capacity * sizeof(*expanded));
        if (!expanded) {
            return -1;
        }
        segments->paths = expanded;
        segments->capacity = capacity;
    }
    copy = af_strdup(path);
    if (!copy) {
        return -1;
    }
    segments->paths[segments->count++] = copy;
    return 0;
}

static int find_segments(const char *image_path, segment_list *segments) {
    size_t length = strlen(image_path);
    char *prefix;
    char letter;
    int number;
    struct stat status;
    if (length < 4 || strcmp(image_path + length - 4, ".E01")) {
        af_error("EWF input must be the first segment with an .E01 extension");
        return -1;
    }
    prefix = af_strdup(image_path);
    if (!prefix) {
        return -1;
    }
    prefix[length - 4] = '\0';
    for (letter = 'E'; letter <= 'Z'; ++letter) {
        for (number = 1; number <= 99; ++number) {
            char candidate[4096];
            int written = snprintf(candidate, sizeof(candidate), "%s.%c%02d", prefix, letter, number);
            if (written < 0 || (size_t)written >= sizeof(candidate)) {
                free(prefix);
                return -1;
            }
            if (stat(candidate, &status) == 0) {
                if (!S_ISREG(status.st_mode) || add_segment(segments, candidate) != 0) {
                    free(prefix);
                    return -1;
                }
            } else if (errno != ENOENT) {
                free(prefix);
                return -1;
            }
        }
    }
    free(prefix);
    if (!segments->count || strcmp(segments->paths[0], image_path)) {
        af_error("cannot enumerate EWF segments for %s", image_path);
        return -1;
    }
    return 0;
}

static char *tool_version(const char *tool) {
    char *argv[] = {(char *)tool, "-V", NULL};
    af_process_result result;
    char *version = NULL;
    size_t length;
    af_process_result_init(&result);
    if (af_process_run(argv, NULL, 0, 65536, &result) != 0 || result.exit_code != 0 ||
        !result.stdout_data.data) {
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

static cJSON *command_array(const char *tool, const char *image_path) {
    cJSON *array = cJSON_CreateArray();
    if (!array || !cJSON_AddItemToArray(array, cJSON_CreateString(tool)) ||
        !cJSON_AddItemToArray(array, cJSON_CreateString(image_path))) {
        cJSON_Delete(array);
        return NULL;
    }
    return array;
}

static char *commands_json(const char *image_path) {
    cJSON *root = cJSON_CreateObject();
    cJSON *info = command_array("ewfinfo", image_path);
    cJSON *verify = command_array("ewfverify", image_path);
    char *output = NULL;
    if (!root || !info || !verify || !cJSON_AddItemToObject(root, "info", info)) {
        cJSON_Delete(root);
        cJSON_Delete(info);
        cJSON_Delete(verify);
        return NULL;
    }
    info = NULL;
    if (!cJSON_AddItemToObject(root, "verify", verify)) {
        cJSON_Delete(root);
        cJSON_Delete(verify);
        return NULL;
    }
    output = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    return output;
}

static int preserve_output(const char *path, const af_process_result *process, char hash[65]) {
    af_buffer output;
    int result;
    af_buf_init(&output);
    result = af_buf_append(&output, process->stdout_data.data, process->stdout_data.len);
    if (result == 0 && process->stderr_data.len) {
        result = af_buf_append(&output, "\n[stderr]\n", 11);
        if (result == 0) {
            result = af_buf_append(&output, process->stderr_data.data, process->stderr_data.len);
        }
    }
    if (result == 0) {
        result = af_write_new_file(path, output.data, output.len);
    }
    if (result == 0) {
        result = af_sha256_file(path, hash);
    }
    af_buf_free(&output);
    return result;
}

static int insert_source(af_db *db, const char *case_id, const char *kind, const char *origin,
                         const char *stored, const char *hash, const char *raw_hash,
                         const char *tool, const char *version, const char *commands,
                         const char *acquired_at, const char *status) {
    af_source source;
    int64_t size = 0;
    int64_t id;
    if (af_file_size(origin, &size) != 0) {
        return -1;
    }
    memset(&source, 0, sizeof(source));
    source.case_id = case_id;
    source.kind = kind;
    source.origin_path = origin;
    source.stored_path = stored;
    source.sha256 = hash;
    source.size_bytes = size;
    source.tool_name = tool;
    source.tool_version = version;
    source.command_json = commands;
    source.acquired_at = acquired_at;
    source.status = status;
    source.raw_sha256 = raw_hash;
    return af_db_insert_source(db, &source, &id);
}

int af_collect_ewf(af_db *db, const char *case_id, const char *image_path,
                   const char *output_dir, const char *host_id, size_t *count) {
    segment_list segments = {0};
    af_process_result info;
    af_process_result verify;
    char acquired_at[AF_TIMESTAMP_SIZE];
    char info_hash[65] = "";
    char verify_hash[65] = "";
    char first_hash[65];
    char *info_path = NULL;
    char *verify_path = NULL;
    char *info_version = NULL;
    char *verify_version = NULL;
    char *commands = NULL;
    char *info_command = NULL;
    int transaction = 0;
    int result = -1;
    size_t index;
    struct stat status;
    af_process_result_init(&info);
    af_process_result_init(&verify);
    *count = 0;
    if (stat(output_dir, &status) != 0 || !S_ISDIR(status.st_mode) || af_now(acquired_at) != 0) {
        af_error("EWF output must be an existing directory");
        goto cleanup;
    }
    if (find_segments(image_path, &segments) != 0 || af_sha256_file(image_path, first_hash) != 0) {
        af_error("cannot enumerate or hash EWF evidence");
        goto cleanup;
    }
    info_path = af_path_join(output_dir, "ewfinfo.txt");
    verify_path = af_path_join(output_dir, "ewfverify.txt");
    info_version = tool_version("ewfinfo");
    verify_version = tool_version("ewfverify");
    commands = commands_json(image_path);
    {
        cJSON *array = command_array("ewfinfo", image_path);
        if (array) {
            info_command = cJSON_PrintUnformatted(array);
            cJSON_Delete(array);
        }
    }
    if (!info_path || !verify_path || !info_version || !verify_version || !commands || !info_command) {
        af_error("ewfinfo and ewfverify are required for EWF collection");
        goto cleanup;
    }
    {
        char *info_argv[] = {"ewfinfo", (char *)image_path, NULL};
        char *verify_argv[] = {"ewfverify", (char *)image_path, NULL};
        if (af_process_run(info_argv, NULL, 0, EWF_OUTPUT_LIMIT, &info) != 0 ||
            af_process_run(verify_argv, NULL, 0, EWF_OUTPUT_LIMIT, &verify) != 0) {
            goto cleanup;
        }
    }
    if (preserve_output(info_path, &info, info_hash) != 0 ||
        preserve_output(verify_path, &verify, verify_hash) != 0) {
        af_error("cannot preserve EWF metadata or verification output");
        goto cleanup;
    }
    if (af_db_begin(db) != 0 || af_db_ensure_case(db, case_id) != 0) {
        goto cleanup;
    }
    transaction = 1;
    if (insert_source(db, case_id, "ewf_image", image_path, verify_path, first_hash, verify_hash,
                      "ewfverify", verify_version, commands, acquired_at,
                      verify.exit_code == 0 ? "completed" : "failed") != 0 ||
        insert_source(db, case_id, "ewf_metadata", image_path, info_path, first_hash, info_hash,
                      "ewfinfo", info_version, info_command, acquired_at,
                      info.exit_code == 0 ? "completed" : "failed") != 0) {
        goto cleanup;
    }
    for (index = 1; index < segments.count; ++index) {
        char hash[65];
        if (af_sha256_file(segments.paths[index], hash) != 0 ||
            insert_source(db, case_id, "ewf_segment", segments.paths[index], "", hash, "",
                          "ewfverify", verify_version, commands, acquired_at, "completed") != 0) {
            goto cleanup;
        }
    }
    if (af_db_commit(db) != 0) {
        goto cleanup;
    }
    transaction = 0;
    if (info.exit_code != 0 || verify.exit_code != 0) {
        af_error("EWF verification failed (ewfinfo=%d, ewfverify=%d); no filesystem events accepted",
                 info.exit_code, verify.exit_code);
        goto cleanup;
    }
    result = af_collect_tsk_impl(db, case_id, image_path, output_dir, host_id, 1, count);
cleanup:
    if (transaction) {
        af_db_rollback(db);
    }
    af_process_result_free(&info);
    af_process_result_free(&verify);
    free_segments(&segments);
    free(info_path);
    free(verify_path);
    free(info_version);
    free(verify_version);
    free(commands);
    free(info_command);
    return result;
}
