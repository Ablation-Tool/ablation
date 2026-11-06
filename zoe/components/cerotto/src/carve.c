#include "carve.h"
#include "process.h"
#include "util.h"

#include <cJSON.h>
#include <dirent.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define CARVER_OUTPUT_LIMIT (64U * 1024U * 1024U)
#define CARVE_MAX_ARTIFACTS 10000U
#define CARVE_MAX_TOTAL_BYTES (1024ULL * 1024ULL * 1024ULL)

typedef struct {
    char *path;
    int64_t size;
    char hash[65];
} carved_file;

typedef struct {
    carved_file *items;
    size_t count;
    size_t capacity;
    uint64_t total_bytes;
} file_list;

static void free_files(file_list *files) {
    size_t index;
    for (index = 0; index < files->count; ++index) {
        free(files->items[index].path);
    }
    free(files->items);
    memset(files, 0, sizeof(*files));
}

static char *path_join(const char *left, const char *right) {
    char *result = af_path_join(left, right);
    if (!result || strlen(result) > AF_MAX_FIELD) {
        free(result);
        return NULL;
    }
    return result;
}

static int add_file(file_list *files, const char *path, int64_t size) {
    carved_file *expanded;
    carved_file *file;
    if (files->count >= CARVE_MAX_ARTIFACTS || size < 0 ||
        (uint64_t)size > CARVE_MAX_TOTAL_BYTES - files->total_bytes) {
        af_error("carved output exceeds artifact or total-size limits");
        return -1;
    }
    if (files->count == files->capacity) {
        size_t capacity = files->capacity ? files->capacity * 2 : 16;
        expanded = realloc(files->items, capacity * sizeof(*expanded));
        if (!expanded) {
            return -1;
        }
        files->items = expanded;
        files->capacity = capacity;
    }
    file = &files->items[files->count];
    file->path = af_strdup(path);
    file->size = size;
    if (!file->path || af_sha256_file(path, file->hash) != 0) {
        free(file->path);
        file->path = NULL;
        return -1;
    }
    ++files->count;
    files->total_bytes += (uint64_t)size;
    return 0;
}

static int scan_directory(const char *root, const char *relative, file_list *files) {
    char *directory_path = relative[0] ? path_join(root, relative) : af_strdup(root);
    DIR *directory;
    struct dirent *entry;
    int result = -1;
    if (!directory_path) {
        return -1;
    }
    directory = opendir(directory_path);
    if (!directory) {
        af_error("cannot open carver output directory %s: %s", directory_path, strerror(errno));
        free(directory_path);
        return -1;
    }
    errno = 0;
    while ((entry = readdir(directory)) != NULL) {
        char *child_relative;
        char *full_path;
        struct stat status;
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) {
            errno = 0;
            continue;
        }
        child_relative = relative[0] ? path_join(relative, entry->d_name) : af_strdup(entry->d_name);
        if (!child_relative) {
            goto cleanup;
        }
        if (!relative[0] && (!strcmp(child_relative, "audit.txt") || !strcmp(child_relative, "cerotto-carver.log"))) {
            free(child_relative);
            errno = 0;
            continue;
        }
        full_path = path_join(root, child_relative);
        if (!full_path || lstat(full_path, &status) != 0) {
            free(child_relative);
            free(full_path);
            goto cleanup;
        }
        if (S_ISLNK(status.st_mode)) {
            af_error("refusing symbolic link in carver output: %s", full_path);
            free(child_relative);
            free(full_path);
            goto cleanup;
        }
        if (S_ISDIR(status.st_mode)) {
            if (scan_directory(root, child_relative, files) != 0) {
                free(child_relative);
                free(full_path);
                goto cleanup;
            }
        } else if (S_ISREG(status.st_mode)) {
            if (add_file(files, full_path, status.st_size) != 0) {
                free(child_relative);
                free(full_path);
                goto cleanup;
            }
        } else {
            af_error("refusing non-regular carver output: %s", full_path);
            free(child_relative);
            free(full_path);
            goto cleanup;
        }
        free(child_relative);
        free(full_path);
        errno = 0;
    }
    if (errno) {
        af_error("cannot enumerate carver output: %s", strerror(errno));
        goto cleanup;
    }
    result = 0;
cleanup:
    closedir(directory);
    free(directory_path);
    return result;
}

static char *tool_version(const char *carver) {
    char *argv[] = {(char *)carver, "-V", NULL};
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
    result.stdout_data.data[length] = '\0';
    if (length >= AF_MAX_FIELD) {
        af_process_result_free(&result);
        return NULL;
    }
    version = af_strdup(result.stdout_data.data);
    af_process_result_free(&result);
    return version;
}

static char *command_json(const char *carver, const char *image_path, const char *output_dir) {
    cJSON *array = cJSON_CreateArray();
    char *output = NULL;
    int scalpel = !strcmp(carver, "scalpel");
    if (!array || !cJSON_AddItemToArray(array, cJSON_CreateString(carver)) ||
        (scalpel && !cJSON_AddItemToArray(array, cJSON_CreateString("-b"))) ||
        (!scalpel && !cJSON_AddItemToArray(array, cJSON_CreateString("-i"))) ||
        (!scalpel && !cJSON_AddItemToArray(array, cJSON_CreateString(image_path))) ||
        !cJSON_AddItemToArray(array, cJSON_CreateString("-o")) ||
        !cJSON_AddItemToArray(array, cJSON_CreateString(output_dir)) ||
        (scalpel && !cJSON_AddItemToArray(array, cJSON_CreateString(image_path)))) {
        cJSON_Delete(array);
        return NULL;
    }
    output = cJSON_PrintUnformatted(array);
    cJSON_Delete(array);
    return output;
}

static int preserve_log(const char *path, const af_process_result *process, char hash[65]) {
    af_buffer content;
    int result;
    af_buf_init(&content);
    result = af_buf_append(&content, process->stdout_data.data, process->stdout_data.len);
    if (result == 0 && process->stderr_data.len) {
        result = af_buf_append(&content, "\n[stderr]\n", 11);
        if (result == 0) result = af_buf_append(&content, process->stderr_data.data, process->stderr_data.len);
    }
    if (result == 0) result = af_write_new_file(path, content.data, content.len);
    if (result == 0) result = af_sha256_file(path, hash);
    af_buf_free(&content);
    return result;
}

static int insert_run(af_db *db, const char *case_id, const char *image_path, const char *log_path,
                      const char *image_hash, const char *log_hash, int64_t image_size,
                      const char *carver, const char *version, const char *command,
                      const char *acquired_at, const char *status, int64_t *run_id) {
    af_source source;
    memset(&source, 0, sizeof(source));
    source.case_id = case_id;
    source.kind = "carver_run";
    source.origin_path = image_path;
    source.stored_path = log_path;
    source.sha256 = image_hash;
    source.size_bytes = image_size;
    source.tool_name = carver;
    source.tool_version = version;
    source.command_json = command;
    source.acquired_at = acquired_at;
    source.status = status;
    source.raw_sha256 = log_hash;
    return af_db_insert_source(db, &source, run_id);
}

static int insert_artifact(af_db *db, const char *case_id, const char *image_path,
                           const carved_file *file, const char *image_hash, int64_t image_size,
                           const char *carver, const char *version, const char *command,
                           const char *acquired_at, const char *host, int64_t run_id,
                           int64_t *artifact_id) {
    af_source source;
    af_event event;
    cJSON *details = NULL;
    char *printed = NULL;
    char event_id[64];
    int result;
    memset(&source, 0, sizeof(source));
    source.case_id = case_id;
    source.kind = "carved_artifact";
    source.origin_path = image_path;
    source.stored_path = file->path;
    source.sha256 = image_hash;
    source.size_bytes = image_size;
    source.tool_name = carver;
    source.tool_version = version;
    source.command_json = command;
    source.acquired_at = acquired_at;
    source.status = "completed";
    source.raw_sha256 = file->hash;
    if (af_db_insert_source(db, &source, artifact_id) != 0) {
        return -1;
    }
    details = cJSON_CreateObject();
    if (!details || !cJSON_AddStringToObject(details, "sha256", file->hash) ||
        !cJSON_AddNumberToObject(details, "size_bytes", (double)file->size) ||
        !cJSON_AddNumberToObject(details, "carver_run_id", (double)run_id) ||
        snprintf(event_id, sizeof(event_id), "carved-%" PRId64, *artifact_id) >= (int)sizeof(event_id)) {
        cJSON_Delete(details);
        return -1;
    }
    printed = cJSON_PrintUnformatted(details);
    cJSON_Delete(details);
    if (!printed) {
        return -1;
    }
    memset(&event, 0, sizeof(event));
    event.id = event_id;
    event.case_id = case_id;
    event.source_id = *artifact_id;
    event.observed_at = acquired_at;
    event.host_id = host;
    event.source_tool = carver;
    event.event_type = "evidence_recovered";
    event.conversation_id = "";
    event.prompt_id = "";
    event.tool_call_id = "";
    event.process_id = -1;
    event.parent_process_id = -1;
    event.path = file->path;
    event.deleted = -1;
    event.details_json = printed;
    result = af_db_insert_event(db, &event);
    free(printed);
    return result;
}

int af_carve(af_db *db, const char *case_id, const char *image_path,
             const char *output_dir, const char *host_id, const char *carver,
             size_t *count) {
    struct stat status;
    af_process_result process;
    file_list files = {0};
    char image_hash[65];
    char log_hash[65] = "";
    char acquired_at[AF_TIMESTAMP_SIZE];
    char *version = NULL;
    char *command = NULL;
    char *log_path = NULL;
    int64_t image_size;
    int64_t run_id = 0;
    int transaction = 0;
    int result = -1;
    size_t index;
    af_process_result_init(&process);
    *count = 0;
    if (strcmp(carver, "foremost") && strcmp(carver, "scalpel")) {
        af_error("carver must be foremost or scalpel");
        goto cleanup;
    }
    if (stat(image_path, &status) != 0 || !S_ISREG(status.st_mode)) {
        af_error("carving input must be a regular raw image");
        goto cleanup;
    }
    if (lstat(output_dir, &status) == 0 || errno != ENOENT) {
        af_error("carver output path must not already exist: %s", output_dir);
        goto cleanup;
    }
    if (af_file_size(image_path, &image_size) != 0 || af_sha256_file(image_path, image_hash) != 0 ||
        af_now(acquired_at) != 0) {
        af_error("cannot hash carving input or record acquisition time");
        goto cleanup;
    }
    version = tool_version(carver);
    command = command_json(carver, image_path, output_dir);
    if (!version || !command) {
        af_error("cannot prepare %s collection", carver);
        goto cleanup;
    }
    if (!strcmp(carver, "foremost")) {
        char *argv[] = {"foremost", "-i", (char *)image_path, "-o", (char *)output_dir, NULL};
        if (af_process_run(argv, NULL, 0, CARVER_OUTPUT_LIMIT, &process) != 0) goto cleanup;
    } else {
        char *argv[] = {"scalpel", "-b", "-o", (char *)output_dir, (char *)image_path, NULL};
        if (af_process_run(argv, NULL, 0, CARVER_OUTPUT_LIMIT, &process) != 0) goto cleanup;
    }
    if (lstat(output_dir, &status) != 0 || !S_ISDIR(status.st_mode)) {
        af_error("carver did not create a real output directory");
        goto cleanup;
    }
    log_path = af_path_join(output_dir, "cerotto-carver.log");
    if (!log_path || preserve_log(log_path, &process, log_hash) != 0) {
        af_error("cannot preserve carver console output");
        goto cleanup;
    }
    if (process.exit_code == 0 && scan_directory(output_dir, "", &files) != 0) {
        goto cleanup;
    }
    if (af_db_begin(db) != 0 || af_db_ensure_case(db, case_id) != 0) {
        goto cleanup;
    }
    transaction = 1;
    if (insert_run(db, case_id, image_path, log_path, image_hash, log_hash, image_size,
                   carver, version, command, acquired_at,
                   process.exit_code == 0 ? "completed" : "failed", &run_id) != 0) {
        goto cleanup;
    }
    if (process.exit_code == 0) {
        for (index = 0; index < files.count; ++index) {
            int64_t artifact_id;
            if (insert_artifact(db, case_id, image_path, &files.items[index], image_hash, image_size,
                                carver, version, command, acquired_at, host_id, run_id, &artifact_id) != 0) {
                goto cleanup;
            }
        }
    }
    if (af_db_commit(db) != 0) {
        goto cleanup;
    }
    transaction = 0;
    if (process.exit_code != 0) {
        af_error("%s failed with exit code %d; no artifacts accepted", carver, process.exit_code);
        goto cleanup;
    }
    *count = files.count;
    result = 0;
cleanup:
    if (transaction) af_db_rollback(db);
    af_process_result_free(&process);
    free_files(&files);
    free(version);
    free(command);
    free(log_path);
    return result;
}
