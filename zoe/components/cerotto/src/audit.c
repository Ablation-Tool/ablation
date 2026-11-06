#include "audit.h"
#include "util.h"

#include <cJSON.h>
#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define AUDIT_MAX_GROUPS 100000U
#define AUDIT_MAX_ARGC 1024

typedef struct {
    char *type;
    char *text;
} audit_record;

typedef struct {
    int64_t seconds;
    int microseconds;
    int64_t serial;
    audit_record *records;
    size_t count;
    size_t capacity;
} audit_group;

typedef struct {
    int present;
    int64_t number;
    int64_t pid;
    int64_t ppid;
    int64_t auid;
    int64_t uid;
    int success;
    char *exe;
    char *arch;
} syscall_info;

static void free_group(audit_group *group) {
    size_t index;
    for (index = 0; index < group->count; ++index) {
        free(group->records[index].type);
        free(group->records[index].text);
    }
    free(group->records);
    memset(group, 0, sizeof(*group));
}

static int hex_value(char value) {
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    if (value >= 'A' && value <= 'F') return value - 'A' + 10;
    return -1;
}

static int decode_field(const char *line, const char *key, int allow_hex, char **output) {
    size_t key_length = strlen(key);
    const char *cursor = line;
    const char *start;
    const char *end;
    size_t length;
    char *value;
    size_t i;
    *output = NULL;
    while ((cursor = strstr(cursor, key)) != NULL) {
        if ((cursor == line || cursor[-1] == ' ') && cursor[key_length] == '=') {
            break;
        }
        cursor += key_length;
    }
    if (!cursor) {
        return 0;
    }
    start = cursor + key_length + 1;
    if (*start == '"') {
        int escaped = 0;
        allow_hex = 0;
        ++start;
        end = start;
        while (*end) {
            if (!escaped && *end == '"') {
                break;
            }
            if (!escaped && *end == '\\') escaped = 1;
            else escaped = 0;
            ++end;
        }
        if (*end != '"' || (end[1] && end[1] != ' ')) {
            return -1;
        }
        length = (size_t)(end - start);
        if (length > AF_MAX_FIELD * 2) {
            return -1;
        }
        value = malloc(length + 1);
        if (!value) {
            return -1;
        }
        length = 0;
        while (start < end) {
            if (*start == '\\' && start + 1 < end) {
                ++start;
            }
            value[length++] = *start++;
        }
        value[length] = '\0';
    } else {
        end = strchr(start, ' ');
        if (!end) {
            end = start + strlen(start);
        }
        length = (size_t)(end - start);
        if (!length || length > AF_MAX_FIELD * 2) {
            return -1;
        }
        value = malloc(length + 1);
        if (!value) {
            return -1;
        }
        memcpy(value, start, length);
        value[length] = '\0';
    }
    if (allow_hex && length >= 2 && length % 2 == 0) {
        int is_hex = 1;
        for (i = 0; i < length; ++i) {
            if (hex_value(value[i]) < 0) {
                is_hex = 0;
                break;
            }
        }
        if (is_hex) {
            char *decoded = malloc(length / 2 + 1);
            if (!decoded) {
                free(value);
                return -1;
            }
            for (i = 0; i < length / 2; ++i) {
                decoded[i] = (char)(hex_value(value[i * 2]) * 16 + hex_value(value[i * 2 + 1]));
                if (!decoded[i]) {
                    free(decoded);
                    free(value);
                    return -1;
                }
            }
            decoded[length / 2] = '\0';
            free(value);
            value = decoded;
        }
    }
    if (strlen(value) > AF_MAX_FIELD) {
        free(value);
        return -1;
    }
    *output = value;
    return 1;
}

static int number_field(const char *line, const char *key, int64_t *number) {
    char *text;
    char *end;
    intmax_t parsed;
    int result = decode_field(line, key, 0, &text);
    if (result <= 0) {
        return result;
    }
    errno = 0;
    parsed = strtoimax(text, &end, 10);
    if (errno || end == text || *end || parsed < 0 || parsed > INT64_MAX) {
        free(text);
        return -1;
    }
    free(text);
    *number = (int64_t)parsed;
    return 1;
}

static int parse_message_id(const char *line, int64_t *seconds, int *microseconds, int64_t *serial) {
    const char *start = strstr(line, "msg=audit(");
    char *cursor;
    intmax_t parsed;
    int digits = 0;
    int fraction = 0;
    if (!start) {
        return -1;
    }
    start += 10;
    errno = 0;
    parsed = strtoimax(start, &cursor, 10);
    if (errno || cursor == start || *cursor != '.' || parsed < 0 || parsed > INT64_MAX) {
        return -1;
    }
    *seconds = (int64_t)parsed;
    start = cursor + 1;
    while (isdigit((unsigned char)*start)) {
        if (++digits > 6) {
            return -1;
        }
        fraction = fraction * 10 + *start++ - '0';
    }
    if (!digits || *start != ':') {
        return -1;
    }
    while (digits++ < 6) {
        fraction *= 10;
    }
    *microseconds = fraction;
    ++start;
    errno = 0;
    parsed = strtoimax(start, &cursor, 10);
    if (errno || cursor == start || *cursor != ')' || parsed < 0 || parsed > INT64_MAX) {
        return -1;
    }
    *serial = (int64_t)parsed;
    return 0;
}

static int audit_timestamp(const audit_group *group, char output[AF_TIMESTAMP_SIZE]) {
    time_t seconds = (time_t)group->seconds;
    struct tm broken_down;
    char base[32];
    int length;
    if ((int64_t)seconds != group->seconds || !gmtime_r(&seconds, &broken_down) ||
        !strftime(base, sizeof(base), "%Y-%m-%dT%H:%M:%S", &broken_down)) {
        return -1;
    }
    length = snprintf(output, AF_TIMESTAMP_SIZE, "%s.%06dZ", base, group->microseconds);
    return length == (int)AF_TIMESTAMP_SIZE - 1 ? 0 : -1;
}

static int group_host(const audit_group *group, const char *fallback, char **host) {
    size_t index;
    *host = NULL;
    for (index = 0; index < group->count; ++index) {
        char *node;
        int found = decode_field(group->records[index].text, "node", 0, &node);
        if (found < 0 || (found && strlen(node) > 256)) {
            free(node);
            return -1;
        }
        if (found) {
            if (*host && strcmp(*host, node)) {
                free(node);
                return -1;
            }
            if (!*host) {
                *host = node;
            } else {
                free(node);
            }
        }
    }
    if (!*host) {
        *host = af_strdup(fallback);
    }
    return *host ? 0 : -1;
}

static void free_syscall(syscall_info *info) {
    free(info->exe);
    free(info->arch);
    memset(info, 0, sizeof(*info));
}

static int parse_syscall(const audit_group *group, syscall_info *info) {
    size_t index;
    memset(info, 0, sizeof(*info));
    info->auid = -1;
    info->uid = -1;
    info->success = -1;
    for (index = 0; index < group->count; ++index) {
        const char *line = group->records[index].text;
        char *success;
        int found;
        if (strcmp(group->records[index].type, "SYSCALL")) {
            continue;
        }
        if (info->present || number_field(line, "syscall", &info->number) != 1 ||
            number_field(line, "pid", &info->pid) != 1 || number_field(line, "ppid", &info->ppid) != 1) {
            return -1;
        }
        info->present = 1;
        found = decode_field(line, "success", 0, &success);
        if (found != 1 || (strcmp(success, "yes") && strcmp(success, "no"))) {
            free(success);
            return -1;
        }
        info->success = strcmp(success, "yes") == 0;
        free(success);
        found = number_field(line, "auid", &info->auid);
        if (found < 0) return -1;
        found = number_field(line, "uid", &info->uid);
        if (found < 0) return -1;
        found = decode_field(line, "exe", 1, &info->exe);
        if (found < 0) return -1;
        found = decode_field(line, "arch", 0, &info->arch);
        if (found < 0) return -1;
    }
    return 0;
}

static int is_exec(int64_t number) {
    return number == 59 || number == 322 || number == 11 || number == 358 ||
           number == 221 || number == 281;
}

static int is_connect(int64_t number) {
    return number == 42 || number == 203;
}

static int is_open(int64_t number) {
    return number == 2 || number == 257 || number == 56 || number == 85;
}

static int is_unlink(int64_t number) {
    return number == 87 || number == 263 || number == 35;
}

static cJSON *base_details(const audit_group *group, const syscall_info *info) {
    char audit_id[96];
    cJSON *details;
    if (snprintf(audit_id, sizeof(audit_id), "%" PRId64 ".%06d:%" PRId64,
                 group->seconds, group->microseconds, group->serial) >= (int)sizeof(audit_id)) {
        return NULL;
    }
    details = cJSON_CreateObject();
    if (!details || !cJSON_AddStringToObject(details, "audit_event", audit_id) ||
        !cJSON_AddNumberToObject(details, "syscall", (double)info->number) ||
        !cJSON_AddBoolToObject(details, "success", info->success) ||
        !cJSON_AddNumberToObject(details, "auid", (double)info->auid) ||
        !cJSON_AddNumberToObject(details, "uid", (double)info->uid)) {
        cJSON_Delete(details);
        return NULL;
    }
    if (info->arch && !cJSON_AddStringToObject(details, "arch", info->arch)) {
        cJSON_Delete(details);
        return NULL;
    }
    if (info->exe && !cJSON_AddStringToObject(details, "exe", info->exe)) {
        cJSON_Delete(details);
        return NULL;
    }
    return details;
}

static int emit_event(af_db *db, const char *case_id, int64_t source_id, const char *host,
                      const audit_group *group, const syscall_info *info, const char *timestamp,
                      const char *role, int item, const char *event_type, const char *path,
                      int deleted, cJSON *details, size_t *count) {
    char id[512];
    char *printed = NULL;
    af_event event;
    int result;
    if (!details || snprintf(id, sizeof(id), "audit-%s-%" PRId64 "-%06d-%" PRId64 "-%s-%d",
                            host, group->seconds, group->microseconds, group->serial, role, item) >=
                       (int)sizeof(id)) {
        cJSON_Delete(details);
        return -1;
    }
    printed = cJSON_PrintUnformatted(details);
    cJSON_Delete(details);
    if (!printed) {
        return -1;
    }
    memset(&event, 0, sizeof(event));
    event.id = id;
    event.case_id = case_id;
    event.source_id = source_id;
    event.observed_at = timestamp;
    event.host_id = host;
    event.source_tool = "linux_audit";
    event.event_type = event_type;
    event.conversation_id = "";
    event.prompt_id = "";
    event.tool_call_id = "";
    event.process_id = info->pid;
    event.parent_process_id = info->ppid;
    event.path = path ? path : "";
    event.deleted = deleted;
    event.details_json = printed;
    result = af_db_insert_event(db, &event);
    free(printed);
    if (result == 0) {
        ++*count;
    }
    return result;
}

static int emit_process(af_db *db, const char *case_id, int64_t source_id, const char *host,
                        const audit_group *group, const syscall_info *info, const char *timestamp,
                        size_t *count) {
    cJSON *details = base_details(group, info);
    size_t index;
    int found_execve = 0;
    if (!info->exe || !details) {
        cJSON_Delete(details);
        return -1;
    }
    for (index = 0; index < group->count; ++index) {
        const char *line = group->records[index].text;
        int64_t argc;
        int64_t argument;
        cJSON *arguments;
        if (strcmp(group->records[index].type, "EXECVE")) {
            continue;
        }
        if (found_execve || number_field(line, "argc", &argc) != 1 || argc > AUDIT_MAX_ARGC) {
            cJSON_Delete(details);
            return -1;
        }
        found_execve = 1;
        arguments = cJSON_CreateArray();
        if (!arguments || !cJSON_AddItemToObject(details, "arguments", arguments)) {
            cJSON_Delete(arguments);
            cJSON_Delete(details);
            return -1;
        }
        for (argument = 0; argument < argc; ++argument) {
            char key[32];
            char *value;
            if (snprintf(key, sizeof(key), "a%" PRId64, argument) >= (int)sizeof(key) ||
                decode_field(line, key, 1, &value) != 1) {
                cJSON_Delete(details);
                return -1;
            }
            if (!cJSON_AddItemToArray(arguments, cJSON_CreateString(value))) {
                free(value);
                cJSON_Delete(details);
                return -1;
            }
            free(value);
        }
    }
    if (!found_execve) {
        cJSON_Delete(details);
        return -1;
    }
    return emit_event(db, case_id, source_id, host, group, info, timestamp, "process", 0,
                      info->success ? "process_started" : "process_exec_attempt", info->exe, -1,
                      details, count);
}

static int emit_network(af_db *db, const char *case_id, int64_t source_id, const char *host,
                        const audit_group *group, const syscall_info *info, const char *timestamp,
                        size_t *count) {
    size_t index;
    int emitted = 0;
    for (index = 0; index < group->count; ++index) {
        char *address;
        cJSON *details;
        if (strcmp(group->records[index].type, "SOCKADDR")) {
            continue;
        }
        if (decode_field(group->records[index].text, "saddr", 0, &address) != 1) {
            return -1;
        }
        details = base_details(group, info);
        if (!details || !cJSON_AddStringToObject(details, "socket_address", address)) {
            free(address);
            cJSON_Delete(details);
            return -1;
        }
        if (emit_event(db, case_id, source_id, host, group, info, timestamp, "network", emitted,
                       info->success ? "network_connection" : "network_connection_attempt",
                       address, -1, details, count) != 0) {
            free(address);
            return -1;
        }
        free(address);
        ++emitted;
    }
    return emitted ? 0 : -1;
}

static int emit_files(af_db *db, const char *case_id, int64_t source_id, const char *host,
                      const audit_group *group, const syscall_info *info, const char *timestamp,
                      size_t *count) {
    size_t index;
    int emitted = 0;
    int open_operation = is_open(info->number);
    int unlink_operation = is_unlink(info->number);
    for (index = 0; index < group->count; ++index) {
        const char *line = group->records[index].text;
        char *name = NULL;
        char *nametype = NULL;
        int64_t item = 0;
        int64_t inode = 0;
        int create;
        int remove;
        const char *event_type;
        cJSON *details;
        if (strcmp(group->records[index].type, "PATH")) {
            continue;
        }
        if (decode_field(line, "name", 1, &name) != 1 || decode_field(line, "nametype", 0, &nametype) != 1 ||
            number_field(line, "item", &item) != 1 || number_field(line, "inode", &inode) < 0) {
            free(name);
            free(nametype);
            return -1;
        }
        create = !strcmp(nametype, "CREATE") || info->number == 85;
        remove = !strcmp(nametype, "DELETE") || unlink_operation;
        if (!open_operation && !unlink_operation && !create && !remove) {
            free(name);
            free(nametype);
            continue;
        }
        if (!info->success) event_type = "file_access_attempt";
        else if (remove) event_type = "file_deleted";
        else if (create) event_type = "file_created";
        else event_type = "file_access";
        details = base_details(group, info);
        if (!details || !cJSON_AddNumberToObject(details, "item", (double)item) ||
            !cJSON_AddNumberToObject(details, "inode", (double)inode) ||
            !cJSON_AddStringToObject(details, "nametype", nametype)) {
            free(name);
            free(nametype);
            cJSON_Delete(details);
            return -1;
        }
        if (emit_event(db, case_id, source_id, host, group, info, timestamp, "file", (int)item,
                       event_type, name, remove ? 1 : (create ? 0 : -1), details, count) != 0) {
            free(name);
            free(nametype);
            return -1;
        }
        free(name);
        free(nametype);
        ++emitted;
    }
    if ((open_operation || unlink_operation) && !emitted) {
        return -1;
    }
    return 0;
}

static int process_group(af_db *db, const char *case_id, int64_t source_id, const char *fallback,
                         const audit_group *group, size_t *count) {
    syscall_info info;
    char timestamp[AF_TIMESTAMP_SIZE];
    char *host = NULL;
    int result = -1;
    size_t index;
    if (parse_syscall(group, &info) != 0) {
        free_syscall(&info);
        return -1;
    }
    if (!info.present) {
        for (index = 0; index < group->count; ++index) {
            const char *type = group->records[index].type;
            if (!strcmp(type, "EXECVE") || !strcmp(type, "PATH") || !strcmp(type, "SOCKADDR")) {
                free_syscall(&info);
                return -1;
            }
        }
        free_syscall(&info);
        return 0;
    }
    if (group_host(group, fallback, &host) != 0 || audit_timestamp(group, timestamp) != 0) {
        free(host);
        free_syscall(&info);
        return -1;
    }
    if (is_exec(info.number)) {
        result = emit_process(db, case_id, source_id, host, group, &info, timestamp, count);
    } else if (is_connect(info.number)) {
        result = emit_network(db, case_id, source_id, host, group, &info, timestamp, count);
    } else {
        result = emit_files(db, case_id, source_id, host, group, &info, timestamp, count);
    }
    free(host);
    free_syscall(&info);
    return result;
}

static int append_record(audit_group *group, char *type, char *line) {
    audit_record *records;
    if (group->count == group->capacity) {
        size_t capacity = group->capacity ? group->capacity * 2 : 8;
        records = realloc(group->records, capacity * sizeof(*records));
        if (!records) {
            return -1;
        }
        group->records = records;
        group->capacity = capacity;
    }
    group->records[group->count].type = type;
    group->records[group->count].text = line;
    ++group->count;
    return 0;
}

int af_ingest_audit(af_db *db, const char *case_id, const char *input_path,
                    const char *host_id, int64_t source_id, size_t *count) {
    FILE *input;
    audit_group *groups = NULL;
    size_t group_count = 0;
    size_t group_capacity = 0;
    char *line = NULL;
    size_t line_capacity = 0;
    ssize_t length;
    size_t line_number = 0;
    size_t index;
    int transaction = 0;
    int result = -1;
    *count = 0;
    input = strcmp(input_path, "-") == 0 ? stdin : fopen(input_path, "rb");
    if (!input) {
        af_error("cannot open %s: %s", input_path, strerror(errno));
        return -1;
    }
    while ((length = getline(&line, &line_capacity, input)) >= 0) {
        int64_t seconds;
        int microseconds;
        int64_t serial;
        char *type = NULL;
        char *stored = NULL;
        ++line_number;
        if ((size_t)length > AF_MAX_LINE) {
            af_error("%s:%zu: audit record exceeds %u bytes", input_path, line_number, AF_MAX_LINE);
            goto cleanup;
        }
        while (length > 0 && (line[length - 1] == '\n' || line[length - 1] == '\r')) {
            line[--length] = '\0';
        }
        if (!length) {
            continue;
        }
        if (parse_message_id(line, &seconds, &microseconds, &serial) != 0 ||
            decode_field(line, "type", 0, &type) != 1) {
            af_error("%s:%zu: malformed audit record or missing msg=audit ID", input_path, line_number);
            free(type);
            goto cleanup;
        }
        for (index = 0; index < group_count; ++index) {
            if (groups[index].seconds == seconds && groups[index].microseconds == microseconds &&
                groups[index].serial == serial) {
                break;
            }
        }
        if (index == group_count) {
            audit_group *expanded;
            if (group_count >= AUDIT_MAX_GROUPS) {
                af_error("audit input exceeds %u event groups", AUDIT_MAX_GROUPS);
                free(type);
                goto cleanup;
            }
            if (group_count == group_capacity) {
                size_t capacity = group_capacity ? group_capacity * 2 : 16;
                expanded = realloc(groups, capacity * sizeof(*groups));
                if (!expanded) {
                    free(type);
                    goto cleanup;
                }
                groups = expanded;
                group_capacity = capacity;
            }
            memset(&groups[group_count], 0, sizeof(*groups));
            groups[group_count].seconds = seconds;
            groups[group_count].microseconds = microseconds;
            groups[group_count].serial = serial;
            ++group_count;
        }
        stored = af_strdup(line);
        if (!stored || append_record(&groups[index], type, stored) != 0) {
            free(type);
            free(stored);
            goto cleanup;
        }
    }
    if (ferror(input) || af_db_begin(db) != 0) {
        goto cleanup;
    }
    transaction = 1;
    for (index = 0; index < group_count; ++index) {
        if (process_group(db, case_id, source_id, host_id, &groups[index], count) != 0) {
            af_error("%s: invalid or incomplete audit event %" PRId64 ".%06d:%" PRId64,
                     input_path, groups[index].seconds, groups[index].microseconds, groups[index].serial);
            goto cleanup;
        }
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
    for (index = 0; index < group_count; ++index) {
        free_group(&groups[index]);
    }
    free(groups);
    free(line);
    if (input != stdin) {
        fclose(input);
    }
    return result;
}
