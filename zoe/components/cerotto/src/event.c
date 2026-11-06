#include "event.h"
#include "util.h"

#include <cJSON.h>
#include <ctype.h>
#include <errno.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int get_string(cJSON *object, const char *name, int required, const char **value) {
    cJSON *item = cJSON_GetObjectItemCaseSensitive(object, name);
    *value = "";
    if (!item) {
        if (required) {
            af_error("missing required event field: %s", name);
            return -1;
        }
        return 0;
    }
    if (!cJSON_IsString(item) || !item->valuestring || strlen(item->valuestring) > AF_MAX_FIELD) {
        af_error("event field %s must be a string of at most %u bytes", name, AF_MAX_FIELD);
        return -1;
    }
    if (required && item->valuestring[0] == '\0') {
        af_error("event field %s cannot be empty", name);
        return -1;
    }
    *value = item->valuestring;
    return 0;
}

static int parse_event(cJSON *object, const char *case_id, int64_t source_id,
                       const char *timestamp, af_event *event, char **details) {
    cJSON *process;
    cJSON *deleted;
    cJSON *details_object;
    memset(event, 0, sizeof(*event));
    event->case_id = case_id;
    event->source_id = source_id;
    event->process_id = -1;
    event->parent_process_id = -1;
    event->deleted = -1;
    event->details_json = "{}";
    if (!cJSON_IsObject(object)) {
        af_error("each JSONL record must be an object");
        return -1;
    }
    if (get_string(object, "id", 1, &event->id) ||
        get_string(object, "host_id", 1, &event->host_id) ||
        get_string(object, "source_tool", 1, &event->source_tool) ||
        get_string(object, "event_type", 1, &event->event_type) ||
        get_string(object, "conversation_id", 0, &event->conversation_id) ||
        get_string(object, "prompt_id", 0, &event->prompt_id) ||
        get_string(object, "tool_call_id", 0, &event->tool_call_id) ||
        get_string(object, "path", 0, &event->path)) {
        return -1;
    }
    event->observed_at = timestamp;
    process = cJSON_GetObjectItemCaseSensitive(object, "process_id");
    if (process) {
        if (!cJSON_IsNumber(process) || !isfinite(process->valuedouble) ||
            process->valuedouble < 0 || process->valuedouble > 9007199254740991.0 ||
            floor(process->valuedouble) != process->valuedouble) {
            af_error("event field process_id must be a nonnegative safe integer");
            return -1;
        }
        event->process_id = (int64_t)process->valuedouble;
    }
    process = cJSON_GetObjectItemCaseSensitive(object, "parent_process_id");
    if (process) {
        if (!cJSON_IsNumber(process) || !isfinite(process->valuedouble) ||
            process->valuedouble < 0 || process->valuedouble > 9007199254740991.0 ||
            floor(process->valuedouble) != process->valuedouble) {
            af_error("event field parent_process_id must be a nonnegative safe integer");
            return -1;
        }
        event->parent_process_id = (int64_t)process->valuedouble;
    }
    deleted = cJSON_GetObjectItemCaseSensitive(object, "deleted");
    if (deleted) {
        if (!cJSON_IsBool(deleted)) {
            af_error("event field deleted must be a boolean");
            return -1;
        }
        event->deleted = cJSON_IsTrue(deleted) ? 1 : 0;
    }
    details_object = cJSON_GetObjectItemCaseSensitive(object, "details");
    if (details_object) {
        if (!cJSON_IsObject(details_object)) {
            af_error("event field details must be an object");
            return -1;
        }
        *details = cJSON_PrintUnformatted(details_object);
        if (!*details) {
            af_error("cannot serialize event details");
            return -1;
        }
        event->details_json = *details;
    }
    return 0;
}

int af_ingest_jsonl(af_db *db, const char *case_id, const char *input_path,
                    int64_t source_id, size_t *count) {
    FILE *input;
    char *line = NULL;
    size_t capacity = 0;
    ssize_t length;
    size_t line_number = 0;
    int result = -1;
    *count = 0;
    input = strcmp(input_path, "-") == 0 ? stdin : fopen(input_path, "rb");
    if (!input) {
        af_error("cannot open %s: %s", input_path, strerror(errno));
        return -1;
    }
    if (af_db_begin(db) != 0) {
        goto cleanup;
    }
    while ((length = getline(&line, &capacity, input)) >= 0) {
        cJSON *object = NULL;
        cJSON *timestamp_item;
        char timestamp[AF_TIMESTAMP_SIZE];
        char *details = NULL;
        af_event event;
        ++line_number;
        if ((size_t)length > AF_MAX_LINE) {
            af_error("%s:%zu: record exceeds %u bytes", input_path, line_number, AF_MAX_LINE);
            goto rollback;
        }
        while (length > 0 && (line[length - 1] == '\n' || line[length - 1] == '\r')) {
            line[--length] = '\0';
        }
        if (length == 0) {
            af_error("%s:%zu: empty record", input_path, line_number);
            goto rollback;
        }
        object = cJSON_ParseWithLength(line, (size_t)length);
        if (!object) {
            af_error("%s:%zu: invalid JSON", input_path, line_number);
            goto rollback;
        }
        timestamp_item = cJSON_GetObjectItemCaseSensitive(object, "observed_at");
        if (!cJSON_IsString(timestamp_item) ||
            af_timestamp_normalize(timestamp_item->valuestring, timestamp) != 0) {
            af_error("%s:%zu: observed_at must be an ISO-8601 UTC timestamp with at most six fractional digits", input_path, line_number);
            cJSON_Delete(object);
            goto rollback;
        }
        if (parse_event(object, case_id, source_id, timestamp, &event, &details) != 0) {
            af_error("%s:%zu: invalid event", input_path, line_number);
            free(details);
            cJSON_Delete(object);
            goto rollback;
        }
        if (af_db_insert_event(db, &event) != 0) {
            af_error("%s:%zu: event insertion failed", input_path, line_number);
            free(details);
            cJSON_Delete(object);
            goto rollback;
        }
        free(details);
        cJSON_Delete(object);
        ++*count;
    }
    if (ferror(input)) {
        af_error("cannot read %s: %s", input_path, strerror(errno));
        goto rollback;
    }
    if (af_db_commit(db) != 0) {
        goto cleanup;
    }
    result = 0;
    goto cleanup;
rollback:
    af_db_rollback(db);
cleanup:
    free(line);
    if (input != stdin && fclose(input) != 0) {
        af_error("cannot close %s: %s", input_path, strerror(errno));
        result = -1;
    }
    return result;
}
