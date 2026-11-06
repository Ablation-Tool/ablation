#include "guard.h"
#include "db.h"
#include "forecast.h"
#include "manifest.h"
#include "timeline.h"
#include "util.h"

#include <cJSON.h>
#include <errno.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define GUARD_INPUT_LIMIT (16U * 1024U * 1024U)
#define GUARD_POLICY_VERSION "cerotto-evidence-v1"
#define GUARD_SOURCE_TOOL "cerotto-native-guard-v1"

static int valid_text(const char *value, size_t maximum, int empty) {
    const unsigned char *cursor = (const unsigned char *)value;
    size_t length;
    if (!value || (!empty && !value[0])) {
        return 0;
    }
    length = strlen(value);
    if (length > maximum) {
        return 0;
    }
    while (*cursor) {
        if (*cursor < 0x20 || *cursor == 0x7f) {
            return 0;
        }
        ++cursor;
    }
    return 1;
}

static int fields_allowed(cJSON *object, const char *const *names, size_t count) {
    cJSON *field;
    int fields = 0;
    if (!cJSON_IsObject(object)) {
        return -1;
    }
    for (field = object->child; field; field = field->next) {
        cJSON *previous;
        size_t index;
        int allowed = 0;
        for (index = 0; index < count; ++index) {
            if (field->string && strcmp(field->string, names[index]) == 0) {
                allowed = 1;
                break;
            }
        }
        if (!allowed) {
            return -1;
        }
        for (previous = object->child; previous != field; previous = previous->next) {
            if (previous->string && field->string && strcmp(previous->string, field->string) == 0) {
                return -1;
            }
        }
        ++fields;
    }
    return fields;
}

static int fields_exact(cJSON *object, const char *const *names, size_t count) {
    return fields_allowed(object, names, count) == (int)count;
}

static int safe_integer(cJSON *item, int64_t *value) {
    if (!cJSON_IsNumber(item) || !isfinite(item->valuedouble) ||
        item->valuedouble < 0 || item->valuedouble > 9007199254740991.0 ||
        floor(item->valuedouble) != item->valuedouble) {
        return -1;
    }
    *value = (int64_t)item->valuedouble;
    return 0;
}

static int valid_digest(const char *value) {
    size_t index;
    if (!value || strlen(value) != 64) {
        return 0;
    }
    for (index = 0; index < 64; ++index) {
        if ((value[index] < '0' || value[index] > '9') && (value[index] < 'a' || value[index] > 'f')) {
            return 0;
        }
    }
    return 1;
}

static char *read_input(const char *path, size_t *length) {
    FILE *file = NULL;
    char *content = NULL;
    int64_t size = 0;
    if (af_file_size(path, &size) != 0 || size < 1 || size > GUARD_INPUT_LIMIT) {
        return NULL;
    }
    file = fopen(path, "rb");
    if (!file) {
        return NULL;
    }
    content = malloc((size_t)size + 1);
    if (!content || fread(content, 1, (size_t)size, file) != (size_t)size || ferror(file)) {
        free(content);
        fclose(file);
        return NULL;
    }
    if (fclose(file) != 0) {
        free(content);
        return NULL;
    }
    content[size] = '\0';
    *length = (size_t)size;
    return content;
}

static int forecast_context(const char *case_id, cJSON *proposal, char output[65]) {
    cJSON *context = cJSON_CreateObject();
    cJSON *arguments = cJSON_GetObjectItemCaseSensitive(proposal, "arguments");
    char *printed = NULL;
    int result = -1;
    if (!context ||
        !cJSON_AddStringToObject(context, "case_id", case_id) ||
        !cJSON_AddStringToObject(context, "conversation_id", cJSON_GetObjectItemCaseSensitive(proposal, "conversation_id")->valuestring) ||
        !cJSON_AddItemToObject(context, "expected_event_count", cJSON_Duplicate(cJSON_GetObjectItemCaseSensitive(proposal, "expected_event_count"), 1)) ||
        !cJSON_AddStringToObject(context, "action", cJSON_GetObjectItemCaseSensitive(proposal, "action")->valuestring) ||
        !cJSON_AddItemToObject(context, "arguments", cJSON_Duplicate(arguments, 1))) {
        goto cleanup;
    }
    printed = cJSON_PrintUnformatted(context);
    if (printed && af_sha256_bytes(printed, strlen(printed), output) == 0) {
        result = 0;
    }
cleanup:
    free(printed);
    cJSON_Delete(context);
    return result;
}

static int current_event_count(af_db *db, const char *case_id, int64_t *count) {
    sqlite3_stmt *statement = NULL;
    int result = -1;
    if (sqlite3_prepare_v2(db->handle, "SELECT COUNT(*) FROM events WHERE case_id=?1", -1, &statement, NULL) != SQLITE_OK) {
        return -1;
    }
    sqlite3_bind_text(statement, 1, case_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(statement) == SQLITE_ROW) {
        *count = sqlite3_column_int64(statement, 0);
        result = 0;
    }
    sqlite3_finalize(statement);
    return result;
}

static const char *validate_action(cJSON *proposal, af_timeline_query *query,
                                   char from[AF_TIMESTAMP_SIZE], char to[AF_TIMESTAMP_SIZE],
                                   const char **event_id) {
    const char *action = cJSON_GetObjectItemCaseSensitive(proposal, "action")->valuestring;
    cJSON *arguments = cJSON_GetObjectItemCaseSensitive(proposal, "arguments");
    memset(query, 0, sizeof(*query));
    query->case_id = cJSON_GetObjectItemCaseSensitive(proposal, "case_id")->valuestring;
    query->conversation_id = cJSON_GetObjectItemCaseSensitive(proposal, "conversation_id")->valuestring;
    query->host_id = cJSON_GetObjectItemCaseSensitive(proposal, "host_id")->valuestring;
    query->limit = 200;
    *event_id = NULL;
    if (strcmp(action, "query_timeline") == 0) {
        static const char *const allowed[] = {"from", "to", "limit"};
        cJSON *limit;
        cJSON *from_value;
        cJSON *to_value;
        if (fields_allowed(arguments, allowed, 3) < 0) {
            return "timeline_arguments_invalid";
        }
        limit = cJSON_GetObjectItemCaseSensitive(arguments, "limit");
        if (limit) {
            int64_t parsed;
            if (safe_integer(limit, &parsed) != 0 || parsed < 1 || parsed > 1000) {
                return "timeline_limit_invalid";
            }
            query->limit = (size_t)parsed;
        }
        from_value = cJSON_GetObjectItemCaseSensitive(arguments, "from");
        to_value = cJSON_GetObjectItemCaseSensitive(arguments, "to");
        if (from_value && (!cJSON_IsString(from_value) || af_timestamp_normalize(from_value->valuestring, from) != 0)) {
            return "timeline_from_invalid";
        }
        if (to_value && (!cJSON_IsString(to_value) || af_timestamp_normalize(to_value->valuestring, to) != 0)) {
            return "timeline_to_invalid";
        }
        query->from = from_value ? from : "";
        query->to = to_value ? to : "";
        if (from_value && to_value && strcmp(from, to) >= 0) {
            return "timeline_range_invalid";
        }
        return NULL;
    }
    if (strcmp(action, "get_event") == 0) {
        static const char *const allowed[] = {"event_id"};
        cJSON *id;
        if (!fields_exact(arguments, allowed, 1)) {
            return "event_arguments_invalid";
        }
        id = cJSON_GetObjectItemCaseSensitive(arguments, "event_id");
        if (!cJSON_IsString(id) || !valid_text(id->valuestring, AF_MAX_FIELD, 0)) {
            return "event_id_invalid";
        }
        *event_id = id->valuestring;
        query->limit = 10000;
        return NULL;
    }
    if (strcmp(action, "get_manifest") == 0 || strcmp(action, "verify_case") == 0) {
        if (fields_allowed(arguments, NULL, 0) != 0) {
            return "case_arguments_invalid";
        }
        return NULL;
    }
    return "command_not_supported";
}

static cJSON *execute_action(af_db *db, const char *action, const char *event_id,
                             const af_timeline_query *query, cJSON **summary) {
    cJSON *result = NULL;
    *summary = cJSON_CreateObject();
    if (!*summary) {
        return NULL;
    }
    if (strcmp(action, "get_manifest") == 0) {
        result = af_manifest_create(db, query->case_id);
        if (result) {
            cJSON *sources = cJSON_GetObjectItemCaseSensitive(result, "sources");
            cJSON_AddNumberToObject(*summary, "source_count", cJSON_GetArraySize(sources));
        }
        return result;
    }
    if (strcmp(action, "verify_case") == 0) {
        char *text = NULL;
        size_t length = 0;
        FILE *stream = open_memstream(&text, &length);
        int status;
        if (!stream) {
            cJSON_Delete(*summary);
            *summary = NULL;
            return NULL;
        }
        status = af_verify_case(db, query->case_id, NULL, stream);
        if (fclose(stream) != 0) {
            status = -1;
        }
        if (status >= 0 && text) {
            result = cJSON_ParseWithLength(text, length);
        }
        free(text);
        if (result) {
            cJSON *verified = cJSON_GetObjectItemCaseSensitive(result, "verified");
            if (cJSON_IsBool(verified)) {
                cJSON_AddBoolToObject(*summary, "verified", cJSON_IsTrue(verified));
            }
        }
        return result;
    }
    {
        af_buffer json;
        cJSON *timeline = NULL;
        af_buf_init(&json);
        if (af_timeline_build(db, query, &json) != 0) {
            af_buf_free(&json);
            cJSON_Delete(*summary);
            *summary = NULL;
            return NULL;
        }
        timeline = cJSON_ParseWithLength(json.data, json.len);
        af_buf_free(&json);
        if (!timeline) {
            cJSON_Delete(*summary);
            *summary = NULL;
            return NULL;
        }
        if (strcmp(action, "query_timeline") == 0) {
            cJSON *events = cJSON_GetObjectItemCaseSensitive(timeline, "events");
            cJSON_AddNumberToObject(*summary, "result_event_count", cJSON_GetArraySize(events));
            return timeline;
        }
        {
            cJSON *events = cJSON_GetObjectItemCaseSensitive(timeline, "events");
            cJSON *event;
            cJSON_ArrayForEach(event, events) {
                cJSON *id = cJSON_GetObjectItemCaseSensitive(event, "event_id");
                if (cJSON_IsString(id) && strcmp(id->valuestring, event_id) == 0) {
                    result = cJSON_Duplicate(event, 1);
                    break;
                }
            }
            cJSON_Delete(timeline);
            if (result) {
                cJSON_AddStringToObject(*summary, "event_id", event_id);
            }
            return result;
        }
    }
}

static int insert_guard_event(af_db *db, const char *case_id, int64_t source_id, const char *action_id,
                              const char *host_id, const char *conversation_id,
                              const char *context_hash, int sequence, const char *event_type,
                              cJSON *details) {
    af_event event;
    char id[400];
    char timestamp[AF_TIMESTAMP_SIZE];
    char *printed = cJSON_PrintUnformatted(details);
    int result;
    cJSON_Delete(details);
    if (!printed || snprintf(id, sizeof(id), "native-guard:%s:%02d:%s", action_id, sequence, event_type) >= (int)sizeof(id) ||
        af_now(timestamp) != 0) {
        free(printed);
        return -1;
    }
    memset(&event, 0, sizeof(event));
    event.id = id;
    event.case_id = case_id;
    event.source_id = source_id;
    event.observed_at = timestamp;
    event.host_id = host_id;
    event.source_tool = GUARD_SOURCE_TOOL;
    event.event_type = event_type;
    event.conversation_id = conversation_id;
    event.prompt_id = context_hash;
    event.tool_call_id = action_id;
    event.path = "";
    event.process_id = -1;
    event.parent_process_id = -1;
    event.deleted = -1;
    event.details_json = printed;
    result = af_db_insert_event(db, &event);
    free(printed);
    return result;
}

static cJSON *forecast_details(cJSON *forecast, const char *context_hash,
                               const af_forecast_measurement *measurement) {
    cJSON *details = cJSON_CreateObject();
    cJSON *model = cJSON_GetObjectItemCaseSensitive(forecast, "model");
    if (!details || !cJSON_AddStringToObject(details, "model", model->valuestring) ||
        !cJSON_AddStringToObject(details, "context_sha256", context_hash) ||
        !cJSON_AddStringToObject(details, "forecast_source", "caller_supplied_distribution") ||
        !cJSON_AddItemToObject(details, "measurement", af_forecast_measurement_json(measurement))) {
        cJSON_Delete(details);
        return NULL;
    }
    return details;
}

static cJSON *proposal_details(cJSON *proposal) {
    cJSON *details = cJSON_CreateObject();
    if (!details || !cJSON_AddStringToObject(details, "action", cJSON_GetObjectItemCaseSensitive(proposal, "action")->valuestring) ||
        !cJSON_AddItemToObject(details, "arguments", cJSON_Duplicate(cJSON_GetObjectItemCaseSensitive(proposal, "arguments"), 1))) {
        cJSON_Delete(details);
        return NULL;
    }
    return details;
}

static cJSON *decision_details(const char *decision, const char *reason, int64_t event_count) {
    cJSON *details = cJSON_CreateObject();
    if (!details || !cJSON_AddStringToObject(details, "policy_version", GUARD_POLICY_VERSION) ||
        !cJSON_AddStringToObject(details, "decision", decision) ||
        !cJSON_AddStringToObject(details, "reason", reason) ||
        !cJSON_AddNumberToObject(details, "case_event_count", (double)event_count) ||
        !cJSON_AddStringToObject(details, "accessible_volume_role", "observational")) {
        cJSON_Delete(details);
        return NULL;
    }
    return details;
}

static int write_result(const char *path, cJSON *document) {
    char *printed = cJSON_PrintUnformatted(document);
    af_buffer output;
    int result = -1;
    if (!printed) {
        return -1;
    }
    af_buf_init(&output);
    if (af_buf_append(&output, printed, strlen(printed)) == 0 && af_buf_append(&output, "\n", 1) == 0) {
        if (path) {
            result = af_write_new_file(path, output.data, output.len);
        } else if (fwrite(output.data, 1, output.len, stdout) == output.len) {
            result = 0;
        }
    }
    af_buf_free(&output);
    free(printed);
    return result;
}

int af_guard_run(const char *database_path, const char *case_id,
                 const char *input_path, const char *output_path) {
    static const char *const proposal_fields[] = {
        "schema_version", "action_id", "host_id", "conversation_id",
        "expected_event_count", "action", "arguments", "forecast",
    };
    static const char *const forecast_fields[] = {"model", "context_sha256", "probabilities"};
    af_db db = {0};
    cJSON *proposal = NULL;
    cJSON *forecast = NULL;
    cJSON *result_document = NULL;
    cJSON *execution_result = NULL;
    cJSON *execution_summary = NULL;
    char *input = NULL;
    size_t input_length = 0;
    char context_hash[65];
    af_forecast_measurement measurement;
    af_timeline_query query;
    char from[AF_TIMESTAMP_SIZE];
    char to[AF_TIMESTAMP_SIZE];
    const char *event_id = NULL;
    const char *action;
    const char *action_id;
    const char *host_id;
    const char *conversation_id;
    const char *forecast_hash;
    const char *policy_reason;
    int64_t expected_count;
    int64_t actual_count = 0;
    int64_t source_id = 0;
    int exists = 0;
    int transaction = 0;
    int executed = 0;
    int succeeded = 0;
    int status = 1;
    if (!database_path || !case_id || !input_path || !valid_text(case_id, 256, 0)) {
        af_error("guard requires --db, --case, and --input");
        return 1;
    }
    if (output_path && (access(output_path, F_OK) == 0 || errno != ENOENT)) {
        af_error("guard output already exists or cannot be checked: %s", output_path);
        return 1;
    }
    input = read_input(input_path, &input_length);
    if (!input) {
        af_error("cannot read a bounded guard proposal from %s", input_path);
        return 1;
    }
    proposal = cJSON_ParseWithLengthOpts(input, input_length + 1, NULL, 1);
    if (!proposal || !fields_exact(proposal, proposal_fields, 8) ||
        !cJSON_IsNumber(cJSON_GetObjectItemCaseSensitive(proposal, "schema_version")) ||
        cJSON_GetObjectItemCaseSensitive(proposal, "schema_version")->valuedouble != 1) {
        af_error("guard proposal must be one schema-version-1 object");
        goto cleanup;
    }
    action_id = cJSON_GetObjectItemCaseSensitive(proposal, "action_id")->valuestring;
    host_id = cJSON_GetObjectItemCaseSensitive(proposal, "host_id")->valuestring;
    conversation_id = cJSON_GetObjectItemCaseSensitive(proposal, "conversation_id")->valuestring;
    action = cJSON_GetObjectItemCaseSensitive(proposal, "action")->valuestring;
    if (!valid_text(action_id, 128, 0) || !valid_text(host_id, 256, 0) ||
        !valid_text(conversation_id, 256, 0) || !valid_text(action, 128, 0) ||
        !cJSON_IsObject(cJSON_GetObjectItemCaseSensitive(proposal, "arguments")) ||
        safe_integer(cJSON_GetObjectItemCaseSensitive(proposal, "expected_event_count"), &expected_count) != 0) {
        af_error("guard proposal contains invalid identity, action, arguments, or case state");
        goto cleanup;
    }
    if (!cJSON_AddStringToObject(proposal, "case_id", case_id)) {
        goto cleanup;
    }
    forecast = cJSON_GetObjectItemCaseSensitive(proposal, "forecast");
    if (!fields_exact(forecast, forecast_fields, 3) ||
        !cJSON_IsString(cJSON_GetObjectItemCaseSensitive(forecast, "model")) ||
        !valid_text(cJSON_GetObjectItemCaseSensitive(forecast, "model")->valuestring, AF_MAX_FIELD, 0) ||
        !cJSON_IsString(cJSON_GetObjectItemCaseSensitive(forecast, "context_sha256")) ||
        !valid_digest(cJSON_GetObjectItemCaseSensitive(forecast, "context_sha256")->valuestring) ||
        af_forecast_measure(cJSON_GetObjectItemCaseSensitive(forecast, "probabilities"), &measurement) != 0 ||
        forecast_context(case_id, proposal, context_hash) != 0) {
        af_error("guard forecast is invalid");
        goto cleanup;
    }
    forecast_hash = cJSON_GetObjectItemCaseSensitive(forecast, "context_sha256")->valuestring;
    if (af_db_open(database_path, &db) != 0 || af_db_init(&db) != 0 ||
        af_db_case_exists(&db, case_id, &exists) != 0 || !exists) {
        af_error("guard case is unavailable: %s", case_id);
        goto cleanup;
    }
    if (af_db_begin(&db) != 0) {
        goto cleanup;
    }
    transaction = 1;
    {
        af_source source;
        char source_hash[65];
        char acquired_at[AF_TIMESTAMP_SIZE];
        int64_t source_size = 0;
        if (af_sha256_file(input_path, source_hash) != 0 || af_file_size(input_path, &source_size) != 0 ||
            af_now(acquired_at) != 0) {
            goto cleanup;
        }
        memset(&source, 0, sizeof(source));
        source.case_id = case_id;
        source.kind = "guard_proposal";
        source.origin_path = input_path;
        source.stored_path = "";
        source.sha256 = source_hash;
        source.size_bytes = source_size;
        source.tool_name = GUARD_SOURCE_TOOL;
        source.tool_version = "1";
        source.command_json = "[]";
        source.acquired_at = acquired_at;
        source.status = "completed";
        source.raw_sha256 = source_hash;
        if (af_db_insert_source(&db, &source, &source_id) != 0) {
            goto cleanup;
        }
    }
    if (current_event_count(&db, case_id, &actual_count) != 0) {
        goto cleanup;
    }
    policy_reason = validate_action(proposal, &query, from, to, &event_id);
    if (!policy_reason && expected_count != actual_count) {
        policy_reason = "stale_case_event_count";
    }
    if (!policy_reason && strcmp(forecast_hash, context_hash) != 0) {
        policy_reason = "forecast_context_mismatch";
    }
    if (!policy_reason) {
        executed = 1;
        execution_result = execute_action(&db, action, event_id, &query, &execution_summary);
        succeeded = execution_result != NULL;
    }
    result_document = cJSON_CreateObject();
    if (!result_document || !cJSON_AddNumberToObject(result_document, "schema_version", 1) ||
        !cJSON_AddStringToObject(result_document, "action_id", action_id) ||
        !cJSON_AddStringToObject(result_document, "decision", policy_reason ? "deny" : "allow") ||
        !cJSON_AddStringToObject(result_document, "reason", policy_reason ? policy_reason : (succeeded ? "authorized" : "action_execution_failed")) ||
        !cJSON_AddBoolToObject(result_document, "executed", executed) ||
        !cJSON_AddBoolToObject(result_document, "succeeded", succeeded) ||
        !cJSON_AddNumberToObject(result_document, "case_event_count", (double)actual_count)) {
        goto cleanup;
    }
    if (execution_result && !cJSON_AddItemToObject(result_document, "result", execution_result)) {
        goto cleanup;
    }
    if (execution_result) {
        execution_result = NULL;
    }
    if (!succeeded && executed && !cJSON_AddStringToObject(result_document, "error", "the action did not return a valid scoped result")) {
        goto cleanup;
    }
    if (insert_guard_event(&db, case_id, source_id, action_id, host_id, conversation_id, context_hash,
                           1, "model_forecast", forecast_details(forecast, context_hash, &measurement)) != 0 ||
        insert_guard_event(&db, case_id, source_id, action_id, host_id, conversation_id, context_hash,
                           2, "action_proposal", proposal_details(proposal)) != 0 ||
        insert_guard_event(&db, case_id, source_id, action_id, host_id, conversation_id, context_hash,
                           3, "policy_decision", decision_details(policy_reason ? "deny" : "allow", policy_reason ? policy_reason : "authorized", actual_count)) != 0) {
        goto cleanup;
    }
    if (executed) {
        cJSON *receipt = cJSON_CreateObject();
        if (!receipt || !cJSON_AddStringToObject(receipt, "status", succeeded ? "succeeded" : "failed") ||
            (execution_summary && !cJSON_AddItemToObject(receipt, "result", execution_summary))) {
            cJSON_Delete(receipt);
            goto cleanup;
        }
        if (execution_summary) {
            execution_summary = NULL;
        }
        if (insert_guard_event(&db, case_id, source_id, action_id, host_id, conversation_id, context_hash,
                               4, "execution_receipt", receipt) != 0) {
            goto cleanup;
        }
    }
    if (af_db_commit(&db) != 0) {
        transaction = 0;
        goto cleanup;
    }
    transaction = 0;
    if (write_result(output_path, result_document) != 0) {
        af_error("cannot write guard result");
        goto cleanup;
    }
    status = policy_reason ? 3 : (succeeded ? 0 : 1);
cleanup:
    if (transaction) {
        af_db_rollback(&db);
    }
    if (db.handle) {
        af_db_close(&db);
    }
    cJSON_Delete(proposal);
    cJSON_Delete(execution_result);
    cJSON_Delete(execution_summary);
    cJSON_Delete(result_document);
    free(input);
    return status;
}
