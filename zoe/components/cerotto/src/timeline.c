#include "timeline.h"

#include <cJSON.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *column_text(sqlite3_stmt *statement, int column) {
    const unsigned char *value = sqlite3_column_text(statement, column);
    return value ? (const char *)value : "";
}

static int add_string(cJSON *object, const char *name, const char *value) {
    return cJSON_AddStringToObject(object, name, value) ? 0 : -1;
}

int af_timeline_build(af_db *db, const af_timeline_query *query, af_buffer *json) {
    static const char sql[] =
        "SELECT id,source_id,observed_at,host_id,source_tool,event_type,conversation_id,"
        "prompt_id,tool_call_id,process_id,parent_process_id,path,deleted,details_json FROM events "
        "WHERE case_id=?1 AND (?2='' OR observed_at>=?2) AND (?3='' OR observed_at<?3) "
        "AND (conversation_id=?4 OR (host_id IN "
        "(SELECT DISTINCT host_id FROM events WHERE case_id=?1 AND conversation_id=?4) "
        "AND (?5='' OR host_id=?5))) ORDER BY observed_at,id LIMIT ?6";
    sqlite3_stmt *statement = NULL;
    cJSON *root = NULL;
    cJSON *events = NULL;
    char *printed = NULL;
    int result = -1;
    int status;
    size_t length;
    if (!query->case_id || !query->conversation_id || !query->conversation_id[0] ||
        query->limit == 0 || query->limit > 10000) {
        af_error("timeline requires a case, conversation, and limit between 1 and 10000");
        return -1;
    }
    root = cJSON_CreateObject();
    if (!root || add_string(root, "case_id", query->case_id) ||
        add_string(root, "conversation_id", query->conversation_id) ||
        add_string(root, "host_id", query->host_id ? query->host_id : "") ||
        add_string(root, "from", query->from ? query->from : "") ||
        add_string(root, "to", query->to ? query->to : "") ||
        !cJSON_AddNumberToObject(root, "limit", (double)query->limit)) {
        goto cleanup;
    }
    events = cJSON_AddArrayToObject(root, "events");
    if (!events || sqlite3_prepare_v2(db->handle, sql, -1, &statement, NULL) != SQLITE_OK) {
        af_error("cannot prepare timeline query: %s", sqlite3_errmsg(db->handle));
        goto cleanup;
    }
    sqlite3_bind_text(statement, 1, query->case_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(statement, 2, query->from ? query->from : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(statement, 3, query->to ? query->to : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(statement, 4, query->conversation_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(statement, 5, query->host_id ? query->host_id : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(statement, 6, (int)query->limit);
    while ((status = sqlite3_step(statement)) == SQLITE_ROW) {
        cJSON *event = cJSON_CreateObject();
        cJSON *details = NULL;
        if (!event || add_string(event, "event_id", column_text(statement, 0)) ||
            !cJSON_AddNumberToObject(event, "source_id", (double)sqlite3_column_int64(statement, 1)) ||
            add_string(event, "observed_at", column_text(statement, 2)) ||
            add_string(event, "host_id", column_text(statement, 3)) ||
            add_string(event, "source_tool", column_text(statement, 4)) ||
            add_string(event, "event_type", column_text(statement, 5)) ||
            add_string(event, "conversation_id", column_text(statement, 6)) ||
            add_string(event, "prompt_id", column_text(statement, 7)) ||
            add_string(event, "tool_call_id", column_text(statement, 8))) {
            cJSON_Delete(event);
            goto cleanup;
        }
        if (sqlite3_column_type(statement, 9) == SQLITE_NULL) {
            if (!cJSON_AddNullToObject(event, "process_id")) {
                cJSON_Delete(event);
                goto cleanup;
            }
        } else if (!cJSON_AddNumberToObject(event, "process_id", (double)sqlite3_column_int64(statement, 9))) {
            cJSON_Delete(event);
            goto cleanup;
        }
        if (sqlite3_column_type(statement, 10) == SQLITE_NULL) {
            if (!cJSON_AddNullToObject(event, "parent_process_id")) {
                cJSON_Delete(event);
                goto cleanup;
            }
        } else if (!cJSON_AddNumberToObject(event, "parent_process_id", (double)sqlite3_column_int64(statement, 10))) {
            cJSON_Delete(event);
            goto cleanup;
        }
        if (add_string(event, "path", column_text(statement, 11))) {
            cJSON_Delete(event);
            goto cleanup;
        }
        if (sqlite3_column_type(statement, 12) == SQLITE_NULL) {
            if (!cJSON_AddNullToObject(event, "deleted")) {
                cJSON_Delete(event);
                goto cleanup;
            }
        } else if (!cJSON_AddBoolToObject(event, "deleted", sqlite3_column_int(statement, 12))) {
            cJSON_Delete(event);
            goto cleanup;
        }
        if (!query->metadata_only) {
            details = cJSON_Parse(column_text(statement, 13));
            if (!details || !cJSON_AddItemToObject(event, "details", details)) {
                cJSON_Delete(details);
                cJSON_Delete(event);
                af_error("invalid stored details for event %s", column_text(statement, 0));
                goto cleanup;
            }
        }
        if (!cJSON_AddItemToArray(events, event)) {
            cJSON_Delete(event);
            goto cleanup;
        }
    }
    if (status != SQLITE_DONE) {
        af_error("timeline query failed: %s", sqlite3_errmsg(db->handle));
        goto cleanup;
    }
    printed = cJSON_PrintUnformatted(root);
    if (!printed) {
        goto cleanup;
    }
    length = strlen(printed);
    if (af_buf_append(json, printed, length) != 0) {
        goto cleanup;
    }
    result = 0;
cleanup:
    sqlite3_finalize(statement);
    free(printed);
    cJSON_Delete(root);
    return result;
}

int af_timeline_write(af_db *db, const af_timeline_query *query, FILE *output) {
    af_buffer json;
    int result;
    af_buf_init(&json);
    result = af_timeline_build(db, query, &json);
    if (result == 0 && (fwrite(json.data, 1, json.len, output) != json.len || fputc('\n', output) == EOF)) {
        af_error("cannot write timeline output");
        result = -1;
    }
    af_buf_free(&json);
    return result;
}
