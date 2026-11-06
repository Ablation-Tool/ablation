#include "vault.h"
#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int add_string(cJSON *object, const char *name, const char *value) {
    return cJSON_AddStringToObject(object, name, value) ? 0 : -1;
}

static const char *column_text(sqlite3_stmt *statement, int column) {
    const unsigned char *value = sqlite3_column_text(statement, column);
    return value ? (const char *)value : "";
}

static cJSON *row_event(sqlite3_stmt *statement, int details_column) {
    cJSON *event = cJSON_CreateObject();
    cJSON *details = NULL;
    if (!event || add_string(event, "event_id", column_text(statement, 0)) ||
        add_string(event, "observed_at", column_text(statement, 1)) ||
        add_string(event, "host_id", column_text(statement, 2)) ||
        add_string(event, "source_tool", column_text(statement, 3)) ||
        add_string(event, "event_type", column_text(statement, 4)) ||
        add_string(event, "conversation_id", column_text(statement, 5)) ||
        add_string(event, "tool_call_id", column_text(statement, 6)) ||
        add_string(event, "path", column_text(statement, 7))) {
        cJSON_Delete(event);
        return NULL;
    }
    if (details_column >= 0) {
        details = cJSON_Parse(column_text(statement, details_column));
        if (!details || !cJSON_AddItemToObject(event, "details", details)) {
            cJSON_Delete(details);
            cJSON_Delete(event);
            return NULL;
        }
    }
    if (sqlite3_column_type(statement, 9) != SQLITE_NULL) {
        cJSON_AddNumberToObject(event, "process_id", (double)sqlite3_column_int64(statement, 9));
    } else {
        cJSON_AddNullToObject(event, "process_id");
    }
    if (sqlite3_column_type(statement, 10) != SQLITE_NULL) {
        cJSON_AddNumberToObject(event, "parent_process_id", (double)sqlite3_column_int64(statement, 10));
    } else {
        cJSON_AddNullToObject(event, "parent_process_id");
    }
    return event;
}

static int append_related(af_db *db, const char *case_id, const char *host_id,
                          const char *observed_at, const char *path, cJSON *processes,
                          cJSON *network, cJSON *agent, int64_t process_id) {
    sqlite3_stmt *statement = NULL;
    int result = -1;
    if (sqlite3_prepare_v2(db->handle,
        "SELECT id,observed_at,host_id,source_tool,event_type,conversation_id,tool_call_id,path,details_json,"
        "process_id,parent_process_id FROM events WHERE case_id=?1 AND host_id=?2 "
        "AND datetime(observed_at) BETWEEN datetime(?3,'-5 seconds') AND datetime(?3,'+10 seconds') "
        "AND process_id>=0 AND (path=?4 OR event_type LIKE 'network_%') "
        "ORDER BY observed_at,id LIMIT 100", -1, &statement, NULL) != SQLITE_OK) {
        return -1;
    }
    sqlite3_bind_text(statement, 1, case_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(statement, 2, host_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(statement, 3, observed_at, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(statement, 4, path, -1, SQLITE_TRANSIENT);
    while (sqlite3_step(statement) == SQLITE_ROW) {
        cJSON *event = row_event(statement, 8);
        const char *type = column_text(statement, 4);
        if (!event) {
            goto cleanup;
        }
        if (strncmp(type, "network_", 8) == 0) {
            if (!cJSON_AddItemToArray(network, event)) {
                cJSON_Delete(event);
                goto cleanup;
            }
        } else {
            if (!cJSON_AddItemToArray(processes, event)) {
                cJSON_Delete(event);
                goto cleanup;
            }
            if (sqlite3_column_int64(statement, 9) == process_id &&
                sqlite3_column_int64(statement, 9) > 0) {
                sqlite3_stmt *agent_statement = NULL;
                if (sqlite3_prepare_v2(db->handle,
                    "SELECT id,observed_at,host_id,source_tool,event_type,conversation_id,tool_call_id,path,details_json,"
                    "process_id,parent_process_id FROM events WHERE case_id=?1 AND host_id=?2 "
                    "AND event_type='tool_call' AND process_id=?3 "
                    "AND datetime(observed_at) BETWEEN datetime(?4,'-5 seconds') AND datetime(?4,'+5 seconds') "
                    "ORDER BY observed_at,id LIMIT 20", -1, &agent_statement, NULL) != SQLITE_OK) {
                    cJSON_Delete(event);
                    goto cleanup;
                }
                sqlite3_bind_text(agent_statement, 1, case_id, -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(agent_statement, 2, host_id, -1, SQLITE_TRANSIENT);
                sqlite3_bind_int64(agent_statement, 3, process_id);
                sqlite3_bind_text(agent_statement, 4, observed_at, -1, SQLITE_TRANSIENT);
                while (sqlite3_step(agent_statement) == SQLITE_ROW) {
                    cJSON *agent_event = row_event(agent_statement, 8);
                    if (!agent_event || !cJSON_AddItemToArray(agent, agent_event)) {
                        cJSON_Delete(agent_event);
                        sqlite3_finalize(agent_statement);
                        cJSON_Delete(event);
                        goto cleanup;
                    }
                }
                sqlite3_finalize(agent_statement);
            }
        }
        if (process_id <= 0 && sqlite3_column_int64(statement, 9) > 0) {
            /* Agent correlation is evaluated below against the first independent process candidate. */
        }
    }
    result = 0;
cleanup:
    if (statement) sqlite3_finalize(statement);
    return result;
}

static int append_agent_candidates(af_db *db, const char *case_id, const char *host_id,
                                   const char *observed_at, cJSON *processes, cJSON *agent) {
    size_t index;
    for (index = 0; index < (size_t)cJSON_GetArraySize(processes); ++index) {
        cJSON *process = cJSON_GetArrayItem(processes, (int)index);
        cJSON *pid = cJSON_GetObjectItemCaseSensitive(process, "process_id");
        sqlite3_stmt *statement = NULL;
        if (!cJSON_IsNumber(pid) || pid->valuedouble <= 0) {
            continue;
        }
        if (sqlite3_prepare_v2(db->handle,
            "SELECT id,observed_at,host_id,source_tool,event_type,conversation_id,tool_call_id,path,details_json,"
            "process_id,parent_process_id FROM events WHERE case_id=?1 AND host_id=?2 "
            "AND event_type='tool_call' AND process_id=?3 "
            "AND datetime(observed_at) BETWEEN datetime(?4,'-5 seconds') AND datetime(?4,'+5 seconds') "
            "ORDER BY observed_at,id LIMIT 20", -1, &statement, NULL) != SQLITE_OK) {
            return -1;
        }
        sqlite3_bind_text(statement, 1, case_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(statement, 2, host_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(statement, 3, (int64_t)pid->valuedouble);
        sqlite3_bind_text(statement, 4, observed_at, -1, SQLITE_TRANSIENT);
        while (sqlite3_step(statement) == SQLITE_ROW) {
            cJSON *event = row_event(statement, 8);
            if (!event || !cJSON_AddItemToArray(agent, event)) {
                cJSON_Delete(event);
                sqlite3_finalize(statement);
                return -1;
            }
        }
        sqlite3_finalize(statement);
    }
    return 0;
}

int af_vault_correlate(const af_vault_options *options) {
    af_db db = {0};
    sqlite3_stmt *statement = NULL;
    cJSON *root = NULL;
    cJSON *target = NULL;
    cJSON *processes = NULL;
    cJSON *network = NULL;
    cJSON *agent = NULL;
    cJSON *alternatives = NULL;
    cJSON *target_details = NULL;
    char analysis[AF_TIMESTAMP_SIZE];
    const char *attribution = "unresolved";
    const char *confidence = "unknown";
    int result = -1;
    if (!options || !options->database_path || !options->case_id || !options->event_id ||
        af_vault_open(&db, options->database_path) != 0 || af_now(analysis) != 0) {
        goto cleanup;
    }
    if (sqlite3_prepare_v2(db.handle,
        "SELECT id,observed_at,host_id,source_tool,event_type,conversation_id,tool_call_id,path,details_json,"
        "process_id,parent_process_id FROM events WHERE case_id=?1 AND id=?2 AND source_tool='cerotto.vault'",
        -1, &statement, NULL) != SQLITE_OK) {
        goto cleanup;
    }
    sqlite3_bind_text(statement, 1, options->case_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(statement, 2, options->event_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(statement) != SQLITE_ROW) {
        af_error("vault event not found: %s", options->event_id);
        goto cleanup;
    }
    target = row_event(statement, 8);
    if (!target) {
        goto cleanup;
    }
    target_details = cJSON_Duplicate(cJSON_GetObjectItemCaseSensitive(target, "details"), 1);
    processes = cJSON_CreateArray();
    network = cJSON_CreateArray();
    agent = cJSON_CreateArray();
    alternatives = cJSON_CreateArray();
    root = cJSON_CreateObject();
    if (!target_details || !processes || !network || !agent || !alternatives || !root ||
        !cJSON_AddItemToObject(root, "target", cJSON_Duplicate(target, 1)) ||
        !cJSON_AddItemToObject(root, "process_evidence", processes) ||
        !cJSON_AddItemToObject(root, "network_evidence", network) ||
        !cJSON_AddItemToObject(root, "agent_evidence", agent) ||
        !cJSON_AddItemToObject(root, "benign_alternatives", alternatives) ||
        add_string(root, "format", "cerotto-vault-correlation-v1") ||
        add_string(root, "case_id", options->case_id) ||
        add_string(root, "analysis_utc", analysis)) {
        goto cleanup;
    }
    if (append_related(&db, options->case_id, column_text(statement, 2), column_text(statement, 1),
                       column_text(statement, 7), processes, network, agent, -1) != 0 ||
        append_agent_candidates(&db, options->case_id, column_text(statement, 2), column_text(statement, 1),
                                processes, agent) != 0) {
        goto cleanup;
    }
    if (cJSON_GetArraySize(agent) > 0) {
        attribution = "agent_correlated";
        confidence = "moderate";
    } else if (cJSON_GetArraySize(processes) > 0) {
        attribution = "process_correlated";
        confidence = "limited";
    }
    if (!cJSON_AddStringToObject(root, "attribution", attribution) ||
        !cJSON_AddStringToObject(root, "confidence", confidence) ||
        !cJSON_AddStringToObject(root, "network_assessment",
            cJSON_GetArraySize(network) ? "contact_followed_by_network" : "no_independent_network_match") ||
        !cJSON_AddStringToObject(root, "intent", "unresolved")) {
        goto cleanup;
    }
    if (!cJSON_AddItemToArray(alternatives, cJSON_CreateString("backup_or_antivirus")) ||
        !cJSON_AddItemToArray(alternatives, cJSON_CreateString("indexing_or_synchronization")) ||
        !cJSON_AddItemToArray(alternatives, cJSON_CreateString("administrative_or_user_approved_job"))) {
        goto cleanup;
    }
    {
        cJSON *plaintext = cJSON_GetObjectItemCaseSensitive(target_details, "plaintext_state");
        cJSON *consent = cJSON_GetObjectItemCaseSensitive(target_details, "consent");
        if (!cJSON_AddStringToObject(root, "plaintext_state", cJSON_IsString(plaintext) ? plaintext->valuestring : "unknown") ||
            !cJSON_AddStringToObject(root, "consent", cJSON_IsString(consent) ? consent->valuestring : "unknown")) {
            goto cleanup;
        }
    }
    {
        char *printed = cJSON_PrintUnformatted(root);
        af_buffer output;
        int write_result = -1;
        if (!printed) {
            goto cleanup;
        }
        af_buf_init(&output);
        if (af_buf_append(&output, printed, strlen(printed)) == 0 && af_buf_append(&output, "\n", 1) == 0) {
            if (options->output_path) {
                write_result = af_write_new_file(options->output_path, output.data, output.len);
            } else {
                write_result = fwrite(output.data, 1, output.len, stdout) == output.len ? 0 : -1;
            }
        }
        af_buf_free(&output);
        free(printed);
        if (write_result != 0) {
            goto cleanup;
        }
    }
    result = 0;
cleanup:
    if (statement) sqlite3_finalize(statement);
    if (target) cJSON_Delete(target);
    if (target_details) cJSON_Delete(target_details);
    if (root) cJSON_Delete(root);
    if (db.handle) af_db_close(&db);
    return result;
}
