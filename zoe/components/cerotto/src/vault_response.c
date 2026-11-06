#include "vault.h"
#include "util.h"

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int af_vault_respond(const af_vault_options *options, int resume) {
    af_db db = {0};
    sqlite3_stmt *statement = NULL;
    cJSON *target = NULL;
    cJSON *configuration = NULL;
    cJSON *raw = NULL;
    char timestamp[AF_TIMESTAMP_SIZE];
    char session[AF_VAULT_SESSION_SIZE];
    char event_id[192];
    char boot_id[AF_VAULT_ID_SIZE];
    char *printed = NULL;
    const char *action = resume ? "resume" : "suspend";
    int64_t source_id = 0;
    int result = 1;
    if (!options || !options->database_path || !options->case_id || !options->event_id ||
        !options->approve || !options->host_id || options->agent_pid <= 1 || (!resume && !options->output_path)) {
        af_error("response requires a vault event, agent PID, explicit approval, and an evidence export for suspension");
        goto cleanup;
    }
    if (af_vault_open(&db, options->database_path) != 0 ||
        sqlite3_prepare_v2(db.handle,
            "SELECT details_json FROM events WHERE case_id=?1 AND id=?2 AND source_tool='cerotto.vault'",
            -1, &statement, NULL) != SQLITE_OK) {
        goto cleanup;
    }
    sqlite3_bind_text(statement, 1, options->case_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(statement, 2, options->event_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(statement) != SQLITE_ROW) {
        af_error("vault event not found for response");
        goto cleanup;
    }
    target = cJSON_Parse((const char *)sqlite3_column_text(statement, 0));
    sqlite3_finalize(statement);
    statement = NULL;
    if (!target) {
        goto cleanup;
    }
    if (!resume && af_vault_export(options) != 0) {
        af_error("evidence preservation failed; agent was not suspended");
        goto cleanup;
    }
    if (kill(options->agent_pid, resume ? SIGCONT : SIGSTOP) != 0) {
        af_error("cannot %s agent process %lld", action, (long long)options->agent_pid);
        goto cleanup;
    }
    af_vault_session_id(session);
    if (af_now(timestamp) != 0 ||
        snprintf(event_id, sizeof(event_id), "vault:response:%s", session) >= (int)sizeof(event_id)) {
        goto cleanup;
    }
    configuration = cJSON_CreateObject();
    if (!configuration || !cJSON_AddStringToObject(configuration, "action", action) ||
        !cJSON_AddNumberToObject(configuration, "agent_pid", (double)options->agent_pid) ||
        !cJSON_AddStringToObject(configuration, "authorization", "operator_approved") ||
        !cJSON_AddBoolToObject(configuration, "evidence_preserved", !resume)) {
        goto cleanup;
    }
    printed = cJSON_PrintUnformatted(configuration);
    if (!printed || af_vault_source(&db, options->case_id, "vault_response",
                                     resume ? "" : options->output_path, printed, &source_id) != 0) {
        af_error("response source registration failed");
        goto cleanup;
    }
    raw = cJSON_CreateObject();
    if (!raw) {
        goto cleanup;
    }
    if (!cJSON_AddStringToObject(raw, "action", action)) {
        af_error("response action field failed");
        goto cleanup;
    }
    if (!cJSON_AddNumberToObject(raw, "agent_pid", (double)options->agent_pid)) {
        af_error("response PID field failed");
        goto cleanup;
    }
    if (!cJSON_AddStringToObject(raw, "authorization", "operator_approved")) {
        af_error("response authorization field failed");
        goto cleanup;
    }
    if (!cJSON_AddBoolToObject(raw, "reversible", 1)) {
        af_error("response reversible field failed");
        goto cleanup;
    }
    if (!cJSON_AddBoolToObject(raw, "evidence_preserved", !resume)) {
        af_error("response evidence field failed");
        goto cleanup;
    }
    if (!resume && !cJSON_AddStringToObject(raw, "evidence_export", options->output_path)) {
        af_error("response export field failed");
        goto cleanup;
    }
    af_vault_boot_id(boot_id);
    {
        cJSON *vault_id = cJSON_GetObjectItemCaseSensitive(target, "vault_id");
        cJSON *path = cJSON_GetObjectItemCaseSensitive(target, "path");
        cJSON *plaintext = cJSON_GetObjectItemCaseSensitive(target, "plaintext_state");
        cJSON *agent_session = cJSON_GetObjectItemCaseSensitive(target, "agent_session");
        cJSON *tool_call = cJSON_GetObjectItemCaseSensitive(target, "tool_call");
        if (af_vault_emit(&db, options->case_id, source_id, event_id,
                          resume ? "response.resumed" : "response.suspended", timestamp,
                          options->host_id, boot_id, "", 0,
                          cJSON_IsString(vault_id) ? vault_id->valuestring : "",
                          cJSON_IsString(path) ? path->valuestring : "",
                          cJSON_IsString(agent_session) ? agent_session->valuestring : NULL,
                          cJSON_IsString(tool_call) ? tool_call->valuestring : NULL,
                          "approved", cJSON_IsString(plaintext) ? plaintext->valuestring : "unknown",
                          "operator_supplied_pid", raw) != 0) {
            af_error("response event persistence failed");
            goto cleanup;
        }
    }
    printf("{\"action\":\"%s\",\"agent_pid\":%lld,\"evidence_preserved\":%s}\n",
           action, (long long)options->agent_pid, resume ? "not_applicable" : "true");
    result = 0;
cleanup:
    if (statement) sqlite3_finalize(statement);
    if (target) cJSON_Delete(target);
    if (configuration) cJSON_Delete(configuration);
    if (raw) cJSON_Delete(raw);
    if (db.handle) af_db_close(&db);
    free(printed);
    return result;
}
