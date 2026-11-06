#include "vault.h"
#include "crypto.h"
#include "gemseal.h"
#include "util.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int future_path(const char *path, char output[PATH_MAX]) {
    char parent[PATH_MAX];
    char resolved[PATH_MAX];
    const char *slash = strrchr(path, '/');
    if (!slash) {
        if (!realpath(".", resolved)) return -1;
        return snprintf(output, PATH_MAX, "%s/%s", resolved, path) < PATH_MAX ? 0 : -1;
    }
    if (slash == path) {
        if (!realpath("/", resolved)) return -1;
        return snprintf(output, PATH_MAX, "/%s", slash + 1) < PATH_MAX ? 0 : -1;
    }
    if ((size_t)(slash - path) >= sizeof(parent)) return -1;
    memcpy(parent, path, (size_t)(slash - path));
    parent[slash - path] = '\0';
    if (!realpath(parent, resolved)) return -1;
    return snprintf(output, PATH_MAX, "%s/%s", resolved, slash + 1) < PATH_MAX ? 0 : -1;
}

static int absolute_inside(const char *path, const char *directory) {
    size_t length = strlen(directory);
    if (length == 1 && directory[0] == '/') {
        return 1;
    }
    return strncmp(path, directory, length) == 0 && (path[length] == '\0' || path[length] == '/');
}

static int parent_path(const char *path, char output[PATH_MAX]) {
    const char *slash = strrchr(path, '/');
    if (!slash) return snprintf(output, PATH_MAX, ".") < PATH_MAX ? 0 : -1;
    if (slash == path) return snprintf(output, PATH_MAX, "/") < PATH_MAX ? 0 : -1;
    if ((size_t)(slash - path) >= PATH_MAX) return -1;
    memcpy(output, path, (size_t)(slash - path));
    output[slash - path] = '\0';
    return 0;
}

static cJSON *release_details(const af_vault_options *options, const char *release_id,
                              const char *container_hash, const char *content_hash,
                              const char *release_time, const char *expires, const char *cleanup,
                              int approved) {
    cJSON *details = cJSON_CreateObject();
    if (!details || !cJSON_AddStringToObject(details, "release_id", release_id) ||
        !cJSON_AddStringToObject(details, "container_sha256", container_hash) ||
        (content_hash ? !cJSON_AddStringToObject(details, "content_sha256", content_hash)
                      : !cJSON_AddNullToObject(details, "content_sha256")) ||
        !cJSON_AddStringToObject(details, "requester", options->requester) ||
        (options->agent_session ? !cJSON_AddStringToObject(details, "agent_session", options->agent_session)
                                : !cJSON_AddNullToObject(details, "agent_session")) ||
        (options->tool_call ? !cJSON_AddStringToObject(details, "tool_call", options->tool_call)
                            : !cJSON_AddNullToObject(details, "tool_call")) ||
        !cJSON_AddStringToObject(details, "reason", options->reason) ||
        !cJSON_AddBoolToObject(details, "approved", approved) ||
        !cJSON_AddStringToObject(details, "destination", options->output_path) ||
        !cJSON_AddStringToObject(details, "permitted_identity", options->identity) ||
        !cJSON_AddStringToObject(details, "release_time", release_time) ||
        !cJSON_AddStringToObject(details, "expiration", expires) ||
        !cJSON_AddStringToObject(details, "cleanup_result", cleanup) ||
        !cJSON_AddStringToObject(details, "key_custody", "external_unverified")) {
        cJSON_Delete(details);
        return NULL;
    }
    return details;
}

static int emit_release(af_db *db, const af_vault_options *options, int64_t source_id,
                        const char *release_id, const char *type, const char *container_hash,
                        const char *content_hash, const char *release_time, const char *expires,
                        const char *cleanup, int approved, const char *plaintext_state,
                        const char *consent) {
    cJSON *details = release_details(options, release_id, container_hash, content_hash,
                                     release_time, expires, cleanup, approved);
    char event_id[160];
    char boot_id[AF_VAULT_ID_SIZE];
    char vault_id[AF_VAULT_ID_SIZE];
    char vault_path[PATH_MAX];
    int result;
    if (!details || snprintf(event_id, sizeof(event_id), "vault:release:%s", release_id) >= (int)sizeof(event_id) ||
        parent_path(options->input_path, vault_path) != 0 || af_vault_path_id(vault_path, vault_id) != 0) {
        cJSON_Delete(details);
        return -1;
    }
    af_vault_boot_id(boot_id);
    result = af_vault_emit(db, options->case_id, source_id, event_id, type, release_time,
                           options->host_id, boot_id, "", 0, vault_id, options->input_path,
                           options->agent_session, options->tool_call, consent, plaintext_state,
                           approved ? "operator_approved" : "unresolved", details);
    cJSON_Delete(details);
    return result;
}

int af_vault_release(const af_vault_options *options) {
    af_db db = {0};
    unsigned char key[AF_GEMSEAL_KEY_SIZE];
    char container[PATH_MAX];
    char release_root[PATH_MAX];
    char output[PATH_MAX];
    char vault_path[PATH_MAX];
    char key_path[PATH_MAX];
    char release_id[AF_VAULT_SESSION_SIZE];
    char container_hash[65] = "";
    char content_hash[65];
    char release_time[AF_TIMESTAMP_SIZE];
    char expires[AF_TIMESTAMP_SIZE] = "";
    cJSON *configuration = NULL;
    char *printed = NULL;
    int64_t source_id = 0;
    int result = 1;
    int created_plaintext = 0;
    struct stat status;
    if (!options || !options->database_path || !options->case_id || !options->key_path ||
        !options->input_path || !options->output_path || !options->release_root ||
        !options->requester || !options->reason || !options->reason[0] || !options->identity ||
        !options->host_id) {
        af_error("release requires a container, external key, release area, requester, reason, and permitted identity");
        goto cleanup;
    }
    if (!realpath(options->input_path, container) || !realpath(options->release_root, release_root) ||
        !realpath(options->key_path, key_path)) {
        af_error("release container, key, or release area cannot be resolved: %s", strerror(errno));
        goto cleanup;
    }
    if (future_path(options->output_path, output) != 0 || parent_path(container, vault_path) != 0) {
        af_error("release destination cannot be resolved: %s", options->output_path);
        goto cleanup;
    }
    if (absolute_inside(output, release_root) != 1 || af_vault_path_inside(container, release_root) == 1 ||
        absolute_inside(output, vault_path) == 1 || af_vault_path_inside(key_path, vault_path) == 1 ||
        af_vault_path_inside(options->database_path, vault_path) == 1 ||
        stat(release_root, &status) != 0 || !S_ISDIR(status.st_mode) || (status.st_mode & 077) != 0) {
        af_error("release must use a separate owner-only release area outside the vault");
        goto cleanup;
    }
    if (af_sha256_file(container, container_hash) != 0 || af_now(release_time) != 0) {
        goto cleanup;
    }
    if (options->expires) {
        char now[AF_TIMESTAMP_SIZE];
        if (af_timestamp_normalize(options->expires, expires) != 0 || af_now(now) != 0 || strcmp(expires, now) <= 0) {
            af_error("release expiration must be a future UTC timestamp");
            goto cleanup;
        }
    } else if (options->approve) {
        af_error("approved releases require an expiration");
        goto cleanup;
    }
    af_vault_session_id(release_id);
    configuration = cJSON_CreateObject();
    if (!configuration || !cJSON_AddStringToObject(configuration, "release_id", release_id) ||
        !cJSON_AddStringToObject(configuration, "requester", options->requester) ||
        !cJSON_AddBoolToObject(configuration, "approved", options->approve) ||
        !cJSON_AddStringToObject(configuration, "container_sha256", container_hash)) {
        goto cleanup;
    }
    printed = cJSON_PrintUnformatted(configuration);
    if (af_vault_open(&db, options->database_path) != 0 || !printed ||
        af_vault_source(&db, options->case_id, "vault_release", container, printed, &source_id) != 0) {
        goto cleanup;
    }
    if (!options->approve) {
        if (emit_release(&db, options, source_id, release_id, "release.denied", container_hash,
                         NULL, release_time, expires, "not_released", 0, "ciphertext", "denied") != 0) {
            goto cleanup;
        }
        printf("{\"release_id\":\"%s\",\"decision\":\"denied\",\"plaintext_released\":false}\n", release_id);
        result = 2;
        goto cleanup;
    }
    if (af_gemseal_load_key(key_path, key) != 0 || af_gemseal_decrypt_file(key, container, output) != 0) {
        af_error("approved plaintext release failed");
        goto cleanup;
    }
    created_plaintext = 1;
    if (af_sha256_file(output, content_hash) != 0 ||
        emit_release(&db, options, source_id, release_id, "release.approved", container_hash,
                     content_hash, release_time, expires, "residual_plaintext_present", 1, "released", "approved") != 0) {
        af_error("approved plaintext release failed");
        goto cleanup;
    }
    printf("{\"release_id\":\"%s\",\"decision\":\"approved\",\"plaintext_released\":true,\"cleanup_result\":\"residual_plaintext_present\"}\n", release_id);
    result = 0;
cleanup:
    if (result != 0 && created_plaintext) {
        unlink(output);
    }
    if (db.handle) af_db_close(&db);
    cJSON_Delete(configuration);
    free(printed);
    af_crypto_zero(key, sizeof(key));
    return result;
}

int af_vault_cleanup(const af_vault_options *options) {
    af_db db = {0};
    sqlite3_stmt *statement = NULL;
    cJSON *details = NULL;
    cJSON *release = NULL;
    cJSON *configuration = NULL;
    const char *destination = NULL;
    const char *expected_hash = NULL;
    const char *agent_session = NULL;
    const char *tool_call = NULL;
    char actual_hash[65];
    char timestamp[AF_TIMESTAMP_SIZE];
    char event_id[192];
    char *printed = NULL;
    int64_t source_id = 0;
    int result = 1;
    if (!options || !options->database_path || !options->case_id || !options->release_id ||
        !options->approve || !options->host_id) {
        af_error("cleanup requires a release ID, case host, and explicit approval");
        goto cleanup;
    }
    if (af_vault_open(&db, options->database_path) != 0 ||
        sqlite3_prepare_v2(db.handle,
            "SELECT details_json FROM events WHERE case_id=?1 AND source_tool='cerotto.vault' "
            "AND event_type='release.approved' AND json_extract(details_json,'$.source_detail.release_id')=?2",
            -1, &statement, NULL) != SQLITE_OK) {
        goto cleanup;
    }
    sqlite3_bind_text(statement, 1, options->case_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(statement, 2, options->release_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(statement) != SQLITE_ROW) {
        af_error("approved release not found");
        goto cleanup;
    }
    details = cJSON_Parse((const char *)sqlite3_column_text(statement, 0));
    if (!details) {
        goto cleanup;
    }
    release = cJSON_GetObjectItemCaseSensitive(details, "source_detail");
    if (!cJSON_IsObject(release)) {
        goto cleanup;
    }
    destination = cJSON_GetObjectItemCaseSensitive(release, "destination")->valuestring;
    expected_hash = cJSON_GetObjectItemCaseSensitive(release, "content_sha256")->valuestring;
    agent_session = cJSON_GetObjectItemCaseSensitive(release, "agent_session")->valuestring;
    tool_call = cJSON_GetObjectItemCaseSensitive(release, "tool_call")->valuestring;
    configuration = cJSON_CreateObject();
    if (!configuration || !cJSON_AddStringToObject(configuration, "release_id", options->release_id) ||
        !cJSON_AddStringToObject(configuration, "destination", destination)) {
        goto cleanup;
    }
    printed = cJSON_PrintUnformatted(configuration);
    if (!printed || af_vault_source(&db, options->case_id, "vault_cleanup", "", printed, &source_id) != 0 ||
        af_now(timestamp) != 0) {
        goto cleanup;
    }
    if (access(destination, F_OK) == 0) {
        if (af_sha256_file(destination, actual_hash) != 0 || strcmp(actual_hash, expected_hash) != 0) {
            cJSON *raw = cJSON_CreateObject();
            char boot_id[AF_VAULT_ID_SIZE];
            char vault_id[AF_VAULT_ID_SIZE];
            char vault_path[PATH_MAX];
            char session[AF_VAULT_SESSION_SIZE];
            if (!raw || !cJSON_AddStringToObject(raw, "release_id", options->release_id) ||
                !cJSON_AddStringToObject(raw, "cleanup_result", "modified_retained") ||
                !cJSON_AddStringToObject(raw, "residual_plaintext", "true") ||
                !cJSON_AddStringToObject(raw, "actual_sha256", actual_hash) ||
                parent_path(destination, vault_path) != 0 || af_vault_path_id(vault_path, vault_id) != 0) {
                cJSON_Delete(raw);
                goto cleanup;
            }
            af_vault_session_id(session);
            af_vault_boot_id(boot_id);
            if (snprintf(event_id, sizeof(event_id), "vault:cleanup-failed:%s", session) >= (int)sizeof(event_id) ||
                af_vault_emit(&db, options->case_id, source_id, event_id, "release.cleanup_failed", timestamp,
                              options->host_id, boot_id, "", 0, vault_id, destination,
                              agent_session, tool_call, "approved", "residual_plaintext", "modified_unresolved", raw) != 0) {
                cJSON_Delete(raw);
                goto cleanup;
            }
            cJSON_Delete(raw);
            af_error("release content changed; refusing deletion");
            goto cleanup;
        }
        if (unlink(destination) != 0) {
            goto cleanup;
        }
    } else if (errno != ENOENT) {
        goto cleanup;
    }
    {
        cJSON *raw = cJSON_CreateObject();
        char boot_id[AF_VAULT_ID_SIZE];
        char vault_id[AF_VAULT_ID_SIZE];
        char vault_path[PATH_MAX];
        if (!raw || !cJSON_AddStringToObject(raw, "release_id", options->release_id) ||
            !cJSON_AddStringToObject(raw, "cleanup_result", "removed_or_absent") ||
            !cJSON_AddStringToObject(raw, "residual_plaintext", "false") ||
            parent_path(destination, vault_path) != 0 || af_vault_path_id(vault_path, vault_id) != 0 ||
            snprintf(event_id, sizeof(event_id), "vault:cleanup:%s", options->release_id) >= (int)sizeof(event_id)) {
            af_error("cleanup metadata construction failed");
            cJSON_Delete(raw);
            goto cleanup;
        }
        af_vault_boot_id(boot_id);
        if (af_vault_emit(&db, options->case_id, source_id, event_id, "release.cleanup", timestamp,
                          options->host_id, boot_id, "", 0, vault_id, destination,
                          agent_session, tool_call, "approved", "cleanup_complete", "operator_approved", raw) != 0) {
            af_error("cleanup event persistence failed");
            cJSON_Delete(raw);
            goto cleanup;
        }
        cJSON_Delete(raw);
    }
    printf("{\"release_id\":\"%s\",\"cleanup_result\":\"removed_or_absent\",\"residual_plaintext\":false}\n", options->release_id);
    result = 0;
cleanup:
    if (statement) sqlite3_finalize(statement);
    if (details) cJSON_Delete(details);
    if (configuration) cJSON_Delete(configuration);
    if (db.handle) af_db_close(&db);
    free(printed);
    return result;
}
