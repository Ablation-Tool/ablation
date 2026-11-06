#include "vault.h"
#include "crypto.h"
#include "gemseal.h"
#include "util.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int add_string(cJSON *object, const char *name, const char *value) {
    return cJSON_AddStringToObject(object, name, value) ? 0 : -1;
}

static int add_null(cJSON *object, const char *name) {
    return cJSON_AddNullToObject(object, name) ? 0 : -1;
}

int af_vault_open(af_db *db, const char *path) {
    if (af_db_open(path, db) != 0 || af_db_init(db) != 0) {
        return -1;
    }
    return 0;
}

int af_vault_source(af_db *db, const char *case_id, const char *kind,
                    const char *origin_path, const char *details_json, int64_t *source_id) {
    af_source source;
    char timestamp[AF_TIMESTAMP_SIZE];
    char hash[65] = "";
    int64_t size = 0;
    if (af_now(timestamp) != 0 || af_db_ensure_case(db, case_id) != 0) {
        return -1;
    }
    if (origin_path && af_file_size(origin_path, &size) == 0) {
        if (af_sha256_file(origin_path, hash) != 0) {
            return -1;
        }
    }
    memset(&source, 0, sizeof(source));
    source.case_id = case_id;
    source.kind = kind;
    source.origin_path = origin_path ? origin_path : "";
    source.stored_path = "";
    source.sha256 = hash;
    source.size_bytes = size;
    source.tool_name = AF_VAULT_SOURCE;
    source.tool_version = "1";
    source.command_json = details_json ? details_json : "{}";
    source.acquired_at = timestamp;
    source.status = "completed";
    source.raw_sha256 = hash;
    return af_db_insert_source(db, &source, source_id);
}

void af_vault_session_id(char output[AF_VAULT_SESSION_SIZE]) {
    static const char hex[] = "0123456789abcdef";
    unsigned char random[16];
    int index;
    if (af_crypto_random(random, sizeof(random)) != 0) {
        strcpy(output, "unknown");
        return;
    }
    for (index = 0; index < 16; ++index) {
        output[index * 2] = hex[random[index] >> 4];
        output[index * 2 + 1] = hex[random[index] & 15];
    }
    output[32] = '\0';
    af_crypto_zero(random, sizeof(random));
}

int af_vault_path_id(const char *path, char output[AF_VAULT_ID_SIZE]) {
    if (!path || !output) {
        return -1;
    }
    return af_sha256_bytes(path, strlen(path), output);
}

int af_vault_boot_id(char output[AF_VAULT_ID_SIZE]) {
    int descriptor = open("/proc/sys/kernel/random/boot_id", O_RDONLY | O_CLOEXEC);
    char buffer[65];
    ssize_t amount;
    if (descriptor < 0) {
        strcpy(output, "unknown");
        return -1;
    }
    amount = read(descriptor, buffer, sizeof(buffer) - 1);
    close(descriptor);
    if (amount <= 0) {
        strcpy(output, "unknown");
        return -1;
    }
    buffer[amount] = '\0';
    if (buffer[amount - 1] == '\n') {
        buffer[amount - 1] = '\0';
    }
    if (strlen(buffer) > AF_VAULT_ID_SIZE - 1) {
        strcpy(output, "unknown");
        return -1;
    }
    strcpy(output, buffer);
    return 0;
}

int af_vault_path_inside(const char *path, const char *directory) {
    char resolved_path[PATH_MAX];
    char resolved_directory[PATH_MAX];
    size_t length;
    if (!path || !directory || !realpath(path, resolved_path) || !realpath(directory, resolved_directory)) {
        return -1;
    }
    length = strlen(resolved_directory);
    if (length == 1 && resolved_directory[0] == '/') {
        return 1;
    }
    return strncmp(resolved_path, resolved_directory, length) == 0 &&
           (resolved_path[length] == '\0' || resolved_path[length] == '/');
}

int af_vault_emit(af_db *db, const char *case_id, int64_t source_id,
                  const char *event_id, const char *event_type, const char *observed_at,
                  const char *host_id, const char *boot_id, const char *watcher_session,
                  uint64_t sequence, const char *vault_id, const char *path,
                  const char *agent_session, const char *tool_call, const char *consent,
                  const char *plaintext_state, const char *attribution,
                  const cJSON *source_detail) {
    af_event event;
    cJSON *details = cJSON_CreateObject();
    char recorded[AF_TIMESTAMP_SIZE];
    char *printed = NULL;
    int result = -1;
    int field = 0;
    if (!details || af_now(recorded) != 0) {
        cJSON_Delete(details);
        return -1;
    }
#define CHECK_FIELD(expression) do { \
        if (expression) { \
            af_error("vault event field %d failed for %s", field, event_type); \
            cJSON_Delete(details); \
            return -1; \
        } \
        ++field; \
    } while (0)
    CHECK_FIELD(!cJSON_AddStringToObject(details, "schema_version", "1.0"));
    CHECK_FIELD(add_string(details, "event_id", event_id));
    CHECK_FIELD(add_string(details, "source", AF_VAULT_SOURCE));
    CHECK_FIELD(add_string(details, "event_type", event_type));
    CHECK_FIELD(add_string(details, "observed_utc", observed_at));
    CHECK_FIELD(add_string(details, "recorded_utc", recorded));
    CHECK_FIELD(add_null(details, "analysis_utc"));
    CHECK_FIELD(add_string(details, "host_id", host_id));
    CHECK_FIELD(add_string(details, "boot_id", boot_id));
    CHECK_FIELD(add_string(details, "watcher_session", watcher_session));
    CHECK_FIELD(!cJSON_AddNumberToObject(details, "sequence", (double)sequence));
    CHECK_FIELD(add_string(details, "vault_id", vault_id));
    CHECK_FIELD(add_string(details, "path", path));
    CHECK_FIELD(add_null(details, "process"));
    CHECK_FIELD(agent_session ? add_string(details, "agent_session", agent_session) : add_null(details, "agent_session"));
    CHECK_FIELD(tool_call ? add_string(details, "tool_call", tool_call) : add_null(details, "tool_call"));
    CHECK_FIELD(add_string(details, "consent", consent ? consent : "unknown"));
    CHECK_FIELD(add_string(details, "plaintext_state", plaintext_state));
    CHECK_FIELD(add_string(details, "attribution", attribution));
#undef CHECK_FIELD
    if (!cJSON_AddItemToObject(details, "source_detail", cJSON_Duplicate(source_detail, 1))) {
        af_error("vault event source-detail construction failed for %s", event_type);
        cJSON_Delete(details);
        return -1;
    }
    printed = cJSON_PrintUnformatted(details);
    cJSON_Delete(details);
    if (!printed) {
        af_error("vault event serialization failed for %s", event_type);
        return -1;
    }
    memset(&event, 0, sizeof(event));
    event.id = event_id;
    event.case_id = case_id;
    event.source_id = source_id;
    event.observed_at = observed_at;
    event.host_id = host_id;
    event.source_tool = AF_VAULT_SOURCE;
    event.event_type = event_type;
    event.conversation_id = agent_session ? agent_session : "";
    event.prompt_id = "";
    event.tool_call_id = tool_call ? tool_call : "";
    event.process_id = -1;
    event.parent_process_id = -1;
    event.path = path;
    event.deleted = -1;
    event.details_json = printed;
    result = af_db_insert_event(db, &event);
    free(printed);
    return result;
}

static int canonical_future(const char *path, char output[PATH_MAX]) {
    char parent[PATH_MAX];
    char resolved[PATH_MAX];
    const char *slash = strrchr(path, '/');
    if (!slash) {
        if (!realpath(".", resolved)) {
            return -1;
        }
        return snprintf(output, PATH_MAX, "%s/%s", resolved, path) < PATH_MAX ? 0 : -1;
    }
    if (slash == path) {
        if (!realpath("/", resolved)) {
            return -1;
        }
        return snprintf(output, PATH_MAX, "/%s", slash + 1) < PATH_MAX ? 0 : -1;
    }
    if ((size_t)(slash - path) >= sizeof(parent)) {
        return -1;
    }
    memcpy(parent, path, (size_t)(slash - path));
    parent[slash - path] = '\0';
    if (!realpath(parent, resolved)) {
        return -1;
    }
    return snprintf(output, PATH_MAX, "%s/%s", resolved, slash + 1) < PATH_MAX ? 0 : -1;
}

static int create_canary_source(const char *path) {
    static const char text[] = "This Cerotto canary contains no sensitive information.\n";
    int descriptor = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (descriptor < 0) {
        return -1;
    }
    if (write(descriptor, text, sizeof(text) - 1) != (ssize_t)(sizeof(text) - 1) || fsync(descriptor) != 0) {
        close(descriptor);
        return -1;
    }
    return close(descriptor) == 0 ? 0 : -1;
}

int af_vault_init(const af_vault_options *options) {
    af_db db = {0};
    unsigned char key[AF_GEMSEAL_KEY_SIZE];
    char vault_path[PATH_MAX];
    char key_path[PATH_MAX];
    char database_path[PATH_MAX];
    char canary_path[PATH_MAX];
    char source_path[PATH_MAX];
    char vault_id[AF_VAULT_ID_SIZE];
    char boot_id[AF_VAULT_ID_SIZE];
    char key_id[AF_VAULT_ID_SIZE];
    char container_hash[AF_VAULT_ID_SIZE];
    char event_id[AF_VAULT_ID_SIZE + 32];
    char timestamp[AF_TIMESTAMP_SIZE];
    cJSON *detail = NULL;
    char *printed = NULL;
    int64_t source_id = 0;
    int created_vault = 0;
    int created_key = 0;
    int created_canary = 0;
    int transaction = 0;
    int result = -1;
    if (!options || !options->database_path || !options->case_id || !options->vault_path ||
        !options->key_path || !options->host_id ||
        canonical_future(options->vault_path, vault_path) != 0 ||
        canonical_future(options->key_path, key_path) != 0 ||
        canonical_future(options->database_path, database_path) != 0 ||
        af_vault_path_inside(key_path, vault_path) == 1 || af_vault_path_inside(database_path, vault_path) == 1) {
        af_error("vault initialization requires valid paths with the key and evidence store outside the vault");
        goto cleanup;
    }
    if (snprintf(canary_path, sizeof(canary_path), "%s/%s", vault_path,
                 options->name ? options->name : "project_notes.gemseal") >= (int)sizeof(canary_path) ||
        snprintf(source_path, sizeof(source_path), "%s.canary.tmp", canary_path) >= (int)sizeof(source_path) ||
        strchr(options->name ? options->name : "project_notes.gemseal", '/')) {
        af_error("canary name must be one filename");
        goto cleanup;
    }
    if (mkdir(vault_path, 0700) != 0) {
        af_error("cannot create vault %s: %s", vault_path, strerror(errno));
        goto cleanup;
    }
    created_vault = 1;
    if (af_gemseal_generate_key(key_path) != 0 || af_gemseal_load_key(key_path, key) != 0) {
        af_error("cannot generate an external vault key");
        goto cleanup;
    }
    created_key = 1;
    if (create_canary_source(source_path) != 0 ||
        af_gemseal_encrypt_file(key, source_path, canary_path, 4096) != 0) {
        af_error("cannot create encrypted canary");
        goto cleanup;
    }
    created_canary = 1;
    unlink(source_path);
    if (af_vault_open(&db, options->database_path) != 0 ||
        af_sha256_file(canary_path, container_hash) != 0 ||
        af_sha256_bytes(key, sizeof(key), key_id) != 0) {
        goto cleanup;
    }
    if (options->vault_id) {
        if (strlen(options->vault_id) >= sizeof(vault_id)) {
            goto cleanup;
        }
        strcpy(vault_id, options->vault_id);
    } else if (af_vault_path_id(vault_path, vault_id) != 0) {
        goto cleanup;
    }
    af_vault_boot_id(boot_id);
    detail = cJSON_CreateObject();
    if (!detail || add_string(detail, "api", "native") ||
        add_string(detail, "key_custody", "external_unverified") ||
        add_string(detail, "key_id", key_id) ||
        add_string(detail, "container_sha256", container_hash) ||
        add_string(detail, "canary_name", options->name ? options->name : "project_notes.gemseal")) {
        goto cleanup;
    }
    printed = cJSON_PrintUnformatted(detail);
    if (!printed || af_db_begin(&db) != 0) {
        goto cleanup;
    }
    transaction = 1;
    if (af_vault_source(&db, options->case_id, "vault_config", vault_path, printed, &source_id) != 0 ||
        af_now(timestamp) != 0 ||
        snprintf(event_id, sizeof(event_id), "vault:init:%s", container_hash) >= (int)sizeof(event_id) ||
        af_vault_emit(&db, options->case_id, source_id, event_id, "vault.initialized", timestamp,
                      options->host_id, boot_id, "", 0, vault_id, canary_path, NULL, NULL,
                      "unknown", "ciphertext", "unresolved", detail) != 0 ||
        af_db_commit(&db) != 0) {
        goto cleanup;
    }
    transaction = 0;
    printf("{\"vault_id\":\"%s\",\"canary\":\"%s\",\"key_custody\":\"external_unverified\"}\n", vault_id, canary_path);
    result = 0;
cleanup:
    if (transaction) {
        af_db_rollback(&db);
    }
    if (detail) {
        cJSON_Delete(detail);
    }
    free(printed);
    if (db.handle) {
        af_db_close(&db);
    }
    unlink(source_path);
    if (result != 0) {
        if (created_canary) unlink(canary_path);
        if (created_key) unlink(key_path);
        if (created_vault) rmdir(vault_path);
    }
    af_crypto_zero(key, sizeof(key));
    return result;
}

static int write_json_document(const char *path, cJSON *document, int exclusive) {
    char *printed = cJSON_PrintUnformatted(document);
    af_buffer output;
    int result = -1;
    if (!printed) {
        return -1;
    }
    af_buf_init(&output);
    if (af_buf_append(&output, printed, strlen(printed)) == 0 && af_buf_append(&output, "\n", 1) == 0) {
        if (path) {
            result = exclusive ? af_write_new_file(path, output.data, output.len) : -1;
            if (!exclusive) {
                FILE *file = fopen(path, "wb");
                if (file) {
                    result = fwrite(output.data, 1, output.len, file) == output.len && fclose(file) == 0 ? 0 : -1;
                }
            }
        } else {
            result = fwrite(output.data, 1, output.len, stdout) == output.len ? 0 : -1;
        }
    }
    af_buf_free(&output);
    free(printed);
    return result;
}

static cJSON *event_from_row(sqlite3_stmt *statement) {
    cJSON *event = cJSON_CreateObject();
    cJSON *details = NULL;
    const unsigned char *text;
    if (!event) {
        return NULL;
    }
#define TEXT_COLUMN(index) ((const char *)(sqlite3_column_text(statement, index) ? sqlite3_column_text(statement, index) : (const unsigned char *)""))
    if (add_string(event, "event_id", TEXT_COLUMN(0)) ||
        add_string(event, "observed_at", TEXT_COLUMN(1)) ||
        add_string(event, "host_id", TEXT_COLUMN(2)) ||
        add_string(event, "source_tool", TEXT_COLUMN(3)) ||
        add_string(event, "event_type", TEXT_COLUMN(4)) ||
        add_string(event, "conversation_id", TEXT_COLUMN(5)) ||
        add_string(event, "tool_call_id", TEXT_COLUMN(6)) ||
        add_string(event, "path", TEXT_COLUMN(7))) {
        cJSON_Delete(event);
        return NULL;
    }
    text = sqlite3_column_text(statement, 8);
    details = cJSON_Parse(text ? (const char *)text : "{}");
    if (!details || !cJSON_AddItemToObject(event, "details", details)) {
        cJSON_Delete(details);
        cJSON_Delete(event);
        return NULL;
    }
    return event;
#undef TEXT_COLUMN
}

int af_vault_timeline(const af_vault_options *options) {
    af_db db = {0};
    sqlite3_stmt *statement = NULL;
    cJSON *root = NULL;
    cJSON *events = NULL;
    char analysis[AF_TIMESTAMP_SIZE];
    int result = -1;
    if (!options || !options->database_path || !options->case_id || af_vault_open(&db, options->database_path) != 0 ||
        af_now(analysis) != 0) {
        goto cleanup;
    }
    root = cJSON_CreateObject();
    events = cJSON_AddArrayToObject(root, "events");
    if (!root || !events || add_string(root, "format", "cerotto-vault-timeline-v1") ||
        add_string(root, "case_id", options->case_id) ||
        add_string(root, "vault_id", options->vault_id ? options->vault_id : "") ||
        add_string(root, "analysis_utc", analysis) ||
        sqlite3_prepare_v2(db.handle,
            "SELECT id,observed_at,host_id,source_tool,event_type,conversation_id,tool_call_id,path,details_json "
            "FROM events WHERE case_id=?1 AND source_tool='cerotto.vault' "
            "AND (?2='' OR json_extract(details_json,'$.vault_id')=?2) ORDER BY observed_at,id LIMIT 10000",
            -1, &statement, NULL) != SQLITE_OK) {
        goto cleanup;
    }
    sqlite3_bind_text(statement, 1, options->case_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(statement, 2, options->vault_id ? options->vault_id : "", -1, SQLITE_TRANSIENT);
    while (sqlite3_step(statement) == SQLITE_ROW) {
        cJSON *event = event_from_row(statement);
        if (!event || !cJSON_AddItemToArray(events, event)) {
            cJSON_Delete(event);
            goto cleanup;
        }
    }
    if (write_json_document(options->output_path, root, options->output_path != NULL) != 0) {
        goto cleanup;
    }
    result = 0;
cleanup:
    if (statement) sqlite3_finalize(statement);
    if (root) cJSON_Delete(root);
    if (db.handle) af_db_close(&db);
    return result;
}

int af_vault_export(const af_vault_options *options) {
    af_db db = {0};
    sqlite3_stmt *statement = NULL;
    cJSON *payload = NULL;
    cJSON *custody = NULL;
    cJSON *events = NULL;
    cJSON *sources = NULL;
    char analysis[AF_TIMESTAMP_SIZE];
    char payload_hash[65];
    char payload_path[PATH_MAX];
    char custody_path[PATH_MAX];
    char *printed = NULL;
    int result = -1;
    if (!options || !options->database_path || !options->case_id || !options->output_path ||
        mkdir(options->output_path, 0700) != 0 || af_vault_open(&db, options->database_path) != 0 ||
        af_now(analysis) != 0) {
        goto cleanup;
    }
    payload = cJSON_CreateObject();
    events = cJSON_AddArrayToObject(payload, "events");
    sources = cJSON_AddArrayToObject(payload, "evidence_sources");
    if (!payload || !events || !sources || add_string(payload, "format", "cerotto-vault-export-v1") ||
        add_string(payload, "case_id", options->case_id) ||
        sqlite3_prepare_v2(db.handle,
            "SELECT id,observed_at,host_id,source_tool,event_type,conversation_id,tool_call_id,path,details_json "
            "FROM events WHERE case_id=?1 AND source_tool='cerotto.vault' ORDER BY observed_at,id",
            -1, &statement, NULL) != SQLITE_OK) {
        goto cleanup;
    }
    sqlite3_bind_text(statement, 1, options->case_id, -1, SQLITE_TRANSIENT);
    while (sqlite3_step(statement) == SQLITE_ROW) {
        cJSON *event = event_from_row(statement);
        if (!event || !cJSON_AddItemToArray(events, event)) {
            cJSON_Delete(event);
            goto cleanup;
        }
    }
    sqlite3_finalize(statement);
    statement = NULL;
    if (sqlite3_prepare_v2(db.handle,
        "SELECT id,kind,origin_path,sha256,status FROM evidence_sources WHERE case_id=?1 AND kind LIKE 'vault_%' ORDER BY id",
        -1, &statement, NULL) != SQLITE_OK) {
        goto cleanup;
    }
    sqlite3_bind_text(statement, 1, options->case_id, -1, SQLITE_TRANSIENT);
    while (sqlite3_step(statement) == SQLITE_ROW) {
        cJSON *source = cJSON_CreateObject();
        if (!source || !cJSON_AddNumberToObject(source, "id", (double)sqlite3_column_int64(statement, 0)) ||
            add_string(source, "kind", (const char *)sqlite3_column_text(statement, 1)) ||
            add_string(source, "origin_path", (const char *)sqlite3_column_text(statement, 2)) ||
            add_string(source, "sha256", (const char *)sqlite3_column_text(statement, 3)) ||
            add_string(source, "status", (const char *)sqlite3_column_text(statement, 4)) ||
            !cJSON_AddItemToArray(sources, source)) {
            cJSON_Delete(source);
            goto cleanup;
        }
    }
    printed = cJSON_PrintUnformatted(payload);
    if (!printed || af_sha256_bytes(printed, strlen(printed), payload_hash) != 0 ||
        snprintf(payload_path, sizeof(payload_path), "%s/payload.json", options->output_path) >= (int)sizeof(payload_path) ||
        snprintf(custody_path, sizeof(custody_path), "%s/custody.json", options->output_path) >= (int)sizeof(custody_path) ||
        af_write_new_file(payload_path, printed, strlen(printed)) != 0) {
        goto cleanup;
    }
    custody = cJSON_CreateObject();
    if (!custody || add_string(custody, "format", "cerotto-vault-custody-v1") ||
        add_string(custody, "analysis_utc", analysis) ||
        !cJSON_AddNumberToObject(custody, "exporter_uid", (double)getuid()) ||
        !cJSON_AddNumberToObject(custody, "retention_days", (double)options->retention_days) ||
        add_string(custody, "payload_sha256", payload_hash) ||
        write_json_document(custody_path, custody, 1) != 0) {
        goto cleanup;
    }
    printf("{\"payload_sha256\":\"%s\",\"retention_days\":%zu,\"events\":%d}\n",
           payload_hash, options->retention_days, cJSON_GetArraySize(events));
    result = 0;
cleanup:
    if (statement) sqlite3_finalize(statement);
    if (payload) cJSON_Delete(payload);
    if (custody) cJSON_Delete(custody);
    if (db.handle) af_db_close(&db);
    free(printed);
    return result;
}
