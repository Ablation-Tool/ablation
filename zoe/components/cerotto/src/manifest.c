#include "manifest.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char source_query[] =
    "SELECT id,kind,origin_path,stored_path,sha256,size_bytes,tool_name,tool_version,"
    "command_json,acquired_at,status,raw_sha256 FROM evidence_sources WHERE case_id=?1 ORDER BY id";

static const char *column_text(sqlite3_stmt *statement, int column) {
    const unsigned char *value = sqlite3_column_text(statement, column);
    return value ? (const char *)value : "";
}

static int add_string(cJSON *object, const char *name, const char *value) {
    return cJSON_AddStringToObject(object, name, value) ? 0 : -1;
}

cJSON *af_manifest_create(af_db *db, const char *case_id) {
    sqlite3_stmt *statement = NULL;
    cJSON *root = NULL;
    cJSON *sources = NULL;
    int exists;
    int status;
    if (af_db_case_exists(db, case_id, &exists) != 0 || !exists) {
        af_error("case not found: %s", case_id);
        return NULL;
    }
    root = cJSON_CreateObject();
    if (!root || add_string(root, "format", "cerotto-case-manifest-v1") ||
        !cJSON_AddNumberToObject(root, "schema_version", AF_SCHEMA_VERSION) ||
        add_string(root, "case_id", case_id)) {
        goto failure;
    }
    sources = cJSON_AddArrayToObject(root, "sources");
    if (!sources || sqlite3_prepare_v2(db->handle, source_query, -1, &statement, NULL) != SQLITE_OK) {
        goto failure;
    }
    sqlite3_bind_text(statement, 1, case_id, -1, SQLITE_TRANSIENT);
    while ((status = sqlite3_step(statement)) == SQLITE_ROW) {
        cJSON *source = cJSON_CreateObject();
        cJSON *commands = NULL;
        if (!source || !cJSON_AddNumberToObject(source, "id", (double)sqlite3_column_int64(statement, 0)) ||
            add_string(source, "kind", column_text(statement, 1)) ||
            add_string(source, "origin_path", column_text(statement, 2)) ||
            add_string(source, "stored_path", column_text(statement, 3)) ||
            add_string(source, "sha256", column_text(statement, 4)) ||
            !cJSON_AddNumberToObject(source, "size_bytes", (double)sqlite3_column_int64(statement, 5)) ||
            add_string(source, "tool_name", column_text(statement, 6)) ||
            add_string(source, "tool_version", column_text(statement, 7))) {
            cJSON_Delete(source);
            goto failure;
        }
        commands = cJSON_Parse(column_text(statement, 8));
        if (!commands || !cJSON_AddItemToObject(source, "commands", commands)) {
            cJSON_Delete(commands);
            cJSON_Delete(source);
            goto failure;
        }
        commands = NULL;
        if (add_string(source, "acquired_at", column_text(statement, 9)) ||
            add_string(source, "status", column_text(statement, 10)) ||
            add_string(source, "raw_sha256", column_text(statement, 11)) ||
            !cJSON_AddItemToArray(sources, source)) {
            cJSON_Delete(source);
            goto failure;
        }
    }
    if (status != SQLITE_DONE) {
        goto failure;
    }
    sqlite3_finalize(statement);
    return root;
failure:
    sqlite3_finalize(statement);
    cJSON_Delete(root);
    af_error("cannot build case manifest: %s", sqlite3_errmsg(db->handle));
    return NULL;
}

static int write_json(FILE *output, cJSON *json) {
    char *text = cJSON_Print(json);
    int result = -1;
    if (text && fputs(text, output) != EOF && fputc('\n', output) != EOF) {
        result = 0;
    }
    free(text);
    return result;
}

int af_manifest_write(af_db *db, const char *case_id, FILE *output) {
    cJSON *manifest = af_manifest_create(db, case_id);
    int result;
    if (!manifest) {
        return -1;
    }
    result = write_json(output, manifest);
    cJSON_Delete(manifest);
    return result;
}

static char *resolved_path(const char *base, const char *path) {
    if (!base || !base[0] || path[0] == '/') {
        return af_strdup(path);
    }
    return af_path_join(base, path);
}

static int verify_file(cJSON *checks, int64_t source_id, const char *role, const char *base,
                       const char *path, const char *expected, int64_t expected_size) {
    char actual[65] = "";
    char *resolved = resolved_path(base, path);
    const char *status = "passed";
    int64_t size = -1;
    int failed = 0;
    cJSON *check = NULL;
    if (!resolved || af_file_size(resolved, &size) != 0) {
        status = "missing";
        failed = 1;
    } else if ((expected_size >= 0 && size != expected_size) || af_sha256_file(resolved, actual) != 0) {
        status = "mismatch";
        failed = 1;
    } else if (strcmp(actual, expected)) {
        status = "mismatch";
        failed = 1;
    }
    check = cJSON_CreateObject();
    if (!check || !cJSON_AddNumberToObject(check, "source_id", (double)source_id) ||
        add_string(check, "role", role) || add_string(check, "path", path) ||
        add_string(check, "expected_sha256", expected) || add_string(check, "actual_sha256", actual) ||
        add_string(check, "status", status) || !cJSON_AddItemToArray(checks, check)) {
        cJSON_Delete(check);
        free(resolved);
        return -1;
    }
    free(resolved);
    return failed ? 1 : 0;
}

int af_verify_case(af_db *db, const char *case_id, const char *base_path, FILE *output) {
    sqlite3_stmt *statement = NULL;
    cJSON *root = NULL;
    cJSON *checks = NULL;
    int exists;
    int status;
    int failed = 0;
    int result = -1;
    if (af_db_case_exists(db, case_id, &exists) != 0 || !exists) {
        af_error("case not found: %s", case_id);
        return -1;
    }
    root = cJSON_CreateObject();
    if (!root || add_string(root, "case_id", case_id)) {
        goto cleanup;
    }
    checks = cJSON_AddArrayToObject(root, "checks");
    if (!checks || sqlite3_prepare_v2(db->handle, source_query, -1, &statement, NULL) != SQLITE_OK) {
        goto cleanup;
    }
    sqlite3_bind_text(statement, 1, case_id, -1, SQLITE_TRANSIENT);
    while ((status = sqlite3_step(statement)) == SQLITE_ROW) {
        int check_result;
        if (column_text(statement, 4)[0] && strcmp(column_text(statement, 2), "-")) {
            check_result = verify_file(checks, sqlite3_column_int64(statement, 0), "origin", base_path,
                                       column_text(statement, 2), column_text(statement, 4),
                                       sqlite3_column_int64(statement, 5));
            if (check_result < 0) goto cleanup;
            failed |= check_result;
        }
        if (column_text(statement, 11)[0] && column_text(statement, 3)[0]) {
            check_result = verify_file(checks, sqlite3_column_int64(statement, 0), "stored_output", base_path,
                                       column_text(statement, 3), column_text(statement, 11), -1);
            if (check_result < 0) goto cleanup;
            failed |= check_result;
        }
    }
    if (status != SQLITE_DONE || !cJSON_AddBoolToObject(root, "verified", !failed) ||
        write_json(output, root) != 0) {
        goto cleanup;
    }
    result = failed ? 1 : 0;
cleanup:
    sqlite3_finalize(statement);
    cJSON_Delete(root);
    if (result < 0) {
        af_error("cannot verify case: %s", sqlite3_errmsg(db->handle));
    }
    return result;
}
