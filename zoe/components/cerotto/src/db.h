#ifndef AF_DB_H
#define AF_DB_H

#include <sqlite3.h>
#include <stdint.h>

#define AF_SCHEMA_VERSION 2

typedef struct {
    sqlite3 *handle;
} af_db;

typedef struct {
    const char *case_id;
    const char *kind;
    const char *origin_path;
    const char *stored_path;
    const char *sha256;
    int64_t size_bytes;
    const char *tool_name;
    const char *tool_version;
    const char *command_json;
    const char *acquired_at;
    const char *status;
    const char *raw_sha256;
} af_source;

typedef struct {
    const char *id;
    const char *case_id;
    int64_t source_id;
    const char *observed_at;
    const char *host_id;
    const char *source_tool;
    const char *event_type;
    const char *conversation_id;
    const char *prompt_id;
    const char *tool_call_id;
    int64_t process_id;
    int64_t parent_process_id;
    const char *path;
    int deleted;
    const char *details_json;
} af_event;

int af_db_open(const char *path, af_db *db);
void af_db_close(af_db *db);
int af_db_init(af_db *db);
int af_db_ensure_case(af_db *db, const char *case_id);
int af_db_insert_source(af_db *db, const af_source *source, int64_t *id);
int af_db_insert_event(af_db *db, const af_event *event);
int af_db_begin(af_db *db);
int af_db_commit(af_db *db);
int af_db_rollback(af_db *db);
int af_db_case_exists(af_db *db, const char *case_id, int *exists);

#endif
