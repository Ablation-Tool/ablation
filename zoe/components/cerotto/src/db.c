#include "db.h"
#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int execute(af_db *db, const char *sql) {
    char *message = NULL;
    int status = sqlite3_exec(db->handle, sql, NULL, NULL, &message);
    if (status != SQLITE_OK) {
        af_error("database error: %s", message ? message : sqlite3_errmsg(db->handle));
        sqlite3_free(message);
        return -1;
    }
    return 0;
}

int af_db_open(const char *path, af_db *db) {
    db->handle = NULL;
    if (sqlite3_open_v2(path, &db->handle, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL) != SQLITE_OK) {
        af_error("cannot open database %s: %s", path, db->handle ? sqlite3_errmsg(db->handle) : "out of memory");
        af_db_close(db);
        return -1;
    }
    sqlite3_busy_timeout(db->handle, 5000);
    if (execute(db, "PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;") != 0) {
        af_db_close(db);
        return -1;
    }
    return 0;
}

void af_db_close(af_db *db) {
    if (db->handle) {
        sqlite3_close(db->handle);
        db->handle = NULL;
    }
}

int af_db_init(af_db *db) {
    static const char schema[] =
        "CREATE TABLE IF NOT EXISTS cases ("
        " id TEXT PRIMARY KEY,"
        " created_at TEXT NOT NULL"
        ");"
        "CREATE TABLE IF NOT EXISTS evidence_sources ("
        " id INTEGER PRIMARY KEY,"
        " case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,"
        " kind TEXT NOT NULL,"
        " origin_path TEXT NOT NULL,"
        " stored_path TEXT NOT NULL DEFAULT '',"
        " sha256 TEXT NOT NULL DEFAULT '',"
        " size_bytes INTEGER NOT NULL DEFAULT 0 CHECK(size_bytes >= 0),"
        " tool_name TEXT NOT NULL DEFAULT '',"
        " tool_version TEXT NOT NULL DEFAULT '',"
        " command_json TEXT NOT NULL DEFAULT '[]',"
        " acquired_at TEXT NOT NULL,"
        " status TEXT NOT NULL,"
        " raw_sha256 TEXT NOT NULL DEFAULT ''"
        ");"
        "CREATE TABLE IF NOT EXISTS events ("
        " id TEXT PRIMARY KEY,"
        " case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,"
        " source_id INTEGER REFERENCES evidence_sources(id) ON DELETE SET NULL,"
        " observed_at TEXT NOT NULL,"
        " host_id TEXT NOT NULL,"
        " source_tool TEXT NOT NULL,"
        " event_type TEXT NOT NULL,"
        " conversation_id TEXT NOT NULL DEFAULT '',"
        " prompt_id TEXT NOT NULL DEFAULT '',"
        " tool_call_id TEXT NOT NULL DEFAULT '',"
        " process_id INTEGER,"
        " parent_process_id INTEGER,"
        " path TEXT NOT NULL DEFAULT '',"
        " deleted INTEGER CHECK(deleted IN (0,1)),"
        " details_json TEXT NOT NULL DEFAULT '{}'"
        ");"
        "CREATE INDEX IF NOT EXISTS idx_sources_case ON evidence_sources(case_id);"
        "CREATE INDEX IF NOT EXISTS idx_events_case_time ON events(case_id, observed_at, id);"
        "CREATE INDEX IF NOT EXISTS idx_events_conversation ON events(case_id, conversation_id, observed_at);"
        "CREATE INDEX IF NOT EXISTS idx_events_host_time ON events(case_id, host_id, observed_at);";
    int version = 0;
    sqlite3_stmt *statement = NULL;
    if (sqlite3_prepare_v2(db->handle, "PRAGMA user_version", -1, &statement, NULL) != SQLITE_OK ||
        sqlite3_step(statement) != SQLITE_ROW) {
        af_error("cannot read database schema version: %s", sqlite3_errmsg(db->handle));
        sqlite3_finalize(statement);
        return -1;
    }
    version = sqlite3_column_int(statement, 0);
    sqlite3_finalize(statement);
    if (version > AF_SCHEMA_VERSION) {
        af_error("database schema version %d is newer than supported version %d", version, AF_SCHEMA_VERSION);
        return -1;
    }
    if (af_db_begin(db) != 0 || execute(db, schema) != 0) {
        af_db_rollback(db);
        return -1;
    }
    if (version == 1 && execute(db, "ALTER TABLE events ADD COLUMN parent_process_id INTEGER") != 0) {
        af_db_rollback(db);
        return -1;
    }
    if (sqlite3_exec(db->handle, "PRAGMA user_version=" "2", NULL, NULL, NULL) != SQLITE_OK ||
        af_db_commit(db) != 0) {
        af_db_rollback(db);
        return -1;
    }
    return 0;
}

int af_db_begin(af_db *db) {
    return execute(db, "BEGIN IMMEDIATE");
}

int af_db_commit(af_db *db) {
    return execute(db, "COMMIT");
}

int af_db_rollback(af_db *db) {
    return execute(db, "ROLLBACK");
}

int af_db_ensure_case(af_db *db, const char *case_id) {
    sqlite3_stmt *statement = NULL;
    int status;
    if (sqlite3_prepare_v2(db->handle, "INSERT OR IGNORE INTO cases(id,created_at) VALUES(?1,strftime('%Y-%m-%dT%H:%M:%fZ','now'))", -1, &statement, NULL) != SQLITE_OK) {
        af_error("cannot prepare case insertion: %s", sqlite3_errmsg(db->handle));
        return -1;
    }
    sqlite3_bind_text(statement, 1, case_id, -1, SQLITE_TRANSIENT);
    status = sqlite3_step(statement);
    if (status != SQLITE_DONE) {
        af_error("cannot create case: %s", sqlite3_errmsg(db->handle));
        sqlite3_finalize(statement);
        return -1;
    }
    sqlite3_finalize(statement);
    return 0;
}

int af_db_case_exists(af_db *db, const char *case_id, int *exists) {
    sqlite3_stmt *statement = NULL;
    int status;
    *exists = 0;
    if (sqlite3_prepare_v2(db->handle, "SELECT 1 FROM cases WHERE id=?1", -1, &statement, NULL) != SQLITE_OK) {
        return -1;
    }
    sqlite3_bind_text(statement, 1, case_id, -1, SQLITE_TRANSIENT);
    status = sqlite3_step(statement);
    if (status == SQLITE_ROW) {
        *exists = 1;
    } else if (status != SQLITE_DONE) {
        af_error("cannot query case: %s", sqlite3_errmsg(db->handle));
        sqlite3_finalize(statement);
        return -1;
    }
    sqlite3_finalize(statement);
    return 0;
}

int af_db_insert_source(af_db *db, const af_source *source, int64_t *id) {
    static const char sql[] =
        "INSERT INTO evidence_sources(case_id,kind,origin_path,stored_path,sha256,size_bytes,"
        "tool_name,tool_version,command_json,acquired_at,status,raw_sha256) "
        "VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)";
    sqlite3_stmt *statement = NULL;
    if (sqlite3_prepare_v2(db->handle, sql, -1, &statement, NULL) != SQLITE_OK) {
        af_error("cannot prepare source insertion: %s", sqlite3_errmsg(db->handle));
        return -1;
    }
    sqlite3_bind_text(statement, 1, source->case_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(statement, 2, source->kind, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(statement, 3, source->origin_path, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(statement, 4, source->stored_path, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(statement, 5, source->sha256, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(statement, 6, source->size_bytes);
    sqlite3_bind_text(statement, 7, source->tool_name, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(statement, 8, source->tool_version, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(statement, 9, source->command_json, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(statement, 10, source->acquired_at, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(statement, 11, source->status, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(statement, 12, source->raw_sha256, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(statement) != SQLITE_DONE) {
        af_error("cannot insert evidence source: %s", sqlite3_errmsg(db->handle));
        sqlite3_finalize(statement);
        return -1;
    }
    sqlite3_finalize(statement);
    *id = sqlite3_last_insert_rowid(db->handle);
    return 0;
}

int af_db_insert_event(af_db *db, const af_event *event) {
    static const char sql[] =
        "INSERT INTO events(id,case_id,source_id,observed_at,host_id,source_tool,event_type,"
        "conversation_id,prompt_id,tool_call_id,process_id,parent_process_id,path,deleted,details_json) "
        "VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15)";
    sqlite3_stmt *statement = NULL;
    if (sqlite3_prepare_v2(db->handle, sql, -1, &statement, NULL) != SQLITE_OK) {
        af_error("cannot prepare event insertion: %s", sqlite3_errmsg(db->handle));
        return -1;
    }
    sqlite3_bind_text(statement, 1, event->id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(statement, 2, event->case_id, -1, SQLITE_TRANSIENT);
    if (event->source_id > 0) {
        sqlite3_bind_int64(statement, 3, event->source_id);
    } else {
        sqlite3_bind_null(statement, 3);
    }
    sqlite3_bind_text(statement, 4, event->observed_at, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(statement, 5, event->host_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(statement, 6, event->source_tool, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(statement, 7, event->event_type, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(statement, 8, event->conversation_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(statement, 9, event->prompt_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(statement, 10, event->tool_call_id, -1, SQLITE_TRANSIENT);
    if (event->process_id >= 0) {
        sqlite3_bind_int64(statement, 11, event->process_id);
    } else {
        sqlite3_bind_null(statement, 11);
    }
    if (event->parent_process_id >= 0) {
        sqlite3_bind_int64(statement, 12, event->parent_process_id);
    } else {
        sqlite3_bind_null(statement, 12);
    }
    sqlite3_bind_text(statement, 13, event->path, -1, SQLITE_TRANSIENT);
    if (event->deleted >= 0) {
        sqlite3_bind_int(statement, 14, event->deleted);
    } else {
        sqlite3_bind_null(statement, 14);
    }
    sqlite3_bind_text(statement, 15, event->details_json, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(statement) != SQLITE_DONE) {
        af_error("cannot insert event %s: %s", event->id, sqlite3_errmsg(db->handle));
        sqlite3_finalize(statement);
        return -1;
    }
    sqlite3_finalize(statement);
    return 0;
}
