#include "analyze.h"
#include "artifact.h"
#include "audit.h"
#include "carve.h"
#include "collect.h"
#include "crypto.h"
#include "db.h"
#include "event.h"
#include "gemseal.h"
#include "guard.h"
#include "manifest.h"
#include "report.h"
#include "timeline.h"
#include "util.h"
#include "vault.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define VERSION "0.6.0"

typedef struct {
    const char *db;
    const char *case_id;
    const char *input;
    const char *image;
    const char *output;
    const char *host;
    const char *conversation;
    const char *from;
    const char *to;
    const char *analysis;
    const char *format;
    const char *reviewer;
    const char *review_status;
    const char *base;
    const char *carver;
    const char *key;
    const char *vault;
    const char *vault_id;
    const char *name;
    const char *release_root;
    const char *requester;
    const char *reason;
    const char *agent_session;
    const char *tool_call;
    const char *identity;
    const char *expires;
    const char *release_id;
    const char *event_id;
    const char *wordlist;
    const char *mode;
    const char *prefix;
    const char *suffix;
    int64_t source_id;
    int64_t agent_pid;
    size_t max_bytes;
    size_t chunk_size;
    size_t limit;
    size_t max_events;
    size_t duration;
    size_t retention_days;
    size_t digits;
    size_t variable_bytes;
    size_t candidate_limit;
    int include_details;
    int format_set;
    int approve;
    int inject_overflow;
    int inject_clock_change;
    int fail_evidence_write;
} options;

static void usage(FILE *output) {
    fputs(
        "CEROTTO " VERSION "\n\n"
        "Usage:\n"
        "  cerotto init --db DB\n"
        "  cerotto ingest --db DB --case CASE --input EVENTS.jsonl\n"
        "  cerotto ingest-audit --db DB --case CASE --input AUDIT.log --host HOST\n"
        "  cerotto guard --db DB --case CASE --input PROPOSAL.json [--output RESULT.json]\n"
        "  cerotto keygen --output KEY\n"
        "  cerotto encrypt --key KEY --input PLAINTEXT --output CONTAINER [--chunk-size N]\n"
        "  cerotto decrypt --key KEY --input CONTAINER --output PLAINTEXT\n"
        "  cerotto vault init|watch|release|cleanup|timeline|correlate|export|respond|resume [options]\n"
        "  cerotto crack wordlist|pin|raw-prefix [options]\n"
        "  cerotto collect-tsk --db DB --case CASE --image IMAGE --output DIR --host HOST\n"
        "  cerotto collect-ewf --db DB --case CASE --image evidence.E01 --output DIR --host HOST\n"
        "  cerotto carve --db DB --case CASE --image IMAGE --output NEW_DIR --host HOST [--carver foremost|scalpel]\n"
        "  cerotto timeline --db DB --case CASE --conversation ID [--host HOST] [--from UTC] [--to UTC] [--limit N] [--include-details] [--output FILE]\n"
        "  cerotto analyze --db DB --case CASE --conversation ID [--host HOST] [--from UTC] [--to UTC] [--limit N] [--output FILE]\n"
        "  cerotto manifest --db DB --case CASE [--output FILE]\n"
        "  cerotto verify --db DB --case CASE [--base DIR] [--output FILE]\n"
        "  cerotto report --db DB --case CASE --conversation ID [--analysis FILE] [--format json|markdown] [--reviewer NAME --review-status STATUS] [--output FILE]\n"
        "  cerotto artifact show --db DB --case CASE --source-id ID [--format hex|json] [--max-bytes N] [--base DIR] [--output FILE]\n\n"
        "Timestamps must be ISO-8601 UTC, for example 2026-10-27T12:00:00Z.\n"
        "Analysis requires CEROTTO_BASE_URL and CEROTTO_MODEL.\n"
        "The base URL is the OpenAI-compatible prefix before /chat/completions.\n",
        output);
}

static int valid_id(const char *value) {
    const unsigned char *cursor = (const unsigned char *)value;
    size_t length;
    if (!value || !value[0]) {
        return 0;
    }
    length = strlen(value);
    if (length > 256) {
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

static int parse_size_value(const char *value, const char *name, size_t maximum, size_t *output) {
    char *end;
    unsigned long long parsed;
    errno = 0;
    parsed = strtoull(value, &end, 10);
    if (errno || end == value || *end || parsed > maximum) {
        af_error("%s must be an integer between 0 and %zu", name, maximum);
        return -1;
    }
    *output = (size_t)parsed;
    return 0;
}

static int parse_options(int argc, char **argv, options *parsed, int allow_no_db) {
    int index;
    memset(parsed, 0, sizeof(*parsed));
    parsed->limit = 10000;
    parsed->max_bytes = 8192;
    parsed->chunk_size = 4096;
    parsed->format = "markdown";
    parsed->carver = "foremost";
    parsed->review_status = "unreviewed";
    for (index = 0; index < argc; ++index) {
        const char *name = argv[index];
        const char *value = NULL;
        if (strcmp(name, "--include-details") == 0) {
            parsed->include_details = 1;
            continue;
        }
        if (strcmp(name, "--approve") == 0) {
            parsed->approve = 1;
            continue;
        }
        if (strcmp(name, "--inject-overflow") == 0) {
            parsed->inject_overflow = 1;
            continue;
        }
        if (strcmp(name, "--inject-clock-change") == 0) {
            parsed->inject_clock_change = 1;
            continue;
        }
        if (strcmp(name, "--fail-evidence-write") == 0) {
            parsed->fail_evidence_write = 1;
            continue;
        }
        if (index + 1 >= argc) {
            af_error("missing value for %s", name);
            return -1;
        }
        value = argv[++index];
        if (strcmp(name, "--db") == 0) parsed->db = value;
        else if (strcmp(name, "--case") == 0) parsed->case_id = value;
        else if (strcmp(name, "--input") == 0) parsed->input = value;
        else if (strcmp(name, "--image") == 0) parsed->image = value;
        else if (strcmp(name, "--output") == 0) parsed->output = value;
        else if (strcmp(name, "--host") == 0) parsed->host = value;
        else if (strcmp(name, "--conversation") == 0) parsed->conversation = value;
        else if (strcmp(name, "--from") == 0) parsed->from = value;
        else if (strcmp(name, "--to") == 0) parsed->to = value;
        else if (strcmp(name, "--analysis") == 0) parsed->analysis = value;
        else if (strcmp(name, "--format") == 0) {
            parsed->format = value;
            parsed->format_set = 1;
        }
        else if (strcmp(name, "--reviewer") == 0) parsed->reviewer = value;
        else if (strcmp(name, "--review-status") == 0) parsed->review_status = value;
        else if (strcmp(name, "--base") == 0) parsed->base = value;
        else if (strcmp(name, "--carver") == 0) parsed->carver = value;
        else if (strcmp(name, "--key") == 0) parsed->key = value;
        else if (strcmp(name, "--vault") == 0) parsed->vault = value;
        else if (strcmp(name, "--vault-id") == 0) parsed->vault_id = value;
        else if (strcmp(name, "--name") == 0) parsed->name = value;
        else if (strcmp(name, "--release-root") == 0) parsed->release_root = value;
        else if (strcmp(name, "--requester") == 0) parsed->requester = value;
        else if (strcmp(name, "--reason") == 0) parsed->reason = value;
        else if (strcmp(name, "--agent-session") == 0) parsed->agent_session = value;
        else if (strcmp(name, "--tool-call") == 0) parsed->tool_call = value;
        else if (strcmp(name, "--identity") == 0) parsed->identity = value;
        else if (strcmp(name, "--expires") == 0) parsed->expires = value;
        else if (strcmp(name, "--release-id") == 0) parsed->release_id = value;
        else if (strcmp(name, "--event-id") == 0) parsed->event_id = value;
        else if (strcmp(name, "--wordlist") == 0) parsed->wordlist = value;
        else if (strcmp(name, "--mode") == 0) parsed->mode = value;
        else if (strcmp(name, "--prefix") == 0) parsed->prefix = value;
        else if (strcmp(name, "--suffix") == 0) parsed->suffix = value;
        else if (strcmp(name, "--chunk-size") == 0) {
            char *end;
            errno = 0;
            unsigned long amount = strtoul(value, &end, 10);
            if (errno || *end || end == value || amount == 0 || amount > AF_GEMSEAL_MAX_CHUNK) {
                af_error("chunk-size must be between 1 and %u", AF_GEMSEAL_MAX_CHUNK);
                return -1;
            }
            parsed->chunk_size = (size_t)amount;
        }
        else if (strcmp(name, "--source-id") == 0) {
            char *end;
            errno = 0;
            long long id = strtoll(value, &end, 10);
            if (errno || *end || end == value || id <= 0) {
                af_error("source-id must be a positive integer");
                return -1;
            }
            parsed->source_id = (int64_t)id;
        }
        else if (strcmp(name, "--max-bytes") == 0) {
            char *end;
            errno = 0;
            unsigned long amount = strtoul(value, &end, 10);
            if (errno || *end || end == value || amount == 0 || amount > 1048576) {
                af_error("max-bytes must be between 1 and 1048576");
                return -1;
            }
            parsed->max_bytes = (size_t)amount;
        }
        else if (strcmp(name, "--max-events") == 0) {
            if (parse_size_value(value, "max-events", 1000000, &parsed->max_events) != 0) return -1;
        }
        else if (strcmp(name, "--duration") == 0) {
            if (parse_size_value(value, "duration", 86400, &parsed->duration) != 0) return -1;
        }
        else if (strcmp(name, "--retention-days") == 0) {
            if (parse_size_value(value, "retention-days", 36500, &parsed->retention_days) != 0) return -1;
        }
        else if (strcmp(name, "--digits") == 0) {
            if (parse_size_value(value, "digits", 8, &parsed->digits) != 0) return -1;
        }
        else if (strcmp(name, "--variable-bytes") == 0) {
            if (parse_size_value(value, "variable-bytes", 4, &parsed->variable_bytes) != 0) return -1;
        }
        else if (strcmp(name, "--candidate-limit") == 0) {
            if (parse_size_value(value, "candidate-limit", 1000000000, &parsed->candidate_limit) != 0) return -1;
        }
        else if (strcmp(name, "--pid") == 0) {
            size_t pid;
            if (parse_size_value(value, "pid", 2147483647, &pid) != 0) return -1;
            parsed->agent_pid = (int64_t)pid;
        }
        else if (strcmp(name, "--limit") == 0) {
            char *end;
            unsigned long limit;
            errno = 0;
            limit = strtoul(value, &end, 10);
            if (errno || *end || end == value || limit == 0 || limit > 10000) {
                af_error("limit must be between 1 and 10000");
                return -1;
            }
            parsed->limit = (size_t)limit;
        } else {
            af_error("unknown option: %s", name);
            return -1;
        }
    }
    if ((!allow_no_db && !parsed->db) || (parsed->case_id && !valid_id(parsed->case_id)) ||
        (parsed->host && !valid_id(parsed->host)) ||
        (parsed->conversation && !valid_id(parsed->conversation)) ||
        (parsed->reviewer && !valid_id(parsed->reviewer))) {
        af_error("a database and valid case, host, and conversation identifiers are required");
        return -1;
    }
    return 0;
}

static int open_database(const options *parsed, af_db *db) {
    if (af_db_open(parsed->db, db) != 0) {
        return -1;
    }
    if (af_db_init(db) != 0) {
        af_db_close(db);
        return -1;
    }
    return 0;
}

static int set_source_status(af_db *db, int64_t source_id, const char *status) {
    sqlite3_stmt *statement = NULL;
    int result = -1;
    if (sqlite3_prepare_v2(db->handle, "UPDATE evidence_sources SET status=?1 WHERE id=?2", -1, &statement, NULL) != SQLITE_OK) {
        return -1;
    }
    sqlite3_bind_text(statement, 1, status, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(statement, 2, source_id);
    if (sqlite3_step(statement) == SQLITE_DONE) {
        result = 0;
    }
    sqlite3_finalize(statement);
    return result;
}

static int command_ingest(const options *parsed, int audit) {
    af_db db;
    af_source source;
    char acquired_at[AF_TIMESTAMP_SIZE];
    char hash[65] = "";
    int64_t size = 0;
    int64_t source_id = 0;
    size_t count = 0;
    int result = -1;
    int ingest_result;
    if (!parsed->case_id || !parsed->input || (audit && !parsed->host)) {
        af_error("%s requires --case and --input%s", audit ? "ingest-audit" : "ingest",
                 audit ? " and --host" : "");
        return 1;
    }
    if (open_database(parsed, &db) != 0) {
        return 1;
    }
    if (af_now(acquired_at) != 0 ||
        (strcmp(parsed->input, "-") && (af_sha256_file(parsed->input, hash) || af_file_size(parsed->input, &size)))) {
        af_error("cannot read ingestion source metadata");
        goto cleanup;
    }
    if (af_db_begin(&db) || af_db_ensure_case(&db, parsed->case_id)) {
        goto cleanup;
    }
    memset(&source, 0, sizeof(source));
    source.case_id = parsed->case_id;
    source.kind = audit ? "audit_log" : "agent_jsonl";
    source.origin_path = parsed->input;
    source.stored_path = "";
    source.sha256 = hash;
    source.size_bytes = size;
    source.tool_name = "cerotto";
    source.tool_version = VERSION;
    source.command_json = "[]";
    source.acquired_at = acquired_at;
    source.status = "ingesting";
    source.raw_sha256 = hash;
    if (af_db_insert_source(&db, &source, &source_id) || af_db_commit(&db)) {
        af_db_rollback(&db);
        goto cleanup;
    }
    if (audit) {
        ingest_result = af_ingest_audit(&db, parsed->case_id, parsed->input, parsed->host, source_id, &count);
    } else {
        ingest_result = af_ingest_jsonl(&db, parsed->case_id, parsed->input, source_id, &count);
    }
    if (ingest_result != 0) {
        set_source_status(&db, source_id, "failed");
        goto cleanup;
    }
    if (set_source_status(&db, source_id, "completed") != 0) {
        goto cleanup;
    }
    printf("{\"source_id\":%lld,\"events_ingested\":%zu}\n", (long long)source_id, count);
    result = 0;
cleanup:
    af_db_close(&db);
    return result == 0 ? 0 : 1;
}

static int command_collect(const options *parsed, int ewf) {
    af_db db;
    size_t count = 0;
    int result;
    if (!parsed->case_id || !parsed->image || !parsed->output || !parsed->host) {
        af_error("%s requires --case, --image, --output, and --host", ewf ? "collect-ewf" : "collect-tsk");
        return 1;
    }
    if (open_database(parsed, &db) != 0) {
        return 1;
    }
    result = ewf ? af_collect_ewf(&db, parsed->case_id, parsed->image, parsed->output, parsed->host, &count)
                 : af_collect_tsk(&db, parsed->case_id, parsed->image, parsed->output, parsed->host, &count);
    af_db_close(&db);
    if (result == 0) {
        printf("{\"events_collected\":%zu}\n", count);
        return 0;
    }
    return 1;
}

static int prepare_timeline(const options *parsed, af_timeline_query *query,
                            char from[AF_TIMESTAMP_SIZE], char to[AF_TIMESTAMP_SIZE]) {
    memset(query, 0, sizeof(*query));
    if (!parsed->case_id || !parsed->conversation) {
        af_error("timeline, analyze, and report require --case and --conversation");
        return -1;
    }
    if (parsed->from && af_timestamp_normalize(parsed->from, from) != 0) {
        af_error("invalid --from timestamp");
        return -1;
    }
    if (parsed->to && af_timestamp_normalize(parsed->to, to) != 0) {
        af_error("invalid --to timestamp");
        return -1;
    }
    if (parsed->from && parsed->to && strcmp(from, to) >= 0) {
        af_error("--from must be earlier than --to");
        return -1;
    }
    query->case_id = parsed->case_id;
    query->conversation_id = parsed->conversation;
    query->host_id = parsed->host ? parsed->host : "";
    query->from = parsed->from ? from : "";
    query->to = parsed->to ? to : "";
    query->limit = parsed->limit;
    query->metadata_only = !parsed->include_details;
    return 0;
}

static int command_timeline(const options *parsed, int analyze) {
    af_db db;
    af_timeline_query query;
    char from[AF_TIMESTAMP_SIZE];
    char to[AF_TIMESTAMP_SIZE];
    FILE *output = stdout;
    int result;
    if (prepare_timeline(parsed, &query, from, to) != 0) {
        return 1;
    }
    if (analyze) {
        query.metadata_only = 1;
        if (query.limit > 500) {
            query.limit = 500;
        }
    }
    if (open_database(parsed, &db) != 0) {
        return 1;
    }
    if (parsed->output) {
        output = fopen(parsed->output, "wb");
        if (!output) {
            af_error("cannot open output %s: %s", parsed->output, strerror(errno));
            af_db_close(&db);
            return 1;
        }
    }
    result = analyze ? af_analyze(&db, &query, output) : af_timeline_write(&db, &query, output);
    if (output != stdout && fclose(output) != 0) {
        af_error("cannot close output: %s", strerror(errno));
        result = -1;
    }
    af_db_close(&db);
    return result == 0 ? 0 : 1;
}

static int command_case_output(const options *parsed, int verify) {
    af_db db;
    FILE *output = stdout;
    int result;
    if (!parsed->case_id) {
        af_error("%s requires --case", verify ? "verify" : "manifest");
        return 1;
    }
    if (open_database(parsed, &db) != 0) {
        return 1;
    }
    if (parsed->output) {
        output = fopen(parsed->output, "wb");
        if (!output) {
            af_error("cannot open output %s: %s", parsed->output, strerror(errno));
            af_db_close(&db);
            return 1;
        }
    }
    result = verify ? af_verify_case(&db, parsed->case_id, parsed->base, output)
                    : af_manifest_write(&db, parsed->case_id, output);
    if (output != stdout && fclose(output) != 0) {
        result = -1;
    }
    af_db_close(&db);
    return result == 0 ? 0 : 1;
}

static int command_report(const options *parsed) {
    af_db db;
    af_timeline_query query;
    char from[AF_TIMESTAMP_SIZE];
    char to[AF_TIMESTAMP_SIZE];
    FILE *output = stdout;
    int result;
    if (prepare_timeline(parsed, &query, from, to) != 0) {
        return 1;
    }
    if (open_database(parsed, &db) != 0) {
        return 1;
    }
    if (parsed->output) {
        output = fopen(parsed->output, "wb");
        if (!output) {
            af_error("cannot open output %s: %s", parsed->output, strerror(errno));
            af_db_close(&db);
            return 1;
        }
    }
    result = af_report_write(&db, &query, parsed->analysis, parsed->format,
                             parsed->reviewer, parsed->review_status, output);
    if (output != stdout && fclose(output) != 0) {
        result = -1;
    }
    af_db_close(&db);
    return result == 0 ? 0 : 1;
}

static int command_carve(const options *parsed) {
    af_db db;
    size_t count = 0;
    int result;
    if (!parsed->case_id || !parsed->image || !parsed->output || !parsed->host) {
        af_error("carve requires --case, --image, --output, and --host");
        return 1;
    }
    if (open_database(parsed, &db) != 0) {
        return 1;
    }
    result = af_carve(&db, parsed->case_id, parsed->image, parsed->output,
                      parsed->host, parsed->carver, &count);
    af_db_close(&db);
    if (result == 0) {
        printf("{\"artifacts_recovered\":%zu}\n", count);
        return 0;
    }
    return 1;
}

static int command_artifact(const options *parsed) {
    af_db db;
    const char *format = parsed->format_set ? parsed->format : "hex";
    FILE *output = stdout;
    int result;
    if (!parsed->case_id || parsed->source_id <= 0) {
        af_error("artifact show requires --case and --source-id");
        return 1;
    }
    if (open_database(parsed, &db) != 0) {
        return 1;
    }
    if (parsed->output) {
        output = fopen(parsed->output, "wb");
        if (!output) {
            af_error("cannot open output %s: %s", parsed->output, strerror(errno));
            af_db_close(&db);
            return 1;
        }
    }
    result = af_artifact_show(&db, parsed->case_id, parsed->source_id, format,
                              parsed->max_bytes, parsed->base, output);
    if (output != stdout && fclose(output) != 0) {
        result = -1;
    }
    af_db_close(&db);
    return result == 0 ? 0 : 1;
}

static void make_vault_options(const options *parsed, af_vault_options *vault) {
    memset(vault, 0, sizeof(*vault));
    vault->database_path = parsed->db;
    vault->case_id = parsed->case_id;
    vault->vault_path = parsed->vault;
    vault->key_path = parsed->key;
    vault->host_id = parsed->host;
    vault->vault_id = parsed->vault_id;
    vault->name = parsed->name;
    vault->input_path = parsed->input;
    vault->output_path = parsed->output;
    vault->release_root = parsed->release_root;
    vault->requester = parsed->requester;
    vault->reason = parsed->reason;
    vault->agent_session = parsed->agent_session;
    vault->tool_call = parsed->tool_call;
    vault->identity = parsed->identity;
    vault->expires = parsed->expires;
    vault->release_id = parsed->release_id;
    vault->event_id = parsed->event_id;
    vault->wordlist = parsed->wordlist;
    vault->mode = parsed->mode;
    vault->prefix = parsed->prefix;
    vault->suffix = parsed->suffix;
    vault->approve = parsed->approve;
    vault->agent_pid = parsed->agent_pid;
    vault->max_events = parsed->max_events;
    vault->duration = parsed->duration;
    vault->retention_days = parsed->retention_days;
    vault->digits = parsed->digits;
    vault->variable_bytes = parsed->variable_bytes;
    vault->limit = parsed->candidate_limit;
    vault->inject_overflow = parsed->inject_overflow;
    vault->inject_clock_change = parsed->inject_clock_change;
    vault->fail_evidence_write = parsed->fail_evidence_write;
}

static int command_vault(const options *parsed, const char *command) {
    af_vault_options vault;
    make_vault_options(parsed, &vault);
    if (strcmp(command, "vault-init") == 0) return af_vault_init(&vault);
    if (strcmp(command, "vault-watch") == 0) return af_vault_watch(&vault);
    if (strcmp(command, "vault-release") == 0) return af_vault_release(&vault);
    if (strcmp(command, "vault-cleanup") == 0) return af_vault_cleanup(&vault);
    if (strcmp(command, "vault-timeline") == 0) return af_vault_timeline(&vault);
    if (strcmp(command, "vault-correlate") == 0) return af_vault_correlate(&vault);
    if (strcmp(command, "vault-export") == 0) return af_vault_export(&vault);
    if (strcmp(command, "vault-respond") == 0) return af_vault_respond(&vault, 0);
    if (strcmp(command, "vault-resume") == 0) return af_vault_respond(&vault, 1);
    if (strncmp(command, "crack-", 6) == 0) return af_vault_crack(&vault, command + 6);
    af_error("unknown vault command: %s", command);
    return 2;
}

static int command_crypto(const options *parsed, int operation) {
    unsigned char key[AF_GEMSEAL_KEY_SIZE];
    int result = -1;
    if (operation == 0) {
        if (!parsed->output) {
            af_error("keygen requires --output");
            return 1;
        }
        result = af_gemseal_generate_key(parsed->output);
    } else {
        if (!parsed->key || !parsed->input || !parsed->output) {
            af_error("encryption and decryption require --key, --input, and --output");
            return 1;
        }
        if (af_gemseal_load_key(parsed->key, key) == 0) {
            result = operation == 1
                ? af_gemseal_encrypt_file(key, parsed->input, parsed->output, (uint32_t)parsed->chunk_size)
                : af_gemseal_decrypt_file(key, parsed->input, parsed->output);
        }
        af_crypto_zero(key, sizeof(key));
    }
    if (result != 0) {
        af_error("cryptographic operation failed");
        return 1;
    }
    printf("{\"operation\":\"%s\",\"status\":\"completed\"}\n",
           operation == 0 ? "keygen" : (operation == 1 ? "encrypt" : "decrypt"));
    return 0;
}

int main(int argc, char **argv) {
    options parsed;
    const char *command;
    char subcommand[64];
    int option_index = 2;
    if (argc == 2 && (strcmp(argv[1], "--version") == 0 || strcmp(argv[1], "version") == 0)) {
        puts(VERSION);
        return 0;
    }
    if (argc < 3 || strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "help") == 0) {
        usage(argc < 2 ? stderr : stdout);
        return argc < 2 ? 2 : 0;
    }
    command = argv[1];
    if (!strcmp(command, "artifact")) {
        if (argc < 4 || strcmp(argv[2], "show")) {
            af_error("expected artifact show");
            return 2;
        }
        command = "artifact-show";
        option_index = 3;
    }
    if (!strcmp(command, "vault") || !strcmp(command, "crack")) {
        if (argc < 4) {
            af_error("expected a %s subcommand", command);
            return 2;
        }
        if (snprintf(subcommand, sizeof(subcommand), "%s-%s", command, argv[2]) >= (int)sizeof(subcommand)) {
            return 2;
        }
        command = subcommand;
        option_index = 3;
    }
    if (parse_options(argc - option_index, argv + option_index, &parsed,
                      strcmp(command, "keygen") == 0 || strcmp(command, "encrypt") == 0 ||
                      strcmp(command, "decrypt") == 0 || strncmp(command, "crack-", 6) == 0) != 0) {
        return 2;
    }
    if (strcmp(command, "init") == 0) {
        af_db db;
        if (open_database(&parsed, &db) != 0) {
            return 1;
        }
        af_db_close(&db);
        printf("{\"database_initialized\":true,\"schema_version\":%d}\n", AF_SCHEMA_VERSION);
        return 0;
    }
    if (strcmp(command, "ingest") == 0) return command_ingest(&parsed, 0);
    if (strcmp(command, "ingest-audit") == 0) return command_ingest(&parsed, 1);
    if (strcmp(command, "guard") == 0) return af_guard_run(parsed.db, parsed.case_id, parsed.input, parsed.output);
    if (strcmp(command, "keygen") == 0) return command_crypto(&parsed, 0);
    if (strcmp(command, "encrypt") == 0) return command_crypto(&parsed, 1);
    if (strcmp(command, "decrypt") == 0) return command_crypto(&parsed, 2);
    if (strncmp(command, "vault-", 6) == 0 || strncmp(command, "crack-", 6) == 0) return command_vault(&parsed, command);
    if (strcmp(command, "collect-tsk") == 0) return command_collect(&parsed, 0);
    if (strcmp(command, "collect-ewf") == 0) return command_collect(&parsed, 1);
    if (strcmp(command, "carve") == 0) return command_carve(&parsed);
    if (strcmp(command, "timeline") == 0) return command_timeline(&parsed, 0);
    if (strcmp(command, "analyze") == 0) return command_timeline(&parsed, 1);
    if (strcmp(command, "manifest") == 0) return command_case_output(&parsed, 0);
    if (strcmp(command, "verify") == 0) return command_case_output(&parsed, 1);
    if (strcmp(command, "report") == 0) return command_report(&parsed);
    if (strcmp(command, "artifact-show") == 0) return command_artifact(&parsed);
    af_error("unknown command: %s", command);
    usage(stderr);
    return 2;
}
