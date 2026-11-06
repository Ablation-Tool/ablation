#ifndef AF_VAULT_H
#define AF_VAULT_H

#include "db.h"
#include <cJSON.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#define AF_VAULT_SOURCE "cerotto.vault"
#define AF_VAULT_SESSION_SIZE 33
#define AF_VAULT_ID_SIZE 65

typedef struct {
    const char *database_path;
    const char *case_id;
    const char *vault_path;
    const char *key_path;
    const char *host_id;
    const char *vault_id;
    const char *name;
    const char *input_path;
    const char *output_path;
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
    size_t digits;
    size_t variable_bytes;
    size_t limit;
    int approve;
    int64_t agent_pid;
    size_t max_events;
    size_t duration;
    size_t retention_days;
    int inject_overflow;
    int inject_clock_change;
    int fail_evidence_write;
} af_vault_options;

int af_vault_open(af_db *db, const char *path);
int af_vault_source(af_db *db, const char *case_id, const char *kind,
                    const char *origin_path, const char *details_json, int64_t *source_id);
int af_vault_emit(af_db *db, const char *case_id, int64_t source_id,
                  const char *event_id, const char *event_type, const char *observed_at,
                  const char *host_id, const char *boot_id, const char *watcher_session,
                  uint64_t sequence, const char *vault_id, const char *path,
                  const char *agent_session, const char *tool_call, const char *consent,
                  const char *plaintext_state, const char *attribution,
                  const cJSON *source_detail);
void af_vault_session_id(char output[AF_VAULT_SESSION_SIZE]);
int af_vault_path_id(const char *path, char output[AF_VAULT_ID_SIZE]);
int af_vault_boot_id(char output[AF_VAULT_ID_SIZE]);
int af_vault_path_inside(const char *path, const char *directory);
int af_vault_init(const af_vault_options *options);
int af_vault_watch(const af_vault_options *options);
int af_vault_release(const af_vault_options *options);
int af_vault_cleanup(const af_vault_options *options);
int af_vault_timeline(const af_vault_options *options);
int af_vault_correlate(const af_vault_options *options);
int af_vault_export(const af_vault_options *options);
int af_vault_respond(const af_vault_options *options, int resume);
int af_vault_crack(const af_vault_options *options, const char *kind);

#endif
