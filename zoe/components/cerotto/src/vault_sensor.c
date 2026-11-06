#include "vault.h"
#include "util.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define MAX_WATCHES 256
#define MAX_WATCH_DEPTH 32
#define EVENT_BUFFER_SIZE 65536

static volatile sig_atomic_t stop_requested = 0;

typedef struct {
    int descriptor;
    char *path;
} watch_entry;

typedef struct {
    int fd;
    af_db db;
    watch_entry watches[MAX_WATCHES];
    size_t count;
    char session[AF_VAULT_SESSION_SIZE];
    char boot_id[AF_VAULT_ID_SIZE];
    char vault_id[AF_VAULT_ID_SIZE];
    char vault_path[PATH_MAX];
    int64_t source_id;
    uint64_t sequence;
    size_t published;
    const af_vault_options *options;
} watcher_state;

static void request_stop(int signal_number) {
    (void)signal_number;
    stop_requested = 1;
}

static void free_watches(watcher_state *state) {
    size_t index;
    for (index = 0; index < state->count; ++index) {
        free(state->watches[index].path);
    }
    state->count = 0;
}

static int add_watch(watcher_state *state, const char *path) {
    char resolved[PATH_MAX];
    struct stat status;
    int descriptor;
    size_t index;
    if (state->count >= MAX_WATCHES || lstat(path, &status) != 0 || !S_ISDIR(status.st_mode) ||
        S_ISLNK(status.st_mode) || !realpath(path, resolved)) {
        return -1;
    }
    for (index = 0; index < state->count; ++index) {
        if (strcmp(state->watches[index].path, resolved) == 0) {
            return 0;
        }
    }
    descriptor = inotify_add_watch(state->fd, resolved,
        IN_ACCESS | IN_MODIFY | IN_ATTRIB | IN_CLOSE_WRITE | IN_OPEN |
        IN_MOVED_FROM | IN_MOVED_TO | IN_CREATE | IN_DELETE |
        IN_DELETE_SELF | IN_MOVE_SELF | IN_ONLYDIR);
    if (descriptor < 0) {
        return -1;
    }
    state->watches[state->count].descriptor = descriptor;
    state->watches[state->count].path = strdup(resolved);
    if (!state->watches[state->count].path) {
        inotify_rm_watch(state->fd, descriptor);
        return -1;
    }
    ++state->count;
    return 0;
}

static int watch_recursive(watcher_state *state, const char *path, unsigned depth) {
    DIR *directory;
    struct dirent *entry;
    int result = -1;
    if (depth > MAX_WATCH_DEPTH || add_watch(state, path) != 0) {
        return -1;
    }
    directory = opendir(path);
    if (!directory) {
        return -1;
    }
    while ((entry = readdir(directory)) != NULL) {
        char child[PATH_MAX];
        struct stat status;
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        if (snprintf(child, sizeof(child), "%s/%s", path, entry->d_name) >= (int)sizeof(child)) {
            continue;
        }
        if (lstat(child, &status) == 0 && S_ISDIR(status.st_mode) && !S_ISLNK(status.st_mode)) {
            if (watch_recursive(state, child, depth + 1) != 0) {
                goto cleanup;
            }
        }
    }
    result = 0;
cleanup:
    if (closedir(directory) != 0) {
        result = -1;
    }
    return result;
}

static const char *watch_path(const watcher_state *state, int descriptor) {
    size_t index;
    for (index = 0; index < state->count; ++index) {
        if (state->watches[index].descriptor == descriptor) {
            return state->watches[index].path;
        }
    }
    return NULL;
}

static uint64_t monotonic_ns(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
        return 0;
    }
    return (uint64_t)now.tv_sec * 1000000000ULL + (uint64_t)now.tv_nsec;
}

static int emit_event(watcher_state *state, const char *type, const char *path, cJSON *raw) {
    char timestamp[AF_TIMESTAMP_SIZE];
    char event_id[160];
    int result;
    if (state->options->fail_evidence_write && strncmp(type, "file.", 5) == 0) {
        af_error("vault evidence write failed");
        return -1;
    }
    if (af_now(timestamp) != 0) {
        return -1;
    }
    ++state->sequence;
    if (snprintf(event_id, sizeof(event_id), "vault:%s:%llu", state->session,
                 (unsigned long long)state->sequence) >= (int)sizeof(event_id)) {
        return -1;
    }
    result = af_vault_emit(&state->db, state->options->case_id, state->source_id, event_id, type,
                           timestamp, state->options->host_id, state->boot_id, state->session,
                           state->sequence, state->vault_id, path, NULL, NULL, "unknown",
                           "ciphertext", "unresolved", raw);
    return result;
}

static int emit(watcher_state *state, const char *type, const char *path,
                uint32_t mask, int descriptor, uint32_t cookie, const char *name, int is_directory) {
    cJSON *raw = cJSON_CreateObject();
    char mask_text[16];
    int result;
    if (!raw) {
        return -1;
    }
    snprintf(mask_text, sizeof(mask_text), "0x%08x", mask);
    if (!cJSON_AddStringToObject(raw, "api", "inotify") ||
        !cJSON_AddStringToObject(raw, "mask", mask_text) ||
        !cJSON_AddNumberToObject(raw, "watch_descriptor", descriptor) ||
        !cJSON_AddNumberToObject(raw, "cookie", cookie) ||
        !cJSON_AddNumberToObject(raw, "monotonic_ns", (double)monotonic_ns()) ||
        !cJSON_AddBoolToObject(raw, "is_directory", is_directory) ||
        (name && !cJSON_AddStringToObject(raw, "name", name))) {
        cJSON_Delete(raw);
        return -1;
    }
    result = emit_event(state, type, path, raw);
    cJSON_Delete(raw);
    if (result == 0 && strncmp(type, "file.", 5) == 0) {
        ++state->published;
    }
    return result;
}

static int emit_health(watcher_state *state, const char *type, const char *reason) {
    cJSON *raw = cJSON_CreateObject();
    int result;
    if (!raw || !cJSON_AddStringToObject(raw, "api", "health") ||
        !cJSON_AddStringToObject(raw, "reason", reason) ||
        !cJSON_AddNumberToObject(raw, "monotonic_ns", (double)monotonic_ns())) {
        cJSON_Delete(raw);
        return -1;
    }
    result = emit_event(state, type, state->vault_path, raw);
    cJSON_Delete(raw);
    return result;
}

static int handle_event(watcher_state *state, const struct inotify_event *event) {
    const char *base;
    const char *name = event->len ? event->name : "";
    char path[PATH_MAX];
    static const struct {
        uint32_t mask;
        const char *type;
    } types[] = {
        {IN_ACCESS, "file.read"}, {IN_MODIFY, "file.modify"},
        {IN_ATTRIB, "file.metadata"}, {IN_CLOSE_WRITE, "file.close_write"},
        {IN_OPEN, "file.open"}, {IN_MOVED_FROM, "file.moved_from"},
        {IN_MOVED_TO, "file.moved_to"}, {IN_CREATE, "file.create"},
        {IN_DELETE, "file.delete"}, {IN_DELETE_SELF, "file.delete_self"},
        {IN_MOVE_SELF, "file.move_self"},
    };
    size_t index;
    if (event->mask & IN_Q_OVERFLOW) {
        return emit(state, "sensor.queue_overflow", state->vault_path, event->mask, event->wd, event->cookie, "", 0);
    }
    if (event->mask & IN_IGNORED) {
        return emit(state, "sensor.watch_removed", state->vault_path, event->mask, event->wd, event->cookie, "", 0);
    }
    base = watch_path(state, event->wd);
    if (!base) {
        return 0;
    }
    if (name[0]) {
        if (snprintf(path, sizeof(path), "%s/%s", base, name) >= (int)sizeof(path)) {
            return -1;
        }
    } else if (snprintf(path, sizeof(path), "%s", base) >= (int)sizeof(path)) {
        return -1;
    }
    if ((event->mask & IN_ISDIR) && (event->mask & (IN_CREATE | IN_MOVED_TO))) {
        if (add_watch(state, path) != 0) {
            return emit_health(state, "sensor.degraded", "recursive_watch_failed");
        }
    }
    for (index = 0; index < sizeof(types) / sizeof(types[0]); ++index) {
        if (event->mask & types[index].mask) {
            if (emit(state, types[index].type, path, event->mask, event->wd,
                     event->cookie, name, (event->mask & IN_ISDIR) != 0) != 0) {
                return -1;
            }
        }
    }
    return 0;
}

static int check_clock(watcher_state *state, time_t initial_real, time_t initial_mono) {
    time_t current_real = time(NULL);
    time_t current_mono = 0;
    double difference;
    struct timespec monotonic;
    if (current_real == (time_t)-1 || clock_gettime(CLOCK_MONOTONIC, &monotonic) != 0) {
        return 0;
    }
    current_mono = monotonic.tv_sec;
    difference = difftime(current_real - initial_real, current_mono - initial_mono);
    if (difference > 5.0 || difference < -5.0) {
        if (emit_health(state, "sensor.clock_change", "realtime_monotonic_diverged") != 0) {
            return -1;
        }
        return 1;
    }
    return 0;
}

int af_vault_watch(const af_vault_options *options) {
    watcher_state state;
    struct sigaction action;
    char resolved[PATH_MAX];
    char *configuration = NULL;
    cJSON *detail = NULL;
    time_t initial_real;
    time_t initial_mono;
    struct timespec monotonic;
    time_t started;
    int result = -1;
    int failed = 0;
    memset(&state, 0, sizeof(state));
    state.fd = -1;
    state.options = options;
    if (!options || !options->database_path || !options->case_id || !options->vault_path ||
        !options->host_id || !realpath(options->vault_path, resolved)) {
        af_error("vault watch requires a database, case, host, and existing vault");
        return 1;
    }
    if (af_vault_path_inside(options->database_path, resolved) == 1) {
        af_error("evidence store must be outside the watched vault");
        return 1;
    }
    if (options->vault_id) {
        if (strlen(options->vault_id) >= sizeof(state.vault_id)) {
            return 1;
        }
        strcpy(state.vault_id, options->vault_id);
    } else if (af_vault_path_id(resolved, state.vault_id) != 0) {
        return 1;
    }
    strcpy(state.vault_path, resolved);
    af_vault_session_id(state.session);
    af_vault_boot_id(state.boot_id);
    state.fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    if (state.fd < 0 || watch_recursive(&state, resolved, 0) != 0) {
        af_error("cannot initialize inotify watches: %s", strerror(errno));
        goto cleanup;
    }
    detail = cJSON_CreateObject();
    if (!detail || !cJSON_AddStringToObject(detail, "api", "inotify") ||
        !cJSON_AddStringToObject(detail, "watcher_session", state.session) ||
        !cJSON_AddStringToObject(detail, "vault_path", resolved) ||
        !cJSON_AddNumberToObject(detail, "watch_count", (double)state.count) ||
        !cJSON_AddStringToObject(detail, "process_attribution", "unavailable_from_inotify")) {
        goto cleanup;
    }
    configuration = cJSON_PrintUnformatted(detail);
    if (!configuration) {
        goto cleanup;
    }
    if (af_vault_open(&state.db, options->database_path) != 0 ||
        af_vault_source(&state.db, options->case_id, "vault_watch", resolved, configuration, &state.source_id) != 0) {
        goto cleanup;
    }
    memset(&action, 0, sizeof(action));
    action.sa_handler = request_stop;
    sigemptyset(&action.sa_mask);
    sigaction(SIGINT, &action, NULL);
    sigaction(SIGTERM, &action, NULL);
    stop_requested = 0;
    if (emit_health(&state, "sensor.started", "watch_initialized") != 0 ||
        emit_health(&state, "sensor.ready", "watches_active") != 0) {
        goto cleanup;
    }
    if (options->inject_overflow) {
        struct inotify_event injected;
        memset(&injected, 0, sizeof(injected));
        injected.wd = -1;
        injected.mask = IN_Q_OVERFLOW;
        if (handle_event(&state, &injected) != 0) {
            failed = 1;
        }
    }
    if (options->inject_clock_change && emit_health(&state, "sensor.clock_change", "injected_diagnostic") != 0) {
        failed = 1;
    }
    initial_real = time(NULL);
    started = initial_real;
    initial_mono = 0;
    if (clock_gettime(CLOCK_MONOTONIC, &monotonic) == 0) {
        initial_mono = monotonic.tv_sec;
    }
    while (!stop_requested && !failed) {
        struct pollfd descriptor = {state.fd, POLLIN, 0};
        int ready = poll(&descriptor, 1, 500);
        time_t current = time(NULL);
        if (options->duration && current >= started && (size_t)(current - started) >= options->duration) {
            break;
        }
        if (check_clock(&state, initial_real, initial_mono) != 0) {
            initial_real = current;
            if (clock_gettime(CLOCK_MONOTONIC, &monotonic) == 0) {
                initial_mono = monotonic.tv_sec;
            }
        }
        if (ready < 0) {
            if (errno == EINTR) {
                continue;
            }
            failed = 1;
            break;
        }
        if (ready == 0) {
            continue;
        }
        {
            unsigned char buffer[EVENT_BUFFER_SIZE];
            ssize_t amount = read(state.fd, buffer, sizeof(buffer));
            size_t offset = 0;
            if (amount < 0 && (errno == EINTR || errno == EAGAIN)) {
                continue;
            }
            if (amount <= 0) {
                failed = 1;
                break;
            }
            while (offset < (size_t)amount) {
                const struct inotify_event *event = (const struct inotify_event *)(buffer + offset);
                if (handle_event(&state, event) != 0) {
                    failed = 1;
                    break;
                }
                offset += sizeof(struct inotify_event) + event->len;
            }
            if (options->max_events && state.published >= options->max_events) {
                break;
            }
        }
    }
    if (failed) {
        if (emit_health(&state, "sensor.degraded", "event_processing_failed") != 0) {
            goto cleanup;
        }
        result = 1;
    } else {
        const char *reason = stop_requested ? "signal" :
            (options->max_events && state.published >= options->max_events ? "max_events" : "duration");
        if (emit_health(&state, "sensor.stopped", reason) != 0) {
            goto cleanup;
        }
        result = 0;
    }
cleanup:
    if (state.fd >= 0) {
        close(state.fd);
    }
    free_watches(&state);
    if (state.db.handle) {
        af_db_close(&state.db);
    }
    cJSON_Delete(detail);
    free(configuration);
    return result;
}
