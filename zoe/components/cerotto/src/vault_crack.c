#include "vault.h"
#include "crypto.h"
#include "gemseal.h"
#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef struct {
    af_gemseal_challenge challenge;
    const af_vault_options *options;
    size_t tested;
    size_t skipped;
    int found;
    unsigned char recovered_key[AF_GEMSEAL_KEY_SIZE];
    unsigned char candidate_display[1024];
    size_t candidate_size;
    double started;
} crack_state;

static double monotonic_seconds(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
        return 0;
    }
    return (double)now.tv_sec + (double)now.tv_nsec / 1000000000.0;
}

static int transform_candidate(crack_state *state, const unsigned char *candidate,
                               size_t length, const char *mode) {
    if (state->options->limit && state->tested >= state->options->limit) {
        return 1;
    }
    if (strcmp(mode, "sha256") == 0) {
        af_sha256_raw(candidate, length, state->recovered_key);
    } else if (strcmp(mode, "zero-padded") == 0) {
        if (length > AF_GEMSEAL_KEY_SIZE) {
            ++state->skipped;
            return 0;
        }
        memset(state->recovered_key, 0, AF_GEMSEAL_KEY_SIZE);
        memcpy(state->recovered_key, candidate, length);
    } else if (strcmp(mode, "raw") == 0) {
        if (length != AF_GEMSEAL_KEY_SIZE) {
            ++state->skipped;
            return 0;
        }
        memcpy(state->recovered_key, candidate, AF_GEMSEAL_KEY_SIZE);
    } else {
        return -1;
    }
    ++state->tested;
    if (af_gemseal_verify_first(state->recovered_key, &state->challenge) == 1) {
        state->found = 1;
        if (length > sizeof(state->candidate_display)) {
            length = sizeof(state->candidate_display);
        }
        memcpy(state->candidate_display, candidate, length);
        state->candidate_size = length;
        return 1;
    }
    return 0;
}

static void hex_candidate(char *output, size_t output_size, const unsigned char *candidate, size_t length) {
    static const char hex[] = "0123456789abcdef";
    size_t index;
    size_t maximum = (output_size - 1) / 2;
    if (length > maximum) {
        length = maximum;
    }
    for (index = 0; index < length; ++index) {
        output[index * 2] = hex[candidate[index] >> 4];
        output[index * 2 + 1] = hex[candidate[index] & 15];
    }
    output[length * 2] = '\0';
}

static int finish(crack_state *state, const char *mode) {
    cJSON *root = cJSON_CreateObject();
    char candidate_hex[2049];
    char *printed;
    double elapsed = monotonic_seconds() - state->started;
    double rate = elapsed > 0 ? state->tested / elapsed : 0;
    int result = state->found ? 0 : 1;
    hex_candidate(candidate_hex, sizeof(candidate_hex), state->candidate_display, state->candidate_size);
    if (!root || !cJSON_AddStringToObject(root, "mode", mode) ||
        !cJSON_AddNumberToObject(root, "tested", (double)state->tested) ||
        !cJSON_AddNumberToObject(root, "skipped", (double)state->skipped) ||
        !cJSON_AddNumberToObject(root, "elapsed_seconds", elapsed) ||
        !cJSON_AddNumberToObject(root, "candidates_per_second", rate) ||
        !cJSON_AddBoolToObject(root, "found", state->found) ||
        !cJSON_AddStringToObject(root, "candidate_hex", state->found ? candidate_hex : "") ||
        !cJSON_AddStringToObject(root, "scope", "weak_manual_key_derivation_only_not_generic_chacha20_attack")) {
        cJSON_Delete(root);
        return 2;
    }
    if (state->found && state->options->output_path) {
        if (af_gemseal_decrypt_file(state->recovered_key, state->options->input_path,
                                    state->options->output_path) != 0) {
            cJSON_Delete(root);
            return 2;
        }
        if (!cJSON_AddBoolToObject(root, "full_container_verified", 1)) {
            cJSON_Delete(root);
            return 2;
        }
    }
    printed = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!printed) {
        return 2;
    }
    printf("%s\n", printed);
    free(printed);
    return result;
}

static int crack_wordlist(crack_state *state, const char *mode) {
    FILE *file = fopen(state->options->wordlist, "rb");
    char *line = NULL;
    size_t capacity = 0;
    ssize_t length;
    int result = 0;
    if (!file) {
        return 2;
    }
    while (!state->found && (length = getline(&line, &capacity, file)) >= 0) {
        if (length > 1024) {
            result = 2;
            break;
        }
        while (length > 0 && (line[length - 1] == '\n' || line[length - 1] == '\r')) {
            line[--length] = '\0';
        }
        result = transform_candidate(state, (const unsigned char *)line, (size_t)length, mode);
        if (result < 0 || (result == 1 && !state->found && state->options->limit && state->tested >= state->options->limit)) {
            break;
        }
    }
    free(line);
    fclose(file);
    return result < 0 ? 2 : finish(state, mode);
}

static int crack_pin(crack_state *state, const char *mode) {
    size_t digits = state->options->digits ? state->options->digits : 4;
    size_t maximum = 1;
    size_t index;
    const char *prefix = state->options->prefix ? state->options->prefix : "";
    const char *suffix = state->options->suffix ? state->options->suffix : "";
    if (digits < 1 || digits > 8) {
        return 2;
    }
    for (index = 0; index < digits; ++index) {
        maximum *= 10;
    }
    for (index = 0; index < maximum && !state->found; ++index) {
        char candidate[1024];
        int length = snprintf(candidate, sizeof(candidate), "%s%0*zu%s", prefix, (int)digits, index, suffix);
        int status;
        if (length < 0 || (size_t)length >= sizeof(candidate)) {
            return 2;
        }
        status = transform_candidate(state, (const unsigned char *)candidate, (size_t)length, mode);
        if (status < 0 || (status == 1 && !state->found && state->options->limit && state->tested >= state->options->limit)) {
            break;
        }
    }
    return finish(state, mode);
}

static int crack_raw_prefix(crack_state *state) {
    size_t variable = state->options->variable_bytes ? state->options->variable_bytes : 1;
    size_t maximum = 1;
    size_t index;
    if (variable < 1 || variable > 4) {
        return 2;
    }
    for (index = 0; index < variable; ++index) {
        maximum *= 256;
    }
    for (index = 0; index < maximum && !state->found; ++index) {
        unsigned char candidate[AF_GEMSEAL_KEY_SIZE] = {0};
        size_t byte;
        int status;
        for (byte = 0; byte < variable; ++byte) {
            candidate[byte] = (unsigned char)(index >> (byte * 8));
        }
        status = transform_candidate(state, candidate, sizeof(candidate), "raw");
        if (status < 0 || (status == 1 && !state->found && state->options->limit && state->tested >= state->options->limit)) {
            break;
        }
    }
    return finish(state, "raw");
}

int af_vault_crack(const af_vault_options *options, const char *kind) {
    crack_state state;
    const char *mode = options && options->mode ? options->mode : "sha256";
    int result;
    memset(&state, 0, sizeof(state));
    if (!options || !options->input_path || !kind || af_gemseal_load_challenge(options->input_path, &state.challenge) != 0) {
        af_error("cannot load a valid GEMSEAL first-record challenge");
        return 2;
    }
    state.options = options;
    state.started = monotonic_seconds();
    if (strcmp(kind, "wordlist") == 0) {
        if (!options->wordlist) {
            result = 2;
        } else {
            result = crack_wordlist(&state, mode);
        }
    } else if (strcmp(kind, "pin") == 0) {
        result = crack_pin(&state, mode);
    } else if (strcmp(kind, "raw-prefix") == 0) {
        result = crack_raw_prefix(&state);
    } else {
        result = 2;
    }
    af_gemseal_challenge_free(&state.challenge);
    af_crypto_zero(state.recovered_key, sizeof(state.recovered_key));
    return result;
}
