#ifndef AF_PROCESS_H
#define AF_PROCESS_H

#include "util.h"

#include <stddef.h>

typedef struct {
    af_buffer stdout_data;
    af_buffer stderr_data;
    int exit_code;
} af_process_result;

void af_process_result_init(af_process_result *result);
void af_process_result_free(af_process_result *result);
int af_process_run(char *const argv[], const void *stdin_data, size_t stdin_length,
                   size_t max_output, af_process_result *result);

#endif
