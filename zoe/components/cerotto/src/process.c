#include "process.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

void af_process_result_init(af_process_result *result) {
    af_buf_init(&result->stdout_data);
    af_buf_init(&result->stderr_data);
    result->exit_code = -1;
}

void af_process_result_free(af_process_result *result) {
    af_buf_free(&result->stdout_data);
    af_buf_free(&result->stderr_data);
    result->exit_code = -1;
}

static int set_nonblocking(int descriptor) {
    int flags = fcntl(descriptor, F_GETFL, 0);
    return flags < 0 ? -1 : fcntl(descriptor, F_SETFL, flags | O_NONBLOCK);
}

static int create_pipe(int descriptors[2]) {
    if (pipe(descriptors) != 0) {
        return -1;
    }
    if (fcntl(descriptors[0], F_SETFD, FD_CLOEXEC) != 0 ||
        fcntl(descriptors[1], F_SETFD, FD_CLOEXEC) != 0) {
        close(descriptors[0]);
        close(descriptors[1]);
        return -1;
    }
    return 0;
}

static void close_descriptor(int *descriptor) {
    if (*descriptor >= 0) {
        close(*descriptor);
        *descriptor = -1;
    }
}

int af_process_run(char *const argv[], const void *stdin_data, size_t stdin_length,
                   size_t max_output, af_process_result *result) {
    int input_pipe[2] = {-1, -1};
    int output_pipe[2] = {-1, -1};
    int error_pipe[2] = {-1, -1};
    pid_t child = -1;
    const unsigned char *input = stdin_data;
    size_t input_offset = 0;
    int failed = 0;
    int child_status = 0;
    int output_open = 1;
    int error_open = 1;
    int input_open = stdin_data && stdin_length;
    struct pollfd descriptors[3];
    char chunk[16384];

    if (!argv || !argv[0] || create_pipe(output_pipe) != 0 || create_pipe(error_pipe) != 0 ||
        (input_open && create_pipe(input_pipe) != 0)) {
        af_error("cannot create subprocess pipes: %s", strerror(errno));
        goto failure;
    }
    child = fork();
    if (child < 0) {
        af_error("cannot fork subprocess: %s", strerror(errno));
        goto failure;
    }
    if (child == 0) {
        if (input_open) {
            if (dup2(input_pipe[0], STDIN_FILENO) < 0) {
                _exit(126);
            }
        } else {
            int null_input = open("/dev/null", O_RDONLY);
            if (null_input < 0 || dup2(null_input, STDIN_FILENO) < 0) {
                _exit(126);
            }
            if (null_input != STDIN_FILENO) {
                close(null_input);
            }
        }
        if (dup2(output_pipe[1], STDOUT_FILENO) < 0 || dup2(error_pipe[1], STDERR_FILENO) < 0) {
            _exit(126);
        }
        close(input_pipe[0]); close(input_pipe[1]);
        close(output_pipe[0]); close(output_pipe[1]);
        close(error_pipe[0]); close(error_pipe[1]);
        execvp(argv[0], argv);
        _exit(127);
    }

    close_descriptor(&input_pipe[0]);
    close_descriptor(&output_pipe[1]);
    close_descriptor(&error_pipe[1]);
    if (input_open && set_nonblocking(input_pipe[1]) != 0) {
        af_error("cannot configure subprocess input: %s", strerror(errno));
        goto failure;
    }
    if (set_nonblocking(output_pipe[0]) != 0 || set_nonblocking(error_pipe[0]) != 0) {
        af_error("cannot configure subprocess output: %s", strerror(errno));
        goto failure;
    }

    while (output_open || error_open || input_open) {
        int ready;
        int count = 0;
        nfds_t index = 0;
        int input_index = -1;
        int output_index = -1;
        int error_index = -1;
        if (input_open) {
            input_index = (int)index;
            descriptors[index].fd = input_pipe[1];
            descriptors[index].events = POLLOUT;
            descriptors[index].revents = 0;
            ++index;
            ++count;
        }
        if (output_open) {
            output_index = (int)index;
            descriptors[index].fd = output_pipe[0];
            descriptors[index].events = POLLIN;
            descriptors[index].revents = 0;
            ++index;
            ++count;
        }
        if (error_open) {
            error_index = (int)index;
            descriptors[index].fd = error_pipe[0];
            descriptors[index].events = POLLIN;
            descriptors[index].revents = 0;
            ++index;
            ++count;
        }
        ready = poll(descriptors, (nfds_t)count, -1);
        if (ready < 0) {
            if (errno == EINTR) {
                continue;
            }
            af_error("subprocess polling failed: %s", strerror(errno));
            goto failure;
        }
        if (input_index >= 0 && descriptors[input_index].revents) {
            ssize_t written = write(input_pipe[1], input + input_offset, stdin_length - input_offset);
            if (written > 0) {
                input_offset += (size_t)written;
                if (input_offset == stdin_length) {
                    close_descriptor(&input_pipe[1]);
                    input_open = 0;
                }
            } else if (written < 0 && errno != EAGAIN && errno != EINTR) {
                if (errno != EPIPE) {
                    af_error("cannot write subprocess input: %s", strerror(errno));
                    goto failure;
                }
                close_descriptor(&input_pipe[1]);
                input_open = 0;
            }
        }
        if (output_index >= 0 && descriptors[output_index].revents) {
            short events = descriptors[output_index].revents;
            ssize_t received = read(output_pipe[0], chunk, sizeof(chunk));
            if (received > 0) {
                if ((size_t)received > max_output - result->stdout_data.len ||
                    af_buf_append(&result->stdout_data, chunk, (size_t)received) != 0) {
                    af_error("subprocess stdout exceeds %zu bytes", max_output);
                    goto failure;
                }
            } else if (received == 0 || (events & (POLLHUP | POLLERR | POLLNVAL))) {
                close_descriptor(&output_pipe[0]);
                output_open = 0;
            } else if (errno != EAGAIN && errno != EINTR) {
                af_error("cannot read subprocess stdout: %s", strerror(errno));
                goto failure;
            }
        }
        if (error_index >= 0 && descriptors[error_index].revents) {
            short events = descriptors[error_index].revents;
            ssize_t received = read(error_pipe[0], chunk, sizeof(chunk));
            if (received > 0) {
                if ((size_t)received > max_output - result->stderr_data.len ||
                    af_buf_append(&result->stderr_data, chunk, (size_t)received) != 0) {
                    af_error("subprocess stderr exceeds %zu bytes", max_output);
                    goto failure;
                }
            } else if (received == 0 || (events & (POLLHUP | POLLERR | POLLNVAL))) {
                close_descriptor(&error_pipe[0]);
                error_open = 0;
            } else if (errno != EAGAIN && errno != EINTR) {
                af_error("cannot read subprocess stderr: %s", strerror(errno));
                goto failure;
            }
        }
    }
    while (waitpid(child, &child_status, 0) < 0) {
        if (errno != EINTR) {
            af_error("cannot wait for subprocess: %s", strerror(errno));
            goto failure;
        }
    }
    child = -1;
    if (!WIFEXITED(child_status)) {
        af_error("subprocess terminated abnormally");
        goto failure;
    }
    result->exit_code = WEXITSTATUS(child_status);
    failed = 0;
    goto cleanup;

failure:
    failed = 1;
    if (child > 0) {
        kill(child, SIGKILL);
        while (waitpid(child, &child_status, 0) < 0 && errno == EINTR) {
        }
        child = -1;
    }
cleanup:
    close_descriptor(&input_pipe[0]); close_descriptor(&input_pipe[1]);
    close_descriptor(&output_pipe[0]); close_descriptor(&output_pipe[1]);
    close_descriptor(&error_pipe[0]); close_descriptor(&error_pipe[1]);
    return failed ? -1 : 0;
}
