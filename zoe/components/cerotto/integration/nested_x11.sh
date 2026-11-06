#!/usr/bin/env bash
set -euo pipefail

display="${CEROTTO_NESTED_DISPLAY:-:98}"
if DISPLAY="$display" xwininfo -root >/dev/null 2>&1; then
    printf 'Display %s is already in use; choose another CEROTTO_NESTED_DISPLAY.\n' "$display" >&2
    exit 1
fi

LIBGL_ALWAYS_SOFTWARE=1 Xephyr "$display" \
    -screen "${CEROTTO_NESTED_SCREEN:-1600x1000}" -ac -nolisten tcp -noreset &
server_pid=$!
cleanup() {
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

ready=false
for _ in {1..50}; do
    if DISPLAY="$display" xwininfo -root >/dev/null 2>&1; then
        ready=true
        break
    fi
    if ! kill -0 "$server_pid" 2>/dev/null; then
        wait "$server_pid"
        exit 1
    fi
    sleep 0.1
done
if [[ "$ready" != true ]]; then
    printf 'Xephyr did not create display %s.\n' "$display" >&2
    exit 1
fi

export DISPLAY="$display"
export GDK_BACKEND=x11
export LIBGL_ALWAYS_SOFTWARE=1
if [[ -d /usr/lib/python3/dist-packages ]]; then
    export PYTHONPATH="${PYTHONPATH:+$PYTHONPATH:}/usr/lib/python3/dist-packages"
fi

if (($# == 0)); then
    printf 'Usage: %s COMMAND [ARG ...]\n' "$0" >&2
    exit 2
fi

"$@"
