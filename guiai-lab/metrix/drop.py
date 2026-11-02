import os
from pathlib import Path
import shlex


MAX_DROP_BYTES = 8 * 1024 * 1024


def quote_dropped_path(path, windows=None):
    if windows is None:
        windows = os.name == "nt"
    if windows:
        if '"' in path:
            raise ValueError("Drop rejected: a Windows path contains a double quote")
        return f'"{path}"'
    return shlex.quote(path)


def dropped_payload(paths, windows=None):
    normalized = []
    for value in paths:
        path = os.path.abspath(os.fspath(value))
        if any(ord(character) < 32 or ord(character) == 127 for character in path):
            raise ValueError("Drop rejected: paths containing control characters are not supported")
        if not Path(path).exists():
            raise ValueError(f"Drop rejected: local path does not exist: {path}")
        normalized.append(path)
    if not normalized:
        raise ValueError("Drop rejected: no local files or folders were supplied")
    quoted = [quote_dropped_path(path, windows) for path in normalized]
    payload = (" ".join(quoted) + " ").encode("utf-8")
    if len(payload) > MAX_DROP_BYTES:
        raise ValueError("Drop rejected: 8 MiB maximum; use the CLI's file-input workflow")
    return payload
