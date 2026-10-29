import os
from pathlib import Path

from .errors import SafetyError


def ensure_directory(path):
    path = Path(path)
    if path.is_symlink():
        raise SafetyError(f"output directory is a symlink: {path}")
    path.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise SafetyError(f"output directory is a symlink: {path}")
    return path


def _open_flags(path, overwrite):
    flags = os.O_WRONLY | os.O_CREAT
    flags |= os.O_TRUNC if overwrite else os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if os.path.lexists(path):
        if Path(path).is_symlink():
            raise SafetyError(f"unsafe output file: {path}")
        if not overwrite:
            raise FileExistsError(path)
        if not Path(path).is_file():
            raise SafetyError(f"unsafe output file: {path}")
    return flags


def write_bytes(path, data, overwrite=False):
    path = Path(path)
    flags = _open_flags(path, overwrite)
    with os.fdopen(os.open(path, flags, 0o666), "wb") as stream:
        stream.write(data)


def write_text(path, text, overwrite=False):
    write_bytes(path, text.encode("utf-8"), overwrite)


def remove_for_symlink(path, overwrite=False):
    path = Path(path)
    if not os.path.lexists(path):
        return
    if not overwrite:
        raise FileExistsError(path)
    if path.is_dir() and not path.is_symlink():
        raise SafetyError(f"cannot replace directory with symlink: {path}")
    path.unlink()
