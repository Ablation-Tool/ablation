import os


LOCK_SH = 1
LOCK_EX = 2
LOCK_UN = 8

if os.name == "nt":
    import msvcrt
else:
    import fcntl


def file_lock(stream, operation):
    if os.name == "nt":
        stream.seek(0)
        msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK if operation == LOCK_UN else msvcrt.LK_LOCK, 1)
    else:
        fcntl.flock(stream.fileno(), operation)
