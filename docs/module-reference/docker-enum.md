# Docker / Container Enumeration

**File:** `modules/docker_enum.py`

## Why this exists

Docker API and container attack surface enumeration: exposed Docker sockets, container escape opportunities, privileged containers, mounted host paths, and credential material in environment variables.

## Key constants

| Constant | Value | Applied to |
|---|---|---|
| `_MAX_HTTP_BYTES` | 4 MB | Docker API HTTP response body |
| `_MAX_FILE_BYTES` | 64 KB | `/proc/1/cgroup` and procfs reads |

## FORGE audit

Gate: **PASSED**. No HIGH or CRITICAL findings. All HTTP reads use `resp.read(_MAX_HTTP_BYTES)`. All `/proc/1/cgroup` reads use `f.read(_MAX_FILE_BYTES)`. No lief.parse().
