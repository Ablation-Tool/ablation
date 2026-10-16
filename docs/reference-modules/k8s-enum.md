# Kubernetes Enumeration

**File:** `modules/k8s_enum.py`

## Why this exists

Kubernetes attack surface enumeration: exposed API server endpoints, RBAC misconfigurations, privileged pod detection, hostPath volume mounts, service account token exposure, and kubelet read-only port (10255) checks.

## Key constants

| Constant | Value | Applied to |
|---|---|---|
| `_MAX_FILE_BYTES` | 64 KB | procfs / kubepods cgroup file reads |

## FORGE audit

Gate: **PASSED**. No HIGH or CRITICAL findings. All procfs reads use `f.read(_MAX_FILE_BYTES).splitlines()` including `_check_privileged_caps()` `/proc/self/status` (L2801 — fixed this session). HTTP/API responses use inline `resp.read(4 * 1024 * 1024)` cap (4 MB). All kubectl subprocess calls have `timeout=` on continuation lines. No lief.parse().
