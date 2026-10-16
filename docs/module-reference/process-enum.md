# Process Enumeration

**File:** `modules/process_enum.py`

## Why this exists

Enumerates running processes, loaded modules, and memory maps from `/proc`: process names, cmdlines, environment variables, open file descriptors, and memory-mapped regions. Used in post-exploitation to identify high-value processes and loaded credentials in memory.

## Key constants

| Constant | Value | Applied to |
|---|---|---|
| `_MAX_PROC_BYTES` | 4 MB | `/proc/pid/environ`, `/proc/pid/cmdline` |

## FORGE audit

Gate: **PASSED**. No HIGH or CRITICAL findings. `/proc/pid/comm` reads use `f.read(16)` (kernel TASK_COMM_LEN=16). cmdline and environ reads use `f.read(_MAX_PROC_BYTES)`. No lief.parse(). No HTTP reads.
