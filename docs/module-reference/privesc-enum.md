# Privilege Escalation Enumeration

**File:** `modules/privesc_enum.py`

## Why this exists

Enumerates common privilege escalation vectors: SUID/SGID binaries, world-writable cron jobs, sudoers misconfigurations, capability sets (CAP_SYS_PTRACE, CAP_DAC_READ_SEARCH), writable PATH directories, and kernel version exploitation checks. Synthesized from *Hacking: The Art of Exploitation* and Linux PrivEsc guides.

## Key constants

| Constant | Value | Applied to |
|---|---|---|
| `_MAX_LOG_BYTES` | 64 MB | Log file reads |
| `_MAX_FILE_BYTES` | 64 KB | procfs / config / sudoers reads |

## FORGE audit

Gate: **PASSED**. No HIGH or CRITICAL findings. All config/sudoers reads use `f.read(_MAX_FILE_BYTES)`. Log reads use `f.read(_MAX_LOG_BYTES)`. No lief.parse(). No HTTP reads.
