# SyscallTracer / detect_raw_socket_creation / detect_ptrace_abuse

**File:** `modules/syscall_trace.py`

## Why this exists

Three gaps existed before this module:

1. **No unified syscall tracing surface.** Tracing syscalls via strace/dtruss required manual subprocess wrangling per session. SyscallTracer wraps strace (Linux) and dtruss (macOS) with timeouts, error handling, and structured output in one call.

2. **Raw socket and promiscuous mode detection scattered across tools.** `detect_raw_socket_creation()` consolidates `/proc/net/raw`, `/proc/net/packet`, `/sys/class/net/*/flags`, and `/proc/{pid}/status CapEff` checks into a single findings list. Previously these required separate grep commands on each session.

3. **ptrace abuse surface not checked.** `detect_ptrace_abuse()` checks `TracerPid` across all processes, `ptrace_scope`, and seccomp status — these are the three indicators that a system is actively being traced or is vulnerable to tracing attacks.

## Usage

```python
from modules.syscall_trace import SyscallTracer, detect_raw_socket_creation, detect_ptrace_abuse

# Trace a running process
tracer = SyscallTracer(pid=1234)
stats = tracer.trace_process(duration=5)
print(tracer.report(stats))

# Detailed syscall capture with filter
entries = tracer.trace_detailed(duration=5, syscall_filter='open,read,write')
for e in entries:
    print(e['syscall'], e['args'], e['return'])

# Raw socket / promiscuous mode detection (no PID = check system-wide)
findings = detect_raw_socket_creation()
for f in findings:
    print(f['severity'], f['title'])

# ptrace abuse surface
findings = detect_ptrace_abuse()
```

## Key constants

| Constant | Value | Applied to |
|---|---|---|
| `_MAX_BINARY_BYTES` | 256 MB | Binary file read cap |
| `_MAX_PROC_BYTES` | 4 MB | `/proc/pid/cmdline`, `/proc/pid/environ` |
| `_MAX_SYSCTL_BYTES` | 256 B | `/proc/sys/*` sysctl values |
| `_MAX_SYSFS_BYTES` | 64 B | `/sys/class/net/*/flags` and similar counters |

## FORGE audit

Gate: **PASSED**. Two CWE-770 fixes applied:
- `/sys/class/net/*/flags`: `read_text()` → bounded `open().read(_MAX_SYSFS_BYTES)`.
- `/proc/sys/kernel/yama/ptrace_scope`: `read_text()` → bounded `open().read(_MAX_SYSCTL_BYTES)`.

All subprocess calls go through `_run()` which enforces `timeout`. All bounded reads for cmdline/environ use `_MAX_PROC_BYTES`. No lief.parse(). No HTTP reads.
