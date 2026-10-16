# SyscallTracer / System Exploitation Surface Detection

**File:** `modules/syscall_trace.py`

## Why this exists

Three gaps existed before this module:

1. **No unified syscall tracing surface.** Tracing syscalls via strace/dtruss required manual subprocess wrangling per session. `SyscallTracer` wraps strace (Linux) and dtruss (macOS) with timeouts, error handling, and structured output in one call.

2. **Raw socket, ptrace, and kernel exploit surface detection were uncoordinated.** Checks across `/proc/net/raw`, `/proc/sys/kernel/yama/ptrace_scope`, ASLR state, and procfs capability fields required separate commands. This module consolidates all of them into structured findings lists.

3. **Binary-analysis exploitation techniques (shellcode, process hollowing, NTLM relay, dylib hijacking) had no automated detection.** Functions like `detect_shellcode_patterns`, `detect_process_hollowing`, and `detect_ntlm_relay_surface` analyze raw binary bytes for exploitation primitives without requiring file I/O.

---

## Scope

2653-line module covering:

**Syscall tracing (live processes):**
- `SyscallTracer`: strace (Linux) / dtruss (macOS) wrapper — trace, filter, report
- File access / network / process operations convenience wrappers

**Live system detection (procfs):**
- `detect_raw_socket_creation`: `/proc/net/raw`, `/proc/net/packet`, `/sys/class/net/*/flags`, `/proc/{pid}/status CapEff` — raw socket and promiscuous mode
- `detect_ptrace_abuse`: TracerPid scan, ptrace_scope, seccomp status across all PIDs
- `detect_socket_abuse_patterns`: TCP LISTEN from non-root on unprivileged ports, connected UDP, world-accessible UNIX sockets
- `check_network_sniffing_indicators`: `ip link show PROMISC`, RX/TX ratio, known sniffer process names
- `detect_heap_spray_artifacts`: ASLR/kptr_restrict/dmesg_restrict/mmap_min_addr/suid_dumpable sysctl checks; large anonymous rwx mappings; VmPeak > 90% RAM
- `detect_kernel_exploit_surface`: ptrace_scope, zero-size/tainted modules, unprivileged BPF, io_uring, user namespaces, huge pages, vsyscall mapping, kallsyms readability

**Binary analysis (bytes input — no file I/O):**
- `detect_dylib_hijacking_surface`: Mach-O LC_RPATH writability, LC_LOAD_DYLIB from /tmp, bundled framework injection, DYLD_INSERT_LIBRARIES
- `detect_macos_task_port_abuse`: task_for_pid, mach_vm_read/write, bootstrap_look_up/register, IOKit
- `detect_shellcode_patterns`: CALL/POP PIC, FPU FSTENV GetPC, NOP sled, egg hunter, null-free candidate
- `detect_process_hollowing`: CreateProcess + ZwUnmapViewOfSection, WriteProcessMemory + SetThreadContext + ResumeThread, VirtualAllocEx, CREATE_SUSPENDED
- `detect_ntlm_relay_surface`: NTLMSSP magic, AcceptSecurityContext, NTLMv1 LM response, pass-the-hash API sequence
- `detect_exploit_socket_patterns`: reverse shell (socket+connect+dup2+execve), bind shell, raw socket, IP_HDRINCL injection, sendto-only UDP exfil, async multiplexing

**Network probes (active network I/O):**
- `probe_smb_exposure`: SMB2 negotiate, signing enforcement check (port 445/139)
- `probe_bacnet_exposure`: BACnet Who-Is, I-Am parsing, ReadProperty objectName
- `probe_ethernet_ip_exposure`: EtherNet/IP ListIdentity, CIP Read Tag service
- `probe_exposed_debug_interface`: Python debugpy/pdb, Node.js CDP inspector, Delve JSON-RPC, GDB RSP, JDWP handshake

---

## Key API

```python
from modules.syscall_trace import (
    SyscallTracer,
    detect_raw_socket_creation,
    detect_ptrace_abuse,
    detect_socket_abuse_patterns,
    check_network_sniffing_indicators,
    detect_dylib_hijacking_surface,
    detect_macos_task_port_abuse,
    detect_shellcode_patterns,
    detect_process_hollowing,
    detect_ntlm_relay_surface,
    detect_exploit_socket_patterns,
    probe_smb_exposure,
    probe_bacnet_exposure,
    probe_ethernet_ip_exposure,
    probe_exposed_debug_interface,
    detect_heap_spray_artifacts,
    detect_kernel_exploit_surface,
)

# Trace a running process
tracer = SyscallTracer(pid=1234)
stats = tracer.trace_process(duration=5)
print(tracer.report(stats))

# Binary analysis — pass raw bytes, no file I/O required
data = open('/path/to/sample.exe', 'rb').read()
findings = detect_shellcode_patterns(data)
findings += detect_process_hollowing(data)
findings += detect_ntlm_relay_surface(data)
findings += detect_exploit_socket_patterns(data, host='', port=0)

# Live system checks — return list of finding dicts
findings = detect_raw_socket_creation()
findings += detect_ptrace_abuse()
findings += detect_heap_spray_artifacts()
findings += detect_kernel_exploit_surface()
```

All probe/detect functions return `list[dict]` with keys: `severity`, `title`, `detail`, `host`, `port`.

---

## Key constants

| Constant | Value | Applied to |
|---|---|---|
| `_MAX_BINARY_BYTES` | 256 MB | Mach-O binary read cap in `detect_dylib_hijacking_surface` |
| `_MAX_PROC_BYTES` | 4 MB | All `/proc/*` file reads (status, maps, modules, cmdline, meminfo, kallsyms) |
| `_MAX_SYSCTL_BYTES` | 256 B | `/proc/sys/*` sysctl single-value reads |
| `_MAX_SYSFS_BYTES` | 64 B | `/sys/class/net/*/flags` interface flag reads |

---

## FORGE audit

Gate: **PASSED**. 9 CWE-770 fixes applied this session (unbounded procfs reads):

| Fix | Function | Old pattern | New pattern |
|---|---|---|---|
| `/proc/{p}/status` CapEff | `detect_raw_socket_creation` | `for line in f:` | `f.read(_MAX_PROC_BYTES).splitlines()` |
| `/proc/{p}/status` TracerPid/Seccomp | `detect_ptrace_abuse` | `for line in f:` | `f.read(_MAX_PROC_BYTES).splitlines()` |
| `/proc/meminfo` MemTotal | `detect_heap_spray_artifacts` | `for line in f:` | `f.read(_MAX_PROC_BYTES).splitlines()` |
| `/proc/{entry}/maps` | `detect_heap_spray_artifacts` | `for line in f:` | `f.read(_MAX_PROC_BYTES).splitlines()` |
| `/proc/{entry}/status` VmPeak | `detect_heap_spray_artifacts` | `for line in f:` | `f.read(_MAX_PROC_BYTES).splitlines()` |
| `/proc/modules` | `detect_kernel_exploit_surface` | `f.readlines()` | `f.read(_MAX_PROC_BYTES).splitlines()` |
| `/proc/kallsyms` io_uring check | `detect_kernel_exploit_surface` | `for line in f:` | `f.read(_MAX_PROC_BYTES).splitlines()` |
| `/proc/self/maps` vsyscall | `detect_kernel_exploit_surface` | `for line in f:` | `f.read(_MAX_PROC_BYTES).splitlines()` |
| `/proc/kallsyms` symbol count | `detect_kernel_exploit_surface` | `for line in f:` | `f.read(_MAX_PROC_BYTES).splitlines()` |

**Additional checks:**
- No bare `except:` — all handlers use `except Exception:`, `except (PermissionError, FileNotFoundError, OSError):`, or `except (socket.timeout, ConnectionRefusedError, OSError):`.
- No lief.parse(). No HTTP reads.
- All subprocess calls use `timeout=` parameter.
- Binary analysis functions take `bytes` parameter — no file I/O inside.
- Network probe sockets use `settimeout()` or `timeout=` in create_connection.
