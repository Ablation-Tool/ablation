# Process Enumeration

**File:** `modules/process_enum.py`

## Why this exists

Full Linux process analysis and binary threat detection toolkit. Covers:
- Process enumeration via `/proc` name, cmdline, environ, maps, status, fds
- Hollow process detection TracerPid, exe/cmdline mismatch, and deleted exe
- DLL hijacking candidates writable mapped paths, LD_LIBRARY_PATH manipulation
- Cron persistence world-writable cron files, reverse-shell patterns, writable-path cron entries
- Volatile forensics timestomping, log tampering, memory artifacts
- Persistence artifacts kernel modules, systemd, /etc/ld.so.preload, cron, bash profile
- ELF analysis suspicious sections, injection artifacts, virus infection markers, packing indicators
- Ptrace instrumentation detection Valgrind, Intel PIN, ASan/TSan/UBSan in process maps
- DLL injection traces, named pipe abuse, Windows service manipulation binary bytes
- Heap spray pattern detection (HeapAlloc + large alloc + NOP sled + landing constants)
- ROP chain indicators RETN density, stack pivot gadgets, VirtualProtect chaining, and DEP bypass
- Anti-disassembly techniques constant jumps, impossible disassembly, SEH flow, self-modification
- Junk code / opaque predicates NOP sleds, dead blocks, XOR/AND/SUB predicates
- Sandbox environment indicators /proc/cpuinfo hypervisor flag, DMI strings, analysis tool processes
- Process injection surface ptrace_scope, core_pattern pipe, /dev/shm, rwx maps, LD_PRELOAD
- Bash history offensive artifacts reverse shells, privesc, data exfil, password cracking
- Writable system paths world-writable dirs/files, SUID/SGID in unusual locations

## Key constants

| Constant | Value | Applied to |
|---|---|---|
| `_MAX_PROC_BYTES` | 4 MB | `/proc/pid/maps`, `/proc/pid/environ`, `/proc/pid/cmdline`, `/proc/pid/comm` |
| `_MAX_FILE_BYTES` | 64 KB | `/proc/pid/status`, cron files, `/proc/modules`, `/proc/meminfo`, bash_history |

## Key API

```python
from modules.process_enum import (
    ProcessEnumerator,
    detect_hollow_process,
    scan_dll_hijacking_candidates,
    detect_suspicious_network_sockets,
    detect_cron_persistence,
    enumerate_volatile_forensics,
    detect_persistence_artifacts,
    detect_ptrace_instrumentation,
    detect_heap_spray_patterns,
    detect_rop_chain_indicators,
    detect_anti_disassembly_techniques,
    detect_junk_code_insertion,
    detect_sandbox_environment_indicators,
    detect_process_injection_surface,
    detect_bash_history_artifacts,
    detect_writable_system_paths,
)

# Class-based live-system scan
enum = ProcessEnumerator()
maps = enum.get_memory_maps()
print(enum.report())

# Standalone live-system checks (return list of finding dicts)
findings = detect_hollow_process(pid=1234)
findings += scan_dll_hijacking_candidates()
findings += detect_cron_persistence()
findings += detect_sandbox_environment_indicators()
findings += detect_process_injection_surface()
findings += detect_bash_history_artifacts()
findings += detect_writable_system_paths()

# Binary analysis (pass raw bytes — no file I/O)
pe_bytes = open('sample.exe', 'rb').read(64 * 1024 * 1024)
findings = detect_heap_spray_patterns(pe_bytes)
findings += detect_rop_chain_indicators(pe_bytes)
findings += detect_anti_disassembly_techniques(pe_bytes)
findings += detect_junk_code_insertion(pe_bytes)
findings += detect_ptrace_instrumentation(pe_bytes)
```

## FORGE audit

Gate: **PASSED**. 14 CWE-770 fixes applied 13 unbounded reads + 1 new constant:

| Fix | Function | Old pattern | New pattern |
|---|---|---|---|
| `/proc/{pid}/maps` | `get_memory_maps` | `for line in f:` | `f.read_MAX_PROC_BYTES.splitlines()` |
| `/proc/{pid}/status` | `detect_hollow_process` | `for line in f:` | `f.read_MAX_FILE_BYTES.splitlines()` |
| `/proc/{pid}/maps` | `scan_dll_hijacking_candidates` | `for line in f:` | `f.read_MAX_PROC_BYTES.splitlines()` |
| cron files | `detect_cron_persistence` | `enumerate(f, 1)` | `enumerate(f.read(_MAX_FILE_BYTES).splitlines(), 1)` |
| `/proc/modules` | `detect_persistence_artifacts` | `for line in f:` | `f.read_MAX_FILE_BYTES.splitlines()` |
| `/proc/{p}/status` | `detect_ptrace_instrumentation` | `for line in fh:` | `fh.read_MAX_FILE_BYTES.splitlines()` |
| `/proc/{p}/maps` (×3) | `detect_ptrace_instrumentation` | `for line in fh:` | `fh.read_MAX_PROC_BYTES.splitlines()` |
| `/proc/meminfo` | `detect_sandbox_environment_indicators` | `for line in f:` | `f.read_MAX_FILE_BYTES.splitlines()` |
| `/proc/{pid}/maps` | `detect_process_injection_surface` | `for line in f:` | `f.read_MAX_PROC_BYTES.splitlines()` |
| `/proc/{pid}/status` | `detect_process_injection_surface` | `for line in f:` | `f.read_MAX_FILE_BYTES.splitlines()` |
| bash_history | `detect_bash_history_artifacts` | `fh.readlines()` | `fh.read_MAX_FILE_BYTES.splitlines()` |
| `/proc/{pid}/status` | `enumerate_volatile_forensics` | `for line in f:` | `f.read_MAX_PROC_BYTES.splitlines()` |

No lief.parse(). No HTTP reads. No bare `except:`. All binary-analysis functions operate on passed `bytes`, no file I/O. Non-Linux paths return `_not_linux_finding()` stubs.

---

## How it works

`ProcessEnumerator()` reads `/proc/<pid>/` entries maps, status, cmdline, comm, environ, fds for all processes. All reads are bounded by `_MAX_PROC_BYTES` (4 MB) or `_MAX_FILE_BYTES` (64 KB). Standalone functions like `detect_hollow_process()`, `detect_cron_persistence()`, and `detect_process_injection_surface()` each read specific `/proc/` entries and return findings independently. Binary analysis functions `detect_heap_spray_patterns()` and `detect_rop_chain_indicators()`, and so on accept raw `bytes` with no file I/O. All findings use `_make_finding()` which returns `{severity, title, detail, host: 'localhost', port: 0}`.

---

## Usage

```python
from modules.process_enum import ProcessEnumerator, detect_hollow_process, detect_cron_persistence

# Class-based live-system scan
enum = ProcessEnumerator()
maps = enum.get_memory_maps()
print(enum.report())

# Standalone findings — [{severity, title, detail, host: 'localhost', port: 0}]
findings = detect_hollow_process(pid=1234)
findings += detect_cron_persistence()
for f in findings:
    print(f"  [{f['severity']}] {f['title']}: {f['detail'][:80]}")
```

---

## Example output

The following is a schematic example showing output structure and field names. Values are illustrative.

```
detect_hollow_process(pid=1234):
  [HIGH] HOLLOW_PROCESS: svchost.exe PID 1234 TracerPid=5678 — potential process injection

detect_cron_persistence():
  [CRITICAL] WRITABLE_CRON_FILE: /etc/cron.d/app-task is world-writable (mode 0666)
  [HIGH]     CRON_REVERSE_SHELL: /etc/cron.d/app-task line 3: bash -i >& /dev/tcp/...
```

---

## False positives

**`detect_sandbox_environment_indicators()` fires on cloud VM instances**: cloud providers use hypervisor flags in `/proc/cpuinfo` and DMI strings `Google`, `Amazon`, and `Microsoft Corporation` that match the sandbox indicator signatures. On cloud hosts this is expected and not a sandbox finding. Filter by checking whether the hypervisor DMI string matches the known cloud provider for the deployment environment.

**`detect_ptrace_instrumentation()` fires on CI/CD agents**: `Valgrind`, `AddressSanitizer`, and Intel PIN appear in process maps on testing hosts. If the host is a CI agent or developer workstation, instrumentation tool presence is expected. Confirm against the host's role before escalating.

---

## Pipeline position

Run `detect_hollow_process()` and `detect_process_injection_surface()` immediately after gaining shell access. Run binary analysis functions `detect_rop_chain_indicators()` and `detect_anti_disassembly_techniques()` during static analysis of suspected malware samples from the host.

---

## Reading findings

All standalone functions return `List[{severity, title, detail, host: 'localhost', port: 0}]`.

| Field | Content |
|:---|:---|
| `severity` | `CRITICAL` / `HIGH` / `MEDIUM` / `INFO` |
| `title` | Finding code such as `HOLLOW_PROCESS`, `WRITABLE_CRON_FILE`, and `CRON_REVERSE_SHELL` |
| `detail` | Explanation of what was found and why it matters |
| `host` | Always `'localhost'`: these are local-system findings |
| `port` | Always `0`: these are local-system findings |

---

## See also

- [Privilege Escalation Enumeration](privesc-enum.md): SUID/sudo/capability escalation on the same host
- [Volatile and Linux Artifact Triage](volatile-and-linux-artifact-triage.md): `enumerate_volatile_forensics()` combining process and forensics analysis
- [Forensics Enumeration](forensics-enum.md): Windows/ELF binary rootkit detection
