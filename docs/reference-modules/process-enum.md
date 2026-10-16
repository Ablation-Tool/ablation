# Process Enumeration

**File:** `modules/process_enum.py`

## Why this exists

Full Linux process analysis and binary threat detection toolkit. Covers:
- Process enumeration via `/proc` (name, cmdline, environ, maps, status, fds)
- Hollow process detection (TracerPid, exe/cmdline mismatch, deleted exe)
- DLL hijacking candidates (writable mapped paths, LD_LIBRARY_PATH manipulation)
- Cron persistence (world-writable cron files, reverse-shell patterns, writable-path cron entries)
- Volatile forensics (timestomping, log tampering, memory artifacts)
- Persistence artifacts (kernel modules, systemd, /etc/ld.so.preload, cron, bash profile)
- ELF analysis (suspicious sections, injection artifacts, virus infection markers, packing indicators)
- Ptrace instrumentation detection (Valgrind, Intel PIN, ASan/TSan/UBSan in process maps)
- DLL injection traces, named pipe abuse, Windows service manipulation (binary bytes)
- Heap spray pattern detection (HeapAlloc + large alloc + NOP sled + landing constants)
- ROP chain indicators (RETN density, stack pivot gadgets, VirtualProtect chaining, DEP bypass)
- Anti-disassembly techniques (constant jumps, impossible disassembly, SEH flow, self-modification)
- Junk code / opaque predicates (NOP sleds, dead blocks, XOR/AND/SUB predicates)
- Sandbox environment indicators (/proc/cpuinfo hypervisor flag, DMI strings, analysis tool processes)
- Process injection surface (ptrace_scope, core_pattern pipe, /dev/shm, rwx maps, LD_PRELOAD)
- Bash history offensive artifacts (reverse shells, privesc, data exfil, password cracking)
- Writable system paths (world-writable dirs/files, SUID/SGID in unusual locations)

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

Gate: **PASSED**. 14 CWE-770 fixes applied (13 unbounded reads + 1 new constant):

| Fix | Function | Old pattern | New pattern |
|---|---|---|---|
| `/proc/{pid}/maps` | `get_memory_maps` | `for line in f:` | `f.read(_MAX_PROC_BYTES).splitlines()` |
| `/proc/{pid}/status` | `detect_hollow_process` | `for line in f:` | `f.read(_MAX_FILE_BYTES).splitlines()` |
| `/proc/{pid}/maps` | `scan_dll_hijacking_candidates` | `for line in f:` | `f.read(_MAX_PROC_BYTES).splitlines()` |
| cron files | `detect_cron_persistence` | `enumerate(f, 1)` | `enumerate(f.read(_MAX_FILE_BYTES).splitlines(), 1)` |
| `/proc/modules` | `detect_persistence_artifacts` | `for line in f:` | `f.read(_MAX_FILE_BYTES).splitlines()` |
| `/proc/{p}/status` | `detect_ptrace_instrumentation` | `for line in fh:` | `fh.read(_MAX_FILE_BYTES).splitlines()` |
| `/proc/{p}/maps` (×3) | `detect_ptrace_instrumentation` | `for line in fh:` | `fh.read(_MAX_PROC_BYTES).splitlines()` |
| `/proc/meminfo` | `detect_sandbox_environment_indicators` | `for line in f:` | `f.read(_MAX_FILE_BYTES).splitlines()` |
| `/proc/{pid}/maps` | `detect_process_injection_surface` | `for line in f:` | `f.read(_MAX_PROC_BYTES).splitlines()` |
| `/proc/{pid}/status` | `detect_process_injection_surface` | `for line in f:` | `f.read(_MAX_FILE_BYTES).splitlines()` |
| bash_history | `detect_bash_history_artifacts` | `fh.readlines()` | `fh.read(_MAX_FILE_BYTES).splitlines()` |
| `/proc/{pid}/status` | `enumerate_volatile_forensics` | `for line in f:` | `f.read(_MAX_PROC_BYTES).splitlines()` |

No lief.parse(). No HTTP reads. No bare `except:`. All binary-analysis functions operate on passed `bytes`, no file I/O. Non-Linux paths return `_not_linux_finding()` stubs.

---

## How it works

Establishes a connection to the target using the specified protocol, iterates through a prioritized probe list, and records each response as a structured finding. Probes run in sequence unless `parallel=True` is set. Each probe checks for a specific weakness class: information disclosure, missing authentication, weak configuration, or exposed management interface. Findings are deduped by endpoint and finding type before returning.

---

## Usage

```python
from ablation.analyzers.process_enum import ProcessEnumeration

results = ProcessEnumeration.from_context(ctx).run()
for r in results:
    print(r)
```

---

## Example output

```
[HIGH]     UNAUTH_ACCESS     /api/v1/config/backup
  detail: unauthenticated GET returns full config including credentials
  evidence: HTTP 200, Content-Type: application/json, body: {"admin_pass": ...}

[MEDIUM]   INFO_DISCLOSURE   /status
  detail: version string exposed without authentication
  evidence: X-Version: FortiOS 7.2.1 build 1254
```

---

## False positives

Findings from internal management interfaces, development endpoints, and lab-only services are not real attack surface. Filter by comparing discovered endpoints against the product's documented management plane. Authentication-required findings are lower severity unless a pre-auth bypass is confirmed separately.

---

## Pipeline position

**Before this module:** Network reachability confirmation and credential acquisition. `BinaryContext` is not required; this module works from a live target or captured traffic.

**After this module:** Feed findings to `FindingRegistry.register()` and review with `LLMAnalyst` for chaining opportunities.

---

## Reading findings

| Field | Content |
|:---|:---|
| `severity` | `CRITICAL` / `HIGH` / `MEDIUM` / `INFO` |
| `finding_type` | Category (e.g., `UNAUTH_ACCESS`, `INFO_DISCLOSURE`, `WEAK_CONFIG`) |
| `endpoint` | URI, port, or service address where the finding was observed |
| `detail` | What was found and why it matters |
| `evidence` | Response excerpt or protocol trace that confirms the finding |

---

## See also

- [FindingRegistry](registry.md) — record confirmed findings from enumeration
- [LateralMovement](lateral-movement.md) — chain enumeration findings into a lateral path
- [NetworkAnalyze](network-analyze.md) — port and service fingerprinting
