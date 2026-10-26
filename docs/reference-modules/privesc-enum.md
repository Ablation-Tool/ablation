# Privilege Escalation Enumeration

Enumerate SUID/SGID binaries with GTFOBins cross-reference, sudo NOPASSWD policies, writable cron jobs and PATH directories, Linux capability misconfigurations, container namespace escape surfaces, kernel module rootkit indicators, and heap injection paths: providing a complete local privilege escalation picture from an unprivileged shell: via `modules/privesc_enum.py` `PrivescEnumerator`.

---

## Why this exists

1. SUID binary enumeration requires GTFOBins cross-reference to separate actionable from benign: `PrivescEnumerator.check_suid_binaries()` finds every SUID binary in standard PATH directories, but the set always includes expected system binaries `sudo`, `su`, and `ping`. Without cross-referencing against GTFOBins patterns, the finding list is unactionable noise. `PrivescEnumerator` cross-references against known-exploitable binaries and additionally checks for SUID binaries in world-writable directories and writable SUID binaries: both conditions that allow direct privilege escalation regardless of GTFOBins membership.

2. Standalone check functions cover runtime indicators that require live system access: `check_loaded_kernel_modules()` compares loaded modules against rootkit signatures (`KNOWN_ROOTKIT_MODULE_LOADED`) and flags modules loaded from non-standard paths. `check_network_namespace_escape()` compares the container's network namespace inode against PID 1's namespace to detect container escape conditions. `check_heap_injection_surface()` scans `/proc/pid/maps` for RWX segments, oversized heaps, and spray indicators. These checks cannot be run from binary analysis alone.

3. Binary analysis functions operate on raw PE/ELF bytes: `detect_token_manipulation()`, `detect_uac_bypass_indicators()`, and `detect_driver_exploitation()` take raw bytes and search for Windows privilege escalation patterns token impersonation sequences, AlwaysInstallElevated registry checks, and vulnerable driver signatures without requiring a Windows execution environment. This enables Windows binary triage from a Linux analysis host.

## Key constants

| Constant | Value | Applied to |
|---|---|---|
| `_MAX_LOG_BYTES` | 64 MB | wtmp/utmp binary log reads |
| `_MAX_FILE_BYTES` | 64 KB | procfs / config / sudoers / sysvipc / net reads |
| `_MAX_PROC_BYTES` | 4 MB | `/proc/{pid}/maps` and other large per-process files |

## Key API

```python
from modules.privesc_enum import (
    PrivescEnumerator,
    check_wtmp_utmp_anomalies,
    check_loaded_kernel_modules,
    check_network_namespace_escape,
    check_ipc_namespace_exposure,
    check_adversary_tool_indicators,
    check_scheduled_task_abuse,
    check_kernel_network_parameters,
    check_ipv6_misconfiguration,
    check_firewall_rules,
    check_network_interface_exposure,
    check_proc_kcore_access,
    check_heap_injection_surface,
    detect_memory_forensic_evasion,
    check_log_deletion_patterns,
    detect_token_manipulation,
    detect_uac_bypass_indicators,
    detect_driver_exploitation,
    detect_kernel_memory_read,
    detect_aslr_bypass_techniques,
    check_suid_binary_chain,
    detect_linux_capability_abuse,
    detect_cron_and_path_hijacking,
)

# Class-based live-system scan
enum = PrivescEnumerator()
enum.enumerate_all()
print(enum.report())

# Standalone checks (return list of finding dicts)
findings = check_loaded_kernel_modules()
findings += check_network_namespace_escape()
findings += check_heap_injection_surface()

# Binary analysis (pass raw bytes)
pe_bytes = open('sample.exe', 'rb').read(64 * 1024 * 1024)
findings = detect_token_manipulation(pe_bytes)
findings += detect_uac_bypass_indicators(pe_bytes)
findings += detect_driver_exploitation(pe_bytes)
```

## FORGE audit

Gate: **PASSED**. 11 CWE-770 fixes applied this session plus 3 from prior commit:

| Fix | Function | Old pattern | New pattern |
|---|---|---|---|
| sysvipc/shm | `check_ipc_namespace_exposure` | `readlines()` | `read_MAX_FILE_BYTES.splitlines()` |
| sysvipc/msg | `check_ipc_namespace_exposure` | `readlines()` | `read_MAX_FILE_BYTES.splitlines()` |
| sysvipc/sem | `check_ipc_namespace_exposure` | `readlines()` | `read_MAX_FILE_BYTES.splitlines()` |
| /proc/net/if_inet6 | `check_network_interface_exposure` | `readlines()` | `read_MAX_FILE_BYTES.splitlines()` |
| /proc/net/arp | `check_network_interface_exposure` | `readlines()` | `read_MAX_FILE_BYTES.splitlines()` |
| /proc/net/dev | `check_network_interface_exposure` | `readlines()` | `read_MAX_FILE_BYTES.splitlines()` |
| /proc/{pid}/maps | `check_heap_injection_surface` | `readlines()` | `read_MAX_PROC_BYTES.splitlines()` |
| YUM.repo files | `check_package_manager_attack_surface` | `for line in fh` | `read_MAX_FILE_BYTES.splitlines()` |
| ~/.npmrc | `check_package_manager_attack_surface` | `for line in fh` | `read_MAX_FILE_BYTES.splitlines()` |
|.bash_history | `check_log_deletion_patterns` | `for line in fh` | `read_MAX_FILE_BYTES.splitlines()` |
| ld.so.conf files | `detect_cron_and_path_hijacking` | `for line in fh` | `read_MAX_FILE_BYTES.splitlines()` |

No lief.parse(). No HTTP reads. No bare `except:`. All subprocess calls timeout-bounded (3–10 s). No user-controlled data in `shell=True` paths.

---

## How it works

`PrivescEnumerator.enumerate_all()` runs a suite of filesystem and system-state checks on the local host: SUID/SGID binary enumeration, sudo policy parsing, writable path and cron job scanning, Linux capability checks, package manager attack surface, and debug flag detection. Each check appends finding dicts to `self.findings` and the full list is returned. Standalone functions `check_loaded_kernel_modules()` and `check_network_namespace_escape()`, and so on are independent and return their own finding lists.

---

## Usage

```python
from modules.privesc_enum import (
    PrivescEnumerator,
    check_loaded_kernel_modules,
    check_network_namespace_escape,
    check_heap_injection_surface,
    detect_token_manipulation,
)

# Class-based scan: PrivescEnumerator.findings shape:
#   {severity, category, count, items, description, exploit}
enum = PrivescEnumerator()
findings = enum.enumerate_all()
print(enum.report())

# Standalone functions return [{severity, title, detail}]
standalone = (
    check_loaded_kernel_modules()
    + check_network_namespace_escape()
    + check_heap_injection_surface()
)
for f in standalone:
    print(f"  [{f['severity']}] {f['title']}: {f['detail'][:80]}")

# Binary analysis (pass raw bytes from PE/ELF for Windows vectors)
pe_bytes = open('sample.exe', 'rb').read(64 * 1024 * 1024)
for f in detect_token_manipulation(pe_bytes):
    print(f"  [{f['severity']}] {f['title']}")
```

---

## Example output

The following is a schematic example showing output structure and field names. Values are illustrative.

```
PrivescEnumerator.report():
  ============================================================
  PRIVILEGE ESCALATION ENUMERATION
  ============================================================
  User: www-data (UID 33)
  Total findings: 5

  [CRITICAL] Sudo Access
    Password-less sudo configured for ALL commands
    Exploit: sudo /bin/bash

  [HIGH] SUID/SGID Binaries
    4 binaries found including: /usr/bin/python3.10 /usr/bin/find
    Exploit: /usr/bin/python3.10 -c 'import os; os.execv("/bin/sh", ["sh"])'

check_loaded_kernel_modules():
  [CRITICAL] KNOWN_ROOTKIT_MODULE_LOADED  (detail: module matches known rootkit signature)
  [HIGH]     MODULE_LOADED_FROM_NONSTANDARD_PATH
```

---

## False positives

**`SUID/SGID Binaries` findings include vendor-expected SUID binaries**: the SUID check flags all SUID binaries against a GTFOBins cross-reference. Some SUID binaries are intentionally installed such as `sudo`, `su`, and `ping` and are not misconfiguration findings. Review `items` in the finding dict to identify unexpected binaries not part of the base distribution.

**`UNREFERENCED_KERNEL_MODULE` from `check_loaded_kernel_modules()`**: custom vendor drivers and out-of-tree modules VirtualBox guest additions and DKMS modules appear as `UNREFERENCED` since they are not in the reference list. Confirm against the target's installed driver list before escalating.

---

## Pipeline position

Run `PrivescEnumerator` on a live host after gaining a shell unprivileged. Run standalone checks `check_network_namespace_escape` and `check_heap_injection_surface` when operating inside a container to confirm escape vectors. For binary analysis of PE files (Windows) on a Linux host, pass the PE bytes to `detect_token_manipulation()` and `detect_driver_exploitation()`.

---

## Reading findings

**`PrivescEnumerator.findings` dict shape:**

| Field | Content |
|:---|:---|
| `severity` | `CRITICAL` / `HIGH` / `MEDIUM` / `LOW` |
| `category` | Descriptive name such as `SUID/SGID Binaries`, `Sudo Access`, and `Dangerous Capabilities` |
| `count` | Number of vulnerable items found |
| `items` | List of specific items paths, binaries, rules |
| `description` | Human-readable explanation of the finding |
| `exploit` | Suggested exploitation command present on CRITICAL/HIGH findings |

**Standalone function findings dict shape:**

| Field | Content |
|:---|:---|
| `severity` | `CRITICAL` / `HIGH` / `MEDIUM` |
| `title` | Finding code such as `KNOWN_ROOTKIT_MODULE_LOADED` and `SCCP_KEEPALIVE_RESPONSIVE` |
| `detail` | Explanation of what was found and why it matters |

---

## See also

- [FindingRegistry](registry.md): record confirmed findings from enumeration
- [LateralMovement](lateral-movement.md): chain enumeration findings into a lateral path
- [NetworkAnalyze](network-analyze.md): port and service fingerprinting
