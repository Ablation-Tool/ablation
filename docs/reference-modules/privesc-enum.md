# Privilege Escalation Enumeration

**File:** `modules/privesc_enum.py`

## Why this exists

Full Linux privilege escalation enumeration and binary analysis toolkit. Covers:
- SUID/SGID binaries (GTFOBins cross-reference, writable SUID, SUID in writable dir)
- World-writable cron, sudoers NOPASSWD, writable PATH / library directories
- Linux capability sets (CAP_SYS_ADMIN, CAP_SETUID, CAP_PTRACE, CAP_NET_ADMIN, file capabilities)
- Group membership, kernel parameter hardening, IPv4/IPv6 misconfiguration, firewall rules
- IPC namespace exposure (sysvipc shm/msg/sem)
- Network interface exposure (if_inet6, ARP cache, default routes, TX errors)
- Process environment scanning (credential and debug flag detection in /proc/*/environ)
- wtmp/utmp login anomalies, loaded kernel module rootkit indicators
- Container escape indicators (network namespace, proc namespace inode comparison)
- Heap injection surface (/proc/pid/maps RWX mappings, oversized heaps, spray indicators)
- Memory forensics evasion indicators (kcore, kmem, /dev/mem, crash dumps)
- Log deletion / anti-forensics patterns
- Adversary tool indicators (C2 staging files, deleted process binaries, scripting shells with sockets)
- Windows-on-Linux vectors (unquoted service paths in.reg, AlwaysInstallElevated, token manipulation, UAC bypass, kernel driver exploitation: operate on raw `bytes`)
- ASLR bypass detection (info-leak patterns, heap spray, ret2libc, mprotect-after-write)
- Scheduled task abuse (cron.d, anacrontab, systemd timers and service units)
- Cron/PATH hijacking (relative-path cron commands, world-writable PATH dirs, ld.so lib dirs, sudo env_keep PATH)
- Kernel memory exposure (kcore, kallsyms, System.map, kmem)

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

Gate: **PASSED**. 11 CWE-770 fixes applied this session (plus 3 from prior commit):

| Fix | Function | Old pattern | New pattern |
|---|---|---|---|
| sysvipc/shm | `check_ipc_namespace_exposure` | `readlines()` | `read(_MAX_FILE_BYTES).splitlines()` |
| sysvipc/msg | `check_ipc_namespace_exposure` | `readlines()` | `read(_MAX_FILE_BYTES).splitlines()` |
| sysvipc/sem | `check_ipc_namespace_exposure` | `readlines()` | `read(_MAX_FILE_BYTES).splitlines()` |
| /proc/net/if_inet6 | `check_network_interface_exposure` | `readlines()` | `read(_MAX_FILE_BYTES).splitlines()` |
| /proc/net/arp | `check_network_interface_exposure` | `readlines()` | `read(_MAX_FILE_BYTES).splitlines()` |
| /proc/net/dev | `check_network_interface_exposure` | `readlines()` | `read(_MAX_FILE_BYTES).splitlines()` |
| /proc/{pid}/maps | `check_heap_injection_surface` | `readlines()` | `read(_MAX_PROC_BYTES).splitlines()` |
| YUM.repo files | `check_package_manager_attack_surface` | `for line in fh` | `read(_MAX_FILE_BYTES).splitlines()` |
| ~/.npmrc | `check_package_manager_attack_surface` | `for line in fh` | `read(_MAX_FILE_BYTES).splitlines()` |
|.bash_history | `check_log_deletion_patterns` | `for line in fh` | `read(_MAX_FILE_BYTES).splitlines()` |
| ld.so.conf files | `detect_cron_and_path_hijacking` | `for line in fh` | `read(_MAX_FILE_BYTES).splitlines()` |

No lief.parse(). No HTTP reads. No bare `except:`. All subprocess calls timeout-bounded (3–10 s). No user-controlled data in `shell=True` paths.
