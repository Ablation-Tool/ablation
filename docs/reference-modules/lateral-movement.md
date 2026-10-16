# Lateral Movement

**File:** `modules/lateral_movement.py`

## Why this exists

Post-exploitation lateral movement: TCP connect scan, SSH credential spray, SMB/RDP pivot, credential harvesting from `/proc/pid/environ` and cmdline, and parallel host coverage. Synthesized from *Violent Python*, *Black Hat Python 2e*, and *Penetration Testing* (Weidman).

## Key constants

| Constant | Value | Applied to |
|---|---|---|
| `_MAX_PROC_BYTES` | 4 MB | `/proc/pid/environ`, `/proc/pid/cmdline`, `/proc/net/arp`, `/proc/net/route` |
| `_MAX_SYSFS_BYTES` | 64 B | sysfs counter files |
| `_MAX_LOG_BYTES` | 64 MB | auth log reads |
| `_MAX_SSH_FILE_BYTES` | 1 MB | `~/.ssh/authorized_keys` and `known_hosts` reads |

## FORGE audit

Gate: **PASSED**. No HIGH or CRITICAL findings. Four CWE-770 reads fixed this session: `/proc/net/arp` (L92) and `/proc/net/route` (L123) changed from `f.readlines()[1:]` to `f.read(_MAX_PROC_BYTES).splitlines()[1:]`; `authorized_keys` (L4924) and `known_hosts` (L4974) changed from `for line in fh:` to `fh.read(_MAX_SSH_FILE_BYTES).splitlines()`. `_MAX_SSH_FILE_BYTES=1MB` constant added. Socket banners bounded at `s.recv(256)`. No lief.parse(). No HTTP reads.
