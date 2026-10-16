# Lateral Movement

**File:** `modules/lateral_movement.py`

## Why this exists

Post-exploitation lateral movement: TCP connect scan, SSH credential spray, SMB/RDP pivot, credential harvesting from `/proc/pid/environ` and cmdline, and parallel host coverage. Synthesized from *Violent Python*, *Black Hat Python 2e*, and *Penetration Testing* (Weidman).

## Key constants

| Constant | Value | Applied to |
|---|---|---|
| `_MAX_PROC_BYTES` | 4 MB | `/proc/pid/environ`, `/proc/pid/cmdline` |
| `_MAX_SYSFS_BYTES` | 64 B | sysfs counter files |

## FORGE audit

Gate: **PASSED**. No HIGH or CRITICAL findings. All `/proc/pid/*` reads use `f.read(_MAX_PROC_BYTES)`. Socket banners bounded at `s.recv(256)`. No file reads beyond procfs. No lief.parse(). No HTTP reads.
