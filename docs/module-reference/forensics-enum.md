# Forensics Enumeration

**File:** `modules/forensics_enum.py`

## Why this exists

SEH chain, SSDT hook, DPC/timer abuse, and Windows forensic artifact detection in a single module. Based on *Practical Reverse Engineering* (Dang/Gazet/Bachaalany, ch1+ch3). Covers: SEH corruption patterns (FS:0, POPAD+JMP eggscan, VEH), SSDT/kernel hook indicators, DPC and timer abuse, and Windows forensic artifacts ($MFT, LNK, Prefetch, EVTX).

## Key constants

| Constant | Value | Applied to |
|---|---|---|
| `_MAX_PROC_BYTES` | 4 MB | procfs reads |

## FORGE audit

Gate: **PASSED**. No HIGH or CRITICAL findings. All procfs reads use `f.read(_MAX_PROC_BYTES)`. MFT detection uses `os.path.getsize()` as a size probe (does not read file contents). No lief.parse(). No HTTP reads.
