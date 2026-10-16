# Forensics Enumeration

**File:** `modules/forensics_enum.py`

## Why this exists

SEH chain, SSDT hook, DPC/timer abuse, and Windows forensic artifact detection in a single module. Based on *Practical Reverse Engineering* (Dang/Gazet/Bachaalany, ch1+ch3). Covers: SEH corruption patterns (FS:0, POPAD+JMP eggscan, VEH), SSDT/kernel hook indicators, DPC and timer abuse, and Windows forensic artifacts ($MFT, LNK, Prefetch, EVTX).

## Key constants

| Constant | Value | Applied to |
|---|---|---|
| `_MAX_PROC_BYTES` | 4 MB | procfs reads (`/proc/{pid}/maps`) |
| `_MAX_WALK_DEPTH` | 8 | `os.walk()` recursion depth in `detect_windows_forensic_artifacts()` |

## FORGE audit

Gate: **PASSED**. No HIGH or CRITICAL findings. All procfs reads use `f.read(_MAX_PROC_BYTES).splitlines()`: three `/proc/{pid}/maps` reads (lines 3639, 3711, 3753 — anonymous rwx mmap, /dev/shm exec region, interpreter injection detection). MFT detection uses `os.path.getsize()` as a size probe (does not read file contents). `os.walk()` depth capped at `_MAX_WALK_DEPTH=8` via `dirnames.clear()`. No lief.parse(). No HTTP reads.
