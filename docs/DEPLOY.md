# Ablation - Deployment Guide

## Quick Deploy

```bash
# 1. Build standalone executable
./build.sh

# 2. Copy to target
scp dist/ablation target:/tmp/re

# 3. Execute on target
ssh target '/tmp/re'
```

## Capabilities

**Platform Detection:**
- OS, kernel, architecture identification
- Security feature detection (ASLR, SELinux, AppArmor)
- Available tools enumeration

**Process Analysis:**
- Running process enumeration
- Memory map analysis
- Loaded module detection
- Open file descriptor tracking
- Environment variable extraction

**Binary Analysis:**
- Multi-format parsing (ELF, PE, Mach-O)
- Disassembly (x86/x64, ARM, MIPS)
- Entry point location
- Section enumeration

**Vulnerability Hunting:**
- ASLR status check
- ptrace restriction analysis
- SUID binary detection
- Writable+executable memory regions

## Output

- JSON report: `/tmp/ablation-report.json`
- Text summary: `/tmp/ablation-summary.txt`

## Modes

```bash
# Full autonomous analysis
./ablation

# Quick platform fingerprint
./ablation --quick

# Analyze specific process
./ablation --process <PID>

# Analyze specific binary
./ablation --binary <FILE>
```

## Self-Contained

The executable is completely self-contained:
- No Python runtime required on target
- All dependencies embedded
- Single ~15MB binary
- Works on any Linux x64 system

## Stealth Notes

- Reads only from /proc (no disk writes except final report)
- No network connections
- Minimal syscall footprint
- Can run from memory (copy to /dev/shm)

```bash
# Memory-only execution
cp ablation /dev/shm/re
/dev/shm/re
rm /dev/shm/re
```
