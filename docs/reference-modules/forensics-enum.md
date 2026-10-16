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

Gate: **PASSED**. No HIGH or CRITICAL findings. All procfs reads use `f.read(_MAX_PROC_BYTES).splitlines()`: three `/proc/{pid}/maps` reads (lines 3639, 3711, 3753, anonymous rwx mmap, /dev/shm exec region, interpreter injection detection). MFT detection uses `os.path.getsize()` as a size probe (does not read file contents). `os.walk()` depth capped at `_MAX_WALK_DEPTH=8` via `dirnames.clear()`. No lief.parse(). No HTTP reads.

---

## How it works

Establishes a connection to the target using the specified protocol, iterates through a prioritized probe list, and records each response as a structured finding. Probes run in sequence unless `parallel=True` is set. Each probe checks for a specific weakness class: information disclosure, missing authentication, weak configuration, or exposed management interface. Findings are deduped by endpoint and finding type before returning.

---

## Usage

```python
from ablation.analyzers.forensics_enum import ForensicsEnumeration

results = ForensicsEnumeration.from_context(ctx).run()
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
