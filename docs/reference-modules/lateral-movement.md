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

---

## How it works

Establishes a connection to the target using the specified protocol, iterates through a prioritized probe list, and records each response as a structured finding. Probes run in sequence unless `parallel=True` is set. Each probe checks for a specific weakness class: information disclosure, missing authentication, weak configuration, or exposed management interface. Findings are deduped by endpoint and finding type before returning.

---

## Usage

```python
from ablation.analyzers.lateral_movement import LateralMovement

results = LateralMovement.from_context(ctx).run()
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
- [NetworkAnalyze](network-analyze.md) — port and service fingerprinting
