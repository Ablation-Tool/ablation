# Docker / Container Enumeration

**File:** `modules/docker_enum.py`

## Why this exists

Docker API and container attack surface enumeration: exposed Docker sockets, container escape opportunities, privileged containers, mounted host paths, and credential material in environment variables.

## Key constants

| Constant | Value | Applied to |
|---|---|---|
| `_MAX_HTTP_BYTES` | 4 MB | Docker API HTTP response body |
| `_MAX_FILE_BYTES` | 64 KB | `/proc/1/cgroup` and procfs reads |

## FORGE audit

Gate: **PASSED**. No HIGH or CRITICAL findings. All HTTP reads use `resp.read(_MAX_HTTP_BYTES)`. Five procfs reads all capped with `f.read(_MAX_FILE_BYTES)` or `f.read(_MAX_FILE_BYTES).splitlines()`: `/proc/1/cgroup` (L112, L366), `/proc/self/status` in `check_privileged()` (L270) and `get_capabilities()` (L297), `/proc/self/mountinfo` in `get_mounts()` (L311). No lief.parse().

---

## How it works

Establishes a connection to the target using the specified protocol, iterates through a prioritized probe list, and records each response as a structured finding. Probes run in sequence unless `parallel=True` is set. Each probe checks for a specific weakness class: information disclosure, missing authentication, weak configuration, or exposed management interface. Findings are deduped by endpoint and finding type before returning.

---

## Usage

```python
from ablation.analyzers.docker_enum import DockerContainerEnumeration

results = DockerContainerEnumeration.from_context(ctx).run()
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
