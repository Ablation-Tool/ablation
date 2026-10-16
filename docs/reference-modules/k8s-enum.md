# Kubernetes Enumeration

**File:** `modules/k8s_enum.py`

## Why this exists

Kubernetes attack surface enumeration: exposed API server endpoints, RBAC misconfigurations, privileged pod detection, hostPath volume mounts, service account token exposure, and kubelet read-only port (10255) checks.

## Key constants

| Constant | Value | Applied to |
|---|---|---|
| `_MAX_FILE_BYTES` | 64 KB | procfs / kubepods cgroup file reads |

## FORGE audit

Gate: **PASSED**. No HIGH or CRITICAL findings. All procfs reads use `f.read(_MAX_FILE_BYTES).splitlines()` including `_check_privileged_caps()` `/proc/self/status` (L2801, fixed this session). HTTP/API responses use inline `resp.read(4 * 1024 * 1024)` cap (4 MB). All kubectl subprocess calls have `timeout=` on continuation lines. No lief.parse().

---

## How it works

Establishes a connection to the target using the specified protocol, iterates through a prioritized probe list, and records each response as a structured finding. Probes run in sequence unless `parallel=True` is set. Each probe checks for a specific weakness class: information disclosure, missing authentication, weak configuration, or exposed management interface. Findings are deduped by endpoint and finding type before returning.

---

## Usage

```python
from ablation.analyzers.k8s_enum import KubernetesEnumeration

results = KubernetesEnumeration.from_context(ctx).run()
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
