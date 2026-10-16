# Nginx Enumeration

**File:** `modules/nginx_enum.py`

## Why this exists

Nginx attack surface enumeration covering: server tokens / version disclosure, CVE-2017-7529 (range filter integer overflow), CVE-2021-23017 (off-by-one in resolver), alias traversal misconfigurations, stub_status / diagnostic endpoint exposure, TLS configuration (session tickets, SNI enforcement, self-signed cert, OCSP stapling), LFI/SSRF confirmation probes, Kubernetes ingress-nginx controller exposure, rate-limit bypass via spoofed headers, error log / config file leakage via alias traversal, and diagnostic endpoint disclosure (phpinfo, server-status, etc.).

## Probe functions

- `check_server_tokens(host, port)`: Server header version disclosure
- `check_cve_2021_23017(host, port)`: DNS resolver off-by-one
- `check_autoindex(host, port)`: directory listing exposure
- `check_internal_endpoint_exposure(host, port)`: internal path probing
- `probe_tls_configuration(host, port)`: TLS session tickets, SNI enforcement, self-signed cert, OCSP
- `probe_lfi_surface(host, port)`: LFI and SSRF via include/page/file parameters
- `probe_nginx_ingress_controller(host, port)`: ingress-nginx /healthz,:10254/metrics, stub_status, XFF injection
- `probe_nginx_rate_limit_bypass(host, port)`: rate-limit absence and X-Real-IP bypass
- `probe_nginx_error_log_exposure(host, port)`: alias traversal to log/config files and error body path disclosure
- `probe_nginx_diagnostic_endpoint_exposure(host, port)`: stub_status, phpinfo, server-status, error redirects

## Constructor

```python
from modules.nginx_enum import NginxEnumerator
enum = NginxEnumerator("10.0.0.1", port=443, use_tls=True)
results = enum.run()
print(enum.report())
```

## FORGE audit

Gate: **PASSED**. One low-severity CLI bug fixed (line 2282: undefined `MACSTADIUM_HOST` → `'localhost'`). All recv loops bounded: `_raw_http()` at 512 KB, SNI probe at 65536 B. All response body processing uses `body[:N]` slices. No file reads. No lief.parse().

---

## How it works

Establishes a connection to the target using the specified protocol, iterates through a prioritized probe list, and records each response as a structured finding. Probes run in sequence unless `parallel=True` is set. Each probe checks for a specific weakness class: information disclosure, missing authentication, weak configuration, or exposed management interface. Findings are deduped by endpoint and finding type before returning.

---

## Usage

```python
from ablation.analyzers.nginx_enum import NginxEnumeration

results = NginxEnumeration.from_context(ctx).run()
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
