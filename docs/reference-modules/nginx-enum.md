# Nginx Enumeration

**File:** `modules/nginx_enum.py`

## Why this exists

Nginx attack surface enumeration covering: server tokens / version disclosure, CVE-2017-7529 (range filter integer overflow), CVE-2021-23017 (off-by-one in resolver), alias traversal misconfigurations, stub_status / diagnostic endpoint exposure, TLS configuration (session tickets, SNI enforcement, self-signed cert, OCSP stapling), LFI/SSRF confirmation probes, Kubernetes ingress-nginx controller exposure, rate-limit bypass via spoofed headers, error log / config file leakage via alias traversal, and diagnostic endpoint disclosure (phpinfo, server-status, etc.).

## Probe functions

- `check_server_tokens(host, port)` — Server header version disclosure
- `check_cve_2021_23017(host, port)` — DNS resolver off-by-one
- `check_autoindex(host, port)` — directory listing exposure
- `check_internal_endpoint_exposure(host, port)` — internal path probing
- `probe_tls_configuration(host, port)` — TLS session tickets, SNI enforcement, self-signed cert, OCSP
- `probe_lfi_surface(host, port)` — LFI and SSRF via include/page/file parameters
- `probe_nginx_ingress_controller(host, port)` — ingress-nginx /healthz, :10254/metrics, stub_status, XFF injection
- `probe_nginx_rate_limit_bypass(host, port)` — rate-limit absence and X-Real-IP bypass
- `probe_nginx_error_log_exposure(host, port)` — alias traversal to log/config files and error body path disclosure
- `probe_nginx_diagnostic_endpoint_exposure(host, port)` — stub_status, phpinfo, server-status, error redirects

## Constructor

```python
from modules.nginx_enum import NginxEnumerator
enum = NginxEnumerator("10.0.0.1", port=443, use_tls=True)
results = enum.run()
print(enum.report())
```

## FORGE audit

Gate: **PASSED**. One low-severity CLI bug fixed (line 2282: undefined `MACSTADIUM_HOST` → `'localhost'`). All recv loops bounded: `_raw_http()` at 512 KB, SNI probe at 65536 B. All response body processing uses `body[:N]` slices. No file reads. No lief.parse().
