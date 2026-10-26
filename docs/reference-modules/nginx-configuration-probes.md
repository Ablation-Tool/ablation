# Nginx Configuration Probes

Probe nginx and co-hosted web server configuration for security misconfigurations: covering security response headers HSTS, CSP, X-Frame-Options, TLS posture self-signed certificates, OCSP stapling, SNI enforcement, session ticket reuse, local file inclusion and path traversal, CGI/diagnostic endpoint exposure, Kubernetes ingress controller attack surface metrics, XFF header injection, rate-limit bypass, URL override, error-body information leakage, and directory listing: using standalone probe functions that operate without a persistent session object.

---

## Why this exists

1. **Security response header absence is the most common MEDIUM finding on all nginx targets, and without a dedicated header scanner, it requires manual inspection of every `curl -I` output from multiple paths.** `probe_security_headers()` checks six headers in a single `GET /` request: HSTS (`Strict-Transport-Security`), CSP (`Content-Security-Policy`), clickjacking protection (`X-Frame-Options`), MIME sniffing (`X-Content-Type-Options: nosniff`), server version disclosure (`Server` regex), and browser feature access (`Permissions-Policy`). Each absence maps to a specific severity HIGH for HSTS, MEDIUM for CSP/X-Frame-Options/MIME-sniffing, LOW for version/Permissions-Policy with an explanation of the attack path.

2. **nginx error-page bodies and proxy error responses leak upstream UNIX socket paths, internal filesystem paths, and nginx version strings, but only when triggered by specific malformed requests that exercise the error path.** `probe_nginx_error_log_exposure()` sends five malformed request types nonexistent path, null-byte URI, long path, deep traversal and inspects the body for `unix:/...` upstream socket paths UPSTREAM_UNIX_SOCKET_PATH_DISCLOSED MEDIUM, absolute filesystem paths INTERNAL_PATH_IN_ERROR_BODY LOW, and nginx version in body NGINX_VERSION_DISCLOSURE_ERROR_BODY LOW. These findings are invisible to header-only analysis.

3. **Kubernetes nginx ingress controller exposes a Prometheus metrics port at `:10254/metrics` by default: unauthenticated, without TLS, on all pod IPs including those reachable from co-tenant namespaces.** `probe_nginx_ingress_controller()` probes `:10254/metrics` for Prometheus `# HELP`/`# TYPE` output NGINX_INGRESS_METRICS_UNAUTH HIGH, `/healthz` for nginx ingress liveness exposure (MEDIUM), `/nginx-status` for stub_status (HIGH), and sends a sentinel XFF value to detect ingress header-injection relay NGINX_HEADER_INJECTION_REFLECTED HIGH. These findings are specific to ingress-nginx deployments and not covered by `NginxEnumerator`.

---

## How it works

```mermaid
flowchart TD
    A(["probe_security_headers(host, port=443, timeout=5.0):\nGET / → code, hdrs, body\nuTLS if port != 80\nCheck 6 headers:\n  HSTS absent → HIGH HSTS_ABSENT\n  CSP absent → MEDIUM CSP_ABSENT\n  X-Frame-Options absent → MEDIUM CLICKJACKING_PROTECTION_ABSENT\n  X-Content-Type-Options nosniff absent → MEDIUM MIME_SNIFFING_ENABLED\n  Server: nginx/X.Y.Z → LOW SERVER_VERSION_DISCLOSURE\n  Permissions-Policy absent → LOW PERMISSIONS_POLICY_ABSENT"]):::input
    B(["probe_tls_configuration(host, port=443, timeout=5.0):\n1. ssl.create_default_context; CERT_NONE; getpeercert()\n   issuer==subject → HIGH SELF_SIGNED_CERTIFICATE\n   cert has OCSP URLs but no staple → MEDIUM OCSP_STAPLING_ABSENT\n   save first_session\n2. Reconnect with session=first_session\n   tls_sock.session_reused=True → MEDIUM TLS_SESSION_TICKETS_ENABLED\n3. wrap_socket(sock) with NO server_hostname → no SNI in ClientHello\n   HTTP/1.0 GET / → 200 → MEDIUM SNI_NOT_REQUIRED"]):::input
    C(["probe_lfi_surface(host, port, timeout):\nURL-encoded 4-level traversal: /?page=%2e%2e%2f×4etc/passwd → 'root:' in body → CRITICAL LFI_CONFIRMED\n3-level plain traversal → same; deduplicated\n/?file=../../../../../proc/self/environ → 'HTTP_' in body → CRITICAL LFI_PROC_ENVIRON\n/?include=php://filter/convert.base64-encode/resource=index.php → ≥100 b64 chars → CRITICAL PHP_FILTER_LFI\n/?page=http://169.254.169.254/latest/meta-data/ → 'ami-id' in body → CRITICAL SSRF_TO_IMDS_VIA_LFI"]):::input
    D(["probe_cgi_exposure(host, port, timeout):\n/cgi-bin/ → 200 or 'Index of' in body → CRITICAL CGI_BIN_ACCESSIBLE\n/cgi-bin/printenv → 200 → CRITICAL CGI_PRINTENV_EXPOSED\n/cgi-bin/test-cgi → 200 → CRITICAL CGI_TEST_EXPOSED\n/server-status → 200 → HIGH APACHE_SERVER_STATUS_EXPOSED\n/server-info → 200 → HIGH APACHE_SERVER_INFO_EXPOSED"]):::input
    E(["probe_common_sensitive_paths(host, port, timeout):\n16 paths mapped to CRITICAL/HIGH/MEDIUM:\n  /.git/config → CRITICAL GIT_CONFIG_EXPOSED (non-404 = hit)\n  /.env → CRITICAL ENV_FILE_EXPOSED\n  /wp-config.php → CRITICAL WP_CONFIG_EXPOSED\n  /.htpasswd → HIGH HTPASSWD_EXPOSED\n  /admin/ → HIGH ADMIN_DIR_EXPOSED\n  /phpinfo.php → MEDIUM PHPINFO_EXPOSED"]):::input
    F(["probe_auth_bypass_patterns(host, port, timeout):\nBaseline: GET /admin/ → base_code (401 or 403)\nAdd headers: X-Forwarded-For: 127.0.0.1 → 200 → CRITICAL AUTH_BYPASS_XFF\n             X-Real-IP: 127.0.0.1 → 200 → CRITICAL AUTH_BYPASS_XREALIP\n             X-Original-URL: / → 200 → CRITICAL ORIGINAL_URL_BYPASS\nGET /admin/../admin/ → 200 → HIGH PATH_NORMALIZATION_BYPASS\nGET /ADMIN/ → 200 → MEDIUM CASE_SENSITIVITY_BYPASS"]):::input
    G(["probe_nginx_ingress_controller(host, port, timeout):\n/healthz on port and port 80 → 200 + nginx Server header → MEDIUM NGINX_INGRESS_HEALTH_EXPOSED\n:10254/metrics → 200 + '# HELP' in body → HIGH NGINX_INGRESS_METRICS_UNAUTH\n/nginx-status /stub_status → 200 + Active connections → HIGH NGINX_STATUS_EXPOSED\nGET / with X-Forwarded-For: sentinel; sentinel echoed in body or response headers → HIGH NGINX_HEADER_INJECTION_REFLECTED"]):::input
    H(["probe_nginx_rate_limit_bypass(host, port, timeout):\n20 rapid GET /api/v1/auth/login → no 429 seen → HIGH NO_RATE_LIMITING\nX-Real-IP: 127.0.0.1 on 5 requests; rate_limited was True but bypass removes 429 → CRITICAL RATE_LIMIT_BYPASS_VIA_HEADER\nGET / then GET / + X-Original-URL: /admin/config → diff body + admin markers → CRITICAL URL_OVERRIDE_HEADER_ACCEPTED\nGET login?_nc=nonce + Cache-Control: no-cache vs plain GET → diff > 50B + cache headers → MEDIUM CACHE_POISONING_SURFACE"]):::input
    I(["probe_nginx_error_log_exposure(host, port, timeout):\nAlias base×log_target traversal → GET /static/../var/log/nginx/error.log\n  200 + nginx log signatures → CRITICAL (environ/conf) or HIGH (logs)\nError trigger paths → /nonexistent, /%00invalid, /A×8000:\n  version regex in body → LOW NGINX_VERSION_DISCLOSURE_ERROR_BODY\n  unix:/... socket path → MEDIUM UPSTREAM_UNIX_SOCKET_PATH_DISCLOSED\n  /var/etc/usr path → LOW INTERNAL_PATH_IN_ERROR_BODY\nDebug paths + X-Debug-Token: 1:\n  200 + nginx config keywords → MEDIUM DEBUG_ENDPOINT_NGINX_CONFIG_LEAKAGE"]):::input
    J(["probe_nginx_diagnostic_endpoint_exposure(host, port, timeout):\n11 status paths: /basic_status, /nginx_status, /status, /server-status,\n  /nginx/status, /server/status, /_nginx_health, /stub_status,\n  /phpinfo.php, /info.php, /php-info.php\nStub_status body → MEDIUM with parsed connection count\nphpinfo() body → HIGH with PHP version\nApache mod_status → MEDIUM APACHE_SERVER_STATUS_EXPOSED\nError 301-308 to external URL → MEDIUM ERROR_PAGE_OPEN_REDIRECT\ntry_files 404 with filesystem path → LOW TRY_FILES_FILESYSTEM_PATH_IN_404"]):::input
    classDef input     fill:#0d47a1,stroke:#1565c0,color:#fff
    classDef primary   fill:#e65100,stroke:#bf360c,color:#fff
    classDef secondary fill:#004d40,stroke:#00695c,color:#fff
    classDef tertiary  fill:#4a148c,stroke:#6a1b9a,color:#fff
    classDef neutral   fill:#37474f,stroke:#546e7a,color:#fff
    classDef output    fill:#1b5e20,stroke:#2e7d32,color:#fff
```

### Standalone function summary

| Function | What it probes | Top severity |
|---|---|---|
| `probe_security_headers()` | HSTS, CSP, X-Frame-Options, MIME-sniff, Server header, Permissions-Policy | HIGH |
| `probe_tls_configuration()` | Self-signed cert, OCSP stapling, SNI enforcement, session ticket reuse | HIGH |
| `probe_lfi_surface()` | LFI via page/file/include params, PHP filter chain, SSRF to AWS IMDS | CRITICAL |
| `probe_cgi_exposure()` | CGI-bin directory, printenv, test-cgi, Apache mod_status/mod_info | CRITICAL |
| `probe_common_sensitive_paths()` | .git/config, .env, wp-config.php, .htpasswd, /admin/, phpinfo.php | CRITICAL |
| `probe_auth_bypass_patterns()` | XFF/X-Real-IP auth bypass, X-Original-URL, path normalisation, case bypass | CRITICAL |
| `probe_nginx_ingress_controller()` | /healthz, :10254/metrics, stub_status, XFF header injection relay | HIGH |
| `probe_nginx_rate_limit_bypass()` | Rate-limit absence, XFF rate-limit bypass, URL override, cache poisoning | CRITICAL |
| `probe_nginx_error_log_exposure()` | Alias traversal to log files, error-body version/socket/path leakage | CRITICAL |
| `probe_nginx_diagnostic_endpoint_exposure()` | All stub_status variants, phpinfo, error_page open redirect, try_files path | HIGH |

---

## Usage

```python
from modules.nginx_enum import (
    probe_security_headers,
    probe_tls_configuration,
    probe_lfi_surface,
    probe_cgi_exposure,
    probe_common_sensitive_paths,
    probe_auth_bypass_patterns,
    probe_nginx_ingress_controller,
    probe_nginx_rate_limit_bypass,
    probe_nginx_error_log_exposure,
    probe_nginx_diagnostic_endpoint_exposure,
    probe_web_framework_disclosure,
    probe_directory_listing,
)

HOST = '192.168.1.100'
PORT = 443

# Security response headers
hdr_findings = probe_security_headers(HOST, PORT)
for f in hdr_findings:
    print(f"[{f['severity']}] {f['title']}: {f['detail'][:80]}")

# TLS configuration
tls_findings = probe_tls_configuration(HOST, PORT)
for f in tls_findings:
    print(f"[{f['severity']}] {f['title']}: {f['detail'][:80]}")

# LFI surface
lfi = probe_lfi_surface(HOST, PORT)
if lfi:
    print(f"\n[!] LFI confirmed: {lfi[0]['title']}")
    print(f"    {lfi[0]['detail'][:120]}")

# CGI exposure (check before auth bypass — /cgi-bin/ is pre-auth)
cgi = probe_cgi_exposure(HOST, PORT)
for f in cgi:
    if f['severity'] == 'CRITICAL':
        print(f"[CRITICAL] {f['title']}: {f['detail'][:80]}")

# Auth bypass
auth_bypass = probe_auth_bypass_patterns(HOST, PORT)
for f in auth_bypass:
    print(f"[{f['severity']}] {f['title']}: {f['detail']}")

# Kubernetes ingress (probe from inside cluster or from external if NodePort exposed)
k8s = probe_nginx_ingress_controller(HOST, PORT)
for f in k8s:
    print(f"[{f['severity']}] {f['title']}: {f['detail'][:100]}")

# Rate-limit bypass (runs 20 requests to login endpoint — takes ~30s at default timeout)
rl = probe_nginx_rate_limit_bypass(HOST, PORT)
for f in rl:
    print(f"[{f['severity']}] {f['title']}")

# Error log and path traversal via alias misconfig
err_log = probe_nginx_error_log_exposure(HOST, PORT)
for f in err_log:
    print(f"[{f['severity']}] {f['title']}: {f['detail'][:100]}")

# All diagnostic endpoint variants
diag = probe_nginx_diagnostic_endpoint_exposure(HOST, PORT)
for f in diag:
    print(f"[{f['severity']}] {f['title']}: {f['detail'][:80]}")
```

---

## Example output

```
probe_security_headers():
[HIGH]   HSTS_ABSENT: Strict-Transport-Security header missing — MITM downgrade risk
[MEDIUM] CSP_ABSENT: Content-Security-Policy header missing — no script source allowlist
[MEDIUM] CLICKJACKING_PROTECTION_ABSENT: X-Frame-Options header missing
[LOW]    SERVER_VERSION_DISCLOSURE: Server header reveals product and version: "nginx/1.18.0"

probe_tls_configuration():
[HIGH]   SELF_SIGNED_CERTIFICATE: Certificate issuer equals subject — {'commonName': '192.168.1.100'}
[MEDIUM] TLS_SESSION_TICKETS_ENABLED: TLS session ticket accepted and reused on reconnect

probe_auth_bypass_patterns():
[CRITICAL] AUTH_BYPASS_XFF: baseline=403; bypass headers={'X-Forwarded-For': '127.0.0.1'} -> 200

probe_nginx_ingress_controller():
[HIGH] NGINX_INGRESS_METRICS_UNAUTH: Nginx ingress controller Prometheus metrics (:10254/metrics)
       accessible without authentication — exposes request rates, upstream latency...
[HIGH] NGINX_HEADER_INJECTION_REFLECTED: X-Forwarded-For value 'ngx-probe-XFF-7f1a' echoed
       in response body — ingress forwards raw client-controlled XFF to backend

probe_nginx_error_log_exposure():
[HIGH] NGINX_ERROR_LOG_VIA_ALIAS: GET /static/../var/log/nginx/error.log returned HTTP 200
       with log content — alias misconfig at '/static/'; body: '[error] 2026/10/14...'
[MEDIUM] UPSTREAM_UNIX_SOCKET_PATH_DISCLOSED: HTTP 502 body contains unix:/run/app.sock
```

---

## False positives

**`probe_nginx_rate_limit_bypass()` makes 20 sequential requests to `/api/v1/auth/login`: the endpoint may not exist on the target.** If the path returns 404 for all 20 requests, `valid_codes` will contain only 404s and `rate_limited` will be False. The result is `NO_RATE_LIMITING HIGH` for a 404 path: the rate-limiting is correctly absent because the path does not exist. Check `valid_codes` in the `detail` field before escalating: `codes observed: {404}` indicates the path was not found; `codes observed: {200, 201}` confirms the path is live.

**`probe_tls_configuration()` reports `OCSP_STAPLING_ABSENT` whenever the certificate has an OCSP URL, but nginx's `ssl_stapling on` requires an upstream CA reachable from the server.** The probe detects whether the cert advertises an OCSP responder and assumes stapling is absent if the Python stdlib does not detect a stapled response. However, Python's `ssl` module does not expose whether the server included a stapled OCSP response in the TLS handshake, it only reports whether the cert has OCSP URLs. This finding is always reported when the cert is CA-issued. Treat as informational and verify with `openssl s_client -connect host:port -status` which does show the OCSP response.

**`probe_nginx_ingress_controller()` port `10254` may be reachable only from within the Kubernetes cluster.** The metrics scrape port is bound to the pod IP, not the service IP. If the probe runs from outside the cluster, the TCP connection to `:10254` times out and `code == 0`, producing no finding. Run the probe from a pod within the cluster or from a host with access to the cluster pod CIDR to get accurate results.

---

## Pipeline position

**Before this module:** Run `probe_security_headers()` first, it makes one GET request and provides baseline severity. Run `probe_common_sensitive_paths()` second: `.git/config`, `.env`, and `wp-config.php` exposure is the highest-impact finding and takes <5 seconds. Save `probe_nginx_rate_limit_bypass()` for last: it makes 25+ HTTP requests and takes ~30 seconds at the default 5.0s timeout.

**After this module:** For `LFI_CONFIRMED CRITICAL`: extract `/etc/passwd`, `/etc/nginx/nginx.conf`, and `/proc/self/environ` to identify users, nginx config alias locations, proxy_pass upstreams, auth directives, and runtime environment variables. For `NGINX_INGRESS_METRICS_UNAUTH HIGH`: parse the Prometheus metrics response to extract per-ingress throughput, upstream latency buckets, and backend connection counts for network mapping. For `RATE_LIMIT_BYPASS_VIA_HEADER CRITICAL`: chain with `probe_auth_bypass_patterns()` XFF bypass to confirm unlimited brute-force capability against the auth endpoint.

---

## Reading findings

| Field | Content |
|:---|:---|
| `f['severity']` | CRITICAL / HIGH / MEDIUM / LOW / INFO |
| `f['title']` | Finding type constant: `HSTS_ABSENT`, `SELF_SIGNED_CERTIFICATE`, `LFI_CONFIRMED`, `RATE_LIMIT_BYPASS_VIA_HEADER`, etc. |
| `f['detail']` | Evidence: body excerpt with markers, parsed header values, or attack-path explanation |
| `f['host']` | Target hostname as passed to the probe function |
| `f['port']` | Target port number |

---

## See also

- [Nginx Fingerprinting and Exposure](nginx-fingerprinting-and-exposure.md): version detection, CVE assessment, stub_status, NX-API enumeration, alias traversal, and HTTP smuggling via `NginxEnumerator`
- [Business Logic and Version Exposure](business-logic-and-version-exposure.md): web framework detection and version disclosure beyond nginx
