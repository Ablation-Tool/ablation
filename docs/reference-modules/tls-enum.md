# TLS Enumeration

**File:** `modules/tls_enum.py`

## Why this exists

Three gaps existed before this module:

1. **Manual TLS weakness identification per target.** Checking TLS version support, weak ciphers, HSTS, HPKP, and certificate pinning required separate nmap/openssl invocations per check. This module consolidates all TLS/PKI probes into structured findings lists.

2. **Certificate chain inspection without third-party tools.** The module inspects certificate expiry, self-signed certs, weak signature algorithms (SHA-1, MD5), RSA key size, EV OID presence, hostname mismatches, SCT embedding, and wildcard scope, using Python's `ssl` module alone, no openssl binary required.

3. **Raw TLS record probing for downgrade and DPI bypass detection.** Checking FALLBACK_SCSV, GREASE acceptance, fragmented ClientHello bypass, and JA3 fingerprint discrimination requires sending raw ClientHello bytes outside the ssl module's normal validation flow.

---

## Scope

2441-line pure network I/O module. No filesystem reads. No subprocess calls. No lief usage. Covers:

- Certificate transparency checks (wildcard SANs, validity window, self-signed, CN/SAN mismatch)
- TLS inspection/DPI bypass detection (GREASE, large session ID, 0-RTT, fragmented ClientHello)
- Weak cipher suite enumeration (SSLv3/POODLE, RC4, DES/SWEET32, NULL, EXPORT/FREAK)
- Certificate pinning bypass detection (HPKP, Expect-CT, SNI-unbound cert swap, security.txt)
- mTLS enforcement probing (no client cert, 0-RTT session ticket, CertificateRequest scan, bogus SNI)
- TLS downgrade attack detection (FALLBACK_SCSV, TLS 1.0/1.1 acceptance, HSTS max-age, preload)
- ACME endpoint exposure (challenge dirs, PKI validation, private CA API, HTTP-01 liveness)
- Certificate transparency monitoring (SCT OID, recently issued, wildcard, SAN count)
- TLS session resumption and 0-RTT replay risk (ticket issued, ticket reused, TLS 1.3 path)
- Weak cipher suite probe (ssl context cipher restriction, RC4, 3DES SWEET32 classification)
- Legacy TLS version support (TLS 1.0, TLS 1.1 acceptance, TLS 1.3 detection)
- Certificate attribute and transparency exposure (RSA key size DER parsing, SHA-1/MD5 OID, EV OID, hostname mismatch)
- Certificate pinning enforcement (HPKP max-age, HSTS preload, Expect-CT, SCT count, issuer recognition)
- Zero Trust / ZTNA bypass surface (direct IP access, SPA enforcement, mTLS, JA3, CORS wildcard, bearer token in URL)
- Cloud proxy / SSL inspection bypass (TLS fingerprint, h2c upgrade, QUIC/HTTP3, CONNECT pivot, 3-fragment ClientHello)

---

## Key API

```python
from modules.tls_enum import (
    check_certificate_transparency,
    probe_tls_inspection_bypass,
    check_weak_cipher_suites,
    probe_certificate_pinning_bypass,
    probe_mtls_enforcement,
    probe_tls_downgrade_attack,
    probe_acme_endpoint_exposure,
    probe_certificate_transparency_monitor,
    probe_tls_session_resumption,
    probe_tls_weak_cipher_suite,
    probe_tls_version_support,
    probe_certificate_transparency_exposure,
    probe_certificate_pinning_enforcement,
    probe_zero_trust_bypass_surface,
    probe_cloud_proxy_ssl_inspection_bypass,
)

# Each function returns list[dict] with keys: severity, title, detail, host, port
findings = check_certificate_transparency('target.example.com', port=443, timeout=5.0)
findings += probe_tls_downgrade_attack('target.example.com', port=443)
findings += probe_zero_trust_bypass_surface('target.example.com', port=443)
```

---

## FORGE audit

Gate: **PASSED** (after 2 fixes).

| Fix | Location | Description |
|---|---|---|
| Missing `return findings` | `probe_tls_downgrade_attack` (line 836) | Function ended without returning findings: silently discarded FALLBACK_SCSV, TLS10, TLS11, HSTS findings |
| Duplicate `return findings` | `probe_certificate_transparency_monitor` (line 1085) | Unreachable dead code second return |

**Security checks:**
- No file I/O: no CWE-770 concerns.
- No `lief.parse()`: no CWE-755 concerns.
- No bare `except:`: all handlers use `except Exception:`, `except ssl.SSLError:`, `except (ssl.SSLError, OSError):`, `except urllib.error.HTTPError:`, or `except AttributeError:`.
- All socket reads bounded: `recv(4096)` for raw TLS probes, `recv(1024)` for HTTP CONNECT response, `recvfrom(4096)` for QUIC UDP probe.
- All `urllib.request.urlopen()` calls read only HTTP headers/status: no `resp.read()` on response bodies.
- `ssl.CERT_NONE` intentional: probe mode against potentially misconfigured TLS endpoints.
- All sockets use `settimeout()` or `create_connection(timeout=)`.

**Known residual:**
- `probe_cloud_proxy_ssl_inspection_bypass` sends a QUIC Long Header Initial packet to UDP/443: active out-of-band probe to a non-TCP port; may generate IDS alerts.
- `probe_zero_trust_bypass_surface` sends a JWT-shaped token as a URL query parameter: may be logged by the target as an attempted auth bypass.
- `probe_certificate_transparency_exposure` line 1079: f-string missing `f` prefix: detail text shows `{san_count}` as a literal string, not the value. Cosmetic error in finding detail, non-critical.

---

## How it works

Establishes a connection to the target using the specified protocol, iterates through a prioritized probe list, and records each response as a structured finding. Probes run in sequence unless `parallel=True` is set. Each probe checks for a specific weakness class: information disclosure, missing authentication, weak configuration, or exposed management interface. Findings are deduped by endpoint and finding type before returning.

---

## Usage

```python
from ablation.analyzers.tls_enum import TLSEnumeration

results = TLSEnumeration.from_context(ctx).run()
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
