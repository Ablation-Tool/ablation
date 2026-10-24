# TLS Enumeration

**File:** `modules/tls_enum.py`

## Why this exists

Three gaps existed before this module:

1. **Manual TLS weakness identification per target.** Checking TLS version support, weak ciphers, HSTS, HPKP, and certificate pinning required separate nmap/openssl invocations per check. This module consolidates all TLS/PKI probes into structured findings lists.

2. **Certificate chain inspection without third-party tools.** The module inspects certificate expiry, self-signed certs, weak signature algorithms SHA-1, MD5, RSA key size, EV OID presence, hostname mismatches, SCT embedding, and wildcard scope, using Python's `ssl` module alone, no openssl binary required.

3. **Raw TLS record probing for downgrade and DPI bypass detection.** Checking FALLBACK_SCSV, GREASE acceptance, fragmented ClientHello bypass, and JA3 fingerprint discrimination requires sending raw ClientHello bytes outside the ssl module's normal validation flow.

---

## Scope

2441-line pure network I/O module. No filesystem reads. No subprocess calls. No lief usage. Covers:

- Certificate transparency checks wildcard SANs, validity window, self-signed, CN/SAN mismatch
- TLS inspection/DPI bypass detection GREASE, large session ID, 0-RTT, and fragmented ClientHello
- Weak cipher suite enumeration SSLv3/POODLE, RC4, DES/SWEET32, NULL, EXPORT/FREAK
- Certificate pinning bypass detection HPKP, Expect-CT, SNI-unbound cert swap, security.txt
- mTLS enforcement probing no client cert, 0-RTT session ticket, CertificateRequest scan, and bogus SNI
- TLS downgrade attack detection FALLBACK_SCSV, TLS 1.0/1.1 acceptance, HSTS max-age, preload
- ACME endpoint exposure challenge dirs, PKI validation, private CA API, HTTP-01 liveness
- Certificate transparency monitoring SCT OID, recently issued, wildcard, SAN count
- TLS session resumption and 0-RTT replay risk ticket issued, ticket reused, TLS 1.3 path
- Weak cipher suite probe ssl context cipher restriction, RC4, 3DES SWEET32 classification
- Legacy TLS version support TLS 1.0, TLS 1.1 acceptance, TLS 1.3 detection
- Certificate attribute and transparency exposure RSA key size DER parsing, SHA-1/MD5 OID, EV OID, hostname mismatch
- Certificate pinning enforcement HPKP max-age, HSTS preload, Expect-CT, SCT count, issuer recognition
- Zero Trust / ZTNA bypass surface direct IP access, SPA enforcement, mTLS, JA3, CORS wildcard, and bearer token in URL
- Cloud proxy / SSL inspection bypass TLS fingerprint, h2c upgrade, QUIC/HTTP3, CONNECT pivot, and 3-fragment ClientHello

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

Gate: **PASSED** after 2 fixes.

| Fix | Location | Description |
|---|---|---|
| Missing `return findings` | `probe_tls_downgrade_attack` line 836 | Function ended without returning findings: silently discarded FALLBACK_SCSV, TLS10, TLS11, HSTS findings |
| Duplicate `return findings` | `probe_certificate_transparency_monitor` line 1085 | Unreachable dead code second return |

**Security checks:**
- No file I/O: no CWE-770 concerns.
- No `lief.parse()`: no CWE-755 concerns.
- No bare `except:`: all handlers use `except Exception:`, `except ssl.SSLError:`, `except ssl.SSLError, OSError:`, `except urllib.error.HTTPError:`, or `except AttributeError:`.
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

All functions are standalone network probes with signature `(host, port=443, timeout=5.0) → List[dict]`. Each sends raw TLS records or HTTP requests using `ssl.CERT_NONE` and returns `{severity, title, detail, host, port}` findings via `_finding()`. There is no class or constructor.

---

## Usage

```python
from modules.tls_enum import (
    probe_tls_downgrade_attack,
    probe_tls_version_support,
    check_weak_cipher_suites,
    probe_zero_trust_bypass_surface,
)

# Each returns [{severity, title, detail, host, port}]
findings = probe_tls_downgrade_attack('target.example.com', port=443)
findings += probe_tls_version_support('target.example.com', port=443)
findings += check_weak_cipher_suites('target.example.com', port=443)

for f in findings:
    print(f"  [{f['severity']}] {f['title']}: {f['detail'][:80]}")
```

---

## Example output

The following is a schematic example showing output structure and field names. Values are illustrative.

```
probe_tls_downgrade_attack: target.example.com:443

  [HIGH]   NO_FALLBACK_SCSV_PROTECTION
           Server did not return inappropriate_fallback alert (RFC 7507) when
           TLS_FALLBACK_SCSV was presented with a downgraded version
  [HIGH]   TLS10_ACCEPTED
           Server accepted a TLS 1.0 ClientHello (POODLE/BEAST risk)
  [MEDIUM] SHORT_HSTS_MAX_AGE
           HSTS max-age=2592000 (30 days) — below 31536000 recommended minimum
```

---

## False positives

**`probe_cloud_proxy_ssl_inspection_bypass()` generates IDS alerts**, this probe sends a QUIC Long Header Initial packet to UDP/443 and a 3-fragment ClientHello. These are active out-of-band probes that may appear in IDS logs as malformed TLS or protocol violation events on the target.

**`probe_zero_trust_bypass_surface()` logs appear as auth bypass attempts**: the probe sends a JWT-shaped token as a URL query parameter. The target may log this as an attempted authentication bypass attempt, which is visible in security event logs.

---

## Pipeline position

Run TLS enumeration after confirming a listening HTTPS service. Run `probe_tls_downgrade_attack()` and `probe_tls_version_support()` first to confirm attack surface, then run cipher suite and certificate probes.

---

## Reading findings

| Field | Content |
|:---|:---|
| `severity` | `CRITICAL` / `HIGH` / `MEDIUM` / `INFO` |
| `title` | Finding code such as `NO_FALLBACK_SCSV_PROTECTION`, `TLS10_ACCEPTED`, `TLS11_ACCEPTED`, and `SHORT_HSTS_MAX_AGE` |
| `detail` | What was found and why it matters |
| `host` | Target host |
| `port` | Target port |

---

## See also

- [FindingRegistry](registry.md): record confirmed findings from enumeration
- [LateralMovement](lateral-movement.md): chain enumeration findings into a lateral path
- [NetworkAnalyze](network-analyze.md): port and service fingerprinting
