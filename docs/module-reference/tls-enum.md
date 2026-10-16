# TLS Enumeration

**File:** `modules/tls_enum.py`

## Why this exists

Three gaps existed before this module:

1. **Manual TLS weakness identification per target.** Checking TLS version support, weak ciphers, HSTS, HPKP, and certificate pinning required a separate nmap scan or openssl invocation per check. TLS enum consolidates all of these into a single findings list returned from one function call.

2. **Certificate chain inspection not available without third-party tools.** The module inspects certificate expiry, self-signed certificates, weak signature algorithms (SHA1, MD5), and hostname mismatches using Python's `ssl` module alone — no openssl binary or external dependency required.

3. **Raw TLS record probing needed for version downgrade checks.** Checking for SSL 2.0/3.0 support requires sending raw ClientHello bytes outside the ssl module's normal validation. `_build_clienthello()` and `_send_raw_clienthello()` handle this cleanly.

## Key functions

| Function | Description |
|---|---|
| `enumerate_tls(host, port)` | Full TLS surface: versions, ciphers, cert, HSTS, HPKP |
| `check_certificate_chain(host, port)` | Cert expiry, self-signed, SHA1/MD5, hostname |
| `check_hsts_policy(host, port)` | HSTS max-age, includeSubDomains, preload |
| `check_hpkp_policy(host, port)` | HPKP header presence, max-age, pin-sha256 |
| `check_downgrade_resistance(host, port)` | SSLv2/3 probes, TLS_FALLBACK_SCSV |
| `check_weak_ciphers(host, port)` | Enumerate NULL, RC4, EXPORT, DES cipher support |

## FORGE audit

Gate: **PASSED**. No HIGH or CRITICAL findings.

- All socket reads are bounded: `recv(4096)` for raw TLS responses, `recv(1024)` for HTTP upgrade responses.
- All `urllib.request.urlopen()` calls read only HTTP headers/status — no `resp.read()` on response bodies.
- No file reads. No lief.parse(). No subprocess.
