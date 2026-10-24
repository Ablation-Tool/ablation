# crypto_audit

## Why this module exists

Four gaps motivated this module:

1. No Ablation tool detected JWT weaknesses on a live host. JWT analysis requires HMAC verification against a candidate secret list, which binary analysis cannot perform.
2. SAML assertion forgery and XML Signature Wrapping require XML parsing and structural analysis. No existing module covered them.
3. TLS and key material weaknesses such as deprecated protocols, weak ciphers, and readable private keys require live network connections and filesystem walks that binary-only modules cannot perform.
4. A large class of cryptographic anti-patterns in firmware binaries such as XOR-based C2 encoding, RC4 usage, GCM nonce reuse, and weak prime generation needed a dedicated analysis surface distinct from the taint and sink-classification chain.

## CryptoAudit

Orchestrates JWT discovery and analysis, SAML assertion inspection, key material scanning, and TLS endpoint analysis on a live host.

```python
from modules.crypto_audit import CryptoAudit

auditor = CryptoAudit()
results = auditor.audit(targets=["10.0.0.1:443", "10.0.0.2"])
print(auditor.report())
```

`targets` is a list of host strings for TLS analysis. Omit for local-only analysis.

### analyze_jwt

Decodes a JWT, checks the algorithm, tests for alg:none, tests the empty string secret, and iterates through known-weak secrets. Returns a dict with header, payload, alg, vulns list, and forged_token.

```python
result = auditor.analyze_jwt(token_string)
if result["forged_token"]:
    print(result["forged_token"])
```

Supported algorithms: HS256 and alg:none. RS256 tokens are flagged for manual algorithm confusion testing but not automatically exploited.

### scan_for_jwts

Walks provided filesystem paths and scans `/proc/pid/environ` for JWT-shaped strings. Returns a list of dicts, each with token and source fields.

```python
found = auditor.scan_for_jwts(["/etc", "/opt", "/home"])
for entry in found:
    analysis = auditor.analyze_jwt(entry["token"])
```

Files larger than 5 MB are skipped. Directory traversal is capped at depth 6.

### analyze_saml_assertion

Parses a SAML 2.0 assertion XML string and flags unsigned assertions, expired conditions, XML comment injection in NameID, and multiple Assertion elements indicating signature wrapping.

```python
result = auditor.analyze_saml_assertion(xml_string)
for vuln in result["vulns"]:
    print(vuln)
```

Input is capped at 1 MB to prevent entity expansion attacks. Signature presence is checked structurally; the signature is not cryptographically verified.

### scan_key_material

Scans filesystem paths for PEM private keys, hardcoded secrets in config files, and sensitive filenames. Defaults to a standard set of credential locations on Linux and macOS.

```python
hits = auditor.scan_key_material(paths=["/etc", "/home", "/root"])
```

Per-file reads are capped at 10 MB. Weak RSA keys below 2048 bits are flagged HIGH.

### analyze_tls

Connects to a host and port, negotiates TLS, and inspects the protocol version, cipher suite, and certificate. Flags deprecated protocols, weak ciphers, expired certificates, and self-signed certificates.

```python
result = auditor.analyze_tls("10.0.0.1", port=443)
for vuln in result["vulns"]:
    print(vuln)
```

Certificate verification is disabled. The connection uses `ssl.CERT_NONE` to allow inspection of invalid certificates.

## KeyCryptoAnalyzer

Extended cryptographic analysis using stdlib only. Covers RSA key inspection, ECDSA nonce reuse detection, X.509 certificate weakness scanning, timing oracle measurement, and hash-based MAC length extension risk assessment.

```python
from modules.crypto_audit import KeyCryptoAnalyzer

analyzer = KeyCryptoAnalyzer()
```

### analyze_rsa_key

Parses a PEM or DER RSA private key using raw ASN.1 parsing. Flags `e=3` at CRITICAL for Coppersmith and Hastad broadcast attacks. Flags keys below 1024 bits at CRITICAL and keys below 2048 bits at HIGH. Supports PKCS#1 and PKCS#8 wrapped keys.

### check_ecdsa_nonce_reuse

Takes a list of signature dicts with `r`, `s`, and `hash` integer fields. Returns a finding for any pair that shares the same `r` value. Shared `r` proves the same ephemeral nonce `k` was used twice and the private key `d` is algebraically recoverable.

```python
findings = analyzer.check_ecdsa_nonce_reuse([
    {"r": r1, "s": s1, "hash": h1},
    {"r": r2, "s": s2, "hash": h2},
])
```

### scan_certificate_weaknesses

Parses an X.509 certificate from PEM and flags: self-signed, MD5 signature algorithm at CRITICAL, SHA-1 signature algorithm at HIGH, RSA key below 2048 bits, wildcard CN at LOW, and expiry within 30 days or past.

### check_timing_oracle

Sends interleaved valid and invalid bearer token requests and measures the mean response time difference. A difference above 5 ms is flagged HIGH as a likely non-constant-time comparison.

```python
result = analyzer.check_timing_oracle(
    url="https://10.0.0.1/api/auth",
    valid_token="...",
    invalid_token="...",
    iterations=20,
)
```

### check_length_extension_vulnerability

Infers the hash algorithm from the MAC hex string length and determines whether bare `H(key || message)` construction is vulnerable to length extension. MD5, SHA-1, SHA-256, and SHA-512 are flagged HIGH. SHA-224 and SHA-384 are not vulnerable due to output truncation.

## Binary analysis functions

These standalone functions take raw binary data bytes and return finding lists. They scan for cryptographic weaknesses in firmware images and stripped binaries.

| Function | Detects |
| -------- | ------- |
| `check_rng_weakness(data)` | libc rand, time-seeded srand, /dev/random without /dev/urandom |
| `detect_xor_based_c2_encoding(data)` | XOR key schedules, rolling XOR patterns suggesting C2 encoding |
| `detect_rc4_usage_in_binary(data)` | RC4 key scheduling loop patterns in binary |
| `detect_base64_c2_encoding(data)` | Embedded base64 alphabet and decode table patterns |
| `detect_salsa20_chacha20_usage(data)` | Salsa20 and ChaCha20 constant strings |
| `detect_aes_usage_in_binary(data)` | AES S-box constants, key expansion patterns |
| `detect_hash_misuse_indicators(data)` | MD5/SHA-1 constant patterns used for security decisions |
| `detect_rolling_xor_encoding(data)` | Rolling XOR byte sequences suggesting obfuscated payloads |
| `detect_arithmetic_encoding(data)` | ADD/XOR/rotate encoding loops |
| `detect_gcm_nonce_misuse(data)` | AES-GCM nonce reuse patterns |
| `detect_weak_random_for_crypto(data)` | Weak PRNG in cryptographic context |

All binary analysis functions return a list of finding dicts with `severity`, `title`, `detail`, `host`, and `port` fields.

## Config and text analysis functions

These functions take text strings from configuration files, shadow databases, or PAM config.

| Function | Input | Detects |
| -------- | ----- | ------- |
| `check_hash_weakness(data)` | Text | MD5/SHA-1 hashes in auth context |
| `check_key_management_weakness(config_text)` | Config text | Hardcoded keys, key derivation gaps |
| `scan_for_crypto_anti_patterns(filepath)` | File path | Regex patterns for common crypto errors |
| `check_shadow_password_weakness(shadow_content)` | /etc/shadow content | Weak hash algorithms, empty passwords |
| `check_password_policy_weakness(pam_config_text)` | PAM config | Absent length or complexity requirements |
| `detect_password_in_binary(data)` | Binary data | Cleartext credential strings |

## Primality and number-theory functions

| Function | Description |
| -------- | ----------- |
| `miller_rabin_primality(n, rounds)` | Returns True if n passes Miller-Rabin primality testing |
| `check_weak_prime(n)` | Flags safe prime failures, small prime factors, smooth numbers |
| `check_discrete_log_weakness(p, g)` | Flags weak DH parameters: small group order or non-prime p |
| `check_birthday_collision_risk(hash_bits, num_samples)` | Estimates birthday collision probability |
| `extract_rsa_modulus_from_cert_der(der_bytes)` | Returns RSA modulus integer from certificate DER bytes |

## Network probe functions

| Function | Description |
| -------- | ----------- |
| `probe_password_hash_disclosure(host, port)` | HTTP probes for hash leakage in error responses |
| `detect_protocol_downgrade_surface(...)` | Identifies endpoints that accept multiple protocol versions |

## Findings format

All methods use the same dict structure:

| Field | Description |
| ----- | ----------- |
| `type` | Short label for the finding class |
| `severity` | CRITICAL, HIGH, MEDIUM, LOW, or INFO |
| `description` | Human-readable description |
| `detail` | Supporting context such as algorithm, key size, or path |
| `exploit` | Suggested proof-of-concept command or formula |

## Limitations

JWT analysis does not use constant-time comparison during the candidate secret iteration. The loop exits on first match, which introduces a timing side-channel. Use for offensive analysis only, not as a server-side verifier.

SAML analysis does not cryptographically validate XML signatures. It only checks for structural presence and anomalies. A signed assertion with a malformed signature is reported as signed.

TLS analysis connects once per target with default ssl settings. It does not enumerate all supported cipher suites or protocol versions. Use testssl.sh for full protocol enumeration.

Binary analysis functions use byte-pattern matching and heuristics, not semantic analysis. False positive rates are higher on obfuscated binaries. Confirm findings with `TaintTracker` before reporting.
