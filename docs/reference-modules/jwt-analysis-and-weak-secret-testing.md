# JWT Analysis and Weak Secret Testing

Decode and verify JSON Web Tokens, detect `alg: none` acceptance, brute-force weak HS256 secrets against a wordlist, forge replacement tokens, and scan process environments for secrets embedded in JWT payloads or signing keys: via `modules/crypto_audit.py` `CryptoAudit` and `forge_jwt()`.

---

## Why this exists

1. **`forge_jwt()` produces valid-looking JWTs with attacker-controlled claims**, it generates HS256-signed tokens with an arbitrary payload claims dict and a known or empty secret. This is used to test whether a server enforces algorithm verification (`alg: none` bypass) and whether a JWT-based authorization system will accept a token whose claims have been modified. `forge_jwt(payload={"role":"admin"}, secret="", alg="none")` produces the classic `alg:none` bypass token.

2. **`CryptoAudit.analyze_jwt()` tests live JWT endpoints**, it decodes a captured JWT, attempts `alg: none` replacement, and tests the provided token against the original endpoint to confirm whether the server accepts it. It also scans for weak secrets by attempting HS256 verification with entries from a configurable wordlist `secret`, `password`, `jwt_secret`, `changeme`, and common variations.

3. **`CryptoAudit.scan_process_secrets()` extracts JWTs and signing keys from running process environments**, it reads `/proc/<pid>/environ` for all readable processes and extracts `JWT_SECRET`, `AUTH_SECRET`, `TOKEN_SIGNING_KEY`, and base64-encoded strings that look like JWT header prefixes (`eyJ`). This is the primary method for discovering signing keys from a compromised host.

---

## How it works

```mermaid
flowchart TD
    A(["forge_jwt(payload, secret='', alg='HS256') → str\n  Build header: {alg, typ: JWT}\n  Build payload: dict → JSON\n  b64url_encode(header).b64url_encode(payload) → signing_input\n  If alg=none: signature=''\n  If alg=HS256: hmac.new(secret, signing_input, sha256)\n  → header.payload.signature (dot-joined)"]):::input --> B["CryptoAudit.analyze_jwt(token) → dict\n  Decode header (alg, kid)\n  Decode payload (exp, iat, sub, role, claims)\n  Test alg:none bypass: forge + resubmit\n  Test weak secrets: wordlist HS256 verify\n  → {alg, payload, none_bypass: bool, weak_secret: str|None}"]:::primary
    B:::primary --> C["CryptoAudit.scan_process_secrets() → List[dict]\n  Walk /proc/[pid]/environ for all readable PIDs\n  Pattern match: JWT_SECRET=, TOKEN_KEY=, eyJ prefix\n  → [{pid, cmdline, key_name, value}]"]:::secondary
    C:::secondary --> D(["check_rng_weakness(binary_data) → list\n  Scan for srand(time(NULL)) pattern (weak seeding)\n  Scan for rand() with no srand call\n  → [{va, description, severity}]\n\ncheck_key_management_weakness(config_text) → list\n  Hardcoded signing keys in config text\n  → [{key_type, value, severity}]"]):::output
    classDef input     fill:#0d47a1,stroke:#1565c0,color:#fff
    classDef primary   fill:#e65100,stroke:#bf360c,color:#fff
    classDef secondary fill:#004d40,stroke:#00695c,color:#fff
    classDef tertiary  fill:#4a148c,stroke:#6a1b9a,color:#fff
    classDef neutral   fill:#37474f,stroke:#546e7a,color:#fff
    classDef output    fill:#1b5e20,stroke:#2e7d32,color:#fff
    linkStyle 0 stroke:#bf360c,stroke-width:2px
    linkStyle 1 stroke:#00695c,stroke-width:2px
    linkStyle 2 stroke:#2e7d32,stroke-width:3px
```

---

## Usage

```python
from modules.crypto_audit import forge_jwt, CryptoAudit

# Forge alg:none token
none_token = forge_jwt({"sub": "1234", "role": "admin"}, secret="", alg="none")
print(f"alg:none token: {none_token}")

# Analyze a captured JWT — method is analyze_jwt(), not audit_jwt()
audit = CryptoAudit()
result = audit.analyze_jwt("<captured_token>")
# Return keys: raw, header, payload, alg, vulns, forged_token
print(f"alg: {result['alg']}")
print(f"vulnerabilities: {result['vulns']}")
if result['forged_token']:
    print(f"forged: {result['forged_token'][:60]}...")

# Scan filesystem paths for JWT secrets
# scan_for_jwts scans files for embedded JWT strings
tokens_found = audit.scan_for_jwts(paths=['/etc', '/home', '/opt'])
for t in tokens_found:
    print(f"  {t.get('source')}: {t.get('token', '')[:40]}...")
```

---

## Example output

The following illustrates JWT analysis output format.

```
CryptoAudit.analyze_jwt:

alg: HS256
none_bypass: True  (server accepted unsigned token)
weak_secret: 'secret'  (matched wordlist entry)

scan_process_secrets:
  PID 1042 (node /app/server.js): JWT_SECRET=mysecretkey123
```

---

## False positives

**`alg: none` bypass test requires a live endpoint**: `analyze_jwt()` cannot confirm bypass without a target URL. When called without an endpoint, `none_bypass` is marked `unknown` (not `True`) to avoid misrepresenting the result as a confirmed finding. Confirm bypass only against the actual token verification endpoint.

**Wordlist weak-secret detection**: HS256 HMAC verification with a matching entry proves the secret was used. However, a token may use a strong secret that simply does not appear in the wordlist. A `weak_secret: null` result does not mean the secret is strong; it means the wordlist was exhausted without a match.

---

## Pipeline position

Run JWT analysis after capturing a token from HTTP traffic (via `PCAPAnalyzer`) or from a response header. Weak secret discovery and `alg: none` bypass confirm token forgery is possible; `scan_process_secrets()` provides the key directly from the application process.

---

## Reading findings

`CryptoAudit.analyze_jwt(token)` returns a dict:

| Key | Content |
|:---|:---|
| `header` | Decoded JWT header dict |
| `payload` | Decoded JWT payload dict |
| `alg` | Algorithm claim string for example `'HS256'`, `'none'` |
| `vulns` | `List[str]`: one entry per detected weakness for example `'CRITICAL:WEAK_SECRET: secret is ...'`, `'MEDIUM:HS256: symmetric; secret may be weak'` |
| `forged_token` | A forged JWT string when a weakness allows forgery, or `None` |

`CryptoAudit.scan_for_jwts(paths)` scans a list of file paths and returns a list of `path, token_string` tuples for all JWT strings found.

---

## See also

- [SAML and Key Material Review](saml-and-key-material-review.md): SAML assertion wrapping and key extraction from XML signing structures
- [RSA/ECDSA and Randomness Checks](rsa-ecdsa-and-randomness-checks.md): cryptographic weakness detection in asymmetric key material
