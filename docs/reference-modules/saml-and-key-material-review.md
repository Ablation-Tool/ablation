# SAML and Key Material Review

Detect SAML assertion wrapping vulnerability surfaces, extract PEM-encoded RSA/EC key material from binaries and configuration files, detect hardcoded private keys and certificates, and assess key management weaknesses in application configuration: via `modules/crypto_audit.py` `CryptoAudit` and `KeyCryptoAnalyzer`.

---

## Why this exists

1. **SAML XML Signature Wrapping (XSW)** is a class of attack where an attacker copies a legitimately signed `<Assertion>` element into a new XML document alongside a forged assertion, relying on the service provider to validate the signed node but process the unsigned node. `CryptoAudit.check_saml_wrapping_risk()` examines SAML response XML to identify whether the SP implementation is likely vulnerable: specifically, whether the `AssertionConsumerServiceURL` is validated, whether the `IssuerID` is checked, and whether the signature references the outer `<Response>` or only the inner `<Assertion>`.

2. **`KeyCryptoAnalyzer` extracts embedded key material from arbitrary binary and configuration data**, it scans for PEM markers `-----BEGIN RSA PRIVATE KEY-----`, `-----BEGIN EC PRIVATE KEY-----`, `-----BEGIN CERTIFICATE-----`, DER-encoded RSA modulus sequences, and base64-encoded PKCS#8 blocks. This surfaces private keys embedded in firmware images, container filesystem layers, and application configuration files that would otherwise require manual inspection.

3. **`check_key_management_weaknessconfig_text`** identifies key management anti-patterns in configuration files: hardcoded signing keys in YAML/JSON/INI format, JWT secrets shorter than 32 characters, symmetric encryption keys stored alongside the data they protect, and certificate pinning disabled via `verify=False` or `SSL_VERIFY=0`. These patterns do not represent broken cryptography but broken key hygiene that makes the cryptographic strength irrelevant.

---

## How it works

```mermaid
flowchart TD
    A(["CryptoAudit.check_saml_wrapping_risk(saml_xml) → dict\n  Parse XML (xml.etree)\n  Check: ds:Signature references Response vs Assertion\n  Check: AssertionConsumerServiceURL validation present\n  Check: multiple Assertion elements (XSW indicator)\n  → {xsw_risk: bool, reasoning: str, signature_scope: str}"]):::input --> B["KeyCryptoAnalyzer(data: bytes) → analyzer\n  Scan for PEM markers in binary data\n    -----BEGIN RSA PRIVATE KEY-----\n    -----BEGIN EC PRIVATE KEY-----\n    -----BEGIN CERTIFICATE-----\n  Scan for DER RSA sequence magic (0x30 0x82)\n  → List[KeyMaterial]"]:::primary
    B:::primary --> C["KeyMaterial:\n  key_type: RSA_PRIVATE / EC_PRIVATE / CERTIFICATE\n  offset: int (byte offset in binary)\n  pem_block: str\n  _estimate_rsa_bits() → key size in bits\n  → {type, offset, size_bits, pem_block}"]:::secondary
    C:::secondary --> D(["check_key_management_weakness(config_text) → list\n  Scan for:\n    jwt_secret < 32 chars\n    hardcoded AES/DES key patterns\n    SSL_VERIFY=false / verify=False\n    PRIVATE_KEY= inline\n  → [{weakness_type, value_snippet, severity}]"]):::output
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
from modules.crypto_audit import CryptoAudit, KeyCryptoAnalyzer, check_key_management_weakness

# SAML assertion analysis — method is analyze_saml_assertion() not check_saml_wrapping_risk()
audit = CryptoAudit()
saml_xml = open('saml_response.xml').read()
result = audit.analyze_saml_assertion(saml_xml)
# Return keys: signed, subject, conditions, vulns
print(f"signed: {result['signed']}")
print(f"subject: {result['subject']}")
for vuln in result['vulns']:
    print(f"  VULN: {vuln}")

# Config file / source key management weakness check
config_text = open('/etc/app/config.yaml').read()
# Returns [{severity, title, detail, host, port}]
for w in check_key_management_weakness(config_text):
    print(f"  [{w['severity']}] {w['title']}: {w['detail'][:80]}")

# Per-key DER analysis — analyze_rsa_key() takes bytes of a DER or PEM key
key_analyzer = KeyCryptoAnalyzer()
# key_analyzer.findings populated by analyze_rsa_key(), check_ecdsa_nonce_reuse(), etc.
rsa_findings = key_analyzer.analyze_rsa_key(open('server.key', 'rb').read())
for f in rsa_findings:
    # findings: {type, severity, description, detail, exploit}
    print(f"  [{f['severity']}] {f['type']}: {f['description']}")
```

---

## Example output

The following illustrates SAML and key material review output format.

```
CryptoAudit.check_saml_wrapping_risk:

XSW risk: True
Signature scope: Assertion (not Response)
Reasoning: ds:Reference URI points to inner Assertion ID only;
  Response element is unsigned and attacker-controlled

KeyCryptoAnalyzer: firmware.bin

  RSA_PRIVATE at offset 0x3f200  bits=2048
  CERTIFICATE at offset 0x3f800

check_key_management_weakness: config.yaml

  [HIGH] hardcoded_jwt_secret: jwt_secret=abc123  (len=6 < 32)
  [MEDIUM] ssl_verify_disabled: verify=False
```

---

## False positives

**`check_saml_wrapping_risk()` is a static analysis of the SAML XML**, it cannot verify whether the SP implementation actually processes the unsigned assertion or the signed one. The risk assessment flags the XML structure; confirm exploitability by testing against the actual SP with a crafted XSW payload.

**PEM marker detection in firmware**: test certificate PEM blocks embedded in firmware for TLS verification not private keys will be flagged by `KeyCryptoAnalyzer`. Distinguish certificate material public key only from private key material by checking the PEM header. Certificate findings are informational only unless the private key is also present.

---

## Pipeline position

Run SAML analysis when a SAML SSO endpoint is present; run `KeyCryptoAnalyzer` on any firmware image or container layer before analyzing specific binary functionality. Key management weakness checks apply to any configuration file retrieved from a compromised host.

---

## Reading output

`CryptoAudit.analyze_saml_assertion(xml_str)` parses a SAML assertion and returns:

| Key | Content |
|:---|:---|
| `signed` | `True` if a `<ds:Signature>` element is present in the Assertion |
| `subject` | NameID string from the Subject element, or `None` |
| `conditions` | `Dict` of NotBefore/NotOnOrAfter expiry values |
| `vulns` | `List[str]`: one entry per detected vulnerability for example `'UNSIGNED_ASSERTION'`, `'EXPIRED'`, `'MULTIPLE_ASSERTIONS'`, `'COMMENT_INJECTION'` |

`KeyCryptoAnalyzer.analyze_rsa_keykey_data` accepts raw DER or PEM bytes and returns `list` of finding dicts. `KeyCryptoAnalyzer.scan_certificate_weaknessescert_pem` accepts a PEM-encoded X.509 certificate string and returns a `list` of finding dicts. Both finding dicts use `type`, `severity`, `description`, `detail`, `exploit` keys.

---

## See also

- [JWT Analysis and Weak Secret Testing](jwt-analysis-and-weak-secret-testing.md): JWT-specific token forgery and weak secret brute-force
- [RSA/ECDSA and Randomness Checks](rsa-ecdsa-and-randomness-checks.md): mathematical weakness analysis of extracted key material
