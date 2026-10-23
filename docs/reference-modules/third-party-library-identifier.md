# ThirdPartyLibraryIdentifier

## Why this exists

One thing was not possible before in Ablation:

1. **Identify embedded third-party libraries without symbol tables.** Stripped firmware compiles third-party libraries statically, removing all symbol names. Without library identification, every analysis must treat the entire binary as unknown code. `SemanticSearcher` finds functions by description; it does not recognize whether a set of functions collectively constitutes OpenSSL, zlib, or wolfSSL. `ThirdPartyLibraryIdentifier` closes this gap using FLIRT-style byte-signature matching: well-known libraries embed characteristic constants such as the AES S-box, zlib CRC-32 polynomial, or SHA-256 initialization vectors. When multiple signatures from the same library match, the library is confirmed present. Confirmed libraries feed directly into `SBOMExtractor` for software bill-of-materials reporting and expose version-specific CVE risk.

## Usage

```python
from ablation.analyzers.third_party_library_identifier import ThirdPartyLibraryIdentifier

ident = ThirdPartyLibraryIdentifier('/path/to/binary')
findings = ident.scan()
print(ident.report(findings))
```

With an existing `BinaryContext`:

```python
from ablation.analyzers.binary_context import BinaryContext
ctx = BinaryContext.load_or_build('/path/to/binary')
ident = ThirdPartyLibraryIdentifier.from_context(ctx)
findings = ident.scan()
```

Control the minimum number of signatures required per library with `min_matches` (default: 2).

## Output: LibraryFinding

| Field | Type | Description |
|-------|------|-------------|
| `library` | str | Library name such as `OpenSSL/LibreSSL` or `zlib` |
| `version_hint` | str | Version range inferred from signatures |
| `matched_sigs` | list[str] | Description of each matched signature |
| `match_count` | int | Total matching signatures |
| `vuln_hints` | list[str] | CVEs associated with the detected version range |
| `confidence` | str | `HIGH` for 3 or more matches, `MEDIUM` for 2 |

## Signature database

19 signatures covering:

| Library | Key constants used |
|---------|-------------------|
| OpenSSL / LibreSSL | AES S-box first row, SHA-256 H0/H1 init, RSA exponent 65537 |
| zlib | Adler-32 modulus, CRC-32 polynomial, deflate header bytes |
| libpng | PNG file signature, IHDR chunk marker |
| libjpeg | JPEG SOI and EOI marker bytes |
| wolfSSL | AES S-box, version string prefix |
| mbedTLS | Function name prefix, AES S-box |
| expat / libxml2 | XML declaration, version string |
| uclibc / musl | Version strings in rodata |

## CVE hint table

| Library | Version | CVEs |
|---------|---------|------|
| OpenSSL | < 1.0.2u | CVE-2016-0800, CVE-2014-3566 |
| OpenSSL | < 1.1.1n | CVE-2022-0778 |
| OpenSSL | < 3.0.7 | CVE-2022-3786, CVE-2022-3602 |
| zlib | < 1.2.12 | CVE-2018-25032, CVE-2022-37434 |
| libpng | < 1.6.37 | CVE-2019-7317 |
| wolfSSL | < 5.1.1 | CVE-2022-25640, CVE-2021-38597 |
| mbedTLS | < 2.28.1 | CVE-2022-35409 |

## FORGE audit

Gate: **PASSED** 2026-10-23. No HIGH or CRITICAL issues.

Tested on:
- zlib-constant binary: `zlib` correctly identified from CRC-32 polynomial and deflate header bytes.
- Incomplete triad: library with only one matching signature correctly excluded at default `min_matches=2`.

## Pipeline position

**Before this module:** `BinaryContext.load_or_build()`.

**After this module:** feed results to `SBOMExtractor` for full software bill-of-materials generation. Use CVE hints to prioritize which library code to analyze first with `SemanticSearcher`. If a vulnerable version of OpenSSL is detected, run `DeprecatedCryptoScanner` to check whether the binary uses the deprecated cipher suites known to affect that version.

## See also

- [SBOMExtractor](sbom-extractor.md): full SBOM generation from library detections
- [DeprecatedCryptoScanner](deprecated-crypto-scanner.md): detect MD5/SHA-1/DES/RC4 in embedded crypto
- [SemanticSearcher](semantic-search.md): find specific crypto functions once library is identified
