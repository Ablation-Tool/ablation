# DeprecatedCryptoScanner

## Why this exists

One thing was not possible before in Ablation:

1. **Identify deprecated cryptographic algorithms in stripped firmware without taint analysis.** `SemanticSearcher` can query for crypto-related strings and `TaintTracker` can trace how values flow through the binary. Neither detects the actual presence of MD5, SHA-1, DES, or RC4 implementation code in a binary that has no symbols and no string references to algorithm names. `DeprecatedCryptoScanner` detects these algorithms by their mathematical constants: initialization vectors, S-box tables, and permutation structures that are fixed by each algorithm's specification and cannot change without breaking the algorithm.

## Usage

```python
from ablation.analyzers.deprecated_crypto_scanner import DeprecatedCryptoScanner

scanner = DeprecatedCryptoScanner('/path/to/firmware.elf')
findings = scanner.scan()
print(scanner.report(findings))
```

With an existing `BinaryContext`:

```python
from ablation.analyzers.binary_context import BinaryContext
ctx = BinaryContext.load_or_build('/path/to/firmware.elf')
scanner = DeprecatedCryptoScanner.from_context(ctx)
findings = scanner.scan()
```

## Output: CryptoFinding

| Field | Type | Description |
|-------|------|-------------|
| `algorithm` | str | `MD5`, `SHA-1`, `DES`, `RC4` |
| `offset` | int | File offset of the matching constant |
| `va` | int | Virtual address (requires LIEF section map; 0 if unavailable) |
| `severity` | str | `HIGH` for all deprecated algorithms |
| `note` | str | Deprecation reference |

## Signatures

| Algorithm | Constant used | Deprecation reference |
|-----------|--------------|----------------------|
| MD5 | Initial hash state: 16-byte magic | RFC 6151, NIST disallowed for keyed use |
| SHA-1 | Initial hash state: 20-byte magic | NIST SP 800-131A Rev 2, deprecated 2013 |
| DES | S-box first table constants | NIST SP 800-131A, disallowed 2015 |
| RC4 | Identity permutation: `0x00`..`0xFF` | RFC 7465, prohibited 2015 |

SHA-1 detection is distinguished from MD5 by the fifth 32-bit word `0xC3D2E1F0`. Both share the same first 16 bytes.

## FORGE audit

Gate: **PASSED** 2026-10-23. No HIGH or CRITICAL issues.

Tested on:
- Synthetic binary with all four constants planted at known offsets: all four algorithms detected.
- MD5 vs SHA-1 disambiguation: SHA-1 init detected at SHA-1 offset, MD5 at separate MD5 offset.
- Empty binary: 0 findings.

## Pipeline position

**Before this module:** nothing. Runs on raw binary bytes, no prior analysis required.

**After this module:** findings are standalone HIGH-severity crypto weakness reports. No taint path is needed: the presence of these constants confirms the algorithm is compiled into the binary. Cross-reference `va` with `BinaryContext.name()` to identify which function implements the deprecated algorithm.

## See also

- [BinaryContext](binary-context.md): VA lookup for findings
- [HardcodedCredentialScanner](hardcoded-credential-scanner.md): detect credentials in rodata
- [SemanticSearcher](semantic-code-search.md): query for crypto-related string patterns
