# SBOMExtractor

## Why this exists

One thing was not possible before in Ablation:

1. **Generate a software bill of materials from a stripped binary.** Source-level SBOM tools parse `package.json`, `go.sum`, or `requirements.txt`. Firmware shipped without source has none of these. `ThirdPartyLibraryIdentifier` detects library presence via byte signatures. `SBOMExtractor` goes further: it sweeps rodata for embedded version strings that library authors include for diagnostics even in stripped builds, combines those with signature matches, and adds ELF metadata sources. The result is a structured component list with SPDX license IDs and version fields that can feed into a vulnerability management pipeline or a CycloneDX SBOM document.

## Usage

```python
from ablation.analyzers.sbom_extractor import SBOMExtractor

extractor = SBOMExtractor('/path/to/binary')
components = extractor.extract()
print(extractor.report(components))
```

With an existing `BinaryContext`:

```python
from ablation.analyzers.binary_context import BinaryContext
ctx = BinaryContext.load_or_build('/path/to/binary')
extractor = SBOMExtractor.from_context(ctx)
components = extractor.extract()
```

## Output: SBOMComponent

| Field | Type | Description |
|-------|------|-------------|
| `name` | str | Canonical library name |
| `version` | str | Detected version string or range |
| `source` | str | `version_string`, `signature`, or `metadata(...)` |
| `spdx_id` | str | SPDX license identifier if known |
| `confidence` | str | `HIGH` for version strings, `MEDIUM` for signatures |
| `notes` | list[str] | Supporting evidence such as matched signature types |

## Data sources

Three complementary sources are combined in priority order:

1. **Version strings** (22 regex patterns): sweeps raw binary bytes for patterns like `OpenSSL 1.1.1k`, `BusyBox v1.34.1`, `zlib 1.2.11`. Source confidence: HIGH.

2. **Byte signatures** (from `ThirdPartyLibraryIdentifier`): 19 patterns matching algorithm constants and marker bytes. Used only for libraries not already found by version string. Source confidence: HIGH/MEDIUM.

3. ELF/PE metadata: `DT_NEEDED` shared library entries and `.comment` build toolchain strings.

## Library coverage

22 version patterns across:

OpenSSL / LibreSSL, wolfSSL / wolfCrypt, mbedTLS, zlib, libpng, libjpeg / libjpeg-turbo, expat, libxml2, SQLite, OpenWRT, Linux kernel, BusyBox, OpenSSH, dropbear, curl, uclibc, musl, glibc.

## FORGE audit

Gate: **PASSED** 2026-10-23. No HIGH or CRITICAL issues.

Tested on:
- Synthetic binary with `OpenSSL 1.1.1k`, `BusyBox v1.34.1`, `zlib 1.2.11` strings: all three components extracted correctly with `version_string` source.

## Pipeline position

**Before this module:** `BinaryContext.load_or_build()`. Run `ThirdPartyLibraryIdentifier` first if you need raw signature data separately.

**After this module:** feed `SBOMComponent` list to `BuildProvenanceExtractor` for build toolchain analysis. Use the version fields to query NVD or OSV for known CVEs matching the detected versions.

## See also

- [ThirdPartyLibraryIdentifier](third-party-library-identifier.md): byte-signature library detection
- [BuildProvenanceExtractor](build-provenance-extractor.md): compiler and toolchain recovery
- [DeprecatedCryptoScanner](deprecated-crypto-scanner.md): detect weak crypto in identified libraries
