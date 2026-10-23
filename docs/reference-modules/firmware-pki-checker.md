# FirmwarePKIChecker

## Why this exists

One thing was not possible before in Ablation:

1. **Detect firmware images that lack cryptographic signature structures for secure boot enforcement.** The existing `BuildIntegrityAnalyzer` checks hardening flags on compiled binaries. No prior module checked whether the firmware image itself carries the structures required for U-Boot FIT image signature verification, UEFI Secure Boot authenticode, or IMA/dm-verity runtime integrity. `FirmwarePKIChecker` searches the raw firmware image for FIT magic + U-Boot signature node strings, PKCS#7 DER OIDs, PEM certificate blocks, WIN_CERT structures, and IMA boot parameters. Absence of these structures means the firmware cannot enforce that only signed payloads execute.

## Usage

```python
from modules.firmware_pki_checker import FirmwarePKIChecker

checker = FirmwarePKIChecker('/path/to/firmware.bin')
findings = checker.scan()
print(checker.report(findings))
```

With an existing `BinaryContext`:

```python
from ablation.analyzers.binary_context import BinaryContext
ctx = BinaryContext.load_or_build('/path/to/firmware.bin')
checker = FirmwarePKIChecker.from_context(ctx)
findings = checker.scan()
```

## Output: PKIFinding

| Field | Type | Description |
|-------|------|-------------|
| `structure` | str | Which structure class is absent (see table) |
| `detail` | str | Specific indicators searched and not found |
| `severity` | str | `HIGH` for direct boot-integrity structures; `MEDIUM` for runtime policy |

## Checked structures

| Structure | Severity | What is searched |
|-----------|----------|-----------------|
| `uboot_fit_signature` | HIGH | FIT magic present but `signature@`, `key-name-hint`, `algo=sha256,rsa*` absent |
| `uefi_authenticode` | HIGH | PE or ELF image without PKCS#7 DER OID, PEM certificate, or WIN_CERT magic |
| `ima_dm_verity` | MEDIUM | No `ima_policy=`, `ima_template=`, `dm-mod.create=verity`, or `root-verity` strings |
| `no_certificate_material` | HIGH | No X.509 material, PKCS#7 envelope, or U-Boot key node found anywhere in image |

## Notes

A clean result does NOT confirm secure boot is enforced. It only confirms the structures are present. The bootloader configuration must also enable verification; a U-Boot FIT image with signature nodes can still have `check_signatures=no` in its environment.

This checker is most useful as a fast first filter. Images that fail all four checks have no PKI material at all and should be escalated for manual bootloader analysis.

## FORGE audit

Gate: **PASSED** 2026-10-23. No HIGH or CRITICAL issues.

Tested on a synthetic ELF stub without any certificate material: three findings emitted correctly.

## See also

- [BuildIntegrityAnalyzer](build-integrity-analyzer.md): PIE, stack canary, NX, RELRO on compiled binaries
- [ELFAnomalyScanner](elf-anomaly-scanner.md): structural ELF anomalies
- [SBOMExtractor](sbom-extractor.md): build provenance and component identification
