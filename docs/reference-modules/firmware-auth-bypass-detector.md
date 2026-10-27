# FirmwareAuthBypassDetector

## Why this exists

Three things were not possible before in Ablation:

1. **Detect unsigned firmware flashers in a single function call.** Before this module, identifying CWE-347 in a PE firmware programmer required manually checking the IAT for WinVerifyTrust and correlating it against HID/USB/serial imports. This module automates the entire decision tree: device imports are matched against a tiered pattern set, signing imports are checked, firmware strings corroborate the classification, and a CRITICAL/HIGH/MEDIUM/CLEAN verdict is returned in one pass.

2. **Distinguish high-confidence device signals from generic noise.** DeviceIoControl and RegQueryValueEx appear in nearly every Windows binary. The module splits patterns into `FIRMWARE_IAT_HIGH` (device-specific: HidD_*/WinUsb_*/SetupDi*/serial comm) and `FIRMWARE_IAT_LOW` (generic: DeviceIoControl/registry). Only `FIRMWARE_IAT_HIGH` hits produce CRITICAL or HIGH verdicts. Low-confidence hits alone, even combined with firmware strings, produce MEDIUM, preventing noise from ordinal-only installers.

3. **Fill the pe_sweep GAP-015 gap outside the sweep pipeline.** The pe_sweep firmware bypass check (`_check_firmware_auth_bypass`) is scoped to the sweep pipeline and checks ordinal-only DLL names. This standalone analyzer is for targeted analysis of a known flasher binary, with full string scanning across `.rdata`, `.data`, and `.text` sections, explicit tiered confidence, and a CLI entry point.

## Background

AUO-001 (eGalaxUpdate2.exe) established that firmware flashers routinely ship for 7+ years without signature verification. The detection pattern is:

1. Binary imports firmware-programming APIs: HID, WinUSB, or serial comm.
2. Binary has no WinVerifyTrust, CryptVerifySignature, or BCryptVerifySignature in IAT.
3. Binary strings confirm firmware context: "firmware", "flash", "erase", and similar.

When all three conditions are true, any USB-accessible firmware blob is accepted without authenticity verification.

## Usage

```python
from modules.firmware_auth_bypass_detector import FirmwareAuthBypassDetector

# Single binary
det = FirmwareAuthBypassDetector.from_path('/path/to/flasher.exe')
result = det.analyze()

if result.is_vulnerable:
    print(f"{result.severity}: {result.summary}")
    print(f"  Device imports: {result.firmware_iat}")

```

```bash
python -m modules.firmware_auth_bypass_detector flasher.exe
```

## Verdict tiers

| Severity | Condition |
|---|---|
| CRITICAL | `FIRMWARE_IAT_HIGH` imports present + firmware strings present + no signing |
| HIGH | `FIRMWARE_IAT_HIGH` imports present + no signing firmware strings absent |
| MEDIUM | Only `FIRMWARE_IAT_LOW` (generic) + firmware strings + no signing; verify payload manually |
| CLEAN | Signing imports present, or no firmware imports at all |

## Pattern sets

### `FIRMWARE_IAT_HIGH` device-specific

HID API: `HidD_SetFeature`, `HidD_GetFeature`, `HidD_SetOutputReport`, `HidD_GetInputReport`,
`HidD_GetAttributes`, `HidD_GetProductString`, `HidD_GetPreparsedData`, `HidD_GetCaps`

Setup API: `SetupDiEnumDeviceInterfaces`, `SetupDiGetDeviceInterfaceDetail*`,
`SetupDiGetClassDevs*`, `SetupDiDestroyDeviceInfoList`, `SetupDiEnumDeviceInfo`

WinUSB: `WinUsb_Initialize`, `WinUsb_WritePipe`, `WinUsb_ReadPipe`,
`WinUsb_ControlTransfer`, `WinUsb_Free`, `WinUsb_GetDescriptor`

Serial touch controllers: `SetCommState`, `SetCommTimeouts`, `PurgeComm`, `EscapeCommFunction`

### `FIRMWARE_IAT_LOW` (generic)

`DeviceIoControl`, `RegQueryValueExA/W`, `RegSetValueExA/W`

### Signing imports any blocks the finding

`WinVerifyTrust`, `CryptVerifySignature*`, `CryptVerifyMessage*`,
`CertVerifyCertificateChainPolicy`, `CertGetCertificateChain`,
`WTHelperProvDataFromStateData`, `BCryptVerifySignature`, `NCryptVerifySignature`

## Validated corpus

| Binary | Expected | Result |
|---|---|---|
| CC3xxxRadioTool 1.0.3.19 | CRITICAL | CRITICAL; serial via SetCommState/PurgeComm |
| CC3xxxRadioTool 1.2 | CRITICAL | CRITICAL; same serial pattern |
| TI TIRTOS setupwin32 2_21_01_08 | CLEAN | CLEAN |
| BLE CC254x 1.5.2.0 | CLEAN | CLEAN; ordinal-only imports, no named firmware functions |

## Limitations

- Ordinal-only HID imports (HIDdAPI.dll imported by ordinal) are not detected by IAT name matching. Use `pe_sweep.py`'s `_check_firmware_auth_bypass` function instead, which checks imported DLL names.
- Signing verification implemented in non-standard crypto libraries custom TLV/ASN.1 parsers is not detected.
- The MEDIUM tier requires manual follow-up. `DeviceIoControl` + firmware strings is common in legitimate utilities that are not flashers.

## FORGE audit

Gate: **PASSED**. Two fixes applied:
- CWE-770: added `_MAX_PE_BYTES=256MB` + `os.path.getsize()` guard in `_load()` before `lief.parse()` and `Path.read_bytes()`.
- CWE-755: wrapped `lief.parse()` in `try/except Exception`: lief can raise C++ exceptions that bypass the `is None` null check.
No HIGH or CRITICAL findings remain.

---

## How it works

Loads the firmware image, maps entropy across the file using a sliding window, and classifies regions as encrypted, compressed, or plaintext. Known cryptographic constants and key derivation patterns are matched against the corpus. Partition boundaries are recovered from format signatures in the plaintext regions. Each finding includes the byte offset, the matched pattern, and the confidence level.

---

## Example output

```
[CRITICAL] HARDCODED_KEY   offset=0x1A40C0  len=32
  detail: AES-256 key matches family corpus entry FGT-SHARED-2022
  evidence: 8b3f...e1c4 (first 4 / last 4 bytes shown)

[HIGH] WEAK_ALGO   offset=0x3B200
  detail: MD5 constant detected in hash init sequence
```

---

## False positives

Version-mismatch findings appear when a known key or certificate is present in a build where it was intentionally removed. Cross-reference against the family table in `FirmwareKeyCorpus` and the product release notes before escalating. Development-only debug keys identifiable by subject CN matching vendor dev lab naming conventions are not production findings.

---

## Pipeline position

**Before this module:** Download the firmware image and confirm the file is complete (no `.aria2` sidecar). Read the product CLI Reference and Release Notes in `docs/` before analysis.

**After this module:** Feed extracted filesystems or ELF binaries to `SemanticSearcher`, `TaintTracker`, and `FirmwareAuthBypassDetector`.

---

## Reading output

`FirmwareAuthBypassDetector.from_path(path).analyze()` returns a `FirmwareAuthBypassResult`:

| Attribute | Content |
|:---|:---|
| `path` | Path of the analyzed binary |
| `is_vulnerable` | `True` if a firmware auth bypass pattern was detected |
| `severity` | `CLEAN` / `INFO` / `MEDIUM` / `HIGH` / `CRITICAL` |
| `summary` | Human-readable summary of the finding |
| `firmware_iat` | `List[str]`: firmware-related IAT import names |
| `signing_iat` | `List[str]`: signing-related IAT import names |
| `firmware_strings` | `List[str]`: firmware-related strings found in the binary |
| `arch` | Detected architecture string such as `'x86_64'` and `'ARM'` |
| `has_resources` | `True` if the binary has embedded PE resources |

---

## See also

- [FirmwareContainers](firmware-containers.md): partition extraction from container images
- [FirmwareContainerKeyExtractor](firmware-container-key-extractor.md): recover embedded key material
- [TaintAnalysis](taint-analysis.md): trace network input to sinks in extracted binaries
- [SemanticSearch](semantic-search.md): find vulnerability candidates in extracted ELFs
