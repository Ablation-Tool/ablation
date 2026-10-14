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
from ablation.analyzers.firmware_auth_bypass_detector import FirmwareAuthBypassDetector

# Single binary
det = FirmwareAuthBypassDetector.from_path('/path/to/flasher.exe')
result = det.analyze()

if result.is_vulnerable:
    print(f"{result.severity}: {result.summary}")
    print(f"  Device imports: {result.firmware_iat}")

# CLI
python -m ablation.analyzers.firmware_auth_bypass_detector flasher.exe
```

## Verdict tiers

| Severity | Condition |
|---|---|
| CRITICAL | `FIRMWARE_IAT_HIGH` imports present + firmware strings present + no signing |
| HIGH | `FIRMWARE_IAT_HIGH` imports present + no signing (firmware strings absent) |
| MEDIUM | Only `FIRMWARE_IAT_LOW` (generic) + firmware strings + no signing; verify payload manually |
| CLEAN | Signing imports present, or no firmware imports at all |

## Pattern sets

### `FIRMWARE_IAT_HIGH` (device-specific)

HID API: `HidD_SetFeature`, `HidD_GetFeature`, `HidD_SetOutputReport`, `HidD_GetInputReport`,
`HidD_GetAttributes`, `HidD_GetProductString`, `HidD_GetPreparsedData`, `HidD_GetCaps`

Setup API: `SetupDiEnumDeviceInterfaces`, `SetupDiGetDeviceInterfaceDetail*`,
`SetupDiGetClassDevs*`, `SetupDiDestroyDeviceInfoList`, `SetupDiEnumDeviceInfo`

WinUSB: `WinUsb_Initialize`, `WinUsb_WritePipe`, `WinUsb_ReadPipe`,
`WinUsb_ControlTransfer`, `WinUsb_Free`, `WinUsb_GetDescriptor`

Serial (touch controllers): `SetCommState`, `SetCommTimeouts`, `PurgeComm`, `EscapeCommFunction`

### `FIRMWARE_IAT_LOW` (generic)

`DeviceIoControl`, `RegQueryValueExA/W`, `RegSetValueExA/W`

### Signing imports (any blocks the finding)

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
- Signing verification implemented in non-standard crypto libraries (custom TLV/ASN.1 parsers) is not detected.
- The MEDIUM tier requires manual follow-up. `DeviceIoControl` + firmware strings is common in legitimate utilities that are not flashers.
