"""
FirmwareAuthBypassDetector: detect PE firmware flashers without signature verification.

Identifies Windows executables that have firmware update capability but lack
cryptographic signature verification in their Import Address Table.

Firmware update indicators:
  - DeviceIoControl, WriteFile with device paths
  - HID API functions: HidD_SetFeature, HidD_GetFeature, HidD_GetAttributes
  - Setup API functions: SetupDiEnumDeviceInterfaces, SetupDiGetClassDevs
  - WinUSB functions: WinUsb_WritePipe, WinUsb_ReadPipe
  - Firmware strings: "firmware", "flash", "update", ".bin", ".hex"

Signature verification indicators (any of):
  - WinVerifyTrust
  - CryptVerifySignature*
  - Crypt*Signature*
  - WTHelperProvDataFromStateData
  - Certificate chain validation functions

Finding: CWE-347 Improper Verification of Cryptographic Signature
Severity: CRITICAL when firmware update capability confirmed without signing

Gap closed: GAP-015 (AUO eGalax finding)

Usage:
    det = FirmwareAuthBypassDetector.from_path('flasher.exe')
    result = det.analyze()
    if result.is_vulnerable:
        print(f"CRITICAL: {result.summary}")
"""

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set

_MAX_PE_BYTES = 256 * 1024 * 1024

try:
    import lief
except ImportError:
    lief = None  # type: ignore


@dataclass
class FirmwareAuthBypassResult:
    """Analysis result from FirmwareAuthBypassDetector."""

    path: str
    is_vulnerable: bool = False
    severity: str = "CLEAN"
    summary: str = ""

    # Evidence
    firmware_iat: List[str] = field(default_factory=list)      # firmware-related IAT imports
    signing_iat: List[str] = field(default_factory=list)       # signing-related IAT imports
    firmware_strings: List[str] = field(default_factory=list)  # firmware-related strings

    # Metadata
    arch: str = "unknown"
    image_base: int = 0
    has_resources: bool = False

    def __str__(self) -> str:
        lines = [
            f"FirmwareAuthBypassDetector: {Path(self.path).name}",
            f"  Severity: {self.severity}",
            f"  Vulnerable: {self.is_vulnerable}",
            f"  Summary: {self.summary}",
            f"  Architecture: {self.arch}",
        ]
        if self.firmware_iat:
            lines.append(f"  Firmware IAT imports ({len(self.firmware_iat)}): {', '.join(self.firmware_iat[:5])}")
        if self.signing_iat:
            lines.append(f"  Signing IAT imports ({len(self.signing_iat)}): {', '.join(self.signing_iat[:3])}")
        if self.firmware_strings:
            lines.append(f"  Firmware strings ({len(self.firmware_strings)}): {', '.join(self.firmware_strings[:3])}")
        return "\n".join(lines)


# HIGH-CONFIDENCE firmware update API patterns (device-specific; lowercase)
# Any of these imports, combined with no signing imports, is strong evidence.
FIRMWARE_IAT_HIGH = {
    # HID device functions (USB HID firmware update)
    'hidd_setfeature', 'hidd_getfeature', 'hidd_setoutputreport', 'hidd_getinputreport',
    'hidd_getattributes', 'hidd_getproductstring', 'hidd_getmanufacturerstring',
    'hidd_getserialnumberstring', 'hidd_getpreparseddata', 'hidd_getcaps',
    'hidd_getindexedstring', 'hidd_flush', 'hidd_getnuminputbuffers',

    # Setup API (device enumeration for firmware update)
    'setupdienumdeviceinterfaces', 'setupdigetdeviceinterfacedetaila',
    'setupdigetdeviceinterfacedetailw', 'setupdigetclassdevsa',
    'setupdigetclassdevsw', 'setupdidestroydeviceinfolist',
    'setupdienumdeviceinfo', 'setupdigetdeviceregistrypropertya',

    # WinUSB (USB bulk firmware transfer)
    'winusb_initialize', 'winusb_writepipe', 'winusb_readpipe',
    'winusb_controltransfer', 'winusb_setpipepolicy', 'winusb_free',
    'winusb_getdescriptor', 'winusb_queryinterfacesettings',

    # Serial port firmware update: touch controllers, embedded targets
    'setcommstate', 'setcommtimeouts', 'purgecomm', 'escapecommfunction',
}

# LOW-CONFIDENCE firmware update API patterns (generic; need corroboration)
# DeviceIoControl is ubiquitous; registry access is universal. Only use as
# a tiebreaker when HIGH_CONFIDENCE or strings are also present.
FIRMWARE_IAT_LOW = {
    'deviceiocontrol',
    'regqueryvalueexa', 'regqueryvalueexw', 'regsetvalueexa', 'regsetvalueexw',
}

# Union for backward compatibility
FIRMWARE_IAT_PATTERNS = FIRMWARE_IAT_HIGH | FIRMWARE_IAT_LOW

# Strings indicating firmware functionality (lowercase)
FIRMWARE_STRING_PATTERNS = [
    'firmware', 'flash', 'bootloader', 'iap', 'in-app',
    'update', 'upgrade', 'program',
    '.bin', '.hex', '.uf2', '.dfu',
    'erase', 'write flash', 'read flash',
]

# Cryptographic signature verification APIs (lowercase)
SIGNING_IAT_PATTERNS = {
    # Primary signature verification
    'winverifytrust', 'winverifytrusthex',

    # CryptoAPI signature functions
    'cryptverifysignature', 'cryptverifysignaturea', 'cryptverifysignaturew',
    'cryptverifydetachedsignature', 'cryptverifydetachedsignaturea',
    'cryptverifycertificatesignature', 'cryptverifymessagesignature',

    # Certificate chain validation
    'certverifycertificatechainpolicy', 'certgetcertificatechain',
    'certverifycrlrevocation', 'certverifytimevalidity',

    # WinTrust helper functions
    'wthelperprovdatafromstatedata', 'wthelpercertcheckpolicysignature',
    'wthelpercertisselfsinged',
}


class FirmwareAuthBypassDetector:
    """
    Detects Windows PE executables with firmware update capability but no signature verification.

    Usage:
        det = FirmwareAuthBypassDetector.from_path('/path/to/flasher.exe')
        result = det.analyze()
        if result.is_vulnerable:
            print(f"CRITICAL: {result.summary}")
    """

    def __init__(self, path: str):
        self.path = path
        self._pe = None
        self._data: Optional[bytes] = None

    @classmethod
    def from_path(cls, path: str) -> 'FirmwareAuthBypassDetector':
        return cls(path)

    def _load(self):
        """Load PE binary and extract IAT + strings."""
        if lief is None:
            raise RuntimeError("lief not available; run: pip install lief")

        if self._pe is None:
            bin_size = os.path.getsize(self.path)
            if bin_size > _MAX_PE_BYTES:
                raise ValueError(
                    f'{self.path}: file size {bin_size} exceeds {_MAX_PE_BYTES} byte limit')
            try:
                self._pe = lief.parse(self.path)
            except Exception as exc:
                raise ValueError(f"lief.parse() failed for {self.path}: {exc}") from exc
            if self._pe is None:
                raise ValueError(f"lief.parse() returned None for {self.path}")
            self._data = Path(self.path).read_bytes()

    def _build_iat(self) -> Set[str]:
        """Return set of all imported function names (lowercase)."""
        self._load()
        iat_names = set()
        for lib in self._pe.imports:
            for entry in lib.entries:
                if entry.name:
                    iat_names.add(entry.name.lower())
        return iat_names

    def _scan_strings(self, min_len: int = 4) -> List[str]:
        """Extract printable ASCII strings from .rdata + .data sections."""
        self._load()
        strings = []

        for section in self._pe.sections:
            name = section.name.lower().rstrip('\x00')
            if name not in ('.rdata', '.data', '.text'):
                continue

            try:
                sec_data = bytes(section.content)
            except Exception:
                continue
            if not sec_data:
                continue
            current = []
            for byte in sec_data:
                if 32 <= byte < 127:
                    current.append(chr(byte))
                else:
                    if len(current) >= min_len:
                        strings.append(''.join(current))
                    current = []
            if len(current) >= min_len:
                strings.append(''.join(current))

        return strings

    def analyze(self) -> FirmwareAuthBypassResult:
        """
        Analyze PE binary for firmware update capability without signature verification.

        Returns:
            FirmwareAuthBypassResult with is_vulnerable=True if:
              - Firmware-related IAT imports present, AND
              - No signature verification imports, AND
              - Firmware-related strings present (corroboration)
        """
        self._load()

        result = FirmwareAuthBypassResult(
            path=self.path,
            arch=str(self._pe.header.machine),
            image_base=self._pe.optional_header.imagebase,
            has_resources=len(self._pe.resources.childs) > 0 if hasattr(self._pe, 'resources') else False,
        )

        # Step 1: Extract IAT
        iat_names = self._build_iat()

        # Step 2: Match firmware-related imports (tiered)
        high_iat = sorted([n for n in iat_names if n in FIRMWARE_IAT_HIGH])
        low_iat  = sorted([n for n in iat_names if n in FIRMWARE_IAT_LOW])
        result.firmware_iat = high_iat + [n for n in low_iat if n not in high_iat]

        # Step 3: Match signing-related imports
        result.signing_iat = sorted([
            name for name in iat_names
            if any(pat in name for pat in SIGNING_IAT_PATTERNS)
        ])

        # Step 4: Scan strings for firmware keywords
        all_strings = self._scan_strings(min_len=4)
        result.firmware_strings = [
            s for s in all_strings
            if any(pat in s.lower() for pat in FIRMWARE_STRING_PATTERNS)
        ][:20]  # limit to 20 hits for reporting

        # Step 5: Tiered verdict
        #   CRITICAL: HIGH-confidence device imports + firmware strings, no signing
        #   HIGH:     HIGH-confidence device imports, no strings, no signing
        #   LOW:      only LOW-confidence (generic) imports + firmware strings, no signing
        #   CLEAN:    no device imports, or signing present
        has_high_iat   = len(high_iat) > 0
        has_low_iat    = len(low_iat) > 0
        has_signing    = len(result.signing_iat) > 0
        has_fw_strings = len(result.firmware_strings) > 0

        if has_high_iat and not has_signing and has_fw_strings:
            result.is_vulnerable = True
            result.severity = "CRITICAL"
            result.summary = (
                f"Firmware update capability confirmed ({len(high_iat)} device imports, "
                f"{len(result.firmware_strings)} firmware strings) with NO signature verification "
                f"(WinVerifyTrust/CryptVerifySignature absent from IAT)"
            )
        elif has_high_iat and not has_signing:
            result.is_vulnerable = True
            result.severity = "HIGH"
            result.summary = (
                f"Firmware device imports detected ({len(high_iat)}: {', '.join(high_iat[:3])}) "
                f"with NO signature verification; firmware strings absent, manual verify recommended"
            )
        elif has_low_iat and not has_signing and has_fw_strings:
            result.is_vulnerable = True
            result.severity = "MEDIUM"
            result.summary = (
                f"Generic firmware indicators (DeviceIoControl/registry + firmware strings) "
                f"with no signing imports; may be installer or wrapper, verify payload"
            )
        elif has_signing:
            result.is_vulnerable = False
            result.severity = "CLEAN"
            result.summary = (
                f"Signature verification present ({len(result.signing_iat)} signing imports) "
                f"firmware bypass not applicable"
            )
        else:
            result.is_vulnerable = False
            result.severity = "CLEAN"
            result.summary = "No firmware update capability detected"

        return result

    @staticmethod
    def report(result: FirmwareAuthBypassResult) -> str:
        """Generate human-readable report."""
        return str(result)


# ─────────────────────────────────────────────────────────────────────────────
# CLI entry point
# ─────────────────────────────────────────────────────────────────────────────

def main():
    import sys
    if len(sys.argv) < 2:
        print("Usage: python -m ablation.analyzers.firmware_auth_bypass_detector <pe_file>")
        sys.exit(1)

    detector = FirmwareAuthBypassDetector.from_path(sys.argv[1])
    result = detector.analyze()
    print(FirmwareAuthBypassDetector.report(result))

    sys.exit(0 if not result.is_vulnerable else 1)


if __name__ == '__main__':
    main()
