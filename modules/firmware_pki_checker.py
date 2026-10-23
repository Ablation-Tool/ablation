"""
firmware_pki_checker.py: Firmware PKI / secure boot structure absence checker.

Detects firmware images that lack cryptographic signature structures used by
U-Boot FIT image verification, UEFI Secure Boot, and IMA (Linux Integrity
Measurement Architecture). When these structures are absent, there is no
evidence that the firmware enforces signed-boot policies.

Structures searched:
  - U-Boot FIT image: magic 0xD00DFEED + signature node strings
    ("signature@" property, "algo=" containing "rsa", SHA-based hash names)
  - UEFI PE Authenticode: OID 1.2.840.113549.1.7.2 (signedData) + WIN_CERT
    structure magic (0x0100 or 0x0200 in attribute certificate table)
  - PKCS#7 / CMS envelope: PEM header "-----BEGIN PKCS7-----"
    or DER sequence for OID 1.2.840.113549.1.7.2
  - IMA / dm-verity: "verity" or "ima_policy" string in kernel command line
    area of initrd/kernel images
  - U-Boot public key node: "key-name-hint" or "required" FDT properties
    which mark the key node as a mandatory verification step

A finding is emitted for each ABSENT structure class. Presence of all classes
means the firmware image likely enforces PKI; absence of all means it does not.

Usage:
    checker = FirmwarePKIChecker('/path/to/firmware.bin')
    findings = checker.scan()
    print(checker.report(findings))
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional


# U-Boot FIT image magic bytes (big-endian device tree blob)
_FDT_MAGIC = b'\xd0\x0d\xfe\xed'

# U-Boot signature node indicators
_UBOOT_SIG_STRINGS: list[bytes] = [
    b'signature@',
    b'key-name-hint',
    b'algo=sha256,rsa2048',
    b'algo=sha256,rsa4096',
    b'algo=sha384,rsa4096',
    b'required',
]

# UEFI Authenticode: OID 1.2.840.113549.1.7.2 in DER
# = 0x06 0x09 0x2a 0x86 0x48 0x86 0xf7 0x0d 0x01 0x07 0x02
_PKCS7_SIGNED_DATA_DER = b'\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x07\x02'

_PEM_PKCS7 = b'-----BEGIN PKCS7-----'
_PEM_CERT  = b'-----BEGIN CERTIFICATE-----'

# IMA / dm-verity boot-param markers
_IMA_STRINGS: list[bytes] = [
    b'ima_policy=',
    b'ima_template=',
    b'dm-mod.create=verity',
    b'root-verity',
]

# UEFI WIN_CERTIFICATE magic in PE optional header attribute certificate table
_WIN_CERT_MAGIC: list[bytes] = [
    b'\x00\x02\x02\x00',   # wCertificateType = WIN_CERT_TYPE_PKCS_SIGNED_DATA
    b'\x00\x02\x01\x00',   # wCertificateType = WIN_CERT_TYPE_PKCS1_MODULE_SIGN
]


@dataclass
class PKIFinding:
    structure:  str     # which structure class is absent
    detail:     str     # why it was determined absent
    severity:   str     # HIGH / MEDIUM

    def fmt(self) -> str:
        return (f"  {self.severity:6s}  [NO_PKI]  {self.structure}\n"
                f"         {self.detail}")


class FirmwarePKIChecker:
    """Check for absence of firmware PKI / secure-boot signature structures."""

    def __init__(self, path: str) -> None:
        self._path = path

    @classmethod
    def from_context(cls, ctx) -> 'FirmwarePKIChecker':
        obj = cls.__new__(cls)
        obj._path = ctx.path
        return obj

    def _read_raw(self) -> bytes:
        try:
            return open(self._path, 'rb').read()
        except OSError:
            return b''

    def scan(self) -> List[PKIFinding]:
        raw = self._read_raw()
        if not raw:
            return []

        findings: list[PKIFinding] = []

        # Check 1: U-Boot FIT image signature
        has_fit_magic = _FDT_MAGIC in raw
        if has_fit_magic:
            # Image is a FIT image; check for signature nodes
            sig_nodes_found = [s for s in _UBOOT_SIG_STRINGS if s in raw]
            if len(sig_nodes_found) < 2:
                findings.append(PKIFinding(
                    'uboot_fit_signature',
                    f'FIT image magic present but signature node strings absent '
                    f'(found {len(sig_nodes_found)}/{len(_UBOOT_SIG_STRINGS)} indicators)',
                    'HIGH',
                ))
        else:
            # Not a FIT image; check for UEFI PE or bare kernel
            has_pe = raw[:2] == b'MZ'
            has_elf = raw[:4] == b'\x7fELF'

            if has_pe or has_elf:
                # Check for PKCS#7 / Authenticode
                has_pkcs7_der = _PKCS7_SIGNED_DATA_DER in raw
                has_pem       = _PEM_PKCS7 in raw or _PEM_CERT in raw
                has_win_cert  = any(m in raw for m in _WIN_CERT_MAGIC)

                if not (has_pkcs7_der or has_pem or has_win_cert):
                    img_type = 'PE (UEFI)' if has_pe else 'ELF kernel'
                    findings.append(PKIFinding(
                        'uefi_authenticode',
                        f'{img_type} image lacks PKCS#7 signedData OID, PEM certificates, and WIN_CERT structure',
                        'HIGH',
                    ))

        # Check 2: IMA / dm-verity boot parameters
        ima_found = [s for s in _IMA_STRINGS if s in raw]
        if not ima_found:
            findings.append(PKIFinding(
                'ima_dm_verity',
                'No IMA policy parameters or dm-verity root hash strings found in image',
                'MEDIUM',
            ))

        # Check 3: Any certificate material at all
        has_any_cert = (
            _PKCS7_SIGNED_DATA_DER in raw
            or _PEM_PKCS7 in raw
            or _PEM_CERT in raw
            or any(s in raw for s in [b'signature@', b'key-name-hint'])
        )
        if not has_any_cert:
            findings.append(PKIFinding(
                'no_certificate_material',
                'No X.509 certificate material, PKCS#7 envelope, or U-Boot key node found anywhere in image',
                'HIGH',
            ))

        return findings

    def report(self, findings: Optional[List[PKIFinding]] = None) -> str:
        if findings is None:
            findings = self.scan()
        if not findings:
            return f'FirmwarePKIChecker: PKI structures present in {self._path}'
        lines = [f'FirmwarePKIChecker: {len(findings)} absence(s) in {self._path}', '']
        for f in findings:
            lines.append(f.fmt())
            lines.append('')
        return '\n'.join(lines)
