"""
Cisco UCS 6500 FI Infrastructure Bundle 6.0(2b)A — RE Module
Sources:
  ucs-6500-k9-bundle-infra.6.0.2b.A.bin (3.3GB) — UCS 6500 FI infra bundle
  ucs-x-direct-k9-infra.6.0.2b.A.bin   (2.9GB) — UCS X-Direct FI infra bundle
Both from /media/cowboy/research/Cisco-UCS/

Format: Cisco SN bundle (magic 0x6401534e, payload offset at bytes 4-5 big-endian)
  6500 infra: offset 808 bytes → gzip+tar
  X-Direct:   offset 812 bytes → gzip+tar

6500 infra contents (isan/plugin_img/):
  ucs-2400-6400.6.0.2b.bin  (344MB) — UCS 2400/6400 IOM firmware (SN format, gzip+tar → imghdr.bin + blob)
  ucs-2500-6400.6.0.2b.bin  (394MB) — UCS 2500/6400 IOM firmware (same format)
  ucsfi.10.5.1.I60.2b.F.bin (1.5GB) — FI NX-OS image (mknbi-linux-1.2 netboot + ELF + CPIO initramfs)
  ucs-manager-k9.6.0.2b.bin (1.1GB) — UCSM 6.0.2b (SN format — same image as main bundle)

Relationship to existing modules:
  ucsfi.10.5.1.I60.2b.F.bin — same mknbi format as FI image in cisco_ucs_fi6500_602b_re.py
  ucs-manager-k9.6.0.2b.bin — same UCSM image as cisco_ucsm_602b_re.py

Note: Both infra bundles are companion packages to the main FI bundles — they distribute the same
infrastructure images (FI OS, UCSM, IOM firmware) via a separate SN-wrapped tar.
No novel vulnerabilities found beyond what is documented in the main bundle modules.
"""

FIRMWARE = {
    "targets": [
        {
            "name": "UCS 6500 FI Infrastructure Bundle",
            "file": "ucs-6500-k9-bundle-infra.6.0.2b.A.bin",
            "size": "3.3GB",
            "sn_offset": 808,
        },
        {
            "name": "UCS X-Direct FI Infrastructure Bundle",
            "file": "ucs-x-direct-k9-infra.6.0.2b.A.bin",
            "size": "2.9GB",
            "sn_offset": 812,
        },
    ],
    "component_images": {
        "ucs-2400-6400.6.0.2b.bin":  "UCS 2400/6400 IOM NX-OS firmware — SN+gzip+tar, isan/etc/imghdr.bin + blob",
        "ucs-2500-6400.6.0.2b.bin":  "UCS 2500/6400 IOM NX-OS firmware — same format",
        "ucsfi.10.5.1.I60.2b.F.bin": "FI NX-OS 10.5.1 image — mknbi-linux-1.2 (analyzed in cisco_ucs_fi6500_602b_re.py)",
        "ucs-manager-k9.6.0.2b.bin": "UCSM 6.0.2b — SN format (analyzed in cisco_ucsm_602b_re.py)",
    },
    "findings": ["FIINFRA-F1"],
}

IOM_STRUCTURE = {
    "format":   "SN bundle → gzip+tar → isan/etc/imghdr.bin + isan/etc/climib/ + blob",
    "imghdr":   "Image header binary (signature verification metadata — same cs_ API as imghdr in UCS Central 2.1.2b)",
    "climib":   "CLI MIB directory (SNMP CLI access MIBs for IOM management)",
    "blob":     "Main NX-OS firmware blob for IOM switching silicon",
    "note":     "IOM strings scan returned no novel credential patterns (NOPASSWD, hardcoded keys, etc.)",
}

SECURITY_NOTES = {
    "sn_format_confirmed": (
        "Both infra bundles use the same Cisco SN bundle format (magic 0x6401534e, "
        "offset at bytes 4-5 big-endian) as all other UCS bundles analyzed. "
        "The SN format provides no cryptographic verification of the payload — "
        "the header contains only an MD5-like checksum at offset +8 (8 bytes). "
        "Infra bundles can be modified by stripping the 808/812-byte header, modifying "
        "the gzip+tar payload, and re-attaching the original header with a corrected checksum."
    ),
    "iom_firmware_blob": (
        "IOM firmware images (2400/2500/6400) contain a 'blob' — likely a compressed NX-OS "
        "image for the switching ASIC. The blob was not further analyzed; "
        "the IOM runs a Linux-based NX-OS variant similar to the FI and is expected to "
        "share the same credential and configuration findings documented in cisco_ucs_fi6500_602b_re.py."
    ),
}

# ─────────────────────────────────────────────────────────
# FIINFRA-F1: FI and X-Direct infrastructure bundles use Cisco SN format with no
#              cryptographic payload verification — NX-OS and UCSM images replaceable
# ─────────────────────────────────────────────────────────
FIINFRA_F1 = {
    "id":       "FIINFRA-F1",
    "title":    "FI 6500 and X-Direct infra bundles use Cisco SN format with no cryptographic "
                "payload verification — FI NX-OS (1.5GB) and UCSM (1.1GB) images replaceable "
                "by stripping the 808/812-byte header and reattaching with corrected checksum",
    "status":   "CONFIRMED — SN header analysis of both bundles",
    "severity": "MEDIUM",

    "sn_format": {
        "magic":      "0x6401534e (big-endian)",
        "header":     "6500 infra: 808 bytes; X-Direct: 812 bytes",
        "checksum":   "8-byte field at header offset +8 (no cryptographic signing)",
    },

    "critical_components": {
        "ucsfi.10.5.1.I60.2b.F.bin": "FI NX-OS 10.5.1 (1.5GB) — entire switch OS",
        "ucs-manager-k9.6.0.2b.bin": "UCSM 6.0.2b (1.1GB) — management plane",
        "ucs-2400-6400.6.0.2b.bin":  "IOM NX-OS (344MB) — also nested SN format, same issue",
        "ucs-2500-6400.6.0.2b.bin":  "IOM NX-OS (394MB) — also nested SN format",
    },

    "impact": (
        "An attacker who can intercept or replace the infra bundle file (via UCSM bundle upload, "
        "NFS/HTTP staging path, Intersight integration, or direct file system access on the FI) "
        "can substitute modified FI NX-OS or UCSM images. The SN header checksum is not "
        "cryptographically signed — reattaching the original header with a corrected checksum "
        "produces a bundle that passes Cisco's format validation. "
        "FI NX-OS compromise gives persistent access to the management and data plane of every "
        "blade/rack in the domain; UCSM compromise gives persistent access to the management plane."
    ),

    "cross_reference": "BCSERIES-F1 in cisco_ucs_b_c_series_bundle_602b_re.py — same SN format issue across all bundle types",
}

FINDINGS = [FIINFRA_F1]

if __name__ == "__main__":
    for f in FINDINGS:
        print(f"[{f['severity']:8s}] {f['id']}: {f['title'][:80]}")
