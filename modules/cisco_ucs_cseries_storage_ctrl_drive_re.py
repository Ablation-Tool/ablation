"""
Cisco UCS C-Series -- Rio Beach Storage Controller, Marvell M2 HWRAID, Solidigm/Samsung SSD RE
Targets: ucs-storage-controller-riobeach.8.10.1.0, ucs-storage-controller-m2-hwraid-marvell.2.3.17.2002,
         ucs-ssd-solidigm-SSDSC2K*, ucs-ssd-samsung-MZ7L3*, ucs-hdd-seagate/toshiba

Rio Beach is Marvell-based, plaintext, with complete PKI certificate validation chain exposed.
Solidigm SSDs use Intel FPT format (06000000) with drive debug state strings.
"""

RIO_BEACH = {
    "product": "ucs-storage-controller-riobeach",
    "fw_version": "8.10.1.0-00065-00002",
    "bundle_member": "./isan/plugin_img/ucs-storage-controller-riobeach.8.10.1.0-00065-00002.bin",
    "raw_size_kb": 5459,
    "packaging": "SN -> gzip -> inner TAR -> ./blob (ZIP, unencrypted) -> Rio_Beach_full_fw_vsn_pkg_signed.rom",
    "rom_size_kb": 13012,
    "rom_md5": "cd7302e8ae62870661869a80ce096ff6",
    "rom_encryption": "plaintext",
    "security_strings": {
        "security_version": [
            "%08x Security Version check failure. Status %08x",
            "%08x Security Version check passed",
        ],
        "kek": "Unable to fill KEK keys - status = %x",
        "efuse": [
            "Efuse debug:",
            "SBLI GetSecVer: PtrSecurityVersion=%d",
        ],
        "cert_validation": [
            "no ASN1 CertLen %08x",
            "Error: Unexpected type %02x length %x nextOffset %x end %x",
            "ERROR OID Mismatch",
            "Comparing image signature to computed SHA%d",
            "Signatures match, image verified.",
            "Valid PubKey/Hash Evaluate %d",
        ],
        "pubkey_hash": [
            "Examining Public key Hash %d",
            "Public key hash %d found in the eFuse memory.",
            "Hashed Keys Do No Match:",
            "Good key, Generate hash.",
            "Generated public key hash",
            "KeySize %08x",
        ],
        "key_management": [
            "New Key %d status is invalid (0x%02X)",
            "Invalidating key %d",
            "Key %d status is not invalid (0x%02X)",
            "Failed check of existing key, invalidate slot %d",
        ],
        "hw_check": "Image is designed for different HW Found:%x",
    },
    "fault_strings": [
        "Translation Fault",
        "Access Flag Fault",
        "Permission Fault",
        "Parity Error Sync:%d",
        "AltCore in Fault %x, Fault %x on core %x!!!!",
        "Sec core detected recursive fault, going to WFI",
        "ERROR - Stack Range 0x%08x",
    ],
}

MARVELL_M2 = {
    "product": "ucs-storage-controller-m2-hwraid-marvell",
    "fw_version": "2.3.17.2002",
    "rom_name": "ImageA1-2002.bin",
    "rom_size_kb": 2048,
    "rom_encryption": "plaintext",
    "packaging": "SN -> gzip -> inner TAR -> ./blob (ZIP) -> ImageA1-2002.bin",
}

SOLIDIGM_SSD = {
    "vendor": "Solidigm (Intel NAND, SK Hynix acquisition 2021)",
    "sample_product": "SSDSC2KB480GZK",
    "fw_version": "7CV1CS05",
    "format": "Intel FPT (06000000a1000000 magic)",
    "size_kb": 1428,
    "debug_strings": [
        "*INITIALIZED",
        "*DISLOG_ADU_HARD",
        "*NO_SPACE",
        "*BAD_CONTEXT",
        "*NO_CONTEXT",
    ],
    "note": "Unlike PMEM (PMEM-F1 fully encrypted), Solidigm SSDs expose debug state strings",
}

SAMSUNG_SSD = {
    "vendor": "Samsung",
    "sample_product": "MZ7L37T6HELA-00AK1",
    "fw_version": "JXTG2F3Q",
    "format": "Samsung proprietary (magic 49d1aca3)",
    "size_kb": 2560,
    "metadata_leak": "FW_IMAGE_META_SIGNATURE_________JXTG2F3Q1-",
    "note": "Firmware version visible in metadata header; content otherwise opaque",
}

DRIVE_FORMATS = {
    "Seagate SAS": {"magic": "e71a0e59", "encryption": "proprietary"},
    "Toshiba SAS": {"magic": "464d434c20204d47", "meaning": "FMCL  MG (Toshiba FMCL format)"},
    "Samsung SSD": {"magic": "49d1aca3", "encryption": "proprietary Samsung format"},
    "Solidigm SSD": {"magic": "06000000", "format": "Intel FPT (same as PMEM)"},
    "Micron NVMe": {"magic": "variable", "note": "analyzed separately (PMEM module)"},
}

NC3220 = {
    "product": "ucs-adaptor-ucsc-p-NC3220",
    "fw_version": "32.46.1006",
    "raw_size_mb": 425,
    "sn_hsize": 764,
    "gzip_offset": 764,
    "note": "Largest single firmware entry in C-Series bundle; VIC 1500 Copper adapter; decompresses to estimated 1GB+; deferred",
}

FINDINGS = {
    "RIOBEACH-F1": {
        "id": "RIOBEACH-F1",
        "severity": "HIGH",
        "title": "Rio Beach storage controller plaintext 13MB ROM exposes full PKI signing chain: eFuse key slots, KEK, SHA verification, ASN1/OID parsing, key invalidation",
        "affected": ["ucs-storage-controller-riobeach (8.10.1.0-00065-00002)"],
        "evidence": {
            "rom_encryption": "plaintext (ZIP unencrypted, like SmartIOC pattern)",
            "efuse_debug": "Efuse debug: / SBLI GetSecVer: PtrSecurityVersion=%d",
            "kek": "Unable to fill KEK keys - status = %x",
            "pubkey": "Public key hash %d found in the eFuse memory. (indexed slots)",
            "key_invalidation": "Invalidating key %d / Failed check of existing key, invalidate slot %d",
            "cert_chain": "Comparing image signature to computed SHA%d / ERROR OID Mismatch / no ASN1 CertLen",
            "hw_check": "Image is designed for different HW Found:%x",
            "security_version": "%08x Security Version check failure. Status %08x",
        },
        "mechanism": (
            "Rio Beach HBA/RAID firmware (13MB ROM, Marvell-based) is distributed in plaintext. "
            "The ROM exposes the complete secure boot / code signing chain: "
            "(1) eFuse security version checking (SBLI GetSecVer) with debug output; "
            "(2) KEK (Key Encryption Key) loading with failure path exposed; "
            "(3) Multiple indexed public key hash slots in eFuse memory (hash %d); "
            "(4) Key invalidation mechanism (slot invalidation + recursive fault guard); "
            "(5) ASN1/OID certificate parsing with error strings; "
            "(6) SHA hash comparison for image signature verification; "
            "(7) HW version check ('Image is designed for different HW Found:%x'). "
            "The full error string set enables reconstructing the PKI validation state machine "
            "and identifying failure conditions that could be leveraged for rollback."
        ),
        "impact": "Plaintext PKI chain enables full recovery of signing architecture, eFuse key slot numbering, and failure conditions; key invalidation path exposure aids rollback/bypass analysis",
    },
    "SOLIDIGM-F1": {
        "id": "SOLIDIGM-F1",
        "severity": "LOW",
        "title": "Solidigm SSDs use Intel FPT format (06000000) with drive debug state strings exposed; contrast with fully-encrypted PMEM",
        "affected": ["ucs-ssd-solidigm-SSDSC2KB*/SSDSC2KG* (7CV1CS05)"],
        "evidence": {
            "format": "Intel FPT (06000000a1000000 -- same magic as PMEM DIMM/BPS)",
            "debug_strings": ["*INITIALIZED", "*DISLOG_ADU_HARD", "*NO_SPACE", "*BAD_CONTEXT", "*NO_CONTEXT"],
            "version_visible": "7CV1CS05 readable in firmware",
        },
        "mechanism": (
            "Solidigm SSDs (post-Intel NAND) use the Intel FPT firmware format (magic 06000000) -- "
            "the same format as PMEM DIMM/BPS (PMEM-F1). However, unlike PMEM (fully encrypted payload), "
            "Solidigm SSD firmware exposes drive internal state strings: "
            "*DISLOG_ADU_HARD (abnormal disconnect during ADU hard log), "
            "*NO_SPACE/*NO_CONTEXT/*BAD_CONTEXT (drive state machine error conditions), "
            "*INITIALIZED (initialization state marker). These are the drive's internal "
            "diagnostic state identifiers. Intel FPT format without encryption in SSDs "
            "vs full encryption in PMEM shows Solidigm's differential encryption posture."
        ),
        "impact": "Drive state machine error conditions exposed; diagnostic state identifiers available for firmware analysis; FPT format without PMEM-level encryption",
    },
    "MARVELL-M2-F1": {
        "id": "MARVELL-M2-F1",
        "severity": "LOW",
        "title": "Marvell M2 HWRAID ships plaintext firmware (ImageA1-2002.bin, 2MB) in plaintext ZIP",
        "affected": ["ucs-storage-controller-m2-hwraid-marvell (2.3.17.2002)"],
        "evidence": {
            "encryption": "plaintext ZIP -> plaintext 2MB ImageA1-2002.bin",
            "format": "Marvell firmware image (A1 stepping, version 2002)",
        },
        "mechanism": "M2 NVMe HWRAID Marvell controller ships plaintext 2MB firmware in plaintext ZIP -- no protection vs SmartIOC/Rio Beach pattern; enables direct binary analysis",
        "impact": "Plaintext firmware enables direct binary analysis; A1 stepping marker reveals validation stage",
    },
}

ALL_FINDINGS = list(FINDINGS.values())

SUMMARY = {
    "module": "cisco_ucs_cseries_storage_ctrl_drive_re",
    "targets": "Rio Beach, Marvell M2 HWRAID, Solidigm SSD, Samsung SSD, HDD formats",
    "total_findings": len(ALL_FINDINGS),
    "by_severity": {"HIGH": 1, "MEDIUM": 0, "LOW": 2},
    "headline": (
        "Rio Beach controller plaintext 13MB ROM exposes full PKI signing chain: "
        "indexed eFuse key slots, KEK, SHA verification, ASN1/OID, key invalidation. "
        "Solidigm SSDs use Intel FPT format (like PMEM) but without encryption, "
        "exposing drive state machine error identifiers."
    ),
    "nc3220_note": "NC3220 VIC (425MB raw) deferred -- would decompress to estimated 1GB+",
    "drive_format_survey": DRIVE_FORMATS,
}

if __name__ == "__main__":
    for f in ALL_FINDINGS:
        print(f"[{f['severity']:6s}] {f['id']}: {f['title']}")
    print(f"\nTotal: {SUMMARY['total_findings']} findings "
          f"({SUMMARY['by_severity']['HIGH']}H/"
          f"{SUMMARY['by_severity']['MEDIUM']}M/"
          f"{SUMMARY['by_severity']['LOW']}L)")
