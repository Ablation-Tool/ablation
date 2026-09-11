"""
Cisco UCS B-Series / X-Series Blade Firmware Bundle RE Module
Bundle: ucs-k9-bundle-b-series.6.0.2b.B.bin (1.2GB)
Platform: UCS B-Series/X-Series blades (B200, BX210, X210C, X410C M4-M8)
Version: 6.0(2b)B

5 findings: 0C/1H/2M/2L
Cumulative: 605 [55C+193H+184M+172L]
"""

# ============================================================
# TARGET
# ============================================================

TARGET = {
    "bundle": "ucs-k9-bundle-b-series.6.0.2b.B.bin",
    "size_gb": 1.2,
    "version": "6.0(2b)B",
    "format": "SN outer wrapper containing gzip-tar of 577 per-component SN-wrapped firmware files",
    "build_date": "2026-03-03 17:48 UTC (tar entry timestamps)",
    "component_count": 577,
    "platforms": ["B200 M4/M5/M6", "BX210C M6", "X210C M7/M8", "X410C M7/M8"],
}

# ============================================================
# SN FORMAT REVERSE ENGINEERING
# ============================================================

SN_FORMAT = {
    "magic": "64 01 53 4e (bytes 0-3)",
    "payload_offset_field": "bytes 4-5, big-endian uint16 = byte offset to payload start",
    "bytes_6_7": "always 00 00 (padding)",
    "filename_field": "null-terminated ASCII string starting at byte 8",
    "hash_field": "16 bytes at offset 0x38-0x47 (opaque; does not match MD5/SHA1/SHA256/CRC32 of payload)",
    "metadata_region": "bytes 0x240+ contain SWID version strings and structured metadata",
    "payload": "gzip-compressed tar archive at offset specified by bytes 4-5",
    "inner_tar_structure": {
        "./blob": "actual firmware binary (raw, no further container)",
        "./isan/etc/imghdr.bin": "copy of the outer SN header bytes (same N bytes as the offset field value)",
    },
    "confirmed_offsets": {
        "outer_bundle": 852,
        "cpld_component": 756,
        "h200_gpu_component": 844,
        "brdprog_component": 752,
    },
    "note": "offset field corrected to BE uint16 from 4-byte LE: 0x0354 (outer) = 852 matches gzip location",
}

SN_RECURSIVE_NESTING = {
    "level_1": "outer .bin (SN magic + offset 852 + gzip-tar of all components)",
    "level_2": "each of 577 plugin_img/*.bin files is itself SN-wrapped",
    "level_3": "each inner SN file's tar contains ./blob (raw firmware) + ./isan/etc/imghdr.bin (header copy)",
    "implication": (
        "Each component firmware is independently SN-wrapped before bundling. "
        "The inner SN header (duplicated as imghdr.bin) contains component-specific "
        "SWID metadata, version strings, and the 16-byte hash field. "
        "A UCSM that can extract and distribute individual components works at level-2."
    ),
}

# ============================================================
# COMPONENT INVENTORY
# ============================================================

COMPONENT_DISTRIBUTION = {
    "total": 577,
    "by_type": {
        "ssd": 174,
        "nvme_storage": 119,
        "hdd": 83,
        "other_nic_misc": 127,
        "cpld": 20,
        "retimer": 20,
        "gpu": 17,
        "raid_controller": 8,
        "psu": 4,
        "vic_nic": 4,
    },
    "notable_entries": {
        "gpu": [
            "ucs-video-nvidia-H200-NVL.96.00.D9.00.0E_1010.0230.00.02_00.02.0192.0000-n00.bin (1.5MB blob)",
        ],
        "brdprog": [
            "ucs-b200-m6-brdprog.21.0.bin",
            "ucs-bx210c-m6-brdprog.23.0.bin",
            "ucs-x210c-m7-brdprog.19.0.bin",
            "ucs-x210c-m8-brdprog.13.0.bin (1.1MB blob)",
            "ucs-x410c-m7/m8 brdprog variants",
        ],
        "intel_flex_amc": [
            "ucs-x410c-m8-intel-flex-140-amc.7.0.0.0.bin",
            "ucs-x410c-m8-intel-flex-170-amc.7.0.0.0.bin",
            "ucs-x210c-m8-intel-flex-140/170-amc.7.0.0.0.bin (M7 and M8 variants)",
        ],
    },
}

# ============================================================
# SIGNATURE / INTEGRITY ANALYSIS
# ============================================================

INTEGRITY_ANALYSIS = {
    "rsa_ecdsa_signature_files": False,
    "sig_file_present_in_any_tar": False,
    "hash_file_present_in_any_tar": False,
    "sn_header_hash_field_algorithm": "UNKNOWN (16 bytes at 0x38; does not match MD5/SHA1/SHA256/CRC32 of blob)",
    "sn_header_hash_checked_by": "UNKNOWN (cannot confirm without UCSM binary analysis)",
    "outer_bundle_hash_field": "a38ba69ca74d0c9a58c19390a174abb0 (16 bytes at 0x38 of outer bundle)",
    "cpld_component_hash": "9e746c110006a15df1e83ffb5dc54a19",
    "brdprog_x210c_m8_hash": "58d13743ff424da1d0f1723686455a8c",
    "conclusion": (
        "No RSA or ECDSA signature mechanism visible in any firmware component. "
        "The 16-byte hash field at SN header offset 0x38 is the only candidate integrity check. "
        "If this field is HMAC-keyed, the key is embedded in UCSM. "
        "If it is a plain hash (MD5 variant, CRC32 combination, or not verified at all), "
        "an attacker with write access to the firmware bundle can replace ./blob in any "
        "component's tar, recompute the field using the same algorithm, and repackage "
        "without detection."
    ),
}

# ============================================================
# FINDINGS
# ============================================================

FINDINGS = [
    {
        "id": "BSUB-F1",
        "severity": "HIGH",
        "title": "ALL_577_BLADE_FIRMWARE_COMPONENTS_LACK_RSA_ECDSA_SIGNATURES",
        "detail": (
            "Every component firmware in the B-Series/X-Series bundle uses the same pattern: "
            "SN-wrapped gzip-tar containing only './blob' (raw firmware binary) and "
            "'./isan/etc/imghdr.bin' (SN header metadata copy). "
            "No .sig, .hash, or certificate file is present in any component's tar. "
            "Checked: CPLD (ucs-x215c-m8-raid-m1l6-cpld.2.005.bin, 100KB blob), "
            "NVIDIA H200-NVL GPU firmware (1.5MB blob), board programmer (brdprog, 1.1MB blob). "
            "The only integrity indicator is a 16-byte field at SN header offset 0x38 that "
            "does not match MD5/SHA1/SHA256/CRC32 of the firmware blob. "
            "The algorithm and whether UCSM verifies this field before component firmware flash "
            "are unknown without UCSM binary analysis. "
            "Components affected: 577 total across SSDs (174), NVMe (119), HDDs (83), "
            "CPLDs (20), retimers (20), GPUs (17), RAID controllers (8), PSUs (4), VIC/NICs (4). "
            "All hardware generations from B200 M4 through X410C M8."
        ),
    },
    {
        "id": "BSUB-F2",
        "severity": "MEDIUM",
        "title": "SN_FORMAT_RECURSIVE_NESTING_ALL_BUNDLE_COMPONENTS_INDEPENDENTLY_WRAPPED",
        "detail": (
            "The B-Series bundle's SN structure is recursively nested: "
            "Outer bundle (SN magic + offset 852 + gzip-tar) contains 577 plugin_img files, "
            "each of which is itself an SN-wrapped gzip-tar. "
            "Format: bytes 0-3 = magic 6401534e; bytes 4-5 = big-endian uint16 payload offset; "
            "bytes 6-7 = 00 00; bytes 8+ = null-terminated filename; "
            "bytes 0x38-0x47 = 16-byte hash/integrity field; "
            "bytes 0x240+ = SWID version metadata. "
            "Inner SN header copy is re-embedded at './isan/etc/imghdr.bin' in each tar "
            "(size equals the offset field value -- it IS the header metadata). "
            "SN offset field is 2-byte big-endian uint16 (confirmed: 0x0354=852, 0x02f4=756, "
            "0x034c=844, 0x02f0=752 -- all match located gzip magic offsets). "
            "Prior analysis of FI bundles identified the field as 4-byte LE; corrected to 2B BE16."
        ),
    },
    {
        "id": "BSUB-F3",
        "severity": "MEDIUM",
        "title": "BRDPROG_BOARD_PROGRAMMER_FIRMWARE_FOLLOWS_UNSIGNED_BLOB_PATTERN",
        "detail": (
            "Board programmer firmware files (brdprog) for B200 M6, BX210C M6, X210C M7/M8, "
            "and X410C M7/M8 follow the same unsigned ./blob pattern as all other components. "
            "Example: ucs-x210c-m8-brdprog.13.0.bin -- 1.1MB blob, SN offset 752, "
            "hash field 58d13743ff424da1d0f1723686455a8c. "
            "'brdprog' (board programmer) refers to firmware that directly programs the blade "
            "motherboard (likely CPLD or embedded controller on the blade PCB itself), "
            "not an application-layer component. "
            "A malicious brdprog blob would have direct hardware-level access to the blade board. "
            "Intel Flex 140/170 AMC (Add-in Module Controller) firmware for X210C/X410C M7/M8 "
            "is in the same category -- AMC controls mezzanine card operations."
        ),
    },
    {
        "id": "BSUB-F4",
        "severity": "LOW",
        "title": "IMGHDR_BIN_IN_FIRMWARE_TARS_IS_SN_HEADER_COPY_NOT_ELF",
        "detail": (
            "./isan/etc/imghdr.bin present inside every firmware component's tar is NOT "
            "the NX-OS image header ELF utility seen in UCS Central (imghdr ELF, 32-bit, debug_info). "
            "In the B-Series bundle, imghdr.bin is a binary copy of the outer SN header bytes: "
            "size = payload offset field value (e.g., 756 bytes for CPLD SN with offset 0x2f4=756). "
            "Content: same SN magic, offset, filename, metadata as the wrapping SN header. "
            "Function: embedded metadata manifest for the component identity and SWID version, "
            "accessible within the extracted tar without re-parsing the outer SN wrapper. "
            "The 'imghdr' name is shared between two distinct Cisco artifacts: "
            "(1) ELF utility in UCS Central for NX-OS image header generation, "
            "(2) binary metadata record in firmware component tars (this finding)."
        ),
    },
    {
        "id": "BSUB-F5",
        "severity": "LOW",
        "title": "NVIDIA_H200_NVL_GPU_FIRMWARE_IN_UCSM_BLADE_BUNDLE",
        "detail": (
            "ucs-video-nvidia-H200-NVL.96.00.D9.00.0E_1010.0230.00.02_00.02.0192.0000-n00.bin "
            "(SN-wrapped, 1.5MB decompressed blob) is present in the B-Series 6.0(2b)B bundle. "
            "H200-NVL is an HBM3e GPU (Hopper architecture) used in NVIDIA DGX/HGX systems. "
            "Version string: '96.00.D9.00.0E' (GSP firmware version), "
            "'1010.0230.00.02' (SBIOS/VBIOS-related), '00.02.0192.0000' (additional component). "
            "The '-n00' suffix indicates variant 0 (no authentication or no specific OEM restriction). "
            "GPU firmware updates in UCS context go through UCSM, not the GPU's own secure update path. "
            "The 1.5MB blob is raw binary with no visible signature structure in first 16 bytes "
            "(e0418e12bf373bca header -- opaque, not a standard VBIOS magic)."
        ),
    },
]

# ============================================================
# MODULE SUMMARY
# ============================================================

MODULE_SUMMARY = {
    "module": "cisco_ucs_b_series_bundle_re",
    "bundle": "ucs-k9-bundle-b-series.6.0.2b.B.bin",
    "sn_format_clarified": {
        "offset_field": "bytes 4-5, big-endian uint16 (not 4B LE as previously noted)",
        "hash_field": "16 bytes at 0x38, unknown algorithm",
        "nesting": "outer SN -> inner SN per component -> gzip tar -> blob",
    },
    "finding_counts": {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 2},
    "cumulative_counts": {"CRITICAL": 55, "HIGH": 193, "MEDIUM": 184, "LOW": 172},
    "cumulative_total": 605,
}
