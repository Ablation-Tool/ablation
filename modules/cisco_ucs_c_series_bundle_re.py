"""
Cisco UCS C-Series / S-Series UCSM Firmware Bundle RE Module
Bundle: ucs-k9-bundle-c-series.6.0.2b.C.bin (3.1GB)
Platform: UCS C-Series/S-Series rack servers (C125/C220/C225/C240/C245/C480/S3260 M5-M8)
Version: 6.0(2b)C

6 findings: 0C/2H/2M/2L
Cumulative: 611 [55C+195H+186M+174L]
"""

# ============================================================
# TARGET
# ============================================================

TARGET = {
    "bundle": "ucs-k9-bundle-c-series.6.0.2b.C.bin",
    "size_gb": 3.1,
    "version": "6.0(2b)C",
    "format": "SN outer wrapper + gzip-tar + 723 per-component SN-wrapped firmware files",
    "platforms": [
        "C125 M5", "C220 M5/M6/M7/M8", "C225 M6/M8",
        "C240 M5/M6/M7/M8", "C245 M6/M8", "C480 M5", "S3260 M5",
    ],
}

# ============================================================
# COMPONENT INVENTORY
# ============================================================

COMPONENT_DISTRIBUTION = {
    "total": 723,
    "by_type": {
        "ssd": 181,
        "other_adapters_misc": 164,
        "nvme_storage": 156,
        "hdd": 126,
        "bios_cimc_brdprog": 46,
        "gpu": 31,
        "retimer": 2,
        "cpld": 5,
        "raid_psoc": 5,
        "vic_nic_lom": 6,
        "imghdr_metadata": 1,
    },
    "bios_cimc_brdprog_breakdown": {
        "bios_files": [
            "ucs-c220-m5-bios.C220M5.4.3.2g.0.0116260835.bin",
            "ucs-c220-m6-bios.C220M6.6.0.2a.0.0121260813.bin",
            "ucs-c220-m7-bios.C220M7.6.0.2a.0.0130261651.bin",
            "ucs-c220-m8-bios.C220M8.6.0.2a.0.0126261758.bin",
            "ucs-c225-m6-bios.C225M6.6.0.2a.0.0120262146.bin",
            "ucs-c225-m8-bios.C225M8.6.0.2a.0.0121261128.bin",
            "ucs-c240-m5-bios.C240M5.4.3.2h.0.0116260835.bin",
            "ucs-c240-m6-bios.C240M6.6.0.2a.0.0121260813.bin",
            "ucs-c240-m7-bios.C240M7.6.0.2a.0.0130261651.bin",
            "ucs-c240-m8-bios.C240M8.6.0.2a.0.0126261758.bin",
            "ucs-c245-m6-bios.C245M6.6.0.2a.0.0120262146.bin",
            "ucs-c245-m8-bios.C245M8.6.0.2a.0.0121261129.bin",
            "ucs-c480-m5-bios.C480M5.4.3.2g.0.0116260833.bin",
            "ucs-c125-bios.C125.4.3.2h.0.1113252254.bin",
            "ucs-s3260-m5-bios.S3X60M5.4.3.2g.0.0116260834.bin",
        ],
        "cimc_files": [
            "ucs-c220-m5-k9-cimc.4.3.2.260007.bin",
            "ucs-c220-m6-k9-cimc.6.0.2.260044.bin",
            "ucs-c220-m7-k9-cimc.6.0.2.260044.bin",
            "ucs-c245-m8-k9-cimc.6.0.2.260044.bin",
            "ucs-c240-m6-k9-cimc.6.0.2.260044.bin",
            "ucs-intel-rack-m8-k9-cimc.6.0.2.260044.bin",
            "ucs-s3260-m5-k9-cimc.4.3.6.260017.bin",
        ],
        "brdprog_files": [
            "ucs-c220-m5-brdprog.62.0.bin",
            "ucs-c220-m6-brdprog.39.0.bin",
            "ucs-c220-m7-brdprog.37.0.bin",
            "ucs-c220-m8-brdprog.20.0.bin",
            "ucs-c240-m5-brdprog.65.0.bin",
            "ucs-c240-m6-brdprog.42.0.bin",
            "ucs-c240-m7-brdprog.39.0.bin",
            "ucs-c240-m8-brdprog.24.0.bin",
            "ucs-c245-m6-brdprog.29.0.bin",
            "ucs-c245-m8-brdprog.21.0.bin",
            "ucs-c225-m6-brdprog.27.0.bin",
            "ucs-c225-m8-brdprog.12.0.bin",
            "ucs-c480-m5-brdprog.57.0.bin",
            "ucs-c125-brdprog.25.0.bin",
            "ucs-c3260-brdprog.1.0.28.bin",
            "ucs-S3260-brdprog.1.0.28.bin",
            "ucs-bmc-brdprog-S3260M5.10.0.bin",
        ],
    },
}

# ============================================================
# FIRMWARE FORMAT ANALYSIS
# ============================================================

BIOS_PACKAGE_FORMAT = {
    "header_id": "[CISCO UCS BIOS CIMCPackage]",
    "header_version": "HeaderVersion=1",
    "image_offset": "ImageOffset=8192 (BIOS image starts at byte 8192)",
    "example_version": "ImageVersion=C220M8.6.0.2a.0.0126261758",
    "example_size": "ImageByteSize=19442161",
    "signing": {
        "present": True,
        "format": "X.509 certificate subject in plaintext header",
        "cert_subject": "CN=CiscoSystems;OU=BIOS_IMG;O=CiscoSystems",
        "cert_serial": "6977B42F (appears twice in header)",
        "signature_location": "bytes ~1700-8192 in pkg header (before ImageOffset)",
    },
    "blob_structure": "SN gzip-tar -> ./blob -> gzip -> tar -> C220M8-BIOS-6-0-2a-0.pkg (18.5MB)",
    "note": (
        "BIOS .pkg decompresses to a tar containing the single .pkg file. "
        "The .pkg has a 8192-byte header with X.509 PKI signing and the BIOS image follows. "
        "Signing org unit is BIOS_IMG, separate from general Cisco signing."
    ),
}

CIMC_FIRMWARE_FORMAT = {
    "magic": "55 AA (x86 BIOS option ROM / ARM boot marker)",
    "arm_code_at": "offset 8192 (ARM Thumb instructions: BX LR, etc.)",
    "size_example": "134MB (ucs-c245-m8-k9-cimc.6.0.2.260044.bin)",
    "visible_signing": False,
    "embedded_platform_images": [
        "SPLImage-CSeriesM7",
        "SPLImage-ast2600_evb",
        "SPLImage-mountrainier1",
        "SPLImage-mountrainier2",
        "SPLImage-mountadams1",
        "SPLImage-mountadams2",
        "BISImage-CSeriesM7",
        "BISImage-ast2600_evb",
        "BISImage-mountrainier1",
        "BISImage-mountrainier2",
        "BISImage-mountadams1",
        "BISImage-mountadams2",
    ],
    "note": (
        "CIMC = Cisco Integrated Management Controller (AST2600 ARM BMC). "
        "SPL = Secondary Program Loader (U-Boot SPL). "
        "BIS = likely BIOS Image Signature or Board Init Sequence. "
        "Single CIMC binary includes images for all C-Series M7/M8 platform variants. "
        "ast2600_evb is the Aspeed AST2600 evaluation board development target."
    ),
}

BRDPROG_FORMAT = {
    "header_id": "[pkg]",
    "header_version": "headerVersion=2",
    "platform_field": "platform=<codename> (e.g., godzilla1 for C220M8)",
    "tar_offset": "tarOffset=128 (inner tar starts at byte 128)",
    "header_total_size": "128 bytes (null padded after INI text; NO binary signature)",
    "visible_signing": False,
    "inner_tar_contents": [
        "images/brdprog.img (10240 bytes -- board programmer image)",
        "doc/git_info.txt",
        "doc/version.txt (LLF map JSON)",
    ],
    "example_git_info": {
        "branch": "cseries_m8_intel_godz_6_0_1_250007",
        "commit": "46f2b42a3fd3014964b5ed14654c912a04e720de",
        "build_date": "Fri Mar 21 20:11:42 UTC 2025",
    },
}

# ============================================================
# PLATFORM CODENAMES
# ============================================================

CODENAMES = {
    "C220M8": "godzilla1 (in brdprog platform field and git branch cseries_m8_intel_godz_*)",
    "C-Series M7 family": "CSeriesM7 (in CIMC SPLImage/BISImage strings)",
    "Mount Rainier variant 1": "mountrainier1 (in CIMC SPLImage/BISImage strings)",
    "Mount Rainier variant 2": "mountrainier2 (in CIMC SPLImage/BISImage strings)",
    "Mount Adams variant 1": "mountadams1 (in CIMC SPLImage/BISImage strings)",
    "Mount Adams variant 2": "mountadams2 (in CIMC SPLImage/BISImage strings)",
    "CIMC dev board": "ast2600_evb (Aspeed AST2600 evaluation board, present in production)",
    "note": "Mount Rainier and Mount Adams are Washington state mountains (C245/C240 M8 candidates)",
}

# ============================================================
# FINDINGS
# ============================================================

FINDINGS = [
    {
        "id": "CSUB-F1",
        "severity": "HIGH",
        "title": "ASYMMETRIC_SIGNING_BIOS_HAS_X509_PKI_CIMC_BRDPROG_LACK_PACKAGE_LEVEL_SIGNING",
        "detail": (
            "BIOS firmware uses a signed CIMCPackage format with explicit X.509 metadata: "
            "header '[CISCO UCS BIOS CIMCPackage]' contains "
            "'CN=CiscoSystems;OU=BIOS_IMG;O=CiscoSystems' with cert serial 6977B42F. "
            "BIOS image occupies bytes 8192+ of the 8192-byte signed header. "
            "CIMC firmware (C245M8 CIMC = 134MB) uses a '55AA' binary format "
            "with ARM code at offset 8192 -- no plaintext PKI header, no visible signing metadata. "
            "brdprog firmware uses a '[pkg]' format with 128-byte header: "
            "INI-format key-value pairs null-padded to 128 bytes -- NO binary signature, "
            "no X.509 metadata, nothing after the null padding. "
            "BIOS (memory region visible to CPU software, attack target for persistence) has PKI. "
            "CIMC (ARM BMC firmware with full out-of-band access) and brdprog "
            "(board programmer that programs embedded controllers on the blade PCB) "
            "lack visible package-level PKI signing."
        ),
    },
    {
        "id": "CSUB-F2",
        "severity": "HIGH",
        "title": "CIMC_134MB_BUNDLE_EMBEDS_AST2600_EVB_EVAL_BOARD_BUILD_TARGET_IN_PRODUCTION",
        "detail": (
            "The production CIMC firmware (ucs-c245-m8-k9-cimc.6.0.2.260044.bin, 134MB) "
            "contains embedded image identifiers: "
            "'SPLImage-ast2600_evb' and 'BISImage-ast2600_evb'. "
            "ast2600_evb is the Aspeed AST2600 evaluation board development target -- "
            "a breadboard/prototype platform, not a production server. "
            "The eval board SPL/BIS images are included alongside the production targets: "
            "mountrainier1/2 (C245M8 or C220M8 variants) and mountadams1/2. "
            "A CIMC that loads the wrong platform image (ast2600_evb instead of mountrainier1) "
            "would initialize BMC hardware with evaluation board parameters -- "
            "wrong GPIO mappings, wrong clock configuration, or wrong memory layout. "
            "Presence of eval board target in production also reveals the AST2600-based development "
            "environment structure and any eval board-specific debug features "
            "that may not be enabled in the production path."
        ),
    },
    {
        "id": "CSUB-F3",
        "severity": "MEDIUM",
        "title": "BRDPROG_GIT_COMMIT_AND_BRANCH_NAME_IN_PRODUCTION_DOC_ARTIFACTS",
        "detail": (
            "brdprog firmware for C220M8 (ucs-c220-m8-brdprog.20.0.bin) includes: "
            "doc/git_info.txt containing build timestamp 'Fri Mar 21 20:11:42 UTC 2025', "
            "branch 'cseries_m8_intel_godz_6_0_1_250007', "
            "commit '46f2b42a3fd3014964b5ed14654c912a04e720de'. "
            "doc/version.txt contains the LLF (Low Level Firmware) component version map: "
            "{'FBP': '24071003', 'FBP_1U10NVME': '22061120', 'standby': '22070102', ...}. "
            "git commit hash discloses the exact Cisco internal git repo commit used to build "
            "this production artifact. "
            "Branch name 'cseries_m8_intel_godz_*' confirms godzilla1=C220M8 and "
            "Intel platform reference. "
            "LLF version map exposes internal component naming (FBP, standby, 1U10NVME variants) "
            "and their version cross-references."
        ),
    },
    {
        "id": "CSUB-F4",
        "severity": "MEDIUM",
        "title": "C_SERIES_723_PERIPHERAL_COMPONENTS_UNSIGNED_SN_BLOB_PATTERN",
        "detail": (
            "All 723 C-Series bundle components use the same SN-wrapped unsigned blob pattern "
            "as B-Series: gzip-tar containing only './blob' + './isan/etc/imghdr.bin'. "
            "No .sig or certificate file in any component tar. "
            "C-Series extends coverage beyond B-Series with: BIOS for 15 platform variants, "
            "CIMC for 7 variants, brdprog for 17 platforms, Intel network adapters "
            "(N6/N7/M6 series at 22-28 Gbps), NVIDIA RTX PRO 6000 GPU, RAID controller PSoC. "
            "The SN hash field at header offset 0x38 is the only integrity indicator across all. "
            "ucs-bmc-brdprog-S3260M5.10.0.bin -- BMC board programmer for the S3260 storage server "
            "(S3260 = 4U 60-bay high-density storage, up to 360 3.5-inch drives) -- "
            "follows the same unsigned pattern."
        ),
    },
    {
        "id": "CSUB-F5",
        "severity": "LOW",
        "title": "PLATFORM_CODENAMES_GODZILLA_MOUNTRAINIER_MOUNTADAMS_IN_PRODUCTION_ARTIFACTS",
        "detail": (
            "Internal platform codenames in production firmware artifacts: "
            "'godzilla1' -- C220M8 (in brdprog [pkg] platform field and git branch name); "
            "'mountrainier1', 'mountrainier2' -- two variants of a C-Series M8 platform "
            "(Mount Rainier, WA; likely C245M8 or C240M8 based on naming convention); "
            "'mountadams1', 'mountadams2' -- two variants of another C-Series M8 platform "
            "(Mount Adams, WA; adjacent peak to Mount Rainier -- consistent naming pattern); "
            "'CSeriesM7' -- generic C-Series M7 family; "
            "'ast2600_evb' -- Aspeed AST2600 evaluation board. "
            "All appear in CIMC SPLImage/BISImage string table. "
            "Washington mountain names form the codename family: "
            "Mt. Rainier, Mt. Adams (CascadeRange peaks); godzilla follows a separate track."
        ),
    },
    {
        "id": "CSUB-F6",
        "severity": "LOW",
        "title": "BIOS_PACKAGE_DISCLOSES_SIGNING_CERTIFICATE_SUBJECT_IN_PLAINTEXT_HEADER",
        "detail": (
            "BIOS CIMCPackage header (bytes 0-8192) includes X.509 certificate subject "
            "in plaintext: 'CN=CiscoSystems;OU=BIOS_IMG;O=CiscoSystems 6977B42F'. "
            "The subject string appears twice in the header (before and after binary signature data). "
            "6977B42F appears to be the certificate serial number (hex). "
            "Converting: 0x6977B42F = 1769808943 decimal. "
            "OU=BIOS_IMG indicates a dedicated signing CA for BIOS images, "
            "separate from general Cisco code signing (which typically uses OU=ACT2). "
            "The binary signature block (RSA or ECDSA) occupies the space between the "
            "plaintext INI key-value section and the 8192-byte boundary."
        ),
    },
]

# ============================================================
# MODULE SUMMARY
# ============================================================

MODULE_SUMMARY = {
    "module": "cisco_ucs_c_series_bundle_re",
    "bundle": "ucs-k9-bundle-c-series.6.0.2b.C.bin",
    "firmware_formats": {
        "BIOS": "CIMCPackage (X.509 PKI, CN=CiscoSystems;OU=BIOS_IMG)",
        "CIMC": "55AA + ARM code, 134MB, no visible PKI header",
        "brdprog": "[pkg] INI format, 128B header, NO signature",
        "peripheral": "SN blob (unsigned)",
    },
    "codenames": {
        "C220M8": "godzilla1",
        "CIMC M8 variant A": "mountrainier1/2",
        "CIMC M8 variant B": "mountadams1/2",
        "dev_platform": "ast2600_evb (in production)",
    },
    "finding_counts": {"CRITICAL": 0, "HIGH": 2, "MEDIUM": 2, "LOW": 2},
    "cumulative_counts": {"CRITICAL": 55, "HIGH": 195, "MEDIUM": 186, "LOW": 174},
    "cumulative_total": 611,
}
