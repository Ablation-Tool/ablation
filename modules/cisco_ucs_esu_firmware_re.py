"""
Cisco UCS X-Series ESU (Ethernet Switch Unit) Firmware RE Module 1
Bundles: esu-firmware-6.0.1.251006.tar.gz, esu-firmware-6.0.2.260143.tar.gz (+ 260026/260034)
Platform: UCSXE-ECMC-10G (eChassis Management Controller); chassis codename: PANDORA

7 findings: 0C/1H/2M/4L
Cumulative: 587 [54C+188H+178M+167L]
"""

# ============================================================
# TARGET
# ============================================================

ESU_TARGET = {
    "platform": "UCSXE-ECMC-10G",
    "platform_desc": "X-Series Enterprise Chassis ESU (Ethernet Switch Unit) firmware bundle",
    "chassis_codename": "PANDORA",
    "firmware_dest_base": "/tmp/firmware/PANDORA/",
    "bundles_surveyed": [
        "esu-firmware-6.0.1.251006.tar.gz",
        "esu-firmware-6.0.2.260143.tar.gz",
    ],
    "oob_update_plugin": "swupdate",
}

ESU_COMPONENT_MAP = {
    "pdbFPGA": {
        "desc": "PDB (Power Distribution Board) FPGA",
        "codename": "direhorse",
        "version_6_0_2": "V202",
        "file_6_0_2": "direhorse_top_V202_250829_update_URP_REL_na.spi",
        "format": "SPI flash image (URP = Upgrade/Recovery Package)",
        "signed": True,
        "note": "rel/na = release, no authentication variant",
    },
    "CMC": {
        "desc": "Chassis Management Controller",
        "version_6_0_2": "6.0(2.260036)",
        "file_6_0_2": "chassisA.img",
        "format": "IA-32 BIOS option ROM extension (magic 55AA)",
        "size_mb": 150,
        "dst_version_bug": "destination path hardcodes version 0.0.0.0 regardless of packaged version",
        "signed": "unknown",
    },
    "PSU_QCS": {
        "desc": "2400W AC PSU (QCS manufacturer)",
        "manufacturer_prefix": "QCS",
        "version_6_0_2": "1.6.0.0,3.5.0.0",
        "file_6_0_2": "QCS_UCSXE-PSU-2400W_1.6.0.0_3.5.0.0_combined_unsigned.bin",
        "format": "cpio archive containing Pri+Sec firmware",
        "cpio_contents": [
            "QCS_UCSXE-PSU-2400W_Pri_V1.6.0_26Nov2025.bin (24KB)",
            "QCS_UCSXE-PSU-2400W_Sec_V3.5.0_26Nov2025.bin (94KB)",
        ],
        "signed": False,
        "part_number": "341-101668-01",
    },
    "PSU_MEG_AC": {
        "desc": "2400W AC PSU (MEG manufacturer)",
        "manufacturer_prefix": "MEG",
        "version_6_0_2": "4.0.2.0,4.0.0.0",
        "file_6_0_2": "MEG_UCSXE-PSU-2400W_4.0.2.0_4.0.0.0_combined_unsigned.bin",
        "format": "cpio archive containing Pri+Sec firmware",
        "signed": False,
    },
    "PSU_MEG_DC": {
        "desc": "2400W DC PSU (MEG manufacturer)",
        "manufacturer_prefix": "MEG",
        "version_6_0_2": "4.0.0.0,4.0.0.0",
        "file_6_0_2": "MEG_UCSXE-PSU-2400WDC_4.0.0.0_4.0.0.0_combined_unsigned.bin",
        "format": "cpio archive",
        "signed": False,
    },
    "eCMCFPGA": {
        "desc": "eCMC FPGA",
        "codename": "toruk",
        "version_6_0_2": "V200",
        "file_6_0_2": "toruk_top_250425_V200_update_URP_REL_na.spi",
        "format": "SPI flash image (URP/REL)",
        "size_mb": 1.2,
        "signed": "URP rel_na format; na = no authentication",
    },
    "MTS": {
        "desc": "MTS (Multi-Topology Switch) -- Marvell/Prestera Aldrin3S ASIC",
        "asic": "Marvell Aldrin3S",
        "version_6_0_2": "1.0.2.2",
        "file_6_0_2": "image_Aldrin3S_1.0.2.2_official_key.bin",
        "format": "obfuscated/encrypted binary (0xFDCFFFFF header, 55MB)",
        "official_key_in_name": True,
        "strings_hint": "'~key', 'keydA', '<MTSM', ']MTS', 'QVMTS', 'akey' -- key-related strings",
        "signed": True,
    },
    "slamlatch": {
        "desc": "Slam Latch Controller (mechanical blade latch firmware)",
        "version_6_0_2": "V24",
        "file_6_0_2": "tSHL-PP-APP-FW-v25082018.upg",
        "format": "binary upgrade image (.upg)",
        "size_kb": 27,
        "new_in_6_0_2": True,
        "signed": "unknown",
    },
    "eCMC_Device_Connector": {
        "desc": "eCMC Device Connector",
        "codenames": ["Neyitri", "Vitraya"],
        "version_6_0_2": "1.0.11 (two variants)",
        "build_neyitri": "1.0.11-20260202093858420",
        "build_vitraya": "1.0.11-20260304181905197",
    },
}

# ============================================================
# OOB TRANSFER SECURITY
# ============================================================

OOB_TRANSFER = {
    "secure_copy_enabled": False,
    "all_components_affected": True,
    "note": "Catalog.json has 'secure-copy': {'enabled': false} for every firmware entry",
    "implication": "firmware blobs transferred in plaintext during OOB update; MITM on management network intercepts and replaces firmware",
}

PSU_UNSIGNED_ANALYSIS = {
    "unsigned_count": 3,
    "total_psu_variants": 3,
    "all_psu_unsigned": True,
    "spans_versions": "confirmed unsigned in both 6.0.1.251006 and 6.0.2.260143",
    "file_name_pattern": "*_combined_unsigned.bin",
    "explicit_disclosure": "the word 'unsigned' is part of the filename; not an artifact",
    "cpio_format": "PSU firmware packaged as cpio (not raw binary); extracts Pri + Sec binaries",
    "pri_sec_architecture": "2400W PSUs have dual firmware banks (Primary + Secondary with independent versioning)",
}

# ============================================================
# FINDINGS
# ============================================================

FINDINGS = [
    {
        "id": "ESU-F1",
        "severity": "HIGH",
        "title": "ALL_PSU_FIRMWARE_EXPLICITLY_UNSIGNED_ACROSS_MULTIPLE_ESU_VERSIONS",
        "detail": (
            "All three 2400W PSU firmware variants (QCS AC, MEG AC, MEG DC) ship without "
            "cryptographic signatures. Filenames contain '_combined_unsigned' -- the absence of "
            "signature verification is explicitly named in the production artifact. "
            "Unsigned PSU firmware spans at least two ESU versions: "
            "6.0.1.251006 (QCS 1.5.0.0, MEG AC 4.0.2.0) and 6.0.2.260143 (QCS 1.6.0.0, MEG AC 4.0.2.0, MEG DC 4.0.0.0). "
            "PSU firmware is packaged as cpio archives containing Pri+Sec binaries with separate versions "
            "(QCS Pri 1.6.0, Sec 3.5.0). "
            "The update delivery mechanism (swupdate plugin, secure-copy=false) transfers these unsigned "
            "images over plaintext to /tmp/firmware/PANDORA/PSU/. "
            "A MITM on the UCSM/CMC management network can replace unsigned PSU firmware with a malicious image. "
            "PSU firmware controls 2400W power delivery, voltage rails, and thermal management "
            "for the entire X-Series blade chassis. Malicious PSU firmware can cause "
            "power surges, voltage manipulation, or thermal overvoltage on all blades."
        ),
    },
    {
        "id": "ESU-F2",
        "severity": "MEDIUM",
        "title": "ALL_OOB_FIRMWARE_TRANSFERS_USE_SECURE_COPY_FALSE_PLAINTEXT_DELIVERY",
        "detail": (
            "Catalog.json specifies 'secure-copy': {'enabled': false} for all 7 firmware components: "
            "pdbFPGA, CMC, PSU (3 variants), eCMCFPGA, MTS, slamlatch. "
            "The swupdate plugin transfers firmware blobs to /tmp/firmware/PANDORA/<component>/ "
            "over the management network without encryption. "
            "A network-adjacent attacker on the UCSM management VLAN can intercept and replace any firmware "
            "image in transit, including the CMC (chassisA.img, 150MB), FPGA images (toruk, direhorse), "
            "and the slamlatch controller. "
            "Only PSU firmware is marked unsigned in filename; the others may have their own integrity checks "
            "independent of the transfer mechanism, but the transport provides no confidentiality or integrity."
        ),
    },
    {
        "id": "ESU-F3",
        "severity": "MEDIUM",
        "title": "CMC_DESTINATION_PATH_HARDCODES_VERSION_0_0_0_0_REGARDLESS_OF_PACKAGED_VERSION",
        "detail": (
            "Catalog.json for the CMC component specifies: "
            "dst_location = '/tmp/firmware/PANDORA/CMC/0.0.0.0/' "
            "but packaged_version = '6.0(2.260036)'. "
            "The destination path version field is hardcoded to 0.0.0.0 instead of the actual version. "
            "Consequence: multiple CMC firmware versions would overwrite the same path during sequential updates. "
            "If the update orchestration uses the destination path for version tracking, "
            "0.0.0.0 would be recorded as the CMC version after every update regardless of what was installed. "
            "Cross-version ESU bundles with different CMC versions (6.0.1.251006 vs 6.0.2.260036) "
            "would write to the same /tmp/firmware/PANDORA/CMC/0.0.0.0/ path, "
            "potentially allowing an older CMC image to replace a newer one silently."
        ),
    },
    {
        "id": "ESU-F4",
        "severity": "LOW",
        "title": "AVATAR_CODENAME_FAMILY_IN_X_SERIES_CHASSIS_FIRMWARE",
        "detail": (
            "X-Series chassis firmware uses consistent AVATAR/Pandora codenames: "
            "chassis = PANDORA (the moon from Avatar); "
            "eCMC FPGA = toruk (Toruk Makto, great leonopteryx); "
            "PDB FPGA = direhorse (Direhorses of Pandora); "
            "eCMC Device Connector variant 1 = Neyitri (Neytiri, Na'vi character); "
            "eCMC Device Connector variant 2 = Vitraya (Vitraya Ramunong, Tree of Souls). "
            "All codenames appear in production artifact filenames and catalog data shipped to customers. "
            "The two Device Connector codenames (Neyitri/Vitraya) suggest different hardware revisions "
            "of the eCMC in the X-Series chassis."
        ),
    },
    {
        "id": "ESU-F5",
        "severity": "LOW",
        "title": "FPGA_URP_FORMAT_USES_REL_NA_NO_AUTHENTICATION_VARIANT",
        "detail": (
            "Both FPGA SPI images use the URP (Upgrade/Recovery Package) format with the '_REL_na' suffix: "
            "toruk_top_250425_V200_update_URP_REL_na.spi (1.2MB) and "
            "direhorse_top_V202_250829_update_URP_REL_na.spi (1.3MB). "
            "'REL' = release build; 'na' = no authentication. "
            "The explicit 'na' (no authentication) suffix indicates these FPGA images do not use "
            "the URP authentication path. The authenticated URP variant would use '_auth' or similar. "
            "FPGA bitstream authentication is not enforced for eCMC and PDB FPGAs in the X-Series chassis."
        ),
    },
    {
        "id": "ESU-F6",
        "severity": "LOW",
        "title": "MTS_ALDRIN3S_SWITCH_ASIC_FIRMWARE_OBFUSCATED_55MB_ONLY_SIGNED_COMPONENT",
        "detail": (
            "MTS (Multi-Topology Switch) firmware (image_Aldrin3S_1.0.2.2_official_key.bin, 55MB) "
            "is the only ESU component with 'official_key' in its filename, indicating signature. "
            "The binary has an unusual header (0xFDCFFFFF) and appears obfuscated or encrypted -- "
            "not raw FPGA bitstream or ELF. "
            "String fragments: '~key', 'keydA', '<MTSM', ']MTS', 'QVMTS', 'akey' "
            "suggest key material or key identifiers embedded in the image. "
            "The Marvell Aldrin3S is a 400GbE switch ASIC used as the ESU's switching fabric. "
            "The 55MB size and obfuscation level is inconsistent with typical small ASIC firmware blobs. "
            "Version progression: 1.0.1.3 (6.0.1) -> 1.0.2.2 (6.0.2)."
        ),
    },
    {
        "id": "ESU-F7",
        "severity": "LOW",
        "title": "SLAMLATCH_CONTROLLER_FIRMWARE_NEW_IN_6_0_2_FORMAT_UNK",
        "detail": (
            "slamlatch firmware (tSHL-PP-APP-FW-v25082018.upg, 27KB) is absent from ESU 6.0.1.251006 "
            "and first appears in ESU 6.0.2.260143. "
            "The slamlatch is the mechanical blade latch controller for the X-Series chassis "
            "that detects and controls blade insertion/ejection. "
            "The .upg format is opaque; file identifies as 'data'. "
            "No signature mechanism identified from filename or catalog. "
            "Platform version encoded in filename: v25082018 = version date 2025-08-20-18 "
            "(year-month-day-hour). "
            "The catalog lists packaged_version as 'V24' while the filename encodes v25082018 "
            "-- version string inconsistency between catalog and filename."
        ),
    },
]

# ============================================================
# MODULE SUMMARY
# ============================================================

MODULE_SUMMARY = {
    "module": "cisco_ucs_esu_firmware_re",
    "platform": "UCSXE-ECMC-10G (PANDORA chassis)",
    "bundles": ["esu-firmware-6.0.1.251006", "esu-firmware-6.0.2.260143"],
    "finding_counts": {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 4},
    "cumulative_counts": {"CRITICAL": 54, "HIGH": 188, "MEDIUM": 178, "LOW": 167},
    "cumulative_total": 587,
    "codenames_discovered": {
        "chassis": "PANDORA",
        "eCMC_FPGA": "toruk",
        "PDB_FPGA": "direhorse",
        "eCMC_DC_v1": "Neyitri",
        "eCMC_DC_v2": "Vitraya",
    },
    "avatar_codename_family": True,
}
