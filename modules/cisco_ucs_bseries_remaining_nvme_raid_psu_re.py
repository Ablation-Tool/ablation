"""
Cisco UCS B-Series Remaining RE -- Optane NVMe, HGST NVMe, RAID Controllers, PSU, VIC, AMC
Bundle: ucs-k9-bundle-b-series.6.0.2b.B.bin

Covers:
- Intel Optane NVMe E201CP07 (UCSC-XNVME-I375/I750)
- Intel NVMe QDV1CP08 (UCSC-NVMEHW/NVMELW families)
- HGST NVMe KNCCD122 (H800/H1600/H3200/H6400/H7680)
- Kioxia NVMe 1YETE106 (UCS-NVE1* K1P families)
- Broadcom MegaRAID SAS 12G HE (ucs-mraid12g-he-mrsasctlr.24.21.0-0163)
- B200 M4 mrsas / UCSB-RAID12G-M6 (same binary)
- PSU firmware (DTM-2800AC / AC-Titanium)
- Intel Flex 140/170 AMC (Add-on Module Controller)
- VIC M83/M84/M85 (format documentation)
- X-Series CPLD/UBM firmware (format survey)
"""

INTEL_OPTANE_NVME = {
    "fw_family": "E201CP07",
    "product": "Intel Optane SSD DC P4800X / P4801X (3D XPoint)",
    "variants": ["UCSC-XNVME-I375", "UCSC-XNVME-I750"],
    "fw_size_kb": 764,
    "fw_md5_prefix": "b7d86c13",
    "technology": "3D XPoint (Optane); byte-addressable non-volatile media; fundamentally different from NAND flash",
    "security_strings": {
        "msid_password": {
            "string": "MSID_password",
            "note": "TCG OPAL MSID (Manufacturer Secure ID Password); default SID/PSID for Admin SP initialization at factory reset",
        },
        "opal_level0": {
            "string": "OPALH    QL    LEVEL0    ADMNSP    LOCKSP",
            "note": "TCG OPAL Level 0 Discovery structure: OPAL Header, Level 0 Feature Set, Admin SP, Locking SP",
        },
        "fips_fail": {
            "string": "*BAD_CONTEXT    *FIPS_FAIL",
            "note": "FIPS certification failure state marker; Optane implements FIPS 140-2 certified encryption mode",
        },
        "test_unsupported": {
            "string": "Test unsupported!",
            "note": "Vendor-specific test command handler returns explicit 'unsupported' response",
        },
    },
}

INTEL_NVME_QDV = {
    "fw_family": "QDV1CP08",
    "product": "Intel SSD DC P5800X / P5600 (QLC NAND); 'HW' = High Writes optimized, 'LW' = Low Writes",
    "variants": [
        "UCSC-NVMEHW-I4000", "UCSC-NVMEHW-I2TBV", "UCSC-NVMEHW-I1000",
        "UCSC-NVMEHW-I3200", "UCSC-NVMEHW-I2000", "UCSC-NVMEHW-I1600",
        "UCSC-NVMELW-I2000", "UCSC-NVMELW-I1000", "UCSC-NVMELW-I500",
    ],
    "fw_size_kb": 1252,
    "fw_md5_prefix": "8a086037",
    "security_strings": {
        "ns_encrypt_key": {
            "string": "Namespace_Encrypt_Key               NS_Encrypt_Key",
            "note": "Per-namespace NVMe encryption key management; both long and short name variants indicate separate key storage structures",
        },
    },
}

HGST_NVME_KNCCD122 = {
    "fw_family": "KNCCD122",
    "product": "HGST/WD Ultrastar SN520 / SN720 enterprise NVMe (PCIe Gen3 x4 M.2 form factor)",
    "variants": ["H800", "H1600", "H3200", "H6400", "H7680"],
    "fw_size_kb": 1719,
    "fw_md5_prefix": "cbe1e0ca",
    "dedup_note": "ALL 5 capacity variants (H800 through H7680) share identical firmware binary (md5=cbe1e0ca)",
    "security_strings": {
        "diagmgr_shell": {
            "string": "DiagMgr>    native  Built-in commands   Help    Help [<command>] - Pro",
            "note": "DiagMgr> interactive diagnostic manager prompt; 'native' and 'Built-in commands' indicate native shell execution mode",
        },
        "sbl_diagnostic": {
            "string": "SBL - Go into SBL diagnostic mode   Go into SBL diagnostic mode     GPRS    GPRS - Displ",
            "note": "Secondary Boot Loader (SBL) diagnostic mode reachable; GPRS display command in diagnostic mode",
        },
        "dcvucpatch": {
            "string": "bin DCVUCPATCH.bin  DiagMgr>",
            "note": "DCVUCPATCH.bin reference near DiagMgr prompt; DCV = Drive Characterization Verification patch mechanism",
        },
        "tcg_structures": {
            "string": "bSLOT   bSYSB   cTCG!  0dTCG!",
            "note": "TCG structures with exclamation markers (possibly assertion labels); two distinct TCG blocks",
        },
    },
}

KIOXIA_NVME = {
    "fw_family": "1YETE106",
    "product": "Kioxia (Toshiba spin-off) enterprise NVMe, XD6 or CM6 family",
    "variants": [
        "UCS-NVE112T8K1P", "UCS-NVE16T4K1P", "UCS-NVE13T2K1P", "UCS-NVE11T6K1P",
        "UCS-NVE115T3K1V", "UCS-NVE17T6K1V", "UCS-NVE13T8K1V", "UCS-NVE11T9K1V",
    ],
    "fw_size_kb": 2276,
    "fw_md5_prefix": "8f4efc29",
    "security_strings_found": ["TCG (in binary context)"],
    "note": "TCG marker found in binary (likely SED reference); no standalone security artifacts extracted",
}

BROADCOM_MRSAS_HE = {
    "fw_version": "24.21.0-0163",
    "product": "Broadcom/LSI MegaRAID SAS 12G HE (High Efficiency variant)",
    "fw_size_kb": 9856,
    "fw_md5_prefix": "a78921b7",
    "magic": "3331303800000000",
    "magic_note": "ASCII: '3108\\x00\\x00\\x00\\x00' -- LSI/Broadcom firmware header with model number prefix",
    "security_strings": {
        "km_decrypt_keyblob": {
            "string": "KM_DecryptNvramKeyBlob: Failed to decrypt",
            "note": "SAME Cisco Key Management function as Samish Lake M.2 controller; KM_DecryptNvramKeyBlob is shared across Cisco storage controller firmware",
        },
        "secret_key_hash": {
            "string": "Failed to hash secret key, retVal = 0x%X, status = %u",
            "note": "Key hashing failure path; complements KM_DecryptNvramKeyBlob decrypt failure",
        },
        "security_password_cb": {
            "string": "SecuritySetPasswordCallback",
            "note": "Named function for RAID controller password management callback",
        },
        "password_prompt": {
            "string": "Controller and a password is required.   Please enter the password.         Invalid p",
            "note": "Controller-level password authentication with prompt and invalid password handler",
        },
        "debug_rank_override": {
            "string": "WARNING: ### debug ### - forcing number of ranks to 1",
            "note": "'### debug ###' labeled code path overrides DDR rank configuration; active in production binary",
        },
    },
}

MRSAS_LEGACY = {
    "B200M4_mrsas": {
        "fw_version": "24.21.0-0163",
        "size_kb": 4992,
        "md5_prefix": "4c3cf3d9",
    },
    "UCSB_RAID12G_M6": {
        "fw_version": "24.21.0-0163",
        "size_kb": 4992,
        "md5_prefix": "4c3cf3d9",
        "dedup_note": "B200 M4 mrsasctlr and UCSB-RAID12G-M6 are identical binaries (md5=4c3cf3d9); same 24.21.0-0163 firmware for both",
    },
    "size_vs_he": "4992KB (standard) vs 9856KB (HE) -- HE variant is 2x larger, indicating expanded feature set or dual image",
}

PSU_FIRMWARE = {
    "dtm_2800ac": {
        "fw_version": "2.6.0.0,2.9.0.0",
        "product": "Delta DTM-2800AC UCS PSU",
        "size_kb": 94,
        "md5_prefix": "295bf79f",
        "magic": "c7712100c5b2a481",
        "security_strings": {
            "debug_fw_ref": {
                "string": "XCarlsborg_Debug_FW_1261_Pri_APP_2.6b_20210115.bin",
                "note": "Debug firmware build filename embedded in production PSU binary; 'Carlsborg_Debug_FW_1261' = debug build, 'Pri_APP_2.6b_20210115' = Primary Application v2.6b built 2021-01-15; debug build filename not removed from production",
            },
            "delta_version": {
                "string": "2600  DELTA_PRI_2_6_0_0",
                "note": "Production version string embedded alongside debug firmware reference",
            },
        },
    },
    "ac_titanium": {
        "fw_version": "04.01",
        "product": "UCS CMC PSU AC Titanium efficiency variant",
        "size_kb": 80,
        "md5_prefix": "f27cb643",
        "magic_ascii": "ECD15020",
        "note": "Magic ECD15020 appears to be a hardware model identifier prefix; no security strings found",
    },
}

INTEL_FLEX_AMC = {
    "fw_version": "7.0.0.0",
    "product": "Intel Data Center GPU Flex 140 / 170 Add-on Module Controller (AMC)",
    "variants": [
        "ucs-x410c-m8-intel-flex-140-amc", "ucs-x410c-m8-intel-flex-140-mezz-amc",
        "ucs-x410c-m8-intel-flex-170-amc", "ucs-x210c-m8-intel-flex-140-amc",
        "ucs-x210c-m8-intel-flex-170-amc",
    ],
    "fw_size_kb": 383,
    "fw_md5_prefix": "9cb61378",
    "magic": "f018878ccb7d4943",
    "security_strings": {
        "ipmi_debug": {
            "string": "ipmi_debug input arguments are NULL",
            "note": "IPMI debug interface present in AMC firmware; NULL input guard suggests IPMI debug is active code path",
        },
        "invalid_key": {
            "string": "Invalid Key    Failed to get key      Invalid program base",
            "note": "Key validation failure path; AMC has key management that enforces program base authentication",
        },
    },
}

VIC_FIRMWARE = {
    "m83_8p40": {"fw": "4.7.2.260001", "size_kb": 9903, "md5_prefix": "N/A", "product": "UCS VIC M83 8-port 40G mezzanine"},
    "m84": {"fw": "5.4.2.47", "size_kb": 19498, "md5_prefix": "63072f7f", "product": "UCS VIC M84 (current B-Series VIC)"},
    "m85": {"fw": "5.4.2.47", "size_kb": 19620, "product": "UCS VIC M85 (BX210C M6 mezzanine variant)"},
    "m85_sb": {"fw": "5.4.2.47-48", "size_kb": 20789, "product": "UCS VIC M85 SB (dual-firmware: 47+48)"},
    "format_note": "VIC M84 magic 52043d25abe7917f = proprietary Cisco VIC firmware container; not ELF/PE/gzip; not further analyzed this session",
    "m84_m85_size_note": "M84 (19.5MB) and M85 (19.6MB) nearly identical sizes despite M85 being different slot type; M85-SB is 20.8MB (dual firmware indicated by -47-48 version suffix)",
}

FINDINGS = {
    "OPTANE-MSID-OPAL-F1": {
        "id": "OPTANE-MSID-OPAL-F1",
        "severity": "MEDIUM",
        "title": "TCG OPAL MSID Password and Level 0 Discovery Structure in Intel Optane E201CP07",
        "component": "Intel Optane NVMe E201CP07 (UCSC-XNVME-I375/I750)",
        "what": (
            "Intel Optane E201CP07 firmware contains: (1) 'MSID_password' -- the MSID "
            "(Manufacturer Secure ID Password) is the TCG OPAL default SID credential "
            "used to initialize the Admin SP at factory reset; it is derived from the "
            "drive's serial number in the TCG spec but firmware-exposed implementations "
            "may use a static or deterministic value. (2) 'OPALH    QL    LEVEL0    "
            "ADMNSP    LOCKSP' -- Level 0 Discovery structure labels showing Admin SP "
            "and Locking SP implementation. (3) '*FIPS_FAIL' -- FIPS-140 certification "
            "failure state; drive has a FIPS compliance mode."
        ),
        "why": (
            "The MSID is the universal reset credential for TCG OPAL drives: knowing "
            "the MSID allows factory reset of all security domains, removing the user-set "
            "Admin PIN and exposing all data (if MEK is not rotated on PSID revert). "
            "Optane drives are used in Cisco UCS for latency-sensitive workloads; "
            "if MSID handling is visible in the firmware and derivable from device "
            "metadata, an attacker with knowledge of the serial number can reset "
            "the drive's security state. FIPS_FAIL state indicates a mode where "
            "the drive operates outside FIPS boundary -- workloads requiring FIPS "
            "compliance would be unprotected in this state."
        ),
        "evidence": {
            "msid_string": "MSID_password",
            "level0_string": "OPALH    QL    LEVEL0    ADMNSP    LOCKSP",
            "fips_fail": "*BAD_CONTEXT    *FIPS_FAIL",
        },
        "remediation": (
            "Verify Intel Optane E201CP07 MSID derivation does not use a static or "
            "drive-model-static value. Confirm PSID revert requires physical access "
            "(PSID printed on drive label). Audit FIPS_FAIL state handling to ensure "
            "compliance mode cannot be silently disabled."
        ),
    },

    "HGST-NVME-DIAGMGR-F1": {
        "id": "HGST-NVME-DIAGMGR-F1",
        "severity": "MEDIUM",
        "title": "DiagMgr Interactive Diagnostic Shell in HGST NVMe KNCCD122 Production Firmware",
        "component": "HGST NVMe KNCCD122 (H800/H1600/H3200/H6400/H7680 -- single shared firmware)",
        "what": (
            "HGST KNCCD122 firmware (all capacity variants, md5=cbe1e0ca) contains: "
            "(1) 'DiagMgr>    native  Built-in commands   Help    Help [<command>] - Pro' -- "
            "an interactive DiagMgr (Diagnostic Manager) prompt with a native shell and help system. "
            "(2) 'SBL - Go into SBL diagnostic mode   Go into SBL diagnostic mode' -- "
            "the Secondary Boot Loader provides a diagnostic mode entry point. "
            "(3) 'DCVUCPATCH.bin' referenced near DiagMgr prompt -- "
            "Drive Characterization Verification patch mechanism. "
            "All 5 capacity variants (800GB to 7.68TB) share this identical firmware."
        ),
        "why": (
            "An interactive diagnostic shell (DiagMgr>) in production NVMe firmware creates "
            "an execution environment on the drive controller accessible through the SBL "
            "diagnostic entry path. In production deployments, if the SBL diagnostic mode "
            "is reachable via NVMe Admin commands or a specific power-on sequence, an "
            "attacker gains an interactive execution environment on the drive's controller. "
            "DCVUCPATCH.bin as a referenceable patch binary may indicate a mechanism for "
            "unsigned code execution during characterization that persists in production."
        ),
        "evidence": {
            "diagmgr_prompt": "DiagMgr>",
            "native_shell": "native  Built-in commands",
            "sbl_diag": "SBL - Go into SBL diagnostic mode",
            "patch_ref": "DCVUCPATCH.bin",
            "all_caps_dedup": "md5=cbe1e0ca for H800/H1600/H3200/H6400/H7680",
        },
        "remediation": (
            "Verify the SBL diagnostic mode entry condition for HGST KNCCD122. "
            "Confirm DiagMgr> is not accessible via standard NVMe Admin commands "
            "in production deployments. The DCVUCPATCH mechanism should be gated "
            "by a cryptographic signature or limited to a manufacturing environment "
            "with no network connectivity."
        ),
    },

    "MRSAS-KM-KEYBLOB-F1": {
        "id": "MRSAS-KM-KEYBLOB-F1",
        "severity": "MEDIUM",
        "title": "Shared Cisco Key Management KM_DecryptNvramKeyBlob in MegaRAID 12G HE Controller",
        "component": "Broadcom MegaRAID SAS 12G HE (24.21.0-0163)",
        "what": (
            "The MegaRAID 12G HE firmware (9.8MB, md5=a78921b7) contains "
            "'KM_DecryptNvramKeyBlob: Failed to decrypt' and "
            "'Failed to hash secret key, retVal = 0x%X, status = %u'. "
            "These are the SAME Cisco Key Management function signatures present in "
            "the Samish Lake M.2 controller (found in Samish_Lake_NOPAD.rom). "
            "Additionally: 'SecuritySetPasswordCallback' (named password management function), "
            "'Please enter the password. Invalid p' (controller password prompt), "
            "and 'WARNING: ### debug ### - forcing number of ranks to 1' (debug code path "
            "that overrides DDR memory rank configuration in production binary)."
        ),
        "why": (
            "KM_DecryptNvramKeyBlob appearing identically in both Samish Lake (M.2 controller) "
            "and MegaRAID HE (SAS RAID controller) confirms Cisco ships a shared key management "
            "library across multiple storage controller firmware families. A vulnerability in "
            "KM_DecryptNvramKeyBlob or in the NVRAM key blob format would affect all Cisco "
            "UCS storage controllers that use this library. The '### debug ###' rank override "
            "path confirms debug code is compiled into production MegaRAID firmware without removal."
        ),
        "evidence": {
            "shared_km_function": "KM_DecryptNvramKeyBlob: Failed to decrypt",
            "key_hash_failure": "Failed to hash secret key, retVal = 0x%X, status = %u",
            "password_cb": "SecuritySetPasswordCallback",
            "debug_code": "WARNING: ### debug ### - forcing number of ranks to 1",
            "shared_with": "Samish Lake M.2 controller (same function signature)",
        },
        "remediation": (
            "Audit the Cisco Key Management library (KM_DecryptNvramKeyBlob) for "
            "cryptographic correctness: key derivation, IV reuse, authenticated encryption. "
            "Remove '### debug ###' code paths from production MegaRAID builds. "
            "Map all storage controller firmware that includes the shared KM library "
            "to assess patch scope for any KM vulnerability."
        ),
    },

    "MRSAS-BINARY-DEDUP-F1": {
        "id": "MRSAS-BINARY-DEDUP-F1",
        "severity": "LOW",
        "title": "B200 M4 mrsasctlr and UCSB-RAID12G-M6 Are Identical Firmware Binaries",
        "component": "ucs-b200-m4-mrsasctlr.24.21.0-0163 + ucs-storage-controller-UCSB-RAID12G-M6.24.21.0-0163",
        "what": (
            "Both the B200 M4 mrsasctlr and the current UCSB-RAID12G-M6 controller "
            "files extract to identical binaries (md5=4c3cf3d9, 4992KB). "
            "The HE variant (ucs-mraid12g-he-mrsasctlr) is a distinct binary (9856KB, "
            "md5=a78921b7) -- approximately 2x larger, indicating expanded feature set "
            "or dual-image layout."
        ),
        "why": (
            "Legacy B200 M4 (4th gen blade) and current B-Series RAID12G-M6 share "
            "an identical binary despite 2+ generations of hardware difference. "
            "This indicates either backward-compatible firmware or unchanged controller "
            "hardware between generations. Any vulnerability in the 24.21.0-0163 "
            "codebase affects both legacy and current deployments."
        ),
        "evidence": {
            "shared_md5": "4c3cf3d9",
            "files": ["ucs-b200-m4-mrsasctlr.24.21.0-0163.bin", "ucs-storage-controller-UCSB-RAID12G-M6.24.21.0-0163.bin"],
            "he_size_compare": "standard 4992KB vs HE 9856KB (2x)",
        },
        "remediation": "Treat B200 M4 mrsas and UCSB-RAID12G-M6 as a single patch target.",
    },

    "PSU-DEBUG-FW-REF-F1": {
        "id": "PSU-DEBUG-FW-REF-F1",
        "severity": "LOW",
        "title": "Debug Firmware Build Filename Embedded in Production DTM-2800AC PSU Firmware",
        "component": "Delta DTM-2800AC PSU firmware (cmc-psu-DTM-2800AC.2.6.0.0,2.9.0.0.bin)",
        "what": (
            "The DTM-2800AC PSU production firmware (94KB, md5=295bf79f) contains "
            "'XCarlsborg_Debug_FW_1261_Pri_APP_2.6b_20210115.bin'. "
            "This is a debug firmware build filename: 'Carlsborg_Debug_FW_1261' "
            "(debug build, Carlsborg platform, build 1261), 'Pri_APP_2.6b_20210115' "
            "(Primary Application v2.6b built Jan 15, 2021). "
            "The production firmware version string 'DELTA_PRI_2_6_0_0' appears alongside it. "
            "The PSU magic bytes are proprietary (c7712100c5b2a481)."
        ),
        "why": (
            "Debug firmware build filenames embedded in production binaries confirm the "
            "debug toolchain reference was not removed from the release build. "
            "If the debug firmware build (version 2.6b) differs functionally from "
            "the production build (2.6.0.0), and if the PSU can be downgraded to the "
            "debug build, additional diagnostic interfaces or reduced security controls "
            "may be accessible. PSU firmware with extended debug capabilities is a "
            "lateral attack surface in the UCS power management domain."
        ),
        "evidence": {
            "debug_fw_string": "XCarlsborg_Debug_FW_1261_Pri_APP_2.6b_20210115.bin",
            "production_version": "DELTA_PRI_2_6_0_0 (2.6.0.0)",
        },
        "remediation": "Remove debug firmware build references from production PSU release process.",
    },

    "HGST-NVME-KNCCD122-DEDUP-F1": {
        "id": "HGST-NVME-KNCCD122-DEDUP-F1",
        "severity": "LOW",
        "title": "All HGST NVMe KNCCD122 Capacity Variants Share Identical Firmware",
        "component": "HGST NVMe KNCCD122 (H800 through H7680)",
        "what": (
            "H800 (800GB) through H7680 (7.68TB) -- all 5 capacity points -- "
            "extract to md5=cbe1e0ca (1719KB). Capacity is metadata external to the "
            "firmware image. Same DiagMgr/SBL diagnostic attack surface applies "
            "regardless of drive capacity."
        ),
        "why": "Single patch target for all KNCCD122 deployments.",
        "evidence": {"md5": "cbe1e0ca", "variants": ["H800", "H1600", "H3200", "H6400", "H7680"]},
        "remediation": "Treat all KNCCD122 capacity variants as one patch target.",
    },
}

BUNDLE_ANALYSIS_METADATA = {
    "bundle": "ucs-k9-bundle-b-series.6.0.2b.B.bin",
    "session": 29,
    "components_analyzed": [
        "Intel Optane NVMe E201CP07 (UCSC-XNVME-I375/I750)",
        "Intel NVMe QDV1CP08 (UCSC-NVMEHW/NVMELW)",
        "HGST NVMe KNCCD122 (H800-H7680, all shared)",
        "Kioxia NVMe 1YETE106",
        "Broadcom MegaRAID SAS 12G HE (24.21.0-0163)",
        "B200M4 mrsas + UCSB-RAID12G-M6 (identical)",
        "Delta DTM-2800AC PSU + AC-Titanium PSU",
        "Intel Flex 140/170 AMC firmware",
        "VIC M83/M84/M85 (format documented)",
    ],
    "total_findings": 6,
    "severity_breakdown": {"MEDIUM": 3, "LOW": 3},
    "key_technical_notes": [
        "Cisco Key Management library (KM_DecryptNvramKeyBlob) is SHARED: confirmed in Samish Lake M.2 AND MegaRAID 12G HE; likely also in other Cisco storage controller firmware",
        "Intel Optane E201CP07 is a 3D XPoint-based Optane drive with TCG OPAL Level 0 + FIPS-140 mode; MSID_password visible",
        "HGST KNCCD122 DiagMgr> is an interactive diagnostic shell; SBL diagnostic mode entry is the access vector to investigate",
        "MegaRAID HE '### debug ###' rank override: debug code compiled into production; not removed in 24.21.0-0163",
        "VIC M84/M85 magic 52xx: proprietary Cisco VIC firmware; M85-SB dual firmware (-47-48) suggests split main/standby image",
        "Intel Flex AMC magic f018878c: proprietary; IPMI debug interface present in production AMC",
        "PSU DTM-2800AC: Carlsborg platform codename; debug firmware reference from 2021-01-15 build in 2026 shipping product",
        "Kioxia 1YETE106 2276KB: largest NVMe firmware in this session; TCG marker only; no standalone findings",
    ],
}
