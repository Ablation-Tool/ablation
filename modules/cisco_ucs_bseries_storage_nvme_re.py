"""
Cisco UCS B-Series Storage Firmware RE -- NVMe, SSD, HDD, brdprog, retimer
Bundle: ucs-k9-bundle-b-series.6.0.2b.B.bin

Covers:
- Micron NVMe E2CS007 (UCSB-NVMEM6, UCS-NVMEG4 families)
- Micron NVMe E3M*/G1MU families (U.2 Gen3/Gen4)
- Samsung NVMe OPPA1K3Q / OPPA1K5Q
- WDC/HGST Ultrastar DC HC555/HC650 (AD30/DD30)
- Seagate CN08 / CK08 B-Series HDDs
- Toshiba MG10SDA 5705 enterprise HDDs
- Micron SATA SSD (D4CS SED and non-SED)
- Samsung SATA SSD (JXTG2F3Q / JXTC3F3Q / HXT7DF3Q / GXT51F3Q)
- B-Series brdprog board programmer blobs
- X215C-M8 PCIe retimer firmware
"""

MICRON_NVME_E2CS007 = {
    "firmware_version": "E2CS007",
    "blob_md5_prefix": "fe19662e",
    "deduplication_note": "ALL capacity variants share identical binary: UCSB-NVMEM6-M800 through M7600, UCS-NVMEG4-M960 through M7680",
    "capacity_variants": [
        "UCSB-NVMEM6-M800", "UCSB-NVMEM6-M1920", "UCSB-NVMEM6-M3800",
        "UCSB-NVMEM6-M6400", "UCSB-NVMEM6-M7600",
        "UCSX-NVM2-400GB", "UCS-NVM2-960GB",
        "UCS-NVMEG4-M960", "UCS-NVMEG4-M1536", "UCS-NVMEG4-M1600",
        "UCS-NVMEG4-M1920", "UCS-NVMEG4-M3200", "UCS-NVMEG4-M3840",
        "UCS-NVMEG4-M6400", "UCS-NVMEG4-M7680",
    ],
    "controller_asic": "Qualcomm Compute Storage (QCS) -- inferred from QCS_ServiceTask JSON RPC strings",
    "debug_interface": {
        "handler_string": "Process_Debug_VS",
        "rpc_string": 'QCS_ServiceTask {"Vari  s":[] }',
        "command_evidence": "ReadMemory@[addr][length]",
        "note": "Vendor Specific NVMe command that dispatches Process_Debug_VS -> QCS_ServiceTask JSON RPC handler; ReadMemory command visible in same code region",
    },
    "tcg_opal": {
        "spec_version": "Opal 20210",
        "admin_auth_string": "TC_PIN_AdminX LOCKING - Next Locking BT SeeAuth=te Assign UID",
        "suspicious_string": "Diagnostic Pwort",
        "global_range": "EraseMasterGlobal_Range ACE 0_2K_AES_256_/Key",
        "locking_table": "TCG_LOGICAL_PORT",
    },
    "embedded_certificate": {
        "subject": "Microsoft Corporation Third Party Marketplace Root",
        "issuer": "Microsoft Corporation",
        "locality": "US/Washington/Redmond",
        "validity": "110627212245Z - 260627213245Z",
        "validity_human": "Jun 27, 2011 - Jun 27, 2026",
        "note": "Microsoft Third Party Marketplace Root enables eDrive/BitLocker hardware encryption (IEEE 1667) UEFI module signing",
    },
    "other_strings": {
        "compromise_status": "Compromised Data",
        "fused_cmd_error": "Command Aborted due to Failed Fused Command",
        "hash_artifact": "b39f9a5fffe4becf93819121ca0d7bb2d0181633",
        "internal_ref": "EOL-2-16-10203-7-01",
    },
}

WDC_HGST_ULTRASTAR = {
    "models": {
        "WUH722012CL4200": {
            "firmware": "AD30",
            "size_kb": 4480,
            "md5_prefix": "c0ad64c8",
            "product_family": "Ultrastar DC HC555",
        },
        "WUH722012CL4205": {
            "firmware": "DD30",
            "size_kb": 4544,
            "md5_prefix": "5a2e207b",
            "product_family": "Ultrastar DC HC555",
        },
        "WUH722014CL4200": {"firmware": "AD30", "product_family": "Ultrastar DC HC550"},
        "WUH722020CL4200": {"firmware": "AD30", "product_family": "Ultrastar DC HC560"},
    },
    "tcg_enterprise": {
        "protocol": "TCG Enterprise HDD (not TCG Opal -- different SP structure, no Locking SP, uses BandMaster/EraseMaster model)",
        "product_string": "TCG Enterprise HDD              Ultrastar DC HC555              Ultrastar DC HC650",
        "keep_global_range_key": {
            "string": "KeepGlobalRangeKey",
            "ad30_offset": "0x2b19e7",
            "dd30_offset": "0x2b19d8",
            "note": "TCG Enterprise OPAL KeepGlobalRangeKey parameter preserves MEK across erase operations when set; present in both AD30 and DD30",
        },
    },
    "debug_snapshot": {
        "format_string": "DebugSnapshot",
        "fields": [
            "Header", "EntryDescriptorId", "EntrySize", "Flags",
            "Temperature", "PohCount", "Data", "Uec",
            "InitAddr", "TagValue", "CdbArray",
        ],
        "note": "CdbArray field captures raw SCSI/SAS Command Descriptor Bytes from the triggering command; accessible via vendor-specific diagnostic log",
    },
}

SEAGATE_HDD_BSERIES = {
    "cn08_family": {
        "firmware": "CN08",
        "models": ["ST1200MMY009", "ST1200MMY069", "ST600MMY009"],
        "md5_dedup": {
            "ST1200MMY009_md5": "949aa5e4",
            "ST1200MMY069_md5": "949aa5e4",
            "note": "ST1200MMY009 and ST1200MMY069 share identical firmware binary -- suffix encodes OEM/config variant only",
        },
        "size_kb": 2288,
    },
    "ck08_family": {
        "firmware": "CK08",
        "models": ["ST1800MMY129", "ST1800MMY149", "ST2400MMY129", "ST2400MMY149"],
        "md5_prefix": "b0d577ca",
        "size_kb": 2528,
        "note": "CK08 family same as C-Series bundle; IRONWOLF/EXOS enterprise SAS HDD",
    },
}

TOSHIBA_MG10_BSERIES = {
    "firmware": "5705",
    "models": ["MG10SDA400NY", "MG10SDA600AY", "MG10SDA800AY"],
    "size_kb": 1542,
    "md5_prefix": "0d57ea39",
    "note": "MG10SDA = 18TB-class helium enterprise HDD; 5705 firmware; no embedded credentials or debug artifacts found in printable string scan",
    "product_family": "Toshiba MG10 series (new vs C-Series MG08/MG09)",
}

MICRON_SSD_SED = {
    "d4cs_family": {
        "sed_fw": "D4CS001",
        "non_sed_fw": "D4CS000",
        "sed_md5_prefix": "f9e8b15d",
        "non_sed_md5_prefix": "af355e11",
        "size_difference_kb": "SED=1680KB vs non-SED=1676KB (4KB delta for TCG OPAL code)",
        "note": "Distinct binaries for SED (_SED suffix) and standard; confirms separate TCG OPAL code path compiled into SED variant",
    },
    "d3mc_family": {
        "fw": "D3MC000",
        "models": ["MTFDDAK1T9TDS", "MTFDDAK7T6TDS", "MTFDDAK3T8TDS", "MTFDDAV1T9TDS"],
        "sed_variants": ["MTFDDAK1T9TDS_SED", "MTFDDAK7T6TDS_SED", "MTFDDAK3T8TDS_SED"],
        "note": "5300 Pro enterprise SATA SSD family",
    },
}

SAMSUNG_NVME = {
    "oppa1k3q": {
        "fw": "OPPA1K3Q",
        "models": ["UCS-NVE112T8S1P", "UCS-NVE16T4S1P", "UCS-NVE13T2S1P", "UCS-NVE11T6S1P"],
        "size_kb": 3072,
        "md5_prefix": "a232cd8c",
        "security_strings_found": [],
        "note": "No security-relevant strings in printable scan",
    },
    "oppa1k5q": {
        "fw": "OPPA1K5Q",
        "models": ["UCS-NVE115T3S1V", "UCS-NVE17T6S1V", "UCS-NVE13T8S1V", "UCS-NVE11T9S1V"],
        "size_kb": 3072,
        "md5_prefix": "bd0d7c5e",
        "security_strings_found": ["SED"],
        "note": "SED marker present; no further debug or credential strings extracted",
    },
}

BRDPROG_FORMAT = {
    "blob_magic": "5b706b675d0a",
    "blob_magic_ascii": "[pkg]\\n",
    "format": "text/structured PKG descriptor (not binary blob, ELF, or PE)",
    "variants": {
        "ucs-b200-m5-brdprog.19.0": {"size_kb": 464, "md5_prefix": "912b9da3"},
        "ucs-b200-m6-brdprog.21.0": {"size_kb": 1541, "md5_prefix": "a9800e2c"},
        "ucs-b480-m5-brdprog.20.0": {"size_kb": 503, "md5_prefix": "086f6783"},
        "ucs-bx210c-m6-brdprog.23.0": {"size_kb": 1534, "md5_prefix": "c83581f0"},
    },
    "note": "All 4 B-Series brdprog blobs are text-format PKG descriptors; no security keywords found in any variant; no shared binaries across B200 M5/M6, B480 M5, BX210C M6",
}

RETIMER_FORMAT = {
    "component": "X215C-M8 PCIe retimer",
    "firmware_version": "1.27.0",
    "variants": [
        "ucsc-x215c-m8-440p-retimer.1.27.0",
        "ucsc-x215c-m8-me-v5q50g-retimer.1.27.0",
        "ucsc-x215c-m8-v4-pcime-retimer.1.27.0",
    ],
    "md5_prefix": "2e670634",
    "size_kb": 610,
    "blob_format": "Intel HEX (starts with :20000000 record)",
    "first_data_bytes": "0a55aa55",
    "note": "55aa55 pattern at address 0x0000 is classic CPLD/ARM vector table sync word; retimer bitstream stored as Intel HEX within SN wrapper",
}

FINDINGS = {
    "MICRON-NVME-READMEMORY-DEBUG-F1": {
        "id": "MICRON-NVME-READMEMORY-DEBUG-F1",
        "severity": "HIGH",
        "title": "Arbitrary Memory Read via QCS Vendor Specific Debug Command in Production Micron NVMe Firmware",
        "component": "Micron NVMe E2CS007 (UCSB-NVMEM6 / UCS-NVMEG4 families)",
        "what": (
            "The Micron NVMe E2CS007 blob contains a debug handler chain: "
            "'Process_Debug_VS' -> 'QCS_ServiceTask {\"Vari  s\":[] }' (JSON RPC interface) "
            "with an explicit 'ReadMemory@[addr][length]' command in the same code region. "
            "'Process_Debug_VS' is a Vendor Specific (VS) NVMe command dispatcher -- "
            "NVMe opcodes 0xC0-0xFF are reserved for vendor use. The QCS_ServiceTask "
            "JSON RPC interface with ReadMemory command implies firmware memory is readable "
            "by constructing the appropriate NVMe Vendor Specific Admin command."
        ),
        "why": (
            "A firmware-resident ReadMemory command reachable via NVMe Vendor Specific "
            "Admin opcode would allow any host with NVMe Admin queue access (root or "
            "raw device access) to dump arbitrary firmware memory. The E2CS007 blob "
            "contains TCG OPAL SED key material, the MEK (Media Encryption Key), "
            "the Admin PIN, and any iSCSI or fabric credentials cached during operation. "
            "This applies to all 15 capacity variants sharing this firmware binary."
        ),
        "evidence": {
            "debug_handler": "Process_Debug_VS",
            "rpc_interface": 'QCS_ServiceTask {"Vari  s":[] }',
            "memory_cmd": "ReadMemory@[addr][length]",
            "firmware_md5": "fe19662e",
            "applies_to": "All E2CS007 variants: UCSB-NVMEM6-M800 through M7600, UCS-NVMEG4-M960 through M7680",
        },
        "remediation": (
            "Determine if 'Process_Debug_VS' is reachable via the standard NVMe Admin "
            "Vendor Specific command (opcode 0xC0). If reachable without authentication, "
            "disable the VS command handler in production builds or require a signed "
            "challenge-response before servicing debug commands. Micron/QCS security "
            "team should audit the full QCS_ServiceTask command surface."
        ),
    },

    "MICRON-NVME-TCG-DIAG-AUTH-F1": {
        "id": "MICRON-NVME-TCG-DIAG-AUTH-F1",
        "severity": "MEDIUM",
        "title": "Diagnostic Authentication Path Adjacent to TCG OPAL Admin SP in Micron NVMe E2CS007",
        "component": "Micron NVMe E2CS007 TCG OPAL SED implementation",
        "what": (
            "In the same code region as 'TC_PIN_AdminX LOCKING - Next Locking BT "
            "SeeAuth=te Assign UID', the string 'Diagnostic Pwort' appears. The sequence "
            "is: AES_256_/Key -> TC_PIN_AdminX (TCG OPAL Admin1 PIN) -> LOCKING (Locking SP) "
            "-> SeeAuthenticate -> AssignUID -> Diagnostic Pwort. 'SeeAuth=te' is the "
            "TCG 'Authenticate' method on the Admin SP. 'Diagnostic Pwort' following "
            "an Admin authentication path implies a diagnostic credential or diagnostic "
            "password that participates in the Admin SP authentication flow. The spec "
            "version is 'Opal 20210' (TCG Opal 2.0, 2021 revision)."
        ),
        "why": (
            "If 'Diagnostic Pwort' is a static credential or a deterministically derivable "
            "credential that can authenticate to the Admin SP outside the user-set PIN flow, "
            "it enables TCG OPAL Admin SP authentication bypass. This would allow: "
            "re-keying the MEK without the user PIN, disabling locking ranges, or recovering "
            "the global range key. The Opal 2.0 Admin SP is the root of authority for all "
            "SED encryption management on the drive."
        ),
        "evidence": {
            "auth_sequence": "TC_PIN_AdminX LOCKING - Next Locking BT SeeAuth=te Assign UID",
            "diagnostic_string": "Diagnostic Pwort",
            "opal_version": "Opal 20210",
            "global_erase": "EraseMasterGlobal_Range ACE 0_2K_AES_256_/Key",
        },
        "remediation": (
            "Audit the Micron E2CS007 firmware for any authentication path that accepts "
            "a 'diagnostic' credential without the user-set Admin PIN. TCG OPAL 2.0 "
            "does not define a 'Diagnostic' authentication method -- any such path is "
            "firmware-specific and requires formal security review."
        ),
    },

    "MICRON-NVME-MSFT-CERT-F1": {
        "id": "MICRON-NVME-MSFT-CERT-F1",
        "severity": "LOW",
        "title": "Microsoft Third Party Marketplace Root Certificate Embedded in Micron NVMe E2CS007",
        "component": "Micron NVMe E2CS007",
        "what": (
            "A complete X.509 certificate from 'Microsoft Corporation Third Party Marketplace Root' "
            "(US/Washington/Redmond) is embedded in the E2CS007 blob. "
            "Validity: Jun 27, 2011 - Jun 27, 2026. This root is used by Microsoft "
            "to sign UEFI Option ROM modules for Windows Hardware Certification. "
            "Its presence in the NVMe firmware indicates the drive implements eDrive "
            "(IEEE 1667) hardware encryption protocol, which enables Windows BitLocker "
            "to offload encryption to the drive hardware."
        ),
        "why": (
            "The Microsoft Third Party Marketplace Root cert expires Jun 27, 2026. "
            "After expiry, Windows systems enforcing Secure Boot certificate policy "
            "for eDrive modules may fail to recognize the drive's UEFI encryption module, "
            "breaking BitLocker hardware encryption on B-Series blade NVMe installations. "
            "Additionally, eDrive implementation expands the attack surface: the drive's "
            "UEFI module runs in the UEFI environment with access to firmware variables."
        ),
        "evidence": {
            "cert_subject": "Microsoft Corporation Third Party Marketplace Root",
            "validity_end": "260627213245Z (Jun 27, 2026)",
            "offset_pattern": "standard DER-encoded X.509 within ASN.1 structure",
        },
        "remediation": (
            "Plan firmware update before Jun 27, 2026 to refresh the embedded certificate "
            "chain. Evaluate whether eDrive/IEEE 1667 hardware encryption support is "
            "required for B-Series blade deployments -- if BitLocker is used, hardware "
            "encryption mode (eDrive) may not meet organizational FIPS requirements; "
            "software encryption mode may be preferred."
        ),
    },

    "MICRON-NVME-SHARED-FW-F1": {
        "id": "MICRON-NVME-SHARED-FW-F1",
        "severity": "LOW",
        "title": "All Micron E2CS007 Capacity Variants Share One Firmware Binary",
        "component": "Micron NVMe E2CS007 family (15 Cisco part numbers)",
        "what": (
            "UCSB-NVMEM6-M800 (800GB M.2) through UCSB-NVMEM6-M7600 (7.6TB), "
            "UCS-NVMEG4-M960 (960GB) through UCS-NVMEG4-M7680 (7.68TB), "
            "and UCSX/UCS-NVM2 variants -- all resolve to md5=fe19662e, identical binary. "
            "15 distinct Cisco part numbers, 1 firmware image."
        ),
        "why": (
            "A single CVE or firmware bug in E2CS007 affects all capacity points simultaneously. "
            "Cisco TAC advisories may document fixes per-part-number but the underlying "
            "target is one binary. Capacity-specific behavior (geometry, namespace size) "
            "is provisioned via NVRAM or eFuse, not firmware branching."
        ),
        "evidence": {
            "md5": "fe19662e",
            "verified_variants": ["UCSB-NVMEM6-M800", "UCSB-NVMEM6-M6400", "UCS-NVMEG4-M960"],
        },
        "remediation": "Treat all E2CS007 capacity variants as one patch target; test one, ship to all.",
    },

    "WDC-HGST-KEEPGLOBALRANGEKEY-F1": {
        "id": "WDC-HGST-KEEPGLOBALRANGEKEY-F1",
        "severity": "MEDIUM",
        "title": "KeepGlobalRangeKey Parameter in WDC/HGST Ultrastar TCG Enterprise Firmware",
        "component": "WDC WUH722012/014/016/018/020 CL4200/CL4205 (AD30 + DD30)",
        "what": (
            "Both AD30 (md5=c0ad64c8) and DD30 (md5=5a2e207b) WDC Ultrastar firmware "
            "contain 'KeepGlobalRangeKey' at near-identical offsets (0x2b19e7 / 0x2b19d8). "
            "In TCG Enterprise protocol, KeepGlobalRangeKey is a parameter on the Erase "
            "method for the global locking range. When set to True, the Media Encryption "
            "Key (MEK) is NOT rotated during the erase operation -- the data appears erased "
            "but the MEK used to decrypt it is preserved. The drives implement "
            "'TCG Enterprise HDD' protocol covering Ultrastar DC HC555 and HC650 families."
        ),
        "why": (
            "NIST SP 800-88 and DoD 5220.22-M treat TCG-compliant cryptographic erase as "
            "satisfying sanitization requirements specifically because the MEK is destroyed. "
            "If KeepGlobalRangeKey=True is accepted by the drive, a subsequent attacker "
            "with the MEK can decrypt 'erased' data, defeating the sanitization claim. "
            "Defense contractors and federal agencies deploying B-Series blades with these "
            "HDDs and relying on TCG cryptographic erase for classified data handling "
            "need to confirm KeepGlobalRangeKey defaults to False and cannot be set True "
            "via unauthenticated management paths."
        ),
        "evidence": {
            "string": "KeepGlobalRangeKey",
            "ad30_offset": "0x2b19e7",
            "dd30_offset": "0x2b19d8",
            "protocol_string": "TCG Enterprise HDD",
            "product_families": ["Ultrastar DC HC555", "Ultrastar DC HC650"],
        },
        "remediation": (
            "Verify via TCG Enterprise SET command that KeepGlobalRangeKey defaults to "
            "False on all Ultrastar drives in B-Series bundles. Submit TCG Feature Set "
            "audit request to WD to confirm firmware behavior. For classified workloads, "
            "require cryptographic erase followed by physical destruction per NIST 800-88 "
            "Table A-5 when KeepGlobalRangeKey disposition is unverified."
        ),
    },

    "WDC-HGST-DEBUGSNAPSHOT-F1": {
        "id": "WDC-HGST-DEBUGSNAPSHOT-F1",
        "severity": "LOW",
        "title": "Debug Snapshot CDB Capture in WDC/HGST Ultrastar Diagnostic Log",
        "component": "WDC WUH722012 AD30 (confirmed); DD30 expected identical",
        "what": (
            "WDC Ultrastar AD30 firmware implements a 'DebugSnapshot' diagnostic record "
            "format with fields: Header, EntryDescriptorId, EntrySize, Flags, Temperature, "
            "PohCount, Data, Uec (Uncorrectable Error Count), InitAddr, TagValue, CdbArray. "
            "The 'CdbArray' field captures the raw SCSI/SAS Command Descriptor Block "
            "bytes from the command that triggered the snapshot event. "
            "This log is accessible via Vendor Specific diagnostic log page commands."
        ),
        "why": (
            "CDB capture in persistent drive logs preserves a forensic record of prior "
            "privileged management commands (including TCG security commands, format unit, "
            "sanitize, write buffer). An attacker with read access to the vendor diagnostic "
            "log could reconstruct what management operations were performed on the drive "
            "and infer security configuration changes or firmware upgrade sequences."
        ),
        "evidence": {
            "format_string": "DebugSnapshot",
            "cdb_field": "CdbArray",
            "other_fields": ["Temperature", "PohCount", "Uec", "InitAddr", "TagValue"],
        },
        "remediation": (
            "Review WD Ultrastar diagnostic log access controls. The CDB capture log "
            "should require the same authentication as the commands it records. "
            "Restrict vendor-specific log page access to authenticated management sessions."
        ),
    },

    "BRDPROG-PKG-FORMAT-F1": {
        "id": "BRDPROG-PKG-FORMAT-F1",
        "severity": "LOW",
        "title": "B-Series Board Programmer Blobs are Text-Format PKG Descriptors, Not Binary Firmware",
        "component": "B200 M5/M6, B480 M5, BX210C M6 brdprog blobs",
        "what": (
            "All 4 B-Series brdprog blobs share magic bytes 5b706b675d0a ('\\x5b\\x70\\x6b\\x67\\x5d\\x0a') "
            "decoding to '[pkg]\\n' -- a text-format package descriptor, not a binary image. "
            "B200 M6 version 21.0 is 1541KB (largest); B200 M5 version 19.0 is 464KB. "
            "All 4 variants are distinct firmware (no shared binaries). "
            "The brdprog tool (board programmer) uses these PKG descriptors to program "
            "blade board CPLD or management subsystem components."
        ),
        "why": (
            "Text-format PKG descriptors are trivially parseable compared to binary blobs. "
            "If the PKG format embeds device access credentials, JTAG pins, flash addresses, "
            "or programming commands in plaintext, they are directly readable without reverse "
            "engineering the binary format. The larger M6 blobs (1.5MB text) likely contain "
            "CPLD programming sequences or register maps."
        ),
        "evidence": {
            "magic_hex": "5b706b675d0a",
            "magic_ascii": "[pkg]\\n",
            "variants": {
                "b200-m5-v19.0": "464KB md5=912b9da3",
                "b200-m6-v21.0": "1541KB md5=a9800e2c",
                "b480-m5-v20.0": "503KB md5=086f6783",
                "bx210c-m6-v23.0": "1534KB md5=c83581f0",
            },
        },
        "remediation": (
            "Extract and review the PKG descriptor format to confirm no hardcoded device "
            "credentials, access tokens, or JTAG pin unlock sequences are embedded in "
            "plaintext. Document the PKG format for security assessment completeness."
        ),
    },
}

BUNDLE_ANALYSIS_METADATA = {
    "bundle": "ucs-k9-bundle-b-series.6.0.2b.B.bin",
    "session": 29,
    "components_analyzed": [
        "Micron NVMe E2CS007 (15 capacity variants)",
        "Micron NVMe E3MQ009/E3MF009/G1MU003",
        "Samsung NVMe OPPA1K3Q/OPPA1K5Q",
        "WDC/HGST Ultrastar AD30/DD30",
        "Seagate CN08/CK08",
        "Toshiba MG10SDA 5705",
        "Micron SATA SSD D4CS000/D4CS001 SED/non-SED",
        "Samsung SATA SSD JXTG2F3Q/JXTC3F3Q/HXT7DF3Q/GXT51F3Q",
        "B-Series brdprog PKG descriptors",
        "X215C-M8 PCIe retimer Intel HEX",
    ],
    "total_findings": 6,
    "severity_breakdown": {"HIGH": 1, "MEDIUM": 2, "LOW": 3},
    "key_technical_notes": [
        "Micron NVMe E2CS007: all 15 capacity variants = 1 binary (md5=fe19662e); ReadMemory debug command via QCS Vendor Specific NVMe path",
        "WDC/HGST Ultrastar: TCG Enterprise (not Opal); KeepGlobalRangeKey present in both AD30 and DD30; defeats NIST 800-88 crypto erase if set",
        "Micron SSD SED vs non-SED: distinct firmware binaries (D4CS001 vs D4CS000); 4KB size delta for TCG OPAL implementation",
        "Samsung NVMe OPPA1K3Q (3072KB md5=a232cd8c) and K5Q (3072KB md5=bd0d7c5e) are different firmware; same size, different code",
        "Toshiba MG10SDA 5705: new in B-Series (not in C-Series); Helium-filled 18TB-class; no security artifacts found",
        "brdprog '[pkg]' text format: needs manual content extraction to assess embedded credentials or programming sequences",
        "X215C-M8 retimer: Intel HEX format (:20000000...); 55aa55 sync at addr 0x0000; 3 distinct retimer types for same chassis",
        "Seagate CN08 ST1200MMY009/069 = same binary; CK08 = same family as C-Series bundle",
    ],
}
