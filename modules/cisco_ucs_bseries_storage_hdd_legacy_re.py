"""
Cisco UCS B-Series Storage: HDD, SAS, Legacy NVMe, CPLD
Bundle: ucs-k9-bundle-b-series.6.0.2b.B.bin

Covers:
- Solidigm NVMe 9CV10510 (UCS-NVB* family -- 15 variants)
- Toshiba SAS SSD px05smb / px05srb 0104 (Phoenix-M3 framework)
- HGST SAS HDD families: A320, ADD5, A40K, A9GH, HUC101, HUH721/728, HUS72x, T410
- Toshiba HDD/SAS: al13seb (5706), al13sxb (5703), al14seb (5705), al14sxb/al15seb (5704)
- Toshiba SAS MG04SCA (5705)
- WDC NVMe R121000B (NVMW series)
- Intel C-Series NVMe 8DV1CP02 (UCSC-F-I family)
- HGST NVMe KMCCP108 (SDHPCIE family)
- Intel MAX 10 FPGA CPLD (gpufm-cpld.1.005) -- SVF format
- RAID M1L6 CPLD (2.005), RAIDF UBM (0x445)
- PSU DV variants (Delta, Emerson)
- HGST SAS SSD: HUSMM32 (D17D), HUSMR32 (A17D), HUSTR7 (A551)
"""

SOLIDIGM_NVME = {
    "fw_family": "9CV10510",
    "vendor": "Solidigm (Intel NAND business, acquired by SK Hynix 2021)",
    "product": "Solidigm D7-P5510/P5520/P5620 NVMe enterprise SSD",
    "variants": [
        "UCS-NVB12T8O1P", "UCS-NVB15TO1V", "UCS-NVB1T6O1P", "UCS-NVB1T9O1V",
        "UCS-NVB3T2O1P", "UCS-NVB3T8O1V", "UCS-NVB6T4O1P", "UCS-NVB7T6O1V",
        # plus 7 additional capacity/endurance variants
    ],
    "fw_size_kb": 1484,
    "fw_md5_prefix": "ba30360b",
    "magic": "06000000a1000000",
    "magic_note": "Same magic as Intel C-Series NVMe 8DV1CP02 (06000000a1000000); shared container format",
    "security_strings": {
        "asymmetric_diag_unlock": {
            "string": "Asymmetric Diag Unlock    Auth Key    MaxComPacket    MaxIndToken",
            "note": "Asymmetric key authentication protocol for diagnostic unlock; TCG-style session with MaxComPacket/MaxIndToken session limits",
        },
        "d2_bmc_mgmt": {
            "string": "D1 - maximum power i\"    D2 - bmc management%",
            "note": "NVMe Feature ID D2h = vendor-specific BMC management interface; D1h = power management; D2 adjacent to D1 confirms Feature descriptor",
        },
        "msid_password": {
            "string": "MSID_password (x2 occurrence)",
            "note": "Manufacturer Secure ID Password for TCG OPAL Admin SP initialization; same as Optane E201CP07 (separate product line)",
        },
        "fips_states": {
            "string": "*FIPS_IN_PROGRE[SS]    *INITIALIZED    HEALTHY",
            "note": "FIPS drive lifecycle states; FIPS_IN_PROGRESS indicates drive in FIPS certification mode during provisioning",
        },
        "dislog_adu": {
            "string": "*DISLOG_ADU_HAR",
            "note": "Probable 'Disable Log for ADU Hardware'; ADU = Asymmetric Diag Unlock; state where ADU hardware event suppresses logging",
        },
        "tcg_opal_session": {
            "string": "Responsed    PaxSes    aTransa    Exchange    DCert<    wSigning+    itialCred    oedHash$",
            "note": "Partial TCG OPAL method name strings: Response/Session/Transaction/Exchange/Certificate/Signing/InitialCredential/Hash; confirms full OPAL/OPAL2 implementation",
        },
        "ns_encrypt": {
            "string": "Namespace_Encrypt_Key    S UEFI",
            "note": "Per-namespace NVMe encryption key management; 'S UEFI' = UEFI Secure Boot interaction",
        },
        "nist_hmac_test": {
            "string": "8Cwhat do ya want for nothing?",
            "note": "NIST FIPS 198-1 HMAC test vector string; '\\x8cWhat do ya want for nothing?' is the HMAC message in RFC 2202 / FIPS test case 4; presence confirms HMAC implementation tested against NIST vectors",
        },
    },
}

TOSHIBA_SAS_SSD = {
    "fw_family": "0104",
    "platform": "Phoenix-M3 (Phoenix Technologies SSD firmware framework)",
    "variants": {
        "px05smb": {
            "product": "Toshiba PX05SMB enterprise SAS SSD (MLC NAND)",
            "sizes": ["040", "080", "160"],
            "label": "SSD class",
        },
        "px05srb": {
            "product": "Toshiba PX05SRB enterprise SAS SSD (high-endurance)",
            "sizes": ["048", "096", "192", "384"],
            "label": "SSD class (labeled as HDD in Cisco package names)",
        },
    },
    "fw_size_kb": 1142,
    "fw_md5_prefix": "ef37dcf8",
    "dedup_note": "PX05SMB and PX05SRB share IDENTICAL firmware (md5=ef37dcf8); all 7 capacity variants are the same binary",
    "magic_ascii": "PM04DHWF",
    "magic": "504d303444485746",
    "security_strings": {
        "erase_menu": {
            "strings": [
                "pGPhoenix-M3 FW:",
                "1: Erase SFROM.",
                "4: Erase FW.",
                "5: Erase DDP.",
                "6: Erase Log.",
                "8: Block erase.",
                "-- Erase SFROM --",
                "waiting for completion chip erase...",
                "-- Erase FW --",
            ],
            "note": (
                "Phoenix-M3 framework diagnostic erase menu in production firmware. "
                "SFROM = SPI Flash ROM (factory configuration), FW = Firmware, "
                "DDP = Device Data Partition, Log = diagnostic logs, Block erase = low-level. "
                "'waiting for completion chip erase...' is a SFROM chip erase progress message. "
                "Numbered menu (1,4,5,6,8) with missing items suggests some erase operations "
                "are conditionally hidden but implemented."
            ),
        },
    },
}

HGST_SAS_HDD_FAMILIES = {
    "tcg_enterprise_common": {
        "note": "All HGST enterprise SAS HDD families implement TCG Enterprise security subset; common method labels across families",
        "common_methods": [
            "HashAndSign", "PresentCertificate", "ResponseSign", "ActiveKey",
            "EraseMaster", "MakerDiag",
        ],
        "families": {
            "A320": {
                "product": "HGST Ultrastar SAS HDD HUS724 (2TB/3TB/4TB)",
                "fw_md5_prefix": "264db405",
                "magic": "1200000000000000",
                "additional_strings": ["ReEncryptState", "ReEncryptRequest", "AdvKeyMode", "LastReEncryptLBA", "MaxReEncryptions"],
            },
            "ADD5": {
                "product": "HGST Ultrastar He8/He6 HUS726 (4TB/6TB/8TB SAS)",
                "fw_md5_prefix": "9b71ca56",
                "magic": "1e00000000000000",
                "additional_strings": ["20LockingTemplateClass", "SIGNATURE"],
            },
            "AD50": {
                "product": "HGST Ultrastar SS200 HUC101 (10K SAS)",
                "fw_md5_prefix": "c03a6326",
                "magic": "1e00000000000000",
                "variants_count": 2,
            },
            "A40K_D40K": {
                "product": "HGST Ultrastar He He8 HUS726T (SAS 4TB/6TB, dual firmware A/D)",
                "fw_md5_prefix_a": "9589f6bf",
                "magic": "2330000000000000",
                "additional_strings": ["Obsolete method accessed", "Locking"],
            },
            "A9GH": {
                "product": "HGST Ultrastar He10 HUS728T8TAL4200 (8TB SAS)",
                "fw_md5_prefix": "81090820",
                "magic": "2280000000000000",
                "special_note": "Contains BOTH 'HGST Ultrastar He10 TCG Enterprise HDD, ' AND 'HGST Ultrastar He12 TCG Enterprise HDD, ' identity strings in same binary",
            },
            "T410": {
                "product": "HGST Ultrastar He12 HUS728T8TALE600 (8TB SAS)",
                "fw_md5_prefix": "6088ee98",
                "magic": "2200000000000000",
                "note": "Contains He12 identity string only; T410 vs A9GH = He12 vs He10 generation fork",
            },
            "A730": {
                "product": "HGST Ultrastar HUC109 10K SAS (300/600/900GB)",
                "fw_md5_prefix": "334a3c04",
                "magic": "0e80000000000000",
                "note": "Older model; TCG Enterprise subset minimal ('Obsolete method accessed' -- backward compatibility indicator)",
            },
            "A3Z4": {
                "product": "HGST Ultrastar He10 HUH721010AL4200 (10TB SATA/SAS)",
                "fw_md5_prefix": "197c0dbb",
                "magic": "20e0000000000000",
            },
            "A7JX": {
                "product": "HGST Ultrastar He12 HUH728080AL4200 (8TB SAS)",
                "fw_md5_prefix": "7b78f243",
                "magic": "1c80000000000000",
                "additional_strings": ["20LockingTemplateClass", "SIGNATURE"],
            },
        },
    },
}

TOSHIBA_SAS_HDD = {
    "fw_header_magic_ascii": "FMCL  AL",
    "magic_hex": "464d434c2020414c",
    "common_strings": ["Tcg0####", "Tcg1####"],
    "families": {
        "5706": {
            "product": "Toshiba AL13SEB enterprise SAS HDD (300/600/900GB)",
            "fw_md5_prefix": "ed4f7b37",
            "variants": 3,
        },
        "5703": {
            "product": "Toshiba AL13SXB enterprise SAS HDD (300/450/600GB)",
            "fw_md5_prefix": "91049d33",
            "variants": 3,
            "additional_strings": ["MAP EYE DIAGRAM", "@' BER <  0.000001", "$' BER <  0.0001"],
        },
        "1703_5705": {
            "product": "Toshiba AL14SEB enterprise SAS HDD (300/600/900GB) -- two firmware families share AL14SEB platform",
            "fw_md5_5705": "6e30a5fc",
            "additional_strings": ["MAP EYE DIAGRAM", "@' BER <  0.000001", "$' BER <  0.0001"],
        },
        "5704": {
            "product": "Toshiba AL14SXB / AL15SEB enterprise SAS HDD (12 variants across SXB and SEB models)",
            "fw_md5_prefix_al14sxb": "da8b7639",
            "fw_md5_prefix_al15seb": "5a04f761",
            "additional_strings": ["MAP EYE DIAGRAM", "@' BER <  0.000001", "$' BER <  0.0001", "Sample message for keylen<blocklen"],
        },
        "5705_mg04": {
            "product": "Toshiba MG04SCA enterprise SAS HDD (2/4/6TB)",
            "fw_md5_prefix": "60c3b616",
            "additional_strings": ["MAP EYE DIAGRAM", "@' BER <  0.000001", "$' BER <  0.0001"],
        },
    },
    "eye_diagram_note": (
        "'5. MAP EYE DIAGRAM' with BER threshold display ('@' BER < 0.000001, '$' BER < 0.0001) "
        "appears in production AL13SXB/AL14SEB/AL14SXB/AL15SEB/MG04SCA firmware. "
        "Signal quality map is a diagnostic output in the field firmware binary."
    ),
}

CPLD_FIRMWARE = {
    "gpufm_cpld": {
        "fw_version": "1.005",
        "product": "Intel MAX 10 FPGA -- GPU Form Module CPLD (x10c-gpufm-cpld)",
        "instances": ["x210c-m7", "x210c-m8", "x410c-m7", "x410c-m8", "x215c-m8"],
        "fw_md5_prefix": "09e5a3f4",
        "magic": "27436f7079726967",
        "format": "JTAG SVF (Serial Vector Format) for Intel MAX 10 FPGA programming",
        "svf_bypass_operations": [
            "DO_BYPASS_CFM OPTIONAL",
            "DO_BYPASS_UFM OPTIONAL",
            "DO_BYPASS_ICB OPTIONAL",
            "DO_BYPASS_CFM1 OPTIONAL",
            "DO_IGNORE_IDCODE_ERRORS OPTIONAL",
            "DO_IGNORE_INTOSC_BYPASS RECOMMENDED",
            "DO_BYPASS_SECOND_IDCODE_READ OPTIONAL",
        ],
        "svf_segments": ["CFM0", "CFM1", "UFM"],
        "usercode": "000A9D93",
    },
    "m1l6_cpld": {
        "fw_version": "2.005",
        "product": "RAID M1L6 CPLD (raid-m1l6-cpld)",
        "magic": "4646464642444233",
        "format": "Binary bitstream (FFFFBDB3 pattern -- raw CPLD programming data)",
        "security_hits": "none",
    },
    "raidf_ubm": {
        "fw_version": "0x445",
        "product": "RAIDF UBM (Universal Backplane Management) firmware",
        "magic": "3031303032313133",
        "magic_ascii": "01002113",
        "format": "UBM protocol version header",
        "security_hits": "none",
    },
}

WDC_NVME_R12 = {
    "fw_family": "R121000B",
    "product": "WDC Ultrastar DC ZN540 / DC SN640 NVMe (NVMW series, B-Series blade optimized)",
    "variants": ["NVMW19T", "NVMW64T"],
    "fw_size_kb": 2883,
    "fw_md5_prefix": "d5dc5a59",
    "magic_ascii": "PACV",
    "magic": "50414356000c2d00",
    "security_hits": "none",
    "note": "PACV header (WDC NVMe container format); 4 capacity variants all share same md5",
}

HGST_NVME_KMCCP108 = {
    "fw_family": "KMCCP108",
    "product": "HGST WD_BLACK AN1500 / WD Blue SN570 enterprise PCIe NVMe (SDHPCIE form factor)",
    "variants": ["SDHPCIE800GB", "SDHPCIE16TB"],
    "fw_size_kb": 1060,
    "fw_md5_prefix": "71ea7d7c",
    "magic_ascii": "FWHEADER",
    "magic": "4657484541444552",
    "security_strings": {
        "debug_exception_vector": {
            "string": ".DebugExceptionVector.literal    .DebugExceptionVector.text",
            "note": "Xtensa ISA ELF section names for the hardware debug exception handler; Xtensa DebugExceptionVector is triggered by hardware breakpoints and OCD (On-Chip Debugging). KMCCP108 uses Xtensa CPU vs KNCCD122 (ARM), confirming different microarchitecture.",
        },
        "erase_count": {
            "string": "ERASECNT",
            "note": "Flash erase count tracking; standard SSD wear management metadata visible as a string",
        },
    },
}

HGST_SAS_SSD = {
    "D17D": {
        "product": "HGST Ultrastar SS200 HUSMM32 enterprise SAS SSD",
        "fw_md5_prefix": "0da1126f",
        "magic": "1710000000000000",
        "variants": 3,
        "security_hits": "none",
    },
    "A17D": {
        "product": "HGST Ultrastar SS200 HUSMR32 enterprise SAS SSD",
        "fw_md5_prefix": "55a784e5",
        "magic": "1710000000000000",
        "variants": 4,
        "note": "Same magic prefix as D17D (0x1710); same firmware container format, different binary",
        "security_hits": "none",
    },
    "A551": {
        "product": "HGST Ultrastar SS300 HUSTR7 enterprise SAS SSD",
        "fw_md5_prefix": "c3b83835",
        "magic": "1850000000000000",
        "variants": 4,
        "security_hits": "none",
    },
}

PSU_DV = {
    "Delta_DV": {
        "fw_version": "03.00.00",
        "product": "Delta DV-series PSU firmware",
        "fw_size_kb": 48,
        "fw_md5_prefix": "f52d6703",
        "magic": "f101020c02021353",
        "security_hits": "none",
        "note": "DV variant smaller (48KB) vs DTM-2800AC (94KB)",
    },
    "Emerson_DV": {
        "fw_version": "05.0b",
        "product": "Emerson/Vertiv DV-series PSU firmware",
        "fw_size_kb": "approx 8-25",
        "note": "Emerson PSU; no security hits",
    },
}

FINDINGS = {
    "SOLIDIGM-ASYM-DIAG-UNLOCK-F1": {
        "id": "SOLIDIGM-ASYM-DIAG-UNLOCK-F1",
        "severity": "HIGH",
        "title": "Asymmetric Key Diagnostic Unlock Protocol in Solidigm 9CV10510 NVMe Firmware",
        "component": "Solidigm NVMe 9CV10510 (UCS-NVB* family, 15 capacity variants, shared md5=ba30360b)",
        "what": (
            "Solidigm 9CV10510 firmware contains an 'Asymmetric Diag Unlock' mechanism "
            "with an associated 'Auth Key' and TCG OPAL-style session parameters "
            "(MaxComPacket, MaxIndToken). Surrounding context includes: "
            "'Exchange', 'DCert<' (Device Certificate), 'wSigning+' (signing operation), "
            "'itialCred' (InitialCredential), 'oedHash$' (signed/HMAC hash). "
            "The state machine includes 'DISLOG_ADU_HAR' (probable: Disable Log for ADU Hardware) "
            "adjacent to FIPS states ('*FIPS_IN_PROGRESS', 'INITIALIZED', 'HEALTHY'). "
            "Additional finding: NVMe Feature ID D2h labeled 'bmc management' -- "
            "a vendor-specific BMC management interface. "
            "NIST FIPS 198-1 HMAC test vector 'what do ya want for nothing?' is embedded."
        ),
        "why": (
            "An asymmetric key diagnostic unlock with its own authentication protocol "
            "(certificate exchange, signing, credential verification) creates a privileged "
            "access channel on the drive controller. If Solidigm uses a shared or "
            "escrowable private key for the diagnostic certificate, any party who recovers "
            "that key can unlock diagnostic access on all drives of this firmware family. "
            "The DISLOG_ADU state suppresses logging during the diagnostic unlock, "
            "making forensic detection of ADU abuse harder. "
            "The D2h BMC management interface is an out-of-band channel that a BMC compromise "
            "could use to communicate directly with the SSD controller. "
            "15 capacity variants all sharing one binary (md5=ba30360b) means a single "
            "vulnerability affects the entire NVB capacity range."
        ),
        "evidence": {
            "asym_diag_unlock": "Asymmetric Diag Unlock",
            "auth_key": "Auth Key",
            "session_params": "MaxComPacket    MaxIndToken",
            "cert_exchange": "DCert<    wSigning+    itialCred    oedHash$",
            "state_machine": "*DISLOG_ADU_HAR    *FIPS_IN_PROGRE[SS]    *INITIALIZED    HEALTHY",
            "bmc_mgmt": "D2 - bmc management%",
            "nist_hmac_tv": "8Cwhat do ya want for nothing?",
        },
        "remediation": (
            "Obtain Solidigm ADU key management documentation. Verify whether the "
            "asymmetric private key used for diagnostic authentication is per-drive, "
            "per-batch, or per-family. Per-drive keys (requiring physical access to "
            "extract) are acceptable; shared keys are not. Confirm ADU log suppression "
            "cannot be abused to mask diagnostic access. Disable the D2h BMC management "
            "NVMe feature on Cisco UCS deployments unless explicitly required."
        ),
    },

    "TOSHIBA-PHOENIX-ERASE-MENU-F1": {
        "id": "TOSHIBA-PHOENIX-ERASE-MENU-F1",
        "severity": "MEDIUM",
        "title": "Phoenix-M3 Diagnostic Erase Menu in Production Toshiba PX05 SAS SSD Firmware",
        "component": "Toshiba PX05SMB + PX05SRB SAS SSDs (0104 firmware, 7 variants, single shared binary md5=ef37dcf8)",
        "what": (
            "Both Toshiba PX05SMB (enterprise SAS SSD) and PX05SRB (high-endurance SAS SSD) "
            "share identical firmware (md5=ef37dcf8) built on the Phoenix-M3 SSD firmware framework. "
            "The firmware contains a numbered diagnostic erase menu with the following options: "
            "'1: Erase SFROM.' (SPI Flash ROM -- factory configuration), "
            "'4: Erase FW.' (Firmware flash), "
            "'5: Erase DDP.' (Device Data Partition), "
            "'6: Erase Log.' (Diagnostic log partition), "
            "'8: Block erase.' (Low-level block erase). "
            "Menu includes the progress message 'waiting for completion chip erase...' for SFROM operations. "
            "The non-contiguous numbering (1,4,5,6,8) suggests omitted items conditionally hidden."
        ),
        "why": (
            "A diagnostic erase menu with Firmware and SFROM erase capabilities in production firmware "
            "creates a destructive capability reachable through the Phoenix-M3 diagnostic interface. "
            "If the Phoenix-M3 diagnostic mode is accessible via: "
            "(a) SAS vendor-specific commands (SPC-5 vendor-unique opcodes), "
            "(b) SCSI Maintenance In diagnostic functions, or "
            "(c) direct SPI programming via JTAG, "
            "an attacker could erase the firmware partition of all PX05 drives in a UCS deployment. "
            "SFROM erase removes factory configuration data and may brick the drive. "
            "The 7-variant dedup (md5=ef37dcf8) means the identical exposure exists across "
            "all PX05SMB and PX05SRB capacity points."
        ),
        "evidence": {
            "platform": "pGPhoenix-M3 FW:",
            "erase_sfrom": "1: Erase SFROM.",
            "erase_fw": "4: Erase FW.",
            "erase_ddp": "5: Erase DDP.",
            "erase_log": "6: Erase Log.",
            "block_erase": "8: Block erase.",
            "chip_erase_wait": "waiting for completion chip erase...",
            "dedup": "PX05SMB and PX05SRB share md5=ef37dcf8",
        },
        "remediation": (
            "Determine the access vector for the Phoenix-M3 diagnostic interface on the PX05 platform. "
            "If accessible via any SAS command reachable from the host OS, the diagnostic erase "
            "must be gated by a hardware authentication mechanism (PIN, challenge-response). "
            "Confirm that Firmware erase requires physical presence (JTAG pin access)."
        ),
    },

    "HGST-SAS-HDD-TCG-ENTERPRISE-F1": {
        "id": "HGST-SAS-HDD-TCG-ENTERPRISE-F1",
        "severity": "MEDIUM",
        "title": "TCG Enterprise SED with MakerDiag + EraseMaster + ReEncrypt Across All HGST SAS HDD Families",
        "component": (
            "HGST SAS HDD: A320 (HUS724), ADD5 (HUS726), A40K (HUS726T), A9GH (HUS728 He10), "
            "T410 (HUS728 He12), HUC101 (AD50 10K), HUH721 (He10 SATA/SAS), HUH728 (He12), A730 (HUC109)"
        ),
        "what": (
            "All HGST enterprise SAS HDD families implement TCG Enterprise security subset with "
            "a consistent set of manufacturer-level method labels: "
            "'MakerDiag' (manufacturer diagnostic), 'EraseMaster' (cryptographic master erase), "
            "'HashAndSign', 'PresentCertificate', 'ResponseSign', 'ActiveKey'. "
            "A320/ADD5/A7JX/HUH728 families additionally include: "
            "'ReEncryptState', 'ReEncryptRequest', 'AdvKeyMode', 'LastReEncryptLBA', 'MaxReEncryptions' -- "
            "an in-place live-data re-encryption capability with state tracking. "
            "A9GH single binary contains identity strings for BOTH 'HGST Ultrastar He10 TCG Enterprise HDD' "
            "AND 'HGST Ultrastar He12 TCG Enterprise HDD'. "
            "A730 (older HUC109 family) contains 'Obsolete method accessed' -- "
            "backward compatibility path for deprecated TCG Enterprise methods."
        ),
        "why": (
            "MakerDiag is a TCG Enterprise-specific manufacturer diagnostic command intended for "
            "factory use. Its presence in field firmware means any entity that knows the "
            "MakerDiag authentication credential can run manufacturer diagnostics on deployed drives. "
            "EraseMaster is a cryptographic erase of the master encryption key (MEK), permanently "
            "destroying all data. If reachable via SAS vendor-specific or SCSI Maintenance commands "
            "without physical-access authentication, it becomes a data destruction vector. "
            "ReEncryptRequest/State on A320/ADD5 families indicates live re-encryption can be triggered; "
            "if this can be abused, an adversary could initiate expensive re-encryption operations "
            "to degrade drive performance. "
            "A9GH dual He10/He12 identity: a firmware update targeting He12 is accepted by He10 "
            "hardware (or vice versa), potentially pushing an incompatible but validated image."
        ),
        "evidence": {
            "maker_diag": "MakerDiag (all families)",
            "erase_master": "EraseMaster (all families)",
            "re_encrypt": "ReEncryptState, ReEncryptRequest, LastReEncryptLBA, MaxReEncryptions (A320/ADD5/HUH728)",
            "dual_identity": "'HGST Ultrastar He10 TCG Enterprise HDD, ' + 'HGST Ultrastar He12 TCG Enterprise HDD, ' in A9GH binary",
            "obsolete_method": "Obsolete method accessed (A730/A40K/HUH721)",
        },
        "remediation": (
            "Audit access control for TCG Enterprise MakerDiag and EraseMaster methods in deployed "
            "HGST drives. Confirm these methods require a hardware-bound credential (per-drive or "
            "per-batch certificate) that is not recoverable from the firmware binary. "
            "Investigate whether ReEncrypt operations can be triggered via standard SAS commands "
            "or require TCG session authentication. Review Cisco UCS storage controller SAS zoning "
            "to limit which host HBAs can issue vendor-specific SAS commands to HGST drives."
        ),
    },

    "CPLD-SVF-BYPASS-OPTIONAL-F1": {
        "id": "CPLD-SVF-BYPASS-OPTIONAL-F1",
        "severity": "LOW",
        "title": "Intel MAX 10 FPGA CPLD SVF Programming File Marks Verification Steps OPTIONAL",
        "component": "x10c-gpufm-cpld.1.005 (SVF file; gpufm = GPU Form Module CPLD; present on x210c-m7/m8, x410c-m7/m8, x215c-m8)",
        "what": (
            "The GPU Form Module CPLD firmware (gpufm-cpld.1.005) is a JTAG SVF (Serial Vector Format) "
            "file for an Intel MAX 10 FPGA. The SVF defines programming actions with the following "
            "verification steps marked as OPTIONAL: "
            "DO_BLANK_CHECK OPTIONAL, DO_VERIFY RECOMMENDED (not REQUIRED), "
            "DO_BYPASS_CFM OPTIONAL, DO_BYPASS_UFM OPTIONAL, "
            "DO_BYPASS_ICB OPTIONAL (ICB = Initial Configuration Byte), "
            "DO_BYPASS_CFM1 OPTIONAL, DO_IGNORE_IDCODE_ERRORS OPTIONAL, "
            "DO_BYPASS_SECOND_IDCODE_READ OPTIONAL. "
            "The file programs three CFM/UFM flash segments and identifies the target by USERCODE 000A9D93. "
            "The actions defined are: PROGRAM (L0), BLANKCHECK (L17), CONFIGURE (L20), ERASE (L24)."
        ),
        "why": (
            "SVF files with OPTIONAL verification steps allow a programming tool to skip: "
            "blank check (verify erase before programming -- skipping allows overwrite without erase), "
            "IDCODE verification (skip chip identity check -- allows cross-programming wrong device), "
            "post-programming verify (skip read-back confirmation -- allows silent programming failures), "
            "ICB authentication bypass (Initial Configuration Byte controls MAX 10 boot security). "
            "If a malicious SVF file can be delivered to the Cisco UCS CPLD update path "
            "(CIMC/UCSM firmware update), these OPTIONAL markers mean the programming tool "
            "will not halt on failed verifications. The GPU Form Module CPLD controls GPU slot "
            "power and PCIe presence -- a corrupted CPLD could disable or misconfigure GPU slots."
        ),
        "evidence": {
            "bypass_cfm": "DO_BYPASS_CFM OPTIONAL",
            "bypass_icb": "DO_BYPASS_ICB OPTIONAL",
            "ignore_idcode": "DO_IGNORE_IDCODE_ERRORS OPTIONAL",
            "usercode": "USERCODE 000A9D93",
            "segments": "MAX 10 CFM0/CFM1/UFM",
        },
        "remediation": (
            "Verify that the Cisco CIMC/UCSM CPLD update path validates USERCODE before and after "
            "programming, even when the SVF marks steps as OPTIONAL. The programming tool should "
            "override OPTIONAL bypass steps to enforce full verification. "
            "Confirm ICB (Initial Configuration Byte) is not bypassable on deployed hardware."
        ),
    },

    "HGST-NVME-KMCCP108-XTENSA-F1": {
        "id": "HGST-NVME-KMCCP108-XTENSA-F1",
        "severity": "LOW",
        "title": "Xtensa ISA DebugExceptionVector in HGST NVMe KMCCP108 Production Firmware",
        "component": "HGST NVMe KMCCP108 (SDHPCIE800GB/16TB, md5=71ea7d7c, magic FWHEADER)",
        "what": (
            "HGST KMCCP108 firmware contains ELF section names: "
            "'.DebugExceptionVector.literal' and '.DebugExceptionVector.text'. "
            "These are Xtensa ISA ELF sections for the hardware debug exception vector "
            "(triggered by JTAG/OCD hardware breakpoints). "
            "KMCCP108 (SDHPCIE form factor) uses Xtensa CPU architecture, "
            "distinct from KNCCD122 (1719KB, FWHEADER magic, ARM-style DiagMgr shell). "
            "The firmware container magic 'FWHEADER' is shared between KMCCP108 and KNCCD122."
        ),
        "why": (
            "The DebugExceptionVector.text ELF section contains the handler for hardware debug "
            "exceptions (JTAG trap instructions, hardware breakpoints). Its presence in the "
            "production binary means OCD (On-Chip Debugging) is not fully disabled in the "
            "production build. An attacker with physical JTAG access could trigger debug "
            "exceptions to gain code execution visibility into the Xtensa controller."
        ),
        "evidence": {
            "elf_sections": ".DebugExceptionVector.literal    .DebugExceptionVector.text",
            "arch": "Xtensa ISA (Cadence/Tensilica)",
            "magic": "FWHEADER",
        },
        "remediation": "Confirm Xtensa OCD (OnCD) interface is fused off in KMCCP108 production silicon.",
    },

    "TOSHIBA-HDD-EYE-DIAGRAM-F1": {
        "id": "TOSHIBA-HDD-EYE-DIAGRAM-F1",
        "severity": "LOW",
        "title": "SAS Signal Quality Eye Diagram + BER Thresholds in Production Toshiba HDD Firmware",
        "component": "Toshiba HDD/SAS AL13SXB (5703), AL14SEB (5705/1703), AL14SXB (5704), AL15SEB (5704), MG04SCA (5705) -- all FMCL  AL magic",
        "what": (
            "Multiple Toshiba SAS HDD production firmware families (5703/5704/5705/1703) contain: "
            "'5. MAP EYE DIAGRAM' (signal quality diagnostic output), "
            "'At sign \\x27@\\x27 BER < 0.000001' (best signal threshold), "
            "'Dollar sign \\x27$\\x27 BER < 0.0001' (marginal signal threshold). "
            "AL15SEB (5704) additionally: 'Sample message for keylen<blocklen' -- HMAC test vector "
            "string confirming HMAC implementation with keylen < blocklen test case. "
            "All families share 'Tcg0####' and 'Tcg1####' TCG marker strings. "
            "All use 'FMCL  AL' (464d434c2020414c) firmware container magic."
        ),
        "why": (
            "Eye diagram output in production HDD firmware (via SAS diagnostic commands) allows "
            "physical layer signal quality measurement without specialized test equipment. "
            "An attacker with SAS bus access could issue the eye diagram diagnostic command "
            "to confirm whether a SAS link is operating at marginal BER -- useful intelligence "
            "for fault injection timing. This is informational rather than directly exploitable, "
            "but diagnostic outputs of this type should require authentication in the field."
        ),
        "evidence": {
            "eye_diagram": "5. MAP EYE DIAGRAM",
            "ber_thresholds": "@' BER < 0.000001    $' BER < 0.0001",
            "hmac_test_vector": "Sample message for keylen<blocklen (AL15SEB 5704 only)",
            "tcg_markers": "Tcg0####    Tcg1####",
        },
        "remediation": "Confirm whether eye diagram diagnostic output requires authentication (SAS Maintenance In or vendor-specific opcode with authentication requirement).",
    },
}

BUNDLE_ANALYSIS_METADATA = {
    "bundle": "ucs-k9-bundle-b-series.6.0.2b.B.bin",
    "session": 29,
    "module_number": 5,
    "components_analyzed_count": "40+",
    "total_findings": 6,
    "severity_breakdown": {"HIGH": 1, "MEDIUM": 2, "LOW": 3},
    "key_technical_notes": [
        "Solidigm 9CV10510 is the FIRST non-Intel brand enterprise NVMe in this bundle (Solidigm = post-spin-off Intel NAND); Asymmetric Diag Unlock is a novel diagnostic auth mechanism not seen in other drives",
        "D2h NVMe Feature ID for BMC management in Solidigm: vendor-specific, not in NVMe base spec",
        "HGST SAS HDD TCG Enterprise: MakerDiag and EraseMaster are manufacturer-only commands; 10+ families all implement the same set",
        "ReEncrypt (A320/ADD5) = in-place re-encryption: key rotation without data decryption; MaxReEncryptions bounds the operation count",
        "A9GH binary dual identity (He10+He12): both hardware generations share one firmware binary with dual identity strings",
        "Toshiba HDD FMCL AL magic: all Toshiba HDD families in bundle use same container format (FMCL  AL header)",
        "gpufm-cpld SVF is for Intel MAX 10 FPGA (not an older CPLD -- MAX 10 is Intel's lowest-cost FPGA family with integrated flash); CPLD in Cisco UCS X-Series controls GPU Form Module power/presence",
        "HGST KMCCP108 vs KNCCD122: different CPU arch (Xtensa vs ARM), different product line (SDHPCIE vs standard NVMe M.2), different diagnostic mechanisms",
        "Toshiba 0104 family covers both SSD (px05smb) and SAS SSD (px05srb) in same binary -- Phoenix-M3 is the common platform firmware",
        "All Toshiba SAS HDD families: Tcg0/Tcg1 markers only; no full OPAL/Enterprise SED method labels -- lighter TCG implementation than HGST",
        "WDC NVMe R121000B (PACV header) -- 4 capacity variants identical; no security hits in printed strings",
        "HGST SAS SSDs (D17D/A17D/A551) -- large binaries (1.4-1.5MB), no security string hits; SAS SSD vs HDD: SSDs may have different diagnostic interface",
    ],
}
