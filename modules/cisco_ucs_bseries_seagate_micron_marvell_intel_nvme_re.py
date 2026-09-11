"""
Cisco UCS B-Series: Seagate HDD/SSD, Micron SATA, Marvell RAID, Intel NVMe Advanced, WD SAS SSD
Bundle: ucs-k9-bundle-b-series.6.0.2b.B.bin

Covers:
- Intel/Solidigm NVMe multi-family Asymmetric Diag Unlock survey
  (VDV1CP05 P4511/UCSC-NVME2H, ACV10370 NVMEI4-Q, 7CV1CS05 Youngsville, L031CP02 NVMEXP)
- Seagate SAS HDD families: N0A6/K0A6/CN06/N004/K0E5/CT06/CN04/CK08/CN02/A005/C007/0003/0002/0004/0003
- Seagate SAS SSD: CE05 (XS960SE), CE02 (XS3200LE)
- Micron SATA SSD: 5100 (D0MH/D0MC), 5200 (D1MH/D1CH), D3MC000, FIPS MB19, legacy 0157
- Micron SATA SSD M.2: MTFDDAV D3MC000
- Marvell M.2 HWRAID: marvell.2.3.17.2002 + 88SE92xx.2.3.17.1014
- WD/HGST SAS SSD: D971 (WUSTM) + A971 (WUSTR)
- Samish Lake controller 52.34.0-6415 (second binary, different version)
- MegaRAID HE CPLD (00011) -- Intel MAX II security bits
- PT4F CPLD.3.006 (x210c/x410c variants) -- Altera MAX SVF bypass
- B200M6/B480M5 CIMC -- jtagboot + presidio/pomona CHIMP codenames
- Samsung SSD HMAC function chain
"""

INTEL_ADU_SURVEY = {
    "asymmetric_diag_unlock_confirmed_families": {
        "9CV10510_Solidigm_NVMe": {
            "fw_size_kb": 1484,
            "md5_prefix": "ba30360b",
            "adu_string": "Asymmetric Diag Unlock    Auth Key",
            "note": "Solidigm enterprise NVMe (covered in prior module; confirms ADU pattern is cross-family)",
        },
        "VDV1CP05_Intel_P4511_SED": {
            "product": "Intel P4511 M.2 SED Opal NVMe (UCSC-NVME2H-I*)",
            "variants": 6,
            "fw_size_kb": 1508,
            "md5_prefix": "edf8cb97",
            "magic": "06000000a1000000",
            "adu_string": "Asymmetric Diag Unlock          Asymmetric Diag Unlock Auth Key",
            "additional_strings": {
                "msid": "MSID_password",
                "fw_auth": "Device_FW_Authentication        FW_MAC_Key",
                "ns_encrypt": "Namespace_Encrypt_Key    NS_Encrypt_Key",
                "max_auth": "MaxAuthentications",
                "product_ids": ["Intel P4511 M.2 650GB SED Opal", "Intel P4511 M.2 1TB SED Opal", "Intel P4511 M.2 2TB SED Opal"],
            },
        },
        "ACV10370_Intel_NVMEQ_1536": {
            "product": "Intel NVMe UCS-NVMEQ-1536 (Queues optimized for 1536 SQ/CQ?)",
            "fw_size_kb": 1812,
            "md5_prefix": "bf6fdfa5",
            "magic": "06000000a1000000",
            "adu_full_string": "Asymmetric Diag Unlock          Asymmetric Diag Unlock Auth Key    MaxAuthentications    HostExchangeAuthority    HostExchangeCert    HostSigningAuthority    HostSigningCert",
            "note": "MOST COMPLETE ADU certificate chain seen: adds HostExchangeAuthority/Cert and HostSigningAuthority/Cert -- full PKI chain for ADU",
            "additional_strings": {
                "ns_encrypt": "Namespace_Encrypt_Key    NS_Encrypt_Key",
                "adu_data": "Asymmetric Diag Unlock Auth Key 010 (with data suffix)",
            },
        },
        "7CV1CS05_Solidigm_SATA": {
            "product": "Solidigm/Intel Youngsville RR SATA SSD (SSDSC2KB480GZK etc.) -- enterprise SATA SED",
            "variants": 9,
            "fw_size_kb": 1428,
            "md5_prefix": "d9437c2a",
            "magic": "06000000a1000000",
            "dual_bootloader_identity": {
                "string1": "Intel Youngsville RR Bootloader",
                "string2": "Solidigm Youngsville RR Bootloader",
                "note": "Same firmware binary contains BOTH Intel and Solidigm bootloader identity strings; post-acquisition dual branding",
            },
            "adu_string": "Asymmetric Diag Unlock    Asymmetric Diag Unlock Auth Key 010",
            "additional_strings": {
                "msid": "MSID_password",
                "fw_auth": "Device_FW_Authentication    FW_MAC_Key",
                "ns_encrypt": "Namespace_Encrypt_Key    NS_Encrypt_Key",
            },
            "note": "SATA interface (not NVMe) -- ADU mechanism also implemented in SATA SSDs",
        },
        "L031CP02_Intel_NVMEXP": {
            "product": "Intel/Solidigm NVMe UCSC-NVMEXP-I800 (Express Bay NVMe)",
            "variants": 2,
            "fw_size_kb": 1328,
            "md5_prefix": "c880347b",
            "magic": "06000000a1000000",
            "fips_states": ["*BAD_ASSIGN_ID", "*FIPS_IN_PROGRESS", "*SECURITY_FAIL"],
            "dell_identity_strings": [
                "Dell Ent NVMe P5800x SED WI",
                "Dell Ent NVMe P5810x SED WI",
                "Dell Ent NVMe P5810x SED WI U.2 400GB",
                "Dell Ent NVMe P5800x SED WI U.2 400GB",
                "Dell Ent NVMe P5810x SED WI U.2 800GB",
            ],
            "note": "Dell product identity strings embedded in Cisco UCS NVMEXP firmware; same Intel/Solidigm P5800x/P5810x binary re-labeled for both Dell and Cisco",
        },
    },
    "change_definition_verify_password": {
        "fw_family": "2CV1C036",
        "product": "Intel NVMe UCSC-NVMEI4-I6400 (I4 QLC enterprise NVMe)",
        "variants": 6,
        "fw_size_kb": 1764,
        "md5_prefix": "17deb0fe",
        "strings": [
            "ChangeDefinitionVerifyPassword 02",
            "ChangeDefinitionVerifyPassword 03 - password=%d",
            "ChangeDefinitionVerifyPassword 04",
            "ChangeDefinitionVerifyPassword 05",
            "ChangeDefinitionVerifyPassword pBuffer=%p",
        ],
        "fips_states": ["*FIPS_IN_PROGRESS", "*FIPS_DRAM_FAIL", "*FIPS_SRAM_FAIL"],
        "note": "ChangeDefinitionVerifyPassword is a TCG SSC template modification method requiring password authentication; numbered steps (02-05) visible with format strings; FIPS DRAM and SRAM failure states indicate separate memory self-tests",
    },
}

SEAGATE_SAS_HDD = {
    "common_magic": "e71a0e5901000200",
    "common_fuse_error": " Misconfigured SBP Fuse Bits: ",
    "common_tcg": ["_SecurityOperatingMode", "ActiveKey", "~IsMixedKey", "_PortLocking", "Authority"],
    "common_sig_verify": [" VerifyCtrlFirmwareSignature failed", " VerifyOverlaySignature failed "],
    "diagnostic_mode": ["UDS_Debug", "PsgDiagOnline", "DiagExtrinc"],
    "families": {
        "N0A6": {
            "product": "Seagate ST300MM0008 / ST600MM0008 SAS 10K (300/600GB)",
            "fw_md5_300": "9cee03ea", "fw_md5_600": "4d9d9525",
            "variants_total": 6,
            "note": "Misconfigured SBP Fuse Bits + sig verification failures",
        },
        "K0E5": {
            "product": "Seagate ST6000NM0014 SAS nearline 6TB",
            "fw_md5": "5be0f192",
            "additional_strings": ["Head Tests - CumTestsPassedHeadMask %04X", "EraseMaster"],
        },
        "A005": {
            "product": "Seagate ST4000NM0063 / ST300MM0006 SAS nearline (4TB/300GB)",
            "note": "NVC Debug Log + GlobalHeader EraseInProgress tracking",
            "nvc_strings": ["NVC Debug Log:", "Last Saved GlobalHeader EraseInProgress:", "flash empty read disc disc data sign not match", "NVCClearingEraseInProgress"],
        },
        "CN06": {
            "product": "Seagate ST1000NX0453 / ST1200NX0053 SAS nearline 1-1.2TB",
            "note": "Misconfigured SBP Fuse Bits; all near-line families share fuse error path",
        },
        "CT06": {
            "product": "Seagate ST1000NX0423 SAS nearline 1TB",
            "additional_strings": ["PsgDiagOnline", "DiagExtrinc", "UDS_Debug"],
        },
        "CN04": {
            "product": "Seagate ST300MM0048 / ST600MM0048 SAS 10K",
            "fw_md5": "e0a18381",
            "additional_strings": ["EraseMaster", "_SecurityStateControl"],
        },
        "CK08": {
            "product": "Seagate ST1800MMY129/149 / ST2400MMY129/149 SAS 10K 1.8/2.4TB",
            "fw_md5": "b0d577ca",
            "additional_strings": ["Head Tests - CumTestsPassedHeadMask %04X", "EraseMaster"],
        },
        "N004": {
            "product": "Seagate ST300MP0005 / ST600MP0005 / ST1200MP0005 SAS 10K 2.5-inch",
            "fw_md5": "400ac437",
            "note": "Same Misconfigured SBP Fuse Bits pattern",
        },
        "legacy_families": {
            "0003_0002": {
                "product": "Seagate ST3600057SS / ST33000650SS / ST2000NM0001 SAS legacy",
                "magic": "0000000000000000",
                "strings": ["Unknown signal", "User-defined signal 1", "SetDiagnosticTest is done.", "Diagnostics", "DiagExtrinc", "UDS_Debug", "PsgDiagOnline"],
                "note": "Older generation; null magic; diagnostic modes present",
            },
            "early_nvme": {
                "product": "Seagate ST1000NM0023 C007 / ST91000640SS 0004 / ST1200MM0007 0003",
                "magic": "0000000000000000",
                "strings": ["Unable to load Diag Cmd Processor Overlay", "Invalid Diag Cmd", "Diag Batch File", "Diag Data Type %04X Rev %02X DiagErr %08X", "TCG IV Version: n/a"],
                "note": "TCG IV Version: n/a -- TCG OPAL not implemented in these early SAS drives",
            },
        },
    },
}

SEAGATE_SAS_SSD = {
    "CE05": {
        "product": "Seagate NYTRO XS960SE70075 / XS1920SE70075 enterprise SAS SSD",
        "fw_size_kb": 2064,
        "fw_md5_prefix": "a32f066a",
        "magic": "e71a0e5901000200",
        "variants": 8,
        "security_strings": [
            " Misconfigured SBP Fuse Bits: ",
            "Firmware Signature verification failed.",
            "MERT_ERASE",
            " MERT Error: Pattern END signature is not 0x%x",
            " Performing Blocking MList process...",
            " IP0 GetFlashSegmentParameters PASSED DL_MERT=%ld",
            " <<<<<<<decryption error on recovery>>>>>>",
            " shred previous buffer error on recovery",
        ],
    },
    "CE02": {
        "product": "Seagate NYTRO XS3200LE70114 / XS800LE70114 enterprise SAS SSD",
        "fw_size_kb": 2096,
        "fw_md5_prefix": "4a1b7f5b",
        "magic": "e71a0e5901000200",
        "variants": 6,
        "security_strings": [
            " Misconfigured SBP Fuse Bits: ",
            "Firmware Signature verification failed.",
            " <<<<<<<decryption error on recovery>>>>>>",
            " shred previous buffer error on recovery",
            " MakeActive_KeyStore >> Transition to FAILED state...",
            "_PortLocking",
            "EraseMaster",
            "Authority",
        ],
    },
}

MICRON_SATA_SSD = {
    "common_magic_prefix": "4e52434d",
    "magic_note": "NRCM header (4e52434d = 'NRCM'? -- Micron firmware container magic)",
    "common_fde_strings": [
        "<FDE> ATA Security Locked",
        "<FDE> ATA Security UnLocked",
        "<FDE> ATA Security Frozen",
        "<FDE> ATA Security UnFrozen",
    ],
    "families": {
        "5100": {
            "fw_family": "D0MH077 / D0MH447 / D0MH847",
            "product": "Micron 5100 PRO/MAX enterprise SATA SSD (TLC NAND)",
            "variants": "8+ across capacity and TLC/MLC",
            "sanitize_strings": ["Cancel Wl for SecurityErase", "Sanitize BlkErase InvalidL2P Finished"],
            "diagnostic_fw": {"product": "Micron SATA 0157 (legacy: MTFDDAK100/400MAR)", "strings": ["ATA_DEVICE_DIAGNOSTIC_CMD", "SPI BULK ERASE TEST FAILED", "SPI BULK ERASE TEST PASSED", "SPI SECTOR ERASE TEST FAILED", "DDR TEST PASSED", "FAIL: received an invalid bootloader image"]},
        },
        "5100_SED": {
            "fw_family": "D0MC077 / D0MC447",
            "product": "Micron 5100 PRO SED enterprise SATA SSD",
            "additional_strings": ["gtSecurityContext.wSecurityVersion : 0x%x", "gtSecurityContext.tSpState : 0x%x", "gtSecurityContext.dMaxLBA  : 0x%x", "gtSecurityContext.abIntegrityCheck  : 0x%x"],
            "note": "SED variant exposes full SecurityContext structure with version, state, max LBA, and integrity check fields",
        },
        "5200": {
            "fw_family": "D1MH031 / D1MH431 / D1MH831 / D1CH431",
            "product": "Micron 5200 PRO/MAX enterprise SATA SSD (TLC NAND, newer generation)",
            "variants": "8+ capacity variants",
            "sanitize_strings": ["Sanitize BlkErase InvalidL2P Finished", "<Sanitize>BufferAlloc Failed", "<Sanitize>WritePage Request Failed"],
            "SED_note": "D1CH431 = SED variant with different md5 but same security string profile as D1MH431",
        },
        "D3MC000": {
            "fw_family": "D3MC000",
            "product": "Micron SSD MTFDDAK*/MTFDDAV* D3 generation (M.2 and 2.5in SATA)",
            "variants": "14+ (SED and non-SED; 2.5in MTFDDAK and M.2 MTFDDAV)",
            "container_magic": "4e52434de0af1600 (NRCM) series",
            "note": "D3MC000 covers multiple SKUs; same FDE strings pattern as 5100/5200 but different NRCM magic suffix",
        },
        "FIPS_MB19": {
            "fw_family": "MB19",
            "product": "Micron S650DC FIPS 140-2 certified SATA SSD (s650dc400/800/1600fips)",
            "variants": 3,
            "security_strings": [
                " VerifyCtrlFirmwareSignature failed",
                " SignaturePtr: 0x%x ",
                " KeyIndex: 0x%x ",
                "jtag_in_use",
                "_SecurityOperatingMode",
                "ActiveKey",
                "~IsMixedKey",
                "_PortLocking",
            ],
            "note": "FIPS 140-2 certified drives; 'jtag_in_use' flag indicates runtime JTAG state tracking -- JTAG use detection in a FIPS-certified product",
        },
    },
}

MARVELL_HWRAID = {
    "marvell_2017_2002": {
        "fw_version": "2.3.17.2002",
        "product": "Marvell M.2 HWRAID controller (ucs-storage-controller-m2-hwraid-marvell)",
        "fw_size_kb": 2048,
        "fw_md5_prefix": "d6d63ef0",
        "magic": "a5a5a5a5140804d0",
    },
    "marvell_88SE92xx_1014": {
        "fw_version": "2.3.17.1014",
        "product": "Marvell 88SE92xx M.2 HWRAID controller (older silicon variant)",
        "fw_size_kb": 2048,
        "fw_md5_prefix": "5346b653",
        "magic": "a5a5a5a5140804d0",
    },
    "security_strings": [
        "PORT(%d) dev %p , SECURITY UNLOCK",
        "BE_DEV_F_SECURITY",
        "source LD(%d) DDF update, update SPI security key",
        "PORT(%d) dev %p has security status : 0x%04x , (lock:%x , frozen:%x) , fla",
        "### raid_coldswap_auto_rebuild_check , LD(security_ld:%p) matching vd_secur",
    ],
    "malloc_signature": "MaTf((struct malloc_tlsf *)(tlsf))->signature == 'fTaM'",
}

WD_SAS_SSD = {
    "D971": {
        "product": "WD Ultrastar SS300 WUSTM3216ASS205 enterprise SAS SSD",
        "variants": 6,
        "fw_size_kb": 2512,
        "fw_md5_prefix": "5a9ffcf7",
        "magic": "2740000000000000",
    },
    "A971": {
        "product": "WD Ultrastar SS300 WUSTR6432ASS200 enterprise SAS SSD (high-endurance)",
        "variants": 8,
        "fw_size_kb": 2512,
        "fw_md5_prefix": "2085e779",
        "magic": "2740000000000000",
    },
    "common_strings": [
        "HGST Ultrastar SS300 TCG Enterprise SSD,",
        "MakerDiag", "HashAndSign", "PresentCertificate", "ResponseSign",
        "ActiveKey", "ReEncryptState", "ReEncryptRequest",
    ],
    "note": "Same TCG Enterprise SED pattern as HGST SAS HDD families; WD SAS SSDs use identical method labels to HGST HDDs (same firmware heritage)",
}

SAMISH_LAKE_V2 = {
    "fw_version": "52.34.0-6415_001F",
    "product": "Cisco Samish Lake M.2 storage controller (second firmware version in bundle)",
    "fw_size_kb": 7808,
    "fw_md5_prefix": "b715097e",
    "magic": "420000eb0000827f",
    "note": "Same magic 420000eb as first Samish Lake binary; different fw version (52.34.0-6415 vs other version)",
    "security_strings": {
        "read_mem_diag": {
            "string": "CBB iopiDiagCmdReadMem: Non-Dword Aligned Address encountered.",
            "note": "iopiDiagCmdReadMem confirmed in second Samish Lake binary; ReadMem diagnostic is a consistent feature of Samish Lake controller firmware",
        },
        "erase_signatures": {
            "string": "iopiMsgFwDownload: Erasing signatures",
            "note": "Firmware download process explicitly erases signatures before flashing; signature erasure during update is a window where signature verification is not enforced",
        },
        "nvram_warnings": [
            "PLATFORM Warning: Local NVRAM HAL major version is invalid. major ver = %x",
            "PLATFORM Warning: primary local nvram HAL area checksum is bad",
            "PLATFORM Warning: local nvram version incorrect",
            "PLATFORM Warning: read to second copy of local nvram failed",
            "PLATFORM Warning: secondary local nvram HAL area checksum is bad",
            "PLATFORM: Next boot default MPSS failed to write to nvram, rc=0x%x",
        ],
    },
}

CPLD_ADDITIONAL = {
    "mraid12g_he_cpld": {
        "fw_version": "00011",
        "product": "Broadcom MegaRAID 12G HE CPLD (mraid12g-he-cpld)",
        "fw_size_kb": 128,
        "fw_md5_prefix": "700b4ffd",
        "magic": "3331303880000000",
        "magic_note": "Same 3108 prefix as MegaRAID HE firmware",
        "format": "JTAG SVF for Intel MAX II CPLD (Altera MAXII, now Intel)",
        "security_strings": [
            "DO_BYPASS_CFM",
            "DO_BYPASS_UFM",
            "Failed to erase or program ASC device",
            "Unable to erase the protected sector(s) of the ASC device",
            "Failed to verify Security bit(s)",
            "programming MAXII security bit(s)...",
        ],
        "note": "Intel MAX II has hardware security bits that prevent JTAG readback of the device; 'programming MAXII security bit(s)...' shows the CPLD's security fuse is being set during production programming",
    },
    "pt4f_cpld": {
        "fw_version": "3.006",
        "product": "PT4F CPLD (x10c-pt4f-cpld) -- PCIe/Thunderbolt Form Factor CPLD",
        "variants": ["x210c-m8", "x410c-m8", "x410c-m7", "x210c-m7"],
        "fw_size_kb": 161,
        "magic": "0d0a0d0a27436f70",
        "copyright_note": "Altera Corporation (pre-Intel acquisition)",
        "format": "JTAG SVF for Altera MAX (same OPTIONAL bypass pattern as gpufm-cpld but Altera instead of Intel)",
        "security_strings": [
            "DO_BYPASS_CFM OPTIONAL, DO_BYPASS_UFM OPTIONAL,",
            "DO_BYPASS_ICB OPTIONAL, DO_BYPASS_CFM1 OPTIONAL,",
            "ACTION CONFIGURE = L20, DO_READ_USERCODE OPTIONAL, DO_HALT_ON_CHIP_CC OPTIONAL",
            "ACTION ERASE = L24, DO_BLANK_CHECK OPTIONAL,",
        ],
        "note": "Same OPTIONAL bypass pattern as gpufm-cpld (Intel MAX 10); both use identical SVF structure; confirms this is a Cisco-wide CPLD programming practice, not gpufm-specific",
    },
}

CIMC_ADDITIONAL = {
    "B200M6_CIMC": {
        "fw_version": "6.0.2.260040",
        "fw_size_kb": 51335,
        "md5_prefix": "c443b194",
        "magic": "55aa0007000c804d",
        "uboot": "U-Boot 2012.10 (Feb 14 2026 - 13:54:30)",
        "jtagboot": True,
        "pilot_strings": ["pilot_sdh_request", "pilot4spi"],
        "note": "B200 M6 CIMC also has U-Boot 2012.10 + jtagboot; same vulnerability as BXSeries M6 VIC",
    },
    "B480M5_CIMC": {
        "fw_version": "6.0.1.260012",
        "fw_size_kb": 50851,
        "md5_prefix": "0d12c83c",
        "magic": "55aa0007000c80b8",
        "uboot": "U-Boot 2012.10 (Feb 24 2026 - 19:43:15)",
        "jtagboot": True,
        "chimp_platform_strings": [
            "bootImgCHIMP-BSeriesM5",
            "bootImgCHIMP-presidio",
            "bootImgCHIMP-pomona",
        ],
        "note": "B480 M5 CIMC -- CHIMP install patterns explicitly name BSeriesM5, presidio, and pomona codenames",
    },
    "X410M7_CIMC": {
        "fw_version": "6.0.2.260040",
        "fw_size_kb": 66942,
        "md5_prefix": "ecef967a",
        "magic": "55aa001100208017",
        "uboot": "U-Boot SPL 2019.04 (Dec 06 2023 - 14:05:48 +0000)",
        "note": "X410 M7 CIMC uses U-Boot SPL 2019.04 (newer than 2012.10 in B-Series/BXSeries); X-Series M7/M8 generation upgraded bootloader",
    },
}

SAMSUNG_SSD = {
    "hmac_functions": {
        "functions": [
            "SEC_SHA256_HMAC_SetKey",
            "SEC_SHA256_HMAC_InnerHash_SetInfo",
            "SEC_SHA256_InnerHash_HMAC_Init",
            "SEC_SHA256_InnerHash_HMAC_Update",
            "SEC_SHA256_HMAC_InnerHash_Final",
            "SEC_SHA256_HMAC_OuterHash",
        ],
        "note": "Full HMAC-SHA256 function chain visible in all Samsung SSD firmware families; function names exported as symbols",
        "families": {
            "GXT51F3Q": {"product": "Samsung 983 DCT / PM883 SAS SSD", "magic": "792188ee40b90422"},
            "33F3Q": {"product": "Samsung PM953/SM863a SAS SSD 3.84TB", "magic": "61ab755d9a78a7dc"},
            "8F3Q": {"product": "Samsung SM863a SAS SSD 240GB", "magic": "53414d53554e475f", "magic_ascii": "SAMSUNG_"},
            "JXTG2F3Q/JXTC3F3Q/HXT7DF3Q": {"product": "Samsung NVMe PM9A3/PM9A1 enterprise SSD", "magic_prefix": "variable", "note": "TCG marker Q=TCG!9x in JXTG2F3Q"},
        },
    },
}

FINDINGS = {
    "INTEL-ADU-MULTI-FAMILY-F1": {
        "id": "INTEL-ADU-MULTI-FAMILY-F1",
        "severity": "HIGH",
        "title": "Asymmetric Diag Unlock Confirmed Across 5 Intel/Solidigm Firmware Families Including SATA SSDs",
        "component": "VDV1CP05 (P4511 M.2 SED, 6 variants), ACV10370 (NVMEQ-1536), 7CV1CS05 (Youngsville SATA, 9 variants), 9CV10510 (Solidigm NVMe), L031CP02 (NVMEXP)",
        "what": (
            "Asymmetric Diag Unlock (ADU) is confirmed as a systematic feature across all "
            "Intel/Solidigm enterprise storage firmware families in this bundle, regardless of "
            "interface (NVMe and SATA) or product line (Solidigm cloud, Intel P4511, P5800x, Youngsville). "
            "ACV10370 (NVMEQ-1536) reveals the most complete PKI chain: "
            "'Asymmetric Diag Unlock    Asymmetric Diag Unlock Auth Key    MaxAuthentications    "
            "HostExchangeAuthority    HostExchangeCert    HostSigningAuthority    HostSigningCert'. "
            "This is a complete asymmetric key exchange protocol: host presents certificate signed "
            "by a recognized authority, drive authenticates it, then grants diagnostic access. "
            "Solidigm SATA 7CV1CS05 (SSDSC2KB480GZK) adds: dual Intel/Solidigm bootloader identity "
            "('Intel Youngsville RR Bootloader' + 'Solidigm Youngsville RR Bootloader' in same binary). "
            "VDV1CP05 (P4511 M.2 SED) adds: Device_FW_Authentication + FW_MAC_Key -- "
            "firmware-level MAC key for firmware update authentication. "
            "L031CP02 (NVMEXP-I800) contains Dell product identity strings: "
            "'Dell Ent NVMe P5800x SED WI U.2 400GB' alongside Cisco UCS product identity -- "
            "same binary used by both Dell and Cisco OEM deployments."
        ),
        "why": (
            "ADU in 5 firmware families spanning NVMe and SATA, 20+ capacity variants, "
            "establishes that this is a platform-level feature of the Intel/Solidigm enterprise "
            "firmware platform -- not a one-off implementation. Any single ADU key compromise "
            "would affect all families using the same issuing CA. "
            "HostExchangeAuthority/Cert + HostSigningAuthority/Cert confirms a CA hierarchy: "
            "the drive trusts a HostExchangeAuthority whose cert is signed by a higher CA. "
            "If that CA is shared across all Intel/Solidigm enterprise drives, a CA key compromise "
            "enables ADU on every such drive in any deployment worldwide. "
            "Dell+Cisco dual-identity in L031CP02 means drives sold as Cisco may be "
            "interchangeable with Dell-labeled drives at the firmware level -- identical ADU keys apply."
        ),
        "evidence": {
            "adu_families": "9CV10510, VDV1CP05, ACV10370, 7CV1CS05, L031CP02",
            "full_pki_chain": "HostExchangeAuthority/HostExchangeCert/HostSigningAuthority/HostSigningCert (ACV10370)",
            "sata_adu": "7CV1CS05 -- ADU in SATA SSD (not just NVMe)",
            "dual_bootloader": "Intel Youngsville RR Bootloader + Solidigm Youngsville RR Bootloader (7CV1CS05)",
            "dell_cisco_dedup": "Dell Ent NVMe P5800x SED WI + Cisco NVMEXP-I800 in same binary (L031CP02)",
        },
        "remediation": (
            "Request Intel/Solidigm PKI documentation for ADU certificate hierarchy. "
            "Confirm whether HostExchangeAuthority is per-drive, per-batch, per-product-line, or global. "
            "On Cisco UCS deployments, confirm that ADU is not accessible via any in-band NVMe "
            "or SATA admin command reachable from the host OS. "
            "Evaluate whether Dell/Cisco cross-identity means Dell-signed ADU credentials "
            "could be used against Cisco-branded drives."
        ),
    },

    "SEAGATE-SBP-FUSE-MERT-F1": {
        "id": "SEAGATE-SBP-FUSE-MERT-F1",
        "severity": "MEDIUM",
        "title": "Misconfigured SBP Fuse Bits Error + MERT Erase + Recovery Decryption Error in Seagate HDD/SSD Firmware",
        "component": "Seagate SAS HDD: N0A6/K0A6/CN06/N004/K0E5/CK08 + Seagate SAS SSD: CE05/CE02",
        "what": (
            "Multiple Seagate SAS HDD and SSD production firmware families contain: "
            "(1) 'Misconfigured SBP Fuse Bits:' -- runtime eFuse configuration error message; "
            "SBP fuse bits configure manufacturing/security parameters at the die level. "
            "(2) Seagate SAS SSD CE05/CE02 specifically: "
            "'MERT_ERASE' -- Manufacturing Erase Reset Test erase operation; "
            "'MERT Error: Pattern END signature is not 0x%x' -- MERT validation failure; "
            "'<<<<<<<decryption error on recovery>>>>>>' -- encrypted data decryption failure during recovery; "
            "'shred previous buffer error on recovery' -- secure data shredding failure during recovery; "
            "'MakeActive_KeyStore >> Transition to FAILED state...' (CE02 only) -- KeyStore state machine failure. "
            "CE05/CE02 also have: "
            "'Firmware Signature verification failed.' -- firmware update signature check failure."
        ),
        "why": (
            "SBP fuse bit misconfiguration in field drives indicates that production firmware "
            "includes a check for fuse-level hardware configuration that can fail at runtime -- "
            "if the SBP fuse configuration diverges from what the firmware expects "
            "(due to partial programming, counterfeit drives, or hardware fault), this error fires. "
            "It also means the firmware has a runtime eFuse verification path that could be probed. "
            "The MERT erase operation in SAS SSD firmware is a manufacturing-test erase; "
            "if reachable via vendor-specific SAS commands, it would be a data destruction vector. "
            "Decryption error on recovery confirms the SSD has an encrypted recovery path; "
            "failure handling is explicit. KeyStore FAILED state (CE02) means the key management "
            "component has a distinct failure/halted mode."
        ),
        "evidence": {
            "fuse_error": " Misconfigured SBP Fuse Bits: ",
            "mert_erase": "MERT_ERASE (CE05/CE02 SAS SSD)",
            "decryption_error": "<<<<<<<decryption error on recovery>>>>>>(CE05/CE02)",
            "keystore_fail": "MakeActive_KeyStore >> Transition to FAILED state... (CE02)",
        },
        "remediation": "Audit Seagate SBP fuse bit verification to confirm no fuse state allows bypassing security restrictions.",
    },

    "MICRON-FIPS-JTAG-IN-USE-F1": {
        "id": "MICRON-FIPS-JTAG-IN-USE-F1",
        "severity": "MEDIUM",
        "title": "jtag_in_use Runtime Flag in Micron S650DC FIPS 140-2 Certified SATA SSD Firmware",
        "component": "Micron S650DC FIPS SSD (s650dc400/800/1600fips.MB19, 3 variants, md5=e581229a)",
        "what": (
            "Micron S650DC FIPS 140-2 certified enterprise SATA SSD firmware (MB19) contains: "
            "'jtag_in_use' -- a runtime flag tracking whether JTAG is currently active. "
            "Also: ' VerifyCtrlFirmwareSignature failed', ' SignaturePtr: 0x%x', ' KeyIndex: 0x%x' -- "
            "firmware signature verification with pointer and key index format strings. "
            "The S650DC is an enterprise SATA SSD with FIPS 140-2 Level 2 certification, "
            "meaning hardware security requirements include tamper evidence. "
            "Other Seagate SAS SSD families (CE05) share the same magic (e71a0e5901000200), "
            "suggesting the Micron S650DC uses a Seagate-derived or common firmware platform."
        ),
        "why": (
            "A 'jtag_in_use' flag in a FIPS 140-2 certified product indicates that JTAG state "
            "is tracked at runtime but is not necessarily disabled. FIPS 140-2 Level 2 requires "
            "role-based authentication, but does not mandate physical JTAG disable if the module "
            "can detect and respond to JTAG access. The presence of this flag means: "
            "(a) JTAG hardware interface exists and is functional, "
            "(b) the firmware monitors JTAG state at runtime. "
            "Verification failures (SignaturePtr, KeyIndex format strings) indicate the firmware "
            "surfaces key material metadata during signature verification failure -- "
            "the key index and pointer values are logged when verification fails."
        ),
        "evidence": {
            "jtag_flag": "jtag_in_use",
            "sig_verify": " VerifyCtrlFirmwareSignature failed",
            "sig_ptr": " SignaturePtr: 0x%x    KeyIndex: 0x%x",
        },
        "remediation": "Confirm JTAG is disabled by fuse in S650DC FIPS production units. Confirm 'jtag_in_use' responds by halting cryptographic operations if JTAG is detected active.",
    },

    "MARVELL-HWRAID-SPI-KEY-UPDATE-F1": {
        "id": "MARVELL-HWRAID-SPI-KEY-UPDATE-F1",
        "severity": "LOW",
        "title": "SPI Security Key Update in RAID Logical Drive DDF in Marvell M.2 HWRAID Controller",
        "component": "ucs-storage-controller-m2-hwraid-marvell.2.3.17.2002 + m2-hwraid-88SE92xx.2.3.17.1014",
        "what": (
            "Both Marvell M.2 HWRAID controller variants contain: "
            "'source LD(%d) DDF update, update SPI security key' -- the RAID logical drive DDF "
            "(Disk Data Format -- DDF is the standardized RAID metadata format) update path "
            "includes a 'SPI security key' update operation. "
            "Also: 'PORT(%d) dev %p , SECURITY UNLOCK' -- port-level security unlock; "
            "'PORT(%d) dev %p has security status : 0x%04x , (lock:%x , frozen:%x)' -- "
            "per-port security state visibility; "
            "'raid_coldswap_auto_rebuild_check' -- automatic rebuild monitoring after hot/cold swap. "
            "Magic pattern a5a5a5a5 = alternating 1s/0s fill pattern used in Marvell firmware."
        ),
        "why": (
            "A 'SPI security key' stored in RAID DDF metadata and updated during LG (Logical Drive) "
            "DDF writes means a RAID security key is persisted in the DDF on each physical member drive. "
            "If an attacker can read the DDF from any member drive (by swapping it out), they may "
            "recover the SPI security key. The per-port security unlock operation in a RAID controller "
            "is a direct data path to encrypted drives attached to that port."
        ),
        "evidence": {
            "spi_key_update": "source LD(%d) DDF update, update SPI security key",
            "port_unlock": "PORT(%d) dev %p , SECURITY UNLOCK",
            "security_status": "PORT(%d) dev %p has security status : 0x%04x , (lock:%x , frozen:%x)",
        },
        "remediation": "Confirm the 'SPI security key' in RAID DDF is not the drive encryption key or a derivative that grants access to drive data. Review DDF security key scope.",
    },

    "SAMISH-LAKE-V2-NVRAM-SIGNATURE-ERASE-F1": {
        "id": "SAMISH-LAKE-V2-NVRAM-SIGNATURE-ERASE-F1",
        "severity": "LOW",
        "title": "Firmware Download Signature Erase + NVRAM HAL Warnings in Samish Lake V2",
        "component": "ucs-storage-controller-samish-lake.52.34.0-6415_001F.bin (7808KB, md5=b715097e)",
        "what": (
            "'iopiMsgFwDownload: Erasing signatures' -- the Samish Lake firmware download handler "
            "explicitly erases signatures before flashing. "
            "NVRAM warnings: 'PLATFORM Warning: Local NVRAM HAL major version is invalid', "
            "'primary local nvram HAL area checksum is bad', 'local nvram version incorrect', "
            "'read to second copy of local nvram failed', 'secondary local nvram HAL area checksum is bad', "
            "'Next boot default MPSS failed to write to nvram, rc=0x%x'. "
            "iopiDiagCmdReadMem confirmed again (same as first Samish Lake binary -- "
            "ReadMem diagnostic is consistent across both Samish Lake firmware versions)."
        ),
        "why": (
            "'Erasing signatures' before firmware flash means there is a window where the "
            "controller has erased the old signature but not yet written the new firmware -- "
            "if power is lost here, the controller is in an unverified state. "
            "More critically, this confirms signatures are stored alongside the firmware and "
            "explicitly erased as part of the update process. "
            "NVRAM HAL warning paths indicate multiple NVRAM validation failures can occur "
            "without halting the controller -- the controller continues booting despite bad checksums."
        ),
        "evidence": {
            "sig_erase": "iopiMsgFwDownload: Erasing signatures",
            "nvram_warnings": ["primary local nvram HAL area checksum is bad", "secondary local nvram HAL area checksum is bad", "NVRAM version incorrect"],
            "read_mem": "CBB iopiDiagCmdReadMem (consistent with first Samish Lake binary)",
        },
        "remediation": "Confirm Samish Lake firmware update process re-verifies signature after flash write before marking update complete. Confirm NVRAM checksum failures trigger controller halt rather than silent continue.",
    },

    "MRAID12G-HE-CPLD-MAXII-SECURITY-F1": {
        "id": "MRAID12G-HE-CPLD-MAXII-SECURITY-F1",
        "severity": "LOW",
        "title": "Intel MAX II Security Bit Programming in MegaRAID 12G HE CPLD SVF",
        "component": "mraid12g-he-cpld.00011.bin (128KB, md5=700b4ffd)",
        "what": (
            "The MegaRAID 12G HE CPLD SVF file includes: "
            "'programming MAXII security bit(s)...' -- the Intel MAX II CPLD security fuse "
            "is explicitly programmed during this SVF execution. "
            "'Failed to verify Security bit(s)' -- verification path for security bit confirms "
            "the fuse verification is part of the programming flow. "
            "'DO_BYPASS_CFM', 'DO_BYPASS_UFM' -- same OPTIONAL bypass operations as other CPLDs. "
            "'Failed to erase or program ASC device' -- ASC = MAX II CPLD device. "
            "Magic prefix 3331303880000000 matches MegaRAID HE firmware magic (3108 prefix)."
        ),
        "why": (
            "Intel MAX II security bit is a one-time-programmable fuse that, when set, prevents "
            "JTAG readback of the CPLD configuration -- it does NOT prevent JTAG reprogramming. "
            "If 'Failed to verify Security bit(s)' is reached in the field (e.g., bit not programmed), "
            "the CPLD configuration can be read back via JTAG, potentially exposing sensitive "
            "security logic in the MegaRAID HE controller CPLD. "
            "The DO_BYPASS operations still apply to this CPLD."
        ),
        "evidence": {
            "security_bit": "programming MAXII security bit(s)...",
            "verify_fail": "Failed to verify Security bit(s)",
            "magic_match": "3331303880000000 prefix matches MegaRAID HE firmware",
        },
        "remediation": "Confirm Intel MAX II security bit is programmed in production MegaRAID HE CPLD units. Verify 'Failed to verify Security bit(s)' never occurs on production hardware.",
    },
}

BUNDLE_ANALYSIS_METADATA = {
    "bundle": "ucs-k9-bundle-b-series.6.0.2b.B.bin",
    "session": 29,
    "module_number": 7,
    "total_findings": 6,
    "severity_breakdown": {"HIGH": 1, "MEDIUM": 2, "LOW": 3},
    "key_technical_notes": [
        "ADU is confirmed as a system-wide Intel/Solidigm enterprise storage platform feature; 5 firmware families, 2 interfaces (NVMe + SATA), 30+ capacity variants all implement it identically",
        "ACV10370 NVMEQ-1536 reveals the full ADU PKI chain: HostExchangeAuthority/Cert + HostSigningAuthority/Cert -- not just Auth Key but a CA certificate hierarchy for host authentication",
        "L031CP02 (Cisco NVMEXP-I800) contains Dell Ent NVMe P5800x/P5810x identity strings -- same firmware binary serves both Dell and Cisco OEM; ADU keys from one OEM context apply to the other",
        "7CV1CS05 dual bootloader: 'Intel Youngsville RR Bootloader' + 'Solidigm Youngsville RR Bootloader' in same binary -- legacy dual branding preserved post-SK Hynix acquisition",
        "B480 M5 CIMC: bootImgCHIMP-BSeriesM5/presidio/pomona -- platform codenames in production CIMC; same U-Boot 2012.10 + jtagboot as BXSeries/B200M6",
        "X410 M7 CIMC: U-Boot SPL 2019.04 (7 years old but newer than 2012.10); SPL (Secondary Program Loader) = two-stage boot unlike monolithic U-Boot in B-Series",
        "Micron S650DC FIPS MB19 and Seagate CE05/CE02 share magic e71a0e5901000200 -- possibly same firmware platform used by both Micron and Seagate for FIPS-certified enterprise SSDs",
        "Marvell 88SE92xx and Marvell 2017 HWRAID: both use a5a5a5a5 magic and same DDF security key string; different silicon variant, same firmware codebase",
        "WD SAS SSD (D971/A971) implement the SAME TCG Enterprise SED method set as HGST SAS HDDs (MakerDiag, EraseMaster, ReEncrypt) -- WD organizational firmware heritage",
        "mraid12g-he-cpld security bit: Intel MAX II security bit prevents readback (not reprogramming); if bit is unset in production, the CPLD configuration is fully readable via JTAG",
        "Seagate SBP Fuse Bits: found in 10+ Seagate firmware families (SAS HDD and SAS SSD); consistent production check for fuse-level silicon configuration",
        "Samsung SSD HMAC chain: SEC_SHA256_HMAC_* function names exported as symbols in multiple Samsung families -- full HMAC-SHA256 implementation visible; function-level code reuse confirmed",
        "NVMEQ-1536 firmware ACV10370 is the highest-version Intel NVMe variant in this bundle; NVMEI4 I6400 2CV1C036 ChangeDefinitionVerifyPassword adds TCG template management to the list of ADU-adjacent security methods",
    ],
}
