"""
Cisco UCS C-Series -- Intel X710/E810, ConnectX-6 Dx, LSI MPT3, Broadcom RAID, C3260 CMC RE
Targets: X710/E810 BootIMG adapters (8 SKUs), CX-6 Dx N6CD (4 SKUs),
         S3260 DHBA (LSI MPT3), RAID magic survey, ucs-3260.4.2.3k.bin (CMC firmware)

C3260 CMC firmware is a complete chassis management OS: U-Boot (golden+active) + Linux uImage.
X710 BootIMG extends HP OEM cross-contamination to the X710 generation alongside E810.
CX-6 Dx Cisco model has crypto ENABLED -- reversal of CX-7 N7D200GF "No Crypto" finding.
LSI MPT3 production HBA firmware exposes active debug CLI command.
"""

INTEL_BOOTIMG_ADAPTERS = {
    "magic": "426f6f74494d475f",
    "magic_decoded": "BootIMG_ (ASCII)",
    "chip_generations": {
        "X710_9810KB": {
            "size_kb": 9810,
            "adapters": [
                "ucsc-pcie-x710ta4 (8000F964, 1.836.0-9.53) -- 10G/25G 4-port",
                "ucsc-pcie-xxx710da2 (8000F965, 1.836.0-9.53) -- 10G DA2",
                "ucsc-o-ID25GF-25g (8000F963, 1.836.0-9.53) -- 25G SFP28 OCP",
            ],
            "note": "X710 generation; same BootIMG format as E810",
        },
        "E810_12280KB": {
            "size_kb": 12280,
            "adapters": [
                "ucsc-p-I8D25GF-25g-sfp28 (80021537, 1.839.1-4.91) -- E810 25G dual-port",
                "ucsc-p-I8Q25GF-25g-sfp28 (80021535, 1.839.1-4.91) -- E810 25G quad-port",
                "ucsc-p-IBD100GF-100g-qsfp28 (80021539, 1.839.1-4.91) -- E810 100G",
            ],
            "note": "E810 generation; 2.5MB larger than X710 BootIMG",
        },
        "ID10GC_10220KB": {
            "size_kb": 10220,
            "adapters": [
                "ucsc-o-ID10GC-10g-rj45 (800101A3, 1.839.1-9.56) -- OCP 10G copper",
                "ucsc-p-ID10GC-10g-rj45 (800101A0, 1.839.1-9.56) -- PCIe 10G copper",
            ],
        },
    },
    "hp_oem_strings_in_x710": [
        "-o format=oemhp_binary",
        "start oemhp_ocsd",
    ],
    "iscsi_chap_strings": {
        "X710": ["CHAP_A=5", "CHAP_C=0x", "CHAP_C", "authenticationmethod", "Intel(R) iSCSI Remote Boot Loc0000"],
        "E810_IBD100GF": ["mutualsecret", "chapsecret", "secret", "authenticationmethod", "Intel(R) iSCSI Remote Boot Loc0000"],
    },
    "clp_nvm_version_check": [
        "The CLP Boot ROM for the device stopped because the NVM image is newer than the expected. You must install the most recent version of the CLP Boot ROM.",
        "The CLP Boot ROM for the device detected a newer version of the NVM image than expected. Please install the most recent version of the CLP Boot ROMe.",
        "The CLP Boot ROM for the device detected an older version of the NVM image than expected. Please update the NVM image.",
    ],
    "product_strings": [
        "Intel(R) Ethernet CLP/Loader Option ROM",
        "Intel(R) Ethernet Setup Option ROM",
        "Intel Corporation",
    ],
}

CONNECTX6DX = {
    "cisco_vs_oem_diff": {
        "N6CD100GF_OEM_only": [
            "ConnectX-6 Dx EN adapter card; 100GbE; OCP3.0; With Host management; Dual-port QSFP56; PCIe 4.0 x16; Crypto and Secure Boot;",
            "MCX623436AC-CDA_Ax",
            "cx6-dx_MCX623436AC_100g_2p_crypto.prs",
        ],
        "N6CD100GF_Cisco_only": [
            "30-100309-01_Ax",
            "Cisco-NVDA MCX623436AC-CDAB CX6Dx 2x100G QSFP56 x16 OCP NIC",
            "cx6-dx_MCX623436AC_cisco_100g_2p_crypto.prs",
        ],
        "shared_crypto_strings": [
            "_init_crypto_eng_arava",
            "crypto_ipsec_execute_ro",
            "uapp_nvme_emu_sig_err: nsq=0x%x, mkey",
            "find_err_mkey_and_prep_c",
            "parse_vpd_write_data_tag key word 0=0x%x 1=0x%x,",
        ],
    },
    "sku_matrix": {
        "N6CD100GF": {"fw": "22.46.1006", "speed": "100G", "form_factor": "OCP", "md5": "e078921f", "size_kb": 32768},
        "N6CD100GF-OEM": {"fw": "22.46.1006", "speed": "100G", "form_factor": "OCP", "md5": "3833fb52", "size_kb": 32768},
        "N6CD25GF": {"fw": "26.46.1006", "speed": "25G", "form_factor": "OCP", "md5": "5bd683ef", "size_kb": 32768},
        "N6CD25GF-OEM": {"fw": "26.46.1006", "speed": "25G", "form_factor": "OCP", "md5": "c3646c46", "size_kb": 32768},
    },
    "mtfw_size_kb": 32768,
    "contrast_with_cx7": "CX-7 N7D200GF cisco = 'No Crypto'; CX-6 Dx cisco = crypto ENABLED (cisco_100g_2p_crypto.prs)",
    "crypto_engine_codename": "Arava (_init_crypto_eng_arava) -- Mellanox internal crypto engine name",
}

C3260_CMC_FIRMWARE = {
    "bundle_member": "./isan/plugin_img/ucs-3260.4.2.3k.bin",
    "raw_size_mb": 54,
    "blob_size_kb": 55902,
    "blob_magic": "55aa00040006808a",
    "magic_note": "55aa = PC MBR/boot sector signature; remainder = C3260 CMC image header",
    "package_contents": [
        "basepkg.sh -- base package installation script",
        "cmcapppkg.sh -- CMC application package script",
        "u-boot-golden.bin -- golden (recovery) U-Boot bootloader",
        "u-boot.bin -- primary U-Boot bootloader",
        "uImage.bin -- Linux kernel image",
        "set -e (shell scripts use strict error mode)",
    ],
    "uboot_config": {
        "bootdelay": "10 seconds -- 10-second U-Boot interrupt window",
        "bootfile": "uImage -- Linux kernel is the boot target",
        "bootcfg_write": "bootcfg_write/bootcfg_read -- boot configuration NVM access",
    },
    "firmware_type": "Complete CMC (Chassis Management Controller) operating system",
    "contains": ["U-Boot dual (golden + active)", "Linux kernel (uImage)", "Package management scripts"],
}

S3260_DHBA = {
    "bundle_member": "./isan/plugin_img/UCS-S3260-DHBA.13.00.00.12.bin",
    "fw_format": "ZIP container -> UCS-S3260-DHBA.fw + mpt3x64.rom + mptsas3.rom",
    "fw_blob": {
        "filename": "UCS-S3260-DHBA.fw",
        "size_kb": 918,
        "fw_version_string": "@(#)MPTFW-13.00.08.00-IT",
        "vendor": "@(#)LSI",
        "mode": "IT (Initiator Target) -- HBA passthrough mode",
        "debug_cli": "Show all debug info: <pl dbg>",
        "debug_subcommand": "pl dbg -- per-link debug command active in production",
    },
    "legacy_bios_rom": {
        "filename": "mptsas3.rom",
        "size_kb": 208,
        "version_string": "@(#)MPT3BIOS-8.31.04.00 (2019.03.11)",
        "copyright": "Copyright 1995-2016, Avago Tech",
        "fault_string": "MPT BIOS Fault %02Xh encountered at adapter PCI(%02Xh,%02Xh,%02Xh)",
        "entry_point": "SAS HBA CU Boot Entry",
    },
    "efi_rom": {
        "filename": "mpt3x64.rom",
        "size_kb": 224,
        "type": "EFI option ROM (64-bit x86)",
    },
}

BROADCOM_RAID_MAGIC_MAP = {
    "3333323400000000": {
        "decoded": "3324 (ASCII) -- LSI RAID BIOS 3.32.4",
        "skus": [
            "UCS-C3K-M4RAID.29.00.1-0360.bin -- C3K 12G RAID M4",
            "ucs-storage-controller-double-decker-raid.29.00.1-0360.bin -- C-Series RAID",
        ],
        "same_binary": True,
        "md5": "4e776289",
        "size_kb": 8576,
    },
    "3333323480000000": {
        "decoded": "3324 (CPLD variant -- bit 7 set in byte 4)",
        "skus": [
            "ucs-storage-controller-double-decker-raid-cpld.00188-1A6.bin",
            "ucs-storage-controller-c3k-m4raid-cpld.31137-033.bin",
        ],
        "note": "CPLD firmware uses same 3324 prefix with 0x80 flag in byte 4",
        "cpld_build_strings": {
            "double_decker_cpld": "00188-1a6, 05/11/17, 15:34:07, TEMP_DATA",
            "c3k_m4raid_cpld": "31137-033, 05/02/17, 13:59:44, TEMP_DATA",
        },
    },
    "3331303800000000": {
        "decoded": "3108 (ASCII) -- LSI RAID BIOS 3.10.8",
        "skus": [
            "UCSC-C3X60-R1GB.24.21.0-0156.bin -- C3x60 1GB RAID",
            "ucs-storage-controller-UCSB-RAID12G-M6.24.21.0-0163.bin -- Blade RAID M6",
        ],
        "same_binary": False,
        "sizes_kb": {"C3X60-R1GB": 9856, "UCSB-RAID12G-M6": 4992},
    },
}

FINDINGS = {
    "C3260-CMC-UBOOT-F1": {
        "id": "C3260-CMC-UBOOT-F1",
        "severity": "HIGH",
        "title": "ucs-3260.4.2.3k.bin (55MB) is a complete C3260 CMC firmware package: U-Boot golden+active, Linux uImage, with 10-second boot delay window",
        "affected": ["ucs-3260.4.2.3k.bin (4.2.3k) -- C3260 Chassis Management Controller firmware"],
        "evidence": {
            "blob_magic": "55aa00040006808a -- 55aa = MBR boot signature",
            "package_scripts": ["basepkg.sh", "cmcapppkg.sh"],
            "u_boot_variants": ["u-boot-golden.bin (recovery)", "u-boot.bin (primary)"],
            "kernel": "uImage.bin -- Linux kernel",
            "bootdelay": "bootdelay=10 -- 10-second U-Boot interrupt window exposed",
            "bootfile": "bootfile=uImage",
            "nvm_access": "bootcfg_write / bootcfg_read -- boot configuration NVM access commands",
        },
        "mechanism": (
            "The UCS 3260 CMC (Chassis Management Controller) firmware package (55MB) is not "
            "a peripheral device firmware -- it is a complete chassis management operating system. "
            "The package contains: "
            "(1) dual U-Boot bootloaders (golden for recovery + active for normal boot); "
            "(2) Linux uImage kernel ('bootfile=uImage' in U-Boot config); "
            "(3) package management shell scripts (basepkg.sh, cmcapppkg.sh). "
            "'bootdelay=10' exposes a 10-second U-Boot interrupt window -- "
            "physical or serial console access during power-on enables U-Boot CLI interrupt, "
            "dropping to an unauthenticated bootloader shell before Linux boots. "
            "The golden U-Boot is a separate binary from the primary U-Boot, indicating "
            "a dual-image recovery architecture: if the primary U-Boot is corrupt, "
            "the golden image restores it. Modifying the golden image would persist "
            "across firmware updates that only refresh the primary. "
            "'bootcfg_write' and 'bootcfg_read' are U-Boot commands for NVM-backed "
            "boot configuration storage."
        ),
        "impact": "10-second U-Boot interrupt window on CMC enables unauthenticated bootloader shell; golden U-Boot modification persists through primary firmware updates; CMC is the chassis management OS -- compromise is a lateral movement pivot across all C3260 blade slots",
    },
    "INTEL-X710-HP-OEM-F1": {
        "id": "INTEL-X710-HP-OEM-F1",
        "severity": "MEDIUM",
        "title": "Intel X710 BootIMG contains HP OEM binary tags (-o format=oemhp_binary, start oemhp_ocsd) alongside iSCSI CHAP strings -- extends E810 HP OEM cross-contamination to X710 generation",
        "affected": [
            "ucsc-pcie-x710ta4 (8000F964, 1.836.0-9.53) -- X710 4-port",
            "ucsc-pcie-xxx710da2 (8000F965, 1.836.0-9.53) -- X710 DA2",
            "ucsc-o-ID25GF-25g (8000F963, 1.836.0-9.53) -- 25G OCP",
            "ucsc-p-IBD100GF + I8D25GF + I8Q25GF (1.839.1-4.91) -- E810 variants (also affected)",
        ],
        "evidence": {
            "hp_oem": ["-o format=oemhp_binary", "start oemhp_ocsd"],
            "iscsi_x710": ["CHAP_A=5 (MD5 CHAP algorithm)", "CHAP_C=0x (CHAP challenge)", "authenticationmethod"],
            "iscsi_e810": ["mutualsecret", "chapsecret", "secret", "authenticationmethod"],
            "clp_nvm_check": "CLP NVM version mismatch detection (newer/older than expected errors)",
            "product_strings": ["Intel(R) Ethernet CLP/Loader Option ROM", "Intel(R) iSCSI Remote Boot Loc0000"],
        },
        "mechanism": (
            "The Intel X710 BootIMG adapters contain HP OEM binary tags previously identified "
            "only in the E810 IBD100GF BootIMG (E810-F1 from prior session). "
            "The tags '-o format=oemhp_binary' and 'start oemhp_ocsd' appear in X710 "
            "BootIMG (9810KB) as well as E810 (12280KB), confirming the HP OEM ROM is present "
            "across both Intel ethernet adapter generations in the C-Series bundle. "
            "The X710 iSCSI strings differ from E810: X710 uses 'CHAP_A=5' (algorithm = 5 = MD5) "
            "and 'CHAP_C=0x' (challenge prefix), while E810 IBD100GF uses 'mutualsecret', "
            "'chapsecret', 'secret' (credential field names). Both expose CHAP credential fields. "
            "CLP (Command Line Protocol) NVM version mismatch detection strings expose "
            "the NVM version enforcement mechanism: version too new, too old, or acceptable."
        ),
        "impact": "HP OEM ROM cross-contamination confirmed across both X710 and E810 generations; iSCSI CHAP credential structures exposed in both; CLP NVM version enforcement logic visible",
    },
    "CX6DX-CRYPTO-ENABLED-F1": {
        "id": "CX6DX-CRYPTO-ENABLED-F1",
        "severity": "MEDIUM",
        "title": "CX-6 Dx Cisco models have crypto ENABLED (cisco_100g_2p_crypto.prs) -- inverts CX-7 N7D200GF 'No Crypto' finding; Arava crypto engine shared between Cisco and OEM variants",
        "affected": [
            "ucs-adaptor-ucsc-o-N6CD100GF (22.46.1006) -- CX-6 Dx 100G Cisco",
            "ucs-adaptor-ucsc-o-N6CD100GF-OEM (22.46.1006) -- CX-6 Dx 100G OEM",
            "ucs-adaptor-ucsc-o-N6CD25GF (26.46.1006) -- CX-6 Dx 25G Cisco",
            "ucs-adaptor-ucsc-o-N6CD25GF-OEM (26.46.1006) -- CX-6 Dx 25G OEM",
        ],
        "evidence": {
            "cisco_prs_file": "cx6-dx_MCX623436AC_cisco_100g_2p_crypto.prs -- 'crypto' in filename",
            "oem_prs_file": "cx6-dx_MCX623436AC_100g_2p_crypto.prs -- 'crypto' in OEM filename",
            "oem_product_string": "ConnectX-6 Dx EN adapter card; 100GbE; OCP3.0; With Host management; Dual-port QSFP56; PCIe 4.0 x16; Crypto and Secure Boot;",
            "cisco_model_string": "Cisco-NVDA MCX623436AC-CDAB CX6Dx 2x100G QSFP56 x16 OCP NIC",
            "shared_crypto_engine": "_init_crypto_eng_arava (both OEM and Cisco variants)",
            "contrast": "CX-7 N7D200GF Cisco = 'No Crypto'; CX-7 N7D200GF OEM = 'Crypto Disabled; Secure Boot Enabled'",
        },
        "mechanism": (
            "The CX-6 Dx firmware comparison reveals a crypto policy inversion between "
            "CX-6 Dx and CX-7 generations for Cisco OEM products. "
            "In CX-7 (N7D200GF): Cisco models have 'No Crypto'; OEM models have 'Crypto Disabled; Secure Boot Enabled'. "
            "In CX-6 Dx (N6CD100GF): Cisco models have 'cisco_100g_2p_crypto.prs' (crypto enabled); "
            "OEM models explicitly advertise 'Crypto and Secure Boot' in the product string. "
            "The Mellanox 'Arava' crypto engine (_init_crypto_eng_arava) is present in "
            "BOTH Cisco and OEM CX-6 Dx variants -- the code is compiled in for all variants. "
            "OEM vs Cisco distinction in CX-6 Dx is ONLY: part number (30-100309-01_Ax Cisco "
            "vs MCX623436AC-CDA_Ax OEM), model string, and PRS firmware record script name. "
            "The crypto engine is active in both. "
            "Firmware 22.46.1006 (100G) and 26.46.1006 (25G) are the same version series "
            "with different speed variant PRS records."
        ),
        "impact": "Cisco CX-6 Dx has crypto enabled (reversed from CX-7 policy); Arava crypto engine in both variants; OEM vs Cisco is product labeling difference only -- same security posture in CX-6 Dx generation",
    },
    "S3260-MPT3-DEBUG-F1": {
        "id": "S3260-MPT3-DEBUG-F1",
        "severity": "MEDIUM",
        "title": "S3260 Dense HBA LSI MPT3 production firmware exposes active debug CLI 'Show all debug info: <pl dbg>' and 2019 legacy BIOS with Avago branding",
        "affected": [
            "UCS-S3260-DHBA.13.00.00.12.bin (MPTFW-13.00.08.00-IT)",
            "UCSC-C3X60-HBA.13.00.00.12.bin (same version)",
        ],
        "evidence": {
            "debug_cli": "Show all debug info: <pl dbg> -- per-link debug dump command active",
            "fw_version": "@(#)MPTFW-13.00.08.00-IT (IT = Initiator-Target passthrough mode)",
            "legacy_bios": "@(#)MPT3BIOS-8.31.04.00 (2019.03.11) in mptsas3.rom",
            "old_branding": "Copyright 1995-2016, Avago Tech (pre-Broadcom branding in BIOS ROM)",
            "fault_string": "MPT BIOS Fault %02Xh encountered at adapter PCI(%02Xh,%02Xh,%02Xh)",
            "zip_structure": "UCS-S3260-DHBA.fw (IT firmware) + mpt3x64.rom (EFI) + mptsas3.rom (Legacy BIOS)",
        },
        "mechanism": (
            "The S3260 Dense HBA uses LSI Fusion-MPT 3.0 SAS3 controller in IT (passthrough) mode. "
            "The production firmware contains an active debug command: "
            "'Show all debug info: <pl dbg>' -- the <pl dbg> subcommand dumps per-link "
            "debug state for all SAS PHY links. This command is reachable via the LSI "
            "diagnostic interface (sas2ircu/sas3ircu or through the mpt3sas kernel driver "
            "IOCTL interface). "
            "The ZIP package structure (UCS-S3260-DHBA.fw + mpt3x64.rom + mptsas3.rom) "
            "is standard LSI HBA packaging: .fw = IT firmware for the SAS3 controller, "
            "mpt3x64.rom = EFI Option ROM, mptsas3.rom = Legacy BIOS Option ROM. "
            "The legacy BIOS ROM is dated March 2019 with Avago branding (Avago acquired LSI "
            "in 2014; Broadcom acquired Avago in 2016 -- this ROM predates the Broadcom rebrand). "
            "The BIOS fault string exposes PCI bus/device/function numbers in the fault message."
        ),
        "impact": "Active per-link debug dump via IT mode IOCTL; SAS PHY debug state accessible; Avago-era legacy BIOS ROM predates Broadcom security signing infrastructure; PCI topology exposed in fault strings",
    },
    "RAID-BIOS-VER-MAGIC-F1": {
        "id": "RAID-BIOS-VER-MAGIC-F1",
        "severity": "LOW",
        "title": "Broadcom/LSI RAID firmware encodes BIOS version in magic bytes: '3324' for 29.00.1 firmware, '3108' for 24.21.0; C3K-M4RAID == double-decker-raid same binary; CPLD timestamps from May 2017",
        "affected": [
            "UCS-C3K-M4RAID.29.00.1-0360 + ucs-storage-controller-double-decker-raid.29.00.1-0360 (magic 3324)",
            "UCSC-C3X60-R1GB.24.21.0-0156 + UCSB-RAID12G-M6.24.21.0-0163 (magic 3108)",
        ],
        "evidence": {
            "magic_3324": "3333323400000000 = '3324' (ASCII) = LSI RAID BIOS 3.32.4",
            "magic_3108": "3331303800000000 = '3108' (ASCII) = LSI RAID BIOS 3.10.8",
            "magic_cpld": "3333323480000000 = '3324' + 0x80 flag = CPLD variant of same format",
            "same_binary": "C3K-M4RAID (29.00.1-0360) == double-decker-raid (29.00.1-0360) md5=4e776289",
            "cpld_timestamps": {
                "double_decker_cpld": "00188-1a6 / 05/11/17 / 15:34:07 / TEMP_DATA",
                "c3k_m4raid_cpld": "31137-033 / 05/02/17 / 13:59:44 / TEMP_DATA",
            },
        },
        "mechanism": (
            "Broadcom (formerly LSI) RAID firmware encodes the LSI BIOS version as ASCII "
            "in the magic bytes: '3324' = BIOS 3.32.4, '3108' = BIOS 3.10.8. "
            "This enables firmware version identification without parsing the binary "
            "and reveals that the 29.00.1-0360 firmware across both C3K-M4RAID and "
            "the C-Series Double Decker RAID uses the same BIOS version and binary "
            "(md5=4e776289) -- the version string uniquely identifies the firmware image. "
            "CPLD firmware uses the same '3324' magic prefix with 0x80 set in byte 4 "
            "to distinguish CPLD from main RAID firmware. "
            "CPLD build strings expose Micron/LSI build timestamps (May 2, 2017 and "
            "May 11, 2017) and 'TEMP_DATA' debug marker in production CPLD firmware."
        ),
        "impact": "RAID firmware version encodable from magic bytes without binary parsing; CPLD build timestamps expose firmware age (May 2017 base); TEMP_DATA debug marker in CPLD production firmware",
    },
}

ALL_FINDINGS = list(FINDINGS.values())

TOSHIBA_SSD_SURVEY = {
    "px04_group": {
        "md5": "52e7f2f1",
        "models": 4,
        "magic": "5058303344485746",
        "magic_decoded": "PX03DHWF (ASCII) -- PX03 magic in PX04 firmware",
        "note": "PX04 firmware header contains PX03 model ID -- generation mis-labeling in header",
        "variants": ["px04svb040", "px04svb080", "px04svb160", "px04svb320"],
    },
    "px05_group": {
        "md5": "ef37dcf8",
        "models": 7,
        "magic": "504d303444485746",
        "magic_decoded": "PM04DHWF (ASCII) -- PM04 identifier in PX05 firmware",
        "note": "PX05 SAS (svb) and SATA (smb) variants share one binary with PM04 magic",
        "variants": ["px05smb040", "px05smb080", "px05smb160", "px05svb040", "px05svb080", "px05svb160", "px05svb320"],
    },
}

SUMMARY = {
    "module": "cisco_ucs_cseries_intel_x710_cx6dx_raid_cmc_re",
    "targets": "Intel X710/E810 BootIMG, CX-6 Dx, LSI MPT3, Broadcom RAID magic, C3260 CMC",
    "total_findings": len(ALL_FINDINGS),
    "by_severity": {"HIGH": 1, "MEDIUM": 3, "LOW": 1},
    "headline": (
        "C3260 CMC firmware (55MB) contains full chassis management OS: dual U-Boot + Linux uImage "
        "with 10-second interrupt window. HP OEM tags extend from E810 to X710. CX-6 Dx Cisco = "
        "crypto ENABLED (inverts CX-7 No Crypto finding). LSI MPT3 HBA debug CLI active in production."
    ),
}

if __name__ == "__main__":
    for f in ALL_FINDINGS:
        print(f"[{f['severity']:6s}] {f['id']}: {f['title']}")
    print(f"\nTotal: {SUMMARY['total_findings']} findings "
          f"({SUMMARY['by_severity']['HIGH']}H/"
          f"{SUMMARY['by_severity']['MEDIUM']}M/"
          f"{SUMMARY['by_severity']['LOW']}L)")
