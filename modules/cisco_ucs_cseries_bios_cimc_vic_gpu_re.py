"""
Cisco UCS C-Series firmware RE -- BIOS, CIMC/BMC, VIC, GPU, M6 RAID, C3260 expander
Bundle: cseries_decomp.bin (3.23GB TAR, ./isan/plugin_img/)

Coverage:
  CIMC (BMC) -- C125-M5/C480-M5 (CHIMP gen), C225-M6/C245-M8 (FPGASecure gen)
  BIOS -- C125/C480-M5 (Presidio PKI), C225-M6/C245-M8 (BIOS_IMG PKI)
  Board programmer (brdprog) -- platform codename key-value format
  VIC -- PCIe-85/84/M83/C40Q family (Cisco proprietary)
  NVIDIA GPU -- H100/H200/A100/V100/L-series (CEC microcontroller + VBIOS)
  AMD MI210 -- IFWI package
  C3260 SAS expander -- PMC_BOOT MIPS+EJTAG
  M6 RAID/SAS -- Zuma Beach ARM ASIC (ZIP container)
  SanDisk SAS SSD / Solidigm SATA SSD -- density-encoded formats
  PMEM/BPS DIMM -- Intel persistent memory (opaque binary)

Findings: 3H 3M 4L
"""

# ── CIMC architecture ─────────────────────────────────────────────────────────

CIMC_ARCHITECTURE = {
    "cimc_asic": "CHIMP (Cisco Hardware Integrated Management Processor)",
    "blob_magic": "55aa000a...",
    "magic_note": "55 aa = Cisco BMC; 00 0a/0d = format version; next 2B = content checksum area",
    "generations": {
        "M5_gen": {
            "boot_image_prefix": "bootImgCHIMP-",
            "platforms": {
                "CSeriesM5": "generic M5 C-Series",
                "plumas1": "C125-M5 AMD EPYC variant 1",
                "plumas2": "C125-M5 AMD EPYC variant 2",
                "madeira": "C480-M5 Intel Xeon",
                "castor": "C125-M5 primary",
                "waterford": "C125-M5 variant",
            },
            "pki_ou": "OU=Presidio",
            "same_binary_models": ["C125-M5", "C480-M5"],
            "cimc_md5": "3312221f",
            "cimc_size_kb": 67028,
        },
        "M6_M8_gen": {
            "boot_image_prefix": "bootImgFPGASecure-",
            "platforms": {
                "CSeriesM6": "generic M6 C-Series",
                "trinity1": "C225-M6/C245-M6 AMD EPYC variant 1",
                "trinity2": "C225-M6/C245-M6 AMD EPYC variant 2",
                "tehama1": "C225-M6 primary",
                "tehama2": "C225-M6 variant",
            },
            "pki_ou": "OU=Wasco",
            "fpga_note": "FPGA-backed secure boot; 'Setting BOOT SPI CLK CS0 divider to ensure 25MHz clock to FPGA SPI flash'",
        },
    },
    "image_types_per_platform": ["bootImg", "flashfs", "cloudimgfs"],
    "cloud_note": "cloudimgfs-<platform>.img present in M5 gen -- cloud deployment variant images bundled",
}

CIMC_UBOOT_ENV = {
    "uboot_version": "U-Boot 2012.10",
    "build_date_m5": "Feb 06 2026 - 06:15:24",
    "age_note": "U-Boot 2012.10 is from 2012; 14-year-old bootloader with modern build timestamp",
    "bootdelay": "3 seconds",
    "default_ips": {
        "ipaddr": "192.168.2.100",
        "serverip": "192.168.2.101",
    },
    "nfs_recovery_path": "/nfsroot/%02X%02X%02X%02X.img",
    "boot_methods": {
        "norboot": "Copy Linux from NOR flash to RAM",
        "qspiboot": "Copy Linux from QSPI flash",
        "emmcboot": "Copy Linux from eMMC",
        "sdboot": "Copy Linux from SD0",
        "nandboot": "Copy Linux from NAND flash",
        "jtagboot": "echo TFTPing Linux to RAM...;tftp 0x3000000 ${kernel_image};tftp 0x2A00000 ${devicetree_image};tftp 0x2000000 ${ramdisk_image};bootm 0x3000000 0x2000000 0x2A00000",
        "chimp1boot": "setenv bootargs image=partition1 chimp=1;bootm 0x00180000",
        "chimp2boot": "setenv bootargs image=partition2 chimp=1;bootm 0x01100000",
        "altimgboot": "0 (disabled)",
    },
    "linux_cmdline": "&console=ttyS0,115200n8 root=/dev/ram0 rw bigphysarea=1 enable_hub=1 earlyprintk",
    "chimp_partitions": {
        "partition1_addr": "0x00180000",
        "partition2_addr": "0x01100000",
    },
    "cisco_hardened_image_manager": "Cisco Hardened Image Manager detected",
    "fit_hash_verification": "Bad hash in FIT image! / Bad Data Hash / Verifying Hash Integrity",
}

CIMC_KEY_MANAGEMENT = {
    "key_storage_tiers": ["PRIMARY KEY STORAGE", "ROLLOVER KEY STORAGE", "BACKUP KEY STORAGE"],
    "key_tlv_error_strings": [
        "Unknown key header tag",
        "The public key is marked as to be revoked",
        "The Key Record Magic is Invalid",
        "Invalid length in the key record TLV",
        "Invalid key type for the key record TLV",
        "No keys for the specific key type found",
        "Duplicate entries found in the public key record TLV",
        "Invalid pad bytes in the Key record TLV buffer",
        "The Key record TLV has missing tags",
        "Invalid algorithm found in the The Key record TLV",
        "Invalid key version in key record",
        "Key integrity check failed",
        "Invalid signature length in key record",
        "Invalid Key Type",
        "Invalid key version in signature envelope",
        "Envelope and key record key versions do not match",
        "Key storage handle is invalid",
        "Invalid platform key storage size",
        "Unable to get the platform key storage size",
        "Unknown key storage type",
    ],
    "rollover_strings": [
        "Unable to get platform rollover key record buffer",
        "rollover key buffer size: %d",
        "Error getting rollover key from the platform",
    ],
    "cert_ous": {
        "m5_cimc_bios": "CN=CiscoSystems;OU=Presidio;O=CiscoSystems",
        "m6_cimc": "CN=CiscoSystems;OU=Wasco;O=CiscoSystems",
        "cloud_connector": "CN=CiscoSystems;OU=ucs_mgmt_cloud_connector;O=CiscoSystems",
        "m6_m8_bios": "CN=CiscoSystems;OU=BIOS_IMG;O=CiscoSystems",
    },
}

# ── BIOS format ───────────────────────────────────────────────────────────────

BIOS_FORMAT = {
    "container_header": "[CISCO UCS BIOS CIMCPackage]",
    "fields": {
        "HeaderVersion": "1",
        "ImageOffset": "2048",
        "ImageACM_SVN_Authorized": "2",
        "ImageKM_SVN": "0",
        "ImageBPM_SVN": "0",
    },
    "svn_note": (
        "ImageKM_SVN=0 (Key Manifest Security Version Number) and ImageBPM_SVN=0 "
        "(Boot Policy Manifest SVN) both at initial value -- Intel Boot Guard revocation "
        "never deployed. Signed firmware at SVN=0 can be reflashed indefinitely if signing "
        "key is compromised; no hardware rollback protection."
    ),
    "payload_compression": "bzip2 (magic BZh9 inside UEFI capsule .cap)",
    "models": {
        "C125-M5": {
            "md5": "e19da4ef",
            "size_kb": 11850,
            "pki_ou": "OU=Presidio",
            "capsule": "C125-BIOS-4-3-2h-0.cap",
        },
        "C480-M5": {
            "md5": "3e016582",
            "size_kb": 8860,
            "pki_ou": "OU=Presidio",
            "capsule": "C480M5-BIOS-4-3-2g-0.cap",
        },
        "C225-M6": {
            "md5": "33ab3f47",
            "size_kb": 13790,
            "pki_ou": "OU=BIOS_IMG",
            "capsule": "C225M6-BIOS-6-0-2a-0.pkg",
            "note": "Package.tar inner; .pkg format vs .cap format shift from M5->M6",
        },
        "C245-M8": {
            "md5": "86071d10",
            "size_kb": 24580,
            "pki_ou": "OU=BIOS_IMG",
            "capsule": "C245M8-BIOS-6-0-2a-0.pkg",
            "note": "Largest BIOS in bundle at 24.6MB",
        },
    },
}

BRDPROG_FORMAT = {
    "magic": "5b706b675d0a6865",
    "magic_ascii": "[pkg]\\nhe",
    "structure": "[pkg]\\nheaderVersion=2\\nplatform=<codename>\\nversion=<N>.0\\ntarOffset=128",
    "tar_at_offset": 128,
    "platform_codename_map": {
        "castor": {"server": "C125-M5", "version": "25.0"},
        "tehama1": {"server": "C225-M6", "version": "27.0"},
        "madeira": {"server": "C480-M5", "version": "57.0"},
    },
    "note": "Board programmer version numbers are independent of CIMC/BIOS version; madeira v57.0 implies long-lived CPLD code",
}

# ── VIC firmware ──────────────────────────────────────────────────────────────

VIC_FIRMWARE = {
    "magic_prefix": "52043d25",
    "variant_encoding": "next 4 bytes differ per VIC model (variant discriminator)",
    "build_string_format": "cspgre-<YYMMDD>-<HH:MM:SS>",
    "build_string_note": "cspgre = Cisco Software Platform; date encoded as YYMMDD",
    "models": {
        "pcie85_vic": {
            "magic": "52043d254a1272e5",
            "md5": "bf6bf0f4",
            "size_kb": 19732,
            "build": "cspgre-260131-13:31:41",
            "products": "VIC 1480/15020/15025/15220/15225",
        },
        "pcie84_vic": {
            "magic": "52043d25abe7917f",
            "md5": "63072f7f",
            "size_kb": 19498,
            "build": "cspgre-260131-13:30:11",
        },
        "m83_vic_mezz": {
            "magic": "52043d2562445ac2",
            "md5": "41f8cd57",
            "size_kb": 9940,
            "build": "cspgre-260123-08:44:54",
            "version": "4.7(2.260001)",
            "note": "Mezzanine card; smaller binary (9.9MB) vs PCIe (~19MB)",
        },
    },
    "string_density": "Minimal ASCII content; Cisco proprietary encrypted/compressed format; virtually no debug strings",
}

# ── NVIDIA GPU firmware ───────────────────────────────────────────────────────

NVIDIA_GPU_FIRMWARE = {
    "package_format": "<GPU>_<size>.zip containing nested CEC/ and VBIOS/ sub-packages",
    "cec_controller": {
        "chip": "CEC1736 (Microchip embedded controller on GPU card)",
        "function": "Board management, power management, platform security; independent of GPU VBIOS",
        "shared_cec_firmware": {
            "models": ["H100-80G", "H100-NVL", "H200-NVL"],
            "version": "00.02.0192.0000-n00",
            "file": "cec1736-ecfw-00.02.0192.0000-n00-rel-prod.fwpkg",
            "note": "All three H-series GPUs share identical CEC firmware -- one vulnerability affects all",
        },
        "a100_cec": {
            "file": "ga100_cec_ota_v6.07_prod.bin",
            "version": "v6.07",
            "note": "A-series uses GA100 codename (Ampere architecture) for CEC OTA package",
        },
    },
    "models": {
        "H100-80G": {
            "md5": "34e46d25",
            "size_kb": 1440,
            "magic_ascii": "H100-80_",
            "zip": "H100-80_600.zip",
            "vbios_ver": "96.00.D9.00.0C",
            "inforom_ver": "1010.0200.00.02",
        },
        "H200-NVL": {
            "md5": "4b78a9b7",
            "size_kb": 1510,
            "magic_ascii": "H200_NVL",
            "zip": "H200_NVL_B00.zip",
            "vbios_ver": "96.00.D9.00.0E",
            "shared_cec_with_h100": True,
        },
        "A100": {
            "md5": "2c7af270",
            "size_kb": 400,
            "magic_ascii": "A100_400",
            "irom_file": "1001_0200_883__9200900008.rom",
        },
        "A100-80": {
            "md5": "def3fc2e",
            "size_kb": 480,
            "magic_ascii": "A100-80_",
            "zip": "A100-80_600_601_610_611.zip",
            "note": "Dual-firmware filename encodes primary + fallback VBIOS versions",
        },
        "V100-32GB": {
            "md5": "954a7bbf",
            "size_kb": 180,
            "magic_ascii": "tag.txt",
            "note": "Tag-file format (tag.txt header) -- older packaging convention",
            "zip_contents": {
                "IROM": "G5000202.ifr0",
                "VBIOS": "g500_0202_897__88007E0003.nvr",
            },
        },
    },
    "amd_mi210": {
        "md5": "a4124e30",
        "size_kb": 80970,
        "magic_ascii": "AMD-MI210",
        "format": "TAR archive with AMD-MI210/opt/amdfwflash/ifwi/ga/ directory tree",
        "note": "80MB+ IFWI package; ga/ = GPU architecture directory; amdfwflash = AMD flash utility path baked in",
    },
    "filename_encoding": (
        "NVIDIA GPU firmware filenames encode: "
        "VBIOS_version_InfoROM_version_board_suffix. "
        "Dual-firmware variants use double-underscore separator: "
        "primary_ver__fallback_ver.bin"
    ),
}

# ── C3260 SAS expander (PMC_BOOT) ─────────────────────────────────────────────

C3260_SAS_EXPANDER = {
    "path": "ucs-c3260-sas-expander.04.08.01.B083.bin",
    "magic": "504d435f424f4f54",
    "magic_ascii": "PMC_BOOT",
    "md5": "3dc38ef5",
    "size_kb": 1155,
    "cisco_id_string": "Cisco   C3260           2   ",
    "cpu": "MIPS",
    "debug_interface": "EJTAG (Enhanced JTAG for MIPS)",
    "debug_boot_control": {
        "string": "(bit0: MIPS; bit1: WDG; bit2: EJTAG)",
        "meaning": "Bitfield in boot config word: bit0=MIPS CPU, bit1=Watchdog, bit2=EJTAG debugger",
    },
    "bootcfg_bypass": "BOOTCFG is invalid. Skip partition verification.",
    "note": (
        "Same PMC firmware family as PM8533 NVMe (BOOTCFG bypass string identical). "
        "C3260 SAS expander = PMC SAS expander ASIC (not CUB/CUBR which are LSISAS3xFW). "
        "EJTAG reveals MIPS debug interface present on SAS expander ASIC."
    ),
    "seeprom_management": {
        "crc32_check": "The SEEPROM CRC32 check is failed.",
        "version_update": "FW is updating the SEEPROM with the default settings...",
        "integrity_check": "The SEEPROM integrity check update failed.",
        "success": "The SEEPROM is updated to latest version!",
    },
    "source_path_leak": r"..\src\diag\diag_hdd_test.c",
    "sas_features": ["SAS Attached", "SAS2 Enabled", "SAS2 SSC", "SAS2 CenterSSC", "I-Comsas"],
}

# ── M6 RAID/SAS controllers ───────────────────────────────────────────────────

M6_RAID_SAS = {
    "asic_family": {
        "ZumaBeach": {
            "product": "RAID M6HD/M6SD/M6T (RAID-on-Chip)",
            "magic": "420000eb",
            "magic_note": "ARM branch at reset vector (same convention as CUB/C460 but 0x42 not 0x28)",
            "bl_version": "33.250.02.00",
            "bl_date": "2025-06-17 12:02:50",
            "file_in_zip": "Zuma_Beach_NOPAD.rom",
            "size_kb": 7808,
        },
        "ZumaRock": {
            "product": "SAS M6HD expander component",
            "magic": "420000eb",
            "file_in_zip": "ZumaRock.rom",
            "size_kb": 2042,
            "note": "SAS expander variant of Zuma ASIC family",
        },
        "IT_HBA": {
            "product": "SAS M6HD HBA BIOS (IT mode)",
            "file_in_zip": "IT_HBA_X64_BIOS_PKG_E6.rom",
            "size_kb": 202,
            "magic": "420000eb",
        },
    },
    "container_format": "ZIP (magic 504b0304) -- same as LSI 12G HBA",
    "m6t_psoc": {
        "container": "ZIP containing PSOC-001F.romUT",
        "version": "001F",
        "note": "PSoC firmware update same convention as Pismo Beach Plus CUB I2C PSoC update chain",
    },
    "same_version_across_variants": {
        "raid_m6hd": "52.34.0-6415",
        "raid_m6sd": "52.34.0-6415",
        "raid_m6t": "52.34.0-6415",
        "note": "All three M6 RAID variants share the same version string",
    },
}

# ── Findings ──────────────────────────────────────────────────────────────────

FINDINGS = {

    "CIMC-UBOOT-JTAG-F1": {
        "severity": "HIGH",
        "title": "JTAG debug boot is a defined enabled boot path in all UCS CIMC U-Boot environments",
        "what": (
            "U-Boot environment in C125/C225/C480-M5/C245-M8 CIMC (67-138MB blobs) contains a "
            "defined 'jtagboot' environment variable: "
            "'jtagboot=echo TFTPing Linux to RAM...;tftp 0x3000000 ${kernel_image};tftp "
            "0x2A00000 ${devicetree_image};tftp 0x2000000 ${ramdisk_image};bootm ...' "
            "Combined with 'bootdelay=3' (3-second interrupt window), serial console at "
            "ttyS0 115200 -- physical access to the server's management serial port allows: "
            "1) interrupt U-Boot at boot, 2) execute 'run jtagboot' from U-Boot prompt, "
            "3) load arbitrary kernel + initrd over TFTP from attacker-controlled serverip. "
            "U-Boot version is 2012.10 (13 years old). 'Cisco Hardened Image Manager detected' "
            "is a runtime string indicating Cisco's hardening layer is separate from U-Boot itself."
        ),
        "bootdelay": "3 seconds",
        "uboot_version": "U-Boot 2012.10 (Feb 06 2026 build date)",
        "affected": "C125-M5, C225-M6, C480-M5, C245-M8 CIMC firmware",
        "access_requirement": "Physical access to management serial port (CIMC RS-232 console)",
        "impact": "Arbitrary firmware load via JTAG+TFTP; bypasses all software-enforced boot restrictions",
    },

    "CIMC-THREE-KEY-STORAGE-F1": {
        "severity": "HIGH",
        "title": "CHIMP CIMC exposes complete three-tier key storage state machine via firmware strings",
        "what": (
            "CIMC firmware (all variants) contains the complete error string set for a "
            "three-tier key storage architecture: PRIMARY KEY STORAGE, ROLLOVER KEY STORAGE, "
            "BACKUP KEY STORAGE. Key TLV format errors expose the full structure: magic field, "
            "length field, algorithm field, version field, pad bytes, integrity check, signature "
            "length. Revocation strings: 'The public key is marked as to be revoked'. "
            "Rollover strings: 'Unable to get platform rollover key record buffer', "
            "'rollover key buffer size: %d'. Version enforcement: 'Envelope and key record "
            "key versions do not match'. The complete key management state machine is visible, "
            "enabling construction of a conformant TLV payload to probe the key ingestion path."
        ),
        "key_tiers": ["PRIMARY KEY STORAGE", "ROLLOVER KEY STORAGE", "BACKUP KEY STORAGE"],
        "tlv_fields_exposed": ["magic", "length", "type", "algorithm", "version", "pad", "signature"],
        "impact": "Full key management state machine visible; TLV format reconstructible from error strings",
    },

    "C3260-PMC-EJTAG-F1": {
        "severity": "HIGH",
        "title": "C3260 SAS expander (PMC_BOOT MIPS) has EJTAG debug interface and partition verification bypass",
        "what": (
            "C3260 SAS expander (1155KB, magic 'PMC_BOOT') is a PMC SAS expander ASIC with MIPS CPU. "
            "Boot control bitfield string: '(bit0: MIPS; bit1: WDG; bit2: EJTAG)' -- EJTAG debug "
            "interface is bit-controlled from the same register as watchdog and MIPS CPU enable. "
            "BOOTCFG bypass: 'BOOTCFG is invalid. Skip partition verification.' -- identical to "
            "PM8533 NVMe (prior module), confirming shared PMC firmware family across SAS expander "
            "and NVMe controllers. SEEPROM CRC/integrity/version management strings visible. "
            "Source path leaked: ..\\src\\diag\\diag_hdd_test.c. "
            "Cisco branding string: 'Cisco   C3260           2   ' with model embedded."
        ),
        "cpu": "MIPS with EJTAG",
        "bootcfg_bypass": "BOOTCFG is invalid. Skip partition verification.",
        "shared_string_with": "PM8533 NVMe (prior module cisco_ucs_cseries_megaraid_pm8533_cub_expander_re.py)",
        "access_path": "PMC UART console (same telnet redirect pattern as PM8533) or JTAG via debug header",
        "impact": "MIPS EJTAG debug access on production SAS expander; partition verification bypassable via BOOTCFG",
    },

    "CIMC-PKI-OU-LEAK-F1": {
        "severity": "MEDIUM",
        "title": "Internal Cisco PKI organizational units and platform codenames embedded in CIMC and BIOS firmware",
        "what": (
            "Multiple Cisco-internal PKI OU names are embedded in plaintext across CIMC and BIOS blobs: "
            "'CN=CiscoSystems;OU=Presidio;O=CiscoSystems' -- M5-gen CIMC signing cert (C125/C480 CIMC + BIOS); "
            "'CN=CiscoSystems;OU=Wasco;O=CiscoSystems' -- M6-gen CIMC signing cert (C225-M6 CIMC); "
            "'CN=CiscoSystems;OU=BIOS_IMG;O=CiscoSystems' -- M6/M8 BIOS signing cert; "
            "'CN=CiscoSystems;OU=ucs_mgmt_cloud_connector;O=CiscoSystems' -- cloud connector cert (all CIMC). "
            "Presidio and Wasco are internal platform codenames used as certificate OU identifiers. "
            "Combined with board programmer platform map (castor/madeira/tehama/trinity/plumas/waterford), "
            "the full Cisco UCS C-Series platform codename tree is now reconstructed."
        ),
        "pki_ous": {
            "Presidio": "M5 CIMC and BIOS (C125/C480)",
            "Wasco": "M6 CIMC (C225/C245)",
            "BIOS_IMG": "M6/M8 BIOS (C225-M6/C245-M8)",
            "ucs_mgmt_cloud_connector": "Cloud management plane cert (all generations)",
        },
        "platform_codenames_full": {
            "castor": "C125-M5", "plumas1/2": "C125-M5 variants",
            "madeira": "C480-M5", "waterford": "C125-M5 variant",
            "tehama1/2": "C225-M6", "trinity1/2": "C225/C245-M6",
        },
        "impact": "PKI hierarchy exposed; platform codename tree reconstructed; cert OU used for signing scope inference",
    },

    "BIOS-KM-BPM-SVN-ZERO-F1": {
        "severity": "MEDIUM",
        "title": "Intel Boot Guard Key Manifest and Boot Policy Manifest SVN both at 0 across all C125/C480 BIOS",
        "what": (
            "C125-M5 and C480-M5 BIOS packages both contain: "
            "ImageKM_SVN=0 (Key Manifest Security Version Number), "
            "ImageBPM_SVN=0 (Boot Policy Manifest Security Version Number), "
            "ImageACM_SVN_Authorized=2 (ACM minimum authorized version). "
            "KM_SVN=0 and BPM_SVN=0 mean Intel Boot Guard's anti-rollback protection has never been "
            "incremented -- a compromised KM or BPM at version 0 could be reflashed to any system "
            "indefinitely without hardware countermeasure. Only ACM SVN=2 is enforced. "
            "BIOS payload is bzip2-compressed UEFI capsule (.cap for M5, .pkg+Package.tar for M6/M8). "
            "C225-M6/C245-M8 BIOS switches to OU=BIOS_IMG signing cert and .pkg format -- "
            "format change implies different signing pipeline between M5 and M6 generations."
        ),
        "affected": "C125-M5 (e19da4ef), C480-M5 (3e016582)",
        "intel_boot_guard": {
            "ImageACM_SVN_Authorized": "2",
            "ImageKM_SVN": "0 (never incremented)",
            "ImageBPM_SVN": "0 (never incremented)",
        },
        "impact": "Boot Guard rollback protection never activated for KM/BPM; compromised signing key = permanent reflash window",
    },

    "NVIDIA-CEC-SHARED-H100-H200-F1": {
        "severity": "MEDIUM",
        "title": "H100 and H200 NVL GPU cards share identical CEC1736 embedded controller firmware",
        "what": (
            "H100-80G, H100-NVL, and H200-NVL all contain CEC sub-package: "
            "'cec1736-ecfw-00.02.0192.0000-n00-rel-prod.fwpkg' (identical filename and version). "
            "CEC1736 is the Microchip embedded controller managing GPU card board functions (power, "
            "thermals, platform security) independently of the GPU VBIOS. A vulnerability in the "
            "CEC firmware affects all three H-series GPUs deployed in UCS infrastructure simultaneously. "
            "A100/A30/A40 use a separate 'ga100_cec_ota_v6.07_prod.bin' CEC package. "
            "V100 (older) uses a different 'tag.txt' header format predating the ZIP packaging. "
            "NVIDIA GPU firmware filename convention encodes: VBIOS_version_InfoROM_version_board_ref; "
            "dual-firmware variants use double-underscore separator for primary__fallback versions."
        ),
        "shared_cec_version": "00.02.0192.0000-n00",
        "affected_gpus": ["H100-80G", "H100-NVL", "H200-NVL"],
        "impact": "Single CEC firmware bug = simultaneous exposure across H100 and H200 NVL deployments in UCS C-Series",
    },

    "CIMC-PLATFORM-MULTIIMAGE-F1": {
        "severity": "LOW",
        "title": "CIMC blobs bundle multiple platform images; C125 and C480 CIMC are identical binaries",
        "what": (
            "Each CIMC blob contains three image types per platform: bootImg, flashfs, cloudimgfs. "
            "C125-M5 CIMC bundles 6 platform variants (CSeriesM5, plumas1/2, madeira, castor, waterford). "
            "C225-M6 CIMC bundles 5 variants (CSeriesM6, trinity1/2, tehama1/2). "
            "C125-M5 and C480-M5 CIMC are byte-for-byte identical (md5=3312221f, 67028KB) -- same "
            "CIMC binary manages two physically different server models. "
            "cloudimgfs-<platform>.img entries in M5 blobs indicate cloud deployment variant images "
            "bundled in standard on-prem firmware packages."
        ),
        "same_binary_models": ["C125-M5 CIMC", "C480-M5 CIMC"],
        "md5": "3312221f",
    },

    "RAID-M6-ZUMABEACH-ARM-F1": {
        "severity": "LOW",
        "title": "M6 RAID/SAS uses Zuma Beach ARM ASIC; all three M6 RAID variants share the same version tag",
        "what": (
            "M6HD/M6SD/M6T RAID controllers all use version 52.34.0-6415, delivered as ZIP (magic 504b0304). "
            "RAID M6HD ZIP contains Zuma_Beach_NOPAD.rom (7808KB, magic 420000eb): "
            "ARM boot vector at reset (Zuma Beach = codename for M6 RAID ASIC). "
            "Build: '@(#)BL Version:33.250.02.00' '@(#)BL DATE:06/17/2025 12:02:50'. "
            "SAS M6HD ZIP contains ZumaRock.rom (2042KB, same ARM magic) + IT_HBA_X64_BIOS_PKG_E6.rom. "
            "M6T PSoC (ucsc-raid-m6t-psoc.001F.bin) is ZIP containing PSOC-001F.romUT -- same I2C PSoC "
            "update pattern as Pismo Beach Plus CUB expander (prior module)."
        ),
        "asic_codenames": {"ZumaBeach": "RAID ROC", "ZumaRock": "SAS expander"},
        "arm_magic": "420000eb",
        "build_date": "2025-06-17",
    },

    "VIC-CSPGRE-FORMAT-F1": {
        "severity": "LOW",
        "title": "Cisco VIC firmware uses proprietary format with magic 52043d25; minimal readable content",
        "what": (
            "VIC firmware (pcie85/84, M83 mezz, C40Q) uses magic prefix 52043d25 with variant "
            "discriminator in the next 4 bytes. Only readable string: 'cspgre-<YYMMDD>-<HH:MM:SS>' "
            "build timestamp (cspgre = Cisco Software Platform). M83 VIC also contains version "
            "'4.7(2.260001)'. PCIe-85 and PCIe-84 VIC blobs are ~19.5MB each vs M83 mezz at 9.9MB. "
            "Build dates: PCIe-85/84 = January 31, 2026; M83 = January 23, 2026. "
            "The proprietary encryption/packing leaves no security strings accessible in these blobs."
        ),
        "magic": "52043d25",
        "build_dates": {
            "pcie85": "2026-01-31 13:31:41",
            "pcie84": "2026-01-31 13:30:11",
            "m83": "2026-01-23 08:44:54",
        },
    },
}

# ── Extraction primitives ─────────────────────────────────────────────────────

def decompress_sn(data: bytes) -> bytes:
    import zlib, struct
    hsize = struct.unpack_from(">H", data, 4)[0]
    payload = data[hsize:]
    d = zlib.decompressobj(wbits=31)
    out = bytearray()
    for i in range(0, len(payload), 65536):
        out.extend(d.decompress(payload[i:i+65536]))
    out.extend(d.flush())
    return bytes(out)


def identify_cimc_generation(data: bytes) -> str:
    if b"bootImgFPGASecure" in data[:65536]:
        return "M6/M8 FPGASecure gen"
    if b"bootImgCHIMP" in data[:65536]:
        return "M5 CHIMP gen"
    return "unknown"


def identify_bios_pki_ou(data: bytes) -> str:
    for ou in [b"OU=BIOS_IMG", b"OU=Presidio", b"OU=Wasco"]:
        if ou in data[:8192]:
            return ou.decode()
    return "unknown"
