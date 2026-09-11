"""
Cisco UCS C-Series RE Module 6: RAID Controllers, GPU Firmware, PCIe Devices, BIOS Blobs
Bundle: ucs-c-series.4.3.6.260001.tar
Targets: Double-Decker CPLD, Avago/LSI RAID BIOS, QLogic FC HBAs, Miami SmartIOC,
         BIOS blobs (11 platforms), AMD MI210/NVIDIA A16 GPU, C40Q PCIe, Samsung/Micron/Kioxia NVMe

6 findings: 0C/0H/6L
Cumulative: 535 [54C+179H+163M+139L]
"""

# ============================================================
# DEVICE INVENTORY
# ============================================================

DOUBLE_DECKER_CPLD = {
    "file": "ucs-storage-controller-double-decker-raid-cpld.00188-1A6.bin",
    "size_bytes": 15752,
    "inner_format": "SN(gzip) -> TAR -> STAPL_JAM_bytecode",
    "device": "Altera MAX II 5M160Z",
    "device_idcode": "020A50DD",
    "usercode": "001881A6",
    "checksum": "00185078",
    "created": "Quartus Prime JAM Composer 15.1",
    "build_date": "2017/05/11",
    "source_pof": "Armstrong_5972-4468-P0_002.pof",
    "cisco_codename": "Armstrong",
    "pcb_part": "5972-4468-P0",
    "stapl_version": "JESD71",
    "stapl_operations": [
        "DO_BLANK_CHECK",
        "DO_VERIFY",
        "DO_SECURE",
        "DO_DISABLE_ISP_CLAMP",
        "DO_BYPASS_CFM",
        "DO_BYPASS_UFM",
        "DO_REAL_TIME_ISP",
        "DO_FORCE_SRAM_DOWNLOAD",
        "DO_READ_USERCODE",
        "DO_INIT_CONFIGURATION",
        "PROGRAM",
        "BLANKCHECK",
        "VERIFY",
        "ERASE",
        "READ_USERCODE",
        "CHECK_IDCODE",
    ],
    "error_strings": [
        "Device programming failure",
        "Device verify failure",
        "Device is write-protected",
        "Failed to verify Security bit(s)",
        "programming MAXII security bit(s)...",
        "programming CFM block...",
        "programming UFM block...",
        "erasing MAXII UFM block...",
        "erasing MAXII CFM block...",
        "verifying UFM block...",
        "verifying CFM block...",
        "Silicon ID is ALTERA",
    ],
    "flags": [
        "USE_EXTEND_IR_DELAY_METHOD",
        "USE_FIXED_ALGORITHM",
        "NEED_FREQUENCY_CONTROL",
    ],
}

AVAGO_LSI_RAID_BIOS = {
    "shared_binary_targets": [
        "UCS-C3K-M4RAID.29.00.1-0360.bin",
        "UCSC-C3X60-R1GB.24.21.0-0156.bin",
        "ucs-storage-controller-UCSB-RAID12G-M6.24.21.0-0163.bin",
        "ucs-storage-controller-double-decker-raid.29.00.1-0360.bin",
    ],
    "vendor": "Avago Technologies",
    "rom_version": "6.30.03.3_4.17.08.00_0xC6130204",
    "build_date": "August 10, 2018",
    "build_date_c3x60": "July 02, 2018",
    "product_id": "MEGA RAID",
    "cross_oem_strings": [
        "PERC H330 Adapter(bus    dev   )",
        "PERC H330 Mini(bus    dev   )",
        "PERC H730P Adapter(bus    dev   )",
        "PERC H730P Mini(bus    dev   )",
        "PERC H330 Embedded(bus    dev   )",
        "(Bus    Dev   )PCI RAID Adapter",
        "(Bus   Dev  )Intel(r) RAID Ctlr",
    ],
    "bypass_strings": [
        "HotKey Pressed.BIOS Skipped.",
        "Adapter BIOS Disabled. No Logical Drive Handled by BIOS on HA -",
        "The Preboot configuration utility is disabled for this controller. Use UEFI mode",
    ],
    "product_families": ["MegaRAID", "PERC (Dell PowerEdge RAID Controller)"],
}

QLOGIC_FC_HBAS = {
    "targets": [
        "ucs-c-pci-qle2692.10.04.04.bin",
        "ucs-c-qlogic-pci-qle2742.10.04.04.bin",
    ],
    "models": {
        "QLE2692": "QLogic 16G FC dual-port HBA",
        "QLE2742": "QLogic 32G FC dual-port HBA",
    },
    "inner_blob_name": "bk100404.bin",
    "inner_blob_size_bytes": 3276969,
    "identical_content": True,
    "zip_directories": [
        "FC BIOS/",
        "FC EFI/",
        "FC FCode/",
    ],
    "zip_members": [
        "EFlashX64.efi",
        "FC BIOS/BIOS_Readme.txt",
        "FC BIOS/ReleaseNotes.txt",
        "FC EFI/EflashReadMe.txt",
        "FC EFI/EflashReleaseNotes.txt",
        "FC EFI/Readme.txt",
        "FC EFI/ReleaseNotes.txt",
        "FC FCode/Readme.txt",
        "FC FCode/ReleaseNotes.txt",
        "update.nsh",
    ],
    "rom_types": ["Legacy BIOS ROM", "UEFI EFI driver", "OpenFirmware FCode"],
    "note": "FC FCode = OpenFirmware legacy support for SPARC/POWER boot; EFlashX64.efi = UEFI flash tool",
}

MIAMI_SMARTIOC = {
    "skus": [
        "ucs-storage-controller-miami-beach.03.01.41.040.bin",
        "ucs-storage-controller-miami-beach-plus.03.01.41.040.bin",
        "ucs-storage-controller-miami-river-hba.03.01.41.040.bin",
        "ucs-storage-controller-miami-river-raid.03.01.41.040.bin",
        "ucs-storage-controller-miami-rock.03.01.41.040.bin",
    ],
    "shared_inner_binary": "Cisco_smartioc2200_smartoc3200_03.01.41.040_Production.bin",
    "products_covered": ["smartioc2200", "smartoc3200"],
    "string_count_per_sku": 9273,
    "identical_blobs": True,
    "version": "03.01.41.040",
    "controller_family": "Cisco SmartIOC / SAS RAID controller",
}

BIOS_BLOB_SURVEY = {
    "format": "SN(gzip) -> TAR -> gzip(.pkg) outer wrapper; inner = Cisco PKG format",
    "inner_magic_example": "C245M6-BIOS-6-0-2a-0.pkg",
    "swid_codename_matrix": {
        "C220 M5": {"codename": "plumas1", "cpu": "Intel Skylake-CascadeLake", "file": "ucs-c220-m5-bios.C220M5.4.3.6.a.0.0121261237.bin"},
        "C240 M5": {"codename": "plumas2", "cpu": "Intel Skylake-CascadeLake", "file": "ucs-c240-m5-bios.C240M5.4.3.6.a.0.0121261237.bin"},
        "C480 M5": {"codename": "madeira",  "cpu": "Intel Skylake-CascadeLake", "file": "ucs-c480-m5-bios.C480M5.4.3.6.a.0.0121261237.bin"},
        "S3260 M5": {"codename": "waterford", "cpu": "Intel Skylake-CascadeLake", "file": "ucs-s3260-m5-bios.S3260M5.4.3.6.a.0.0121261237.bin"},
        "C220 M6 (Intel)": {"codename": "trinity1", "cpu": "Intel Ice Lake (ICX)", "file": "ucs-c220-m6-bios.C220M6.6.0.2a.0.0121260813.bin"},
        "C240 M6 (Intel)": {"codename": "trinity2", "cpu": "Intel Ice Lake (ICX)", "file": "ucs-c240-m6-bios.C240M6.6.0.2a.0.0121260813.bin"},
        "C225 M6 (AMD)":   {"codename": "tehama1",  "cpu": "AMD Milan+Rome (EPYC Gen2/Gen3)", "file": "ucs-c225-m6-bios.C225M6.6.0.2a.0.0120262146.bin"},
        "C245 M6 (AMD)":   {"codename": "tehama2",  "cpu": "AMD Milan+Rome (EPYC Gen2/Gen3)", "file": "ucs-c245-m6-bios.C245M6.6.0.2a.0.0120262146.bin"},
        "C220 M7 (Intel)": {"codename": "mountrainier1", "cpu": "Intel Sapphire Rapids (SPR)", "file": "ucs-c220-m7-bios.C220M7.6.0.2a.0.0120262146.bin"},
        "C240 M7 (Intel)": {"codename": "mountrainier2", "cpu": "Intel Sapphire Rapids (SPR)", "file": "ucs-c240-m7-bios.C240M7.6.0.2a.0.0120262146.bin"},
        "C125 (AMD)":      {"codename": "castor",   "cpu": "AMD Naples+Rome (EPYC Gen1/Gen2)", "file": "ucs-c125-m5-bios.C125.4.3.6.a.0.0121261237.bin"},
    },
    "dual_gen_amd_platforms": ["tehama1", "tehama2", "castor"],
    "bios_update_signature_note": "No BiosUpdate/CiscoSignedBinary structures accessible at PKG layer; compare M8 analysis (AMD=BiosUpdate_v1/MD5Sum-only, Intel=BiosUpdate_v3/RSA-4096)",
    "11_blobs_total": True,
    "zero_security_hits_at_pkg_layer": True,
}

C40Q_PCIE = {
    "file": "ucs-pcie-c40q-03.4.7.2.260001.bin",
    "size_mb": 9,
    "version": "4.7(2.260001)",
    "build_id": "cspgre-260123-08:44:54",
    "build_date": "2026-01-23",
    "fpga_component": "mpf29180",
    "fpga_family": "Microchip PolarFire",
    "note": "mpf29180 is a PolarFire FPGA identifier; PolarFire is Microchip FPGA family (SmartFusion2 lineage, hardened crypto core)",
    "blob_opaque": True,
    "security_strings": [],
    "c40q_identity": "Unknown from public Cisco catalog; likely 40G or 40-port PCIe SmartNIC or crypto-offload card",
}

ZERO_HIT_CSERIES_MOD6 = {
    "amd_mi210": {
        "file": "ucs-video-amd-mi210.113-D67307V-075_3.16.bin",
        "size_mb": 22,
        "strings": 36780,
        "genuine_security_hits": 0,
        "note": "AMD Instinct MI210 datacenter GPU; 36K strings but all security keyword hits are case-mixed binary substrings (false positives); firmware is likely signed AMD GFX binary",
    },
    "nvidia_a16": {
        "file": "ucs-video-nvidia-A16.94.07.62.00.04_..._20.43.1014.bin",
        "size_mb": 2,
        "strings": 5152,
        "genuine_security_hits": 0,
        "note": "NVIDIA A16 vGPU (4x PCIe GPU); opaque binary, 0 real security hits",
    },
    "samsung_nvme": {
        "files": ["UCS-NVE11T9S1V.OPPA1K5Q", "UCS-NVE112T8S1P.OPPA1K3Q"],
        "note": "Samsung PM9A3 NVMe (11TB/12TB enterprise EDSFF); encrypted firmware, 0 genuine hits",
    },
    "micron_nvme": {
        "files": ["UCS-NVB30T7M3L.G1MU003", "UCS-NVB61T4M3L.G1MU003"],
        "note": "Micron 7400 Pro NVMe (3TB/6TB); false-positive TCG substring; 0 genuine hits",
    },
    "kioxia_nvme": {
        "files": ["UCS-NVE16T4K1P.1YETE106", "UCS-NVE11T6K1P.1YETE106"],
        "note": "Kioxia CM6-V NVMe (1.6TB/1.92TB); 0 strings at or above threshold; opaque binary",
    },
    "riobeach": {
        "file": "ucs-storage-controller-riobeach.8.10.1.0-00065-00002.bin",
        "note": "LSI Rio Beach RAID controller (SAS 3.0); 0 genuine security hits beyond false-positive substrings",
    },
    "laguna_beach": {
        "files": [
            "ucs-storage-controller-lagunabeach.51.23.0-5009.bin",
            "ucs-storage-controller-lagunabeach-plus.51.23.0-5009.bin",
            "ucs-storage-controller-9460-8i.51.23.0-5009.bin",
        ],
        "product": "Cisco_9460_8i_nopad.rom",
        "note": "Broadcom 9460 MegaRAID variants; 0 genuine hits; product string confirms 9460-8i baseline ROM shared across Laguna Beach family",
    },
    "m6_raid_sd_hd": {
        "files": ["ucsc-raid-m6sd.52.34.0-6415.bin", "ucsc-raid-m6hd.52.34.0-6415.bin"],
        "note": "Broadcom MegaRAID M6 SD/HD variants; 0 genuine hits; AMT substring is false positive",
    },
    "m2_nvme_raid": {
        "file": "ucs-storage-controller-m2-nvmeraid.52.34.0-6415.bin",
        "note": "M.2 NVMe RAID controller; 0 genuine hits",
    },
    "qlogic_ethernet": {
        "files": [
            "ucs-c-qlogic-pcie-ql45611h-100gbe.08.04.15.03.02.bin",
            "ucs-c-qlogic-pcie-ql41232hocu-25gsfp28.08.04.22.03.02.bin",
            "ucs-c-qlogic-pcie-ql41212h-25gsfp28.08.04.22.04.02.bin",
            "ucs-c-qlogic-pcie-ql41132horj-10g.08.04.21.03.02.bin",
            "ucs-c-qlogic-pcie-ql41162hl-10g.08.04.21.02.02.bin",
            "ucs-c-qlogic-pcie-ql45412h-40gqsfp.08.04.23.04.03.bin",
        ],
        "note": "QLogic FastLinQ 41000/45000 series (10/25/40/100G Ethernet); 0 genuine security hits; separate from FC HBA variants",
    },
}

MODULE_SUMMARY = {
    "module": "cisco_ucs_cseries_raid_gpu_pcie_re",
    "bundle": "ucs-c-series.4.3.6.260001.tar",
    "targets_analyzed": 30,
    "findings": [
        {
            "id": "CSERIES-MOD6-F1",
            "severity": "LOW",
            "title": "DOUBLE_DECKER_CPLD_STAPL_BYPASS_MODES",
            "detail": (
                "Production CPLD programming STAPL file for the double-decker RAID platform "
                "(Cisco codename: Armstrong, PCB 5972-4468) includes DO_BYPASS_CFM, DO_BYPASS_UFM, "
                "DO_DISABLE_ISP_CLAMP, and DO_REAL_TIME_ISP operations in the JAM bytecode. "
                "Device is Altera MAX II 5M160Z (IDCODE 020A50DD). "
                "DO_REAL_TIME_ISP enables in-service CPLD reprogramming without power cycle. "
                "DO_DISABLE_ISP_CLAMP removes the safety lockout preventing ISP during normal operation. "
                "DO_BYPASS_CFM/UFM skips CFM/UFM block verification during program. "
                "No cryptographic signature on STAPL bytecode visible in the binary; "
                "delivery via CIMC firmware update path cannot distinguish authentic vs crafted STAPL."
            ),
        },
        {
            "id": "CSERIES-MOD6-F2",
            "severity": "LOW",
            "title": "AVAGO_RAID_BIOS_CROSS_OEM_STRINGS_AND_HOTKEY_BYPASS",
            "detail": (
                "Avago/LSI MegaRAID BIOS ROM distributed for Cisco M4, C3X60, and UCSB-RAID12G-M6 "
                "contains Dell PERC H330/H730P branding strings alongside Cisco branding. "
                "Same ROM binary (version 6.30.03.3, build August 2018) serves 4 Cisco products. "
                "'HotKey Pressed.BIOS Skipped.' enables skipping RAID BIOS initialization via hotkey. "
                "'Adapter BIOS Disabled' + 'disabled for this controller. Use UEFI mode' are live code paths. "
                "Cross-OEM binary identity means a PERC firmware payload could be reflashed to Cisco products "
                "if the outer SN wrapper is the only gate."
            ),
        },
        {
            "id": "CSERIES-MOD6-F3",
            "severity": "LOW",
            "title": "QLOGIC_FC_HBA_16G_32G_IDENTICAL_BLOB_WITH_UEFI_SHELL_FLASH_SCRIPT",
            "detail": (
                "QLogic QLE2692 (16G FC) and QLE2742 (32G FC) firmware packages contain identical inner blobs "
                "(bk100404.bin, 3,276,969 bytes). No generation binding between 16G and 32G firmware at blob level. "
                "Bundle includes update.nsh (UEFI shell script), EFlashX64.efi (UEFI flash tool), "
                "FC FCode ROM (OpenFirmware legacy), FC BIOS ROM (legacy), and FC EFI driver. "
                "UEFI shell attack path: attacker reaching UEFI shell can invoke update.nsh with a modified "
                "EFlashX64.efi to flash unauthorized FC HBA firmware, affecting 16G and 32G variants with one payload."
            ),
        },
        {
            "id": "CSERIES-MOD6-F4",
            "severity": "LOW",
            "title": "MIAMI_SMARTIOC_5_SKU_IDENTICAL_FIRMWARE_NO_BINDING",
            "detail": (
                "Five Cisco SmartIOC storage controller SKUs (miami-beach, miami-beach-plus, miami-river-hba, "
                "miami-river-raid, miami-rock) contain identical firmware images "
                "(Cisco_smartioc2200_smartoc3200_03.01.41.040_Production.bin). "
                "String count identical across all 5 variants (9273). "
                "Products covered: smartioc2200 and smartoc3200. "
                "No hardware binding in the shared binary -- SKU differentiation is at outer SN wrapper only. "
                "A vulnerability in the shared image is simultaneously exploitable across all 5 SKUs."
            ),
        },
        {
            "id": "CSERIES-MOD6-F5",
            "severity": "LOW",
            "title": "BIOS_BLOB_PKG_WRAPPER_SWID_CODENAME_MATRIX",
            "detail": (
                "All 11 C-Series BIOS blobs use SN(gzip)->TAR->gzip(.pkg) format; inner content is Cisco PKG. "
                "SWID tags expose internal platform codename matrix: "
                "C220M5=plumas1, C240M5=plumas2, C480M5=madeira, S3260M5=waterford, "
                "C220M6(Intel)=trinity1, C240M6(Intel)=trinity2, "
                "C225M6(AMD)=tehama1, C245M6(AMD)=tehama2 (both: AMD Milan+Rome dual-gen), "
                "C220M7(Intel)=mountrainier1, C240M7(Intel)=mountrainier2, "
                "C125(AMD)=castor (AMD Naples+Rome dual-gen). "
                "BiosUpdate/CiscoSignedBinary signing structures not accessible at PKG layer. "
                "Based on M8 analysis, AMD BIOS (tehama/castor) likely uses BiosUpdate v1 (MD5Sum only) -- "
                "if confirmed, extends MD5-only blast radius to M5/M6 AMD generations."
            ),
        },
        {
            "id": "CSERIES-MOD6-F6",
            "severity": "LOW",
            "title": "C40Q_PCIE_POLARFIRE_FPGA_IDENTITY",
            "detail": (
                "Cisco UCS PCIe C40Q device uses Microchip PolarFire FPGA (component ID: mpf29180). "
                "Firmware version 4.7(2.260001), build 2026-01-23 (cspgre-260123). "
                "PolarFire (SmartFusion2 lineage) has hardened crypto core and differential power analysis "
                "resistance -- higher security posture than Altera MAX II in the double-decker CPLD (F1). "
                "The 10MB blob is opaque; no accessible security strings. "
                "C40Q identity unknown from public Cisco catalog; build date January 2026 confirms active development."
            ),
        },
    ],
    "finding_counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 6},
    "cumulative_counts": {"CRITICAL": 54, "HIGH": 179, "MEDIUM": 163, "LOW": 139},
    "cumulative_total": 535,
}
