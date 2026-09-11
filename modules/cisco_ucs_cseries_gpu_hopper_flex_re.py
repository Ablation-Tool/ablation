"""
Cisco UCS C-Series -- NVIDIA A16/H200NVL/H100NVL/L40S and Intel Flex 140-Mezz/Flex 170 RE
Targets: ucs-video-nvidia-A16, H200-NVL, H100-NVL, H100-80G, L40S,
         ucs-video-intel-flex-140-Mezz, ucs-video-intel-flex-170

All contain ZipCrypto-encrypted firmware components; developer usernames in TAR headers.
Intel Flex 170 ships Engineering Sample IFWI (PVT_ES_119) + signed ECC_OFF update.
NVIDIA A16 embeds ConnectX-6 (32MB) interconnect firmware alongside GPU VBIOS.
"""

NVIDIA_GPUS = {
    "A16": {
        "product": "ucs-video-nvidia-A16",
        "fw_label": "94.07.62.00.04_G171.0200.00.04_4.01_20.43.1014",
        "architecture": "Ampere GA100 (vGPU multi-instance, 16 MIG partitions)",
        "bundle_member": "./isan/plugin_img/ucs-video-nvidia-A16.*_G171*.bin",
        "inner_zip": "A16_200_302.zip",
        "developer": "mkaushal",
        "zip_contents": {
            "A16/CEC/cec_ota_BMGP3-04.01_prod.bin": {"size_kb": 128, "encrypted": True, "desc": "CEC (chassis embedded controller) OTA firmware"},
            "A16/IROM_VBIOS/g171_0200_890__9407620004-94076200AD-prod.nvr": {"size_kb": 2051, "encrypted": True, "desc": "IROM + VBIOS combined NVR image, dual-VBIOS (04 and AD variants)"},
            "A16/PLX/fw-ConnectX6-rel-20_43_1014-PG171_Ax.signed.bin": {"size_kb": 32768, "encrypted": True, "desc": "ConnectX-6 NVSwitch interconnect fabric firmware, 32MB"},
        },
    },
    "H200_NVL": {
        "product": "ucs-video-nvidia-H200-NVL",
        "fw_label": "96.00.D9.00.0E_1010.0230.00.02_00.02.0192.0000-n00",
        "architecture": "Hopper H200 NVL (NVLink, GH100)",
        "inner_zip": "H200_NVL_B00.zip",
        "developer": "linfu2",
        "zip_contents": {
            "H200_NVL/CEC/cec1736-ecfw-00.02.0192.0000-n00-rel-prod.fwpkg": {"size_kb": 190, "encrypted": True, "desc": "CEC1736 embedded controller firmware"},
            "H200_NVL/IROM_VBIOS/1010_0230_894__9600D9000E-prod-spi.rom": {"size_kb": 4096, "encrypted": True, "desc": "4MB SPI ROM (IROM+VBIOS combined)"},
        },
    },
    "H100_NVL": {
        "product": "ucs-video-nvidia-H100-NVL",
        "fw_label": "96.00.D9.00.0D_1010.0210.00.02_00.02.0192.0000-n00",
        "architecture": "Hopper H100 NVL (NVLink, GH100)",
        "inner_zip": "H100_NVL_700.zip",
        "developer": "linfu2",
        "zip_contents": {
            "H100_NVL/CEC/cec1736-ecfw-00.02.0192.0000-n00-rel-prod.fwpkg": {"size_kb": 190, "encrypted": True, "desc": "CEC1736 embedded controller firmware"},
            "H100_NVL/IROM_VBIOS/1010_0210_886__9600D9000D-prod-spi.rom": {"size_kb": 4096, "encrypted": True, "desc": "4MB SPI ROM"},
        },
    },
    "L40S": {
        "product": "ucs-video-nvidia-L40S",
        "fw_label": "95.02.66.00.15_G133.0242.00.03_00.02.0134.0000-n02",
        "architecture": "Ada Lovelace AD102 (professional rendering)",
        "inner_zip": "L40S_L00.zip",
        "developer": "linfu2",
        "zip_contents": {
            "L40S/CEC/cec1736-ecfw-00.02.0134.0000-n02-rel-prod.fwpkg": {"size_kb": 184, "encrypted": True, "desc": "CEC1736 embedded controller firmware"},
            "L40S/IROM_VBIOS/g133_0242_896__9502660015-prod-spi.rom": {"size_kb": 2048, "encrypted": True, "desc": "2MB SPI ROM"},
        },
    },
}

INTEL_FLEX_GPUS = {
    "Flex_140_PCIe": {
        "fw_label": "DG02-2.2280_7.0.0.0",
        "inner_members": {
            "IFWI_XPUM_Flex_140_128_ES_034_gfx_fwupdate_DG02_2.2280_.bin": {"size_kb": 2052, "designation": "ES (Engineering Sample)", "iteration": 34},
            "pldm_sg2_amc_v_7_0_0_0.bin": {"size_kb": 381, "desc": "PLDM AMC firmware"},
        },
        "developer_uid": 747789,
        "developer_uname": "weslleun",
    },
    "Flex_140_Mezz": {
        "fw_label": "DG02-2.2280_7.0.0.0",
        "note": "IDENTICAL binary to Flex_140_PCIe -- same ES_034 IFWI, same pldm_sg2_amc",
        "inner_members": {
            "IFWI_XPUM_Flex_140_128_ES_034_gfx_fwupdate_DG02_2.2280_.bin": {"size_kb": 2052, "designation": "ES", "iteration": 34},
            "pldm_sg2_amc_v_7_0_0_0.bin": {"size_kb": 381},
        },
        "developer_uid": 747789,
        "developer_uname": "weslleun",
    },
    "Flex_170": {
        "fw_label": "DG02-1.3274_7.0.0.0",
        "codename": "ATS (Arctic Sound / Intel Arc A-Series GPU)",
        "die": "M150 (ATS-M, medium die, SOC1)",
        "stepping": "C0",
        "inner_members": {
            "IFWI_ATS_M150_PVT_ES_119_gfx_fwupdate_SOC1.bin": {
                "size_kb": 2052,
                "designation": "PVT_ES (Pre-Volume Test Engineering Sample)",
                "iteration": 119,
                "note": "iteration 119 -- 3.5x deeper ES chain than Flex 140 ES_034",
            },
            "IFWIDATA_XPUM_ATS_M150_512_C0_PVT_ES_117_DataUpdate_ECC_OFF_Signed.bin": {
                "size_kb": 40,
                "stepping": "C0",
                "ecc": "ECC_OFF (ECC disabled)",
                "signed": True,
                "contents": ["GDTA.met", "Profile 0"],
            },
            "pldm_sg2_amc_v_7_0_0_0.bin": {"size_kb": 381},
        },
        "developer_uid": 747789,
        "developer_uname": "weslleun",
    },
}

DEVELOPER_PII = {
    "mkaushal": ["NVIDIA RTX Pro 6000 (Blackwell)", "NVIDIA A16 (Ampere vGPU)"],
    "linfu2": ["NVIDIA H200 NVL", "NVIDIA H100 NVL", "NVIDIA H100 80G", "NVIDIA L40S"],
    "weslleun": ["Intel Flex 140 PCIe", "Intel Flex 140 Mezz", "Intel Flex 170"],
    "intel_uid_747789": "Build system UID 747789 in all three Intel Flex products",
}

# Findings
A16_F1 = {
    "id": "A16-F1",
    "severity": "HIGH",
    "title": "NVIDIA A16 embeds 32MB ConnectX-6 NVSwitch firmware (ZipCrypto) plus CEC OTA; 3-component ZipCrypto bundle",
    "affected": ["ucs-video-nvidia-A16 (94.07.62.00.04_G171.0200.00.04)"],
    "evidence": {
        "cx6_fw": "A16/PLX/fw-ConnectX6-rel-20_43_1014-PG171_Ax.signed.bin (32MB, ZipCrypto)",
        "vbios": "A16/IROM_VBIOS/g171_0200_890__9407620004-94076200AD-prod.nvr (2MB, ZipCrypto, dual VBIOS)",
        "cec": "A16/CEC/cec_ota_BMGP3-04.01_prod.bin (128KB, ZipCrypto)",
        "developer": "mkaushal (TAR uname)",
        "cx6_version": "20_43_1014 (ConnectX-6 fw version, NVSwitch G171 profile)",
    },
    "mechanism": (
        "The NVIDIA A16 vGPU firmware bundle includes three ZipCrypto-encrypted components: "
        "(1) CEC (Chassis Embedded Controller) OTA firmware for power/thermal management; "
        "(2) IROM+VBIOS NVR image with dual VBIOS variants (94.07.62.00.04 and 94.07.62.00.AD); "
        "(3) ConnectX-6 NVSwitch interconnect firmware (32MB, version 20_43_1014, G171 profile). "
        "The ConnectX-6 firmware in the A16 is the NVSwitch interconnect fabric controller -- "
        "this is the same ConnectX-6 family covered in CX56-F1 (0xBADC0FFE ICMD bypass). "
        "All three components are ZipCrypto encrypted. The 32MB ConnectX-6 blob is the "
        "largest single ZipCrypto target in this bundle."
    ),
    "impact": "ZipCrypto bypass on A16 bundle recovers ConnectX-6 NVSwitch firmware + VBIOS + CEC OTA; ConnectX-6 in A16 may share 0xBADC0FFE ICMD bypass path with CX56-F1",
}

H2H1_F1 = {
    "id": "H2H1-F1",
    "severity": "MEDIUM",
    "title": "H200 NVL, H100 NVL, and L40S include CEC1736 embedded controller firmware (ZipCrypto) alongside 4MB/2MB SPI ROM",
    "affected": [
        "ucs-video-nvidia-H200-NVL (96.00.D9.00.0E)",
        "ucs-video-nvidia-H100-NVL (96.00.D9.00.0D)",
        "ucs-video-nvidia-L40S (95.02.66.00.15)",
    ],
    "evidence": {
        "h200_cec": "H200_NVL/CEC/cec1736-ecfw-00.02.0192.0000-n00-rel-prod.fwpkg (190KB, ZipCrypto)",
        "h100_cec": "H100_NVL/CEC/cec1736-ecfw-00.02.0192.0000-n00-rel-prod.fwpkg (190KB, ZipCrypto)",
        "l40s_cec": "L40S/CEC/cec1736-ecfw-00.02.0134.0000-n02-rel-prod.fwpkg (184KB, ZipCrypto)",
        "spi_rom_size": "4MB (H200/H100 NVL), 2MB (L40S) SPI ROM (vs 256KB for Pascal-era)",
        "developer": "linfu2 (TAR uname, H200/H100/L40S products)",
    },
    "mechanism": (
        "Hopper-era GPUs (H200 NVL, H100 NVL) and Ada (L40S) include a second firmware "
        "component beyond the VBIOS/IROM: a CEC1736 embedded controller firmware package "
        "(.fwpkg). CEC1736 is the chassis EC handling power sequencing, thermal management, "
        "and board-level health monitoring. This is an additional attack surface beyond the "
        "GPU VBIOS. The SPI ROM size has grown from 256KB (Pascal P40) to 4MB (Hopper H200) "
        "-- 16x larger attack surface. All CEC and SPI ROM entries are ZipCrypto encrypted."
    ),
    "impact": "CEC1736 embedded controller firmware is an independent attack surface from VBIOS; thermal/power management bypass via CEC compromise; 4MB SPI ROM is largest GPU firmware surface in this dataset",
}

FLEX170_F1 = {
    "id": "FLEX170-F1",
    "severity": "HIGH",
    "title": "Intel Flex 170 ships PVT_ES IFWI (iteration 119) and signed ECC_OFF data update for C0 stepping",
    "affected": ["ucs-video-intel-flex-170 (DG02-1.3274_7.0.0.0)"],
    "evidence": {
        "ifwi": "IFWI_ATS_M150_PVT_ES_119_gfx_fwupdate_SOC1.bin (2052KB)",
        "designation": "PVT_ES (Pre-Volume Test Engineering Sample), iteration 119",
        "ecc_file": "IFWIDATA_XPUM_ATS_M150_512_C0_PVT_ES_117_DataUpdate_ECC_OFF_Signed.bin (40KB)",
        "ecc_stepping": "C0 (production stepping), PVT_ES iteration 117",
        "ecc_signed": "Signed (Intel signature on ECC_OFF update)",
        "codename": "ATS-M (Arctic Sound M), die M150, SOC1 package",
        "comparison": "Flex 140 ES_034 vs Flex 170 PVT_ES_119: Flex 170 is 3.5x deeper into the ES chain",
        "developer_uid": 747789,
    },
    "mechanism": (
        "Intel Flex 170 (ATS-M Arctic Sound) ships with PVT_ES (Pre-Volume Test Engineering "
        "Sample) IFWI at iteration 119. PVT_ES is a pre-production silicon/firmware stage "
        "between engineering sample and production release (PRQ). Having PVT_ES iteration 119 "
        "in a production Cisco bundle indicates Intel's ES validation firmware was packaged "
        "directly without a production PRQ build. The 40KB signed data update "
        "IFWIDATA_XPUM_ATS_M150_512_C0_PVT_ES_117_DataUpdate_ECC_OFF_Signed.bin disables ECC "
        "on the Flex 170 C0-stepping GPU memory (512MB, C0). This is a signed production update "
        "that selectively disables ECC error correction. The ATS codename and M150 die ID are "
        "Intel's internal Arctic Sound GPU designations."
    ),
    "impact": "PVT_ES firmware (iteration 119) in production has relaxed security controls vs PRQ; signed ECC_OFF update creates path to disable error detection on Flex 170 GPU memory; ATS/M150/C0 internal codenames exposed",
}

GPU_PII_F1 = {
    "id": "GPU-PII-F1",
    "severity": "LOW",
    "title": "Developer usernames from NVIDIA and Intel GPU teams in production Cisco firmware TAR headers",
    "affected": ["All GPU firmware packages in C-Series bundle"],
    "evidence": {
        "mkaushal": "NVIDIA (RTX Pro 6000 Blackwell, A16 Ampere)",
        "linfu2": "NVIDIA (H200 NVL, H100 NVL, H100 80G, L40S)",
        "weslleun": "Intel Flex GPU team (Flex 140 PCIe, Flex 140 Mezz, Flex 170)",
        "intel_uid": "UID 747789 in all three Intel Flex builds",
    },
    "mechanism": (
        "TAR archive uname fields embed the build system usernames of individual developers. "
        "Three developers identified: mkaushal (NVIDIA workstation/datacenter GPU), "
        "linfu2 (NVIDIA HPC/NVL GPU), weslleun (Intel Flex GPU). "
        "Intel UID 747789 is consistent across all three Flex products, pinpointing a single "
        "build system account. These names and UIDs enable developer attribution for specific "
        "GPU firmware builds."
    ),
    "impact": "Developer PII in production firmware headers; build system UID attribution; identity correlation across GPU product lines",
}

FLEX140_MEZZ_F1 = {
    "id": "FLEX140-MEZZ-F1",
    "severity": "LOW",
    "title": "Intel Flex 140 Mezz ships identical firmware binary to Flex 140 PCIe (same ES_034 IFWI, same pldm_sg2_amc)",
    "affected": ["ucs-video-intel-flex-140-Mezz (DG02-2.2280_7.0.0.0)"],
    "evidence": {
        "shared_ifwi": "IFWI_XPUM_Flex_140_128_ES_034_gfx_fwupdate_DG02_2.2280_.bin (2052KB) identical in PCIe and Mezz packages",
        "shared_pldm": "pldm_sg2_amc_v_7_0_0_0.bin (381KB) identical in both",
        "developer": "weslleun, uid 747789 (both packages)",
    },
    "mechanism": "Single IFWI binary serves both PCIe and Mezzanine form factors; form-factor differentiation is handled above the firmware layer",
    "impact": "Any FLEX-F1 finding (ES designation, rot.key, 3DES ciphers) applies equally to Mezz deployments; single binary doubles the impacted SKU count",
}

ALL_FINDINGS = [A16_F1, H2H1_F1, FLEX170_F1, GPU_PII_F1, FLEX140_MEZZ_F1]

SUMMARY = {
    "module": "cisco_ucs_cseries_gpu_hopper_flex_re",
    "targets": "NVIDIA A16/H200NVL/H100NVL/L40S, Intel Flex 140-Mezz/Flex 170",
    "total_findings": len(ALL_FINDINGS),
    "by_severity": {"HIGH": 2, "MEDIUM": 1, "LOW": 2},
    "headline": (
        "NVIDIA A16 embeds 32MB ZipCrypto-encrypted ConnectX-6 NVSwitch firmware plus CEC OTA. "
        "Intel Flex 170 ships PVT_ES iteration 119 IFWI plus signed ECC_OFF data update for C0 stepping. "
        "Developer usernames (mkaushal/linfu2/weslleun) in production TAR headers across all products."
    ),
}

if __name__ == "__main__":
    for f in ALL_FINDINGS:
        print(f"[{f['severity']:6s}] {f['id']}: {f['title']}")
    print(f"\nTotal: {SUMMARY['total_findings']} findings "
          f"({SUMMARY['by_severity']['HIGH']}H/"
          f"{SUMMARY['by_severity']['MEDIUM']}M/"
          f"{SUMMARY['by_severity']['LOW']}L)")
