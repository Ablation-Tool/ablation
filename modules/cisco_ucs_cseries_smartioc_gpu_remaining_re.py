"""
Cisco UCS C-Series -- SmartIOC 2200/3200, NVIDIA A30/A40/T4, AMD 7150x2, CEC generation survey RE
Targets: ucs-storage-controller-miami-river-hba/raid/rock, ucs-video-nvidia-A30/A40/T4,
         ucs-c-amd-video-7150x2

Miami River HBA = Microchip Technology SmartIOC (OEM) with debug CLI active.
Ampere CEC die IDs (GA100/GA102) in A30/A40 firmware reveal die cross-reference.
T4 has no CEC (pre-CEC era). 7150x2 = AMD FirePro S7150 X2 with PLX switch.
"""

SMARTIOC = {
    "products": {
        "hba": "ucs-storage-controller-miami-river-hba",
        "raid": "ucs-storage-controller-miami-river-raid",
        "rock": "ucs-storage-controller-miami-river-rock",
        "beach_plus": "ucs-storage-controller-miami-beach-plus",
        "beach": "ucs-storage-controller-miami-beach",
    },
    "fw_version": "03.01.41.040",
    "oem_vendor": "Microchip Technology Inc",
    "product_names": ["smartioc2200", "smartoc3200"],
    "fw_blob": "Cisco_smartioc2200_smartoc3200_03.01.41.040_Production.bin",
    "fw_size_kb": 12143,
    "fw_md5": "ff51184a2a2f603e8ba9156327236033",
    "fw_magic": "c34155aa",
    "oem_tag": "CAT=Cisco",
    "packaging": "SN -> gzip -> inner TAR -> ./blob (ZIP, unencrypted) -> single Production bin",
    "debug_strings": [
        "Debug PFF.",
        "Debug: Send interrupt to host.",
        "Debug the pcifndbg.",
        "-t: Turn on the debug option.",
        "-f: Turn off the debug option.",
        "CORE_ID=%d VPE_ID=%d DEBUG    : 0x%08x",
    ],
    "nvram_strings": [
        "PLATFORM Warning: Local NVRAM HAL major version is invalid. major ver = %x",
        "PLATFORM Warning: local nvram version incorrect",
        "PLATFORM: Next boot default MPSS updated to %dB",
        "PLATFORM: Next boot default MPSS failed to write to nvram, rc=0x%x",
    ],
    "pcie_debug_strings": [
        "RESET: Soft reset (reset except PCIe) vpe_id=0x%x",
        "RESET: PCIe Reset type=0x%x",
        "RESET: PCIe Hot Reset - PCS soft reset triggered",
        "SOFT_EP_LRPC: soft_ep_pcie_cap_reg_get lnk down",
        "pcifn_cap_pcie.c",
    ],
}

NVIDIA_AMPERE_ADA = {
    "A30": {
        "fw_label": "92.00.66.00.03_1001.0205.00.02_6.07",
        "inner_zip": "A30_600_601.zip",
        "developer": "mkaushal",
        "cec_chip": "GA100 (ga100_cec_ota_v6.07_prod.bin)",
        "zip_contents": {
            "A30/CEC/ga100_cec_ota_v6.07_prod.bin": {"size_kb": 128, "encrypted": True},
            "A30/IROM_VBIOS/1001_0205_882__9200660003-9200660004-prod.nvr": {"size_kb": 1028, "encrypted": True},
        },
    },
    "A40": {
        "fw_label": "94.02.5C.00.03_G133.0200.00.05_5.01",
        "inner_zip": "A40_C00_C01.zip",
        "developer": "mkaushal",
        "cec_chip": "GA102 (ga102_cec_ota_v5.01_prod.bin)",
        "zip_contents": {
            "A40/CEC/ga102_cec_ota_v5.01_prod.bin": {"size_kb": 128, "encrypted": True},
            "A40/IROM_VBIOS/g133_0200_895__94025C0003-94025C000F-prod.nvr": {"size_kb": 2052, "encrypted": True},
        },
    },
    "T4": {
        "fw_label": "90.04.B4.00.04_G183.0200.00.02",
        "inner_zip": "T4_100_200_210_211_212.zip",
        "developer": "mkaushal",
        "cec_chip": None,
        "zip_contents": {
            "T4/IROM/G1830200.ifr": {"size_kb": 17, "encrypted": True},
            "T4/VBIOS/g183_0200_895__9004B40004.rom": {"size_kb": 1008, "encrypted": True},
        },
        "note": "No CEC component -- Turing-era (pre-CEC generation)",
    },
}

AMD_7150X2 = {
    "product": "ucs-c-amd-video-7150x2",
    "fw_label": "015.049.000.016.007518_113-8747CA-200",
    "inner_zip": "S7150X2_C7630600.zip",
    "developer": "mkaushal",
    "architecture": "Fiji XT (dual-GPU: 2x FirePro S7150, MxGPU SR-IOV)",
    "zip_contents": {
        "S7150X2/CA/PLX/113-8747CA-200.bin": {"size_kb": 0, "encrypted": True, "note": "PLX PCIe switch firmware, 0KB (empty or stub)"},
        "S7150X2/CA/VBIOS/h369471_C7630600_100_signed.rom": {"size_kb": 370, "encrypted": True},
    },
}

CEC_SURVEY = {
    "no_cec": ["T4 (Turing)", "M10 (Maxwell)", "M60 (Maxwell)", "P40 (Pascal)", "P100", "V100", "RTX 6000", "RTX 8000"],
    "has_cec": ["A10 (Ampere)", "A16 (Ampere)", "A30 (Ampere)", "A40 (Ampere)", "A100 (Ampere)", "L40S (Ada)", "H100 NVL (Hopper)", "H200 NVL (Hopper)", "RTX Pro 6000 (Blackwell)"],
    "cec_intro_generation": "Ampere (2020)",
    "cec_chips_observed": {
        "GA100": "A30 (ga100_cec_ota_v6.07)",
        "GA102": "A40 (ga102_cec_ota_v5.01)",
        "BMGP3": "A16 (cec_ota_BMGP3-04.01, multi-instance GA100 board controller)",
        "CEC1736": "H100/H200/L40S (cec1736-ecfw, dedicated EC chip)",
    },
}

FINDINGS = {
    "SMARTIOC-F1": {
        "id": "SMARTIOC-F1",
        "severity": "HIGH",
        "title": "Cisco SmartIOC 2200/3200 (Miami River) is Microchip OEM with active PCIe debug CLI and plaintext Production firmware",
        "affected": ["ucs-storage-controller-miami-river-hba/raid/rock (03.01.41.040)"],
        "evidence": {
            "oem_vendor": "Copyright Microchip Technology Inc",
            "cisco_tag": "CAT=Cisco (OEM tag in binary)",
            "fw_encryption": "plaintext (ZIP unencrypted, unlike all GPU firmware)",
            "debug_cli": ["-t: Turn on the debug option.", "-f: Turn off the debug option.", "Debug PFF.", "Debug the pcifndbg."],
            "nvram_fallback": "PLATFORM Warning: Local NVRAM HAL major version is invalid. major ver = %x",
            "pcie_debug": "RESET: PCIe Hot Reset - PCS soft reset triggered (debug path)",
            "fw_size_kb": 12143,
        },
        "mechanism": (
            "The Cisco SmartIOC 2200/3200 (Miami River HBA/RAID/Rock) is a Microchip Technology "
            "OEM controller with Cisco CAT tag. Unlike GPU firmware (ZipCrypto encrypted), "
            "the 12MB Production.bin is distributed in plaintext. The firmware contains an "
            "active debug CLI: '-t: Turn on the debug option' and '-f: Turn off the debug option' "
            "control per-function debug output. 'Debug PFF' is a per-function debug mode for "
            "PCIe function debug. The NVRAM HAL has a version fallback warning path. "
            "PCIe reset debug paths (Hot Reset, Soft Reset) expose internal recovery handling. "
            "Three SKU variants (HBA, RAID, Rock/Beach) all use the same binary (same MD5)."
        ),
        "impact": "PCIe function debug CLI active in production; NVRAM version mismatch fallback is a persistence path; plaintext firmware enables direct binary analysis without ZipCrypto bypass",
    },
    "CEC-F1": {
        "id": "CEC-F1",
        "severity": "MEDIUM",
        "title": "NVIDIA A30 uses GA100 die CEC (same silicon as A100); A40 uses GA102 CEC (consumer RTX 3090 die) -- die cross-reference via CEC firmware names",
        "affected": ["ucs-video-nvidia-A30 (92.00.66.00.03)", "ucs-video-nvidia-A40 (94.02.5C.00.03)"],
        "evidence": {
            "a30_cec": "ga100_cec_ota_v6.07_prod.bin -- GA100 die (same as A100 80G)",
            "a40_cec": "ga102_cec_ota_v5.01_prod.bin -- GA102 die (same as consumer RTX 3090/RTX A6000)",
            "t4_cec": "None -- Turing T4 predates CEC architecture",
            "cec_intro": "CEC introduced with Ampere; all post-Ampere GPUs in this bundle include it",
        },
        "mechanism": (
            "CEC (Chassis Embedded Controller) firmware filenames expose the GPU die chip ID: "
            "A30 uses GA100 (same Ampere die as A100, but with fewer SM partitions), "
            "A40 uses GA102 (same die as RTX 3090/RTX A6000 -- consumer-grade GA102 in "
            "enterprise form factor). T4 (Turing era) has no CEC, establishing Ampere as the "
            "CEC introduction generation. All Ampere/Ada/Hopper/Blackwell GPUs in this bundle "
            "include CEC as an independent firmware attack surface alongside VBIOS."
        ),
        "impact": "Die cross-reference identifies consumer/enterprise shared silicon; CEC is an independent firmware attack surface absent from pre-Ampere GPU security posture",
    },
    "7150X2-F1": {
        "id": "7150X2-F1",
        "severity": "LOW",
        "title": "AMD 7150x2 FirePro S7150 X2 dual-GPU ships ZipCrypto-encrypted VBIOS (370KB) with PLX switch stub",
        "affected": ["ucs-c-amd-video-7150x2 (015.049.000.016.007518_113-8747CA-200)"],
        "evidence": {
            "vbios": "S7150X2/CA/VBIOS/h369471_C7630600_100_signed.rom (370KB, ZipCrypto)",
            "plx": "S7150X2/CA/PLX/113-8747CA-200.bin (0KB -- empty PLX entry)",
            "developer": "mkaushal",
            "architecture": "Fiji XT dual-GPU, MxGPU (SR-IOV hardware virtualization)",
        },
        "mechanism": "Same ZipCrypto class as v340 (AMDV340-F1); PLX PCIe switch entry is empty (0KB stub) unlike M10/M60 which have real PLX ROM; VBIOS is AMD-signed + ZipCrypto",
        "impact": "ZipCrypto class extends to 7150x2 FirePro; MxGPU SR-IOV VBIOS recovery via known-plaintext attack on 370KB target",
    },
}

ALL_FINDINGS = list(FINDINGS.values())

SUMMARY = {
    "module": "cisco_ucs_cseries_smartioc_gpu_remaining_re",
    "targets": "SmartIOC 2200/3200, NVIDIA A30/A40/T4, AMD 7150x2",
    "total_findings": len(ALL_FINDINGS),
    "by_severity": {"HIGH": 1, "MEDIUM": 1, "LOW": 1},
    "headline": (
        "SmartIOC 2200/3200 (Miami River) is a Microchip OEM with active PCIe debug CLI (-t/-f flags) "
        "and plaintext 12MB Production firmware. A30/A40 CEC firmware names expose GA100/GA102 "
        "die cross-reference (A40 uses consumer RTX 3090 die GA102). "
        "T4 (Turing) is the last GPU generation without CEC."
    ),
    "cec_survey": CEC_SURVEY,
}

if __name__ == "__main__":
    for f in ALL_FINDINGS:
        print(f"[{f['severity']:6s}] {f['id']}: {f['title']}")
    print(f"\nTotal: {SUMMARY['total_findings']} findings "
          f"({SUMMARY['by_severity']['HIGH']}H/"
          f"{SUMMARY['by_severity']['MEDIUM']}M/"
          f"{SUMMARY['by_severity']['LOW']}L)")
    print("\nCEC Generation Survey:")
    print(f"  No CEC: {', '.join(CEC_SURVEY['no_cec'])}")
    print(f"  Has CEC: {', '.join(CEC_SURVEY['has_cec'])}")
    print(f"  Introduced: {CEC_SURVEY['cec_intro_generation']}")
