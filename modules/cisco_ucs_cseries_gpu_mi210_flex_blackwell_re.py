"""
Cisco UCS C-Series -- AMD MI210, Intel Flex 140, NVIDIA RTX Pro 6000 (Blackwell) RE
Targets: ucs-video-amd-mi210.113-D67307V-075_3.16, ucs-video-intel-flex-140.DG02-2.2280,
         ucs-video-nvidia-RTX-PRO-6000.98.02.8D.00.01, ucs-m83-8p40-vic.4.7.2.260001

Bundle extraction: tarfile.open(cseries_decomp.bin, 'r:') -> extractfile -> SN header ->
gzip chunk decompress -> inner TAR -> ./blob -> (gzip?) -> inner content TAR or ZIP

SN header format: magic 6401534e (4B) + hsize (2B BE) + pad (2B) + name at [8:hsize] + gzip payload
"""

import hashlib

AMD_MI210 = {
    "product": "ucs-video-amd-mi210",
    "fw_label": "113-D67307V-075_3.16",
    "bundle_member": "./isan/plugin_img/ucs-video-amd-mi210.113-D67307V-075_3.16.bin",
    "raw_size_kb": 24006,
    "inner_tar_size_mb": 79,
    "structure": "SN -> gzip -> inner TAR -> ./blob (gzip) -> AMD-MI210 TAR -> amdfwflash/ifwi/** + sbin/amdfwflash",
    "amdfwflash_size_kb": 23326,
    "ifwi_variants": {
        "count": 88,
        "format": "1472KB each (D6XXXXXX.NNN naming)",
        "memory_configs": ["ga", "mu1", "mu2", "mu3", "mu4", "mu5"],
        "ifwi_magic": "55aa",
    },
    "internal_die_ids": {
        "D65209": {"name": "MI210 full die", "mem": "128GB HBM2E", "cooling": "ROWAIRCOOLEDUBB4"},
        "D65210": {"name": "MI210 variant", "mem": "128GB HBM2E"},
        "D65205": {"name": "MI210 smaller variant", "mem": "unknown"},
        "D67301": {"name": "MI200 64GB SRIOV", "mem": "64GB HBM2E", "flags": "SRIOV"},
        "D67302": {"name": "MI200 OEM (HPE)", "mem": "64GB", "oem_str": "HPE D67302000B"},
        "D67305": {"name": "MI200 AMD variant", "mem": "unknown", "fw": "113-AMDD67305000A.006"},
        "D67307": {"name": "MI200 target die (this bundle)", "mem": "unknown"},
        "D65205_mu": {"name": "mu-memory variant", "fw": "113-AMDD652050Cxx.007"},
    },
    "leaked_build_paths": [
        "AMD_MI200_D65209_XT_A1_HBM2E_128GB_ROWAIRCOOLEDUBB4\\config.h",
        "AMD_MI200_D67301_XT_A1_HBM2E_64GB_SRIOV\\config.h",
    ],
    "security_strings": [
        "SMU_ReadEfuseValue()",
        "SMU_READ_FUSE()overflow",
        "u32EfuseStartIndex=",
        "PSP:Stage2 END.Jump to TOS",
        "Map Secure FB",
        "DEBUG_DATA_PARITY_EN",
        "bls_get_ras_config()",
        "RAS HBM ECC Init",
        "SMN Read failed [%x]",
        "SMN Write failed [%x]",
        "Enable HBM bank harvest",
    ],
    "rmfw_entries": [
        "113-AMDD652050Cxx.007.update.bin",
        "113-AMDD67305000A.006.update.bin",
        "113-DELD6730300xx.014.update.bin",
        "113-DELD6730400xx.009.update.bin",
        "113-HPED67302000B.009.update.bin",
    ],
}

INTEL_FLEX_140 = {
    "product": "ucs-video-intel-flex-140",
    "fw_label": "DG02-2.2280_7.0.0.0",
    "bundle_member": "./isan/plugin_img/ucs-video-intel-flex-140.DG02-2.2280_7.0.0.0.bin",
    "raw_size_kb": 1124,
    "structure": "SN -> gzip -> inner TAR -> ./blob (gzip) -> IFWI TAR with 2 members",
    "inner_members": {
        "IFWI_XPUM_Flex_140_128_ES_034_gfx_fwupdate_DG02_2.2280_.bin": {
            "size_kb": 2052,
            "designation": "ES (Engineering Sample)",
            "iteration": 34,
            "uid": 747789,
        },
        "pldm_sg2_amc_v_7_0_0_0.bin": {
            "size_kb": 381,
            "description": "PLDM firmware for AMC (Advanced Mezzanine Card)",
            "codename": "sg2 (second-gen Flex, aka Xe-HPG DG02 codename SG2)",
        },
    },
    "security_files": ["rot.key"],
    "build_paths": ["src/sg2/sha.c"],
    "leaked_username": "weslleun",
    "deprecated_ciphers": [
        "PBE with SHA1 and 3-Key 3DES",
        "pbeWithSHAAnd2-KeyTripleDES-CBC",
        "PBE with SHA1 and 2-Key 3DES",
        "hmacSHA1",
    ],
    "oem_interfaces": ["intel_oem_fru", "customer_oem_fru"],
}

RTX_PRO_6000 = {
    "product": "ucs-video-nvidia-RTX-PRO-6000",
    "fw_label": "98.02.8D.00.01_G153.0210.00.02",
    "architecture": "Blackwell (GB153)",
    "bundle_member": "./isan/plugin_img/ucs-video-nvidia-RTX-PRO-6000.98.02.8D.00.01_G153.0210.00.02.bin",
    "raw_size_kb": 1311,
    "structure": "SN -> gzip -> inner TAR -> ./blob (gzip) -> RTX_PRO_6000_300_302.zip TAR",
    "inner_zip": "RTX_PRO_6000_300_302.zip",
    "zip_contents": {
        "RTX_PRO_6000/IROM_VBIOS/nvfw_RTXPRO6000BWSE_0003_250826.1.0_prod-signed.fwpkg": {
            "size_kb": 2153,
            "encrypted": True,
            "cipher": "ZipCrypto",
        },
    },
    "leaked_username": "mkaushal",
    "build_timestamp": "2025120501",
    "fw_sku_id": "RTXPRO6000BWSE",
    "fw_date": "250826 (2025-08-26)",
}

FINDINGS = {
    "MI210-F1": {
        "id": "MI210-F1",
        "severity": "HIGH",
        "title": "AMD MI210 IFWI bundle exposes 8 internal die IDs, build paths with die stepping, SRIOV flags, and eFuse access API",
        "affected": ["ucs-video-amd-mi210 (113-D67307V-075_3.16)"],
        "evidence": {
            "die_ids": list(AMD_MI210["internal_die_ids"].keys()),
            "leaked_paths": AMD_MI210["leaked_build_paths"],
            "efuse_api": ["SMU_ReadEfuseValue()", "SMU_READ_FUSE()overflow", "u32EfuseStartIndex="],
            "psp_string": "PSP:Stage2 END.Jump to TOS",
            "sriov_config": "AMD_MI200_D67301_XT_A1_HBM2E_64GB_SRIOV\\config.h",
            "ras_debug": "DEBUG_DATA_PARITY_EN (debug parity mode string in VBIOS)",
            "hbm_harvest": "Enable HBM bank harvest (bank harvest path exposed)",
            "ifwi_count": "88 IFWI variants across 5 memory configurations",
        },
        "mechanism": (
            "The AMD MI210 Cisco UCS package contains 88 IFWI variants (1.4MB each) across "
            "5 memory configurations (ga, mu1-mu5). Each IFWI binary contains ATOMBIOS VBIOS "
            "sections with leaked AMD internal build paths: "
            "'AMD_MI200_D65209_XT_A1_HBM2E_128GB_ROWAIRCOOLEDUBB4\\config.h' reveals die ID "
            "(D65209), stepping (XT_A1), memory config (128GB HBM2E), and cooling config "
            "(ROWAIRCOOLEDUBB4). Eight distinct AMD die IDs are present across the variant set. "
            "The eFuse API surface is exposed: SMU_ReadEfuseValue() and SMU_READ_FUSE()overflow "
            "indicate direct eFuse access paths in the VBIOS. SMN (System Management Network) "
            "read/write failure handlers expose the bus access path. PSP (Platform Security "
            "Processor) Stage 2 completion string is present. SRIOV variant (D67301) is included "
            "alongside non-SRIOV variants with SRIOV encoded in the build path."
        ),
        "impact": "AMD internal silicon identifiers and die stepping exposed; eFuse access API surface identified; 88 IFWI variants provide cross-stepping firmware analysis surface",
    },
    "MI210-F2": {
        "id": "MI210-F2",
        "severity": "MEDIUM",
        "title": "AMD internal amdfwflash tool (23MB ELF) bundled in production Cisco firmware package",
        "affected": ["ucs-video-amd-mi210 (113-D67307V-075_3.16)"],
        "evidence": {
            "path": "AMD-MI210/opt/amdfwflash/sbin/amdfwflash",
            "size_kb": 23326,
            "format": "ELF (AMD internal IFWI flash utility)",
            "command_file": "AMD-MI210/opt/amdfwflash/command.txt",
        },
        "mechanism": (
            "The MI210 firmware bundle includes AMD's internal 'amdfwflash' utility (23MB ELF). "
            "This tool updates IFWI images directly on MI200-class GPUs. It ships alongside "
            "the IFWI images and command.txt configuration in the Cisco UCS C-Series bundle. "
            "This enables IFWI reflash of MI210 GPUs outside of AMD's official flash toolchain."
        ),
        "impact": "AMD internal flash utility enables IFWI reflash path not limited to official AMD toolchain; direct IFWI update without AMD validation chain",
    },
    "FLEX-F1": {
        "id": "FLEX-F1",
        "severity": "HIGH",
        "title": "Intel Flex 140 IFWI labeled as Engineering Sample (ES) iteration 34, with rot.key reference and deprecated 3DES ciphers",
        "affected": ["ucs-video-intel-flex-140 (DG02-2.2280_7.0.0.0)"],
        "evidence": {
            "ifwi_filename": "IFWI_XPUM_Flex_140_128_ES_034_gfx_fwupdate_DG02_2.2280_.bin",
            "es_designation": "ES = Engineering Sample (pre-production silicon designation)",
            "iteration": "034 (iteration 34 of ES firmware)",
            "uid": 747789,
            "security_file": "rot.key (Root of Trust key reference in IFWI structure)",
            "deprecated_ciphers": ["PBE with SHA1 and 3-Key 3DES", "PBE with SHA1 and 2-Key 3DES", "hmacSHA1"],
            "pldm_firmware": "pldm_sg2_amc_v_7_0_0_0.bin (PLDM AMC firmware for sg2 codename)",
            "leaked_username": "weslleun",
        },
        "mechanism": (
            "The Intel Flex 140 IFWI update binary is labeled 'ES' (Engineering Sample) -- "
            "pre-production silicon designation in a Cisco production firmware bundle. ES firmware "
            "is intended for pre-production silicon validation, not production deployment. "
            "ES builds are iteration 34 (034) of the Flex 140 IFWI chain, suggesting this is "
            "a long-running ES firmware track that was packaged into production. The IFWI "
            "structure references 'rot.key' (Root of Trust key), indicating the key management "
            "infrastructure is embedded in the bundle filesystem. Deprecated ciphers "
            "(3DES + SHA1 for PBE) indicate legacy cryptographic components. "
            "The sg2 codename in pldm_sg2_amc_v_7_0_0_0.bin reveals Intel's internal DG02 "
            "Flex GPU architecture codename (SG2)."
        ),
        "impact": "ES-designated IFWI in production: ES builds typically have relaxed security controls vs PRQ (Production Released Qualification); rot.key reference exposes key infrastructure path; 3DES+SHA1 deprecated cipher chain active",
    },
    "RTXPRO-F1": {
        "id": "RTXPRO-F1",
        "severity": "MEDIUM",
        "title": "RTX Pro 6000 Blackwell firmware uses ZipCrypto; developer username and December 2025 build timestamp in TAR header",
        "affected": ["ucs-video-nvidia-RTX-PRO-6000 (98.02.8D.00.01_G153.0210.00.02)"],
        "evidence": {
            "fwpkg": "nvfw_RTXPRO6000BWSE_0003_250826.1.0_prod-signed.fwpkg (2.1MB, ZipCrypto encrypted)",
            "sku_id": "RTXPRO6000BWSE (Blackwell Workstation SE)",
            "fw_date": "250826 (2025-08-26)",
            "build_timestamp": "2025120501 (tag.txt: December 5, 2025)",
            "leaked_username": "mkaushal (uname in production TAR header)",
            "cipher": "ZipCrypto (flag_bits & 1; same class as P40/v340/H200 BCSERIES-F2)",
        },
        "mechanism": (
            "RTX Pro 6000 firmware (GB153 Blackwell) uses ZipCrypto encryption for the .fwpkg "
            "container (nvfw_RTXPRO6000BWSE_0003_250826.1.0_prod-signed.fwpkg). "
            "The SKU identifier RTXPRO6000BWSE reveals Blackwell Workstation SE designation. "
            "Developer username 'mkaushal' is embedded in the production TAR uname field. "
            "The tag.txt build timestamp (2025120501 = December 5, 2025) pinpoints bundle "
            "assembly date. ZipCrypto is the same cipher as BCSERIES-F2 and GPU-ZIPCRYPT-F1; "
            "4th GPU line with ZipCrypto. The .fwpkg is signed ('prod-signed') but the "
            "container uses ZipCrypto."
        ),
        "impact": "ZipCrypto bypass recovers Blackwell IROM/VBIOS; developer PII (mkaushal) in production headers; extends ZipCrypto class to Blackwell generation",
    },
}

ALL_FINDINGS = list(FINDINGS.values())

SUMMARY = {
    "module": "cisco_ucs_cseries_gpu_mi210_flex_blackwell_re",
    "targets": "AMD MI210 (MI200 IFWI), Intel Flex 140 (DG02/SG2), NVIDIA RTX Pro 6000 (Blackwell GB153)",
    "total_findings": len(ALL_FINDINGS),
    "by_severity": {"HIGH": 2, "MEDIUM": 2, "LOW": 0},
    "headline": (
        "AMD MI210 ships 88 IFWI variants with 8 internal die IDs and eFuse access API; "
        "Intel Flex 140 ships ES (Engineering Sample) IFWI with rot.key reference and 3DES ciphers; "
        "RTX Pro 6000 Blackwell firmware ZipCrypto encrypted with developer username in TAR header."
    ),
}

if __name__ == "__main__":
    for f in ALL_FINDINGS:
        print(f"[{f['severity']:6s}] {f['id']}: {f['title']}")
    print(f"\nTotal: {SUMMARY['total_findings']} findings "
          f"({SUMMARY['by_severity']['HIGH']}H/"
          f"{SUMMARY['by_severity']['MEDIUM']}M/"
          f"{SUMMARY['by_severity']['LOW']}L)")
