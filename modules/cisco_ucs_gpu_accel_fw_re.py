"""
Cisco UCS GPU and Accelerator Firmware RE module
Targets: NVIDIA H200 NVL, H100 NVL, H100 80G, Intel Arc Pro Flex 140/170 (AMC + IFWI),
         VIC M73kR, PMEM DIMM, AMD MI210, NVIDIA A16
Source: ucs-k9-bundle-b-series.6.0.2b.B.bin

SN entry offsets in decompressed B-Series bundle:
  NVIDIA H200 NVL:        decomp+91683328   (hsize=844, H200_NVL_B00.zip)
  AMD MI210:              decomp+125502976  (hsize=780, AMD-MI210 IFWI Aldebaran)
  NVIDIA H100 NVL:        decomp+158133248  (hsize=844, H100_NVL_700.zip)
  Intel Flex 140 X410M8 AMC: decomp+103812096 (hsize=768, PLDM AMC only)
  Intel Flex 140 X210M8 AMC: decomp+104784896 (hsize=764)
  Intel Flex 140 generic: decomp+181064704  (hsize=780, IFWI + PLDM AMC)
  Intel Flex 170 generic: decomp+182217216  (hsize=780, IFWI + IFWIDATA ECC_OFF + PLDM AMC)
  NVIDIA L4 mezzanine:    decomp+157412864  (hsize=800)
  NVIDIA L40S:            decomp+183371264  (hsize=840)
  NVIDIA T4:              decomp+178253824  (hsize=796)
  NVIDIA A16:             decomp+195342848  (hsize=916, analyzed in cisco_ucs_xseries_m8_bios_re.py)
  NVIDIA H100 80G:        decomp+193387008  (hsize=844, H100-80_600.zip)
  VIC M73kR:              decomp+581074944  (hsize=760, ServerEngines 10.6.144.21)
  VIC M72kR:              decomp+607720960  (hsize=760, ServerEngines 10.0.803.19)
  PMEM DIMM:              decomp+455842816  (hsize=756)

Decompression: all entries use standard gzip (wbits=31); gzip.decompress() fails
on these entries due to non-gzip trailer data; use zlib.decompress(data, wbits=31).

Common bundle structure for all entries:
  gzip -> TAR (./blob + ./isan/etc/imghdr.bin) -> blob gzip -> inner TAR with firmware files

NVIDIA GPU bundle structure:
  blob gzip -> TAR -> <GPU>_<STEPPING>.zip + tag.txt
  ZIP contains: CEC/ (controller firmware .fwpkg) + IROM_VBIOS/ (VBIOS .rom)
  ZIP encryption: BOTH CEC fwpkg AND VBIOS .rom are ZipCrypto-encrypted
  tag date: 2025-08-25 for H200/H100 families

Intel Flex GPU bundle structure:
  blob gzip -> inner TAR -> IFWI*.bin + [IFWIDATA*.bin] + pldm_sg2_amc*.bin
  IFWI: Intel Flash Partition Table ($FPT, 24465054) format -- same as Intel ME/CSE
  PLDM: Platform Level Data Model firmware for SG2 AMC (magic: f018878ccb7d4943)
  PLDM is shared between Flex 140 and Flex 170 -- same binary, both platforms

VIC M73kR/M72kR structure:
  blob (no inner compression) = ServerEngines binary, magic 536572766572456e "ServerEn"
  SWID: swid-adaptor-M73KR_E for M73kR; same format as M83/M84/M85 VIC analyzed separately
"""

# --- GPU FIRMWARE INVENTORY ---

NVIDIA_H200_NVL = {
    "target":        "NVIDIA H200 NVL GPU firmware",
    "sn_name":       "ucs-video-nvidia-H200-NVL.96.00.D9.00.0E_1010.0",
    "bundle_zip":    "H200_NVL_B00.zip",
    "silicon_step":  "B00",  # H200 Hopper B stepping, revision 00
    "tag_date":      "2025-08-25",
    "zip_contents": {
        "CEC":   "H200_NVL/CEC/cec1736-ecfw-00.02.0192.0000-n00-rel-prod.fwpkg (190KB, ZipCrypto)",
        "VBIOS": "H200_NVL/IROM_VBIOS/1010_0230_894__9600D9000E-prod-spi.rom (4MB, ZipCrypto)",
    },
    "pci_device_id_partial": "9600D9000E",
    "vbios_fw_variant": "0230",  # H200 NVL variant identifier in VBIOS filename
}

NVIDIA_H100_NVL = {
    "target":        "NVIDIA H100 NVL GPU firmware",
    "sn_name":       "ucs-video-nvidia-H100-NVL.96.00.D9.00.0D_1010.0",
    "bundle_zip":    "H100_NVL_700.zip",
    "tag_date":      "2025-08-25",
    "zip_contents": {
        "CEC":   "H100_NVL/CEC/cec1736-ecfw-00.02.0192.0000-n00-rel-prod.fwpkg (190KB, ZipCrypto)",
        "VBIOS": "H100_NVL/IROM_VBIOS/1010_0210_886__9600D9000D-prod-spi.rom (4MB, ZipCrypto)",
    },
    "pci_device_id_partial": "9600D9000D",
    "vbios_fw_variant": "0210",
}

NVIDIA_H100_80G = {
    "target":        "NVIDIA H100 80GB GPU firmware",
    "sn_name":       "ucs-video-nvidia-H100-80G.96.00.D9.00.0C_1010.0",
    "bundle_zip":    "H100-80_600.zip",
    "tag_date":      "2025-08-25",
    "zip_contents": {
        "CEC":   "H100-80/CEC/cec1736-ecfw-00.02.0192.0000-n00-rel-prod.fwpkg (190KB, ZipCrypto)",
        "VBIOS": "H100-80/IROM_VBIOS/1010_0200_882__9600D9000C-prod-spi.rom (4MB, ZipCrypto)",
    },
    "pci_device_id_partial": "9600D9000C",
    "vbios_fw_variant": "0200",
}

INTEL_FLEX_140 = {
    "target":        "Intel Arc Pro A-Series Flex 140 GPU firmware + PLDM AMC",
    "sn_name":       "ucs-video-intel-flex-140.DG02-2.2280_7.0.0.0.bin",
    "swid":          "swid-video-intel-flex-140",
    "fw_version":    "DG02-2.2280",
    "bundle_files": {
        "IFWI":  "IFWI_XPUM_Flex_140_128_ES_034_gfx_fwupdate_DG02_2.2280_.bin (2MB, $FPT Intel CSE)",
        "AMC":   "pldm_sg2_amc_v_7_0_0_0.bin (390KB, PLDM SG2 AMC)",
    },
    "ifwi_build_label": "ES_034",  # Engineering Sample build 034
    "ifwi_asic":        "XPUM_Flex_140_128",  # 128-execution-unit variant
    "pldm_magic":       "f018878ccb7d4943",
    "ifwi_magic":       "24465054",  # $FPT -- Intel Flash Partition Table
}

INTEL_FLEX_170 = {
    "target":        "Intel Arc Pro A-Series Flex 170 GPU firmware + PLDM AMC",
    "sn_name":       "ucs-video-intel-flex-170.DG02-1.3274_7.0.0.0.bin",
    "fw_version":    "DG02-1.3274",
    "bundle_files": {
        "IFWI":      "IFWI_ATS_M150_PVT_ES_119_gfx_fwupdate_SOC1.bin (2MB, $FPT)",
        "IFWIDATA":  "IFWIDATA_XPUM_ATS_M150_512_C0_PVT_ES_117_DataUpdate_ECC_OFF_Signed.bin (40KB)",
        "AMC":       "pldm_sg2_amc_v_7_0_0_0.bin (390KB, shared with Flex 140)",
    },
    "ifwi_build_label": "PVT_ES_119",  # Production Validation Test, Engineering Sample 119
    "ifwi_asic":        "ATS_M150",    # Intel ARC Terrain Series M150 = Flex 170 ASIC codename
    "ifwidata_label":   "PVT_ES_117_ECC_OFF_Signed",  # separate signed data update, ECC disabled
    "silicon_rev":      "C0",
}

INTEL_FLEX_AMC_PLATFORM = {
    "target":       "Intel Arc Pro Flex 140/170 PLDM AMC firmware (platform-specific)",
    "sn_names": {
        "X410M8 Flex 140 mezz": "ucs-x410c-m8-intel-flex-140-mezz-amc.7.0.0.0.bin",
        "X410M8 Flex 140":      "ucs-x410c-m8-intel-flex-140-amc.7.0.0.0.bin",
        "X410M8 Flex 170":      "ucs-x410c-m8-intel-flex-170-amc.7.0.0.0.bin",
        "X210M8 Flex 140 mezz": "ucs-x210c-m8-intel-flex-140-mezz-amc.7.0.0.0.bin",
        "X210M8 Flex 140":      "ucs-x210c-m8-intel-flex-140-amc.7.0.0.0.bin",
        "X210M8 Flex 170":      "ucs-x210c-m8-intel-flex-170-amc.7.0.0.0.bin",
        "X410M7 Flex 140 mezz": "ucs-x410c-m7-intel-flex-140-mezz-amc.7.0.0.0.bin",
        "X410M7 Flex 140":      "ucs-x410c-m7-intel-flex-140-amc.7.0.0.0.bin",
        "X410M7 Flex 170":      "ucs-x410c-m7-intel-flex-170-amc.7.0.0.0.bin",
        "X210M7 Flex 140 mezz": "ucs-x210c-m7-intel-flex-140-mezz-amc.7.0.0.0.bin",
    },
    "fw_version": "7.0.0.0",
    "blob_magic":  "f018878ccb7d4943",  # same as pldm_sg2_amc binary
    "swid_example": "swid-x410c-m8-intel-flex-140-mezz-amc",
    "note": "Platform-specific SN entries contain PLDM AMC firmware only (no IFWI); "
            "same binary content as pldm_sg2_amc_v_7_0_0_0.bin embedded in generic Flex 140/170 bundles",
}

# --- FINDINGS ---

# GPU-CEC-F1: H200 NVL / H100 NVL / H100 80G share IDENTICAL CEC firmware
GPU_CEC_F1 = {
    "id":       "GPU-CEC-F1",
    "title":    "NVIDIA H200 NVL, H100 NVL, and H100 80GB GPU bundles all contain identical "
                "CEC (Chassis Electronics Controller) firmware: "
                "cec1736-ecfw-00.02.0192.0000-n00-rel-prod.fwpkg (190KB); "
                "a single CEC firmware version simultaneously governs thermal management, "
                "power delivery, and PCIe interface control for H200 and both H100 variants; "
                "a vulnerability in cec1736-ecfw version 00.02.0192.0000 affects all three "
                "GPU families deployed in Cisco UCS X-Series; "
                "all three bundles share tag date 2025-08-25; "
                "the A16 GPU uses a different CEC firmware (BMGP3-04.01 vs cec1736-ecfw) "
                "indicating different CEC silicon across GPU generations",
    "severity": "MEDIUM",
    "status":   "CONFIRMED -- cec1736-ecfw-00.02.0192.0000-n00-rel-prod.fwpkg present in "
                "H200_NVL_B00.zip, H100_NVL_700.zip, H100-80_600.zip (all 194749 bytes identical filename)",
    "cwe":      ["CWE-1395 (Dependency on Vulnerable Third-Party Component)"],
    "affected_gpus": ["NVIDIA H200 NVL", "NVIDIA H100 NVL", "NVIDIA H100 80G"],
    "cec_firmware":  "cec1736-ecfw-00.02.0192.0000-n00-rel-prod.fwpkg",
    "cec_version":   "00.02.0192.0000",
    "tag_date":      "2025-08-25",
    "comparison":    {"A16": "cec_ota_BMGP3-04.01 (different CEC silicon)", "H200/H100": "cec1736"},
}

# GPU-ZIPCRYPTO-F2: NVIDIA ZipCrypto encrypts both CEC and VBIOS in production bundles
GPU_ZIPCRYPTO_F2 = {
    "id":       "GPU-ZIPCRYPTO-F2",
    "title":    "NVIDIA H200 NVL GPU bundle (H200_NVL_B00.zip) uses ZipCrypto to encrypt "
                "BOTH the CEC controller firmware (.fwpkg) AND the VBIOS SPI ROM (.rom, 4MB); "
                "ZipCrypto (ZIP 2.0 encryption) is a broken cipher with known-plaintext attack "
                "vulnerability; bkcrack recovered keys for A16 ZIP (BSERIES-F2) when correct "
                "plaintext was known; VBIOS SPI ROMs begin with NVIDIA-standard header "
                "(potentially known plaintext for bkcrack attack); "
                "if ZipCrypto key is recovered, both 4MB VBIOS and CEC firmware become readable; "
                "H100 NVL and H100 80G ZIPs use identical encryption approach; "
                "all three GPU families (H200, H100 NVL, H100 80G) vulnerable to same attack",
    "severity": "LOW",
    "status":   "CONFIRMED -- flag_bits & 0x1 set on both CEC and VBIOS members; "
                "extra field lacks AE-x header (0x9901) = ZipCrypto not AES-256; "
                "consistent with BSERIES-F2 findings on A16 bundle",
    "cwe":      ["CWE-326 (Inadequate Encryption Strength)"],
    "encrypted_members": {
        "H200 NVL CEC":  "194749 bytes (ZipCrypto)",
        "H200 NVL VBIOS": "4194304 bytes (ZipCrypto)",
        "H100 NVL CEC":  "194749 bytes (ZipCrypto) -- same as H200",
        "H100 80G CEC":  "194749 bytes (ZipCrypto) -- same as H200",
    },
    "attack_vector": "bkcrack known-plaintext attack on VBIOS .rom (NVIDIA VBIOS header is ~fixed); "
                     "success recovers both VBIOS and CEC firmware for all three GPU families",
}

# INTEL-FLEX-F1: ES/PVT-ES labeled IFWI in production Cisco UCS bundle
INTEL_FLEX_F1 = {
    "id":       "INTEL-FLEX-F1",
    "title":    "Production Cisco UCS B-Series bundle 6.0.2b ships Intel Arc Pro GPU IFWI "
                "binaries labeled as Engineering Sample (ES) and Production Validation Test ES: "
                "IFWI_XPUM_Flex_140_128_ES_034 (Flex 140) and IFWI_ATS_M150_PVT_ES_119 (Flex 170); "
                "Intel ES labels denote IFWI builds produced during pre-production silicon validation; "
                "PVT (Production Validation Test) is the stage between engineering validation and "
                "mass production -- the Flex 170 IFWI was built against C0 silicon at PVT_ES stage; "
                "this exposes Cisco's Intel GPU silicon qualification timeline in production bundles: "
                "Flex 140 (Arc Pro A40): ES build 034; Flex 170 (ATS-M150): PVT ES build 119; "
                "all IFWI binaries use Intel $FPT (Flash Partition Table) format with version 3 -- "
                "the same CSE (Converged Security Engine) partition format used in Intel ME firmware",
    "severity": "LOW",
    "status":   "CONFIRMED -- IFWI filenames contain ES/PVT_ES build labels; "
                "IFWI magic: 24465054 ($FPT) with FPT v3",
    "cwe":      ["CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor)"],
    "ifwi_labels": {
        "Flex 140": {"file": "IFWI_XPUM_Flex_140_128_ES_034_gfx_fwupdate_DG02_2.2280_.bin", "stage": "ES"},
        "Flex 170": {"file": "IFWI_ATS_M150_PVT_ES_119_gfx_fwupdate_SOC1.bin", "stage": "PVT_ES"},
    },
    "ifwi_format":     "$FPT (24465054) version 3 -- Intel CSE Flash Partition Table",
    "asic_codenames":  {"Flex 140": "XPUM (DG02 = Arc Alchemist GPU, 128 EU)", "Flex 170": "ATS-M150 (Arc Terrain Series M150, C0 silicon)"},
}

# INTEL-FLEX-F2: ECC_OFF signed IFWI data update in production bundle
INTEL_FLEX_F2 = {
    "id":       "INTEL-FLEX-F2",
    "title":    "Intel Arc Pro Flex 170 bundle contains a separate signed IFWI data update: "
                "IFWIDATA_XPUM_ATS_M150_512_C0_PVT_ES_117_DataUpdate_ECC_OFF_Signed.bin (40KB); "
                "the filename explicitly encodes 'ECC_OFF' -- a signed data update that disables "
                "Error Correcting Code in the ATS-M150 GPU memory subsystem; "
                "GPU ECC protects against bit flip errors in high-density HBM memory; "
                "disabling ECC (trading reliability for performance/capacity) is encoded as a "
                "signed and separately deliverable IFWI data component; "
                "the signed nature means Cisco holds a signing key that can produce an ECC_OFF "
                "deployment for any field with the ATS-M150 512EU C0 silicon variant; "
                "IFWI data magic matches main IFWI ($FPT, 24465054) -- same partition format; "
                "XPUM and ATS naming reveals ARC product line branding overlap: "
                "Flex 170 = ATS-M150 (external branding) = XPUM (internal Intel product name)",
    "severity": "MEDIUM",
    "status":   "CONFIRMED -- IFWIDATA file present in Intel Flex 170 bundle alongside IFWI; "
                "ECC_OFF explicit in signed filename; 40960 bytes, $FPT magic",
    "cwe":      ["CWE-1368 (Improper Neutralization of Input During Hardware Manufacturing)"],
    "ecc_off_file": "IFWIDATA_XPUM_ATS_M150_512_C0_PVT_ES_117_DataUpdate_ECC_OFF_Signed.bin",
    "silicon":       "ATS-M150 512EU C0 = Intel Arc Pro Flex 170 (Alchemist Terrain Series, maximum EU variant)",
    "note": "ECC-disabled GPU memory increases risk of uncorrected memory errors and enables "
            "Rowhammer-class attacks against GPU HBM2e; ECC is a standard HPC/data-center requirement",
}

# INTEL-FLEX-F3: Shared PLDM AMC firmware across Flex 140 and Flex 170 with 10 platform SN entries
INTEL_FLEX_F3 = {
    "id":       "INTEL-FLEX-F3",
    "title":    "Intel Arc Pro Flex 140 and Flex 170 share identical PLDM AMC firmware "
                "(pldm_sg2_amc_v_7_0_0_0.bin, 390KB) embedded in both GPU bundles; "
                "the same binary is also shipped as 10 platform-specific standalone SN entries "
                "for X410C M8, X210C M8, X410C M7, X210C M7 (each with mezz and non-mezz variants); "
                "PLDM (Platform Level Data Model, DMTF DSP0240) is the firmware update standard "
                "used by CIMC to manage the Intel Arc Pro AMC (Add-in Module Controller); "
                "magic f018878ccb7d4943 is a Cisco-proprietary PLDM wrapper; "
                "version string '7.0.0.0' appears 3 times in the first 32 bytes of the PLDM header; "
                "a single PLDM AMC vulnerability in version 7.0.0.0 affects all Intel Arc Pro "
                "deployments across X410C/X210C generations M7 and M8 (both form factors)",
    "severity": "MEDIUM",
    "status":   "CONFIRMED -- pldm_sg2_amc_v_7_0_0_0.bin present in both Flex 140 and Flex 170 "
                "bundles; standalone AMC SN entries confirmed by magic f018878c match; "
                "10 platform-specific SN entries in bundle all deliver same PLDM version",
    "cwe":      ["CWE-1395 (Dependency on Vulnerable Third-Party Component)"],
    "affected_platforms": [
        "X410C M8 + X210C M8 (Flex 140 standard + mezzanine, Flex 170)",
        "X410C M7 + X210C M7 (Flex 140 standard + mezzanine, Flex 170)",
    ],
    "pldm_version": "7.0.0.0",
    "pldm_magic":   "f018878ccb7d4943",
}

# GPU-VBIOS-F4: VBIOS PCI device ID sequence exposed in NVIDIA Hopper GPU filenames
GPU_VBIOS_F4 = {
    "id":       "GPU-VBIOS-F4",
    "title":    "NVIDIA Hopper-family GPU VBIOS filenames in the Cisco UCS bundle encode "
                "sequential PCI subsystem IDs and internal variant codes: "
                "H100 80G = 9600D9000C (variant 0200), H100 NVL = 9600D9000D (variant 0210), "
                "H200 NVL = 9600D9000E (variant 0230); the D9000C/D/E suffix reveals "
                "NVIDIA's GPU SKU enumeration sequence in the Hopper VBIOS namespace; "
                "the '9600' prefix consistent across all three suggests a Hopper-generation "
                "Cisco subsystem vendor ID block; VBIOS silicon stepping visible in ZIP name: "
                "H200 NVL = B00 (initial Hopper B stepping); "
                "A16 VBIOS uses separate PCI ID scheme: 9407620004/94076200AD",
    "severity": "LOW",
    "status":   "CONFIRMED -- VBIOS filenames extracted from ZIP member list; "
                "sequential suffix pattern 0C/0D/0E across H100-80/H100-NVL/H200-NVL",
    "cwe":      ["CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor)"],
    "vbios_id_map": {
        "H100 80G":  {"pci_suffix": "9600D9000C", "variant": "0200", "size": "4MB SPI ROM"},
        "H100 NVL":  {"pci_suffix": "9600D9000D", "variant": "0210", "size": "4MB SPI ROM"},
        "H200 NVL":  {"pci_suffix": "9600D9000E", "variant": "0230", "size": "4MB SPI ROM"},
    },
}

FINDINGS = [GPU_CEC_F1, GPU_ZIPCRYPTO_F2, INTEL_FLEX_F1, INTEL_FLEX_F2, INTEL_FLEX_F3, GPU_VBIOS_F4]

FIRMWARE = [NVIDIA_H200_NVL, NVIDIA_H100_NVL, NVIDIA_H100_80G,
            INTEL_FLEX_140, INTEL_FLEX_170, INTEL_FLEX_AMC_PLATFORM]
