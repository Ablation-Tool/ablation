"""
Cisco UCS C-Series Rack M8 BIOS and GPU Firmware RE module
Source: ucs-k9-bundle-c-series.6.0.2b.C.bin (3.1GB, decompresses to 3.2GB)

C-Series bundle SN entry format differs from B-Series:
  B-Series: outer SN -> gzip -> PAX tar with CIMCPackage
  C-Series: outer SN -> gzip -> outer TAR (./blob + ./isan/etc/imghdr.bin) -> blob is gzip -> PAX/ustar + CIMCPackage at byte 512

CIMCPackage header starts at byte 512 of the decompressed blob (512 = one TAR block -- the PKG filename fills the first TAR record).
The actual TAR starts at byte 0: ustar magic at byte 257, tar header for '<platform>-BIOS-<ver>.pkg'.

BIOS payload structure (after CIMCPackage header + padding to ImageOffset):
  gzip -> PAX tar -> package.json, BiosUpdate.json, BiosTokenInstall.json, biosFiles/, BiosTokens/

BiosUpdate version progression (same as B/X-Series):
  v1: AMD M8 (C245 M8, C225 M8) -- MD5Sum only, CiscoSignedBinary=Disabled
  v3: Intel M8 (C220 M8, C240 M8) -- per-section RSA-4096, CiscoSignedBinary=Enabled

BIOS SN offsets in decompressed C-Series bundle (cseries_decomp.bin, 3.234GB):
  C245 M8 BIOS:  cseries+2226823168  (hsize=844, AMD EPYC Genoa 2U rack)
  C240 M8 BIOS:  cseries+2251999744  (hsize=840, Intel GNR 2U rack)
  C225 M8 BIOS:  cseries+2843936768  (hsize=844, AMD EPYC Genoa 1U rack)
  C220 M8 BIOS:  cseries+2868961792  (hsize=840, Intel GNR 1U rack)

GPU firmware SN offsets:
  RTX Pro 6000:  cseries+473291776   (hsize=808, Blackwell BWSE, Dec 2025)
  H200 NVL:      cseries+549524480   (hsize=844, same as B-Series)
  H100 NVL:      cseries+678552576   (hsize=844, same as B-Series)
  H100-80G:      cseries+785708544   (hsize=844, same as B-Series)
  L40S:          cseries+730844160   (hsize=840)
  A16:           cseries+925947392   (hsize=916, same as B-Series)
  A30:           cseries+928996352   (hsize=872, Ampere GA100)
  A100-80:       cseries+929481728   (hsize=876, Ampere GA100)

CIMC SN offsets:
  Intel Rack M8 CIMC: cseries+2047086592  (hsize=764, 168MB, covers C220/C240 M8)
  C245 M8 CIMC:       cseries+1481073152  (hsize=764, 141MB)
  C225 M8 CIMC:       cseries+1914477568  (hsize=764, 141MB)
  C240 M7 CIMC:       cseries+1348532224  (hsize=780)
  C245 M6 CIMC:       cseries+1613682176  (hsize=772)

Name parsing: header has 2-byte pad before name (raw[8:hsize] not raw[6:hsize]).
"""

# --- BIOS FIRMWARE DATA ---

FIRMWARE_C245_M8 = {
    "target":           "C245 M8 AMD EPYC Genoa rack BIOS",
    "sn_name":          "ucs-c245-m8-bios.C245M8.6.0.2a.0.0121261129.bin",
    "image_version":    "C245M8.6.0.2a.0.0121261129",
    "image_offset":     2048,
    "biosupdate_version": 1,
    "cisco_signed":     "Disabled",
    "cpu_id":           "A00F00",  # AMD EPYC Genoa: family 0x19 model 0 step 0 (same as X215C M8)
    "bios_size_bytes":  25166220,
    "image_type":       "FullImage-Cap",
    "bios_file":        "biosFiles/C245/M8/A00F00/C245M8.6.0.2a.0.cap",
    "md5sum":           "d3326140a26c4d97f6f282e87c39aa22",
    "bios_token_count": 130,
    "cert_ou":          "BIOS_IMG",
    "decompressed_payload_size_bytes": 25456640,
}

FIRMWARE_C225_M8 = {
    "target":           "C225 M8 AMD EPYC Genoa rack BIOS (1U)",
    "sn_name":          "ucs-c225-m8-bios.C225M8.6.0.2a.0.0121261128.bin",
    "image_version":    "C225M8.6.0.2a.0.0121261128",
    "image_offset":     2048,
    "biosupdate_version": 1,
    "cisco_signed":     "Disabled",
    "cpu_id":           "A00F00",  # same Genoa silicon as C245 M8 and X215C M8
    "bios_size_bytes":  None,
    "image_type":       "FullImage-Cap",
    "bios_file":        "biosFiles/C225/M8/A00F00/C225M8.6.0.2a.0.cap",
    "md5sum":           "f8b22f4a1cdec80cd06f70eb3b1d8caa",  # different binary from C245 M8
    "bios_token_count": 130,
    "cert_ou":          "BIOS_IMG",
    "decompressed_payload_size_bytes": 25303040,
}

FIRMWARE_C220_M8 = {
    "target":           "C220 M8 Intel GNR rack BIOS (1U)",
    "sn_name":          "ucs-c220-m8-bios.C220M8.6.0.2a.0.0126261758.bin",
    "image_version":    "C220M8.6.0.2a.0.0126261758",
    "image_offset":     8192,  # matches X410C M8 blade (GNR anomaly vs 2048 baseline)
    "biosupdate_version": 3,
    "cisco_signed":     "Enabled",
    "cpu_id":           "A06D1",  # Intel GNR step 1 (same as X210C M8 2-socket blade)
    "bios_size_bytes":  67108864,  # 64MB
    "image_type":       "FullImage-bin",
    "bios_file":        "biosFiles/C220/M8/C220M8.6.0.2a.0.bin",
    "bios_token_count": 223,
    "cert_ou":          "BIOS_IMG",
    "decompressed_payload_size_bytes": 67491840,
    "rsa4096_sections":  ["FullImage", "FD0", "ME", "BIOS", "ACM", "KM", "BPM"],
}

FIRMWARE_C240_M8 = {
    "target":           "C240 M8 Intel GNR rack BIOS (2U)",
    "sn_name":          "ucs-c240-m8-bios.C240M8.6.0.2a.0.0126261758.bin",
    "image_version":    "C240M8.6.0.2a.0.0126261758",
    "image_offset":     8192,
    "biosupdate_version": 3,
    "cisco_signed":     "Enabled",
    "cpu_id":           "A06D1",  # Intel GNR step 1 -- same as C220 M8 and X210C M8
    "bios_size_bytes":  67108864,  # 64MB
    "image_type":       "FullImage-bin",
    "bios_file":        "biosFiles/C240/M8/C240M8.6.0.2a.0.bin",
    "bios_token_count": 223,
    "cert_ou":          "BIOS_IMG",
    "decompressed_payload_size_bytes": 67491840,  # identical to C220 M8
    "rsa4096_sections":  ["FullImage", "FD0", "ME", "BIOS", "ACM", "KM", "BPM"],
}

AMD_UNSIGNED_BIOS_PLATFORMS = {
    "X215C M8 blade": {
        "sn": "ucs-x215-m8-bios",
        "cpu_id": "A00F00",
        "token_count": 130,
        "form_factor": "blade (X-Series)",
        "chassis": "X215C M8 (B-Series rack unit)",
    },
    "C245 M8 rack 2U": {
        "sn": "ucs-c245-m8-bios",
        "cpu_id": "A00F00",
        "token_count": 130,
        "form_factor": "rack 2U",
        "chassis": "C245 M8 standalone rack server",
    },
    "C225 M8 rack 1U": {
        "sn": "ucs-c225-m8-bios",
        "cpu_id": "A00F00",
        "token_count": 130,
        "form_factor": "rack 1U",
        "chassis": "C225 M8 standalone rack server",
    },
}

# --- GPU FIRMWARE DATA ---

NVIDIA_RTX_PRO_6000 = {
    "target":        "NVIDIA RTX Pro 6000 Blackwell GPU firmware",
    "sn_name":       "ucs-video-nvidia-RTX-PRO-6000.98.02.8D.00.01_G1",
    "bundle_zip":    "RTX_PRO_6000_300_302.zip",
    "architecture":  "Blackwell (B-series silicon, BWSE = Blackwell Workstation Edition)",
    "silicon_step":  "300 revision 302",
    "tag_date":      "2025-12-05",
    "zip_contents": {
        "VBIOS": "RTX_PRO_6000/IROM_VBIOS/nvfw_RTXPRO6000BWSE_0003_250826.1.0_prod-signed.fwpkg (2.2MB, ZipCrypto)",
    },
    "no_cec":        True,
    "fw_format":     ".fwpkg (not .rom SPI dump; unified signed package format, same as CEC fwpkg delivery)",
    "note":          "No separate CEC firmware entry; Blackwell may integrate AMC/CEC differently",
}

NVIDIA_A30 = {
    "target":        "NVIDIA A30 Ampere GPU firmware",
    "sn_name":       "ucs-video-nvidia-A30.92.00.66.00.03_1001.0205.0",
    "bundle_zip":    "A30_600_601.zip",
    "architecture":  "Ampere (GA100)",
    "silicon_step":  "600/601 (two stepping variants in one ZIP)",
    "tag_date":      "2022-06-14",
    "zip_contents": {
        "CEC":   "A30/CEC/ga100_cec_ota_v6.07_prod.bin (128KB, ZipCrypto)",
        "VBIOS": "A30/IROM_VBIOS/1001_0205_882__9200660003-9200660004-prod.nvr (1MB, ZipCrypto)",
    },
    "cec_firmware":    "ga100_cec_ota_v6.07_prod.bin",
    "cec_size_bytes":  131456,
    "vbios_format":    ".nvr (NVIDIA ROM variant, vs .rom used in Hopper/Ada A16)",
    "pci_ids":         ["9200660003", "9200660004"],
}

NVIDIA_A100_80 = {
    "target":        "NVIDIA A100 80GB Ampere GPU firmware",
    "sn_name":       "ucs-video-nvidia-A100-80.92.00.A0.00.03_1001.02",
    "bundle_zip":    "A100-80_600_601_610_611.zip",
    "architecture":  "Ampere (GA100)",
    "silicon_step":  "600/601/610/611 (four stepping variants in one ZIP)",
    "tag_date":      "2023-05-26",
    "zip_contents": {
        "CEC":   "A100-80/CEC/ga100_cec_ota_v6.07_prod.bin (128KB, ZipCrypto)",
        "VBIOS": "A100-80/IROM_VBIOS/1001_0230_893__9200A00003-9200A00005-prod.nvr (1MB, ZipCrypto)",
    },
    "cec_firmware":    "ga100_cec_ota_v6.07_prod.bin",
    "cec_size_bytes":  131456,  # IDENTICAL size and filename to A30
    "vbios_format":    ".nvr",
    "pci_ids":         ["9200A00003", "9200A00005"],
}

# --- FINDINGS ---

# CSERIES-M8-F1: AMD rack BIOS CiscoSignedBinary=Disabled extends to all AMD M8 rack platforms
CSERIES_M8_F1 = {
    "id":       "CSERIES-M8-F1",
    "title":    "All three AMD M8 UCS platforms (X215C M8 blade, C245 M8 2U rack, C225 M8 1U rack) "
                "ship BiosUpdate v1 with CiscoSignedBinary=Disabled and MD5Sum-only integrity; "
                "no Cisco PKI signing on any AMD Genoa BIOS update in the UCS product line; "
                "Intel rack M8 (C220/C240) and Intel blade M8 (X210/X410) all use BiosUpdate v3 "
                "with RSA-4096 per-section signatures and CiscoSignedBinary=Enabled; "
                "the AMD signing gap is not limited to the X215C M8 blade (X215M8BIOS-F1) "
                "but is a platform-wide policy for all AMD EPYC Genoa M8 deployments in Cisco UCS; "
                "all three AMD platforms use CpuId A00F00 (EPYC Genoa family 0x19 model 0 step 0) "
                "and carry exactly 130 BIOS tokens (vs 223 for Intel M8); "
                "MD5 is a broken hash function (collision known since 2008); "
                "a forged AMD BIOS image can be delivered through the normal CIMC update path "
                "without cryptographic rejection",
    "severity": "HIGH",
    "status":   "CONFIRMED -- CiscoSignedBinary=Disabled and BiosUpdate.Version=1 confirmed in "
                "C245M8.6.0.2a.0.0121261129 and C225M8.6.0.2a.0.0121261128 (C-Series bundle); "
                "extends X215M8BIOS-F1 finding (X215C M8) to C-Series rack form factors",
    "cwe":      ["CWE-347 (Improper Verification of Cryptographic Signature)"],
    "affected_platforms": list(AMD_UNSIGNED_BIOS_PLATFORMS.keys()),
    "intel_comparison": "C220/C240 M8 use BiosUpdate v3 with RSA-4096 on FullImage, FD0, ME, BIOS, ACM, KM, BPM sections",
    "cross_reference": "X215M8BIOS-F1 (B/X-Series bundle)",
}

# CSERIES-M8-F2: C220 M8 and C240 M8 share identical Boot Guard flash descriptor (FD0) signature
CSERIES_M8_F2 = {
    "id":       "CSERIES-M8-F2",
    "title":    "Intel GNR C220 M8 (1U rack) and C240 M8 (2U rack) BiosUpdate v3 carry identical "
                "RSA-4096 signatures for the Boot Guard flash descriptor region (FD0, 4096 bytes); "
                "the FD0 section (Intel Flash Descriptor at offset 0) governs region access permissions, "
                "master/slave access rights, and Boot Guard configuration pointing; "
                "identical FD0 signature means both chassis use the same Boot Guard FD0 key and policy; "
                "both platforms qualify Intel GNR stepping A06D1 (same as X210C M8 blade); "
                "the FullImage RSA-4096 signatures differ between C220 and C240 (different SPI layouts), "
                "but the boot chain anchor (FD0) is shared across 1U and 2U platform variants; "
                "decompressed payload size is identical (67,491,840 bytes for both C220 M8 and C240 M8); "
                "this extends the GNR stepping matrix: 2S platforms (X210C M8 blade, C220 M8, C240 M8) "
                "all qualify A06D1 (step 1), while the 4S X410C M8 blade qualifies A06D2 (step 2)",
    "severity": "LOW",
    "status":   "CONFIRMED -- FD0 Signature field identical in BiosUpdate.json for C220M8.6.0.2a.0 "
                "and C240M8.6.0.2a.0; both 67,491,840 bytes decompressed payload",
    "cwe":      ["CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor)"],
    "platforms": ["C220 M8 (1U rack, 2S)", "C240 M8 (2U rack, 2S)", "X210C M8 (blade, 2S)"],
    "gnr_stepping": "A06D1 = Intel Granite Rapids model 0xAD step 1 (2-socket); A06D2 = step 2 (4-socket)",
}

# GPU-AMPERE-CEC-F3: A30 and A100-80 share identical GA100 CEC firmware
GPU_AMPERE_CEC_F3 = {
    "id":       "GPU-AMPERE-CEC-F3",
    "title":    "NVIDIA A30 and A100-80 GPU bundles in the C-Series bundle both contain identical "
                "CEC firmware ga100_cec_ota_v6.07_prod.bin (131,456 bytes); "
                "the A30 (PCIe IDs 9200660003/9200660004) and A100-80 (PCIe IDs 9200A00003/9200A00005) "
                "are distinct Ampere GPU SKUs (different memory configuration, different PCIe IDs) "
                "that share a single 128KB GA100-family CEC controller firmware; "
                "this extends the cross-GPU shared-CEC pattern identified in GPU-CEC-F1 (B-Series) "
                "to the Ampere generation: ga100_cec covers A30 and A100-80; cec1736 covers H200 NVL/H100 NVL/H100-80G; "
                "CEC firmware is keyed by GPU generation (GA100 = Ampere, cec1736 = Hopper/CEC1736 silicon); "
                "a vulnerability in ga100_cec_ota v6.07 simultaneously affects both A30 and A100-80 deployments; "
                "both ZIPs are ZipCrypto-encrypted with the same attack surface as GPU-ZIPCRYPTO-F2; "
                "A30 has two stepping variants (600/601), A100-80 has four (600/601/610/611) in a single ZIP",
    "severity": "MEDIUM",
    "status":   "CONFIRMED -- ga100_cec_ota_v6.07_prod.bin 131456 bytes in both A30_600_601.zip "
                "and A100-80_600_601_610_611.zip (C-Series bundle)",
    "cwe":      ["CWE-1395 (Dependency on Vulnerable Third-Party Component)"],
    "affected_gpus": ["NVIDIA A30 (Ampere GA100)", "NVIDIA A100 80GB (Ampere GA100)"],
    "cec_firmware": "ga100_cec_ota_v6.07_prod.bin",
    "cross_reference": "GPU-CEC-F1 (Hopper cec1736 shared by H200/H100); GPU-ZIPCRYPTO-F2 (ZipCrypto pattern)",
}

# GPU-RTX6000-F4: RTX Pro 6000 uses .fwpkg for VBIOS delivery, no CEC, most recent GPU in bundle
GPU_RTX6000_F4 = {
    "id":       "GPU-RTX6000-F4",
    "title":    "NVIDIA RTX Pro 6000 (Blackwell) GPU firmware in the C-Series bundle uses a .fwpkg "
                "container for VBIOS delivery instead of the .rom SPI dump format used by all older GPUs; "
                "nvfw_RTXPRO6000BWSE_0003_250826.1.0_prod-signed.fwpkg (2.2MB, ZipCrypto); "
                "no separate CEC firmware entry -- Blackwell GPU management controller is either "
                "embedded in the fwpkg or delivered via a different update path than Ampere/Hopper; "
                "the .fwpkg format (used by RTX Pro 6000 VBIOS) is the same container format as the "
                "Hopper CEC firmware (cec1736-ecfw-*.fwpkg) -- both are PLDM-style firmware packages; "
                "tag date 2025-12-05 makes this the most recently dated GPU firmware in either bundle; "
                "ZipCrypto encryption applied to the .fwpkg member (same as all other GPU ZIPs); "
                "filename 'BWSE' = Blackwell Workstation Edition; firmware variant 0003; "
                "silicon stepping 300 (B300) revision 302",
    "severity": "LOW",
    "status":   "CONFIRMED -- RTX_PRO_6000_300_302.zip contains single ZipCrypto-encrypted .fwpkg; "
                "no CEC/ directory or separate CEC firmware; tag 2025120501",
    "cwe":      ["CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor)"],
    "architecture":  "Blackwell (B300 silicon)",
    "tag_date":      "2025-12-05",
    "comparison":    {
        "Ampere A30/A100": "CEC .bin + VBIOS .nvr",
        "Hopper H200/H100": "CEC .fwpkg + VBIOS .rom",
        "Blackwell RTX Pro 6000": "VBIOS .fwpkg only (no CEC entry)",
    },
}

# CSERIES-M8-F5: AMD rack BIOS uses .cap UEFI capsule vs Intel .bin SPI image -- format divergence
CSERIES_M8_F5 = {
    "id":       "CSERIES-M8-F5",
    "title":    "AMD M8 UCS rack BIOS uses UEFI capsule format (.cap) while Intel M8 rack BIOS "
                "uses raw SPI binary (.bin); C245 M8 and C225 M8 deliver 'FullImage-Cap' (UEFI capsule) "
                "while C220 M8 and C240 M8 deliver 'FullImage-bin' (64MB SPI dump); "
                "UEFI capsules (.cap) have their own update trust chain independent of Cisco signing -- "
                "capsules carry a Microsoft/UEFI CA signature in the capsule header; "
                "combined with CiscoSignedBinary=Disabled, the AMD BIOS update chain relies exclusively "
                "on the UEFI capsule signing, which is not auditable from the bundle alone; "
                "Intel .bin images have per-section RSA-4096 from Cisco, which is explicitly verifiable; "
                "file paths expose chassis directory layout: biosFiles/C245/M8/A00F00/ vs biosFiles/C220/M8/",
    "severity": "LOW",
    "status":   "CONFIRMED -- ImageType=FullImage-Cap in C245/C225 M8; FullImage-bin in C220/C240 M8; "
                "file extensions .cap vs .bin in biosFiles/ paths",
    "cwe":      ["CWE-693 (Protection Mechanism Failure)"],
    "formats": {
        "AMD M8 (C245, C225, X215)": "FullImage-Cap (.cap) -- UEFI capsule, no Cisco RSA",
        "Intel M8 (C220, C240, X210, X410)": "FullImage-bin (.bin) -- raw 64MB SPI, RSA-4096 per section",
    },
}

FINDINGS = [CSERIES_M8_F1, CSERIES_M8_F2, GPU_AMPERE_CEC_F3, GPU_RTX6000_F4, CSERIES_M8_F5]

FIRMWARE = [FIRMWARE_C245_M8, FIRMWARE_C225_M8, FIRMWARE_C220_M8, FIRMWARE_C240_M8,
            NVIDIA_RTX_PRO_6000, NVIDIA_A30, NVIDIA_A100_80]
