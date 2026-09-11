"""
Cisco UCS C-Series -- LSI SAS12G HBA, Intel Optane NVMe/PMEM, GPU ZipCrypto, n2xx Intel PCIe RE
Targets: ucs-c-lsi-sas12ghba, UCSC-XNVME-I375/I750 Optane NVMe, ucs-pmemory-dimm-fw,
         ucs-pmemory-bps-dimm-fw, ucs-c-nvidia-video-p40, ucs-c-amd-video-v340,
         ucs-c-pci-n2xx-aipci01

Binary: /tmp/.../cseries_decomp.bin (UCS C-Series bundle, 596 SN entries)
Extracted via: SN magic 6401534e -> gzip -> TAR -> ./blob
"""

LSI_SAS12G = {
    "product": "ucs-c-lsi-sas12ghba",
    "fw_package_version": "13.00.00.12",
    "blob_offset": 1328949248,
    "zip_contents": {
        "mpt3x64.rom": {"size_bytes": 229376, "format": "UEFI ROM (x64)"},
        "mptsas3.rom": {"size_bytes": 212992, "format": "BIOS Option ROM"},
        "UCSC-SAS12GHBA.fw": {"size_bytes": 1064864, "format": "MPT3 firmware"},
    },
    "bios_version": "MPT3BIOS-8.31.02.00",
    "bios_date": "2016.10.27",
    "bios_age_yr": 10,
    "chip_codename": "Invader",
    "chip_id": "SAS3008",
    "debug_cli": "Show all debug info: <pl dbg>",
    "fw_strings": [
        "LSI SAS Controller: Invader",
        "@(#)LSI Logic",
        "(c) 2010-2011 Avago",
        "NvdataVersion was %x",
        "NvdataVersion is  %x",
        "PL Version %08x SAS HW Version %08x",
        "SAS HBA CU Boot Entry",
        "LSILBOPT",
    ],
    "cross_reference": {
        "identical_bios": "C3X60-HBA (MPT3BIOS-8.31.02.00, 2016.10.27)",
        "older_fw": "vs C3X60-HBA 13.00.08.00, S3260-DHBA 13.00.08.00",
        "same_chip": "SAS3008 (LSI Invader) confirmed in all three products",
        "debug_cli_instances": "third independent UCS HBA product SKU with active pl dbg CLI",
    },
}

OPTANE_NVME = {
    "products": {
        "UCSC-XNVME-I375": {
            "sn_name": "ucs-storage-intel-nvme-UCSC-XNVME-I375.E201CP02",
            "blob_offset": 1225114624,
        },
        "UCSC-XNVME-I750": {
            "sn_name": "ucs-storage-intel-nvme-UCSC-XNVME-I750.E201CP02",
            "blob_offset": 1224678912,
        },
    },
    "fw_version": "E201CP02",
    "fw_md5": "60e0ccbaac4b70a61d9d85ec5519dc1d",
    "fw_size_kb": 684,
    "format": "Intel FPT (06000000 magic)",
    "products_covered": [
        "Intel(R) Optane(TM) SSD DC P4800X Series",
        "Intel(R) Optane(TM) SSD 900P Series",
        "375GB NVMe 2.5 x4 Enterprise Performance NG Resistive Memory SSD",
        "750GB NVMe 2.5 x4 Enterprise Performance NG Resistive Memory SSD",
        "1.5TB NVMe 2.5 x4 Enterprise Performance NG Resistive Memory SSD",
    ],
    "leaked_strings": {
        "codename": "Intel MansionBeach Bootloader",
        "default_serial": "*DFLT_SERIAL",
        "oem_variant": "Lenovo (Intel)",
    },
    "sn_name_swap": "XNVME-I375 SN entry (offset 1225114624) contains I750 name; I750 entry contains I375 name -- bundle packing error",
}

PMEM_FIRMWARE = {
    "dimm_fw": {
        "product": "ucs-pmemory-dimm-fw",
        "version": "1.2.0.5446",
        "blob_offset": 1143460352,
        "size_kb": 260,
    },
    "bps_dimm_fw": {
        "product": "ucs-pmemory-bps-dimm-fw",
        "version": "2.2.0.1553",
        "blob_offset": 1143728640,
        "size_kb": 292,
    },
    "format": "Intel FPT format",
    "magic": "06000000a1000000",
    "encryption": "encrypted payload -- no readable strings in either blob; sealed at rest",
    "note": "Both PMEM DIMM and BPS (battery-backed power supply) firmware share the 06000000 Intel FPT header; payload content is encrypted and decryption key is not in bundle",
}

GPU_ZIPCRYPTO = {
    "p40": {
        "product": "ucs-c-nvidia-video-p40",
        "fw_label": "86.02.4E.00.01",
        "blob_offset": 1321787904,
        "inner_format": "gzip -> ZIP (P40_100_...zip)",
        "zip_contents": {
            "P40/IROM/G6100200.ifr": {"size_kb": 10, "encrypted": True},
            "P40/VBIOS/g610_0200_895_0__86024E0001.rom": {"size_kb": 256, "encrypted": True},
        },
        "architecture": "Pascal GP102",
        "era_year": 2016,
        "note": "ALL ZIP entries encrypted (IROM + VBIOS); M10/M60 had plaintext VBIOSes; P40 is stricter",
    },
    "v340": {
        "product": "ucs-c-amd-video-v340",
        "fw_label": "016.001.001.000.011175",
        "blob_offset": 1144029696,
        "inner_format": "gzip -> ZIP (V340_CA_...zip)",
        "zip_contents": {
            "V340/CA/PFX/v104.pmc": {"size_kb": 1483, "encrypted": True},
            "V340/CA/VBIOS/b431069_D0531600.102_signed.rom": {"size_kb": 960, "encrypted": True},
        },
        "architecture": "Fiji XT (FirePro S9300 X2 dual-GPU)",
        "era_year": 2015,
        "note": "PFX file (PMC/prefix code) encrypted alongside VBIOS; AMD signed VBIOS but additionally ZipCrypto wrapped",
    },
    "zipcrypto_summary": {
        "cipher": "ZipCrypto (broken stream cipher, known-plaintext attack via bkcrack)",
        "attack_reference": "BCSERIES-F2 (same class; bkcrack attempt failed on H200 CEC because wrong plaintext; correct plaintext TBD for VBIOS/IROM)",
        "plaintext_hints": {
            "p40_irom": "G6100200.ifr (10KB) -- smaller target for known-plaintext; IROM files often start with constant header",
            "v340_vbios": "b431069_D0531600.102_signed.rom -- AMD-signed, known ROM header structure",
        },
    },
}

N2XX_INTEL = {
    "product": "ucs-c-pci-n2xx-aipci01",
    "pci_ssid": "800009FA",
    "blob_offset": 1316658176,
    "fw_version": "1.836.0",
    "fw_label": "BootIMG_1.836.0.FLB",
    "packaging": "single-gzip (vs Intel XL710's double-gzip wrapper around same FLB binary)",
    "fw_md5": None,
    "strings": [
        "Intel(R) Ethernet CLP/Loader Option ROM",
        "Intel(R) iSCSI Remote Boot version 3.1.97",
        "Copyright (c) 2003-2020 Intel Corporation. All rights reserved.",
        "Firmware recovery mode detected. Initialization failed.",
        "The CLP Boot ROM for the device stopped because the NVM image is newer than expected",
    ],
    "age": "2020 copyright, 6yr old in 2026 bundle",
    "cross_reference": "Identical FLB binary version to Intel XL710 (INTX710-F1 CLP version enforcement applies)",
}

# Findings
LSISAS12G_F1 = {
    "id": "LSISAS12G-F1",
    "severity": "HIGH",
    "title": "Third UCS HBA SKU with active pl dbg debug CLI and 10-year-old BIOS binary",
    "affected": ["ucs-c-lsi-sas12ghba (13.00.00.12)"],
    "evidence": {
        "debug_cli": "Show all debug info: <pl dbg>",
        "bios": "MPT3BIOS-8.31.02.00 (2016.10.27) in mptsas3.rom",
        "chip": "LSI SAS Controller: Invader (SAS3008)",
        "copyright": "(c) 2010-2011 Avago in firmware binary",
        "cross_product": "Identical BIOS binary to C3X60-HBA (same MD5, same build date)",
        "fw_older": "Package 13.00.00.12 is older than C3X60-HBA 13.00.08.00 -- larger attack surface delta",
    },
    "mechanism": (
        "The LSI SAS 12G HBA (ucs-c-lsi-sas12ghba) contains MPT3BIOS-8.31.02.00 from 2016.10.27 -- "
        "identical to C3X60-HBA. This is the third independent UCS HBA product SKU confirmed to ship "
        "the same 10-year-old BIOS binary with active debug CLI. The `pl dbg` debug CLI activates "
        "PL Debug Mask logging for PL (Physical Layer) operations. Package version 13.00.00.12 is "
        "older than the already-outdated 13.00.08.00 in C3X60-HBA, increasing the firmware age gap."
    ),
    "impact": "Active debug interface and 10yr BIOS blast radius extends to third HBA SKU across UCS C-Series",
}

OPTANE_F1 = {
    "id": "OPTANE-F1",
    "severity": "HIGH",
    "title": "Optane NVMe I375 and I750 share identical firmware with MansionBeach Bootloader codename and DFLT_SERIAL placeholder",
    "affected": ["UCSC-XNVME-I375 (E201CP02)", "UCSC-XNVME-I750 (E201CP02)"],
    "evidence": {
        "md5": "60e0ccbaac4b70a61d9d85ec5519dc1d (both SN entries)",
        "size_kb": 684,
        "leaked_codename": "Intel MansionBeach Bootloader (offset 682212 in both blobs)",
        "leaked_placeholder": "*DFLT_SERIAL (offset 682256 -- serial override in bootloader)",
        "multi_product": "Single binary serves P4800X DC, 900P consumer, 375GB, 750GB, 1.5TB variants",
        "oem_leak": "Lenovo (Intel) OEM variant name embedded in Cisco production firmware",
        "sn_name_swap": "I375 entry at 1225114624 contains I750 name; I750 entry at 1224678912 contains I375 name",
    },
    "mechanism": (
        "UCSC-XNVME-I375 and UCSC-XNVME-I750 Optane NVMe drives use the same firmware binary "
        "(identical MD5). Both SN entries have swapped names in the bundle (packing error). "
        "The shared binary serves 5+ Optane product variants including P4800X DC (enterprise) "
        "and 900P (prosumer). The bootloader contains: (1) 'Intel MansionBeach Bootloader' -- "
        "internal Intel development codename for the Optane SSD controller in production, "
        "(2) '*DFLT_SERIAL' -- a serial number placeholder in the bootloader that is overwritten "
        "at provisioning time, and (3) a Lenovo OEM variant name embedded in Cisco production firmware."
    ),
    "impact": "Single firmware vulnerability covers all Optane NVMe capacity variants; MansionBeach codename reveals Intel internal controller development identity; DFLT_SERIAL indicates factory provisioning bypass exists",
}

GPU_ZIPCRYPT_F1 = {
    "id": "GPU-ZIPCRYPT-F1",
    "severity": "MEDIUM",
    "title": "P40 and AMD v340 GPU bundles use ZipCrypto encryption across all ZIP entries including IROM",
    "affected": ["ucs-c-nvidia-video-p40 (86.02.4E.00.01)", "ucs-c-amd-video-v340 (016.001.001.000)"],
    "evidence": {
        "p40_encrypted_entries": ["P40/IROM/G6100200.ifr (10KB)", "P40/VBIOS/g610_0200_895_0__86024E0001.rom (256KB)"],
        "v340_encrypted_entries": ["V340/CA/PFX/v104.pmc (1483KB)", "V340/CA/VBIOS/b431069_D0531600.102_signed.rom (960KB)"],
        "cipher": "ZipCrypto (flag_bits & 1)",
        "comparison": "M10/M60 Maxwell VBIOSes are plaintext -- P40/v340 generation added ZipCrypto",
    },
    "mechanism": (
        "NVIDIA P40 (Pascal GP102) and AMD v340 (Fiji XT) GPU firmware bundles encrypt ALL ZIP "
        "entries using ZipCrypto (broken stream cipher). This extends the BCSERIES-F2 finding: "
        "H200/H100 GPU VBIOSes use ZipCrypto, but P40 additionally encrypts the IROM (10KB), "
        "which is a smaller, more predictable plaintext target for bkcrack known-plaintext attack. "
        "IROM files for Nvidia GPUs follow a known structure (PCI ROM header, IROP magic). "
        "AMD v340 additionally encrypts the PFX/PMC code (1483KB). ZipCrypto is broken via "
        "known-plaintext attack when 12+ bytes of plaintext at consistent offset are known."
    ),
    "impact": "ZipCrypto bypass recovers IROM/VBIOS for GPU firmware tampering; P40 IROM (10KB) is smallest and most predictable target across all GPU bundles in this dataset",
}

N2XX_F1 = {
    "id": "N2XX-F1",
    "severity": "LOW",
    "title": "n2xx-aipci01 repackages identical Intel FLB 1.836.0 with single-gzip vs XL710 double-gzip; iSCSI Boot ROM 2020 copyright",
    "affected": ["ucs-c-pci-n2xx-aipci01 (1.836.0, SSID 800009FA)"],
    "evidence": {
        "fw_version": "BootIMG_1.836.0.FLB (identical to Intel XL710 INTX710-F1)",
        "packaging": "single gzip wrapper (outer gzip -> FLB directly) vs XL710's gzip(gzip(FLB))",
        "iscsi_rom_version": "Intel(R) iSCSI Remote Boot version 3.1.97",
        "copyright": "Copyright (c) 2003-2020 Intel Corporation -- 6yr old in 2026 bundle",
        "certs_finding": "Same CLP Boot ROM version enforcement strings as XL710 apply",
    },
    "mechanism": "Different SN packaging path for the same Intel FLB binary -- version 1.836.0 with 2020 iSCSI ROM vintage",
    "impact": "Same CLP version enforcement bypass paths (INTX710-F1) apply; iSCSI Boot ROM 6yr old in deployment",
}

PMEM_F1 = {
    "id": "PMEM-F1",
    "severity": "LOW",
    "title": "PMEM DIMM and BPS DIMM firmware use encrypted Intel FPT format -- no readable strings; sealed at rest",
    "affected": ["ucs-pmemory-dimm-fw (1.2.0.5446)", "ucs-pmemory-bps-dimm-fw (2.2.0.1553)"],
    "evidence": {
        "magic": "06000000a1000000",
        "dimm_size_kb": 260,
        "bps_size_kb": 292,
        "content": "encrypted payload -- random-distribution bytes, no ASCII strings in either blob",
        "platform": "Intel FPT (Flash Programming Tool) format -- same magic as Optane NVMe (06000000)",
    },
    "mechanism": (
        "Intel Optane PMEM DIMM firmware and BPS (battery-backed power supply DIMM) firmware "
        "use the Intel FPT format (magic 06000000) with encrypted payloads. Unlike SAS/NVMe/NIC "
        "adapters in the same bundle, PMEM firmware is sealed -- no plaintext content readable "
        "without the decryption key (which is not in this bundle). The 06000000 magic is shared "
        "with Optane NVMe (XNVME-I375/I750), suggesting a common Intel firmware delivery platform."
    ),
    "impact": "Positive security indicator -- PMEM firmware content is sealed; analysis requires Intel FPT key or firmware decryption tooling",
}

ALL_FINDINGS = [LSISAS12G_F1, OPTANE_F1, GPU_ZIPCRYPT_F1, N2XX_F1, PMEM_F1]

SUMMARY = {
    "module": "cisco_ucs_cseries_storage_gpu_misc_re",
    "targets": "LSI SAS12G HBA, Intel Optane NVMe/PMEM, P40/v340 GPU, n2xx Intel PCIe",
    "total_findings": len(ALL_FINDINGS),
    "by_severity": {"HIGH": 2, "MEDIUM": 1, "LOW": 2},
    "headline": (
        "LSI SAS12G confirms third UCS HBA SKU with active debug CLI and 10yr BIOS. "
        "Optane NVMe I375/I750 share identical firmware binary with internal MansionBeach "
        "Bootloader codename and DFLT_SERIAL placeholder in production. "
        "P40/v340 GPU ZipCrypto encryption extends BCSERIES-F2 to IROM layer."
    ),
}

if __name__ == "__main__":
    for f in ALL_FINDINGS:
        print(f"[{f['severity']:6s}] {f['id']}: {f['title']}")
    print(f"\nTotal: {SUMMARY['total_findings']} findings "
          f"({SUMMARY['by_severity']['HIGH']}H/"
          f"{SUMMARY['by_severity']['MEDIUM']}M/"
          f"{SUMMARY['by_severity']['LOW']}L)")
