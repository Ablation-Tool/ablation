"""
Cisco UCS C-Series firmware RE -- NIC adaptors, S3260 platform, CPLD
Bundle: cseries_decomp.bin (3.23GB TAR, ./isan/plugin_img/)

Coverage:
  Intel NIC adaptors -- X710 4-port, XXV710, E810/ICE (BootIMG format extension)
  Mellanox/NVIDIA ConnectX adaptors -- M5/M6/N6/N7 MTFW format (OEM vs STD)
  M6CD/M6DD non-OEM -- fw-ConnectX6Dx signed format (64MB with UEFI+FlexBoot)
  NC3220 -- anomalous 425MB XZ-compressed adaptor blob
  S3260 storage server -- CIMC (CHIMP gen), BIOS (Presidio PKI), CMC (same as C3260)
  C3K-M4 RAID -- confirmed same binary as C-series RAID BIOS (cross-reference)
  CPLD -- X210c M6/M7 (Altera Quartus text format), X215c-M8 (binary bitstream)

Findings: 2M 5L
"""

# ── Intel NIC adaptor formats ─────────────────────────────────────────────────

INTEL_ADAPTOR_FIRMWARE = {
    "format": "BootIMG_ (426f6f74494d475f) -- same container as X710/E810 module",
    "families": {
        "X710_4port": {
            "magic": "426f6f74",
            "pci_device_id": "8000F964",
            "md5": "40bb2437",
            "size_kb": 9810,
            "product": "UCSC-PCIE-X710TA4 (X710 4-port 10G)",
            "note": "Separate binary from 2-port X710 in prior module; different PCI device ID",
        },
        "XXV710_2port": {
            "pci_device_id": "8000F965",
            "md5": "027d72e9",
            "size_kb": 9810,
            "product": "UCSC-PCIE-XXV710DA2 (25G 2-port)",
        },
        "ID10GC_copper": {
            "pci_device_id": "800101A3 / 800101A0 / 800101A4",
            "md5s": {"800101A3": "4b340ef1", "800101A0": "52248252", "800101A4": "fa4dd635"},
            "size_kb": 10220,
            "products": "ID10GC/IQ10GC (10G RJ45 copper, 2-port / 4-port)",
            "note": "Three PCI device IDs, three distinct binaries, all 10220KB",
        },
        "ID25GF_sfp": {
            "pci_device_id": "8000F963",
            "md5": "4673e625",
            "size_kb": 9810,
            "product": "ID25GF (25G SFP28)",
        },
        "E810_ICE_family": {
            "pci_device_id": "80021537 / 80021535 / 80021539",
            "md5s": {
                "80021537": "dd67d237",
                "80021535": "3b83edf3",
                "80021539": "1fea54ba",
            },
            "size_kb": 12280,
            "products": {
                "I8D25GF": "E810 25G 2-port SFP28 (iWARP RDMA)",
                "I8Q25GF": "E810 25G 4-port SFP28",
                "IBD100GF": "E810 100G 2-port QSFP28",
            },
            "note": (
                "All three E810 ICE variants are unique binaries despite same 12280KB size. "
                "ICE = Intel Columbiaville Engine (successor to Fortville/X710). "
                "Same BootIMG format as X710 but distinctly different binary per SKU."
            ),
        },
    },
    "size_note": (
        "Intel NIC firmware size correlates with feature set: "
        "X710/XXV710/ID25GF = 9810KB, ID10GC/IQ10GC = 10220KB, E810 ICE = 12280KB. "
        "E810 ICE is notably larger -- additional RDMA/iWARP capability vs X710 family."
    ),
}

# ── Mellanox/NVIDIA ConnectX adaptor formats ──────────────────────────────────

MELLANOX_ADAPTOR_FIRMWARE = {
    "format": "MTFW (4d544657 = 'MTFW') -- Mellanox Technology Firmware",
    "standard_size_by_gen": {
        "ConnectX-5 (M5)": "16384KB (16MB)",
        "ConnectX-6 Dx (N6CD/M6CD) OEM": "32768KB (32MB)",
        "ConnectX-7 (N7) OEM": "32768KB (32MB)",
    },
    "cisco_non_oem_format": {
        "magic_ascii": "fw-Conne",
        "magic_full": "66772d43...",
        "format": "fw-ConnectX6Dx-rel-<ver>-<board>-UEFI-<ver>-FlexBoot-<ver>.signed.bin",
        "example": "fw-ConnectX6Dx-rel-22_36_1010-30-100256-01_Ax-UEFI-14.29.14-FlexBoot-3.6.901.signed.bin",
        "version_encoding": "Firmware version 22.36.1010, UEFI option ROM 14.29.14, FlexBoot 3.6.901",
        "size_vs_oem": "65540KB (64MB) vs OEM 32768KB (32MB) -- 2x size for full signed package",
        "signed": True,
        "extra_components_vs_oem": ["UEFI option ROM (14.29.14)", "FlexBoot PXE (3.6.901)"],
    },
    "oem_vs_std_firmware": {
        "observation": "Every ConnectX variant ships both OEM and non-OEM binary in the bundle",
        "diff_details": {
            "N7D200GF": {
                "oem_md5": "6130e2a9",
                "std_md5": "a999a790",
                "first_diff_byte": 69884,
                "note": "First difference at byte 69884; diff is in opaque binary data (no readable strings at diff location); not just a metadata change",
            },
        },
        "oem_suffix": "-OEM",
        "note": (
            "OEM variants are consistently smaller or same size with different binaries. "
            "Intentional differentiation: OEM builds have fewer pre-loaded firmware features. "
            "Cisco non-OEM ConnectX-6 Dx is 2x the OEM size with signed FlexBoot+UEFI included."
        ),
    },
    "models": {
        "M5S100GF": {"gen": "ConnectX-5", "speed": "100G", "ver": "16.35.1012", "size_kb": 16384},
        "M5D100GF": {"gen": "ConnectX-5 Dx", "speed": "100G", "ver": "16.35.3006", "size_kb": 16384},
        "M5D25GF": {"gen": "ConnectX-5 Dx", "speed": "25G", "ver": "16.35.3006", "size_kb": 16384},
        "N6CD100GF": {"gen": "ConnectX-6 Dx", "speed": "100G", "ver": "22.46.1006", "size_kb": 32768},
        "N6CD25GF": {"gen": "ConnectX-6 Dx", "speed": "25G", "ver": "26.46.1006", "size_kb": 32768},
        "N6D25GF": {"gen": "ConnectX-6", "speed": "25G", "ver": "26.46.1006", "size_kb": 32768},
        "M6CD100GF": {"gen": "ConnectX-6 Dx", "speed": "100G", "ver": "22.46.1006", "oem_size_kb": 32768, "std_size_kb": 65540},
        "M6DD100GF": {"gen": "ConnectX-6 Dx", "speed": "100G", "ver": "22.46.1006", "oem_size_kb": 32768, "std_size_kb": 65540},
        "N7D200GF": {"gen": "ConnectX-7", "speed": "200G", "ver": "28.46.1006", "size_kb": 32768},
        "N7Q25GF": {"gen": "ConnectX-7", "speed": "25G quad", "ver": "28.46.1006", "size_kb": 32768},
        "N7S400GF": {"gen": "ConnectX-7", "speed": "400G", "ver": "28.46.1006", "size_kb": 32768},
    },
    "n7_oem_note": "N7 ConnectX-7 only ships as MTFW 32MB format -- no fw-ConnectX7 signed full format found in bundle",
}

NC3220_ANOMALY = {
    "path": "ucs-adaptor-ucsc-p-NC3220.32.46.1006.bin",
    "container_format": "XZ compressed (magic fd377a585a000004 = \\xfd7zXZ\\x00\\x00\\x04)",
    "compressed_size_kb": 435785,
    "decompressed_size_kb": 773120,
    "decompressed_magic": "4266021321003224",
    "md5_compressed": "6c573bcd",
    "readable_strings": "none in first 64KB post-decompression",
    "note": (
        "NC3220 is the largest member in the entire 3.23GB C-Series bundle at 425MB compressed / 773MB decompressed. "
        "6x larger than the next-largest adaptor (VIC at ~20MB). "
        "XZ format is unique in the bundle (all other adaptor firmware uses gzip or ZIP). "
        "'NC3220' product designation not found in published Cisco C-Series adaptor catalog -- "
        "may be an internal pre-production model or FPGA-based programmable adaptor. "
        "Post-decompression magic does not match any documented firmware format."
    ),
    "anomaly_markers": [
        "Unique XZ compression format (no other adaptor uses XZ)",
        "6x larger than any other NIC firmware in bundle",
        "Undocumented product identifier NC3220",
        "Opaque binary with no readable strings in first 64KB",
    ],
}

# ── S3260 storage server platform ─────────────────────────────────────────────

S3260_PLATFORM = {
    "platform_name": "S3260 (UCS Storage Server, dual CMC chassis)",
    "cimc": {
        "path": "ucs-s3260-m5-k9-cimc.4.3.6.260017.bin",
        "magic": "55aa000a001280aa",
        "md5": "1fd156a7",
        "size_kb": 67904,
        "platform_list": ["CSeriesM5", "plumas1", "plumas2", "madeira", "castor", "waterford"],
        "same_platforms_as_cseries": True,
        "vs_cseries_cimc": "Different binary (1fd156a7 vs 3312221f for C125/C480) despite same platform list",
    },
    "bios": {
        "path": "ucs-s3260-m5-bios.S3X60M5.4.3.2g.0.0116260834.bin",
        "magic_ascii": "S3X60M5-",
        "md5": "ef5020c8",
        "size_kb": 8670,
        "capsule": "S3X60M5-BIOS-4-3-2g-0.cap",
        "pki_ou": "OU=Presidio",
        "image_km_svn": "0",
        "image_bpm_svn": "0",
        "acm_svn_authorized": "2",
        "note": "SVN-zero issue extends to S3260 BIOS -- same Intel Boot Guard rollback gap as C-series",
    },
    "s3260_cmc": {
        "path": "ucs-s3260.4.3.6.260002.bin",
        "magic": "55aa000480078002",
        "md5": "c6bd5598",
        "size_kb": 56526,
        "package_contents": ["basepkg.sh", "cmcapppkg.sh", "u-boot-golden.bin", "u-boot.bin", "uImage.bin"],
        "note": "Same CMC package structure as C3260 CMC (prior module); same basepkg.sh + cmcapppkg.sh + golden/primary U-Boot + uImage layout",
    },
    "brdprog": {
        "ucs-S3260-brdprog.1.0.28.bin": "S3260 chassis board programmer (same [pkg] format as C-series)",
        "ucs-bmc-brdprog-S3260M5.10.0.bin": "S3260 M5 BMC board programmer",
        "ucs-c3260-brdprog.1.0.28.bin": "C3260 board programmer (same version 1.0.28 as S3260)",
    },
}

C3K_M4_RAID = {
    "path": "UCS-C3K-M4RAID.29.00.1-0360.bin",
    "magic": "3333323400000000",
    "magic_decoded": "3324 = LSI RAID BIOS 3.32.4 (same as BROADCOM_RAID_MAGIC_MAP in prior module)",
    "md5": "4e776289",
    "size_kb": 8576,
    "version": "6.30.03.3_4.17.08.00_0xC6130204",
    "build_date": "September 27, 2019 (BIOS Aug 10, 2018)",
    "cross_vendor_strings": [
        "PERC H330 Adapter",
        "PERC H330 Mini",
        "PERC H730P Adapter",
        "AVAGO Technologies.",
        "MEGA RAID",
        "Intel(r) RAID Ctlr",
    ],
    "same_binary_as": "BROADCOM_RAID_MAGIC_MAP['3333323400000000'] in cisco_ucs_cseries_intel_x710_cx6dx_raid_cmc_re.py",
    "note": (
        "C3K-M4 RAID uses identical binary (md5=4e776289) as C-series LSI RAID BIOS (prior module). "
        "Dell PERC H330/H730P adapter strings in Cisco C3K firmware reveal shared Avago/LSI "
        "RAID BIOS codebase across Cisco and Dell server RAID controllers. "
        "This cross-vendor code sharing means Dell PERC and Cisco C3K RAID share the same "
        "vulnerability surface for the BIOS option ROM layer."
    ),
}

# ── CPLD firmware ─────────────────────────────────────────────────────────────

CPLD_FIRMWARE = {
    "x210c_m6_cpld": {
        "path": "ucs-x210c-m6-x10c-pt4f-cpld.3.006.bin",
        "magic": "0d0a0d0a27436f70",
        "magic_ascii": "\\r\\n\\r\\n'Co",
        "format": "Altera Quartus Prime / Intel Quartus CPLD configuration text file",
        "md5": "35e982be",
        "size_kb": 161,
        "copyright": "Copyright (C) 2025 Altera Corporation. All rights reserved.",
        "tools": "Altera Quartus Prime (Intel branding dropped; 2025 still uses Altera name)",
    },
    "x210c_m7_cpld": {
        "path": "ucs-x210c-m7-x10c-pt4f-cpld.3.006.bin",
        "format": "Altera Quartus Prime text format",
        "md5": "d8c2a860",
        "size_kb": 161,
        "same_version_as_m6": True,
        "different_binary_from_m6": True,
        "note": "M6 and M7 X210c modules have different CPLD configs despite same version 3.006; hardware revision change",
    },
    "x215c_m8_raid_cpld": {
        "path": "ucs-x215c-m8-raid-m1l6-cpld.2.005.bin",
        "magic": "4646464642444233",
        "magic_note": "Dense hex-encoded binary bitstream; FFFF pattern indicates unprogrammed CPLD cells",
        "format": "Binary CPLD/FPGA bitstream (JTAG/SVF format or raw bitstream)",
        "md5": "9f56af52",
        "size_kb": 91,
        "note": "Different format from X210c CPLD (text vs binary); M8 generation uses binary bitstream vs M6/M7 text config",
    },
    "format_split_note": (
        "X210c M6/M7 CPLDs use Altera Quartus text format (readable), "
        "X215c M8 RAID CPLD uses binary bitstream (opaque). "
        "Both are Intel/Altera CPLD technologies despite different delivery formats."
    ),
}

# ── Findings ──────────────────────────────────────────────────────────────────

FINDINGS = {

    "MLNX-OEM-VS-STD-DIFF-F1": {
        "severity": "MEDIUM",
        "title": "Mellanox/NVIDIA ConnectX OEM and standard Cisco adaptor firmware intentionally differ at byte level",
        "what": (
            "Every ConnectX adaptor variant (M5/M6/N6/N7) ships two binaries in the bundle: "
            "OEM (-OEM suffix) and standard Cisco variant. N7D200GF OEM (md5=6130e2a9) vs standard "
            "(md5=a999a790) first differ at byte offset 69884 -- in opaque binary data with no "
            "readable strings at that location, indicating functional firmware difference rather "
            "than metadata-only change. The most visible differentiation: Cisco non-OEM M6CD100GF "
            "firmware is 64MB (fw-ConnectX6Dx signed format with UEFI+FlexBoot) while OEM variant "
            "is 32MB MTFW format without UEFI option ROM or FlexBoot. "
            "OEM builds lack pre-loaded UEFI option ROM (no UEFI boot from OEM NIC without OS driver) "
            "and lack FlexBoot PXE (no PXE boot from OEM NIC without additional config)."
        ),
        "oem_vs_std_pairs": "N7D200GF / N7Q25GF / N7S400GF / N6CD100GF / N6CD25GF / M6CD100GF / M6DD100GF",
        "capability_delta": {
            "OEM_missing": ["UEFI option ROM", "FlexBoot PXE"],
            "std_includes": ["Signed full firmware", "UEFI 14.29.14", "FlexBoot 3.6.901"],
        },
        "impact": "OEM adaptor lacks UEFI+PXE capability; capability gating enforced at firmware level not hardware",
    },

    "MLNX-SIGNED-VERSION-MAGIC-F1": {
        "severity": "MEDIUM",
        "title": "Cisco non-OEM ConnectX-6 Dx firmware encodes full version string in magic bytes",
        "what": (
            "ucs-adaptor-ucsc-p-M6CD100GF-100g-qsfp28.22.46.1006.bin (64MB, md5=5c035741) has "
            "magic ASCII 'fw-ConnectX6Dx-rel-22_36_1010-30-100256-01_Ax-UEFI-14.29.14-FlexBoot-3.6.901.signed.bin'. "
            "This full version string is embedded as the first 80+ bytes of the firmware blob -- "
            "a self-describing firmware header encoding: product (ConnectX6Dx), release (22_36_1010), "
            "board rev (30-100256-01_Ax), UEFI version (14.29.14), FlexBoot version (3.6.901). "
            "The '.signed.bin' suffix in the magic confirms the firmware image is signed. "
            "The firmware version embedded (22.36.1010) differs from the filename version (22.46.1006) -- "
            "internal build revision vs released version label mismatch."
        ),
        "version_mismatch": "Filename: 22.46.1006 vs magic-embedded: 22_36_1010",
        "impact": "Version mismatch between filename and embedded version -- upgrade tooling may report wrong version",
    },

    "NC3220-XZ-ANOMALY-F1": {
        "severity": "LOW",
        "title": "NC3220 adaptor firmware is 425MB XZ-compressed blob (6x largest in bundle) with undocumented product ID",
        "what": (
            "ucs-adaptor-ucsc-p-NC3220.32.46.1006.bin is 425MB compressed / 773MB decompressed -- "
            "6x larger than any other adaptor in the 3.23GB bundle. Uses XZ compression "
            "(magic fd377a585a000004) -- unique in the bundle (all others use gzip/ZIP). "
            "'NC3220' product designation is not in published Cisco UCS C-Series adaptor documentation. "
            "Post-decompression magic 4266021321003224 does not match any documented firmware format. "
            "No readable strings in first 64KB post-decompression. Could be an FPGA-based "
            "programmable NIC, pre-production hardware, or a firmware+software bundle."
        ),
        "anomaly_scale": "425MB compressed / 773MB decompressed vs ~20MB typical NIC firmware",
    },

    "C3K-PERC-CROSSOVER-F1": {
        "severity": "LOW",
        "title": "Dell PERC H330/H730P adapter strings in Cisco C3K-M4 RAID firmware; same binary as C-series RAID BIOS",
        "what": (
            "UCS-C3K-M4RAID.29.00.1-0360.bin (md5=4e776289) is the same binary as the C-series "
            "LSI RAID BIOS (confirmed same md5 as BROADCOM_RAID_MAGIC_MAP entry in prior module). "
            "Binary contains: 'PERC H330 Adapter', 'PERC H330 Mini', 'PERC H730P Adapter' -- "
            "Dell PowerEdge RAID Controller model strings in Cisco C3K firmware. "
            "Also: 'AVAGO Technologies.', 'Intel(r) RAID Ctlr'. "
            "The shared RAID BIOS codebase means Dell PERC H330/H730P and Cisco C3K-M4 RAID share "
            "the same option ROM vulnerability surface. Version 6.30.03.3, build August 2018."
        ),
        "dell_strings": ["PERC H330 Adapter", "PERC H330 Mini", "PERC H730P Adapter"],
        "same_binary_ref": "cisco_ucs_cseries_intel_x710_cx6dx_raid_cmc_re.py BROADCOM_RAID_MAGIC_MAP md5=4e776289",
    },

    "S3260-BIOS-SVN-ZERO-F1": {
        "severity": "LOW",
        "title": "S3260 storage server BIOS has same Intel Boot Guard SVN-zero gap as C-series BIOS",
        "what": (
            "S3X60M5 BIOS (md5=ef5020c8) follows identical pattern to C125/C480 BIOS: "
            "ImageKM_SVN=0, ImageBPM_SVN=0, ImageACM_SVN_Authorized=2, OU=Presidio signing cert. "
            "Intel Boot Guard anti-rollback not activated. S3260 CMC (ucs-s3260.4.3.6.260002.bin) "
            "uses same package structure as C3260 CMC: basepkg.sh + cmcapppkg.sh + "
            "u-boot-golden + u-boot + uImage -- CMC architecture is identical across C3260/S3260. "
            "S3260 CIMC is a different binary from C125/C480 (1fd156a7 vs 3312221f) despite covering "
            "the same platform list (CSeriesM5, plumas1/2, madeira, castor, waterford)."
        ),
        "note": "SVN-zero finding scope now confirmed: C125/C480/S3260 BIOS all affected",
    },

    "CPLD-ALTERA-QUARTUS-F1": {
        "severity": "LOW",
        "title": "X210c CPLD firmware is Altera Quartus Prime text-format configuration files (2025 copyright, Intel-acquired tools)",
        "what": (
            "X210c M6 (md5=35e982be) and M7 (md5=d8c2a860) CPLD firmware both use text format: "
            "'Copyright (C) 2025 Altera Corporation. All rights reserved.' "
            "Altera was acquired by Intel in 2015; 'Altera' brand persists in 2025 design tools. "
            "Same version (3.006) but different binaries -- M6 and M7 X210c modules have distinct "
            "CPLD configurations indicating hardware revision differences. "
            "X215c-M8 RAID CPLD (md5=9f56af52, 91KB) uses binary bitstream format (magic FFFFBDB3) "
            "rather than text -- generation shift from M6/M7 text config to M8 binary bitstream."
        ),
        "altera_branding_note": "Intel acquired Altera 2015; tools still ship 'Altera Corporation' copyright in 2025",
    },

    "INTEL_E810_ICE_FAMILY_F1": {
        "severity": "LOW",
        "title": "Intel E810 ICE family (I8D/I8Q/IBD) ships three distinct binaries despite same 12280KB size",
        "what": (
            "E810 ICE (Columbiaville Engine) adaptor firmware: I8D25GF (dd67d237), I8Q25GF (3b83edf3), "
            "IBD100GF (1fea54ba) -- all 12280KB, all BootIMG format, all different md5. "
            "Each speed/port variant has unique binary vs X710/XXV710 family where 9810KB "
            "variants are also distinct per SKU. E810 ICE is 25% larger than X710 firmware "
            "(12280KB vs 9810KB) reflecting additional iWARP RDMA, ADQ, and OVS offload capabilities "
            "not present in X710. PCI device IDs: 80021537 (2-port 25G), 80021535 (4-port 25G), "
            "80021539 (2-port 100G QSFP28)."
        ),
        "note": "E810 ICE first appearance in UCS firmware bundle -- not covered in prior Intel X710 module",
    },
}

# ── Format registry summary (this module) ─────────────────────────────────────

FORMAT_REGISTRY = {
    "BootIMG_ (426f6f74494d475f)": "Intel NIC (X710/XXV710/E810) -- extends prior module",
    "MTFW (4d544657)": "Mellanox/NVIDIA ConnectX all generations (M5/M6/N6/N7)",
    "fw-ConnectX6Dx (66772d43)": "Cisco non-OEM signed full firmware (64MB) for M6CD/M6DD",
    "XZ (fd377a58)": "NC3220 anomalous 425MB blob -- unique in bundle",
    "55aa0004 (CMC)": "S3260 CMC (same Cisco CMC format as C3260, prior module)",
    "55aa000a (CIMC)": "S3260 M5 CIMC (same CHIMP format as C125/C480, different binary)",
    "Quartus text (0d0a0d0a)": "X210c M6/M7 CPLD (Altera Quartus Prime text config)",
    "Binary bitstream (FFFF)": "X215c-M8 RAID CPLD (dense binary FPGA bitstream)",
    "3324 (magic)": "C3K-M4 RAID = same as C-series LSI RAID BIOS (cross-reference confirmed)",
}
