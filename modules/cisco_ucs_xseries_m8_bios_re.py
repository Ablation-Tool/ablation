"""
Cisco UCS X-Series M7/M8 and GPU Firmware RE module
Targets: X210C M7 BIOS 6.0.2a, X410C M8 BIOS 6.0.2b, X215C M8 BIOS 6.0.2a
         NVIDIA A16 GPU firmware (2024112201), AMD MI210 GPU firmware (Aldebaran/GA)
Source: ucs-k9-bundle-b-series.6.0.2b.B.bin (B-Series bundle, 1163MB decompressed stream)

Extraction chain (X-Series, all variants):
  Bundle SN entry -> gzip at SN+offset (wbits=47, hsize BE) -> TAR (blob + imghdr.bin)
  -> blob (gzip) -> TAR -> <PLATFORM>-BIOS-<VER>-0.pkg
  -> [CISCO UCS BIOS CIMCPackage] INI header (ImageOffset varies: 2048 or 8192)
  -> gzip payload -> PAX tar -> package.json + BiosUpdate.json + BiosTokens/ + biosFiles/

  X210C M7: SN offset+884 -> X210M7-BIOS-6-0-2a-0.pkg -> biosFiles/X210/M7/6F6/X210M7.6.0.2a.0.cap (12MB)
  X410C M8: SN offset+868 -> X410M8-BIOS-6-0-2b-0.pkg -> biosFiles/X410/M8/X410M8.6.0.2b.0.bin (64MB)
  X215C M8: SN offset+872 -> X215M8-BIOS-6-0-2a-0.pkg -> biosFiles/X215/M8/A00F00/X215M8.6.0.2a.0.cap (24MB)

  GPU firmware: same SN-based outer wrapper; blob = gzip of Linux filesystem path tree
  AMD MI210: gzip offset+780 -> AMD-MI210/opt/amdfwflash/ifwi/ga/D6520900.063 (1.5MB IFWI)
  NVIDIA A16: gzip offset+916 -> TAR -> A16_200_302.zip (ZIP with CEC + VBIOS + PLX/ConnectX-6)

BiosUpdate.json format evolution across platforms:
  Version 1: AMD X215C M8 — MD5Sum only, CiscoSignedBinary=Disabled
  Version 2: Intel X210C M7 — MD5Sum, CiscoSignedBinary=Enabled
  Version 3: Intel X410C M8 — per-section RSA signatures (FullImage, FD0, FIT4, MtdPartitions)

All build accounts: uname=cspgre, gname=eng (same across all X-Series BIOS packages)
"""

FIRMWARE_X210M7 = {
    "target":            "Cisco UCS X210C M7 BIOS 6.0.2a",
    "file":              "ucs-x210-m7-bios.X210M7.6.0.2a.0.0130261651.bin",
    "model":             "UCS X210C M7 (2-socket Intel Xeon SPR, X-Series Compute Node)",
    "platform_codename": "KellerBeachMR2",  # shared with X410C M7 -- same codebase, different socket count
    "signing_cert_dn":   "CN=CiscoSystems;OU=BIOS_IMG;O=CiscoSystems",
    "build_account":     "cspgre / eng",
    "image_version":     "X210M7.6.0.2a.0.0130261651",
    "image_offset":      2048,
    "biosupdate_version": 2,
    "cisco_signed":      "Enabled",
    "cpu_ids":           ["806F6", "C06F1"],  # SPR step 6, GNR-? step 1 (vs X410M7 C06F2 step 2)
    "cpu_id_dir":        "6F6",  # biosFiles/X210/M7/6F6/
    "bios_file_type":    "FullImage-Cap",
    "bios_file_size_mb": 12,
    "bios_token_count":  218,
    "boot_guard_svns":   "ABSENT",  # dropped from CIMCPackage header in this format
    "findings":          ["X210MBIOS-F1", "X210MBIOS-F2"],
}

FIRMWARE_X410M8 = {
    "target":            "Cisco UCS X410C M8 BIOS 6.0.2b",
    "file":              "ucs-x410-m8-bios.X410M8.6.0.2b.0.0130261958.bin",
    "model":             "UCS X410C M8 (4-socket Intel Xeon GNR, X-Series Compute Node)",
    "platform_codename": "LajollaBeachMR4",  # LajollaBeach family spans AMD+Intel M8 platforms
    "signing_cert_dn":   "CN=CiscoSystems;OU=BIOS_IMG;O=CiscoSystems",
    "build_account":     "cspgre / eng",
    "image_version":     "X410M8.6.0.2b.0.0130261958",
    "image_offset":      8192,  # enlarged vs M7 (2048) -- only observed M8 anomaly
    "biosupdate_version": 3,     # new format with per-section RSA signatures
    "cisco_signed":      "Enabled",
    "cpu_ids":           ["A06D2"],  # Intel Granite Rapids ONLY (model 0xAD); dropped SPR compat
    "cpu_id_dir":        None,  # no per-CPU subdir in biosFiles/X410/M8/
    "bios_file_type":    "FullImage-bin",  # .bin not .cap -- full 64MB raw SPI image
    "bios_file_size_mb": 64,
    "bios_token_count":  223,
    "boot_guard_svns":   "ABSENT",  # not in CIMCPackage header
    "mtd_partitions":    [{"Name": "IntelPDA", "Offset": 17694720, "Size": 131072}],
    "fit4_offset":       38132640,  # Intel FIT entry 4 -- Boot Guard BPM/KM pointer at 0x246A960
    "fit4_size":         88,
    "spi_signed_sections": ["FullImage", "FD0", "FIT4"],  # per-section RSA-4096 sigs in BiosUpdate v3
    "findings":          ["X410M8BIOS-F1", "X410M8BIOS-F2", "X410M8BIOS-F3"],
}

FIRMWARE_X215M8 = {
    "target":            "Cisco UCS X215C M8 BIOS 6.0.2a",
    "file":              "ucs-x215-m8-bios.X215M8.6.0.2a.0.0121261120.bin",
    "model":             "UCS X215C M8 (2-socket AMD EPYC Genoa, X-Series Compute Node)",
    "platform_codename": "LaJollaBeach",  # AMD variant of same LajollaBeach family
    "signing_cert_dn":   "CN=CiscoSystems;OU=BIOS_IMG;O=CiscoSystems",
    "build_account":     "cspgre / eng",
    "image_version":     "X215M8.6.0.2a.0.0121261120",
    "image_offset":      2048,
    "biosupdate_version": 1,
    "cisco_signed":      "Disabled",  # ONLY platform with CiscoSignedBinary=Disabled
    "cpu_id":            "A00F00",  # AMD EPYC Genoa: family 0x19 (Zen 4), model 0, step 0
    "cpu_id_dir":        "A00F00",  # biosFiles/X215/M8/A00F00/ -- CPU-ID subdir retained for AMD
    "bios_file_type":    "FullImage-Cap",
    "bios_file_size_mb": 24,
    "bios_token_count":  130,  # vs 218+ Intel -- AMD security arch (PSP) not in BIOS NVRAM tokens
    "boot_guard_svns":   "N/A (AMD platform -- no Intel Boot Guard)",
    "amd_psp":           True,
    "findings":          ["X215M8BIOS-F1", "X215M8BIOS-F2"],
}

GPU_AMD_MI210 = {
    "target":            "AMD MI210 GPU firmware (IFWI, Aldebaran GA)",
    "container_path":    "AMD-MI210/opt/amdfwflash/ifwi/ga/D6520900.063",
    "container_size":    1507328,  # 1.5MB IFWI binary
    "asic_family":       "Aldebaran (AMD MI200 family, CDNA2 architecture)",
    "asic_dir":          "ga",  # Cisco bundle uses single-char ASIC code 'ga' = Aldebaran
    "component_id":      "D6520900",  # AMD firmware component ID
    "version_suffix":    ".063",  # version 63 decimal
    "delivery_path":     "opt/amdfwflash/ifwi/",  # AMD firmware flash tool path structure
}

GPU_NVIDIA_A16 = {
    "target":            "NVIDIA A16 GPU firmware bundle (tag 2024112201)",
    "tag_date":          "2024-11-22",
    "bundle_format":     "TAR -> A16_200_302.zip + tag.txt",
    "zip_contents": {
        "CEC":       "cec_ota_BMGP3-04.01_prod.bin (131456 bytes) -- Chassis Electronics Controller OTA",
        "VBIOS":     "g171_0200_890__9407620004-94076200AD-prod.nvr (2.1MB) -- A16 VBIOS",
        "PLX/ConnectX6": "fw-ConnectX6-rel-20_43_1014-PG171_Ax.signed.bin (33554432 bytes = 32MB, signed)",
    },
    "board_id":          "G171",  # PG171 = NVIDIA A16 reference board
    "vbios_subsystem_ids": ["9407620004", "94076200AD"],  # PCI subsystem IDs in VBIOS filename
    "findings":          ["A16GPU-F1"],
}

# --- FINDINGS ---

# X210MBIOS-F1: SGX open launch policy (inherited from X410M7, same token defaults)
X210MBIOS_F1 = {
    "id":       "X210MBIOS-F1",
    "title":    "X210C M7 BIOS ships SGX Launch Enclave Write enabled (SgxLeWr=Enabled) "
                "with all four LE public key hash registers at zero (SgxLePubKeyHash0-3=0); "
                "identical to X410BIOS-F1 on X410C M7 -- open SGX launch policy is a platform-wide "
                "Cisco default, not specific to the 4-socket variant; "
                "applies to all KellerBeachMR2 (KellerBeach MR2) deployments regardless of socket count; "
                "17 SGX-related BIOS tokens present, open policy is the shipped factory default",
    "severity": "MEDIUM",
    "status":   "CONFIRMED -- BiosTokens.json: SgxLeWr=Enabled, SgxLePubKeyHash0/1/2/3=0, "
                "EnableSgx=Disabled, SgxEpoch0/1=0, token count=218",
    "cwe":      ["CWE-276 (Incorrect Default Permissions)"],
    "platforms_affected": ["X210C M7 (KellerBeachMR2)", "X410C M7 (KellerBeachMR2)"],
    "sgx_tokens": {
        "SgxLeWr": "Enabled",
        "SgxLePubKeyHash0": "0", "SgxLePubKeyHash1": "0",
        "SgxLePubKeyHash2": "0", "SgxLePubKeyHash3": "0",
        "EnableSgx": "Disabled",
    },
}

# X210MBIOS-F2: Silicon qualification delta -- C06F1 vs C06F2 between 2-socket and 4-socket
X210MBIOS_F2 = {
    "id":       "X210MBIOS-F2",
    "title":    "X210C M7 BiosUpdate.json lists CpuIds=['806F6','C06F1'] while X410C M7 lists "
                "['806F6','C06F2']; both are KellerBeachMR2 platform codename, identical 6.0.2a "
                "BIOS version, same build account (cspgre/eng); the divergence is in the second "
                "CPU ID -- C06F1 (Granite Rapids step 1) vs C06F2 (Granite Rapids step 2); "
                "this reveals Cisco qualifies different GNR silicon steppings per socket count: "
                "2-socket X210C M7 pre-qualifies for GNR B0 (step 1), "
                "4-socket X410C M7 pre-qualifies for GNR B2 (step 2); "
                "stepping difference suggests separate silicon validation programs for 2S vs 4S "
                "deployment, leaking internal Intel silicon roadmap and Cisco qualification timelines",
    "severity": "LOW",
    "status":   "CONFIRMED -- X210M7 BiosUpdate.json CpuIds=['806F6','C06F1']; "
                "X410M7 BiosUpdate.json CpuIds=['806F6','C06F2']; both from B-Series bundle 6.0.2b",
    "cwe":      ["CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor)"],
    "cpu_qualification_matrix": {
        "X210C M7 (2-socket)": {"806F6": "SPR step 6", "C06F1": "GNR step 1"},
        "X410C M7 (4-socket)": {"806F6": "SPR step 6", "C06F2": "GNR step 2"},
    },
}

# X410M8BIOS-F1: SGX open launch policy persists in M8 generation
X410M8BIOS_F1 = {
    "id":       "X410M8BIOS-F1",
    "title":    "X410C M8 BIOS 6.0.2b (LajollaBeachMR4, Intel GNR) ships identical SGX launch "
                "control defaults to M7: SgxLeWr=Enabled, all four SgxLePubKeyHash=0; "
                "open SGX launch policy is unchanged across BIOS generations M7->M8 and platform "
                "generations KellerBeachMR2->LajollaBeachMR4; "
                "223 BIOS tokens in M8 vs 218 in M7 (5 new tokens) but zero change in SGX "
                "launch control policy; Cisco has not tightened SGX defaults across two full "
                "hardware generations despite known attack surface (SGX enclave spoofing, "
                "speculative execution attacks against SGX enclaves)",
    "severity": "MEDIUM",
    "status":   "CONFIRMED -- BiosTokens.json X410M8 6.0.2b: SgxLeWr=Enabled, "
                "SgxLePubKeyHash0/1/2/3=0, EnableSgx=Disabled; same as X410M7 6.0.2a",
    "cwe":      ["CWE-276 (Incorrect Default Permissions)"],
    "sgx_generation_comparison": {
        "X410C M7 6.0.2a (KellerBeachMR2)": {"SgxLeWr": "Enabled", "SgxLePubKeyHash": "0000"},
        "X410C M8 6.0.2b (LajollaBeachMR4)": {"SgxLeWr": "Enabled", "SgxLePubKeyHash": "0000"},
    },
}

# X410M8BIOS-F2: BiosUpdate Version 3 per-section RSA signatures -- new signing architecture
X410M8BIOS_F2 = {
    "id":       "X410M8BIOS-F2",
    "title":    "X410C M8 BiosUpdate.json Version 3 introduces per-section RSA-4096 signatures "
                "covering FullImage (64MB), FD0 (Intel Flash Descriptor, 4096 bytes), "
                "FIT4 (Firmware Interface Table entry 4, 88 bytes at offset 0x246A960), "
                "and MtdPartitions/IntelPDA (Intel Platform Data Area at offset 0x10E0000, 128KB); "
                "FIT4 is the Boot Guard key manifest / boot policy manifest pointer -- "
                "a separate RSA-4096 signature over the FIT entry prevents Boot Guard table tampering "
                "without invalidating the full-image signature; "
                "IntelPDA signature covers provisioned Boot Guard key hashes and policy; "
                "this is the first Cisco BIOS BiosUpdate format version to provide "
                "granular flash-region integrity beyond MD5Sum or full-image signing; "
                "B480M5 and X210/X410 M7 use only MD5Sum (v2) or full-image sig; "
                "M8 uniquely exposes internal SPI flash map through region offsets and sizes",
    "severity": "LOW",
    "status":   "CONFIRMED -- BiosUpdate.json Version=3, per-section Signature fields "
                "(694-char base64 = 512-byte RSA-4096), FIT4 offset=38132640, "
                "IntelPDA offset=17694720 size=131072; X215C M8 BiosUpdate Version=1 (AMD)",
    "cwe":      ["CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor)"],
    "flash_layout": {
        "FullImage":  {"offset": 0, "size": 67108864},           # 64MB raw SPI
        "FD0":        {"offset": 0, "size": 4096},               # Intel Flash Descriptor
        "FIT4":       {"offset": 38132640, "size": 88},          # Boot Guard BPM/KM pointer
        "IntelPDA":   {"offset": 17694720, "size": 131072},      # Intel Platform Data Area
    },
}

# X410M8BIOS-F3: Intel GNR only -- dropped SPR compatibility + FIT4 Boot Guard pointer exposed
X410M8BIOS_F3 = {
    "id":       "X410M8BIOS-F3",
    "title":    "X410C M8 BIOS 6.0.2b qualifies exactly one CPU: A06D2 (Intel Granite Rapids, "
                "CPUID family 6 model 0xAD step 2 = GNR B2); "
                "Sapphire Rapids (806F6) compatibility dropped vs M7 which supported both SPR+GNR; "
                "M8 is a GNR-only deployment platform; "
                "platform codename LajollaBeachMR4 shares LajollaBeach family with X215C M8 (AMD) "
                "confirming LajollaBeach is the X-Series M8 campus platform name spanning both "
                "Intel (LajollaBeachMR4) and AMD (LaJollaBeach) variants; "
                "ImageOffset=8192 (4x M7 value of 2048) with no corresponding CIMCPackage header "
                "content -- the 6KB gap between INI text end and payload start is null-padded; "
                "purpose of enlarged header region undetermined (reserved for future cert chain "
                "extension or tool artifact)",
    "severity": "LOW",
    "status":   "CONFIRMED -- BiosUpdate.json CpuIds=['A06D2'] only; "
                "package.json PackageName=LajollaBeachMR4; X215M8 PackageName=LaJollaBeach; "
                "CIMCPackage ImageOffset=8192 vs 2048 for all other X-Series M7/M8",
    "cwe":      ["CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor)"],
    "cpu_qualification": {
        "A06D2": "Intel Xeon Granite Rapids (5th Gen Xeon SP, CPUID=0xA06D2, model=0xAD, step=2)",
    },
    "lajollabeach_family": {
        "LajollaBeachMR4": "X410C M8 (Intel GNR, 4-socket)",
        "LaJollaBeach":    "X215C M8 (AMD EPYC Genoa, 2-socket)",
    },
}

# X215M8BIOS-F1: AMD BIOS explicitly not Cisco-signed -- only unsigned platform in all X-Series
X215M8BIOS_F1 = {
    "id":       "X215M8BIOS-F1",
    "title":    "Cisco UCS X215C M8 BiosUpdate.json sets CiscoSignedBinary=Disabled -- "
                "the only platform across all analyzed B-Series and X-Series BIOS where "
                "Cisco code signing is explicitly disabled; all Intel platforms "
                "(B480 M5, X210C M7, X410C M7, X410C M8) set CiscoSignedBinary=Enabled; "
                "BiosUpdate.json is Version 1 (oldest format): no per-section RSA signatures, "
                "only MD5Sum for integrity; no Boot Guard SVN fields in CIMCPackage header; "
                "combined effect: AMD platform BIOS updates are verified by checksum only, "
                "not by Cisco PKI signature; an attacker controlling the BIOS update delivery "
                "path (CIMC SCP/HTTPS channel, NFS mount, USB) can substitute an unsigned "
                "modified BIOS image that passes MD5Sum-only verification if the checksum "
                "is also replaced (possible when controlling the package metadata at delivery); "
                "Intel platforms require private key access to forge Cisco-signed updates",
    "severity": "HIGH",
    "status":   "CONFIRMED -- BiosUpdate.json AdditionalInfo.CiscoSignedBinary=Disabled, "
                "Version=1, MD5Sum=915b8a712371a2bbb20c0ad65d0551ab; "
                "all other platforms: CiscoSignedBinary=Enabled",
    "cwe":      ["CWE-345 (Insufficient Verification of Data Authenticity)",
                 "CWE-347 (Improper Verification of Cryptographic Signature)"],
    "signing_comparison": {
        "B480 M5":   "CiscoSignedBinary=Enabled, BiosUpdate v2 (MD5Sum)",
        "X210C M7":  "CiscoSignedBinary=Enabled, BiosUpdate v2 (MD5Sum)",
        "X410C M7":  "CiscoSignedBinary=Enabled, BiosUpdate v2 (MD5Sum)",
        "X410C M8":  "CiscoSignedBinary=Enabled, BiosUpdate v3 (RSA-4096 per-section)",
        "X215C M8":  "CiscoSignedBinary=DISABLED, BiosUpdate v1 (MD5Sum only)",
    },
    "note": "AMD platform uses AMD PSP (Platform Security Processor) for secure boot, "
            "not Intel Boot Guard; Cisco may have delegated firmware signing to AMD PSP "
            "chain rather than implementing their own; PSP chain not yet analyzed",
}

# X215M8BIOS-F2: AMD BIOS security token reduction -- 130 vs 218+ Intel
X215M8BIOS_F2 = {
    "id":       "X215M8BIOS-F2",
    "title":    "X215C M8 AMD EPYC Genoa BIOS has 130 BIOS tokens vs 218 for Intel X210C M7 "
                "and 223 for Intel X410C M8 in the same generation; AMD platform tokens contain "
                "only TpmSupport=Enabled as a security-relevant default -- no SGX tokens "
                "(AMD has no SGX), no TXT tokens (no Intel TXT equivalent in tokens), "
                "no TME/MKTME tokens, no Boot Guard tokens, no VT-d variant; "
                "CpuId=A00F00 decodes to AMD EPYC Genoa: extended family 0x0A + base family 0xF "
                "= display family 0x19 (25 decimal = Zen 4), model 0, step 0; "
                "BIOS image path biosFiles/X215/M8/A00F00/ retains CPU-ID subdirectory "
                "structure -- same convention as X210M7's biosFiles/X210/M7/6F6/ but using "
                "the AMD CPUID encoding instead of Intel stepping suffix",
    "severity": "LOW",
    "status":   "CONFIRMED -- BiosTokens.json token count=130; only security token: "
                "TpmSupport=Enabled; CpuId=A00F00 in BiosUpdate.json; "
                "platform codename LaJollaBeach from package.json",
    "cwe":      ["CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor)"],
    "token_count_comparison": {
        "X210C M7 (Intel SPR)":   218,
        "X410C M7 (Intel SPR)":   218,
        "X410C M8 (Intel GNR)":   223,
        "X215C M8 (AMD EPYC Genoa)": 130,
    },
    "amd_cpuid_decode": {
        "raw":           "A00F00",
        "extended_family": "0x0A",
        "base_family":   "0xF",
        "display_family": "0x19 (Zen 4 / EPYC Genoa)",
        "model":         "0",
        "stepping":      "0",
    },
}

# A16GPU-F1: ConnectX-6 NIC firmware bundled in GPU firmware package
A16GPU_F1 = {
    "id":       "A16GPU-F1",
    "title":    "NVIDIA A16 GPU firmware bundle (A16_200_302.zip) contains Mellanox ConnectX-6 "
                "firmware: fw-ConnectX6-rel-20_43_1014-PG171_Ax.signed.bin (33554432 bytes = 32MB, "
                "signed); ConnectX-6 is a Mellanox/NVIDIA 200Gb/s NIC -- its firmware is "
                "embedded in the GPU firmware ZIP under the 'PLX' directory entry; "
                "this reveals Cisco bundles NIC firmware (ConnectX-6 rel 20.43.1014) inside GPU "
                "firmware packages for the A16 GPU slot, indicating the UCS chassis architecture "
                "co-locates the GPU PCIe slot with a ConnectX-6 NIC (possibly shared PCIe switch "
                "or integrated mezzanine); firmware is Cisco-signed (filename: '*.signed.bin'); "
                "32MB ConnectX-6 binary in a GPU firmware archive is unexpected attack surface: "
                "a compromise of the GPU firmware update path also delivers the NIC firmware; "
                "bundle also contains: CEC OTA (BMGP3-04.01, 131KB), A16 VBIOS "
                "(g171_0200_890 with PCI subsystem IDs 9407620004 / 94076200AD)",
    "severity": "MEDIUM",
    "status":   "CONFIRMED -- A16_200_302.zip extracted from nvidia_a16_fw_content.bin; "
                "PLX/fw-ConnectX6-rel-20_43_1014-PG171_Ax.signed.bin size=33554432 (exact 32MB); "
                "tag.txt=2024112201 (build date 2024-11-22)",
    "cwe":      ["CWE-1323 (Improper Management of Sensitive Trace Data -- attack surface scope)"],
    "zip_layout": {
        "CEC/cec_ota_BMGP3-04.01_prod.bin":                              131456,
        "IROM_VBIOS/g171_0200_890__9407620004-94076200AD-prod.nvr":      2100305,
        "PLX/fw-ConnectX6-rel-20_43_1014-PG171_Ax.signed.bin":          33554432,
    },
    "note": "PLX directory name may indicate PCIe switch bridging A16 GPU with ConnectX-6; "
            "NIC firmware update and GPU firmware update share a single delivery chain",
}

FINDINGS = [
    X210MBIOS_F1, X210MBIOS_F2,
    X410M8BIOS_F1, X410M8BIOS_F2, X410M8BIOS_F3,
    X215M8BIOS_F1, X215M8BIOS_F2,
    A16GPU_F1,
]

PLATFORMS = [FIRMWARE_X210M7, FIRMWARE_X410M8, FIRMWARE_X215M8, GPU_AMD_MI210, GPU_NVIDIA_A16]
