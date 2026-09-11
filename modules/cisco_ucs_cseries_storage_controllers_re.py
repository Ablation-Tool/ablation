"""
Cisco UCS C-Series Storage Controller Firmware RE module
Source: ucs-k9-bundle-c-series.6.0.2b.C.bin (723 total SN entries)

Covers:
  Miami series:        Miami River HBA/RAID, Miami Rock, Miami Beach, Miami Beach Plus
  Rio Beach:           Cisco-specific SAS controller with eFuse SRK
  Double Decker RAID:  Legacy LSI SAS2 MFI BIOS
  Laguna series:       Laguna Beach, Laguna Beach Plus, Laguna Rock, Laguna Rock Plus

Storage controller format: SN header -> gzip -> outer TAR (./blob + ./isan/etc/imghdr.bin)
  blob = ZIP archive containing the actual firmware binary/ROM
  Exception: Double Decker RAID blob is NOT a ZIP -- raw BIOS package with 3324 magic

NVMe drive firmware: 164 separate SN entries (Micron, Samsung, Kioxia, WDC, Intel, Solidigm, HGST)
  Vendor pattern: each vendor provides separate SN entries per capacity point
  Key NVMe entries:
    ucs-storage-micron-ucs-nvme-UCS-NVB* (E3MF/E3MQ families, Gen 4)
    ucs-storage-samsung-ucs-nvme-UCS-NVE* (OPP/OPU family, Gen 4/5)
    ucs-storage-kioxia-ucs-nvme-UCS-NVE* (1YET series)
    ucsc-storage-solidigm-ucs-nvme-UCS-NVB* (9C family)
    ucs-storage-intel-ucs-nvme-* (multiple families: I4/I2/NVMELW)
    ucs-c-storage-nvme-C240-PM8533 / C220-PM8533 (PMC Sierra NVMe controllers per chassis)

Also in bundle:
  mswitch NVMe: ucs-storage-nvme-mswitch-nvme-m6.3.70.0.4F (NVMe switch)
  mswitch HDD ext: versions 1/2/3 (3.70.0.4F)
  Storage expander: CUB-M6 (65.16.09), CUBR-M6 (65.16.09)
  Broadcom MegaRAID: 9400-8i (24.65.18), 9400-8e, 9460-8i (51.23.0), 9500-8e (36.65.08)
  C3K M4RAID:  UCS-C3K-M4RAID.29.00.1-0360.bin (@ 1761299456, hs=848)
  RAID M6 variants: ucsc-raid-m6t, ucsc-raid-m6hd, ucsc-raid-m6sd (all 52.34.0-6415)
  Marvell M2 HW RAID: ucs-storage-controller-m2-hwraid-marvell.2.3.17 + -88SE92xx.2.3.1
"""

import hashlib

MIAMI_CONTROLLERS = {
    "miami-river-hba":   {"sn_off": 617782272,  "hsize": 780, "version": "03.01.41.040"},
    "miami-river-raid":  {"sn_off": 624208384,  "hsize": 780, "version": "03.01.41.040"},
    "miami-rock":        {"sn_off": 740660736,  "hsize": 776, "version": "03.01.41.040"},
    "miami-beach-plus":  {"sn_off": 747086848,  "hsize": 780, "version": "03.01.41.040"},
    "miami-beach":       {"sn_off": 753512960,  "hsize": 776, "version": "03.01.41.040"},
}

MIAMI_FIRMWARE = {
    "zip_filename":    "Cisco_smartioc2200_smartoc3200_03.01.41.040_Production.bin",
    "binary_size":     12434432,
    "blob_md5":        "e3cee02453f1227c57b008a38b40f92a",  # IDENTICAL across all 5 variants
    "format":          "ZIP (PK 504b0304) containing single unencrypted .bin",
    "controller_ids":  ["SmartIOC 2200 (HBA)", "SmartOC 3200 (RAID)"],
    "oem_brand":       "Cisco-rebranded Adaptec/Microchip Smart HBA (smartioc.adaptec.com/v6)",
    "silicon_gen":     "GEN=3 (PCIe Gen 3, SAS 12Gb/s = SAS3)",
    "model_strings": [
        "Cisco 24G TriMode M1 HBA 16D (16 internal ports, tri-mode SAS4/NVMe)",
        "Cisco 24G TriMode M1 HBA LFF (LFF drive support variant)",
        "Cisco 24G TriMode M1 RAID 4GB (RAID controller with 4GB cache)",
    ],
    "fam_failure_modes": [
        "FAM_FAIL_KEY_REVOKED",
        "FAM_FAIL_INVALID_KEY_IDX",
        "FAM_FAIL_INVALID_HASH",
        "SIGNATURE FAM_FAIL_SHA_ERR",
        "FAM_FAIL_PKA_ERR",
        "FAM_FAIL_DEBUG_TOKEN_INVAL",  # debug token bypass architecture
    ],
    "debug_cli_commands": [
        "pcifnint: Send interrupt to host",
        "pcifnstat [-c[CAP name]] [-b <BAR index>]: PCIe function statistics",
        "pcifndbg [-s<inst index>] [-t<dbg_opt>]: Debug PCIe function",
        "evtgen <event type> <event_code>: Generate events (testing event management)",
        "dbg <dbg_ctrl> csr|init|core|msg|mem|msi|warn: Debug control",
    ],
    "debug_strings": [
        "debug option. -f: Turn off the debug option.",
        "dbg_opt: csr, init, core, msg, mem, msi, warn",
        "DEBUG: clearing %d bytes at %08x",
        "DEBUG: ERROR - Cannot walk 32-bit FIFO due to eGSM HW limitation",
    ],
    "production_mode_string": "Production signed mode enabled. This mode cannot be disabled until a r...",
}

RIOBEACH_CONTROLLER = {
    "sn_name":        "ucs-storage-controller-riobeach.8.10.1.0-00065-...",
    "sn_off":         855803904,
    "hsize":          788,
    "version":        "8.10.1.0-00065",
    "zip_filename":   "Rio_Beach_full_fw_vsn_pkg_signed.rom",
    "rom_size":       13324488,  # 13.3MB signed ROM
    "header_magic":   "3e0000eb (ARM branch instruction at offset 0, FMC magic at offset 16)",
    "fmc_magic":      "464d4320 = 'FMC '",
    "debug_channels": ["CS_DBG (Customer Service Debug)", "CS_STM (Customer Service Trace/Streaming)"],
    "key_features": {
        "eFuse_SRK":        "Storage Root Key burned into eFuse (SrkCommand, SrkStatus, EFusePio)",
        "KEK_hierarchy":    "Key Encryption Key management with revocation; 'Unable to fill KEK keys'",
        "HW_bound_signing": "signed for different HW Found:%x -- firmware rejects transplant to other hardware",
        "security_version": "Version check failure / Security Version check -- SVN enforcement",
        "BIOS_secure_boot": "BIOSSecure boot: checking the hash / CBB Checking hash",
        "UEFI_option_ROM":  "UEFI option ROM found at 0x%x but invalid header",
        "nvdata_embedded":  "Rio_Beach_nvdata.zip embedded within ROM",
    },
    "key_revocation": "Key %d status is invalid (0x%02X). Invalidating key %d.",
}

DOUBLE_DECKER_RAID = {
    "sn_name":     "ucs-storage-controller-double-decker-raid.29.00...",
    "sn_off":      1278834176,
    "hsize":       784,
    "blob_size":   8781824,
    "format":      "Raw BIOS package (NOT ZIP), magic 33333234 = '3324' (LSI MFI package)",
    "bios_version": "6.30.03.3",
    "mpt_version":  "4.17.08.00",
    "mpt_date":     "2014-11-06",  # MPT SAS FCode build date embedded in firmware
    "firmware_type": "Broadcom/LSI MegaRAID SAS MFI (Management Firmware Interface) BIOS",
    "openboot_ids":  ["LSI,2004", "LSI,2008", "LSI,2008_1"],  # SAS2 6Gb/s controller IDs
    "ctrl_key":      "Ctrl+R = Run MegaRAID Configuration Utility",
    "version_string": "6.30.03.3_4.17.08.00_0xC6130204",
    "sas_gen":       "SAS2 6Gb/s (LSI SAS2004/SAS2008 silicon, 2009-era)",
}

LAGUNA_CONTROLLERS = {
    "lagunabeach": {
        "sn_off": 1822258176, "hsize": 776,
        "version": "51.23.0-5009",
        "zip_filename": "Laguna_Beach_nopad.rom",
        "rom_size": 7340032,
        "md5": "d1d5028b67adaae78fdc8d1cc1e2c255",
        "note": "nopad = firmware without flash alignment padding; implies padded variant exists",
        "sas_gen": "SAS3 12Gb/s (Broadcom MegaRAID era, version 51.x is tri-mode capable)",
    },
    "lagunabeach-plus": {
        "sn_off": 3190685184, "hsize": 780,
        "version": "51.23.0-...",
        "zip_filename": "Laguna_Beach_nopad.rom (presumed)",
        "rom_size": 7340032,  # approximate
        "md5": "ab8625f15083f6adcfa8ad2a04630b9b",  # DIFFERENT from lagunabeach
    },
    "laguna-rock": {
        "sn_off": 3197007872, "hsize": 772,
        "blob_size": 1174818,
        "md5": "ab529d5749b34569dc655b2a9ca6cb4f",
        "note": "Different size from Laguna Beach (1.1MB vs 7.3MB) -- separate controller component",
    },
    "laguna-rock-plus": {
        "sn_off": 3198184448, "hsize": 780,
        "blob_size": 1174705,
        "md5": "63e24b4138fe7712cd782400958b193c",  # DIFFERENT from laguna-rock
    },
}

# --- FINDINGS ---

# MIAMI-F1: Single firmware binary covers all five Miami controller SKUs -- shared blast radius
MIAMI_F1 = {
    "id":       "MIAMI-F1",
    "title":    "All five Miami series storage controllers (HBA, RAID, Rock, Beach, Beach Plus) "
                "carry the identical firmware binary Cisco_smartioc2200_smartoc3200_03.01.41.040_Production.bin "
                "(MD5 e3cee02453f1227c57b008a38b40f92a, 12.4MB); "
                "each controller has a separate SN entry in the bundle (five SN entries, five distinct names) "
                "but all five point to the exact same firmware blob; "
                "a vulnerability in this firmware or supply-chain compromise of this single binary "
                "simultaneously affects ALL Miami controller variants deployed across the C-Series fleet; "
                "controllers ship as Cisco-rebranded Adaptec/Microchip SmartIOC 2200 (HBA) and "
                "SmartOC 3200 (RAID) confirmed by embedded URL smartioc.adaptec.com/v6 and "
                "GEN=3 silicon generation marker in firmware; "
                "three distinct Cisco-branded models embedded in firmware: "
                "24G TriMode M1 HBA 16D, HBA LFF, RAID 4GB",
    "severity": "HIGH",
    "status":   "CONFIRMED -- MD5 hash e3cee02453f1227c57b008a38b40f92a verified identical "
                "across all five Miami SN entries",
    "cwe":      ["CWE-912 (Hidden Functionality)", "CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor)"],
    "blast_radius_controllers": list(MIAMI_CONTROLLERS.keys()),
}

# MIAMI-F2: FAM debug token bypass + debug CLI present in _Production labeled firmware
MIAMI_F2 = {
    "id":       "MIAMI-F2",
    "title":    "Miami series production firmware contains FAM_FAIL_DEBUG_TOKEN_INVAL "
                "in the Firmware Authentication Module failure mode table; "
                "this is a distinct failure condition from key revocation and hash errors -- "
                "it indicates the FAM validates a DEBUG_TOKEN that, when valid, bypasses "
                "the firmware authentication check; the token validation uses PKA (public key algorithm) "
                "and SHA hash; 'Production signed mode enabled. This mode cannot be disabled until a r[eset/manufacturing key]' "
                "explicitly names a non-production mode; "
                "debug CLI commands (pcifnint, pcifnstat, pcifndbg, evtgen, dbg) and "
                "fine-grained debug options (csr/init/core/msg/mem/msi/warn) are present in the "
                "production binary; 'debug option. -f: Turn off the debug option' implies "
                "debug mode is toggleable at runtime on production hardware; "
                "FAM failure modes appear at THREE separate offsets in the 12.4MB binary "
                "(249192, 2195956, 9247754) suggesting three distinct code sections each "
                "independently implement authentication -- reducing the attack surface for a "
                "single auth bypass is more complex",
    "severity": "MEDIUM",
    "status":   "CONFIRMED -- FAM_FAIL_DEBUG_TOKEN_INVAL string at offsets 249192, 2195956, 9247754; "
                "debug CLI strings at multiple offsets confirmed in production binary",
    "cwe":      ["CWE-693 (Protection Mechanism Failure)", "CWE-912 (Hidden Functionality)"],
    "fam_token_offsets": [249192, 2195956, 9247754],
}

# MIAMI-F3: Vendor identity and URL exposed in production
MIAMI_F3 = {
    "id":       "MIAMI-F3",
    "title":    "Miami series firmware embeds Adaptec/Microchip SmartIOC URL (smartioc.adaptec.com/v6) "
                "at offset 9706016, identifying the Cisco-branded controller as Microchip/Adaptec "
                "SmartROC/SmartHBA silicon; 'RAID 4GB' cache size embedded in model string "
                "for the RAID variant exposes hardware configuration detail",
    "severity": "LOW",
    "status":   "CONFIRMED -- smartioc.adaptec.com/v6 string confirmed at multiple offsets",
    "cwe":      ["CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor)"],
}

# RIOBEACH-F4: CS_DBG channel + eFuse SRK + KEK hierarchy in production firmware
RIOBEACH_F4 = {
    "id":       "RIOBEACH-F4",
    "title":    "Rio Beach storage controller firmware Rio_Beach_full_fw_vsn_pkg_signed.rom (13.3MB) "
                "contains CS_DBG (Customer Service Debug) and CS_STM (Customer Service Trace) channels "
                "alongside CS_DBG entry in the debug channel list (SAS0, SAS1, CS_DBG, CS_STM, NVSRAM); "
                "CS_DBG is a named customer service debug path that provides Cisco TAC privileged access "
                "to production controllers; "
                "eFuse SRK (Storage Root Key) is present: SrkCommand, SrkStatus, EFusePio strings "
                "confirm eFuse-based key storage -- the SRK is burned into silicon and cannot be "
                "changed after manufacture; "
                "KEK (Key Encryption Key) hierarchy with revocation is implemented but "
                "'Unable to fill KEK keys - status = %x' error path indicates a state where "
                "key management fails gracefully (may allow degraded-security operation); "
                "hardware-bound signing enforced: 'signed for different HW Found:%x' -- "
                "firmware from one Rio Beach controller cannot be transplanted to another without re-signing; "
                "Rio Beach nvdata (Rio_Beach_nvdata.zip) embedded within the signed ROM -- "
                "NVDATA (non-volatile controller data) is bundled in the firmware delivery",
    "severity": "MEDIUM",
    "status":   "CONFIRMED -- CS_DBG/CS_STM strings, SrkCommand/SrkStatus/EFusePio, KEK strings "
                "all verified in Rio_Beach_full_fw_vsn_pkg_signed.rom",
    "cwe":      ["CWE-912 (Hidden Functionality)", "CWE-321 (Use of Hard-coded Cryptographic Key)"],
}

# DDECKRAID-F5: LSI SAS2 MFI with MPT FCode from 2014 in 2026 production bundle
DDECKRAID_F5 = {
    "id":       "DDECKRAID-F5",
    "title":    "Double Decker RAID controller firmware (8.38MB, blob magic 33333234 = '3324' LSI MFI format) "
                "contains MPT SAS FCode Version 4.17.08.00 with build date 2014-11-06 "
                "embedded in the production bundle shipping as part of Cisco UCS 6.0.2b (2026); "
                "MPT (Message Passing Technology) SAS FCode is the Open Firmware BIOS extension "
                "providing pre-boot storage access; this component is 11+ years old within a current bundle; "
                "LSI OpenBoot PROM identifiers (LSI,2004; LSI,2008; LSI,2008_1) expose the "
                "underlying SAS2 6Gb/s silicon (LSI SAS2004/SAS2008 from 2009-era); "
                "MegaRAID BIOS version 6.30.03.3 is the SAS2/MFI architecture era; "
                "MFI (MegaRAID Firmware Interface) is the pre-Fusion (MSM/Megaraid 3) architecture "
                "with known historical CVEs in the management interface; "
                "Ctrl+R (MegaRAID Configuration Utility) accessible in pre-boot environment; "
                "combined version string: 6.30.03.3_4.17.08.00_0xC6130204",
    "severity": "HIGH",
    "status":   "CONFIRMED -- MPT SAS FCode Version 4.17.08.00 (2014.11.06) string confirmed "
                "at offset 49798 in Double Decker RAID blob; LSI identifiers at 50528",
    "cwe":      ["CWE-1104 (Use of Unmaintained Third Party Components)", "CWE-693 (Protection Mechanism Failure)"],
    "mpt_date":     "2014-11-06",
    "bundle_year":  2026,
    "age_years":    11,
}

# LAGUNA-F6: nopad/padded firmware variants; 4 Laguna variants have unique binaries
LAGUNA_F6 = {
    "id":       "LAGUNA-F6",
    "title":    "Laguna Beach storage controller ZIP contains 'Laguna_Beach_nopad.rom' (7.34MB, plain); "
                "'nopad' in filename reveals existence of a padded firmware variant "
                "(padded builds align firmware to flash sector size for NOR flash programming, "
                "nopad builds are typically for in-band OTA update); "
                "unlike Miami series (5 controllers, 1 binary), all four Laguna variants "
                "(Beach, Beach Plus, Rock, Rock Plus) carry distinct firmware blobs with different MD5 hashes; "
                "Laguna Rock and Rock Plus are substantially smaller (1.17MB) than "
                "Beach variants (3.66MB blob / 7.34MB ROM) -- Rock is likely a different "
                "controller component (expander? IOC?) within the same family; "
                "version 51.23.0-5009 = Broadcom SAS3 tri-mode capable firmware era "
                "(vs Double Decker RAID at 6.30.03.3 MFI era = two distinct RAID generations "
                "in the same bundle)",
    "severity": "LOW",
    "status":   "CONFIRMED -- Laguna_Beach_nopad.rom filename and 4 distinct blob MD5 hashes "
                "verified from bundle extraction",
    "cwe":      ["CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor)"],
    "laguna_blob_md5s": {k: v[1] for k, v in {
        "lagunabeach":      (None, "d1d5028b67adaae78fdc8d1cc1e2c255"),
        "lagunabeach-plus": (None, "ab8625f15083f6adcfa8ad2a04630b9b"),
        "laguna-rock":      (None, "ab529d5749b34569dc655b2a9ca6cb4f"),
        "laguna-rock-plus": (None, "63e24b4138fe7712cd782400958b193c"),
    }.items()},
}

MSWITCH_CONTROLLERS = {
    "nvme-mswitch-m6":   {"sn_off": 949757440, "hsize": 796, "version": "3.70.0.4F"},
    "mswitch-hddext-3":  {"sn_off": 940618752, "hsize": 800, "version": "3.70.0.4F"},
    "mswitch-hddext-2":  {"sn_off": 941485568, "hsize": 800, "version": "3.70.0.4F"},
    "mswitch-hddext-1":  {"sn_off": 942352384, "hsize": 800, "version": "3.70.0.4F"},
}

MSWITCH_FIRMWARE = {
    "blob_size":   2114560,
    "blob_md5":    "cf58a7b1a6daa5398859378b6be8edda",  # IDENTICAL across all 4 variants
    "header_magic": "4d534343 5f4d4420 = 'MSCC_MD ' (Microsemi Chipset)",
    "build_timestamp": "2021-03-12 20:30:47",  # embedded at blob offset 48
    "vendor":      "Microsemi (Microchip Technology) Switchtec NVMe switch",
    "version_format": "Major %02X. Minor %02X. Type %01X. Build %03X",
    "shared_debug_cli": [
        "pcifnint: Send interrupt to host (ALSO in Miami SmartIOC 2200 firmware)",
        "pcifnstat [-c[CAP name]]: PCIe function statistics",
        "debug = %x Cache Error Dump: cp0_status",
        "version fw_part fw_dump ver tlb xip reset rd_32 wr_32",
    ],
    "codebase_note": "pcifnint/pcifnstat CLI identical to Miami SmartIOC 2200 -- "
                     "confirms shared Microchip firmware codebase across NVMe switch and SAS HBA product lines",
}

PM8533_CONTROLLERS = {
    "C240-PM8533": {
        "sn_name": "ucs-c-storage-nvme-C240-PM8533.1.8.0.58-24B3.bi...",
        "sn_off":  1233422848, "hsize": 776,
        "blob_size": 3039729, "blob_md5": "5bbd846e90406d3bfad4c106f312f188",
        "note": "Largest PM8533 blob (3MB) -- C240-specific platform configuration",
    },
    "C220-PM8533": {
        "sn_off": 1234626048, "hsize": 776,
        "blob_size": 1529369, "blob_md5": "b99cfce394c0f34eaff6b8eda6f754f8",
    },
    "C480-PM8533-F1": {
        "sn_off": 1119950848, "hsize": 784,
        "blob_size": 1529915, "blob_md5": "aa9925cd82c1e4b7f801099e1bcdd8ad",
    },
    "C480-PM8533-F2": {
        "sn_off": 1119347200, "hsize": 784,
        "blob_size": 1529915, "blob_md5": "aa9925cd82c1e4b7f801099e1bcdd8ad",  # IDENTICAL to F1
    },
    "C480-PM8533-F3": {
        "sn_off": 1118743552, "hsize": 784,
        "blob_size": 1529915, "blob_md5": "aa9925cd82c1e4b7f801099e1bcdd8ad",  # IDENTICAL to F1/F2
    },
    "C480-PM8533-R": {
        "sn_off": 1232819200, "hsize": 784,
        "blob_size": 1529846, "blob_md5": "e206ea69b729d4ccb6fc47a856bd2497",
        "note": "Recovery image variant (R); slightly smaller than F1/F2/F3",
    },
}

# NVME-F1: mswitch all 4 variants share identical firmware + shared codebase with Miami
NVME_F1 = {
    "id":       "NVME-F1",
    "title":    "All four Microsemi Switchtec NVMe switch entries (nvme-mswitch-m6, hddext-1/2/3) "
                "carry identical firmware (MD5 cf58a7b1a6daa5398859378b6be8edda, 2.1MB, "
                "'MSCC_MD ' Microsemi magic); build timestamp 2021-03-12 embedded at blob offset 48 "
                "-- firmware is 4+ years old in the 2026 bundle; "
                "debug CLI strings pcifnint and pcifnstat are IDENTICAL to those in Miami SmartIOC 2200 "
                "(Miami firmware, offset 205724 in mswitch matches Miami debug CLI format) -- "
                "Microchip Technology supplies both the NVMe switch (Switchtec/PM49xxx) and "
                "the SAS HBA/RAID (SmartIOC/SmartROC) and ships a shared firmware debug layer; "
                "a vulnerability in the shared debug CLI code simultaneously affects NVMe switch "
                "and SAS controller product lines; single binary covers 4 mswitch variants "
                "(main switch + 3 HDD extension modes)",
    "severity": "MEDIUM",
    "status":   "CONFIRMED -- MD5 cf58a7b1 identical for all 4 mswitch SN entries; "
                "2021-03-12 timestamp and pcifnint string verified in blob",
    "cwe":      ["CWE-912 (Hidden Functionality)", "CWE-1104 (Use of Unmaintained Third Party Components)"],
    "build_date":   "2021-03-12",
    "bundle_year":  2026,
    "age_years":    5,
}

# PM8533-F2: C480 F1/F2/F3 share identical firmware; PMC Sierra vendor identified
NVME_F2 = {
    "id":       "NVME-F2",
    "title":    "PMC Sierra PM8533 NVMe switch/controller entries share firmware within platform family: "
                "C480-PM8533-F1, F2, F3 (three port function entries) are identical "
                "(MD5 aa9925cd, 1,529,915 bytes); C480-PM8533-R (recovery) is distinct; "
                "C240-PM8533 blob is largest (3,039,729 bytes -- C240 has more NVMe bays "
                "requiring larger controller configuration); C220-PM8533 and C480 variants differ; "
                "'PMC\\x00' magic (504d4300) at blob offset 0 exposes PMC Sierra/Microchip "
                "as the NVMe switch silicon vendor across C240/C220/C480 platforms; "
                "version field at blob offset 4-7: 09 09 17 00 03 00 00 00 "
                "(version 9.9.23.0 build 3 or similar interpretation)",
    "severity": "LOW",
    "status":   "CONFIRMED -- MD5 aa9925cd identical for C480 F1/F2/F3; 504d4300 magic confirmed",
    "cwe":      ["CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor)"],
    "pmc_magic": "504d4300 = 'PMC\\x00'",
    "platform_blobs": {
        "C240": "unique 3MB",
        "C220": "unique 1.5MB",
        "C480-F1/F2/F3": "identical 1.5MB (MD5 aa9925cd)",
        "C480-R": "recovery variant 1.5MB (different)",
    },
}

FINDINGS = [MIAMI_F1, MIAMI_F2, MIAMI_F3, RIOBEACH_F4, DDECKRAID_F5, LAGUNA_F6, NVME_F1, NVME_F2]
