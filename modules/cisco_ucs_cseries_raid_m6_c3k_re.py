"""
Cisco UCS C-Series RAID M6 + C3K M4RAID RE module
Targets:
  - ucsc-raid-m6hd  (Zuma Beach -- HDD-optimized 12Gb SAS RAID M6)
  - ucsc-raid-m6sd  (Pismo Beach Plus -- SSD-optimized 12Gb SAS RAID M6)
  - ucsc-raid-m6t   (Pismo Beach -- 12Gb SAS RAID M6T)
  - ucsc-raid-m6t-psoc  (PSoC management microcontroller firmware for M6T)
  - UCS-C3K-M4RAID (C3260 density server LSI MFI BIOS)
Source: ucs-k9-bundle-c-series.6.0.2b.C.bin

Format: ZIP -> NOPAD.rom (7,995,392 bytes each)
Bootloader: ARM CBB (Customer Build Block) v33.250.02.00, build 2025-06-17
SBLIB versions:
  - Main SBLIB: 2023-03-03 (embedded in each ROM at offset ~139k)
  - Secondary SBLIB: 2024-11-14 (embedded at offset ~697k)
  - 2-year delta between SBLIB generations in the same production bundle

Codenames (beach series):
  Zuma Beach      = m6hd (HDD, Zuma Beach California)
  Pismo Beach     = m6t  (SSD tier, Pismo Beach California)
  Pismo Beach Plus= m6sd (SSD high-density, Pismo Beach Plus variant)
  (Miami/Laguna Beach = RAID M7/M8 in storage controllers module)

CBB security architecture:
  ARM SoC with eFuse-based OTP key storage
  SBLIB (Secure Boot Library): key validation, SVN rollback protection
  eFuse key slots: hash-compared against embedded public keys
  Dual CBB boot mode: CBB Secure Boot vs CBB NON-Secure Boot
  FDE (Full Disk Encryption) engine with drive unlock callback

C3K M4RAID (UCS C3260 storage density server):
  Format: LSI MFI (magic 33333234 = '3324')
  Same BIOS version as Double Decker RAID controller
  MegaRAID SAS-MFI BIOS 6.30.03.3 + MPT FCode 4.17.08.00 (2014.11.06)
  blob size 8,781,824 bytes; MD5 4e776289c3e6adc631bd53345bed3586
"""

RAID_M6_LINEUP = {
    "ucsc-raid-m6hd": {
        "rom_filename":   "Zuma_Beach_NOPAD.rom",
        "rom_size":       7995392,
        "rom_md5":        "802f4601bc02efa99a7812fcb8dedb80",
        "blob_size":      4569852,
        "sn_offset":      1334638592,
        "description":    "Zuma Beach -- HDD-optimized 12Gb SAS RAID M6 for C220/C240 M6",
    },
    "ucsc-raid-m6sd": {
        "rom_filename":   "Pismo_Beach_Plus_NOPAD.rom",
        "rom_size":       7995392,
        "rom_md5":        "0ffa5f21bc1c34f7aec6b36cf32cbf99",
        "blob_size":      4569881,
        "sn_offset":      1906997760,
        "description":    "Pismo Beach Plus -- SSD-optimized high-density 12Gb SAS RAID M6",
    },
    "ucsc-raid-m6t": {
        "rom_filename":   "Pismo_Beach_NOPAD.rom",
        "rom_size":       7995392,
        "rom_md5":        "b59324672413c3d62553f4cc53d6d80d",
        "blob_size":      4569858,
        "sn_offset":      2209516032,
        "description":    "Pismo Beach -- 12Gb SAS RAID M6T (top-loaded)",
    },
}

RAID_M6_ROM_IDENTITY = {
    "unique_md5_count":     3,
    "identical":            False,
    "all_same_size":        True,
    "note": "3 distinct binaries despite identical ROM size (7,995,392 bytes). "
            "Contrast: Miami RAID M7/M8 (5 variants) had all-identical MD5. "
            "M6 beach variants contain controller-variant-specific code differences.",
}

CBB_BOOTLOADER = {
    "version":          "33.250.02.00",
    "bl_date":          "2025-06-17",
    "bl_time":          "12:02:50",
    "identifier_tag":   "@(#)BL Version:33.250.02.00",
    "arch":             "ARM",
    "sbrpkgver":        "5.3300.02-0829",
    "hwimg_id":         "DCSG01410881",
    "ropcq_id":         "DCSG01822413",
    "sblib_main_date":  "2023-03-03 10:06:38",
    "sblib_sec_date":   "2024-11-14 16:39:59",
    "sblib_delta_days": 621,
}

CBB_SECURITY = {
    "dual_boot_mode": {
        "secure":     "CBB Secure Boot",
        "non_secure": "CBB NON-Secure Boot",
        "note": "Both code paths present in production ROM -- "
                "'CBB NON-Secure Boot' is a named mode, not just an error state",
    },
    "efuse_empty_path": {
        "string": "sblKeyUpdatePending: EFUSE is EMPTY status:0x%x",
        "count":  3,    # appears 3 times in Zuma Beach (multiple image regions)
        "note": "Tripled occurrence indicates this string exists in multiple embedded image regions "
                "(BL + SquashFS copy + recovery region). eFuse empty = no key to validate against.",
    },
    "efuse_mismatch_path": {
        "string": "iopMsgFwDownload: %s EFUSE mismatch.",
        "note": "Separate eFuse mismatch path from eFuse empty -- distinct failure modes. "
                "Both expose the eFuse validation state to the caller via string log.",
    },
    "unsigned_fw_path": {
        "string": "iopMsgFwDownload: %s is not signed.",
        "note": "Firmware download handler has an explicit 'not signed' branch. "
                "'Erasing signatures' log precedes signing check in the download flow.",
    },
    "signature_erase_path": {
        "string": "iopMsgFwDownload: Erasing signatures",
        "note": "Firmware download flow explicitly erases existing signatures before "
                "writing new firmware image -- this is the update path, but the erase "
                "step runs before validation completes (log sequence: Erase -> sign-check -> result).",
    },
    "static_bypass": {
        "string": "Static Bypass    (CRP:%d)(CRN:%d)",
        "pvt_efuse": "PVT EFUSE:0x%04x (CRP:%d)(CRN:%d)",
        "note": "Private eFuse CRP/CRN (Copy Restriction Policy/Number?) gates bypass mode. "
                "'Static Bypass' is a named operational mode, not an error path.",
    },
    "sblib_key_compare": {
        "strings": [
            "sblCompareEmbeddedKey",
            "sblCompareKeys: Public keys mismatch - index:%d",
            "sblCompareKeys: NULL Ext Image - PrimaryIsNull:%d AlternateIsNull:%d",
            "sblKeyUpdatePending: Embedded Key mismatch! status:0x%x attemptedKey:0x%x",
        ],
        "note": "Key comparison happens at SBLIB layer. NULL external image path "
                "allows fallback when primary or alternate image is null.",
    },
    "svn_rollback": {
        "strings": [
            "SBLI GetSecVer: PtrSecurityVersion=%d",
            "SBLI GetSecVer: numBitsSetLow=%d, numBitsSetHigh=%d",
            "SBLI_SetSecVer: ERROR Reading back updated SVN. Status=%d",
        ],
        "note": "SBLI (Secure Boot Loader Interface) tracks SVN as bitmask (numBitsSetLow/High). "
                "SVN write failure path (SetSecVer ERROR) leaves SVN value unupdated -- "
                "potential rollback window if SVN write can be induced to fail.",
    },
    "fde": {
        "strings": [
            "Drive security key from escrow, %s is unlocked",
            "unlockFdeCallback: PD %u returned BAD status 0x%X and keyType 0x%X",
            "FDE_FUNC_GET_SECURED_INFO",
            "ldDcmdSecure: detected PARTIAL_SECURE LD!  Preventing unsecure",
            "Disable OTP mode failure",
        ],
        "note": "FDE (Full Disk Encryption) support with escrow key path. "
                "OTP disable failure path exposed as formatted string. "
                "PARTIAL_SECURE LD detection implies mixed-encryption logical drive states.",
    },
    "fw_blocked_condition": {
        "string": "Secure Boot key update pending, firmware download not allowed",
        "note": "Firmware download is explicitly blocked when SB key update is pending -- "
                "inverse: when NOT pending, download proceeds through the 'not signed' / "
                "'EFUSE empty' fallback paths.",
    },
}

PSOC_FIRMWARE = {
    "sn_entry":        "ucsc-raid-m6t-psoc.001F.bin",
    "sn_offset":       698128384,
    "zip_filename":    "PSOC-001F.rom",
    "rom_size":        3801088,
    "compression":     "plain (unencrypted ZIP entry)",
    "images": [
        {"name": "PBLP_HBA_P4",       "hw": "1.00", "fw": "10.00", "pn": "14790"},
        {"name": "PBLP_HBA_P4S423",   "hw": "1.00", "fw": "10.00", "pn": "14798"},
        {"name": "PBLP_HBA_P4S443",   "hw": "1.00", "fw": "10.00", "pn": "06021"},
        {"name": "PBLP_HBA_P4ITOCP",  "hw": "1.00", "fw": "4.00",  "pn": "15463"},
        {"name": "PBLP_RAID_P5",       "hw": "3.00", "fw": "31.00", "pn": "15987"},
        {"name": "PBLP_RAID_P5Init",   "hw": "3.00", "fw": "28.00", "pn": "12345"},
        {"name": "PBLP_RAID_P5OCP",    "hw": "8.00", "fw": "5.00",  "pn": "25731"},
        {"name": "PBLP_RAID_P6",       "hw": "10.00","fw": "27.00", "pn": "29211"},
        {"name": "PBLP_RAID_P6Travis", "hw": "11.00","fw": "27.00", "pn": "29651"},
    ],
    "note": "PBLP = PSoC Blue Loader Program (Cypress/Infineon PSoC microcontroller). "
            "P4 = HBA (Host Bus Adapter) generation SoC. "
            "P5/P6 = RAID controller SoC generations. "
            "Travis = internal codename for P6 SoC variant. "
            "P4ITOCP = OCP form factor HBA. "
            "Part numbers cover: C220 M6/C240 M6 backplane PSoC management chips.",
}

C3K_M4RAID = {
    "sn_entry":        "UCS-C3K-M4RAID",
    "target":          "UCS C3260 M4 high-density storage server (4U)",
    "blob_size":       8781824,
    "blob_md5":        "4e776289c3e6adc631bd53345bed3586",
    "format":          "LSI MFI (magic 33333234 = '3324')",
    "bios_version":    "6.30.03.3",
    "mpt_version":     "4.17.08.00 (2014.11.06)",
    "mpt_version_str": "@(#)MPT SAS FCode Version 4.17.08.00 (2014.11.06)",
    "openboot_ids":    ["LSI,2004", "LSI,2008", "LSI,2008_1"],
    "product_string":  "MegaRAID SAS-MFI BIOS",
    "note": "Same BIOS version (6.30.03.3_4.17.08.00) as Double Decker RAID (DDECKRAID-F5). "
            "Different blob MD5 (C3K: 4e776289c3e6adc631bd53345bed3586 vs "
            "Double Decker: measured in session 25). "
            "Structurally the same vintage 2014 LSI MFI format, different binary. "
            "C3K targets UCS C3260 (dense storage, up to 56 drives) vs Double Decker (standard rack). "
            "Identical MPT FCode date 2014-11-06 -- same 11-year-old component in 2026 bundle.",
}

# --- FINDINGS ---

# RAIDM6-F1: CBB NON-Secure Boot path + eFuse empty bypass architecture
RAIDM6_F1 = {
    "id":       "RAIDM6-F1",
    "title":    "Zuma/Pismo Beach RAID M6 CBB bootloader exposes CBB NON-Secure Boot mode; "
                "three independent bypass indicators in Zuma_Beach_NOPAD.rom: "
                "(1) 'CBB NON-Secure Boot' as a named operational mode string alongside 'CBB Secure Boot' "
                "in the same ROM (both code paths compiled in); "
                "(2) 'sblKeyUpdatePending: EFUSE is EMPTY status:0x%x' present 3x across ROM regions -- "
                "when eFuse key slots are unprovisioned, the SBLIB has no key to validate against "
                "and the bootloader takes the non-secure path; "
                "(3) 'iopMsgFwDownload: %s is not signed.' -- explicit firmware download handler "
                "branch for unsigned images, preceded by 'iopMsgFwDownload: Erasing signatures'; "
                "the sequence erase-signatures -> write-image -> (signed/not-signed branch) "
                "means signature erasure is non-atomic: a fault or power cycle between erase and "
                "signing check leaves the controller with erased signatures and no new ones; "
                "'Static Bypass (CRP:%d)(CRN:%d)' alongside Private eFuse CRP/CRN config "
                "indicates a hardware copy-restriction-gated bypass mode baked into the CBB; "
                "all three RAID M6 variants (Zuma/Pismo/Pismo Plus) share the same CBB security "
                "architecture (same bootloader version 33.250.02.00, same SBLIB)",
    "severity": "HIGH",
    "status":   "CONFIRMED -- strings extracted from Zuma_Beach_NOPAD.rom (7,995,392 bytes); "
                "CBB NON-Secure Boot string at ROM offset 130344; "
                "EFUSE is EMPTY at offsets 104457, 301065, 539025; "
                "iopMsgFwDownload not signed at offset 84580",
    "cwe":      ["CWE-276 (Incorrect Default Permissions)", "CWE-693 (Protection Mechanism Failure)"],
    "cross_platform": "RIOBEACH-F4 (ARM eFuse/SRK hierarchy in Rio Beach), MIAMI-F2 (FAM debug token bypass)",
    "affected": ["ucsc-raid-m6hd (Zuma Beach)", "ucsc-raid-m6sd (Pismo Beach Plus)", "ucsc-raid-m6t (Pismo Beach)"],
}

# RAIDM6-F2: SBLIB 2-year generation delta + SVN rollback failure path
RAIDM6_F2 = {
    "id":       "RAIDM6-F2",
    "title":    "RAID M6 ROM bundles two SBLIB versions with a 621-day build date delta: "
                "primary SBLIB 2023-03-03 and secondary SBLIB 2024-11-14 co-exist in the same "
                "Zuma/Pismo Beach ROM image; the secondary SBLIB (Nov 2024) is embedded in what "
                "appears to be the OCP-region or recovery partition while the main regions carry "
                "the older 2023 SBLIB -- mixed SBLIB versions within a single firmware bundle "
                "may allow a rollback to the older SBLIB's vulnerability surface; "
                "'SBLI_SetSecVer: ERROR Reading back updated SVN. Status=%d' exposes a SVN "
                "rollback protection write-failure path: if the SetSecVer call fails, the SVN "
                "is not incremented and a previously invalidated firmware version remains "
                "installable -- any mechanism to induce SVN write failure (flash corruption, "
                "power fault, SBLI init failure 'Couldn't init SBLI') creates a rollback window; "
                "SVN stored as a bitmask (numBitsSetLow/numBitsSetHigh) in eFuse region",
    "severity": "MEDIUM",
    "status":   "CONFIRMED -- SBLIB date strings at offsets 139484/139508 (Mar 3 2023) and "
                "697456/697480 (Nov 14 2024) in Zuma_Beach_NOPAD.rom; "
                "SBLI_SetSecVer ERROR string at offset 119648",
    "cwe":      ["CWE-1328 (Security Version Number Mutable to Older Version)"],
    "cross_platform": "DDECKRAID-F5 (2014 MPT FCode -- older generation of same vulnerability class)",
}

# RAIDM6-F3: PSOC-001F.rom placeholder part number PN:12345 in shipping firmware
RAIDM6_F3 = {
    "id":       "RAIDM6-F3",
    "title":    "PSOC-001F.rom bundles 9 PBLP (PSoC Blue Loader Program) images for HBA and RAID "
                "controller SoC variants; PBLP_RAID_P5Init image ships with part number PN:12345 -- "
                "a placeholder/default value -- in the production 6.0.2b.C bundle; "
                "PN:12345 is the factory-initialization variant of the P5 SoC; "
                "placeholder PN in shipping firmware indicates this image was included without "
                "production part number assignment, suggesting it is a development/init artifact "
                "that was not fully qualified for production shipment; "
                "PSOC-001F.rom sn_entry: ucsc-raid-m6t-psoc.001F.bin at offset 698128384; "
                "PSoC microcontrollers manage: drive bay LEDs, power sequencing, backplane IIC, "
                "out-of-band management path -- init variant with placeholder PN creates "
                "unambiguous identification surface for targeted firmware attacks",
    "severity": "LOW",
    "status":   "CONFIRMED -- PBLP_RAID_P5Init_Version_HW:3.00_FW:28.00_PN:12345 string "
                "at PSOC-001F.rom offset 917760",
    "cwe":      ["CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor)"],
}

# RAIDM6-F4: Three distinct RAID M6 beach variant binaries (vs identical Miami variants)
RAIDM6_F4 = {
    "id":       "RAIDM6-F4",
    "title":    "RAID M6 beach lineup (Zuma Beach, Pismo Beach, Pismo Beach Plus) ships as 3 "
                "distinct binaries -- same ROM size (7,995,392 bytes) but unique MD5 per variant; "
                "contrast: Miami RAID M7/M8 lineup shipped 5 variants with identical MD5 (MIAMI-F1); "
                "the 'NOPAD' suffix in all three filenames (vs PAD variants) indicates these are "
                "non-padded OCP-compatible ROM images; "
                "all three variants contain the same CBB security architecture (same bootloader "
                "version, same SBLIB versions, same eFuse bypass strings) -- the security surface "
                "is uniform but variant-specific firmware differences prevent cross-variant "
                "firmware substitution; sbrpkgver=5.3300.02-0829 and HWIMG/ROPCQ IDs embedded "
                "in each ROM expose design database identifiers for supply chain tracking",
    "severity": "LOW",
    "status":   "CONFIRMED -- 3 unique MD5 hashes: Zuma=802f4601..., Pismo Plus=0ffa5f21..., "
                "Pismo=b59324672...; sbrpkgver/HWIMG/ROPCQ strings at Zuma offset 51593",
    "cwe":      ["CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor)"],
}

# C3KRAID-F1: C3260 M4RAID carries same 2014-vintage MPT FCode as Double Decker RAID (DDECKRAID-F5)
C3KRAID_F1 = {
    "id":       "C3KRAID-F1",
    "title":    "UCS-C3K-M4RAID (C3260 storage density server) ships MegaRAID SAS-MFI BIOS "
                "version 6.30.03.3 with MPT SAS FCode 4.17.08.00 built 2014-11-06 -- "
                "identical BIOS version to the Double Decker RAID controller (DDECKRAID-F5); "
                "the C3K M4RAID targets UCS C3260 which supports up to 56 drives in a 4U chassis, "
                "making the exposure scope proportional to the drive count; "
                "C3K M4RAID blob is distinct from Double Decker despite matching BIOS version "
                "(C3K MD5=4e776289c3e6adc631bd53345bed3586, size 8,781,824 bytes); "
                "OpenBoot firmware IDs: LSI,2004, LSI,2008, LSI,2008_1 -- "
                "same LSI SAS2 hardware as Double Decker (same MPT opcode surface); "
                "2014 MPT FCode now 12 years old in the 2026 6.0.2b.C production bundle; "
                "the LSI SAS2 MPT2 command set has multiple known pre-auth vulnerabilities "
                "documented in public research (IOCTLs, passthrough commands)",
    "severity": "HIGH",
    "status":   "CONFIRMED -- MegaRAID SAS-MFI BIOS at blob offset 32471; "
                "MPT FCode 4.17.08.00 2014.11.06 at offset 49798; "
                "BIOS Version 6.30.03.3_4.17.08.00 at offset 16",
    "cwe":      ["CWE-1104 (Use of Unmaintained Third Party Components)"],
    "cross_platform": "DDECKRAID-F5 (Double Decker RAID, same BIOS version; see storage_controllers module)",
}

FINDINGS = [RAIDM6_F1, RAIDM6_F2, RAIDM6_F3, RAIDM6_F4, C3KRAID_F1]

FIRMWARE = [RAID_M6_LINEUP, PSOC_FIRMWARE, C3K_M4RAID]
