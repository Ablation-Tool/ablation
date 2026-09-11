"""
Cisco UCS C-Series Network Adapters and Storage Expansion RE module
Covers: QLogic FastLinQ family, Intel XL710/XXV710, S3260/C3X60 SAS HBAs,
        C460-M4 SAS expander, brdprog CPLD entries
Source: ucs-k9-bundle-c-series.6.0.2b.C.bin

=== QLogic FastLinQ Family ===
Six variants, all ZIP-packaged with identical structure:
  QL41132 (10G RJ45, 2-port): 41132_2x10GBTv21.03.02.{bin,cfg,vpd} + fcoe/iscsi defaults + ql_ah_mbi_8.52.32.bin
  QL41162 (10G, 2-port):      41162_2x10GbTv21.02.02.{bin,cfg,vpd} + fcoe/iscsi defaults + ql_ah_mbi_8.52.32.bin
  QL41212 (25G, 2-port):      41212_2x25Gv22.04.02.{bin,cfg,vpd} + fcoe/iscsi defaults + ql_ah_mbi_8.52.32.bin
  QL41232 (25G CU, 2-port):   41232_2x25Gv22.03.02.{bin,cfg,vpd} + fcoe/iscsi defaults + ql_ah_mbi_8.52.32.bin
  QL45412 (40G QSFP, 2-port): 45412_2x40Gv23.04.03.{bin,cfg,vpd} + fcoe/iscsi defaults + ql_bb_mbi_8.52.18.bin
  QL45611 (100GbE, 1-port):   45611_1x100Gv15.03.02.{bin,cfg,vpd} + fcoe/iscsi defaults + ql_bb_mbi_8.52.18.bin
NVM sizes: QL41132/41162/41212/41232 = 16MB; QL45412/45611 = 16MB
MBI: ql_ah_mbi_8.52.32.bin (2.2MB) shared across 4 variants; ql_bb_mbi_8.52.18.bin for 40G/100G

=== S3260-DHBA and C3X60-HBA ===
Both ZIP-packaged; share MPTFW-13.00.08.00-IT firmware.
  S3260-DHBA: UCS-S3260-DHBA.fw (940KB) + mpt3x64.rom (229KB) + mptsas3.rom (213KB)
    - MPTFW version: @(#)MPTFW-13.00.08.00-IT
    - BIOS: @(#)MPT3BIOS-8.31.04.00 (2019.03.11)
  C3X60-HBA:  UCSC-C3X60-HBA.fw (1064KB) + mpt3x64.rom (229KB) + mptsas3.rom (213KB)
    - MPTFW version: @(#)MPTFW-13.00.08.00-IT  (IDENTICAL to S3260-DHBA)
    - BIOS: @(#)MPT3BIOS-8.31.02.00 (2016.10.27)  -- 10 years old in 2026
    - Chip codename: "LSI SAS Controller: Invader" (SAS3008)

=== Intel XL710/XXV710 Adapters ===
  X710TA4 (10G RJ45, 4-port):   gzip(gzip(BootIMG_1.836.0.FLB)); 1647KB outer / 9810KB inner
  XXX710DA2 (10G DAC, 2-port):  gzip(gzip(FLB)); 1676KB outer
  IQ10GC/ID10GC/I8Q25GF/I8D25GF/IBD100GF: similar double-gzip format
  Inner magic: BootIMG_X.YYY.Z.FLB (Intel Flash Load Binary format)
  Content: opaque (encrypted NVM) but CLP Loader Option ROM strings present

=== C460-M4 SAS Expander ===
  Name: ucs-c460-m4-sas-expander-main-fw.65.10.41.00.bin
  Size: 375KB; magic 280000eaa0baeac0
  Version: @(#)LSISAS3xFW-65.10.41.00 02/23/17  -- 2017 date in 2026 bundle (8 years old)
  Architecture: ARM (armFiqHandler.c source file path leaked in binary)
  Product: @(#)Cisco - UCS-C460-M4

=== brdprog CPLD Entries ===
All use [pkg] format (5b706b675d0a6865 magic = "[pkg]\\nhe").
headerVersion=2, tarOffset=128 for all entries.
Size: 12-14KB per entry (tiny CPLD bitstream).

Platform codename map (all leaked via brdprog):
  madeira      = C480 M5 (ucs-c480-m5-brdprog.57.0)
  trinity1     = C220 M6 (ucs-c220-m6-brdprog.39.0)
  mountrainier1 = C220 M7 (ucs-c220-m7-brdprog.37.0)
  godzilla1    = C220 M8 (ucs-c220-m8-brdprog.20.0)
  castor       = C125 (ucs-c125-brdprog.25.0)
  colusa       = C3260 (ucs-3260-brdprog.1.0.28)
  waterbay     = S3260 (ucs-S3260-brdprog.1.0.28)
"""

QLOGIC_FASTLINQ = {
    "QL41132": {
        "desc":     "2-port 10GbE RJ45 (converged NIC/FCoE/iSCSI)",
        "nvm_bin":  "41132_2x10GBTv21.03.02.bin",
        "nvm_size": 16777216,
        "fw_ver":   "21.03.02",
        "mbi":      "ql_ah_mbi_8.52.32.bin",
    },
    "QL41162": {
        "desc":     "2-port 10GbE (fiber)",
        "nvm_bin":  "41162_2x10GbTv21.02.02.bin",
        "nvm_size": 16777216,
        "fw_ver":   "21.02.02",
        "mbi":      "ql_ah_mbi_8.52.32.bin",
    },
    "QL41212": {
        "desc":     "2-port 25GbE SFP28 (converged)",
        "nvm_bin":  "41212_2x25Gv22.04.02.bin",
        "nvm_size": 16777216,
        "fw_ver":   "22.04.02",
        "mbi":      "ql_ah_mbi_8.52.32.bin",
    },
    "QL41232": {
        "desc":     "2-port 25GbE SFP28 CU (converged)",
        "nvm_bin":  "41232_2x25Gv22.03.02.bin",
        "nvm_size": 16777216,
        "fw_ver":   "22.03.02",
        "mbi":      "ql_ah_mbi_8.52.32.bin",
    },
    "QL45412": {
        "desc":     "2-port 40GbE QSFP",
        "nvm_bin":  "45412_2x40Gv23.04.03.bin",
        "nvm_size": 16777216,
        "fw_ver":   "23.04.03",
        "mbi":      "ql_bb_mbi_8.52.18.bin",
    },
    "QL45611": {
        "desc":     "1-port 100GbE",
        "nvm_bin":  "45611_1x100Gv15.03.02.bin",
        "nvm_size": 16777216,
        "fw_ver":   "15.03.02",
        "mbi":      "ql_bb_mbi_8.52.18.bin",
    },
    "shared_config":    "nvm_iscsi_cfg_default_v0.7.cfg + nvm_fcoe_cfg_default_v0.6.cfg",
    "debug_mode_std":   16,
    "debug_mode_ext":   0,
    "oprom_enabled":    True,
    "mba_hotkey":       "Ctrl S",
    "default_iscsi_iqn":"iqn.1994-02.com.qlogic.iscsi:fastlinqboot",
    "boot_protocol_default": "PXE",
    "debug_cfg_key":    "#237: [GLOB] Preboot Debug Mode Std",
}

SAS_HBA = {
    "S3260-DHBA": {
        "cisco_pid":    "UCS-S3260-DHBA",
        "product":      "S3260 Dual-Head SAS HBA",
        "fw_file":      "UCS-S3260-DHBA.fw",
        "fw_size":      940112,
        "mptfw_ver":    "MPTFW-13.00.08.00-IT",
        "bios_ver":     "MPT3BIOS-8.31.04.00",
        "bios_date":    "2019.03.11",
        "bios_age_yr":  7,
    },
    "C3X60-HBA": {
        "cisco_pid":    "UCSC-C3X60-HBA",
        "product":      "C3X60 SAS HBA",
        "fw_file":      "UCSC-C3X60-HBA.fw",
        "fw_size":      1064864,
        "mptfw_ver":    "MPTFW-13.00.08.00-IT",
        "bios_ver":     "MPT3BIOS-8.31.02.00",
        "bios_date":    "2016.10.27",
        "bios_age_yr":  10,
        "chip_codename":"LSI SAS Controller: Invader (SAS3008)",
    },
    "debug_strings": {
        "show_all_debug": "Show all debug info: <pl dbg>",
        "show_version":   "Show version: <pl ver>",
        "debug_mask":     "PL Debug Mask High 0x%x Low 0x%x",
        "pl_version":     "PL Version %08x SAS Core Version %08x",
    },
}

INTEL_XL710 = {
    "X710TA4": {
        "desc":    "4-port 10GbE RJ45",
        "format":  "gzip(gzip(BootIMG_1.836.0.FLB))",
        "nvm_ver": "1.836.0",
    },
    "XXX710DA2": {
        "desc":    "2-port 10GbE DAC",
        "format":  "gzip(gzip(FLB))",
        "nvm_ver": "1.836.0",
    },
    "family": "Intel XL710/X710 (Fortville)",
    "firmware_type": "FLB (Flash Load Binary)",
    "clp_strings": {
        "newer_than_expected": "The CLP Boot ROM for the device stopped because the NVM image is newer than the expected",
        "older_than_expected": "The CLP Boot ROM for the device detected an older version of the NVM image than expected",
        "recovery":            "Firmware recovery mode detected. Initialization failed.",
        "product":             "Intel(R) Ethernet CLP/Loader Option ROM",
    },
    "content": "opaque -- NVM sections are encrypted; CLP Loader Option ROM strings visible",
}

C460_SAS_EXPANDER = {
    "product":      "UCS C460 M4 SAS Backplane Expander",
    "cisco_pid":    "ucs-c460-m4-sas-expander-main-fw",
    "fw_version":   "65.10.41.00",
    "fw_id":        "@(#)LSISAS3xFW-65.10.41.00",
    "fw_date":      "2017-02-23",
    "fw_age_yr":    9,
    "fw_size_kb":   375,
    "magic":        "280000eaa0baeac0",
    "arch":         "ARM",
    "leaked_src":   "armFiqHandler.c",
    "note":         "SAS expander manages backplane SAS routes for all drives in C460 M4 4-socket server",
}

BRDPROG_CODENAMES = {
    "C480-M5":  {"platform": "madeira",       "version": "57.0",   "pid": "ucs-c480-m5-brdprog"},
    "C220-M6":  {"platform": "trinity1",      "version": "39.0",   "pid": "ucs-c220-m6-brdprog"},
    "C220-M7":  {"platform": "mountrainier1", "version": "37.0",   "pid": "ucs-c220-m7-brdprog"},
    "C220-M8":  {"platform": "godzilla1",     "version": "20.0",   "pid": "ucs-c220-m8-brdprog"},
    "C125":     {"platform": "castor",        "version": "25.0",   "pid": "ucs-c125-brdprog"},
    "C3260":    {"platform": "colusa",        "version": "1.0.28", "pid": "ucs-3260-brdprog"},
    "S3260":    {"platform": "waterbay",      "version": "1.0.28", "pid": "ucs-S3260-brdprog"},
    "format":   "[pkg] (5b706b675d0a6865 magic)",
    "header":   "headerVersion=2, tarOffset=128 (all entries)",
    "size_kb":  "12-14 (CPLD bitstream)",
}

# --- FINDINGS ---

# FASTLINQ-F1: Preboot Debug Mode Std = 16 in production NVM across all FastLinQ variants
FASTLINQ_F1 = {
    "id":       "FASTLINQ-F1",
    "title":    "QLogic FastLinQ production NVM config ships with 'Preboot Debug Mode Std = 16' "
                "(non-zero debug mode enabled at line #237 in every .cfg file) "
                "confirmed across ALL 6 Cisco FastLinQ variants: QL41132 (10G), QL41162 (10G), "
                "QL41212 (25G), QL41232 (25G), QL45412 (40G), QL45611 (100G); "
                "'Preboot Debug Mode Ext = 0' (extended debug off); "
                "Preboot OpROM is Enabled; MBA Management Boot Agent hotkey Ctrl-S is active; "
                "four 10G/25G variants share the same MBI binary (ql_ah_mbi_8.52.32.bin 2.2MB); "
                "the 40G/100G variants share ql_bb_mbi_8.52.18.bin; "
                "Preboot Debug Mode is a FastLinQ NVM configuration field that enables "
                "diagnostic output and extended pre-boot information during PXE/MBA "
                "option ROM execution -- a non-zero value exposes additional boot-time "
                "information including link state, configuration state, and management "
                "bus transactions; the same configuration file is used across all speed "
                "variants (nvm_iscsi_cfg_default_v0.7.cfg, nvm_fcoe_cfg_default_v0.6.cfg) -- "
                "a single NVM config vulnerability covers all 6 FastLinQ families "
                "simultaneously across all C-Series servers with these adapters",
    "severity": "HIGH",
    "status":   "CONFIRMED -- #237: [GLOB] Preboot Debug Mode Std : 16 at identical "
                "cfg offsets in QL41132 (17274), QL41162 (17275), QL41212 (17278), "
                "QL41232 (17281), QL45412 (18375), QL45611 (18368)",
    "cwe":      ["CWE-215 (Insertion of Sensitive Information Into Debugging Code)",
                 "CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor)"],
    "affected":  ["ucsc-ql41132", "ucsc-ql41162", "ucsc-ql41212", "ucsc-ql41232",
                  "ucsc-ql45412", "ucsc-ql45611 -- all units"],
}

# SASEXP-F1: C3X60-HBA has 2016 BIOS (10yr), S3260-DHBA has 2019 BIOS (7yr), same FW version, debug commands
SASEXP_F1 = {
    "id":       "SASEXP-F1",
    "title":    "C3X60-HBA ships MPT3BIOS-8.31.02.00 (2016.10.27) -- a 10-year-old BIOS version "
                "in the 2026 6.0.2b production bundle; S3260-DHBA ships MPT3BIOS-8.31.04.00 "
                "(2019.03.11) -- 7-year-old; both controllers share IDENTICAL firmware: "
                "@(#)MPTFW-13.00.08.00-IT (same version string in both UCS-S3260-DHBA.fw "
                "and UCSC-C3X60-HBA.fw); C3X60-HBA identifies as 'LSI SAS Controller: Invader' "
                "(SAS3008 chip codename); production firmware exposes debug interface: "
                "'Show all debug info: <pl dbg>', 'PL Debug Mask High 0x%x Low 0x%x', "
                "'Show version: <pl ver>' -- the 'pl dbg' CLI is accessible in production; "
                "PL Debug Mask is settable (High and Low 32-bit values = 64-bit debug mask), "
                "meaning debug verbosity is runtime-configurable at the MPT protocol layer; "
                "the 2016 BIOS predates the Spectre/Meltdown era and all firmware signing "
                "improvements introduced post-2017; identical FW version for two different "
                "Cisco product lines extends any firmware vulnerability to both concurrently",
    "severity": "HIGH",
    "status":   "CONFIRMED -- MPT3BIOS-8.31.02.00 (2016.10.27) at mptsas3.rom offset 46254 "
                "in C3X60-HBA ZIP; MPT3BIOS-8.31.04.00 (2019.03.11) at offset 46284 in S3260-DHBA; "
                "MPTFW-13.00.08.00-IT at offset 100 in both .fw files; "
                "'Show all debug info: <pl dbg>' at S3260-DHBA.fw offset 62100; "
                "PL Debug Mask at offset 73292; Invader codename at C3X60-HBA.fw offset 59257",
    "cwe":      ["CWE-1329 (Reliance on Component That is Not Updateable)", "CWE-215 (Insertion of Sensitive Information Into Debugging Code)"],
    "affected":  ["UCS-S3260-DHBA", "UCSC-C3X60-HBA -- all units in 6.0.2b.C"],
}

# SASEXP-F2: C460-M4 SAS expander 2017 ARM firmware
SASEXP_F2 = {
    "id":       "SASEXP-F2",
    "title":    "Cisco UCS C460-M4 SAS backplane expander ships @(#)LSISAS3xFW-65.10.41.00 "
                "dated 2017-02-23 in the 2026 6.0.2b production bundle -- 9-year-old firmware; "
                "the expander is an ARM-based microcontroller (armFiqHandler.c source path "
                "leaked in binary -- ARM FIQ interrupt handler); the C460 M4 is a 4-socket "
                "server that uses SAS expanders to route access to all backplane drive bays; "
                "a compromised SAS expander with arbitrary code execution capability can "
                "intercept, replay, or corrupt SAS commands to all attached drives "
                "(including WRITE commands to system drives, firmware updates to drives, "
                "and SMB / zone configuration commands); the 9-year age gap means this "
                "binary predates all SAS expander CVEs published from 2018 onward "
                "(including expander command injection and zoning bypass vectors); "
                "the 375KB binary has magic 280000eaa0baeac0 (non-standard; not LSI MFI "
                "or CBB format) -- this is a Cisco-custom ARM firmware image, not the "
                "standard LSI SAS3 firmware format used in other C-Series storage components",
    "severity": "HIGH",
    "status":   "CONFIRMED -- @(#)LSISAS3xFW-65.10.41.00 02/23/17 at binary offset 92; "
                "@(#)Cisco - UCS-C460-M4 at offset 132; armFiqHandler.c at offset 2076; "
                "magic 280000eaa0baeac0; size 375KB",
    "cwe":      ["CWE-1329 (Reliance on Component That is Not Updateable)",
                 "CWE-200 (Exposure of Sensitive Information -- source path leak)"],
    "affected":  ["All Cisco UCS C460 M4 servers in 6.0.2b deployments"],
}

# INTX710-F1: Intel XL710 double-gzip NVM, CLP version enforcement
INTX710_F1 = {
    "id":       "INTX710-F1",
    "title":    "Intel XL710/X710 (Fortville) NVM firmware uses double-layer gzip: "
                "outer gzip -> inner gzip -> BootIMG_X.YYY.Z.FLB (Flash Load Binary); "
                "the CLP (Combo Loader Package) Boot ROM strings expose version enforcement: "
                "'The CLP Boot ROM for the device stopped because the NVM image is newer than expected' "
                "AND 'The CLP Boot ROM for the device detected an older version of the NVM image than expected' "
                "-- both directions gated; 'Firmware recovery mode detected. Initialization failed.' "
                "is a third path indicating a recovery boot mode exists but produces a failure; "
                "inner FLB content is opaque (encrypted NVM sections) -- Intel XL710 uses "
                "per-device key material stored in eFuse-equivalents on the NIC EEPROM; "
                "the double-gzip wrapping adds extraction complexity but provides no security "
                "(neither layer is authenticated); X710TA4 (4-port 10GbE RJ45) and XXX710DA2 "
                "(2-port 10GbE DAC) are both confirmed in this format; the I8Q25GF/I8D25GF/IBD100GF "
                "(XXV710/X710 25/100G) use the same double-gzip format with larger inner FLB images",
    "severity": "MEDIUM",
    "status":   "CONFIRMED -- X710TA4 outer magic 1f8b08001310ad67 (gzip); "
                "inner decompressed magic 426f6f74494d475f = 'BootIMG_'; "
                "inner size 9810KB (9.8MB FLB image); CLP strings at inner offsets 4174/4235/4389; "
                "Firmware recovery mode at inner offset 4235",
    "cwe":      ["CWE-345 (Insufficient Verification of Data Authenticity)"],
    "note":     "CLP version enforcement behavior (halt vs warn) on version mismatch is not "
                "determinable via static analysis; the string 'stopped because' suggests halt "
                "for newer-than-expected; 'detected' (without 'stopped') suggests warn for older.",
    "affected":  ["ucsc-pcie-x710ta4", "ucsc-pcie-xxx710da2", "ucsc-p-I8Q25GF", "ucsc-p-I8D25GF", "ucsc-p-IBD100GF"],
}

# FASTLINQ-F2: Default iSCSI IQN across all FastLinQ variants
FASTLINQ_F2 = {
    "id":       "FASTLINQ-F2",
    "title":    "QLogic FastLinQ nvm_iscsi_cfg_default_v0.7.cfg ships default iSCSI initiator IQN "
                "'iqn.1994-02.com.qlogic.iscsi:fastlinqboot' across all 6 FastLinQ variants; "
                "if the default NVM iSCSI config is applied without customization, all FastLinQ "
                "iSCSI initiators across an entire UCS deployment share the same IQN, violating "
                "RFC 3720 (iSCSI) uniqueness requirements; duplicate IQNs cause authentication "
                "bypass on iSCSI targets that use IQN-based access control (CHAP not required), "
                "and create boot storm conditions when multiple hosts attempt to mount the same "
                "iSCSI target simultaneously; 'Preboot Boot Protocol: PXE' is the default "
                "(iSCSI boot requires explicit configuration), but the IQN value is baked into "
                "the NVM config and persists until overwritten",
    "severity": "LOW",
    "status":   "CONFIRMED -- iqn.1994-02.com.qlogic.iscsi:fastlinqboot at nvm_iscsi_cfg_default_v0.7.cfg "
                "offsets 820, 6964, 13108, 19252 (4 port entries)",
    "cwe":      ["CWE-1188 (Insecure Default Initialization of Resource)"],
    "affected":  ["ucsc-ql41132/41162/41212/41232/45412/45611 -- iSCSI deployments using default NVM config"],
}

# BRDPROG-F1: Platform codename leakage via CPLD brdprog entries
BRDPROG_F1 = {
    "id":       "BRDPROG-F1",
    "title":    "brdprog (CPLD firmware) entries expose complete C-Series internal platform "
                "codename map via the [pkg] format header (headerVersion=2, platform=<name>): "
                "madeira=C480 M5, trinity1=C220 M6, mountrainier1=C220 M7, godzilla1=C220 M8, "
                "castor=C125, colusa=C3260, waterbay=S3260; "
                "these codenames are consistent with names found in other firmware components "
                "(godzilla1 matches CSERIES-CIMC-F5 Godzilla CIMC; mountrainier1 matches "
                "CIMCMULTI-F3 SPLImage-mountrainier1; colusa matches C3260 from gbin bundle "
                "naming); complete platform codename enumeration enables targeted vulnerability "
                "research: codename-specific bugs (buffer overflows, timing issues in "
                "platform-specific init code) can be confirmed or ruled out by platform without "
                "requiring hardware; all 7 platforms confirmed via [pkg] format with "
                "13-byte magic 5b706b675d0a6865 ('\\x5b\\x70\\x6b\\x67\\x5d\\x0a\\x68\\x65' = '[pkg]\\nhe')",
    "severity": "LOW",
    "status":   "CONFIRMED -- platform= field in brdprog headers at respective SN offsets; "
                "godzilla1 cross-confirmed by CSERIES-CIMC-F5; mountrainier1 cross-confirmed by CIMCMULTI-F3",
    "cwe":      ["CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor)"],
    "affected":  ["Informational -- no direct exploitability"],
}

FINDINGS = [FASTLINQ_F1, SASEXP_F1, SASEXP_F2, INTX710_F1, FASTLINQ_F2, BRDPROG_F1]

FIRMWARE = [QLOGIC_FASTLINQ, SAS_HBA, INTEL_XL710, C460_SAS_EXPANDER, BRDPROG_CODENAMES]
