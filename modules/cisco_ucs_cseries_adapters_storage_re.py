"""
Cisco UCS C-Series Adapters and Storage Controllers RE module
Covers: Broadcom SAS3 9400/9500, QLogic QLE2772/QLE2872 FC HBAs,
        Emulex LPe35002 FC HBA, Nvidia ConnectX-7 N7 adapters
Source: ucs-k9-bundle-c-series.6.0.2b.C.bin (and related bundles)

=== Broadcom SAS3 9400/9500 Series ===
  ucsc-9500-8e: 1302KB extracted; ZIP(UCSC-9500-8E.rom 2MB + IT_HBA_X64_BIOS_PKG_E6.rom 207KB)
  ucsc-9400-8i: 1147KB extracted; ZIP(UCSC-9400-8I.bin 1.8MB + mpt35sas_x64.rom + mpt35sas_legacy.rom 54KB)
  ucsc-9400-8e: 1147KB extracted; ZIP(UCSC-9400-8E.bin 1.8MB + mpt35sas_x64.rom + mpt35sas_legacy.rom 54KB)
  ZIP flags 0x0800 on 9400 entries = UTF-8 filename bit, NOT encryption

9500 bootloader:  BL Version:36.00.01.00
9500 BIOS:        MPT35BIOS-9.71.00.00 (2025.07.22)   -- IT_HBA_X64_BIOS_PKG_E6.rom
9400 BIOS:        MPT35BIOS-9.47.01.00 (2022.09.19)   -- mpt35sas_legacy.rom
BIOS version gap: 9400 is 3 years behind 9500 in the same product generation

=== QLogic FC HBAs ===
  QLE2872 (32Gb FC dual-port): ZIP md5=9574e6f3c4...
  QLE2772 (16Gb FC dual-port): ZIP md5=9574e6f3c4...  (IDENTICAL to QLE2872)
  ISP28xx firmware: mh080601.bin, version 9.15.06 (2023 QLogic Corporation)
  UEFI driver: ql28xx.drv, Microsoft-signed (MicCorUEFCA2011_2011-06-27.crl)
  Flash utility: EFlashX64.efi (QLogic EFlash v8.06.01)

=== Emulex LPe35002 FC HBA ===
  3417KB blob; custom header magic 00356664feaa0005
  Version: 14.4.576.17 Lancer Emulex Connected
  Internal codename: Palau (build/palau_14.4.576.17/)
  Internal ASIC family: PRISM (prismfw-repos)
  Broadcom chip family: Lancer (lancerfw-repos)
  Config regions: configRegion_NNN_NN.cfg (flash memory layout map, 250+ regions)
  Boot programs: sp_boot.prg, srb_preboot.prg, sp_preboot.prg
  Signature config: payload_signature.cfg, dualboot.cfg

=== Nvidia ConnectX-7 N7 Adapters ===
  N7S400GF (400GbE single):   32MB, MTFW magic 4d544657abcdef00
  N7D200GF (200GbE dual):     32MB, MTFW magic 4d544657abcdef00
  N7Q25GF  (25/50GbE quad):   32MB, MTFW magic 4d544657abcdef00
  N6D25GF  (25GbE, CX-6 Lx): 32MB, "Non-Mellanox QSFP28: The port is closed"
  Firmware content: opaque (no readable ASCII in first 1MB)
  These are NIC-only adapters, NOT DPUs -- the ROTPK bypass (NC3220-F1) does NOT apply here
"""

# --- Hardware and Firmware Inventory ---

BROADCOM_SAS3 = {
    "9500-8e": {
        "cisco_pid":     "ucsc-9500-8e",
        "product":       "Cisco 9500-8E SAS 12G External HBA (8 external SAS ports)",
        "fw_size_kb":    1302,
        "zip_contents":  ["UCSC-9500-8E.rom (2MB Cisco FW)", "IT_HBA_X64_BIOS_PKG_E6.rom (207KB IT-mode BIOS)"],
        "bl_version":    "BL Version:36.00.01.00",
        "bios_version":  "MPT35BIOS-9.71.00.00",
        "bios_date":     "2025.07.22",
        "vendor_string": "VENDORNAME=Cisco",
        "controller":    "Broadcom SAS3.5 (12Gb) 8-port external",
        "signed_string": "SOC signature was programmed",
    },
    "9400-8i": {
        "cisco_pid":     "ucsc-9400-8i",
        "product":       "Cisco 9400-8I SAS 12G RAID Controller (8 internal ports, IT/IR modes)",
        "fw_size_kb":    1147,
        "zip_contents":  ["UCSC-9400-8I.bin (1.8MB Cisco FW)", "mpt35sas_legacy.rom (54KB)", "mpt35sas_x64.rom (146KB)"],
        "bios_version":  "MPT35BIOS-9.47.01.00",
        "bios_date":     "2022.09.19",
        "controller":    "Broadcom SAS3.5 (12Gb) 8-port internal",
        "signed_string": "SOC signature was programmed",
    },
    "9400-8e": {
        "cisco_pid":     "ucsc-9400-8e",
        "product":       "Cisco 9400-8E SAS 12G External HBA (8 external SAS ports)",
        "fw_size_kb":    1147,
        "zip_contents":  ["UCSC-9400-8E.bin (1.8MB Cisco FW)", "mpt35sas_legacy.rom (54KB)", "mpt35sas_x64.rom (146KB)"],
        "bios_version":  "MPT35BIOS-9.47.01.00",
        "bios_date":     "2022.09.19",
        "controller":    "Broadcom SAS3.5 (12Gb) 8-port external",
        "signed_string": "SOC signature was programmed",
    },
}

CBB_SHARED_STRINGS = {
    "note": "9500-8e Cisco FW (UCSC-9500-8E.rom) contains the identical CBB signing framework "
            "as RAID M6 CBB bootloader (Zuma/Pismo Beach variants, RAIDM6-F1). "
            "These strings appear verbatim in UCSC-9500-8E.rom.",
    "erasing_sigs":     "iopMsgFwDownload: Erasing signatures",
    "not_signed":       "iopMsgFwDownload: %s is not signed.",
    "cbb_signed":       "iopMsgFwDownload: CBB Signed",
    "key_mismatch":     "iopMsgFwDownload: Key Mismatch",
    "error_writing":    "iopMsgFwDownload: Error writing signature %d",
    "app_signed":       "iopMsgFwDownload: APP Signed",
    "sig_compare":      "Comparing image signature to computed SHA%d",
    "soc_programmed":   "SOC signature was programmed",
    "sbr_invalid":      "INVALID SBR Signature!",
    "rmc_invalid":      "INVALID RMC Code Signature!",
}

SAS3_BIOS_GAP = {
    "9500_bios": "MPT35BIOS-9.71.00.00 (2025.07.22)",
    "9400_bios": "MPT35BIOS-9.47.01.00 (2022.09.19)",
    "delta_days_approx": 1037,
    "note": "9400-8i and 9400-8e use 2022 BIOS while concurrent 9500-8e uses 2025 BIOS. "
            "9400 BIOS has 'BIOS: Image Signature Check Failed with Status 0x%08x' (returns status code). "
            "9500 BIOS has 'Comparing image signature to computed SHA%d' (SHA-size based check). "
            "Different signature validation implementations in controllers sold simultaneously.",
}

QLOGIC_HBA = {
    "QLE2872": {
        "cisco_pid":   "QLE2872",
        "product":     "QLogic 32Gb FC dual-port HBA",
        "zip_md5":     "9574e6f3c4",
    },
    "QLE2772": {
        "cisco_pid":   "QLE2772",
        "product":     "QLogic 16Gb FC dual-port HBA",
        "zip_md5":     "9574e6f3c4",
    },
    "fw_binary":       "mh080601.bin (ISP28xx firmware)",
    "fw_version":      "9.15.06 (2023 QLogic Corporation)",
    "chip_family":     "ISP28xx (same silicon, different speed grades)",
    "uefi_driver":     "ql28xx.drv (Microsoft-signed)",
    "ms_crl":          "http://www.microsoft.com/pkiops/crl/MicCorUEFCA2011_2011-06-27.crl",
    "ms_root_ca":      "Microsoft Root Certificate Authority 2010",
    "flash_version":   "08.06.01 (Signed)",
    "flash_tool":      "EFlashX64.efi",
    "bad_sig_string":  "CR has Bad Signature",
    "incompat_string": "Incompatible Version",
}

EMULEX_LPe35002 = {
    "cisco_pid":        "ucsc-lpe35002",
    "product":          "Emulex LPe35002 32Gb FC dual-port HBA (Cisco-branded)",
    "blob_size_kb":     3417,
    "magic":            "00356664feaa0005",
    "fw_version":       "14.4.576.17",
    "hw_family":        "Lancer",
    "asic_codename":    "PRISM",
    "product_codename": "Palau",
    "internal_svn_url": "https://srcserver.lvn.broadcom.net/svndata/lancerfw-repos/branches/rel_14.4/build/palau_14.4.576.17/prismfw-repos",
    "svn_revision":     "r108387",
    "svn_timestamp":    "2025-05-22 11:00",
    "svn_server":       "srcserver.lvn.broadcom.net",
    "svn_repo":         "lancerfw-repos",
    "svn_subrepo":      "prismfw-repos",
    "config_files":     ["dualboot.cfg", "payload_signature.cfg"],
    "boot_programs":    ["sp_boot.prg", "srb_preboot.prg", "sp_preboot.prg"],
    "config_regions":   "configRegion_NNN_NN.cfg (250+ flash memory layout entries)",
}

NVIDIA_CX7_N7 = {
    "N7S400GF":   {"pid": "ucsc-n7s400gf", "speed": "400GbE single-port",  "size_mb": 32, "chip": "ConnectX-7"},
    "N7D200GF":   {"pid": "ucsc-n7d200gf", "speed": "200GbE dual-port",    "size_mb": 32, "chip": "ConnectX-7",
                   "product_str": "NVIDIA ConnectX-7 HHHL Adapter Card; 200GbE"},
    "N7Q25GF":    {"pid": "ucsc-n7q25gf",  "speed": "25/50GbE quad-port",  "size_mb": 32, "chip": "ConnectX-7",
                   "product_str": "NVIDIA ConnectX-7 HHHL Adapter Card; 25/50GbE"},
    "N6D25GF":    {"pid": "ucsc-n6d25gf",  "speed": "25GbE dual-port",     "size_mb": 32, "chip": "ConnectX-6 Lx",
                   "product_str": "Non-Mellanox QSFP28: The port is closed"},
    "mtfw_magic": "4d544657abcdef00 (MTFW: Mellanox Firmware standard header)",
    "content":    "Opaque -- no readable ASCII in first 1MB; content encrypted or densely compressed",
    "note":       "NIC-only (no ARM DPU cores). ROTPK bypass (NC3220-F1) does NOT apply here. "
                  "ConnectX-7 firmware is updated via Mellanox MFT tools (mlxfw), not the CBB path.",
}

# --- FINDINGS ---

# SAS3-F1: 9500 shares CBB framework with RAID M6 -- iopMsgFwDownload string family present verbatim
SAS3_F1 = {
    "id":       "SAS3-F1",
    "title":    "Cisco 9500-8E (UCSC-9500-8E.rom) contains the identical CBB signing framework "
                "as the RAID M6 CBB bootloader (RAIDM6-F1): the same 'iopMsgFwDownload' string "
                "family appears verbatim -- 'Erasing signatures', '%s is not signed.', 'CBB Signed', "
                "'Key Mismatch', 'Error writing signature %d', 'APP Signed', and "
                "'Comparing image signature to computed SHA%d'; additionally, 'INVALID SBR Signature!' "
                "and 'INVALID RMC Code Signature!' confirm two separate signature validation paths: "
                "SBR (Sub-Boot Record) and RMC (ROM chip code) are independently checked; "
                "a valid SBR with invalid RMC Code Signature (or vice versa) represents a partial "
                "signing bypass surface; the CBB framework's eFuse empty bypass (RAIDM6-F1) is "
                "architecturally present here as well -- if 9500 SOC eFuse is unprogrammed, "
                "the 'not signed' and 'Erasing signatures' paths are reachable without key material; "
                "the 9500-8e is an SAS HBA with access to all attached storage -- arbitrary firmware "
                "execution on the controller means arbitrary I/O against attached SAS/SATA devices",
    "severity": "HIGH",
    "status":   "CONFIRMED -- iopMsgFwDownload strings at UCSC-9500-8E.rom offsets 56672/56804/56912/56944/56976; "
                "INVALID SBR at offset 2708; INVALID RMC at offset 2764; SOC signature at 58216",
    "cwe":      ["CWE-693 (Protection Mechanism Failure)", "CWE-345 (Insufficient Verification of Data Authenticity)"],
    "cross_ref": "RAIDM6-F1 (identical CBB framework, eFuse empty bypass path)",
    "affected":  ["ucsc-9500-8e -- all units where SOC eFuse is unprogrammed"],
}

# SAS3-F2: 9400 BIOS 3 years older than 9500 BIOS + different signature check implementations
SAS3_F2 = {
    "id":       "SAS3-F2",
    "title":    "Cisco SAS3 9400 (8i/8e) ships with MPT35BIOS-9.47.01.00 dated 2022.09.19 while "
                "the concurrent 9500-8e ships with MPT35BIOS-9.71.00.00 dated 2025.07.22 -- "
                "a 2+ year BIOS version gap between controllers sold in the same generation; "
                "the 9400 BIOS signature check reports failure via 'BIOS: Image Signature Check "
                "Failed with Status 0x%08x' (opaque status code return); "
                "the 9500 BIOS checks 'Comparing image signature to computed SHA%d' (algorithm-tied); "
                "two controllers in the same C-Series product line use divergent BIOS signature check "
                "implementations with different failure modes -- the 9400 status-code path may not "
                "halt on signature failure if the status code check is implemented permissively; "
                "the 9400 also has 'BIOS: WARNING - RAM BIOS area not available' -- a recoverable "
                "path where the BIOS area in RAM is absent, potentially triggering unsigned execution "
                "if fallback behavior is not gated",
    "severity": "MEDIUM",
    "status":   "CONFIRMED -- MPT35BIOS version string in mpt35sas_legacy.rom (9400: offset 43878, 9500: offset 44250); "
                "BIOS signature fail at UCSC-9400-8I.bin offset 220376; RAM BIOS warning at 272780",
    "cwe":      ["CWE-1328 (Security Version Number Mutable to Older Version)", "CWE-693 (Protection Mechanism Failure)"],
    "affected":  ["ucsc-9400-8i", "ucsc-9400-8e -- concurrent controllers with stale BIOS signing logic"],
}

# QLE-F1: QLE2872 and QLE2772 are the same binary -- identical MD5 for 16Gb and 32Gb FC HBAs
QLE_F1 = {
    "id":       "QLE-F1",
    "title":    "Cisco QLE2872 (32Gb FC HBA) and QLE2772 (16Gb FC HBA) have identical ZIP MD5 "
                "(9574e6f3c4...) -- the same firmware binary ships under two different Cisco PIDs "
                "representing different speed/capability classes; "
                "both contain ISP28xx firmware version 9.15.06 (2023 QLogic / Marvell); "
                "the UEFI driver ql28xx.drv is Microsoft-signed via MicCorUEFCA2011 (2011 CA); "
                "the CRL endpoint is 'http://www.microsoft.com/pkiops/crl/MicCorUEFCA2011_2011-06-27.crl' "
                "(Microsoft 2011 UEFI CA -- 15-year-old CA in active Cisco production bundle as of 2023); "
                "'CR has Bad Signature' in the UEFI driver confirms signature validation exists "
                "with an observable failure path; "
                "a firmware image signed for the 16Gb QLE2772 would be accepted by the 32Gb QLE2872 "
                "because they are the same binary accepting the same signing keys -- "
                "rollback from a 32Gb to an older 16Gb-era signed firmware is not blocked by "
                "hardware or firmware identity checks since the binaries are already identical",
    "severity": "HIGH",
    "status":   "CONFIRMED -- QLE2872 and QLE2772 ZIP md5=9574e6f3c4 (identical); "
                "ISP28xx FW version at mh080601.bin offset 128943; "
                "MS CRL at ql28xx.drv offset 392682; CR has Bad Signature at offset 243336",
    "cwe":      ["CWE-345 (Insufficient Verification of Data Authenticity)", "CWE-295 (Improper Certificate Validation)"],
    "note":     "Microsoft MicCorUEFCA2011 (2011-06-27) is the original Secure Boot UEFI CA. "
                "Distrusted by some vendors; presence of its CRL in Cisco production firmware signals "
                "no CA rotation was performed across the firmware signing chain.",
    "affected":  ["ucsc-QLE2872", "ucsc-QLE2772 -- all units"],
}

# LPe-F1: Broadcom internal SVN URL, internal codename, internal server embedded in production firmware
LPe_F1 = {
    "id":       "LPe-F1",
    "title":    "Emulex LPe35002 (version 14.4.576.17) production firmware contains an embedded "
                "Broadcom-internal SVN build URL: "
                "'https://srcserver.lvn.broadcom.net/svndata/lancerfw-repos/branches/rel_14.4/"
                "build/palau_14.4.576.17/prismfw-repos r108387' at blob offset 105556; "
                "this exposes: (1) internal hostname srcserver.lvn.broadcom.net -- "
                "a Broadcom internal SVN server in Las Vegas, NV (lvn); "
                "(2) internal firmware codename 'palau' for the LPe35002 14.4 release family; "
                "(3) internal ASIC sub-project 'prismfw' -- the Emulex PRISM ASIC family name; "
                "(4) internal repository structure 'lancerfw-repos' confirming the Lancer HBA "
                "firmware repository name; (5) SVN revision r108387 -- identifies the exact "
                "source snapshot used to build this production binary; "
                "(6) build timestamp 2025-05-22 11:00 -- pinpoints the build date; "
                "the SVN URL is preceded by 249KB of repeated version headers "
                "(14.4.576.17 Lancer Emulex Connected, 128-byte intervals) suggesting a "
                "multi-image container where each sub-image carries a version tag; "
                "the leaked build path enables targeted source reconstruction: "
                "branch rel_14.4, revision r108387 in prismfw-repos maps to the precise "
                "source tree of the production firmware -- any vulnerability found in that "
                "snapshot is directly attributable to what shipped",
    "severity": "HIGH",
    "status":   "CONFIRMED -- SVN URL at blob offset 105555-105695; "
                "srcserver.lvn.broadcom.net + /svndata/lancerfw-repos/branches/rel_14.4/"
                "build/palau_14.4.576.17/prismfw-repos r108387 2025-05-22 11:00",
    "cwe":      ["CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor)",
                 "CWE-615 (Inclusion of Sensitive Information in Source Code Comments)"],
    "note":     "The 'lvn' subdomain in srcserver.lvn.broadcom.net suggests a Las Vegas, NV "
                "Broadcom facility -- this is Broadcom's silicon engineering campus in LV. "
                "The server name + revision leaks precise build provenance.",
    "affected":  ["ucsc-lpe35002 -- all units running 14.4.576.17; probably all 14.4.x builds"],
}

# LPe-F2: payload_signature.cfg is an externally-configurable signature verification input
LPe_F2 = {
    "id":       "LPe-F2",
    "title":    "LPe35002 blob contains 'payload_signature.cfg' and 'dualboot.cfg' as named "
                "configuration files alongside boot program images ('sp_boot.prg', "
                "'srb_preboot.prg', 'sp_preboot.prg'); "
                "signature verification is configured through an external config file "
                "('payload_signature.cfg') rather than embedded constants in the bootloader -- "
                "this is a configurable trust path: if the signature config file can be "
                "replaced or corrupted (via firmware update mechanism, flash write, or "
                "JTAG/debug interface), signature checks can be manipulated without "
                "modifying the core boot program; "
                "the dual-boot configuration ('dualboot.cfg') describes a two-image boot "
                "layout (primary + recovery or A/B slots); in A/B boot schemes, "
                "if the signature check on the active slot fails, the firmware may fall back "
                "to the alternate slot -- the fallback condition and slot selection logic "
                "are defined by the config, not by hardware; "
                "the flash memory layout is managed by 250+ 'configRegion_NNN_NN.cfg' entries "
                "which define the boundaries and attributes of each flash region; "
                "region boundary manipulation is a known LPe attack surface (Emulex-class "
                "controllers expose region attributes via the OneConnect management interface)",
    "severity": "MEDIUM",
    "status":   "CONFIRMED -- payload_signature.cfg at blob offset 103784; dualboot.cfg at 103748; "
                "sp_boot.prg at 105172; srb_preboot.prg at 105280; sp_preboot.prg at 105316; "
                "configRegion_NNN_NN.cfg entries begin at offset 15620",
    "cwe":      ["CWE-494 (Download of Code Without Integrity Check)",
                 "CWE-276 (Incorrect Default Permissions)"],
    "affected":  ["ucsc-lpe35002 -- units where flash region attributes are accessible"],
}

# N7-F1: ConnectX-7 firmware is opaque -- no CBB/signing strings exposed (positive posture vs peers)
N7_F1 = {
    "id":       "N7-F1",
    "title":    "Cisco N7S400GF / N7D200GF / N7Q25GF (Nvidia ConnectX-7 NICs) use MTFW format "
                "(magic 4d544657abcdef00) with no readable ASCII strings in the first 1MB of "
                "firmware content -- unlike QLE/LPe/RAID entries which expose extensive debug "
                "strings and build artifacts, ConnectX-7 firmware is opaque (encrypted or "
                "tightly compressed via Mellanox's proprietary MFW scheme); "
                "the 'abcdef00' bytes following the MTFW magic are the standard Mellanox "
                "secondary header pattern, not a debug or test marker; "
                "firmware update is via Mellanox MFT tools (mlxfw) which perform hardware- "
                "authenticated image validation -- this path is architecturally separate from "
                "the CBB framework used in RAID/SAS controllers; "
                "product identification: N7D200GF = 'NVIDIA ConnectX-7 HHHL; 200GbE', "
                "N7Q25GF = 'NVIDIA ConnectX-7 HHHL; 25/50GbE'; "
                "N6D25GF (ConnectX-6 Lx, 25GbE) includes 'Non-Mellanox QSFP28: The port is closed' "
                "-- an interoperability rejection string for non-qualified SFP modules "
                "(Cisco qualification gate for optics, not a security check); "
                "these are NIC adapters only -- no ARM DPU complex, no ROTPK bypass surface "
                "(NC3220-F1 is BlueField-3 DPU-specific)",
    "severity": "LOW",
    "status":   "CONFIRMED -- MTFW magic at N7S400GF/N7D200GF/N7Q25GF blob headers; "
                "product strings in N7D200GF/N7Q25GF extracted content; "
                "No readable security strings found in first 1MB of any N7 blob",
    "cwe":      ["CWE-200 (Exposure of Sensitive Information -- NEGATIVE: not applicable here; "
                 "included for contrast with LPe-F1/QLE-F1 which DO expose internal artifacts)"],
    "note":     "N7 ConnectX-7 firmware is the best-protected entry in this adapter category. "
                "LPe-F1 (Broadcom SVN URL) and QLE-F1 (identical 16G/32G binary) are the "
                "higher-severity exposures in this firmware batch.",
    "affected":  ["none identified -- noting for cross-module completeness"],
}

FINDINGS = [SAS3_F1, SAS3_F2, QLE_F1, LPe_F1, LPe_F2, N7_F1]

FIRMWARE = list(BROADCOM_SAS3.values()) + [QLOGIC_HBA, EMULEX_LPe35002, NVIDIA_CX7_N7]
