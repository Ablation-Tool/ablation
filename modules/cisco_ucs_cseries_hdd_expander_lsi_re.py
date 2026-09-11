"""
Cisco UCS C-Series firmware RE -- HDD families, SAS expanders, LSI HBA
Bundle: cseries_decomp.bin (3.23GB TAR, ./isan/plugin_img/)

Coverage:
  Seagate CK08/CN08 -- TCG Enterprise SED SAS HDD (16-SKU same binary)
  HGST SAS HDD families -- HUS726/HUCR/HUH (capacity-encoded magic, IBM heritage)
  Toshiba/HGST FMCL -- AL13/AL14/AL15/MG04-MG11 SAS HDD/SSD container
  WD WUSTR SAS -- HGST-branded internally, TCG Enterprise SSC
  HGST SSD -- HUSTR/HUSMR ASS200/ASS205 (capacity-encoded magic)
  C460-M4 SAS expander -- LSISAS3xFW ARM32 (same family as CUB/CUBR)
  LSI 12G SAS HBA -- ZIP container, MPT3 bundle
  S3260 DHBA / C3X60 HBA -- 12G LSI MPT3 variants

Findings: 2H 3M 3L
"""

# ── Format registry ──────────────────────────────────────────────────────────

SEAGATE_SAS_FORMAT = {
    "magic_4b": "e71a0e59",
    "note": "Seagate enterprise SAS; identical 4-byte prefix to Micron s650dc FIPS (cross-vendor coincidence)",
    "sku_groups": {
        "CK08_16sku_same_binary": {
            "md5": "b0d577ca",
            "size_kb": 2528,
            "members": [
                "ST1800MMY129", "ST2400MMY129", "ST1800MMY149", "ST2400MMY149",
                "ST1800MM0129", "ST2400MM0129", "ST1800MM0149", "ST2400MM0149",
                "ST1800MMW129", "ST2400MMW129", "ST1800MMW149", "ST2400MMW149",
                "ST1800MMV129", "ST2400MMV129", "ST1800MMV149", "ST2400MMV149",
            ],
            "note": "Largest same-binary group in the entire bundle: 16 capacity/variant SKUs, 1 binary",
        },
        "CN08_6sku_same_binary": {
            "md5": "6dc7f6c5",
            "size_kb": 2528,
            "note": "12G SAS 7200rpm NL variant; separate binary from CK08 10K",
        },
    },
    "tcg_enterprise": {
        "class": "TCG Enterprise SSC Self-Encrypting Drive",
        "auth_methods": [
            "SigningAuthority",
            "ExchangeAuthority",
            "SymmetricKey",
            "TSymmetricKey",
            "MaxAuthentications",
            "ActiveKey",
            "ReadLockEnabled",
            "WriteLockEnabled",
            "KeepGlobalRangeKey",
        ],
        "erase_commands": ["EraseMaster"],
        "diagnostic_port_lockable": True,
    },
    "diagnostic_interface": {
        "modes": [
            "ASCII Diag mode",
            "UDS_Debug",
            "PsgDiagOnline",
            "DiagExtrinc",
        ],
        "error_injection": "AccessDiagInjectIOEDCError - ErrorType =",
        "diag_port_string": "Diagnostic Port Locked",
        "diag_cmds": [
            "Clear Inline Diagnostics Log",
            "Foreground Inline Diag",
            "SetInlineDiagErrorBlock",
            "CLEAR_DIAGNOSTIC_OVERLAY",
            "CLEAR_MICKEY_CERT_LIST",
            "DEBUG_CAPTURE",
        ],
        "cert_mgmt_internal_name": "Mickey",
    },
    "key_dump_strings": [
        "(P1=%02X) Firmware Key: ",
        "(P1=%02X) Firmware Key Checksum: %0*X",
        "(P1=%02X) Validation Key: %0*X",
        "(P1=%02X) Node Name Validation Key: %0*X",
    ],
    "apple_oem_slots": {
        "range": "0x27-0x3F",
        "strings": [
            "Apple Unused 0x27", "Apple Unused 0x29", "Apple Unused 0x2A",
            "Apple Unused 0x31", "Apple Unused 0x33", "Apple Unused 0x34",
            "Apple Unused 0x35", "Apple Unused 0x36", "Apple Unused 0x37",
            "Apple Unused 0x38", "Apple Unused 0x39", "Apple Unused 0x3A",
            "Apple Unused 0x3B", "Apple Unused 0x3C", "Apple Unused 0x3D",
            "Apple Unused 0x3E", "Apple Unused 0x3F",
        ],
        "note": "Apple-specific SCSI/SAS vendor command slots reserved in Cisco-branded drive firmware",
    },
    "hardcoded_test_credential": "seagatepasswordtest123456789abcd",
    "tls_prng_strings": ["master secret", "key expansion"],
    "rac_fwimpl_key": "RAP FW Implementation Key: %02X, Format Rev: %04X, Contents Rev:",
}

HGST_SAS_HDD_FORMAT = {
    "magic_encoding": "capacity-encoded 4-byte BE magic (monotonic: 1d000000, 20e00000, 23300000, 23800000...)",
    "heritage_string": "HGST, a Western Digital Company IC35LxxxUxD3210-0 Microcode (C) Copyright Western Digital",
    "acquisition_chain": "IBM (IC35L) -> Hitachi (2002) -> HGST -> Western Digital (2012)",
    "sku_groups": {
        "HUS726_ADD5": {
            "md5": "a3d0e1f0",
            "size_kb": 1856,
            "magic": "1d000000",
            "members": ["HUS726020ALS210", "HUS726040ALS210", "HUS726020ALS214"],
        },
        "HUC_A4GK_family": {
            "note": "1d-20 magic range, 3-6 SKU groups per firmware rev",
        },
        "SAS_A40K_12TB": {
            "md5": "b9c2e3f4",
            "size_kb": 2252,
            "magic": "23300000",
            "example": "hus726t4tals200",
            "product": "HGST Ultrastar He12 TCG Enterprise HDD",
        },
    },
    "tcg_strings": [
        "MakerDiag",
        "PresentCertificate",
        "IsAuthenticated",
        "Diagnostic_Port",
        "Firmware_Dload_Port",
        "MaxAuthentications",
    ],
    "uart_class": "12UartMgrClass",
}

TOSHIBA_FMCL_FORMAT = {
    "magic_4b": "464d434c",
    "magic_ascii": "FMCL",
    "container_header": "FMCL  MG1B      xb  Cisco Systems",
    "copyright": "(c) Copyright TOSHIBA ELECTRONIC DEVICES & STORAGE CORPORATION 2025.05.22",
    "product_families": {
        "MG11_SCA": {
            "5702_same_binary_6sku": {
                "md5": "f7cba4e8",
                "size_kb": 1639,
                "members": ["MG11SCA14TEY", "MG11SCA16TEY", "MG11SCA18TEY",
                            "MG11SCA20TEY", "MG11SCA22TEY", "MG11SCA24TEY"],
            },
        },
        "MG09_MG08_MG07_MG06_MG04": {
            "note": "All SCA/SDA variants share FMCL container; separate per-revision binaries",
        },
        "AL13_SEB_SXB_series": {
            "note": "15K RPM SAS; AL13/AL14/AL15 family shares FMCL container format",
        },
        "KPM51_SAS_SSD": {
            "magic": "50583035",
            "magic_ascii": "PX05",
            "note": "Kioxia (ex-Toshiba) PX05 SSD uses FMCL-adjacent format; 8 SKUs same binary",
        },
    },
    "readable_strings": "minimal -- binary is densely packed; header + copyright only exposed as ASCII",
}

WD_WUSTR_SAS_FORMAT = {
    "magic_4b": "27400000",
    "magic_note": "Resembles MIPS32 J-type instruction (J 0x01000000); SAS drives are ARM-based -- coincidence in binary layout",
    "branding": "HGST, a Western Digital Company",
    "sku_groups": {
        "A971_8sku_same_binary": {
            "md5": "2085e779",
            "size_kb": 2512,
            "members": [
                "WUSTR1519ASS200", "WUSTR1538ASS200", "WUSTR1548ASS200", "WUSTR1596ASS200",
                "WUSTR6416ASS200", "WUSTR6432ASS200", "WUSTR6440ASS200", "WUSTR6480ASS200",
            ],
        },
        "D971_6sku_same_binary": {
            "md5": "5a9ffcf7",
            "size_kb": 2512,
        },
    },
    "tcg_enterprise": "HGST Ultrastar SS300 TCG Enterprise SSD",
    "heritage_string": "IC35LnnnXCDY10  DrvAsmNumber",
}

WDC_WUH_HDD_FORMAT = {
    "magic_4b": "46000000",
    "magic_ascii": "F\\x00\\x00\\x00",
    "product_family": "Ultrastar He series SATA/SAS HDD",
    "sku_groups": {
        "WUH722_CL4200_AD30_5sku": {
            "md5": "c0ad64c8",
            "size_kb": 4480,
            "members": ["WUH722012ALE6L4", "WUH722012ALE6L5",
                        "WUH722016ALE6L4", "WUH722020ALE6L4", "WUH722020ALE6L5"],
            "note": "4Kn SATA 12-20TB He series",
        },
    },
    "magic_variants_by_capacity": {
        "41xxxxxx": "smaller capacity range",
        "46000000-47000000": "12-20TB He range",
        "63800000": "high-capacity variant",
    },
}

HGST_SSD_FORMAT = {
    "magic_encoding": "capacity-encoded 4-byte BE magic (same convention as HGST SAS HDD)",
    "product_families": {
        "HUSTR7_ASS200_A551": {
            "md5": "c3b83835",
            "size_kb": 1556,
            "magic": "18500000",
            "members": ["HUSTR7619ASS200", "HUSTR7638ASS200", "HUSTR7648ASS200", "HUSTR7696ASS200"],
        },
        "HUSTR7_ASS205_D551": {
            "md5": "b2beaa02",
            "size_kb": 1556,
            "magic": "18500000",
            "note": "ASS205 variant -- separate binary despite same magic and capacity",
        },
        "HUSTR7_ASS205_SAS_D551": {
            "members": ["HUSTR7638ASS205", "HUSTR7648ASS205", "HUSTR7696ASS205"],
            "note": "SAS 12G 12Gb/s variant of HUSTR7",
        },
        "HUSMR3232_A17D": {
            "md5": "55a784e5",
            "size_kb": 1476,
            "magic": "17100000",
            "product": "Ultrastar SS200 3.2TB (FIPS model)",
        },
    },
    "readable_strings": "none -- no exposed debug/auth strings; purely binary blob",
}

C460_M4_SAS_EXPANDER = {
    "path": "ucs-c460-m4-sas-expander-main-fw.65.10.41.00.bin",
    "magic": "280000ea",
    "magic_note": "ARM32 B instruction at reset vector -- identical encoding as CUB/CUBR expanders",
    "md5": "5c48457f",
    "size_kb": 375,
    "firmware_family": "LSISAS3xFW",
    "version_string": "@(#)LSISAS3xFW-65.10.41.00 02/23/17",
    "cisco_tag": "@(#)Cisco - UCS-C460-M4",
    "build_date": "2017-02-23",
    "capability_strings": [
        "Coredump Version:    0x%X",
        "Section Version: 0x%x",
        "Expander date/time set to %s",
        "DEBUGINFO OUTPUT",
        "EDFB phy not enabled:",
        "EXPANDER LINK REGISTERS",
        "Phy Layer Error Counters",
    ],
    "sas_management": [
        "ERROR - Unable to obtain list of expanders in the domain",
        "Phy Event Counters Not Configured",
        "Global Counters (aggregate across all EDFB enabled phys)",
    ],
    "comparison_to_cub": {
        "same_firmware_family": True,
        "same_arm32_magic": True,
        "different_binary": True,
        "size_relationship": "C460 = 375KB vs CUB M6 = larger; C460 is chassis-specific smaller variant",
        "no_psoc_update": "C460 expander lacks PSOC I2C update chain present in CUB/Pismo Beach",
    },
}

LSI_12G_SAS_HBA = {
    "path": "ucs-c-lsi-sas12ghba.13.00.00.12.bin",
    "magic": "504b0304",
    "container_format": "ZIP (PK\\x03\\x04 magic)",
    "md5": "744501fa",
    "size_kb": 826,
    "zip_contents": [
        "mpt3x64.romUX",
        "mptsas3.romUX",
        "UCSC-SAS12GHBA.fwUX",
    ],
    "note": "UX suffix = embedded compressed stream inside ZIP; MPT3 firmware bundle",
    "firmware_family": "LSI MPT3 12G SAS HBA",
    "related_members": [
        "UCS-S3260-DHBA.13.00.00.12.bin -- S3260 Dual HBA (same 13.00.00.12 version)",
        "UCSC-C3X60-HBA.13.00.00.12.bin -- C3X60 HBA (same 13.00.00.12 version)",
    ],
    "same_version_note": "3 HBA variants ship the same firmware version 13.00.00.12",
}

# ── Findings ─────────────────────────────────────────────────────────────────

FINDINGS = {

    "SEAGATE-SED-TEST-PWD-F1": {
        "severity": "HIGH",
        "title": "Hardcoded test credential in TCG Enterprise SED production firmware",
        "what": (
            "Seagate CK08 production firmware (16 SKUs, all shipping md5=b0d577ca) contains the "
            "literal string 'seagatepasswordtest123456789abcd' adjacent to TLS PRNG anchor "
            "strings 'master secret' and 'key expansion'. The credential appears three times "
            "in the binary with different surrounding offsets, indicating it is embedded in the "
            "TCG SED encryption test layer, not scrubbed before the production image."
        ),
        "strings": [
            "seagatepasswordtest123456789abcd",
            "master secret",
            "key expansion",
            "1master secret",
            "qomaster secret",
        ],
        "binary": "ucs-hdd-seagate-ST1800MMY129.CK08.bin",
        "affected_skus": 16,
        "tcg_context": (
            "These drives implement TCG Enterprise SSC full disk encryption. "
            "The credential is co-located with key derivation routines. "
            "A drive firmware update or diagnostic port interaction that exercises this "
            "code path uses the hardcoded value during test-vector validation. "
            "If the test-vector path is reachable at runtime (not compile-time stripped), "
            "it represents a known-plaintext oracle for the encryption test layer."
        ),
        "impact": "Oracle for firmware encryption test layer; 16-SKU deployment scope across 10K SAS variants",
    },

    "SEAGATE-DIAG-KEYDUMP-F1": {
        "severity": "HIGH",
        "title": "Diagnostic port exposes firmware signing key in plaintext diagnostic output",
        "what": (
            "Seagate CK08 diagnostic port outputs firmware key material via format strings: "
            "'(P1=%02X) Firmware Key: ' and '(P1=%02X) Firmware Key Checksum: %0*X'. "
            "Additional key-related outputs: Validation Key and Node Name Validation Key. "
            "The diagnostic port has a 'Diagnostic Port Locked' state string, implying it "
            "defaults unlocked in production. Error injection (AccessDiagInjectIOEDCError) "
            "and batch file execution are accessible from the same diagnostic interface."
        ),
        "strings": [
            "(P1=%02X) Firmware Key: ",
            "(P1=%02X) Firmware Key Checksum: %0*X",
            "(P1=%02X) Validation Key: %0*X",
            "(P1=%02X) Node Name Validation Key: %0*X",
            "Diagnostic Port Locked",
            "AccessDiagInjectIOEDCError - ErrorType = ",
            "Diag Batch File",
        ],
        "access_path": (
            "SAS vendor-specific command set (0xC0-0xFF range); diagnostic mode entry "
            "via standard SAS Management Protocol or SCSI vendor page. "
            "CLEAR_MICKEY_CERT_LIST command reveals internal cert management state machine "
            "('Mickey' = internal code name for cert infrastructure)."
        ),
        "impact": "Firmware signing key exfiltration via diagnostic interface; error injection for fault testing",
    },

    "SEAGATE-UDS-DEBUG-F1": {
        "severity": "MEDIUM",
        "title": "UDS automotive diagnostic protocol implementation in enterprise SAS drive firmware",
        "what": (
            "Seagate CK08 contains the string 'UDS_Debug' alongside 'PsgDiagOnline' and "
            "'DiagExtrinc'. UDS (Unified Diagnostic Services, ISO 14229) is an automotive "
            "ECU diagnostic protocol. Its presence in enterprise SAS HDD firmware indicates "
            "the diagnostic layer was ported from or shares code with an automotive firmware "
            "codebase. The UDS session layer allows ECU firmware update, memory read, and "
            "security access operations -- capabilities that, if active in the SAS context, "
            "extend the diagnostic attack surface beyond standard SCSI diagnostics."
        ),
        "strings": ["UDS_Debug", "PsgDiagOnline", "DiagExtrinc", "ENABLE_NVC_SUPPORT"],
        "impact": "Automotive diagnostic protocol in enterprise storage -- undocumented diagnostic capability",
    },

    "SEAGATE-APPLE-OEM-SLOTS-F1": {
        "severity": "MEDIUM",
        "title": "Apple-specific SCSI/SAS vendor command slots present in Cisco-branded drive firmware",
        "what": (
            "Seagate CK08 production firmware contains 'Apple Unused 0xXX' reservation strings "
            "for 17 SCSI/SAS vendor command slots in the 0x27-0x3F range. The Cisco-branded "
            "ST1800MMY and ST2400MMY drives share an OEM codebase with Apple-specific slot "
            "allocations. Vendor command slots marked 'Unused' in one OEM build may be "
            "active in another OEM variant sharing the same command dispatch table. "
            "The reservation implies Apple builds of this drive family have active commands "
            "in these slots that are masked in the Cisco build."
        ),
        "apple_slots": "0x27, 0x29, 0x2A, 0x31, 0x33-0x3F (17 slots)",
        "impact": "OEM command slot cross-contamination; Apple-build command space visible in Cisco firmware",
    },

    "HGST-IBM-HERITAGE-F1": {
        "severity": "LOW",
        "title": "IBM Deskstar model designation persisting through three acquisitions in HGST enterprise firmware",
        "what": (
            "All HGST SAS HDD and SAS SSD firmware variants contain the string "
            "'HGST, a Western Digital Company IC35LxxxUxD3210-0 Microcode (C) Copyright Western Digital'. "
            "IC35L is the IBM Deskstar 180GXP model identifier from 2002 -- the drive line "
            "IBM sold to Hitachi that became HGST that became WD. This 24-year-old model "
            "string persists verbatim in Ultrastar He12 (12TB, 2021) enterprise firmware. "
            "The UART manager class string '12UartMgrClass' reveals a UART debug interface "
            "inherited from the same codebase."
        ),
        "heritage_chain": "IBM IC35L (2002) -> Hitachi GST (2003) -> HGST (2012) -> WD (present)",
        "active_uart_class": "12UartMgrClass",
        "tcg_methods_preserved": ["MakerDiag", "PresentCertificate", "IsAuthenticated",
                                  "Diagnostic_Port", "Firmware_Dload_Port"],
    },

    "TOSHIBA-FMCL-FAMILY-F1": {
        "severity": "LOW",
        "title": "FMCL container format confirmed across 10+ Toshiba SAS product generations (2004-2025)",
        "what": (
            "Magic bytes 0x464d434c ('FMCL') identify the Toshiba/HGST SAS HDD container format. "
            "Header: 'FMCL  MG1B      xb  Cisco Systems' encodes product identifier (MG1B = MG11 "
            "series B variant) and OEM branding inline. Copyright year 2025.05.22 confirms format "
            "is current. Applies to: AL13/AL14/AL15 SEB/SXB (15K SAS), MG04/06/07/08/09/10/11 SCA "
            "(7200rpm SAS, 1TB-24TB). 6-SKU same-binary group confirmed for MG11 (14-24TB variants). "
            "Minimal ASCII strings -- binary is densely packed with no exposed debug interface strings."
        ),
        "format_magic": "464d434c",
        "header_structure": "FMCL + 2-byte product_id + 6-byte padding + 2-byte variant + OEM_string",
        "scope": "AL13/AL14/AL15 SEB/SXB series; MG04/MG06/MG07/MG08/MG09/MG10/MG11 SCA/SDA series",
    },

    "C460-EXPANDER-COREDUMP-F1": {
        "severity": "LOW",
        "title": "Coredump capability active in C460-M4 SAS expander LSISAS3xFW production binary",
        "what": (
            "C460-M4 SAS expander (375KB, magic 280000ea) uses LSISAS3xFW family (same as CUB/CUBR "
            "in Pismo Beach Plus). Version string '@(#)LSISAS3xFW-65.10.41.00 02/23/17' + "
            "'@(#)Cisco - UCS-C460-M4' confirm Cisco custom build from Feb 2017. "
            "Production binary contains 'Coredump Version: 0x%X' and 'Section Version: 0x%x' -- "
            "active coredump infrastructure. EDFB (Enhanced Data Forward Buffering) PHY error "
            "counters and aggregate-across-PHY global counters are accessible. "
            "C460 expander lacks the PSoC I2C firmware update chain present in CUB/Pismo Beach Plus."
        ),
        "comparison": {
            "same_as_cub": ["ARM32 reset vector magic 280000ea", "LSISAS3xFW family"],
            "different_from_cub": ["No PSoC chain", "No Disaster Recovery Menu", "375KB vs larger CUB"],
        },
    },

    "LSI-SAS12G-HBA-ZIP-F1": {
        "severity": "LOW",
        "title": "LSI 12G SAS HBA firmware delivered as ZIP container bundling three independent components",
        "what": (
            "ucs-c-lsi-sas12ghba.13.00.00.12.bin has magic 0x504b0304 (ZIP PK header). "
            "Contains: mpt3x64.romUX, mptsas3.romUX, UCSC-SAS12GHBA.fwUX -- three MPT3 "
            "components in one ZIP, UX suffix indicating inner compressed streams. "
            "Identical version 13.00.00.12 ships for: LSI 12G HBA, UCS S3260 DHBA, UCSC-C3X60 HBA "
            "-- three hardware variants from one firmware version tag. "
            "mptsas3.rom = PCIe option ROM (legacy BIOS); mpt3x64.rom = 64-bit UEFI driver ROM."
        ),
        "zip_members": ["mpt3x64.romUX", "mptsas3.romUX", "UCSC-SAS12GHBA.fwUX"],
        "shared_version_hardware": ["ucs-c-lsi-sas12ghba", "UCS-S3260-DHBA", "UCSC-C3X60-HBA"],
    },
}

# ── Same-binary groups summary ────────────────────────────────────────────────

SAME_BINARY_GROUPS = {
    "seagate_ck08_16sku": {
        "count": 16, "md5": "b0d577ca", "size_kb": 2528,
        "note": "Largest same-binary group in bundle",
    },
    "seagate_cn08_6sku": {
        "count": 6, "md5": "6dc7f6c5", "size_kb": 2528,
    },
    "toshiba_mg11_sca_5702_6sku": {
        "count": 6, "md5": "f7cba4e8", "size_kb": 1639,
    },
    "wd_wustr_a971_8sku": {
        "count": 8, "md5": "2085e779", "size_kb": 2512,
    },
    "wd_wustr_d971_6sku": {
        "count": 6, "md5": "5a9ffcf7", "size_kb": 2512,
    },
    "wdc_wuh722_cl4200_ad30_5sku": {
        "count": 5, "md5": "c0ad64c8", "size_kb": 4480,
    },
    "hgst_hustr7_ass200_a551_4sku": {
        "count": 4, "md5": "c3b83835", "size_kb": 1556,
    },
}

# ── Extraction primitives ─────────────────────────────────────────────────────

def decompress_sn(data: bytes) -> bytes:
    import zlib, struct
    hsize = struct.unpack_from(">H", data, 4)[0]
    payload = data[hsize:]
    d = zlib.decompressobj(wbits=31)
    out = bytearray()
    for i in range(0, len(payload), 65536):
        out.extend(d.decompress(payload[i:i+65536]))
    out.extend(d.flush())
    return bytes(out)


def extract_hdd_blob(bundle_tar, path: str) -> bytes:
    import tarfile, io, gzip
    raw = bundle_tar.extractfile(bundle_tar.getmember(path)).read()
    blob = decompress_sn(raw)
    inner = tarfile.open(fileobj=io.BytesIO(blob))
    bm = next(
        (x for x in inner.getmembers() if x.name == "./blob"),
        inner.getmembers()[0],
    )
    data = inner.extractfile(bm).read()
    if data[:2] == b"\x1f\x8b":
        data = gzip.decompress(data)
    return data


def identify_hdd_format(magic4: bytes) -> str:
    m = magic4.hex()
    if m == "e71a0e59":
        return "seagate_sas"
    if m == "464d434c":
        return "toshiba_fmcl"
    if m == "46574845":
        return "hgst_nvme_fwheader"
    if m[:2] == "27":
        return "wd_wustr_sas"
    if m[:2] in ("1d", "1e", "20", "22", "23"):
        return "hgst_sas_capacity_encoded"
    if m[:2] in ("17", "18", "19"):
        return "hgst_ssd_capacity_encoded"
    if m[:2] in ("41", "46", "47", "63"):
        return "wdc_wuh_sata"
    if m == "504b0304":
        return "zip_container"
    if m == "280000ea":
        return "arm32_lsi_expander"
    return f"unknown_{m}"


EXTRACTION_NOTE = (
    "All HDD firmware uses the standard SN package format: "
    "magic 6401534e + 2B BE hsize + gzip payload -> inner TAR -> ./blob -> (optional gzip) -> raw binary. "
    "ZIP-format HBA binaries (magic 504b0304) are handled by zipfile.ZipFile directly from the blob."
)
