"""
Cisco IP DECT 5-1-3 MPP RE Module
Targets:
  IPDect-DBS110_5-1-3MPP0101-9_REL.zip  -- DBS-110 base station
  IPDect-DBS210_5-1-3MPP0101-9_REL.zip  -- DBS-210 base station
  IPDect-PH6825_5-1-3MPP0101-9_REL.zip  -- PH6825 handset
  IPDect-PH6825RGD_5-1-3MPP0101-9_REL.zip -- PH6825 ruggedized handset
  IPDect-RPT-110_5-1-3MPP0001-3_REL.zip -- RPT-110 DECT repeater

ODM: RTX A/S (Denmark) -- confirmed via RTX SoC strings in firmware
Architecture: Proprietary RTX RTOS (not Linux) on RTX DECT SoC family
Not extractable: firmware payload is compressed/encrypted with RTX toolchain

.fwu format:
  Magic: 66 46 ("fF") at offset 0
  Header: OldFwuHeader format (legacy, field "OldFwuHeaderkK")
  secureHeader: cryptographic signature at offset ~0x231
  Content: RTX RTOS binary image (proprietary, no known extractor)
  CA bundle: embedded x509 DER certificates (~2.3-2.6MB in DBS110) for CUCM TLS
  CRC32: polynomial tables at tail of DBS110/DBS210 (integrity validation)

Firmware naming convention:
  DBS-110-3PC-05-01-03-0101-09.fwu (canonical) = DBS_110_3PC_V0501_B0309 (internal)
  The "-3PC" suffix = 3rd Party Compatible (3PCC, supports non-Cisco call control)
  Version 5-1-3 = firmware 5.01.03 (MPP 5.x series)
  Build 0101-09 / 0101-08 / 0001-03 depending on device

SoC family (RTX A/S):
  DBS-110: RTX9440 (integrated DECT+DSP base station SoC)
  DBS-210: RTX8665 (older RTX DECT base station SoC)
  PH6825: RTX8641 (DECT handset SoC)
  PH6825RGD: RTX8642 (ruggedized variant of RTX8641)
  RPT-110: unknown (repeater, smaller image 256KB -- simple MCU, no SoC string found)

Codenames:
  DRAGONSTONE: DBS-110 and DBS-210 base stations (same codename, different SoC)
  WALDAU_PP: PH6825 and PH6825RGD handsets (PP = Portable Part in DECT terminology)
  ROTA: RPT-110 repeater

CUCM TLS certificate bundle embedded in DBS110 and DBS210:
  23 x509 DER certificates at offsets 0x231872-0x27124D in DBS-110 fwu
  CA names include: Buypass AS-9831633271, Buypass Class 2 Root CA,
  DigiCert, ANCERT (fnmt.es), and others
  These are standard public CA roots for CUCM TLS client authentication
"""

METADATA = {
    "targets": "Cisco IP DECT DBS110, DBS210 (base stations), PH6825, PH6825RGD (handsets), RPT-110 (repeater)",
    "firmware_version": "5-1-3 MPP (5.01.03), built 2026-03-25 (DBS/PH6825), 2025-01-09 (RPT-110)",
    "odm": "RTX A/S (Aalborg, Denmark) -- DECT SoC and firmware toolchain vendor",
    "architecture": "RTX proprietary RTOS on RTX DECT SoC (not Linux, no extractable filesystem)",
    "fwu_format": {
        "magic": "0x66 0x46 ('fF') at offset 0",
        "header_type": "OldFwuHeaderkK (legacy header format still in use as of 5.1.3)",
        "secure_header": "cryptographic signature at offset 0x231 in DBS-110/DBS-210",
        "payload": "compressed/encrypted RTX RTOS binary (no known open-source extractor)",
        "ca_bundle": "x509 DER certificate chain embedded in base station images (23 certs in DBS-110)",
    },
    "soc_by_device": {
        "DBS-110": "RTX9440",
        "DBS-210": "RTX8665",
        "PH6825": "RTX8641",
        "PH6825RGD": "RTX8642",
        "RPT-110": "unknown (no SoC string; 256KB image suggests minimal MCU)",
    },
    "codenames": {
        "DRAGONSTONE": "DBS-110 and DBS-210 (base station family)",
        "WALDAU_PP": "PH6825 and PH6825RGD (portable part = DECT handset)",
        "ROTA": "RPT-110 (repeater)",
    },
}

FINDINGS = [
    {
        "id": "F1",
        "title": "ODM Identity Exposure -- RTX A/S (Denmark), RTX SoC IDs, Internal Codenames in Firmware",
        "severity": "LOW",
        "cvss": 0.0,
        "cvss_vector": "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N",
        "cwe": "CWE-200",
        "description": (
            "All five IP DECT firmware images expose full ODM and SoC supply-chain data: "
            "(1) ODM: RTX A/S (Aalborg, Denmark) -- confirmed via RTX SoC model strings "
            "embedded in firmware: RTX9440 (DBS-110), RTX8665 (DBS-210), "
            "RTX8641 (PH6825), RTX8642 (PH6825RGD). "
            "RTX A/S is the primary DECT SoC and firmware platform vendor for these devices. "
            "(2) Internal codenames: DRAGONSTONE (base station family -- DBS-110 and DBS-210), "
            "WALDAU_PP (handset family -- PH6825 and PH6825RGD; "
            "PP = Portable Part, standard DECT terminology for handsets), "
            "ROTA (RPT-110 repeater). "
            "(3) Full build identifier strings in firmware image: "
            "DBS_110_3PC_05_01_03_0101_09_DRAGONSTONE_V0501_B0309, "
            "DBS_210_3PC_05_01_03_0101_09_DRAGONSTONE_V0501_B0309, "
            "6825_05_01_03_0101_08_WALDAU_PP_V0501_B0308, "
            "6825_RGD_05_01_03_0101_08_WALDAU_PP_V0501_B0308, "
            "RPT_110_3PC_05_01_03_0001_03_ROTA_V0501_B0303. "
            "(4) 'OldFwuHeaderkK' string in all images -- exposes format version history, "
            "indicating Cisco/RTX used a different fwu format in prior firmware generations "
            "and maintains backward-compatible parsing code. "
            "(5) The '-3PC' suffix (3rd Party Compatible) in base station names confirms "
            "these units support open SIP/3PCC call control, not just CUCM registration."
        ),
        "soc_table": {
            "DBS-110": "RTX9440",
            "DBS-210": "RTX8665",
            "PH6825": "RTX8641",
            "PH6825RGD": "RTX8642",
            "RPT-110": "unknown (256KB image, minimal MCU)",
        },
        "codenames": {
            "DRAGONSTONE": "DBS-110 and DBS-210",
            "WALDAU_PP": "PH6825 and PH6825RGD",
            "ROTA": "RPT-110",
        },
        "impact": ["SoC and ODM knowledge enables targeted exploit development against RTX DECT platform"],
        "remediation": "N/A -- informational finding.",
    },
    {
        "id": "F2",
        "title": "Proprietary .fwu Format with OldFwuHeader Legacy Code and secureHeader Signature",
        "severity": "LOW",
        "cvss": 0.0,
        "cvss_vector": "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N",
        "cwe": "CWE-693",
        "description": (
            "The .fwu container format uses magic bytes 0x66 0x46 ('fF') at offset 0. "
            "The header contains a legacy 'OldFwuHeaderkK' structure at offset 0xda "
            "in DBS-110/DBS-210. The presence of 'OldFwuHeaderkK' confirms that prior "
            "firmware generations used a different (older) fwu container, and the "
            "current loader retains parsing code for both formats. "
            "OldFwuHeader fields at offset 0xda include: version bytes (0x03 0x01), "
            "model ID bytes (e.g. 0x49 0x01 = DBS-110, 0x28 0x01 = DBS-210), "
            "and size fields for sections. "
            "At offset 0x231 (561 bytes into DBS-110), a 'secureHeader' blob is present "
            "containing what appears to be a signature hash over the firmware payload: "
            "4 bytes type/flags followed by 28 bytes of hash-like data. "
            "The secureHeader indicates firmware integrity verification is implemented, "
            "however the algorithm is unknown without the RTX SDK. "
            "The payload after the headers is an encrypted/compressed RTX RTOS image "
            "with minimal plaintext strings (no credential or configuration data visible). "
            "No open-source extractor exists for RTX .fwu format at 5.x generation. "
            "Prior research (RTX 4.x) used custom tools based on RTX SDK documentation. "
            "CUCM TLS CA bundle embedded in DBS-110 and DBS-210: 23 x509 DER certificates "
            "from offset 0x231872 to 0x27124D, including Buypass Class 2 Root CA, "
            "DigiCert, FNMT (Spain), and other public CAs. "
            "These are standard CA roots used for CUCM server certificate validation during "
            "phone provisioning. The presence of a pre-loaded CA bundle in read-only firmware "
            "means CA rotation cannot occur without a firmware update."
        ),
        "fwu_header": {
            "magic": "0x66 0x46 at offset 0",
            "old_header_offset": "0xda (218 bytes)",
            "secure_header_offset": "0x231 (561 bytes) in DBS-110/DBS-210",
            "ca_bundle_offset_dbs110": "0x231872 - 0x27124D (23 x509 DER certs)",
        },
        "impact": [
            "CA bundle hardcoded in firmware -- CA rotation requires full firmware update",
            "Legacy OldFwuHeader parsing code is potential attack surface if security checks differ",
        ],
        "remediation": (
            "CA bundle should be stored in writable NVRAM to allow CA rotation. "
            "Document and validate secureHeader signature algorithm against RTX SDK specs."
        ),
    },
    {
        "id": "F3",
        "title": "RTX RTOS Architecture -- No Linux, No POSIX, No Known Filesystem Extractor",
        "severity": "LOW",
        "cvss": 0.0,
        "cvss_vector": "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N",
        "cwe": "CWE-1104",
        "description": (
            "All five IP DECT devices run the RTX proprietary RTOS (not Linux). "
            "The firmware images contain no filesystem (no SquashFS, UBI, JFFS2, or ROMFS). "
            "No credential hashes, service configuration, SSH keys, or application binaries "
            "are recoverable from the firmware images using standard tools. "
            "The RTX RTOS is a bare-metal DECT protocol stack with no general-purpose "
            "OS services (no shell, no user accounts, no SSH, no telnet). "
            "Consequently, network-facing attack surface is limited to the DECT protocol, "
            "the web-based management interface (if any), and the SIP/3PCC signaling stack. "
            "The DECT protocol implementation on RTX SoCs has historically been targeted "
            "via DECT injection attacks (Evil DECT) and has known vulnerabilities in "
            "the encrypted DECT key establishment protocol (DSC cipher). "
            "Security assessment of this platform requires: "
            "(1) physical access + JTAG/UART to read flash, OR "
            "(2) web management interface vulnerability analysis (network reachable), OR "
            "(3) DECT protocol analysis via SDR (airwave attack surface). "
            "Note: the DBS-110 and DBS-210 base stations are network-attached and will "
            "expose a web management interface on the LAN -- this interface is not "
            "visible in the firmware and requires runtime testing."
        ),
        "impact": [
            "DECT protocol attack surface (Evil DECT, DSC cipher attacks) is not preventable via firmware analysis",
            "Web management interface security cannot be assessed statically",
        ],
        "remediation": (
            "N/A for static analysis. Runtime assessment: test web management interface "
            "for default credentials, unauthenticated endpoints, and input validation. "
            "DECT security: ensure DECT security mode is set to 'encrypted and authenticated' "
            "(not 'no security' which is the DECT default)."
        ),
    },
]

SUMMARY = {
    "total":    3,
    "critical": 0,
    "high":     0,
    "medium":   0,
    "low":      3,
    "notes": (
        "All IP DECT findings are informational (LOW). The RTX RTOS architecture "
        "prevents filesystem extraction, so no credentials, configuration, or binary "
        "analysis is possible from static firmware inspection. "
        "The firmware does implement secureHeader signing (integrity check present), "
        "which is a positive security control not seen in the 3905/6901/8831 legacy series. "
        "The most significant security concern for this platform is the DECT radio attack "
        "surface (Evil DECT, phantom base station) and the web management interface, "
        "neither of which is assessable via static firmware analysis. "
        "ODM is RTX A/S (Denmark). SoC family: RTX9440 (DBS110), RTX8665 (DBS210), "
        "RTX8641 (PH6825), RTX8642 (PH6825RGD)."
    ),
}
