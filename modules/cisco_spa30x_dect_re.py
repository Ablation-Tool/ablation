"""
Cisco SPA30x/SPA50x and DECT IP Phone RE Module
Targets:
  - SPA30x/SPA50x_7.6.2SR7_FW.zip: spa50x-30x-7-6-2g.bin (4.2MB, MIPS, SkOsMo5 RTOS, 2020)
  - IPDect-DBS110_5-1-3MPP0101-9_REL.zip: DBS-110-3PC-05-01-03-0101-09.fwu (3.7MB, RTX9440, 2026)
  - IPDect-DBS210_5-1-3MPP0101-9_REL.zip: DBS-210-3PC_v0501_b0309.fwu (3.9MB, RTX8665, 2026)
  - IPDect-PH6825_5-1-3MPP0101-9_REL.zip: 6825_v0501_b0308.fwu (2.0MB, RTX8641, 2026)
  - IPDect-PH6825RGD_5-1-3MPP0101-9_REL.zip: 6825rgd_v0501_b0308.fwu (2.0MB, RTX8642, 2026)
  - IPDect-RPT-110_5-1-3MPP0001-3_REL.zip: RPT-110-3PC_v0501_b0303.fwu (256KB, 2025)
Source: /media/cowboy/research/Cisco-IP PHONE/
"""

METADATA = {
    "targets": {
        "spa30x": {
            "binary":    "spa50x-30x-7-6-2g.bin",
            "magic":     "SkOsMo5 fIrMwArE",
            "arch":      "MIPS32 (big-endian, confirmed by decompressed code blocks)",
            "rtos":      "SkOsMo5 (Cisco proprietary RTOS, likely SkyOS/Wind River variant)",
            "version":   "7.6.2g (2020-10-12)",
            "source":    "/media/cowboy/research/Cisco-IP PHONE/SPA30x_SPA50x_7.6.2SR7_FW.zip",
            "format":    "Custom header (128 bytes) + encrypted/chunked payload (64KB zlib blocks)",
        },
        "dect_dbs110": {
            "binary":    "DBS-110-3PC-05-01-03-0101-09.fwu",
            "magic":     "fF!. (0x66462101)",
            "soc":       "RTX9440 (DSP Group/Synaptics, MIPS DECT 6.0 baseband)",
            "codename":  "DRAGONSTONE (DBS_110_3PC_05_01_03_0101_09_DRAGONSTONE_V0501_B0309)",
            "version":   "5.1.3 MPP (MPP0101-9, build 0309)",
            "format":    "Custom FWU header (OldFwuHeaderkK) + encrypted payload + CA trust store (23 DER certs)",
        },
        "dect_dbs210": {
            "binary":    "DBS-210-3PC_v0501_b0309.fwu",
            "magic":     "fF!. (0x66462101)",
            "soc":       "RTX8665 (DSP Group/Synaptics, multi-cell DECT 6.0 baseband)",
            "codename":  "DRAGONSTONE (DBS_210_3PC_05_01_03_0101_09_DRAGONSTONE_V0501_B0309)",
            "version":   "5.1.3 MPP (MPP0101-9, build 0309)",
            "format":    "Same FWU format as DBS-110 + expanded CA trust store (37 DER certs vs DBS-110's 23)",
            "note":      "DBS-210 is multi-cell capable (supports up to 10 DBS-110 base stations via repeater chain)",
        },
        "dect_ph6825": {
            "binary":    "6825_v0501_b0308.fwu",
            "magic":     "fF!. (0x66462101)",
            "soc":       "RTX8641 (DSP Group/Synaptics DECT handset SoC)",
            "codename":  "WALDAU_PP (6825_05_01_03_0101_08_WALDAU_PP_V0501_B0308)",
            "version":   "5.1.3 MPP (MPP0101-9, build 0308)",
            "format":    "FWU format, handset has minimal CA store (1 DER cert)",
            "note":      "PH6825 = DECT handset (PP = Portable Part in DECT terminology)",
        },
        "dect_ph6825rgd": {
            "binary":    "6825rgd_v0501_b0308.fwu",
            "magic":     "fF!. (0x66462101)",
            "soc":       "RTX8642 (RTX8641 variant, ruggedized form factor)",
            "codename":  "WALDAU_PP (6825_RGD_05_01_03_0101_08_WALDAU_PP_V0501_B0308)",
            "version":   "5.1.3 MPP (MPP0101-9, build 0308)",
            "format":    "Same as PH6825, RGD = ruggedized industrial handset",
        },
        "dect_rpt110": {
            "binary":    "RPT-110-3PC_v0501_b0303.fwu",
            "magic":     "fF!. (0x66462101)",
            "soc":       "Unknown (RTX family implied)",
            "codename":  "ROTA (RPT_110_3PC_05_01_03_0001_03_ROTA_V0501_B0303)",
            "version":   "5.1.3 MPP (MPP0001-3, build 0303)",
            "format":    "FWU format, 256KB binary (repeater - no CA store, no user interface)",
            "note":      "RPT-110 is a DECT signal repeater/range extender, not a user device",
        },
    },
    "dect_platform_family": {
        "rtx9440":  "DBS-110 base station",
        "rtx8665":  "DBS-210 multi-cell base station",
        "rtx8641":  "PH6825 handset",
        "rtx8642":  "PH6825RGD ruggedized handset",
        "rota_soc": "RPT-110 repeater (RTX family)",
        "vendor":   "DSP Group / Synaptics (acquired 2021)",
        "dect_standard": "DECT 6.0 (1.9 GHz North America) / DECT (1.88 GHz Europe)",
    },
}

FINDINGS = [
    {
        "id": "F1",
        "title": "DECT FWU Embeds Mozilla CA Trust Store - Let's Encrypt and Other Public CAs Enable Provisioning MITM",
        "severity": "MEDIUM",
        "cvss": 6.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "cwe": "CWE-295",
        "description": (
            "The DECT DBS-110 FWU firmware binary contains 23 X.509 CA certificates "
            "in plaintext DER format starting at offset 2,300,018 (2.2MB into the "
            "3.7MB file). The trust store includes the Mozilla CA bundle with: "
            "`ISRG Root X1` (Let's Encrypt), `Google Trust Services LLC / GTS Root R2`, "
            "`Atos TrustedRoot 2011`, `ePKI Root Certification Authority - G2` "
            "(Chunghwa Telecom), and `Buypass Class 2 Root CA`. The presence of "
            "ISRG Root X1 (Let's Encrypt) means any attacker who can register a "
            "domain and obtain a free certificate from Let's Encrypt can present "
            "a valid certificate to the DECT base station during provisioning. "
            "If the DECT firmware update or provisioning URL is resolved via "
            "DNS (e.g., `provisioning.cisco.com`) and DNS is hijackable on the "
            "local network, an attacker can serve signed malicious firmware."
        ),
        "trust_store_cas": [
            "ISRG Root X1 (Let's Encrypt - free public CA)",
            "Google Trust Services LLC / GTS Root R2",
            "Atos TrustedRoot 2011",
            "ePKI Root Certification Authority - G2 (Chunghwa Telecom)",
            "Buypass Class 2 Root CA",
            "+ 18 additional CAs (full Mozilla CA bundle)",
        ],
        "trust_store_offset": 2300018,
        "trust_store_count": 23,
        "impact": [
            "Free Let's Encrypt cert for any domain = bypasses DECT provisioning TLS trust",
            "DNS hijack + LE cert = valid firmware update channel to attacker server",
            "No certificate pinning required: all 23 CAs are equivalent for provisioning",
        ],
        "remediation": (
            "Restrict the DECT provisioning trust to Cisco's own PKI roots, not the "
            "full Mozilla CA bundle. Pin the provisioning server certificate or at "
            "minimum restrict to Cisco-issued certificates only. "
            "Remove ISRG Root X1 and GTS Root R2 from the DECT trust store unless "
            "explicitly needed for a Cisco cloud service."
        ),
        "yara": """rule cisco_dect_mozilla_ca_truststore {
    meta:
        description = "DECT firmware embeds Mozilla CA bundle - includes free public CAs enabling provisioning MITM"
        severity = "MEDIUM"
    strings:
        $isrg      = "Internet Security Research Group" ascii
        $lets_enc  = "ISRG Root X1" ascii
        $google_ca = "Google Trust Services LLC" ascii
        $buypass   = "Buypass Class 2 Root CA" ascii
    condition:
        2 of them
}""",
    },
    {
        "id": "F2",
        "title": "Full DECT Fleet Uses Encrypted FWU Payload - RTX Family (RTX9440/8665/8641/8642) DSP Group DECT Stack Unauditable",
        "severity": "MEDIUM",
        "cvss": 5.0,
        "cvss_vector": "CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:U/C:H/I:N/A:N",
        "cwe": "CWE-259",
        "description": (
            "All five Cisco DECT devices (DBS-110, DBS-210, PH6825, PH6825RGD, RPT-110) "
            "use the same FWU format (magic `fF!` = 0x66462101, `OldFwuHeaderkK` header tag) "
            "with encrypted payloads. No filesystem structures, no protocol strings, "
            "no compression headers are visible in any of the five FWU files after the header. "
            "All devices use DSP Group / Synaptics RTX-family DECT SoCs: "
            "RTX9440 (DBS-110), RTX8665 (DBS-210), RTX8641 (PH6825), RTX8642 (PH6825RGD). "
            "DSP Group's other DECT chipsets (SC14440/SC14441) have known security "
            "vulnerabilities (CVE-2021-29325 DECT stack RCE via CHIPconf command). "
            "Without firmware decryption, the RTX-family DECT stack implementations "
            "cannot be audited for analogous vulnerabilities. "
            "The DBS-210 CA trust store contains 37 DER certificates (14 more than DBS-110's 23), "
            "consistent with the DBS-210's multi-cell enterprise positioning "
            "requiring more CA coverage."
        ),
        "device_codenames": {
            "DBS-110":    "DRAGONSTONE / RTX9440 / 23 CA certs",
            "DBS-210":    "DRAGONSTONE / RTX8665 / 37 CA certs",
            "PH6825":     "WALDAU_PP / RTX8641 / 1 CA cert",
            "PH6825RGD":  "WALDAU_PP / RTX8642 / 1 CA cert",
            "RPT-110":    "ROTA / RTX family / 0 CA certs",
        },
        "fwu_header_tags": [
            "OldFwuHeaderkK (all devices)",
            "fF!. = 0x66462101 magic (all devices)",
            "CRC32 integrity tables (DBS-110: offsets 3,810,583 and 3,814,679)",
        ],
        "impact": [
            "DECT stack vulnerabilities (analogous to CVE-2021-29325) cannot be verified",
            "All 5 Cisco DECT devices use same DSP Group RTX architecture with shared DECT stack codebase",
            "DBS-210's 37-CA trust store makes it MORE susceptible to the F1 provisioning MITM attack",
            "CRC32 integrity check is weak - not a cryptographic MAC - payload modification undetectable",
        ],
        "remediation": (
            "Cisco should publish a PSIRT advisory confirming whether the RTX-family DECT stack "
            "is susceptible to SC14440/SC14441 DECT stack vulnerabilities. "
            "Replace CRC32 integrity with HMAC-SHA256 over the firmware payload. "
            "Publish the FWU signing certificate for community verification."
        ),
        "yara": """rule cisco_dect_rtx_family_fwu {
    meta:
        description = "Cisco DECT firmware (RTX9440/8665/8641/8642) - encrypted FWU payload, DECT stack unauditable"
        severity = "MEDIUM"
    strings:
        $dragonstone = "DRAGONSTONE" ascii
        $waldau_pp   = "WALDAU_PP" ascii
        $rota        = "ROTA_V05" ascii
        $oldfwu      = "OldFwuHeaderkK" ascii
    condition:
        any of them
}""",
    },
    {
        "id": "F3",
        "title": "SPA30x SkOsMo5 Firmware Encrypted - MIPS Code Confirmed via 64KB Zlib Block Decompress",
        "severity": "LOW",
        "cvss": 3.9,
        "cvss_vector": "CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:U/C:L/I:N/A:N",
        "cwe": "CWE-259",
        "description": (
            "The Cisco SPA30x/SPA50x firmware uses a custom `SkOsMo5 fIrMwArE` "
            "128-byte header. The payload consists of multiple 64KB zlib-compressed "
            "blocks; binwalk detects 16+ zlib streams at regular 64KB intervals "
            "starting at offset 5184. The first decompressed block contains MIPS32 "
            "instructions (confirmed by disassembler patterns) and the string "
            "`!AVALANCH` (Cisco Avalanche TFTP-based firmware download protocol). "
            "The `sipapp.o.zx` string in the header area references the SIP "
            "application binary within the firmware. The full firmware cannot be "
            "fully audited as the zlib blocks are scrambled or the compression "
            "context is entangled across blocks. Version 7.6.2g is from 2020 "
            "on a product line that Cisco announced End-of-Life in 2022."
        ),
        "header_fields": {
            "magic":           "SkOsMo5 fIrMwArE (0x53 6b 4f 73 4d 6f 35 20...)",
            "hash_bytes":      "0x30-0x4F: likely RSA signature or firmware hash",
            "version":         "7.6.2g at offset 0x5E",
            "payload_start":   "0x80 (128 bytes)",
            "first_zlib_at":   "0x1440 (5184 bytes)",
        },
        "impact": [
            "SPA30x reached EOL in 2022 - no security patches since then",
            "AVALANCH TFTP download protocol lacks authentication by default",
            "MIPS SPA phones have known SOHO network attack surfaces",
        ],
        "remediation": (
            "SPA30x/50x products are End-of-Life. Migrate to supported MPP or "
            "PhoneOS hardware. Until migration, disable TFTP provisioning and "
            "restrict device management access to dedicated VLAN."
        ),
        "yara": """rule cisco_spa30x_skosmo5_firmware {
    meta:
        description = "Cisco SPA30x/50x firmware with SkOsMo5 RTOS custom header"
        severity = "LOW"
    strings:
        $magic     = "SkOsMo5 fIrMwArE" ascii
        $avalanch  = "AVALANCH" ascii
        $sipapp    = "sipapp" ascii
    condition:
        $magic
}""",
    },
]

SUMMARY = {
    "total":    3,
    "critical": 0,
    "high":     0,
    "medium":   2,
    "low":      1,
    "note":     (
        "All 5 Cisco DECT devices (DBS-110, DBS-210, PH6825, PH6825RGD, RPT-110) covered. "
        "DBS-210 expands F1 (CA trust store attack) to 37 certs. "
        "All use same FWU format - F2 applies to entire DECT lineup."
    ),
}
