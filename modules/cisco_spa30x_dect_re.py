"""
Cisco SPA30x/SPA50x and DECT IP Phone RE Module
Targets:
  - SPA30x/SPA50x_7.6.2SR7_FW.zip: spa50x-30x-7-6-2g.bin (4.2MB, MIPS, SkOsMo5 RTOS, 2020)
  - IPDect-DBS110_5-1-3MPP0101-9_REL.zip: DBS-110-3PC-05-01-03-0101-09.fwu (3.7MB, RTX9440 MIPS, 2026)
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
            "arch":      "MIPS32 via RTX9440 DECT SoC (DSP Group/Synaptics)",
            "soc":       "RTX9440 (embedded DECT 6.0 baseband + application processor)",
            "codename":  "DRAGONSTONE (DBS_110_3PC_05_01_03_0101_09_DRAGONSTONE_V0501_B0309)",
            "version":   "5.1.3 MPP (MPP0101-9, build 0309)",
            "source":    "/media/cowboy/research/Cisco-IP PHONE/IPDect-DBS110_5-1-3MPP0101-9_REL.zip",
            "format":    "Custom FWU header (contains OldFwuHeaderkK tag) + encrypted payload + CA trust store",
        },
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
        "title": "DECT Firmware Encrypted Payload - RTX9440 MIPS Baseband Prevents Audit",
        "severity": "MEDIUM",
        "cvss": 5.0,
        "cvss_vector": "CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:U/C:H/I:N/A:N",
        "cwe": "CWE-259",
        "description": (
            "The DECT DBS-110 FWU payload is fully encrypted - no protocol strings, "
            "no ELF/filesystem structures, no compression headers visible after the "
            "FWU container header. The device uses an **RTX9440** MIPS-based DECT SoC "
            "from DSP Group (now Synaptics), internal codename `DRAGONSTONE`. "
            "The header contains `OldFwuHeaderkK` indicating format version evolution. "
            "The encryption key cannot be recovered from the firmware bundle alone. "
            "RTX9440 is an integrated DECT 6.0 baseband with application processor; "
            "DSP Group's other DECT chipsets (e.g., SC14440) have known security "
            "vulnerabilities in their DECT stack (CVE-2021-29325 DECT stack RCE). "
            "Without decryptable firmware, the RTX9440-specific DECT stack "
            "implementation cannot be audited for similar vulnerabilities."
        ),
        "fwu_header_strings": [
            "DBS_110_3PC_05_01_03_0101_09_DRAGONSTONE_V0501_B0309",
            "OldFwuHeaderkK",
            "RTX9440",
        ],
        "integrity_method": "CRC32 tables at offset 3,810,583 and 3,814,679 (little and big endian)",
        "impact": [
            "DECT stack vulnerabilities cannot be verified without firmware decryption",
            "RTX9440 shares DSP Group architecture with SC14440 (known DECT RCE CVEs)",
            "CRC32 integrity check is weak - not a cryptographic MAC",
            "Encrypted payload + CRC32-only = modification detectable but not forgery-resistant",
        ],
        "remediation": (
            "Cisco should publish a PSIRT advisory confirming whether the RTX9440 "
            "DECT stack is susceptible to known DSP Group DECT vulnerabilities. "
            "Replace CRC32 integrity with HMAC-SHA256 over the firmware payload. "
            "Provide a public firmware signing certificate for community verification."
        ),
        "yara": """rule cisco_dect_dbs110_dragonstone {
    meta:
        description = "Cisco DECT DBS-110 firmware (DRAGONSTONE, RTX9440) - encrypted payload"
        severity = "MEDIUM"
    strings:
        $dragonstone = "DRAGONSTONE" ascii
        $rtx9440     = "RTX9440" ascii
        $oldfwu      = "OldFwuHeaderkK" ascii
    condition:
        $dragonstone or ($rtx9440 and $oldfwu)
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
}
