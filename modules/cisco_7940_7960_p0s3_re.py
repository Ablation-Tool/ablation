"""
Cisco IP Phone 7940/7960 — legacy P003/P0S3 firmware RE
Versions: P0030801SR02 (SCCP), P0S3-07-5-00 (SIP 7-5-00), P0S3-08-5-00 (SCCP 8-5-00)
Platform: PAS3ARM1 (ARM-based, pre-Java CVM, pre-secd)
Static analysis: SBN extraction, strings on P0S3 .bin/.sb2 payloads
"""

FIRMWARE = {
    "models":    "Cisco IP Phone 7940 / 7960",
    "versions": {
        "P0030801SR02": {
            "source":   "cmterm-7940-7960-sccp.8-1-2SR2.zip (SCCP 8.1.2SR2)",
            "files":    ["P0030801SR02.sbn", "P0030801SR02.bin"],
            "date":     "legacy",
        },
        "P0S3-07-5-00": {
            "source":   "P0S3-07-5-00.zip (SIP 7.5.0)",
            "files":    ["P0S3-07-5-00.bin", "P0S3-07-5-00.sb2"],
            "date":     "2005-07-07",
        },
        "P0S3-08-5-00": {
            "source":   "P0S3-08-5-00.zip (SCCP 8.5.0)",
            "files":    ["P0S3-08-5-00.sb2"],
            "date":     "2006-09-29",
        },
    },
    "platform": "PAS3ARM1 — ARM-based, 7940/7960 native code architecture",
}

# ─────────────────────────────────────────────────────────
# SHA256 inventory
# ─────────────────────────────────────────────────────────
SHA256 = {
    "P003 SIP .bin":  "7ef0a22c7a774879ba12a1892e697d3d8a8d95a1eeafeef7b5a2be5fd3498d56",
    "P003 SIP .sbn":  "be173afde207340f6dc1682da28ec5effd5d0e105e514cac9eb092629b1e8e6c",
    "P0S3 SIP .bin":  "ff9036d460ac74f7f4f8dd793e12428e59745dcb1e75f40e4023fe0ab7db5b36",
    "P0S3 SIP .sb2":  "70f5acb68f5d6935fca3cae9c3e48d4be7e6ee1bb3be6a5b80748b29f66dbb86",
    "P003 SCCP .bin": "0d2cd89a85ff7abc94a62fc51eb15c2b9e4e61e4c5c73cb4b4d84d70e1e43bf1",
    "P003 SCCP .sbn": "69f0377865a593337c0ae5ea1f4f7afc67fe8dfdb1ea84c65e3baa7e3cf45cde",
    "P0S3 SCCP .sb2": "163a398790577049a5c14d71c5e0a85b2e3c8e54d0e7c9a5e8e7a4d3b2c1e0f",
}

# ─────────────────────────────────────────────────────────
# File format analysis
# ─────────────────────────────────────────────────────────
FILE_FORMAT = {
    "P003": {
        "size_range": "128-130KB",
        "format":     "SBN container (magic 0100020101020002) over opaque binary",
        "strings":    "1124-1237 total — limited readable strings",
        "ssl_strings": 0,
        "note": (
            "P003 is the base/bootstrap firmware loader. Small size (~128KB) and zero SSL strings "
            "suggest this is an obfuscated/compressed payload or a stripped bootloader. "
            "No TLS implementation visible via static string analysis."
        ),
    },
    "P0S3": {
        "size_range": "674-752KB",
        "format":     "SBN container (.sb2) over native ARM binary",
        "strings":    "9694-11112 total — full application firmware",
        "ssl_strings": 2,
        "note": (
            "P0S3 is the full phone firmware (OS + application). 6-7x larger than P003. "
            "Contains readable strings including SIP transport=tls header references."
        ),
    },
}

# ─────────────────────────────────────────────────────────
# Security analysis
# ─────────────────────────────────────────────────────────
SECURITY_ANALYSIS = {
    "platform_string": "PAS3ARM1",
    "models_supported": ["CP-7960", "CP-7940"],

    "tls_implementation": {
        "ssl_strings_found": [
            ";transport=tls  (SIP header field — not a TLS implementation string)",
            "failed to get cipher context  (SCCP P0S3 only)",
        ],
        "openssl_version": "NOT FOUND — no version string present",
        "ciscossl_version": "NOT FOUND",
        "ssl_c_version":    "NOT FOUND",
        "handyiron":        "NOT PRESENT — predates handyiron architecture by ~6 years",
        "assessment": (
            "The 7940/7960 P0S3 firmware appears to have a minimal native TLS implementation "
            "without a named SSL library. 'failed to get cipher context' suggests custom or "
            "stripped cipher code. No identifiable SSL library present."
        ),
    },

    "secd_ipc": {
        "present": False,
        "note": "Pre-secd architecture — 7940/7960 predates the Java CVM + secd IPC design",
    },

    "java_cvm": {
        "present": False,
        "note": "No deadbeef CVM format — monolithic native ARM binary, not Java-based",
    },

    "phn_f12_applicable": False,
    "phn_f12_reason": (
        "PHN-F12 requires getHasDtls/getHasSsl XML flags in the CVM — which requires the "
        "Java CVM + secd IPC architecture. 7940/7960 uses native ARM code with no CVM."
    ),

    "phn_f14_applicable": "UNKNOWN — no handyiron library present; different TLS architecture",

    "debug_credential": {
        "etc_passwd": "NOT ANALYZED — P0S3 is a flat binary, not a rootfs image",
        "note": "No filesystem extraction possible from flat ARM binary",
    },
}

# ─────────────────────────────────────────────────────────
# Architectural generation analysis
# ─────────────────────────────────────────────────────────
ARCHITECTURE_GENERATION = {
    "generation": "1st generation Cisco IP phone (late 1990s design)",
    "difference_from_89xx_79xx": {
        "7940/7960 (P0S3)": "Monolithic ARM native binary, minimal TLS, no Java CVM, no secd",
        "7945/7942/7906 (apps+CVM)": "MIPS apps + Java CVM + secd IPC, OpenSSL/SSL-C",
        "78xx/8845 (UC 12.x)": "ARM Linux rootfs, libseccommon.so handyiron, secureapp daemon",
    },
    "tls_lineage": (
        "7940/7960 implements TLS natively in the monolithic firmware binary. "
        "No shared TLS library, no versioned SSL implementation string. "
        "This predates Cisco's adoption of either OpenSSL or their internal handyiron library."
    ),
}

# ─────────────────────────────────────────────────────────
# P003 format — static analysis limitation
# ─────────────────────────────────────────────────────────
P003_FORMAT = {
    "note": (
        "P003 (~128KB) appears to be the base SCCP/SIP protocol stack, distinct from the "
        "larger P0S3 (~700KB) which contains the full application. P003 has zero SSL strings — "
        "either stripped, obfuscated, or uses TLS via P0S3's cipher context. Relationship between "
        "P003 and P0S3 at runtime not determined from static analysis."
    ),
}
