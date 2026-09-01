"""
Cisco SPA508G (SPA30x/SPA50x series) — RE summary
Firmware: SPA30x_SPA50x_7.5.5_FW.zip (7.5.5)
Linksys-derived architecture — completely different from 79xx/78xx/88xx
Static analysis: magic identification, strings analysis
"""

FIRMWARE = {
    "model":    "Cisco SPA508G / SPA300/SPA500 series",
    "version":  "7.5.5",
    "source":   "SPA30x_SPA50x_7.5.5_FW.zip",
    "date":     "2024-08-26",
    "files": {
        "spa50x-30x-7-5-5.bin":          "Main firmware binary (4.2MB)",
        "spa50x-30x-7-5-5.exe":          "Windows flash utility",
        "spa50x-30x-7-5-5-recovery.exe": "Windows recovery flash utility",
        "spa30X_50X_relnote_7_5_5.pdf":  "Release notes",
    },
}

# ─────────────────────────────────────────────────────────
# Binary format
# ─────────────────────────────────────────────────────────
BINARY_FORMAT = {
    "sha256":  "811341160f99832f1b6cf0e8cc72da95dc7cbb54acf02e6ed3d307ee4650b6e9",
    "size":    4219558,
    "magic":   "536b4f73 (SkOs)",
    "format":  "Custom Linksys/SPA container — 'SkOs' format",
    "arch":    "Unknown — opaque payload, not a standard ELF or Linux image",

    "strings_count":     "minimal",
    "ssl_strings_found": [";tls", "ZSsL (possible obfuscated SSL)", "K0TLS"],
    "version_string":    "7.5.5",

    "note": (
        "'SkOs' is the Linksys SPA firmware container format. The payload appears encrypted "
        "or heavily compressed. Standard zlib/gzip, squashfs, UBI magic not found. "
        "Only 3 TLS-related strings visible — firmware is opaque to static string analysis."
    ),
}

# ─────────────────────────────────────────────────────────
# Architecture — Linksys-derived, not Cisco-native
# ─────────────────────────────────────────────────────────
ARCHITECTURE = {
    "lineage": (
        "SPA series was developed by Sipura Technology, acquired by Linksys, then by Cisco. "
        "The firmware architecture is completely different from the 79xx/78xx/88xx phone lines. "
        "No secd IPC, no Java CVM, no handyiron/libseccommon.so, no UBIFS/SquashFS rootfs."
    ),

    "vs_79xx_89xx": {
        "SPA_series": "Custom SkOs container, minimal strings, Linksys-derived codebase",
        "79xx_series": "MIPS apps + Java CVM + secd IPC + OpenSSL/SSL-C",
        "78xx_88xx":  "ARM Linux rootfs + libseccommon.so + handyiron",
    },

    "finding_applicability": {
        "PHN-F12 (DTLS downgrade)": "NOT APPLICABLE — no Java CVM architecture",
        "PHN-F14 (handyiron bypass)": "NOT APPLICABLE — no libseccommon.so",
        "PHN-F15 (debug credential)": "UNKNOWN — no passwd file accessible",
        "PHN-F16 (CERT_ANY)":         "NOT APPLICABLE — no secureapp",
        "PHN-F17 (TFTP creds)":       "UNKNOWN — depends on deployment configuration",
    },
}

# ─────────────────────────────────────────────────────────
# Static analysis limitation
# ─────────────────────────────────────────────────────────
STATIC_ANALYSIS_LIMITATION = {
    "reason": (
        "SkOs container format is proprietary. Without the decryption/decompression key "
        "or a format specification, payload extraction requires dynamic analysis "
        "(JTAG, UART, firmware update MITM to capture decrypted payload in memory). "
        "Static string analysis yields minimal security-relevant information."
    ),
    "path_forward": (
        "Linksys SPA 'SkOs' format has been partially documented in open-source firmware "
        "modding communities. Decryption tools may exist. Alternatively: UART shell on "
        "physical device provides direct filesystem access."
    ),
}
