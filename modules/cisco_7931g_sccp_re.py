"""
Cisco IP Phone 7931G SCCP 9.4.2SR2-2 (ES22) — RE summary
Firmware: cmterm-7931-sccp.9-4-2SR2-2.tar
Static analysis: SBN extraction, gzip decompression, strings on apps31 + cvm31sccp
"""

FIRMWARE = {
    "model":   "Cisco IP Phone 7931G SCCP",
    "version": "9.4.2SR2-2",
    "label":   "ES22",
    "source":  "cmterm-7931-sccp.9-4-2SR2-2.tar",
}

# ─────────────────────────────────────────────────────────
# SHA256 inventory
# ─────────────────────────────────────────────────────────
SHA256 = {
    "cvm31sccp.9-4-2ES22 (decompressed)": "1cadca28",
    "note": "cvm SHA prefix only (truncated in analysis session)",
}

# ─────────────────────────────────────────────────────────
# apps binary — SSL-C dual-library (ME + standard)
# ─────────────────────────────────────────────────────────
APPS_BINARY = {
    "binary":     "apps31.9-4-2ES22.sbn",
    "arch":       "MIPS big-endian 32-bit ELF, statically linked, stripped",
    "ssl_stack":  "SSL-C ME 1.1.0 + SSL-C 2.3.1 03-Mar-2003 (dual compilation)",
    "ssl_strings": [
        "SSLv3 part of SSL-C ME 1.1.0",
        "SSLv3 part of SSL-C 2.3.1 03-Mar-2003",
    ],
    "note": (
        "7931G apps31 carries both SSL-C ME (Mobile Edition) 1.1.0 AND SSL-C standard 2.3.1. "
        "This dual-library pattern is identical to 7941/7961 and 7906/7911 SR3 (ES26) apps binaries. "
        "SSL-C ME 1.1.0 was the embedded-device variant of RSA's SSL-C library."
    ),
    "vs_7945_7942_apps": (
        "7945/7942 apps uses OpenSSL 0.9.8g. 7931G/7941/7961/7906-SR3 apps uses SSL-C ME+2.3.1. "
        "Architectural split — older RSA SSL-C vs newer OpenSSL family."
    ),
}

# ─────────────────────────────────────────────────────────
# CVM — PHN-F12 DTLS downgrade (CONFIRMED)
# ─────────────────────────────────────────────────────────
CVM_SECURITY = {
    "binary":    "cvm31sccp.9-4-2ES22.sbn",
    "sha256_prefix": "1cadca28",

    "phn_f12_applicable": True,
    "dtls_downgrade_evidence": {
        "getHasDtls": "CONFIRMED in cvm31sccp.9-4-2ES22 (1cadca28)",
        "getHasSsl":  "CONFIRMED in cvm31sccp.9-4-2ES22 (1cadca28)",
        "finding":    "PHN-F12",
    },

    "secd_ipc": {
        "status":       "CONFIRMED",
        "tvs_source":   ".secd_reqApisec_req_api_tvs.c",
        "capf_source":  ".secd_reqApisec_req_api_capf.c",
        "rand_present": False,
        "note":         "SCCP CVM — rand API absent (SIP-only marker), confirms SCCP path",
    },

    "architecture": (
        "7931G SCCP CVM follows same architecture as 7945/7965/7942/7962/7906/7911 SCCP CVMs: "
        "Java deadbeef format, secd IPC for all call-control TLS/DTLS, DTLS XML flags in CVM. "
        "PHN-F12 XmlCallManagersObject getHasDtls/getHasSsl downgrade applies."
    ),
}

# ─────────────────────────────────────────────────────────
# PHN-F12 scope extension
# ─────────────────────────────────────────────────────────
PHN_F12_7931G = {
    "id":      "PHN-F12",
    "extends": "7931G SCCP 9.4.2ES22",
    "note": (
        "7931G SCCP confirmed to carry getHasDtls/getHasSsl in CVM. PHN-F12 DTLS downgrade "
        "via malicious TFTP-delivered CallManager XML applies to the 7931G SCCP variant."
    ),
}
