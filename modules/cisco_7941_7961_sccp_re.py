"""
Cisco IP Phone 7941/7961 SCCP 9.4.2SR3-1 (ES26) — RE summary
Firmware: cmterm-7941_7961-sccp.9-4-2SR3-1.zip
Static analysis: SBN extraction, gzip decompression, strings on apps41 + cvm41sccp
"""

FIRMWARE = {
    "model":   "Cisco IP Phone 7941/7961 SCCP",
    "version": "9.4.2SR3-1",
    "label":   "ES26",
    "source":  "cmterm-7941_7961-sccp.9-4-2SR3-1.zip",
}

# ─────────────────────────────────────────────────────────
# SHA256 inventory
# ─────────────────────────────────────────────────────────
SHA256 = {
    "cvm41sccp.9-4-2ES26 (decompressed)": "5ce5e53b",
    "note": "cvm SHA prefix only (truncated in analysis session)",
}

# ─────────────────────────────────────────────────────────
# apps binary — SSL-C dual-library (ME + standard)
# ─────────────────────────────────────────────────────────
APPS_BINARY = {
    "binary":    "apps41.9-4-2ES26.sbn",
    "arch":      "MIPS big-endian 32-bit ELF, statically linked, stripped",
    "ssl_stack": "SSL-C ME 1.1.0 + SSL-C 2.3.1 03-Mar-2003 (dual compilation)",
    "ssl_strings": [
        "SSLv3 part of SSL-C ME 1.1.0",
        "SSLv3 part of SSL-C 2.3.1 03-Mar-2003",
    ],
    "model_codes": {
        "term41": "7941 device defaults",
        "term61": "7961 device defaults",
    },
    "note": (
        "apps41 7941/7961 SCCP ES26 carries SSL-C ME 1.1.0 + SSL-C 2.3.1 dual library. "
        "Same pattern as apps31 (7931G), apps11 SR3 (7906/7911). "
        "Contrast with 7945/7942 which use OpenSSL 0.9.8g."
    ),
}

# ─────────────────────────────────────────────────────────
# CVM — PHN-F12 DTLS downgrade (CONFIRMED)
# ─────────────────────────────────────────────────────────
CVM_SECURITY = {
    "binary":        "cvm41sccp.9-4-2ES26.sbn",
    "sha256_prefix": "5ce5e53b",

    "phn_f12_applicable": True,
    "dtls_downgrade_evidence": {
        "getHasDtls": "CONFIRMED in cvm41sccp.9-4-2ES26 (5ce5e53b)",
        "getHasSsl":  "CONFIRMED in cvm41sccp.9-4-2ES26 (5ce5e53b)",
        "finding":    "PHN-F12",
    },

    "secd_ipc": {
        "status":       "CONFIRMED",
        "tvs_source":   ".secd_reqApisec_req_api_tvs.c",
        "capf_source":  ".secd_reqApisec_req_api_capf.c",
        "rand_present": False,
        "note":         "SCCP CVM architectural marker",
    },

    "architecture": (
        "7941/7961 SCCP CVM is the same Java deadbeef + secd IPC architecture as all "
        "analyzed 79xx SCCP models. PHN-F12 getHasDtls/getHasSsl DTLS downgrade confirmed."
    ),
}

# ─────────────────────────────────────────────────────────
# PHN-F12 scope extension
# ─────────────────────────────────────────────────────────
PHN_F12_7941_7961 = {
    "id":      "PHN-F12",
    "extends": "7941/7961 SCCP 9.4.2ES26",
    "note": (
        "7941/7961 SCCP confirmed to carry getHasDtls/getHasSsl in CVM41. PHN-F12 DTLS "
        "downgrade via malicious TFTP-delivered CallManager XML applies to 7941/7961 SCCP."
    ),
}
