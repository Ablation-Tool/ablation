"""
Cisco IP Phone 7906/7911 SCCP 9.4.2SR3-1 (ES26) — delta vs ES9 (SR1)
Firmware: cmterm-7911_7906-sccp.9-4-2SR3-1.zip
Static analysis: SBN extraction, gzip decompression, strings on apps11 + cvm11sccp
"""

FIRMWARE = {
    "model":      "Cisco IP Phone 7906/7911 SCCP",
    "version":    "9.4.2SR3-1",
    "label":      "ES26",
    "source":     "cmterm-7911_7906-sccp.9-4-2SR3-1.zip",
    "vs_prior":   "cmterm-7911_7906-sccp.9-4-2SR1-1.zip (ES9)",
}

# ─────────────────────────────────────────────────────────
# SHA256 — delta from ES9
# ─────────────────────────────────────────────────────────
SHA256_DELTA = {
    "cvm11sccp ES9  (9.4.2SR1)": "daee9584ca3f420a0935161789b5d37faae41951f66f24aa8f45c99da302cc2c",
    "cvm11sccp ES26 (9.4.2SR3)": "4ef29aab",
    "cvm_changed": True,
    "apps11 ES9":  "62b2da5b6cca9a686227cf060cbe88c7ca7acb7c4bb1560d2d0d113d5955d387",
    "apps11 ES26": "(not SHA'd independently — needs separate check)",
    "note": "cvm11sccp SHA changed ES9 → ES26 — CVM updated. PHN-F12 present in both.",
}

# ─────────────────────────────────────────────────────────
# apps binary — SSL upgrade ES9 → ES26
# ─────────────────────────────────────────────────────────
APPS_BINARY_DELTA = {
    "ES9_ssl": (
        "OpenSSL 0.9.8g generic TLS path: 'failed to create TLS ctx, err %d'. "
        "Standard OpenSSL, no SSL-C."
    ),
    "ES26_ssl": "SSL-C ME 1.1.0 + SSL-C 2.3.1 03-Mar-2003 (dual compilation, same as apps31/apps41)",
    "ssl_library_change": (
        "7906/7911 apps SWITCHED from OpenSSL 0.9.8g (ES9/SR1) to SSL-C ME 1.1.0+2.3.1 (ES26/SR3). "
        "This is the reverse of what most other Cisco phone lines did — transitioning TO SSL-C rather "
        "than away from it. Likely reflects a build system unification bringing 7906/7911 in line with "
        "7931G/7941/7961 which already used SSL-C."
    ),
    "handyiron_status": "NOT PRESENT in either ES9 or ES26 apps11 — apps binary uses SSL-C, not handyiron",
}

# ─────────────────────────────────────────────────────────
# CVM security — PHN-F12 CONFIRMED in ES26
# ─────────────────────────────────────────────────────────
CVM_SECURITY = {
    "ES26_sha256_prefix": "4ef29aab",

    "phn_f12_applicable": True,
    "dtls_downgrade_evidence": {
        "getHasDtls": "CONFIRMED in cvm11sccp.9-4-2ES26 (4ef29aab)",
        "getHasSsl":  "CONFIRMED in cvm11sccp.9-4-2ES26 (4ef29aab)",
        "finding":    "PHN-F12",
    },

    "secd_ipc": {
        "status":       "CONFIRMED",
        "tvs_source":   ".secd_reqApisec_req_api_tvs.c",
        "capf_source":  ".secd_reqApisec_req_api_capf.c",
        "rand_present": False,
    },

    "continuity_from_ES9": (
        "getHasDtls/getHasSsl CONFIRMED in both ES9 and ES26 CVMs. PHN-F12 persists across "
        "the SR1→SR3 update. CVM SHA changed (new features/bug fixes) but DTLS downgrade "
        "vulnerability was not addressed."
    ),
}

# ─────────────────────────────────────────────────────────
# SSL-C taxonomy across 79xx families
# ─────────────────────────────────────────────────────────
SSL_LIBRARY_TAXONOMY = {
    "OpenSSL_0.9.8g": {
        "models": ["7945/7965 all versions", "7942/7962 all versions", "7906/7911 ES9/SR1"],
        "lib": "OpenSSL 0.9.8g 19 Oct 2007",
    },
    "SSL_C_ME_plus_2.3.1": {
        "models": ["7931G ES22", "7941/7961 ES26", "7906/7911 ES26/SR3", "7970/7971 all versions"],
        "lib": "SSL-C ME 1.1.0 + SSL-C 2.3.1 03-Mar-2003 (RSA Security)",
    },
    "CiscoSSL": {
        "models": ["78xx 12.x UC", "89xx all versions", "Jabber"],
        "lib": "CiscoSSL 1.0.2o / 6.0-fips-dev",
    },
    "note": (
        "7906/7911 is the only model that CHANGED SSL library family between engineering specials. "
        "All other models use a consistent SSL library across versions."
    ),
}
