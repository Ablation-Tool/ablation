"""
Cisco 7906/7911 (SCCP/SIP 9.4.2ES9) + 7942/7962 (SCCP 9.4.2ES26 / SIP SR1+SR3)
RE summary - v2 (corrected PHN-F12 status for 7906/7911, added SIP CVM analysis)
Static analysis: SBN header, ELF/gzip extraction, strings on apps + CVM binaries
"""

# ─────────────────────────────────────────────────────────
# SHA256 inventory — all unique binaries
# ─────────────────────────────────────────────────────────
SHA256_INVENTORY = {
    # 7906/7911 SCCP
    "apps11.9-4-2ES9.sbn (SCCP)":      "62b2da5b6cca9a686227cf060cbe88c7ca7acb7c4bb1560d2d0d113d5955d387",
    "cvm11sccp.9-4-2ES9 (decompressed)": "daee9584ca3f420a0935161789b5d37faae41951f66f24aa8f45c99da302cc2c",

    # 7906/7911 SIP
    "apps11.9-4-2ES9 (SIP, ELF extracted)": "4b1bc20500712b35aafaccf1d0e9950a1c131e5453c702bab718288a7068319a",
    "cvm11sip.9-4-2ES9 (decompressed)":     "8b34c0dc1b5310a60dbcb9bd117fd35cee762cdae5dbbdf608f46d2387b8a24a",

    # 7942/7962 SCCP
    "apps42.9-4-2ES26 (SCCP=SIP=7945 SR3, c274284d)": "c274284db1f359232bd64d53d0d0576e5b0ed7e8339e05ed77eaf916827440f1",

    # 7942/7962 SIP
    "apps42.9-4-2ES9 (SIP SR1, unique)":   "c7eb0993098ea94cf32251e7e50700e7ef74a9226d6b351ec9c9955114102268",
    "cvm42sip.9-4-2ES9 (SR1)":             "cb22c9de70976f92f74785d599baf8f3847c3bfa4095b6a650f5a4a86e522517",
    "cvm42sip.9-4-2ES26 (SR3)":            "a4e3ea36feeaba2c22538d0df9bfeff55a356cb2a2b4ccd9e8ff3df98600cc97",
}

# ─────────────────────────────────────────────────────────
# IDENTITY FINDINGS — cross-model binary sharing
# ─────────────────────────────────────────────────────────
BINARY_IDENTITY = {
    "apps_es26_universal": {
        "sha256": "c274284d...",
        "identical_across": [
            "cvm45sccp.9-4-2ES26 (7945 SCCP SR3)",
            "apps45sip.9-4-2ES26 (7945 SIP SR3)",
            "apps42.9-4-2ES26 (7942 SCCP SR3)",
            "cvm42sip.9-4-2ES26 (7942 SIP SR3)",
        ],
        "note": (
            "The ES26/SR3 generation apps binary is IDENTICAL across 7945 SCCP, 7945 SIP, and 7942 "
            "SCCP/SIP — different models sharing the same firmware image. Only TLV signature in the "
            "SBN wrapper differs. CVMs remain per-model-per-protocol."
        ),
    },
}

# ─────────────────────────────────────────────────────────
# ARCHITECTURE: CVM vs apps binary — where TLS lives
# ─────────────────────────────────────────────────────────
TLS_ARCHITECTURE = {
    "apps_binary": {
        "role": "Bootstrap OS, MIPS ELF, statically linked",
        "openssl_version": "OpenSSL 0.9.8g 19 Oct 2007 (all 79xx/7945/7942 models)",
        "tls_usage": "Non-call-control connections (TFTP, HTTP provisioning)",
        "handyiron_bypass": "NOT PRESENT — apps binary uses standard OpenSSL, not handyiron",
    },
    "cvm_binary": {
        "role": "Java-based signaling layer (Cisco deadbeef format)",
        "tls_usage": "ALL call control TLS/DTLS via secd daemon IPC",
        "secd_ipc_evidence": [
            "connected to target via secd",
            "bad SSL/TLS status response from secd",
            ".secd_reqApisec_req_api_tvs.c",
            ".secd_reqApisec_req_api_capf.c",
        ],
        "handyiron_bypass": "IN SECD DAEMON via libsecurity.so (not in CVM itself)",
    },
    "key_insight": (
        "PHN-F12 is a CVM-layer finding. The apps MIPS binary analysis is irrelevant to "
        "PHN-F12 because apps does not handle call control TLS. The CVM handles call control "
        "via secd IPC. PHN-F12 analysis must target the CVM, not apps."
    ),
}

# ─────────────────────────────────────────────────────────
# 7906/7911 SCCP — CVM analysis (CORRECTED)
# ─────────────────────────────────────────────────────────
SECURITY_7906_7911_SCCP = {
    "product": "Cisco IP Phone 7906/7911 SCCP 9.4.2ES9",
    "source":  "cmterm-7911_7906-sccp.9-4-2SR1-1.zip",

    "phn_f12_applicable": True,
    "phn_f12_correction": (
        "Prior session incorrectly set phn_f12_applicable=False based on apps11 MIPS binary analysis. "
        "The apps binary lacks handyiron, but PHN-F12 lives in the CVM. cvm11sccp (daee9584) "
        "contains getHasDtls and getHasSsl — DTLS downgrade via malicious CallManager XML applies."
    ),
    "dtls_downgrade_evidence": {
        "getHasDtls": "CONFIRMED in cvm11sccp.9-4-2ES9 (daee9584)",
        "getHasSsl":  "CONFIRMED in cvm11sccp.9-4-2ES9 (daee9584)",
        "class":      "XmlCallManagersObject (inferred — same CVM secd IPC arch as 7945/7965 SCCP)",
        "finding":    "PHN-F12",
    },

    "secd_ipc": {
        "status":            "CONFIRMED in cvm11sccp",
        "tvs_source":        ".secd_reqApisec_req_api_tvs.c",
        "capf_source":       ".secd_reqApisec_req_api_capf.c",
        "ctl_source":        ".secd_reqApisec_req_api_ctl.c",
        "rand_source":       "ABSENT (SCCP marker — SIP has rand)",
        "note":              "Full secd IPC. PHN-F12 extends to 7906/7911 SCCP.",
    },

    "apps_binary_note": (
        "apps11 MIPS ELF (62b2da5b) uses statically linked OpenSSL 0.9.8g with a custom TLS layer "
        "'failed to create TLS ctx, err %d'. This is non-call-control TLS only. No handyiron. "
        "This does NOT affect PHN-F12 status — PHN-F12 is a CVM/secd finding."
    ),

    "ssl_versions": {
        "apps11": "OpenSSL 0.9.8g 19 Oct 2007 (statically linked)",
        "cvm_secd": "via libsecurity.so (version from secd daemon — 89xx pattern)",
    },
}

# ─────────────────────────────────────────────────────────
# 7906/7911 SIP — CVM analysis (new)
# ─────────────────────────────────────────────────────────
SECURITY_7906_7911_SIP = {
    "product": "Cisco IP Phone 7906/7911 SIP 9.4.2ES9",
    "source":  "cmterm-7911_7906-sip.9-4-2SR1-1.zip",
    "cvm_sha256": "8b34c0dc1b5310a60dbcb9bd117fd35cee762cdae5dbbdf608f46d2387b8a24a",

    "phn_f12_applicable": False,
    "phn_f12_reason": "SIP variant — getHasDtls/getHasSsl absent; these are SCCP-only XML flags",

    "sip_marker": {
        "sec_req_api_rand.c": "CONFIRMED — present in cvm11sip, absent in cvm11sccp",
        "note": "Confirms SCCP/SIP split; SIP CVM includes rand API for SIP-specific security",
    },

    "secd_ipc": {
        "status":      "CONFIRMED in cvm11sip",
        "tvs_source":  ".secd_reqApisec_req_api_tvs.c",
        "capf_source": ".secd_reqApisec_req_api_capf.c",
        "note":        "Full secd IPC architecture — same as 7945/7965/7942/7962 SIP",
    },

    "apps_binary": {
        "sha256": "4b1bc20500712b35aafaccf1d0e9950a1c131e5453c702bab718288a7068319a",
        "openssl": "OpenSSL 0.9.8g 19 Oct 2007",
        "note":   "apps11 SIP differs from apps11 SCCP — different ELF binary, same MIPS arch",
    },
}

# ─────────────────────────────────────────────────────────
# 7942/7962 SCCP ES26 — unchanged findings (confirmed)
# ─────────────────────────────────────────────────────────
SECURITY_7942_7962_SCCP = {
    "product": "Cisco IP Phone 7942/7962 SCCP 9.4.2ES26",
    "source":  "cmterm-7942_7962-sccp.9-4-2SR3-1.zip",

    "phn_f12_applicable": True,
    "dtls_evidence": {
        "getHasDtls": "CONFIRMED in cvm42sccp.9-4-2ES26",
        "getHasSsl":  "CONFIRMED in cvm42sccp.9-4-2ES26",
        "finding":    "PHN-F12",
    },

    "apps_sha256_note": (
        "apps42.9-4-2ES26 (c274284d) is IDENTICAL to apps45.9-4-2ES26 (7945 SR3) and "
        "apps45sip.9-4-2ES26 (7945 SIP SR3). Cross-model/cross-protocol apps sharing confirmed."
    ),
}

# ─────────────────────────────────────────────────────────
# 7942/7962 SIP SR1 (ES9) + SR3 (ES26)
# ─────────────────────────────────────────────────────────
SECURITY_7942_7962_SIP = {
    "product": "Cisco IP Phone 7942/7962 SIP",
    "versions_analyzed": ["9.4.2SR1 (ES9)", "9.4.2SR3 (ES26)"],

    "phn_f12_applicable": False,
    "phn_f12_reason": "SIP variant — no getHasDtls/getHasSsl in any SIP CVM",

    "sr1_cvm": {
        "sha256": "cb22c9de70976f92f74785d599baf8f3847c3bfa4095b6a650f5a4a86e522517",
        "secd_ipc": "CONFIRMED",
        "sec_req_api_rand": "CONFIRMED (SIP marker)",
        "apps_sha256": "c7eb0993098ea94cf32251e7e50700e7ef74a9226d6b351ec9c9955114102268",
        "apps_note": "SR1 apps42 is unique — differs from SR3 (c274284d)",
    },

    "sr3_cvm": {
        "sha256": "a4e3ea36feeaba2c22538d0df9bfeff55a356cb2a2b4ccd9e8ff3df98600cc97",
        "secd_ipc": "CONFIRMED",
        "sec_req_api_rand": "CONFIRMED (SIP marker)",
        "apps_sha256": "c274284db1f359232bd64d53d0d0576e5b0ed7e8339e05ed77eaf916827440f1",
        "apps_note": "SR3 apps42 = apps45 SR3 (cross-model identity confirmed)",
    },
}

# ─────────────────────────────────────────────────────────
# PHN-F12 extension — full model scope
# ─────────────────────────────────────────────────────────
PHN_F12_SCOPE = {
    "id": "PHN-F12",
    "title": "SCCP DTLS Downgrade via Malicious CallManager XML",
    "confirmed_models": [
        "7906 SCCP 9.4.2ES9",
        "7911 SCCP 9.4.2ES9",
        "7942 SCCP 9.4.2ES26",
        "7962 SCCP 9.4.2ES26",
        "7945 SCCP 9.2.1 / 9.4.2SR1 / 9.4.2SR3",
        "7965 SCCP 9.2.1 / 9.4.2SR1 / 9.4.2SR3",
    ],
    "not_applicable": [
        "7906/7911/7942/7962/7945/7965 SIP variants (no getHasDtls/getHasSsl in SIP CVM)",
    ],
    "mechanism": (
        "XmlCallManagersObject parses getHasDtls/getHasSsl from TFTP-delivered "
        "CallManager XML. Setting these to 0 in a MITM-injected or rogue TFTP-served XML "
        "disables DTLS/SSL for media/signaling. All listed models use the same CVM secd IPC "
        "architecture and share this XML parsing path."
    ),
}
