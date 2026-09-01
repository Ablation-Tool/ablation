"""
Cisco 7945/7965 (and 7942/7962) — version delta analysis
9.2.1 vs 9.4.2SR1 vs 9.4.2SR3, SCCP vs SIP
Static analysis: SHA256 identity, CVM secd IPC, DTLS markers, OpenSSL versioning
"""

# ─────────────────────────────────────────────────────────
# Firmware versions analyzed
# ─────────────────────────────────────────────────────────
VERSIONS = {
    "9.2.1":      "cmterm-7945_7965-sccp/sip.9-2-1.tar (TH1-13 engineering label)",
    "9.4.2SR1":   "Prior-session baseline (cmterm-7945_7965-sccp/sip.9-4-2SR1-1.tar)",
    "9.4.2SR3":   "cmterm-7945_7965-sccp/sip.9-4-2-1SR3-1.tar (ES26 label)",
}

# ─────────────────────────────────────────────────────────
# SHA256 — all CVM binaries are unique across versions
# ─────────────────────────────────────────────────────────
CVM_SHA256 = {
    "cvm45sccp.9-2-1 (7945 SCCP 9.2.1)":   "7a28e5847fedbb520aa3fcdee8758eae7dbf8a04d1f786ece48277a8c4d867fd",
    "cvm45sccp.9-4-2SR1 (baseline)":        "(prior session)",
    "cvm45sccp.9-4-2ES26 (SR3)":            "6c35d014a49590099c23e77e9c3257ee1910f4a0d635b09a228711b59da8fbb6",

    "cvm45sip.9-2-1 (7945 SIP 9.2.1)":     "1a71215757babd611a4bac9af68687b8d9808d23ea144082d4d6081e76f8e601",
    "cvm45sip.9-4-2SR1 (baseline)":         "(prior session)",
    "cvm45sip.9-4-2ES26 (SR3)":             "cf61a7a53d8db12c7b4dfe537c67d0b8afdf8d1ff9811549e13c62957891c288",

    "cvm42sip.9-4-2ES9 (7942 SIP SR1)":    "cb22c9de70976f92f74785d599baf8f3847c3bfa4095b6a650f5a4a86e522517",
    "cvm42sip.9-4-2ES26 (7942 SIP SR3)":   "a4e3ea36feeaba2c22538d0df9bfeff55a356cb2a2b4ccd9e8ff3df98600cc97",
}

# ─────────────────────────────────────────────────────────
# SHA256 — apps binaries show cross-version IDENTITY
# ─────────────────────────────────────────────────────────
APPS_SHA256_IDENTITY = {
    "9.2.1_universal": {
        "sha256": "fe5cf7f282148b2476ddb3dc8bb05841f4ef7998081ad58174485f312381452d",
        "identical_across": [
            "apps45.9-2-1TH1-13.sbn (7945 SCCP 9.2.1)",
            "apps45.9-2-1TH1-13.sbn (7945 SIP 9.2.1)",
        ],
        "note": "apps45 9.2.1 SCCP = SIP — same binary, protocol irrelevant for apps",
    },

    "SR3_ES26_universal": {
        "sha256": "c274284db1f359232bd64d53d0d0576e5b0ed7e8339e05ed77eaf916827440f1",
        "identical_across": [
            "apps45.9-4-2ES26 (7945 SCCP SR3)",
            "apps45.9-4-2ES26 (7945 SIP SR3)",
            "apps42.9-4-2ES26 (7942 SCCP SR3)",
            "apps42.9-4-2ES26 (7942 SIP SR3)",
        ],
        "note": (
            "SR3/ES26 apps binary is UNIVERSAL across 7945 and 7942, both SCCP and SIP. "
            "Four distinct firmware packages ship identical apps. Only TLV wrapper differs."
        ),
    },

    "9.2.1_openssl_version": "OpenSSL 0.9.8g 19 Oct 2007",
    "SR1_openssl_version":   "OpenSSL 0.9.8g 19 Oct 2007",
    "SR3_openssl_version":   "OpenSSL 0.9.8g 19 Oct 2007",

    "openssl_version_stability_note": (
        "OpenSSL 0.9.8g unchanged from 9.2.1 through SR3 (at least). "
        "The apps binary's SSL stack was never updated in the 9.x train."
    ),
}

# ─────────────────────────────────────────────────────────
# CVM security markers — all versions confirm same patterns
# ─────────────────────────────────────────────────────────
CVM_SECURITY_MARKERS = {
    "SCCP_CVMs": {
        "getHasDtls": {
            "9.2.1": "CONFIRMED (cvm45sccp 7a28e584)",
            "SR3":   "CONFIRMED (cvm45sccp 6c35d014)",
        },
        "getHasSsl": {
            "9.2.1": "CONFIRMED (cvm45sccp 7a28e584)",
            "SR3":   "CONFIRMED (cvm45sccp 6c35d014)",
        },
        "secd_ipc": {
            "9.2.1": "CONFIRMED",
            "SR3":   "CONFIRMED",
        },
        "sec_req_api_rand": "ABSENT in all SCCP CVMs (SCCP architectural marker)",
        "phn_f12_finding": "PHN-F12 applies to all 7945/7965/7942/7962 SCCP versions in scope",
    },

    "SIP_CVMs": {
        "getHasDtls": "ABSENT in all SIP CVMs across all versions",
        "getHasSsl":  "ABSENT in all SIP CVMs across all versions",
        "sec_req_api_rand": {
            "7945 SIP 9.2.1":  "CONFIRMED (cvm45sip 1a712157)",
            "7945 SIP SR3":    "CONFIRMED (cvm45sip cf61a7a5)",
            "7942 SIP SR1":    "CONFIRMED (cvm42sip cb22c9de)",
            "7942 SIP SR3":    "CONFIRMED (cvm42sip a4e3ea36)",
        },
        "secd_ipc": "CONFIRMED in all SIP CVMs",
        "phn_f12_finding": "PHN-F12 does NOT apply to any SIP CVM — DTLS flags SCCP-only",
    },
}

# ─────────────────────────────────────────────────────────
# Version delta — no security regression/fix found
# ─────────────────────────────────────────────────────────
VERSION_DELTA = {
    "9.2.1_to_9.4.2SR1_to_SR3": {
        "handyiron_bypass": "PRESENT all versions — never patched in 9.x train",
        "dtls_downgrade":   "PRESENT all versions (SCCP) — never patched in 9.x train",
        "secd_ipc_arch":    "UNCHANGED across all versions analyzed",
        "openssl_version":  "OpenSSL 0.9.8g FROZEN — never updated in apps binary",
        "cvms_unique":      "All CVM SHA256 unique (updated per release)",
        "apps_stable":      "apps binary UNCHANGED within SIP=SCCP pairing; same hash",

        "security_patch_evidence": "NONE — no version in this range removed or mitigated any finding",

        "note": (
            "From 9.2.1 (c.2009) through 9.4.2SR3 (c.2017), the 7945/7965/7942/7962 9.x firmware "
            "train never patched the handyiron ANY-role bypass or the SCCP DTLS downgrade finding. "
            "CVM updates changed functionality but not the security architecture. "
            "OpenSSL 0.9.8g (2007) shipped unchanged for the entire 8+ year span."
        ),
    },
}

# ─────────────────────────────────────────────────────────
# Cross-reference to existing ablation findings
# ─────────────────────────────────────────────────────────
CROSS_REFERENCES = {
    "PHN-F12": {
        "title": "SCCP DTLS Downgrade via CallManager XML",
        "this_module_confirms": (
            "PHN-F12 present in 9.2.1 (earliest available) and SR3 (latest available 9.x). "
            "Unpatched for entire 9.x firmware lifecycle."
        ),
    },
    "handyiron_bypass": {
        "in_secd": "Bypass lives in secd daemon via libsecurity.so — confirmed path from CVM analysis",
        "not_in_apps": "apps MIPS binary contains OpenSSL 0.9.8g, no handyiron",
        "not_in_cvm": "CVM contains secd IPC calls, delegates TLS to secd",
    },
}
