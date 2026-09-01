"""
Cisco 7906/7911 SCCP 9.4.2ES9 + 7942/7962 SCCP 9.4.2ES26 — RE summary
Static analysis: SBN header analysis, ELF extraction, gzip decompression,
strings on CVM and apps binaries
"""

# ─────────────────────────────────────────────────────────
# 7906/7911 SCCP 9.4.2ES9 — architecture
# ─────────────────────────────────────────────────────────
FIRMWARE_7906_7911 = {
    "product":  "Cisco IP Phone 7906/7911 SCCP 9.4.2ES9",
    "date":     "2015-04-22",
    "source":   "cmterm-7911_7906-sccp.9-4-2SR1-1.zip",
    "note":     "ES9 = Engineering Special 9; different build label from standard SR releases",

    "sbn_files": {
        "apps11.9-4-2ES9.sbn": {
            "size": 3156351,
            "sha256": "62b2da5b6cca9a686227cf060cbe88c7ca7acb7c4bb1560d2d0d113d5955d387",
            "format":         "Cisco SBN header (magic 01 00 02 01 01 02 00 02), ELF at 0x10a39",
            "extracted_type": "ELF 32-bit MSB executable, MIPS, MIPS-II, statically linked, stripped",
            "note":           "apps MIPS binary — NO handyiron bypass strings; different TLS arch",
        },
        "cvm11sccp.9-4-2ES9.sbn": {
            "size": 2225648,
            "sha256": "62b2da5b6cca9a686227cf060cbe88c7ca7acb7c4bb1560d2d0d113d5955d387",
            "gzip_offset": "0x463",
            "size_decompressed": "5.2M",
        },
        "jar11sccp.9-4-2ES9.sbn": {"size": 1618309},
        "dsp11.9-4-2ES9.sbn":     {"size": 364207},
        "cnu11.9-4-2ES9.sbn":     {"size": 559855},
    },

    "model_codes": {
        "apps11": "7911 hardware variant",
        "term06": "7906 device defaults",
        "term11": "7911 device defaults",
    },
}

SECURITY_ANALYSIS_7906_7911 = {
    "handyiron_bypass_present": False,
    "tvs_ipc_via_secd":         False,
    "getHasDtls_getHasSsl":     False,
    "phn_f12_applicable":       False,
    "ssl_stack": "Generic TLS via 'failed to create TLS ctx, err %d' path — NOT handyiron",

    "tls_strings_found": [
        "failed to create TLS ctx, err %d",
        "using supplied ciphers for TLS <%s>",
        "failed to apply supplied ciphers for TLS <%s>, err %d",
        "TLSv1",
        "too many open SSL/TLS connections, fd %d",
        "SSL/TLS handshake failed, <%s>",
        "802.1x TLS",
        "VPN_UNTRUSTED",
    ],

    "note": (
        "7906/7911 uses a statically linked MIPS apps binary with a custom TLS layer, "
        "NOT the handyiron secSSLCertVerify architecture used in 7945/7965/7970/7971/78xx. "
        "The bypass conditions identified in JAB-F14/PHN-F14 do NOT have confirmed equivalents "
        "in this firmware. Separate TLS implementation requires independent analysis."
    ),

    "architecture_difference": (
        "7906/7911 is a low-end SCCP-only phone. The apps binary handles SIP/SCCP signaling "
        "and TLS in a single statically linked executable. Contrast with 7945/7965/7942/7962 "
        "which use separate apps + CVM + jar components with the Java-based secd IPC architecture."
    ),
}

# ─────────────────────────────────────────────────────────
# 7942/7962 SCCP 9.4.2ES26 — architecture
# ─────────────────────────────────────────────────────────
FIRMWARE_7942_7962 = {
    "product":  "Cisco IP Phone 7942/7962 SCCP 9.4.2ES26",
    "date":     "2017-02-06",
    "source":   "cmterm-7942_7962-sccp.9-4-2SR3-1.zip",

    "sbn_files": {
        "apps42.9-4-2ES26.sbn": {
            "size": 4638412,
            "sha256": "4051f6751265844c2f16332b1d39b9ff4e51bc8feda82410ffd76f37dbee413d",
        },
        "cvm42sccp.9-4-2ES26.sbn": {
            "size": 2218670,
            "size_decompressed": "5.2M",
            "sha256": "4051f6751265844c2f16332b1d39b9ff4e51bc8feda82410ffd76f37dbee413d",
        },
        "jar42sccp.9-4-2ES26.sbn": {"size": 1763397},
        "dsp42.9-4-2ES26.sbn":     {"size": 364895},
        "cnu42.9-4-2ES26.sbn":     {"size": 581755},
    },

    "model_codes": {
        "apps42": "7942 hardware variant",
        "term42": "7942 device defaults",
        "term62": "7962 device defaults",
    },
}

SECURITY_ANALYSIS_7942_7962 = {
    "architecture": "Java CVM + secd IPC — same as 7945/7965 SCCP",

    "phn_f12_applicable": True,
    "dtls_downgrade_evidence": {
        "getHasDtls": "present in cvm42sccp.9-4-2ES26.sbn",
        "getHasSsl":  "present in cvm42sccp.9-4-2ES26.sbn",
        "class":      "XmlCallManagersObject (inferred — same CVM architecture as 7945/7965)",
        "note":       "PHN-F12 XML DTLS downgrade via malicious TFTP-delivered CallManager XML extends to 7942/7962",
    },

    "tvs_ipc": {
        "secReq_setTvsServer": "present",
        "XmlCallManagerGroupObject": "present",
        "XmlCallManagersObject": "present",
        "note": "Same secd TVS IPC pattern as 7945/7965 SCCP",
    },

    "handyiron_bypass": {
        "confirmed_in_apps42": "NOT confirmed — strings search inconclusive",
        "expected":           "LIKELY — same CVM architecture as 7945/7965 which carries handyiron bypass",
        "note": "Full handyiron bypass analysis requires deeper extraction (jefferson on apps42 JFFS2)",
    },

    "vs_7945_7965_sccp": (
        "7942/7962 SCCP CVM is the same architecture as 7945/7965 SCCP. "
        "Both use 'apps42'/'apps45' + 'cvm42sccp'/'cvm45sccp' + 'jar42sccp'/'jar45sccp'. "
        "PHN-F12 getHasDtls/getHasSsl confirmed in 7942/7962 CVM — extends the finding."
    ),
}

# ─────────────────────────────────────────────────────────
# New firmware versions acquired — cross-model summary
# ─────────────────────────────────────────────────────────
NEW_FIRMWARE_INVENTORY = {
    "78xx.tar (7861 12.5.1SR1-4)": {
        "new_model": True,
        "key_findings": ["PHN-F14 ANY-role bypass confirmed", "PHN-F15 debug MD5 hash", "UBI/UBIFS new format"],
    },
    "cmterm-7911_7906-sccp.9-4-2SR1-1.zip": {
        "new_model": True,
        "key_findings": ["Different TLS arch from handyiron", "PHN-F12 NOT applicable"],
    },
    "cmterm-7911_7906-sip.9-4-2SR1-1.zip": {
        "new_model": True,
        "key_findings": ["SIP variant — extraction pending"],
    },
    "cmterm-7942_7962-sccp.9-4-2SR3-1.zip": {
        "new_model": True,
        "key_findings": ["PHN-F12 confirmed via getHasDtls/getHasSsl", "Same arch as 7945/7965 SCCP"],
    },
    "cmterm-7942_7962-sip.9-4-2SR1-1.zip": {
        "new_version": True,
        "key_findings": ["SIP variant SR1 — extraction pending"],
    },
    "cmterm-7942_7962-sip.9-4-2SR3-1.zip": {
        "new_version": True,
        "key_findings": ["SIP variant SR3 — extraction pending"],
    },
    "cmterm-7945_7965-sccp.9-2-1.tar": {
        "new_version": True,
        "key_findings": ["Earlier 9.2.1 — compare libsecurity.so to 9.4.2SR1"],
    },
    "cmterm-7945_7965-sccp.9-4-2-1SR3-1.tar": {
        "new_version": True,
        "key_findings": ["Later SR3 version — post-SR1 patch delta analysis"],
    },
    "cmterm-7945_7965-sip.9-2-1.tar": {
        "new_version": True,
        "key_findings": ["Earlier 9.2.1 SIP variant"],
    },
    "cmterm-7945_7965-sip.9-4-2-1SR3-1.tar": {
        "new_version": True,
        "key_findings": ["Later SR3 SIP variant"],
    },
    "cmterm-7945_7965-sip.9-4-2-1SR3-1.zip": {
        "new_version": True,
        "key_findings": ["SR3 SIP zip variant"],
    },
}

PENDING_ANALYSIS = [
    "7906/7911 SIP 9.4.2SR1 — extract and compare TLS arch to SCCP variant",
    "7942/7962 SIP SR1/SR3 — confirm handyiron bypass in SIP CVM",
    "7945/7965 SCCP 9.2.1 — compare libsecurity.so SHA256 to SR1/SR3 (version delta)",
    "7945/7965 SCCP SR3 — check if any bypass strings removed vs SR1",
    "7945/7965 SIP 9.2.1 — compare to SR1 baseline",
    "78xx debug hash crack — $1$aoJQnypw$vHpN9WTJEQn1UnHzJdoz71 (hashcat rockyou in progress)",
    "78xx rootfs2 PLATFORM_2 variant — extract and diff vs PLATFORM_1",
]
