"""
Cisco IP Phone 7970/7971 SIP — RE summary
Firmware: 9.2.1TH1-13 and 9.4.2TH1-1
Static analysis: SBN extraction, CVM gzip decompression, strings on apps + CVM
"""

FIRMWARE = {
    "model":   "Cisco IP Phone 7970/7971 SIP",
    "versions": {
        "9.2.1": {
            "source":  "cmterm-7970_7971-sip.9-2-1.tar",
            "date":    "2011-05-16",
            "label":   "TH1-13",
        },
        "9.4.2-1": {
            "source":  "cmterm-7970_7971-sip.9-4-2-1.zip",
            "date":    "(not extracted)",
            "label":   "TH1-1",
        },
    },
    "arch":    "MIPS big-endian (same hardware platform as 7970/7971 SCCP)",
    "platform": "Beamish CVM (J2ME CDC VM), deadbeef format, secd IPC",
}

# ─────────────────────────────────────────────────────────
# SHA256 inventory
# ─────────────────────────────────────────────────────────
SHA256 = {
    # apps — SBN file SHA
    "apps70.9-2-1TH1-13.sbn (SIP)":   "85632f43f9367c7b567ec66692029207f6d0078fd18ed5c330cf0b7eb0e23cca",
    "apps70.9-4-2TH1-1.sbn (SIP)":    "6a3365b1e46a8e73e0c3b5626163f8aed853e2e509929cdcf7b6401ce1d7912b",

    # CVMs (compressed SBN)
    "cvm70sip.9-2-1TH1-13.sbn":       "5ee2ef845266a8225fe220b7f4eaeb1d49ab920e463af09298b8b05b33f6a117",
    "cvm70sip.9-4-2TH1-1.sbn":        "701a343bf6aef112a9b1f461ca99c5bd5b917053eecb01e4f92e8af2c5dd53c1",

    # CVMs (decompressed)
    "cvm70sip.9-2-1 (decompressed)":  "849a560353ef333d6b88ca7d606925012eb3e2ce3c49485c35f569dd4c6bcbc3",
    "cvm70sip.9-4-2-1 (decompressed)": "107ad1334052432f9de159980fcd2100d089bdac939b40e5c837f5b76e6e77bb",
}

# ─────────────────────────────────────────────────────────
# apps binary — payload identity with SCCP, SSL-C
# ─────────────────────────────────────────────────────────
APPS_BINARY = {
    "9.2.1": {
        "sbn_size": 3150893,
        "elf_offset": "0x10a7b",
        "elf_sha256_prefix": "0ae925b476b23ba6afc5437bccd364db",
        "identity_vs_sccp": {
            "status": "IDENTICAL ELF payload",
            "sccp_sbn_sha256": "64d364bb3e8e766a1bfdf243aea64f383fedc87b32e32fcf77890d7ebe2e6c07",
            "difference": "TLV signature region only (0x7d–0x17c, 255 bytes)",
        },
        "ssl_stack": "SSL-C 2.3.1 03-Mar-2003 (RSA Security commercial library)",
        "note": (
            "7970/7971 apps uses RSA SSL-C 2.3.1 (2003), NOT OpenSSL or CiscoSSL. "
            "This differs from ALL other Cisco IP phone models analyzed, which use "
            "OpenSSL 0.9.8g (7945/7942/7906) or CiscoSSL (78xx/89xx/Jabber). "
            "SSL-C 2.3.1 is a commercial SSL library from RSA Security predating the "
            "handyiron architecture."
        ),
    },
    "9.4.2-1": {
        "sbn_size": 3153295,
        "elf_offset": "0x10a3d",
        "ssl_stack": "SSL-C 2.3.1 03-Mar-2003 (IDENTICAL — same library, never updated)",
        "identity_vs_9.2.1": "Different SBN size and SHA — different ELF payload",
        "note": "SSL-C version frozen at 2.3.1 from 9.2.1 (2011) through 9.4.2-1",
    },
}

# ─────────────────────────────────────────────────────────
# CVM security markers — SIP architecture
# ─────────────────────────────────────────────────────────
CVM_SECURITY = {
    "9.2.1": {
        "sha256": "849a560353ef333d6b88ca7d606925012eb3e2ce3c49485c35f569dd4c6bcbc3",
        "gzip_offset": "0x47b",
        "size_decompressed": 6714724,
        "secd_ipc": "CONFIRMED",
        "sec_req_api_tvs":  "CONFIRMED (.secd_reqApisec_req_api_tvs.c)",
        "sec_req_api_rand": "CONFIRMED (SIP marker)",
        "getHasDtls": "ABSENT",
        "getHasSsl":  "ABSENT",
        "phn_f12": "NOT APPLICABLE — SIP CVM, no DTLS XML flags",
    },
    "9.4.2-1": {
        "sha256": "107ad1334052432f9de159980fcd2100d089bdac939b40e5c837f5b76e6e77bb",
        "gzip_offset": "0x477",
        "size_decompressed": 6805372,
        "secd_ipc": "CONFIRMED",
        "sec_req_api_tvs":  "CONFIRMED",
        "sec_req_api_rand": "CONFIRMED (SIP marker)",
        "getHasDtls": "ABSENT",
        "getHasSsl":  "ABSENT",
        "phn_f12": "NOT APPLICABLE — SIP CVM, no DTLS XML flags",
    },
}

# ─────────────────────────────────────────────────────────
# SSL-C vs OpenSSL — architectural significance
# ─────────────────────────────────────────────────────────
SSL_C_ANALYSIS = {
    "library": "SSL-C 2.3.1 by RSA Security",
    "version_date": "2003-03-03",
    "present_in": ["apps70.9-2-1", "apps70.9-4-2-1"],
    "note_sccp": "SSL-C 2.3.1 also present in apps70 SCCP 9.2.1 (identical ELF payload)",

    "handyiron_bypass_status": (
        "handyiron bypass (ANY-role) NOT CONFIRMED in apps70. The handyiron library is not "
        "present in the apps binary — the apps binary uses SSL-C, not CiscoSSL/handyiron. "
        "Whether the secd daemon on 7970/7971 uses handyiron requires independent analysis "
        "of the secd binary (not present in SBN — deployed separately or in another partition)."
    ),

    "cvss_note": (
        "SSL-C 2.3.1 from 2003 predates documented TLS protocol attacks (BEAST, POODLE, CRIME, etc.) "
        "and is EOL. The apps binary carrying this library represents significant TLS exposure "
        "independent of the handyiron bypass question."
    ),

    "comparison_to_other_models": {
        "7906/7911/7942/7962/7945/7965": "OpenSSL 0.9.8g (2007) in apps",
        "78xx":                          "CiscoSSL 1.0.2o-fips / 6.0-fips-dev in libseccommon.so",
        "89xx":                          "CiscoSSL 0.9.8g–1.1.0-fips-dev in libseccommon.so",
        "Jabber Windows":                "CiscoSSL 1.0.2k-fips in ssleay32.dll",
        "7970/7971":                     "SSL-C 2.3.1 (2003) in apps70 — OUTLIER",
    },
}

# ─────────────────────────────────────────────────────────
# Version delta — no security regression/fix
# ─────────────────────────────────────────────────────────
VERSION_DELTA = {
    "9.2.1_to_9.4.2-1": {
        "ssl_library": "SSL-C 2.3.1 UNCHANGED",
        "secd_ipc_arch": "UNCHANGED",
        "sip_dtls_absent": "UNCHANGED (SIP variant, DTLS flags always absent)",
        "cvm_updated": "CVM SHA differs — functionality updated between versions",
        "apps_updated": "apps70 SHA differs — some change between 9.2.1 and 9.4.2-1",
        "security_patch_evidence": "NONE found — SSL-C version frozen, secd architecture unchanged",
    },
}

# ─────────────────────────────────────────────────────────
# Cross-reference to SCCP module
# ─────────────────────────────────────────────────────────
CROSS_REFERENCES = {
    "cisco_7970_7971_sccp_re.py": {
        "gap_in_sccp_module": (
            "SCCP module does not document SSL-C 2.3.1 in apps70 SCCP. "
            "apps70 SCCP 9.2.1 (64d364bb) = apps70 SIP 9.2.1 ELF payload (0ae925b4). "
            "SSL-C finding applies to SCCP apps as well."
        ),
        "phn_f12_sccp": "PHN-F12 CANDIDATE confirmed in SCCP CVM (getHasDtls/getHasSsl present)",
    },
}
