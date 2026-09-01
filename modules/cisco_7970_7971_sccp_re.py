"""
Cisco IP Phone 7970/7971 SCCP firmware reverse engineering module.
Firmware: 7970/7971 SCCP 9.2.1 (cmterm-7970_7971-sccp.9-2-1.tar)
Platform: MIPS big-endian, Beamish CVM (J2ME CDC VM), Linux
Container: CNU_File_Archive (Cisco proprietary, .sbn format)
Date: 2011-05-13
Coverage: secReq IPC set, XML config DTLS flags, SSH surface, DSP identity
"""

FIRMWARE = {
    "model":   "Cisco IP Phone 7970/7971 SCCP",
    "version": "9.2.1TH1-13",
    "arch":    "MIPS big-endian (same platform as 7945/7965)",
    "platform": "Beamish CVM (J2ME CDC VM)",
    "date":    "2011-05-13",
    "container": "CNU_File_Archive (.sbn extension, Cisco TLV sig header)",
}

BINARY_INVENTORY = {
    "apps70.9-2-1TH1-13.sbn": {
        "sha256": "64d364bb3e8e766a1bfdf243aea64f383fedc87b32e32fcf77890d7ebe2e6c07",
        "size":   3150893,
        "identity_vs_sip": "IDENTICAL payload (only TLV sig differs, 255 bytes at 0x7d-0x17c)",
    },
    "cvm70sccp.9-2-1TH1-13.sbn": {
        "sha256": "8f79c275ad6bc088556d80f749454b1e92acf34c450382978af84011c8218e0b",
        "size_compressed": 2213364,
        "size_decompressed": 5405452,
        "magic": "DEADBEEF",
        "gzip_offset": 0x47b,
    },
    "dsp70.9-2-1TH1-13.sbn": {
        "sha256": "e68841d00b5736be6c918e31555dfc1dc812d1fd453d5e4f8bbca35327ec0e22",
        "size":   554113,
    },
    "jar70sccp.9-2-1TH1-13.sbn": {
        "sha256": "b01714da69cfddac0d6726fc12c1f812ac61c6484838c0c45f01bed9a60bf866",
        "size":   1830356,
    },
}

# ---- secReq IPC set ----

SECD_IPC_CALLS = {
    "set": [
        "secReq_AddEntity", "secReq_Auth_N_Decr", "secReq_cancelCapf",
        "secReq_cleanupClient", "secReq_clearCapf", "secReq_CTLdelete",
        "secReq_CTLupdate", "secReq_DelEntity", "secReq_fipsTest",
        "secReq_getCapf", "secReq_getCapfStatus", "secReq_getCertInfo",
        "secReq_getCTLInfo", "secReq_getCTLItem", "secReq_getITLItem",
        "secReq_getProxySock", "secReq_getSrvCertAttr", "secReq_getTvsServer",
        "secReq_initClient", "secReq_initiateCapf", "secReq_Listen",
        "secReq_LookupSrvr", "secReq_secFileOp", "secReq_setCapf",
        "secReq_setEMCCStatus", "secReq_setMode", "secReq_setTvsServer",
        "secReq_setVPNCertificates", "secReq_srtpFipsTest", "secReq_startCapf",
        "secReq_VerifyMIDlet", "secReq_vfyVPNCertificates",
    ],
    "absent_vs_7945_sccp": "secReq_getRand (absent in all 79xx SCCP CVMs — sec_req_api_rand.c excluded)",
    "note": "Identical IPC set to 7945/7965 SCCP 9.4.2SR1-1. secReq_srtpFipsTest present.",
}

# ---- PHN-F12 analogue: XML config DTLS downgrade ----

XML_DTLS_FLAGS = {
    "getHasDtls": "present in CVM — parses hasDtls flag from XmlCallManagersObject",
    "getHasSsl":  "present in CVM — parses hasSsl flag from XmlCallManagersObject",
    "cross_version": "Both flags present in 7970/7971 SCCP 9.2.1 and 7945/7965 SCCP 9.4.2SR1-1",
    "phn_f12_applicable": True,
    "note": (
        "hasDtls/hasSsl are parsed from TFTP-provisioned CallManager XML. "
        "Malicious TFTP server (via DHCP option 150 redirect) can set hasSsl=false "
        "to potentially disable TLS on SCCP signaling. PHN-F12 CANDIDATE on 7970/7971."
    ),
}

# ---- ITL/CTL trust infrastructure ----

CTL_ITL_7970_SCCP = {
    "strings_confirmed": [
        "OK_INITIAL_CTL", "OK_INITIAL_ITL",
        "FAILED_CTL", "FAILED_ITL",
        "CTL_UPDATE",
    ],
    "trust_path": "secd IPC → libsecurity.so (MIPS ELF in apps70.sbn) → CTL/ITL file validation",
    "phn_f02_analogue": "TOFU CTL/ITL acceptance — same as 7945/7965 SCCP",
    "phn_f04_analogue": "TVS-absent bypass — secReq_getTvsServer present, bypass path present",
}

# ---- SSH surface: config-driven, differs from 8941/8945 ----

SSH_SURFACE = {
    "mechanism": "PropertyGetSSHAccess IPC — SSH access is configuration-driven, not unconditionally started",
    "credential_source": "getSshUserid / getSshPassword from config properties (setSshUserInfo)",
    "difference_from_8941": (
        "8941/8945 (PHN-F11/PHN-F13): Dropbear 0.51 unconditionally started, empty-password root/qa in /etc/passwd. "
        "7970/7971: SSH enabled/disabled via config; credentials from provisioned config, not hardcoded empty passwd. "
        "PHN-F13 (hardcoded empty passwd) does NOT apply to 7970/7971."
    ),
    "risk": (
        "If CUCM provisioning enables SSH with default/weak credentials, "
        "and attacker can manipulate the provisioned config (via PHN-F02 TFTP path), "
        "attacker could set chosen SSH credentials. CANDIDATE — needs live device test."
    ),
}

# ---- apps70 SIP/SCCP cross-protocol identity ----

APPS70_IDENTITY = {
    "finding": "apps70 payload IDENTICAL between SIP 9.2.1 and SCCP 9.2.1 (only TLV sig differs)",
    "sig_diff_range": "0x7d-0x17c (255 bytes — same pattern as 7945/7965 apps45)",
    "elf_boundary": 0x10a7b,
    "implication": (
        "All MIPS ELF objects (MIPS CTL/ITL trust logic, secd IPC stubs, libsecurity calls) "
        "are shared verbatim between SIP and SCCP for the same phone model/version. "
        "PHN-F02/F04 analogues (TOFU CTL/ITL) apply equally to SIP and SCCP."
    ),
}

# ---- 7970/7971 SCCP vs 7945/7965 SCCP comparison ----

COMPARISON_7970_vs_7945_SCCP = {
    "7970_sccp_9_2_1": {
        "cvm_decompressed": 5405452,
        "secd_ipc": "identical set to 7945/7965 SCCP",
        "xml_dtls_flags": "getHasDtls + getHasSsl present",
        "ssh": "PropertyGetSSHAccess (config-driven)",
    },
    "7945_sccp_9_4_2SR1_1": {
        "cvm_decompressed": 5426292,
        "secd_ipc": "identical set",
        "xml_dtls_flags": "getHasDtls + getHasSsl present",
        "ssh": "PropertyGetSSHAccess (config-driven)",
    },
    "unchanged": [
        "secReq IPC set (32 calls, no secReq_getRand)",
        "XML config DTLS/SSL flags (getHasDtls, getHasSsl)",
        "CTL/ITL trust framework",
        "secReq_srtpFipsTest FIPS SRTP self-test",
        "secd proxy architecture for TLS",
        "apps MIPS payload identity across SIP/SCCP",
    ],
    "version_gap": "9.2.1 (2011) vs 9.4.2SR1-1 (2015) — 4-year, 2-generation gap — security architecture unchanged",
}

# ─────────────────────────────────────────────────────────
# SSL-C library — corrected from SIP analysis (2026-09-01)
# ─────────────────────────────────────────────────────────
SSL_STACK_APPS = {
    "library": "SSL-C 2.3.1 by RSA Security",
    "version_string": "SSLv3 part of SSL-C 2.3.1 03-Mar-2003",
    "present_in": "apps70 MIPS binary (both SCCP and SIP — identical ELF payload)",

    "note": (
        "apps70 uses RSA SSL-C 2.3.1 (2003), NOT OpenSSL or CiscoSSL. "
        "This is the non-call-control TLS layer in apps (TFTP, provisioning). "
        "Call control TLS routes through secd daemon. "
        "SSL-C 2.3.1 predates all major TLS protocol attacks and is EOL. "
        "All other Cisco IP phone models use OpenSSL 0.9.8g or CiscoSSL — "
        "7970/7971 is the only outlier using SSL-C."
    ),

    "vs_other_models": {
        "7906/7911/7942/7962/7945/7965": "OpenSSL 0.9.8g 19 Oct 2007",
        "78xx (PLATFORM_1)":             "CiscoSSL 1.0.2o.6.2.238-fips",
        "78xx (PLATFORM_2)":             "CiscoSSL 6.0-fips-dev",
        "89xx":                          "OpenSSL 0.9.8g - CiscoSSL 1.1.0-fips-dev",
        "Jabber Windows 11.9.1":         "CiscoSSL 1.0.2k-fips",
        "7970/7971":                     "SSL-C 2.3.1 (2003) — OUTLIER",
    },
}
