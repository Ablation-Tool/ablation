"""
Cisco IP Phone 8941/8945 SCCP firmware reverse engineering module.
Firmware: SCCP 9.3.4-17 (cmterm-8941_8945-sccp.9-3-4-17.zip — 9-file SBN set)
Platform: ARM926EJ-S (ARMv5TEJ), Linux, glibc, OpenSSL 0.9.8k
JFFS2 offset: 0x1e2720 (same as SIP 9.3.4-17)
Key finding: libsecurity.so binary-identical to SIP — PHN-F02/F03/F04/F05 all present.
"""

FIRMWARE = {
    "model":       "Cisco IP Phone 8941/8945 SCCP",
    "version":     "9.3.4-17",
    "arch":        "ARM926EJ-S (ARMv5TEJ, 32-bit LE)",
    "build_env":   "Wind River Linux Sourcery G++ 4.3-85",
    "openssl":     "0.9.8k 25 Mar 2009 (CVE-2009-3555 VULNERABLE)",
    "container":   "Cisco SBN format (Cisco TLV signature, 512-byte strip)",
    "jffs2_offset_in_concatenated": 0x1e2720,
    "file_count":  9,
    "sig_strip_per_file": 512,
    "gumbo_size":  7090528,
    "gumbo_sha256": "a15ce331ed5dd89524882e8c1fcba97f9b32442316d40b6249145b2a3055f24f",
    "protocol":    "SCCP (Skinny Client Control Protocol) — NOT SIP",
}

LIBRARY_COMPARISON_SCCP_vs_SIP = {
    "libsecurity_so": {
        "sccp_sha256": "61315c885151a3c6c797e986a1284b345d8087be3e727ee5feb17a8a89760e54",
        "sip_sha256":  "61315c885151a3c6c797e986a1284b345d8087be3e727ee5feb17a8a89760e54",
        "result": "IDENTICAL",
        "implication": "PHN-F02/F03/F04 present in SCCP by binary identity",
    },
    "libseccommon_so": {"result": "IDENTICAL", "implication": "OpenSSL 0.9.8k PHN-F05 present in SCCP"},
    "libfips_so":     {"result": "IDENTICAL"},
    "libfipstest_so": {"result": "IDENTICAL"},
    "libsrtp_so":     {"result": "IDENTICAL"},
    "libtvs_so":      {"result": "IDENTICAL"},
    "libplatform_so": {
        "sccp_size": 105237,
        "sip_size":  72751,
        "result": "DIFFERS — SCCP +32KB",
        "sccp_additions": [
            "CPR socket API: cprAccept, cprBind, cprConnect, cprListen, cprGetSockOpt",
            "Security command dispatch: trust_itl_cmd_proc, trust_ctl_cmd_proc, capftask_cmd_proc, sslconnect_cmd_proc",
            "Secure data store: cprReadRawSecureData, cprWriteRawSecureData, cprGetRawSecureDataLen",
            "nvdata path: /nvdata/SecureData (CRC-protected; CRC failure triggers deletion)",
            "authVerifyPlatformImageBuffer: in-RAM image verification (SCCP-only)",
        ],
    },
    "libcapf_so":    {"sccp_size": 796384, "sip_size": 796384, "result": "DIFFERS — same size, different binary"},
    "libfileauth_so":{"sccp_size": 391636, "sip_size": 391636, "result": "DIFFERS — same size, different binary"},
    "gumbo": {
        "sccp_size": 7090528,
        "sip_size":  6740836,
        "result": "DIFFERS — SCCP +350KB (SCCP stack vs libsipcc.so SIP stack)",
    },
}

PHN_F02_STATUS_8941_SCCP = {
    "finding_id": "PHN-F02",
    "status_8941_sccp": "CONFIRMED PRESENT — libsecurity.so binary-identical to SIP (SHA256 61315c88...)",
    "confirmed_string": " Using leap of faith to accept TL file ",
}

PHN_F03_STATUS_8941_SCCP = {
    "finding_id": "PHN-F03",
    "status_8941_sccp": "CONFIRMED PRESENT — binary-identical libsecurity.so",
    "confirmed_string": "not using TVS for cert validation - role is TVS or SRST",
}

PHN_F04_STATUS_8941_SCCP = {
    "finding_id": "PHN-F04",
    "status_8941_sccp": "CONFIRMED PRESENT — binary-identical libsecurity.so",
    "confirmed_strings": ["Not using TVS - TVS not in Trust list", "VALIDATE CERT - TVS not enabled"],
}

PHN_F05_STATUS_8941_SCCP = {
    "finding_id": "PHN-F05",
    "status_8941_sccp": "CONFIRMED PRESENT — libseccommon.so binary-identical to SIP",
    "openssl_version": "0.9.8k 25 Mar 2009",
}

PHN_F10_NVDATA_CRC_WIPE = {
    "id":     "PHN-F10",
    "title":  "SCCP libplatform.so: /nvdata/SecureData CRC corruption triggers store wipe",
    "binary": "cisco_seclib/libplatform.so (SCCP-specific, 105,237 bytes)",
    "log_string": "CRC Error! remove /nvdata/SecureData",
    "mechanism": (
        "SCCP phones store secure data at /nvdata/SecureData protected by CRC. "
        "cprReadRawSecureData CRC failure triggers automatic store deletion. "
        "Flash write access → corrupt CRC → reboot → store wiped → PHN-F02 TOFU re-trigger."
    ),
    "chain": "Flash write → CRC corrupt → wipe → PHN-F02 TOFU → serve malicious ITLFile.tlv → MITM",
    "protocols": "SCCP only — CPR CRC-wipe logic absent in SIP 8941 libplatform.so",
    "severity": "MEDIUM — requires pre-existing flash write or OS exec primitive",
}

SCCP_CVM_DELTA = {
    "binary": "beamishcvmsccp.cnu (5.4MB decompressed vs SIP CVM 6.8MB)",
    "secd_proxy_confirmed": True,
    "new_vs_sip_cvm": {
        "secReq_srtpFipsTest": (
            "New IPC call in SCCP CVM — absent in SIP CVM. "
            "FIPS SRTP self-test via secd IPC. If test can be forced to fail, "
            "FIPS SRTP falls back to non-FIPS path."
        ),
    },
    "ssltreamconnection_sha256": "291db3749603a3f04f781d7293e23b1deeb1fc6376ea10eec3f3f7a3d1fb3cfe",
    "ssltreamconnection_identical_to_sip": True,
    "phn_f06_f07_apply": "Confirmed — PHN-F06/F07 apply to SCCP CVM by byte-for-byte identity",
}

DSP_BINARY_SCCP = {
    "file":    "dsp45.9-4-2ES9.sbn (364,207 bytes)",
    "magic":   "DEADBEEF at 0x428",
    "version": "8.3(14.15)PSYL",
    "platform": "PSYL (Cisco DSP for 7945/7965)",
    "srtp_mode": "SDES-SRTP — no DTLS strings confirmed",
    "phn_f08_candidate": {
        "string": "DSP INIT-*** DSP_STATE_READY***  BYPASSED **********************",
        "note": "DSP init BYPASSED state — triggers skip of DSP security checks; trigger condition unknown",
    },
    "phn_f09_candidate": {
        "strings": ["RTP TX: sRTP memcmp bypass test failed!", "FIPS SRTP bypass test passed"],
        "note": "FIPS SRTP self-test; forced failure may disable FIPS SRTP path — candidate, not confirmed",
    },
}

SCCP_vs_SIP_ATTACK_DELTA = {
    "identical": [
        "PHN-F02 TOFU (libsecurity.so byte-for-byte same)",
        "PHN-F03 SRST TVS bypass (same)",
        "PHN-F04 TVS-absent bypass (same)",
        "PHN-F05 OpenSSL 0.9.8k CVE-2009-3555 (libseccommon.so byte-for-byte same)",
        "PHN-F06/F07 Java CertStore (SSLStreamConnection.class byte-for-byte same)",
        "SDES-SRTP (libsrtp.so identical)",
        "DHCP option 150 / TFTP provisioning path",
    ],
    "sccp_specific": [
        "TCP 2000/2443 (SCCP/SCCP-S) vs UDP 5060 (SIP)",
        "PHN-F10: /nvdata/SecureData CRC-wipe (SCCP libplatform.so only)",
        "libcapf.so SCCP variant (same size, different binary)",
        "libfileauth.so SCCP variant (same size, different binary)",
        "secReq_srtpFipsTest IPC in SCCP CVM",
    ],
    "assessment": (
        "8941 SCCP 9.3.4-17 shares ALL trust bypass primitives with SIP at the binary level. "
        "The CTL/ITL trust architecture is protocol-agnostic in Cisco's implementation. "
        "PHN-F02 through F05 apply equally to SCCP deployments."
    ),
}

# ---- 8941 SCCP 9.3.1-19: earlier variant (ARM11 arch, static OpenSSL) ----

FIRMWARE_9_3_1_19 = {
    "model":   "Cisco IP Phone 8941/8945 SCCP",
    "version": "9.3.1-19",
    "arch":    "ARM11 (armv6jel, arm1136j-s) — DIFFERENT from 9.3.4-17 (ARM926EJ-S ARMv5TEJ)",
    "toolchain": "arm-wrs-linux-gnueabi-armv6jel-glibc_small-gcc",
    "openssl": "0.9.8g 19 Oct 2007 (older than 9.3.4-17's 0.9.8k)",
    "jffs2_offset": 0x1fd208,
    "concat_size": 0x193f668,
    "files": 10,
    "boot_file": "BOOT8941_8945.0-0-1-0.bin.sgn (110,004 bytes, earlier version than 9.3.4-17)",
}

LIBRARY_ARCHITECTURE_9_3_1_19 = {
    "architecture": "OpenSSL statically linked into libsecurity.so (pre-libseccommon.so split)",
    "libsecurity_so": {
        "size": 1067824,
        "sha256": "498f01e4b094c69ea5f357d3b0ac278ca8c6f386a92302a086b17afe95491dab",
        "note": "1MB monolith — contains OpenSSL 0.9.8g statically linked",
    },
    "absent_libs": ["libseccommon.so", "libfips.so", "libfipstest.so"],
    "openssl_in_lib": "lib/libcrypto.so.0.9.8g (shared, dynamically loaded separately)",
    "openssl_version_string": "OpenSSL 0.9.8g 19 Oct 2007",
}

PHN_F02_STATUS_9_3_1_19 = {
    "finding_id": "PHN-F02",
    "status": "CONFIRMED PRESENT — strings match verbatim",
    "confirmed_string": " Using leap of faith to accept TL file ",
}

PHN_F03_STATUS_9_3_1_19 = {
    "finding_id": "PHN-F03",
    "status": "CONFIRMED PRESENT",
    "confirmed_string": "not using TVS for cert validation - role is TVS or SRST",
}

PHN_F04_STATUS_9_3_1_19 = {
    "finding_id": "PHN-F04",
    "status": "CONFIRMED PRESENT",
    "confirmed_string": "Not using TVS - TVS not in Trust list",
}

PHN_F05_STATUS_9_3_1_19 = {
    "finding_id": "PHN-F05",
    "status": "CONFIRMED PRESENT AND WORSE — OpenSSL 0.9.8g (older than 9.3.4-17's 0.9.8k)",
    "openssl_version": "0.9.8g 19 Oct 2007",
    "additional_cves_vs_0_9_8k": [
        "CVE-2008-5077 — DSA/ECDSA signature check bypass (0.9.8g→0.9.8j window)",
        "CVE-2009-0590 — ASN1_STRING_print_ex buffer overflow",
        "CVE-2009-0789 — DTLS invalid fragment crash",
        "CVE-2008-1672 — ClientHello NULL crash (Server Name extension)",
    ],
}

DROPBEAR_9_3_1_19 = {
    "version": "SSH-2.0-dropbear_0.51",
    "sha256": "880709b43e0ff7342c594505884bce108997665cad6dd9265435635f587801c7",
    "size": 546542,
    "note": "Same 0.51 version, slightly smaller binary than 9.3.4-17 variant (546,542 vs 549,863 bytes)",
}

SCCP_VERSION_COMPARISON = {
    "9.3.1-19": {
        "arch": "armv6jel (ARM11, arm1136j-s)",
        "openssl": "0.9.8g — static in libsecurity.so",
        "libseccommon": "absent — monolith architecture",
        "libsecurity_size": 1067824,
        "phn_f02_f03_f04": "PRESENT",
    },
    "9.3.4-17": {
        "arch": "ARMv5TEJ (ARM926EJ-S)",
        "openssl": "0.9.8k — in libseccommon.so",
        "libseccommon": "913,896 bytes — split architecture",
        "libsecurity_size": 194732,
        "phn_f02_f03_f04": "PRESENT (binary identical to SIP 9.3.4-17)",
    },
    "assessment": (
        "9.3.1-19 is an earlier SoC generation (ARM11 vs ARM926EJ-S) with a monolithic "
        "libsecurity.so and older OpenSSL 0.9.8g. "
        "The bypass logic (PHN-F02/F03/F04) is present in both. "
        "9.3.1-19 has MORE OpenSSL CVE exposure than 9.3.4-17."
    ),
}
