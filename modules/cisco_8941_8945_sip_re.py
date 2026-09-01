"""
Cisco IP Phone 8941/8945 SIP firmware reverse engineering module.
Firmware: SIP 9.3.4-17 (sip8941_9-3-4-17.zip — 10-file SBN set)
Platform: ARM926EJ-S (ARMv5TEJ), Linux, glibc 2.4, OpenSSL 0.9.8k
JFFS2 filesystem extracted from concatenated stripped SBN files
"""

FIRMWARE = {
    "model":     "Cisco IP Phone 8941/8945 SIP",
    "version":   "9.3.4-17",
    "arch":      "ARM926EJ-S (ARMv5TEJ)",
    "libc":      "glibc 2.4 (GLIBC_2.4)",
    "openssl":   "0.9.8k 25 Mar 2009",
    "build_env": "Wind River Linux Sourcery G++ 4.3-85",
    "container": "GUMBO (Cisco proprietary) + JFFS2 filesystem",
    "main_binary": "voip/gumbo (ELF ARM32 EABI5, 6.7MB stripped)",
    "jffs2_offset_in_concatenated": 0x1e2720,
    "jffs2_size": 0x17c0000,
}

# Extraction notes
EXTRACTION = {
    "sig_strip_per_file": 512,
    "file_count": 10,
    "file_size_each": 3145120,
    "concatenated_size": 31452080,
    "kernel_gzip_offset": 0x3c34,
    "jffs2_magic_le": b"\x85\x19\x01\xe0",
    "tool": "jefferson (python JFFS2 extractor)",
    "note": (
        "gzip.decompress() fails on multi-member gzip spanning bins. "
        "Use zlib.decompressobj(wbits=47) with streaming decompress + d.eof check."
    ),
}

# ---- PHN-F02: TOFU 'leap of faith' CTL/ITL acceptance ----

PHN_F02_LEAP_OF_FAITH = {
    "id":     "PHN-F02",
    "title":  "libsecurity.so Trust on First Use — leap-of-faith CTL/ITL acceptance",
    "binary": "cisco_seclib/libsecurity.so (ARM926EJ-S, stripped)",

    # Verbatim log strings from libsecurity.so
    "log_leap_of_faith": "Using leap of faith to accept TL file",
    "log_no_ctlitl":     "Could not load CTL File from persistent memory.",
    "log_itl_missing":   "Could not load ITL File from persistent memory.",

    # Trigger condition
    "trigger": (
        "Phone has no CTL/ITL file in persistent storage — "
        "factory reset, first-time provisioning, or deliberate file deletion."
    ),

    # What happens
    "mechanism": (
        "secInitSecurity() calls secGetTrustListFiles() -> secProcessTrustFile(). "
        "When no prior TL exists, the phone accepts any TL file from the provisioning "
        "server without cryptographic validation. The TL file is then committed to "
        "flash via secUpdateConfigList() as authoritative. All subsequent TLS "
        "connections validate against whatever CA certs the attacker inserted."
    ),

    # Files affected
    "tl_files": ["/CTLFile.tlv", "/ITLFile.tlv", "/CTLFile.bak", "/ITLFile.bak"],

    # Attack chain
    "chain": [
        "Factory-reset phone (or manually delete /CTLFile.tlv + /ITLFile.tlv from flash)",
        "DHCP option 150 / TFTP redirect points phone at attacker provisioning server",
        "Attacker serves malicious ITLFile.tlv containing attacker-controlled CA cert",
        "Phone applies leap-of-faith: installs attacker cert as trusted",
        "All subsequent HTTPS/TLS config downloads validate against attacker CA",
        "Attacker can now MITM all provisioning and redirect CUCM registration",
    ],

    "impact": (
        "Full trust anchor compromise. Attacker gains persistent MITM position "
        "over all signed config delivery and TLS-authenticated communication. "
        "Survives firmware upgrades unless ITL is explicitly re-provisioned from CUCM."
    ),

    "cve_analogues": ["CVE-2014-3300 (CUCM ITL file manipulation)"],

    "note": (
        "Cisco documents this as intended bootstrap behavior. "
        "Mitigated in controlled environments by DHCP server access control "
        "and CAPF pre-enrollment before deployment."
    ),
}

# ---- PHN-F03: SRST role skips TVS certificate validation ----

PHN_F03_SRST_TVS_BYPASS = {
    "id":     "PHN-F03",
    "title":  "libsecurity.so TVS validation bypass for SRST role connections",
    "binary": "cisco_seclib/libsecurity.so (ARM926EJ-S, stripped)",

    "log_string": "not using TVS for cert validation - role is TVS or SRST",

    "trigger": (
        "The remote peer presents a certificate where the role field resolves to "
        "TVS (Trust Verification Service) or SRST (Survivable Remote Site Telephony). "
        "secValidateCertificate() checks secIsRoleMatch() for these roles and "
        "short-circuits before calling secGetTVSServiceCtx()."
    ),

    "mechanism": (
        "secValidateCertificate() calls secIsRoleMatch(). "
        "When role == TVS or role == SRST, the function logs "
        "'not using TVS for cert validation' and returns without TVS validation. "
        "Certificate trust falls back to direct trust list lookup via "
        "secValidateCertificateUsingTL() only."
    ),

    "attack": (
        "An attacker whose cert is in the phone's trust list (e.g., via PHN-F02) "
        "can present a cert with SRST role to bypass the stricter TVS-validated path. "
        "This also enables persistent SRST impersonation with no TVS validation overhead."
    ),

    "impact": "TVS-bypassed MITM for any connection where attacker cert is already trusted.",

    "note": (
        "SRST bypass is architecturally intended — SRST gateways authenticate via "
        "a separate chain. The attack vector requires prior trust anchor compromise "
        "to be effective (chains with PHN-F02)."
    ),
}

# ---- PHN-F04: TVS-absent bypass when TVS not in trust list ----

PHN_F04_TVS_ABSENT = {
    "id":     "PHN-F04",
    "title":  "libsecurity.so silently skips TVS validation when TVS absent from ITL",
    "binary": "cisco_seclib/libsecurity.so (ARM926EJ-S, stripped)",

    "log_strings": [
        "Not using TVS - TVS not in Trust list",
        "VALIDATE CERT - TVS not enabled",
        "Failed to validate cert using TVS",
    ],

    "trigger": (
        "secGetTVSServiceCtx() returns NULL — no TVS entry in the loaded ITL/CTL. "
        "This is the default state when phones are deployed without TVS enrollment "
        "or in environments running older CUCM without TVS."
    ),

    "mechanism": (
        "secValidateCertificate() calls secGetTVSServiceCtx(). "
        "If ctx is NULL, logs 'VALIDATE CERT - TVS not enabled' and falls back to "
        "secValidateCertificateUsingTL() — direct trust list match only. "
        "No online revocation check is performed."
    ),

    "impact": (
        "Certificates that have been revoked (CUCM admin action, cert expiry) "
        "remain accepted if they match the static ITL trust list. "
        "No real-time revocation checking. Stolen/leaked phone certificates "
        "continue to authenticate indefinitely until ITL is manually rotated."
    ),
}

# ---- PHN-F05: OpenSSL 0.9.8k TLS renegotiation attack surface ----

PHN_F05_OPENSSL_0_9_8K = {
    "id":     "PHN-F05",
    "title":  "OpenSSL 0.9.8k TLS renegotiation injection (CVE-2009-3555)",
    "binary": "cisco_seclib/libseccommon.so (embedded OpenSSL 0.9.8k)",

    "openssl_version": "0.9.8k 25 Mar 2009",
    "version_string_va": "libseccommon.so rodata: 'ECDH part of OpenSSL 0.9.8k 25 Mar 2009'",

    "cve": "CVE-2009-3555 (CVSS 5.8)",

    "mechanism": (
        "OpenSSL 0.9.8k has no RFC 5746 renegotiation_info extension. "
        "An attacker performing MITM on a TLS session to the phone can "
        "inject arbitrary plaintext at the start of a TLS connection by "
        "initiating a renegotiation. The injected data is processed by the "
        "server (CUCM/Expressway) as if sent by the phone."
    ),

    "additional_issues": [
        "No TLS 1.1 or TLS 1.2 — only SSL3 and TLS 1.0 available",
        "SSLv2 may be compiled in (0.9.8k default config)",
        "ECDSA timing side channels (pre-constant-time era)",
        "No SNI support — single-cert per IP constraint",
        "OpenSSL FIPS module also 0.9.8k vintage",
    ],

    "impact": (
        "MITM attacker with TLS intercept capability can inject SIP REGISTER "
        "or provisioning commands into the phone's CUCM connection. "
        "Combined with NTP-unsync window (see 8845 PHN-F01 analogue), "
        "this is a viable call hijack primitive."
    ),
}

# ---- PHN-SURFACE: Attack surface enumeration for 8941/8945 SIP ----

PHN_SURFACE_8941 = {
    "tls_library":        "cisco_seclib/libsecurity.so (Cisco wrapper over OpenSSL 0.9.8k)",
    "openssl_embedded":   "cisco_seclib/libseccommon.so (OpenSSL 0.9.8k static-linked)",
    "srtp_library":       "cisco_seclib/libsrtp.so (SDES-SRTP, no DTLS-SRTP)",
    "sip_stack":          "lib/libsipcc.so (ARM32 EABI5, not stripped, 1.7MB)",
    "tvs_library":        "cisco_seclib/libtvs.so (Trust Verification Service client, 766KB)",
    "capf_library":       "cisco_seclib/libcapf.so (Certificate Authority Proxy Function)",
    "fips_module":        "cisco_seclib/libfips.so (FIPS 140-2 crypto)",
    "vpn_libraries":      ["lib/libvpnApi.so", "lib/libvpnPlatform.so"],
    "secd_ipc":           "lib/libsecdApi.so (IPC client to secd security daemon, has debug_info)",
    "main_binary":        "voip/gumbo (6.7MB stripped, ARM926EJ-S)",
    "web_server":         "voip/ (JS-based UI: app.js, mootools, PureMVC)",
    "srtp_mode":          "SDES (SDP a=crypto: attribute) — NOT DTLS-SRTP",
    "dtls_usage":         "VPN only (AnyConnect DTLS), NOT media SRTP",
    "ssl_version":        "lib/libssl.so.7 (OpenSSL 0.9.8g naming, actual 0.9.8k)",
    "crypto_version":     "lib/libcrypto.so.0.9.8g (same)",
    "no_libhstls":        "8941 has NO libhstls.so — Huron Secure TLS is 8800-series MPP specific",
    "capf_auth_modes": [
        "CAPF_CLNT_DECRYPT_FILE_FAILED",
        "capfAuthMode (in download_fingerprint_check log table)",
    ],
    "fake_crt":           "voip/fake.crt — placeholder/test certificate in filesystem",
}

# ---- PHN-CHAIN-8941: Multi-step attack chain ----

PHN_CHAIN_8941 = {
    "scenario": "Unauthenticated remote call MITM on 8941 SIP phone",
    "prerequisites": "Network access between attacker and phone + DHCP/DNS control",
    "steps": [
        ("F02 TOFU", "Factory-reset or clear ITL — force leap-of-faith provisioning"),
        ("DHCP 150", "Redirect TFTP server to attacker via DHCP option 150"),
        ("Malicious ITL", "Serve attacker-signed ITLFile.tlv, phone installs attacker CA"),
        ("F04 TVS", "No TVS in attacker's ITL — cert validation is direct-list only"),
        ("TLS MITM", "Intercept TLS to CUCM with attacker CA-signed cert"),
        ("F05 TLS-renegotiation", "Inject SIP REGISTER redirect to attacker-controlled CM"),
        ("Call hijack", "All calls route through attacker infrastructure"),
    ],
    "gate": "Requires physical access (factory reset) OR DHCP/TFTP control over network segment",
    "note": (
        "Chain can be executed entirely remotely if attacker controls network segment "
        "or can ARP-poison DHCP server responses."
    ),
}

# ---- 8941 vs 8845 MPP comparison ----

COMPARISON_8845_vs_8941 = {
    "8845_mpp": {
        "tls_arch": "libhstls.so (Cisco Huron Secure TLS, OpenSSL 1.1.x wrapper)",
        "bypass":   "PHN-F01: BypassTruststore vtable + NTP-unsync gate",
        "dtls":     "Media DTLS fingerprint in VideoCore IV (VC4 blob, no open disasm)",
        "srtp":     "DTLS-SRTP (RFC 5764)",
    },
    "8941_sip": {
        "tls_arch": "libsecurity.so (Cisco wrapper, OpenSSL 0.9.8k)",
        "bypass":   "PHN-F02/F03/F04: TOFU + SRST role + TVS-absent",
        "dtls":     "No media DTLS — uses SDES (a=crypto: in SDP)",
        "srtp":     "SDES-SRTP (RFC 4568)",
    },
    "shared_attack_surface": [
        "CAPF certificate enrollment (libcapf.so present in both)",
        "CTL/ITL file trust anchor",
        "CUCM registration TLS",
        "TFTP provisioning path",
    ],
}

# ---- PHN-F11: Dropbear SSH 0.51 — systemic across all 8941/894x SIP/SCCP ----

PHN_F11_DROPBEAR_SSH = {
    "id":      "PHN-F11",
    "title":   "Dropbear SSH 0.51 present in all 8941/894x firmware, no auth restrictions",
    "version": "SSH-2.0-dropbear_0.51",
    "debug_info": "WITH debug_info, not stripped — all four variants",
    "cross_platform": {
        "8941_SIP_9.3.4-17":    "sha256 af181f9b... (549,859 bytes)",
        "8941_SCCP_9.3.4-17":   "sha256 6f623c7b... (549,863 bytes)",
        "894x_SIP_9.4.2SR2-2":  "sha256 96a7f3b7... (549,847 bytes)",
        "894x_SCCP_9.4.2SR2-2": "sha256 1bcb4334... (549,851 bytes)",
    },
    "init_invocation": "/usr/sbin/dropbear & (no -w, no -g flags in any variant)",
    "root_login_enabled": True,
    "password_auth_enabled": True,
    "passwd_is_png": (
        "In 894x: /etc/passwd, /etc/group are 38x65 PNG images �� auth data is in nvdata partition. "
        "In 8941: same PNG pattern applies."
    ),
    "cves": [
        "CVE-2012-0920: heap use-after-free in SSH client (0.52 fixes; 0.51 is vulnerable)",
        "libtomcrypt 2008-era: multiple timing side channels",
        "libtommath 2008-era: integer operation issues",
    ],
    "chain": (
        "TCP 22 → dropbear password auth → nvdata user account → root shell → "
        "direct libsecurity.so access → ITL/CTL manipulation → MITM"
    ),
    "severity": "HIGH — all deployed 8941/894x phones with nvdata credentials are SSH-accessible",
}

# ---- PHN-F13: Hardcoded empty-password root and QA accounts (all 9.3.x) ----

PHN_F13_EMPTY_PASSWORD_ACCOUNTS = {
    "id":      "PHN-F13",
    "title":   "Hardcoded empty-password root and QA accounts in /etc/passwd — all 8941/8945 9.3.x",
    "affected": [
        "8941/8945 SIP 9.3.4-17", "8941/8945 SIP 9.3.1-18",
        "8941/8945 SCCP 9.3.4-17", "8941/8945 SCCP 9.3.1-19",
    ],
    "passwd_content": (
        "root::0:0:root:/:\n"
        "bin:*:1:1:bin:/bin:\n"
        "daemon:*:2:2:daemon:/sbin:\n"
        "adm:*:3:4:adm:/var:\n"
        "nobody:*:99:99:Nobody:/:\n"
        "qa::18:544:Linux User,,,:qa:/bin/sh"
    ),
    "mechanism": (
        "root and qa entries have empty password fields (no hash — not even '*' or '!'). "
        "Dropbear 0.51 is started without -w (no root login restriction) and without -g "
        "(no password auth restriction). SSH password auth with empty password succeeds. "
        "TCP/22 → SSH root with empty password → root shell. No credentials needed."
    ),
    "qa_account": {
        "username": "qa",
        "uid": 18, "gid": 544,
        "shell": "/bin/sh",
        "comment": "Linux User,,, — QA testing account left in production firmware",
    },
    "not_affected": [
        "8941/8945 9.4.2SR2-2 (SIP and SCCP): /etc/passwd is PNG anti-forensic file; auth is in nvdata partition",
    ],
    "patched_in":     "9.4.2SR2-2 generation — passwd moved to nvdata (runtime-mounted UBIFS/JFFS2)",
    "chain": (
        "TCP 22 → dropbear 0.51 → empty-password root → root shell → "
        "libsecurity.so access → ITL/CTL wipe → PHN-F02 TOFU trigger → "
        "attacker CA installed → TLS MITM"
    ),
    "severity": "CRITICAL — unauthenticated root shell over TCP on all deployed 8941/8945 9.3.x phones",
    "note": (
        "Comment in init.d/apps: 'VVD9111-D88/VVD9010-D88 AJet Yang 2011/04/20, "
        "fix TT13068/CSCto29080' — dropbear invocation has a bug tracker reference, "
        "confirming it was a known issue during development."
    ),
}

# ---- 8941/8945 SIP 9.3.1-18 variant ----

FIRMWARE_9_3_1_18_SIP = {
    "model":   "Cisco IP Phone 8941/8945 SIP",
    "version": "9.3.1-18",
    "arch":    "ARM (ARM926EJ-S/ARMv5TEJ per libsecurity.so ELF attributes)",
    "openssl": "0.9.8g 19 Oct 2007 (libcrypto.so.0.9.8g, 1,100,756 bytes — dynamic library)",
    "container": "Cisco SGN format (9 .bin.sgn files + 1 BOOT .bin.sgn)",
    "jffs2_offset": 0x1e2650,
    "concat_size":  0x1a76918,
    "file_count": 9,
    "lib_layout": "lib/cisco_seclib/ subdirectory (differs from 9.3.4-17's top-level cisco_seclib/)",
}

LIBRARY_COMPARISON_9_3_1_18_vs_9_3_4_17 = {
    "libsecurity_so": {
        "version_9_3_1_18": {
            "sha256": "498f01e4b094c69ea5f357d3b0ac278ca8c6f386a92302a086b17afe95491dab",
            "size":   1067824,
            "path":   "lib/cisco_seclib/libsecurity.so",
            "openssl_embedded": "0.9.8g (statically linked — matches SCCP 9.3.1-19 architecture)",
        },
        "version_9_3_4_17": {
            "sha256": "61315c885151a3c6c797e986a1284b345d8087be3e727ee5feb17a8a89760e54",
            "size":   "smaller (OpenSSL in separate libseccommon.so)",
            "openssl_in": "cisco_seclib/libseccommon.so (0.9.8k — newer)",
        },
        "cross_protocol_9_3_1_18": (
            "libsecurity.so SHA256 498f01e4... matches 8941/8945 SCCP 9.3.1-19 exactly. "
            "SIP/SCCP identical libsecurity.so pattern holds across all 9.3.x generations."
        ),
    },
    "openssl_version_delta": {
        "9_3_1_18": "0.9.8g 19 Oct 2007 (libcrypto.so.0.9.8g)",
        "9_3_4_17": "0.9.8k 25 Mar 2009 (libseccommon.so embedded)",
        "note": "9.3.4-17 ships newer OpenSSL but still pre-1.1.0. Both vulnerable to CVE-2009-3555.",
    },
    "layout_change": (
        "9.3.1-18: security libs in lib/cisco_seclib/ (subdirectory). "
        "9.3.4-17: security libs in cisco_seclib/ (top-level of jffs2). "
        "Functional equivalence — only directory placement differs."
    ),
    "phn_f02_f03_f04_confirmed": True,
    "phn_f13_confirmed": True,
    "dropbear": {
        "version": "SSH-2.0-dropbear_0.51",
        "sha256":  "d37146180e53e27645aaa8b08f692f10979be70c5d305d64d7946f8e354ed189",
        "size":    546538,
        "init":    "/usr/sbin/dropbear & (no -w, no -g; RSA host key generated on first start)",
    },
}
