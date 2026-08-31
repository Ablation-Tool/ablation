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
