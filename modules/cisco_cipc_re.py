"""
Cisco IP Communicator (CIPC) Windows softphone reverse engineering module.
Version: CIPC 8.6.5.0 (2015)
Source: CiscoIPCommunicatorSetup.msi — Data1.cab -> securitydll.dll (722,784 bytes)
Platform: Win32 PE DLL (Intel 80386), Java JNI layer over SSL-C native crypto
"""

FIRMWARE = {
    "product":   "Cisco IP Communicator (CIPC) 8.6.5.0",
    "type":      "Windows softphone (x86 PE DLL)",
    "date":      "2015-07-01",
    "binary":    "securitydll.dll",
    "size":      722784,
    "sha256":    "199ec39b955261d1a9d96cf8a374adb6d05c84346205175b402ee85e4106279f",
    "pe_type":   "Win32 PE32 DLL GUI, Intel 80386",
    "crypto":    "SSL-C (RSA Security) — NOT OpenSSL",
    "protocol":  "SCCP (Skinny Client Control Protocol) + SRTP",
    "java_layer": "JNI bridge: cip_sec_NativeSecurity + cip_io_NativeSecureSocketImpl",
}

# ---- SSL-C crypto library (RSA Security, not OpenSSL) ----

SSL_C_LIBRARY = {
    "tls_ssl3_version": "SSL-C 2.7.0",
    "x509_version":     "SSL-C 2.1.1 26-Sep-2001",
    "note": (
        "Two SSL-C versions embedded: 2.7.0 for TLS/SSL3 handshake, 2.1.1 for X509 cert handling. "
        "SSL-C is RSA Security's licensed crypto library (before RSA became part of EMC/Dell). "
        "SSL-C 2.1.1 predates TLS 1.1 (RFC 4346, 2006) and TLS 1.2 (RFC 5246, 2008) by 5-7 years."
    ),
    "cipher_suite_string": "ALL:!ADH:RC4+RSA:+HIGH:+MEDIUM:+LOW:+SSLv2:+EXP",
    "cipher_suite_issues": [
        "+SSLv2 — SSLv2 ENABLED (DROWN attack CVE-2016-0800 applicable)",
        "+EXP — Export-grade (40/56-bit) ciphers ENABLED (FREAK attack applicable)",
        "+LOW — Low-security ciphers enabled",
        "RC4+RSA — RC4 explicitly included (RFC 7465 prohibits RC4 in TLS)",
    ],
    "supported_protocols": ["SSLv2", "SSLv3", "TLSv1"],
    "missing_protocols":   ["TLS 1.1", "TLS 1.2", "TLS 1.3"],
}

# ---- JNI interface: full export table ----

JNI_EXPORTS = {
    "socket_layer": {
        "class": "cip.io.NativeSecureSocketImpl",
        "exports": [
            "socketClose", "socketConnect", "socketRead", "socketWrite",
        ],
        "backend": "SSL-C 2.7.0 TLS/SSLv3 implementation",
    },
    "security_layer": {
        "class": "cip.sec.NativeSecurity",
        "exports": [
            "addEntityToCtl", "cancelCapf", "clearCapf", "disposeNativeSecurityApp",
            "eraseCTL", "getAuthInfo", "getCTLInfo", "getCapf", "getCapfStatus",
            "getCertHash", "getCertInfo", "getLastCTLError", "initNativeSecurityApp",
            "lookupCTL", "removeSrstEntities", "removeTftpEntities", "secureFileOp",
            "setAuthMode", "setAuthSecret", "setCapf", "setEMCCStatus",
            "setSecureMode", "setTvsServer", "startCapf", "updateCTL", "verifyMIDlet",
        ],
        "backend": "SEC* native functions over SSL-C 2.1.1 X509",
    },
}

# ---- PHN-F04 analogue: TVS structurally absent in CIPC ----

PHN_F04_CIPC = {
    "finding_id": "PHN-F04-CIPC",
    "title": "CIPC: TVS (Trust Verification Service) is structurally not implemented",
    "evidence": "SECAddTvsServer() - not implemented, rc=<-1>",
    "jni_export": "_Java_cip_sec_NativeSecurity_setTvsServer@48",
    "mechanism": (
        "The JNI export setTvsServer() is present (signature matches ARM firmware), "
        "but the native implementation SECAddTvsServer() returns -1 unconditionally. "
        "TVS is NEVER used in CIPC — cert validation is CTL/ITL direct-list only. "
        "This is stronger than ARM PHN-F04 (where TVS is absent from the trust list); "
        "in CIPC the TVS subsystem was never implemented."
    ),
    "impact": (
        "All cert validation in CIPC uses direct CTL trust list matching only. "
        "No online revocation checking in any deployment scenario. "
        "Revoked certs remain accepted indefinitely as long as they match the static CTL."
    ),
    "comparison": {
        "arm_firmware_PHN_F04": "TVS skipped if absent from ITL trust list (runtime check)",
        "cipc_PHN_F04_analogue": "TVS never implemented — always absent, cannot be added",
    },
}

# ---- SRST cert handling (same pattern as ARM firmware) ----

SRST_HANDLING = {
    "log_strings": ["SRST, bad cert arg", "SRST CA, bad cert arg", "SRST, bad ipAddr arg"],
    "removeSrstEntities": "JNI export present — CIPC can remove SRST entities from CTL",
    "note": (
        "SRST handling pattern identical to ARM libsecurity.so. "
        "PHN-F03 (SRST role bypass) analogue likely present — needs deeper disassembly to confirm."
    ),
}

# ---- Attack surface: CIPC-specific ----

CIPC_ATTACK_SURFACE = {
    "ssl_c_downgrade": {
        "cve": "CVE-2016-0800 (DROWN) — applicable to SSLv2-enabled servers",
        "attack": "CIPC SSLv2 support enables DROWN cross-protocol downgrade against CUCM TLS",
        "cipher": "RC4, export-grade ciphers enable BEAST/FREAK/POODLE",
    },
    "ctl_tofu": {
        "analogue": "PHN-F02 (TOFU CTL/ITL)",
        "evidence": "updateCTL, eraseCTL, getLastCTLError, lookupCTL log strings",
        "note": (
            "CIPC has full CTL management (update, erase, lookup). "
            "CTL update path exists — TOFU leap-of-faith on initial provisioning. "
            "No 'Using leap of faith' string found in static analysis — may be different log message "
            "or implemented differently in Windows softphone. Deeper disassembly needed."
        ),
    },
    "windows_storage": (
        "CTL/ITL storage is Windows-native (registry or AppData). "
        "Attacker with user-level Windows access can modify stored CTL files directly. "
        "No physical flash requirement (unlike ARM phones)."
    ),
    "capf_attack": (
        "Full CAPF implementation: setCapf, startCapf, getCapf, getCapfStatus, cancelCapf, clearCapf. "
        "CAPF enrollment attack surface: if attacker can intercept CAPF TCP connection, "
        "they can replace the enrollment certificate."
    ),
    "midlet_verify": (
        "verifyMIDlet JNI export — CIPC verifies MIDlet JAR signature. "
        "Attack: if cert validation bypassed (PHN-F04-CIPC or via CTL manipulation), "
        "attacker can install unsigned or maliciously-signed MIDlet."
    ),
}

# ---- cdpcert.cer: expired Cisco code-signing certificate ----

CDPCERT_ANALYSIS = {
    "serial": "6d:18:3b:dc:48:ef:01:69:d1:2b:9b:d1:3b:a2:a7:3d",
    "issuer": "VeriSign Class 3 Code Signing 2010 CA",
    "subject": "Cisco Systems, Inc. (Digital ID Class 3, MS Software Validation v2)",
    "valid_from": "2011-01-10",
    "valid_until": "2014-03-30",
    "status": "EXPIRED (2014) — embedded in MSI for installer signature verification",
    "note": (
        "This is Cisco's code-signing certificate used to sign the CIPC installer. "
        "The cert is expired but the MSI signature may still be verifiable via timestamp. "
        "Not an exploitable finding — informational only."
    ),
}

# ---- CIPC vs ARM firmware comparison ----

CIPC_vs_ARM_COMPARISON = {
    "crypto_library": {
        "arm_8941_8945": "OpenSSL 0.9.8k (libseccommon.so) — TLS 1.0 only",
        "arm_894x":      "OpenSSL 1.1.0-fips-dev (libseccommon.so) — TLS 1.2",
        "cipc_windows":  "SSL-C 2.7.0/2.1.1 (RSA Security) — TLSv1/SSLv3/SSLv2",
        "cipc_weakness":  "CIPC enables SSLv2 and export-grade ciphers — weaker than ARM 8941",
    },
    "tvs": {
        "arm_firmware": "PHN-F04: runtime bypass when TVS absent from ITL",
        "cipc":         "PHN-F04-CIPC: TVS structurally not implemented — permanent",
    },
    "architecture": {
        "arm_firmware": "Native C security daemon (secd) + libsecurity.so",
        "cipc":         "Java softphone + JNI bridge to securitydll.dll (Win32 PE)",
    },
    "shared_patterns": [
        "CTL/ITL trust list management (updateCTL, eraseCTL, lookupCTL)",
        "SRST entity management (removeSrstEntities)",
        "CAPF certificate enrollment",
        "MIDlet signature verification (verifyMIDlet)",
        "EMCC (Extension Mobility Cross Cluster) support",
    ],
}
