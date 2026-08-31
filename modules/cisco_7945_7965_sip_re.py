"""
Cisco IP Phone 7945/7965 SIP firmware reverse engineering module.
Firmware: SIP 9.4.2SR1-1 (cmterm-7945_7965-sip.9-4-2SR1-1.zip)
Platform: MIPS big-endian, Beamish CVM (J2ME CDC), Linux
Container: CNU_File_Archive_3.0 (variable-length Cisco sig block, NOT 512-byte strip)
"""

FIRMWARE = {
    "model":      "Cisco IP Phone 7945/7965 SIP",
    "version":    "9.4.2SR1-1",
    "arch":       "MIPS big-endian (EI_DATA=2, e_machine=MIPS, entry=0x10002000)",
    "platform":   "Beamish CVM (J2ME CDC VM — Cisco's embedded JVM)",
    "linux":      "confirmed (/modules/lcd.ko, /modules/power.ko, /etc/group in jar45sip)",
    "jvm_format": "DEADBEEF magic header, 6.8MB decompressed CVM binary",
    "container":  "CNU_File_Archive_3.0 (Cisco proprietary archive)",
    "sig_format": (
        "Variable-length Cisco TLV signature starting at offset 0; "
        "jar45sip.sbn has 0x370f8 (225528) byte sig+header before first ZIP; "
        "cvm45sip.sbn has 0x457-byte sig+header before gzip at 0x457"
    ),
    "jar45sip_structure": {
        "zip1_offset":  0x370f8,
        "zip1_eocd":    0x83979,
        "zip1_entries": 172,
        "zip1_content": "UI resources: fonts, XML config, ringtones, icons",
        "zip2_offset":  0x8398f,
        "zip2_eocd":    0x1a395a,
        "zip2_entries": 1007,
        "zip2_content": "Java class library (CDC Foundation + Cisco additions)",
        "extraction_note": (
            "Python zipfile.ZipFile() on raw slice starting at zip1_offset returns "
            "zip2 (1007 entries) because it finds the LAST EOCD. "
            "Extract zip1 by slicing exactly [0x370f8:0x8398f]."
        ),
    },
    "cvm_gzip_offset": 0x457,
    "cvm_decompressed_size": 0x67d8ec,
    "apps45_elf_count": 61,
    "apps45_arch": "MIPS big-endian ELF",
}

# ---- TLS Architecture ----

TLS_ARCHITECTURE = {
    "java_ssl_package": "com.sun.cdc.io.j2me.ssl (Protocol, SSLStreamConnection)",
    "cisco_ssl_path":   "cip/midp/io/j2me/ssl (registered in CVM native class table, no .class file)",
    "trust_manager":    "com.sun.cdc.io.j2me.ssl.J2meTrustManager (CVM-native — not in any JAR)",
    "secd_socket":      "/tmp/sslAppSrvrSock (Unix domain socket — CVM delegates TLS to secd daemon)",
    "actual_tls":       "secd handles TLS handshake + cert validation via libsecurity.so",
    "java_tls_role":    "SSLStreamConnection is a JSSE facade; real TLS is in secd",
    "boot_config":      "REJECT_UNSIGNED_LOADS REJECT_INVALID_SIGS (in jar45sip CNU boot config)",
}

# ---- PHN-F06: getTrustedCertStore null-return bug ----

PHN_F06_NULL_CERTSTORE = {
    "id":     "PHN-F06",
    "title":  "SSLStreamConnection.getTrustedCertStore() guaranteed null return",
    "class":  "com.sun.cdc.io.j2me.ssl.SSLStreamConnection",
    "method": "getTrustedCertStore()",

    "bytecode": {
        "offset_6":  "ldc 'com.sun.cdc.io.j2me.ssl' (PACKAGE name, not class name)",
        "offset_8":  "Class.forName('com.sun.cdc.io.j2me.ssl') — always throws ClassNotFoundException",
        "offset_23": "astore_0 + goto 27 — exception SILENTLY SWALLOWED",
        "offset_27": "trustedCertStoreInitialized = true",
        "offset_29": "return trustedCertStore (== null — was never set)",
    },

    "exception_table_entry": "from 6 to 20, target 23, type java.lang.Exception",

    "mechanism": (
        "The method tries Class.forName('com.sun.cdc.io.j2me.ssl') — "
        "a package name, not a class name. This always throws ClassNotFoundException, "
        "which is caught by the broad Exception handler at offset 23. "
        "The handler sets trustedCertStoreInitialized=true but leaves trustedCertStore=null. "
        "All subsequent calls to getTrustedCertStore() skip initialization (already initialized) "
        "and return null."
    ),

    "impact_on_j2me_tm": (
        "J2meTrustManager is a CVM-native class that calls getTrustedCertStore() "
        "to retrieve CA certs for server cert validation. "
        "If J2meTrustManager.checkServerTrusted() calls certStore.getCertificates(host) "
        "without null-checking certStore, it throws NullPointerException. "
        "In the secd-proxy architecture this is moot: secd handles actual cert validation "
        "and J2meTrustManager is a callback stub. NPE propagates as InvocationTargetException → "
        "ConnectionNotFoundException (connection fails, not bypasses)."
    ),

    "severity": "LOW — connection fails rather than succeeds on NPE path",
}

# ---- PHN-F07: lockTrustedCertStore null-guard logic inversion ----

PHN_F07_LOCK_BYPASS = {
    "id":     "PHN-F07",
    "title":  "SSLStreamConnection.lockTrustedCertStore() lock inversion — setTrustedCertStore() always injectable",
    "class":  "com.sun.cdc.io.j2me.ssl.SSLStreamConnection",
    "methods": ["lockTrustedCertStore()", "setTrustedCertStore(CertStore)"],

    "lock_bytecode": {
        "offset_0": "getstatic trustedCertStore",
        "offset_3": "ifnonnull 7  ← if store is null, return WITHOUT setting lock",
        "offset_6": "return       ← lock is NEVER acquired when store is null",
        "offset_7": "putstatic trustedCertStoreLocked = true",
        "offset_11": "return",
    },

    "set_bytecode": {
        "offset_0": "getstatic trustedCertStoreLocked",
        "offset_3": "ifne (offset_N) ← if locked, return early (no update)",
        "normal_path": "stores the provided CertStore",
    },

    "mechanism": (
        "lockTrustedCertStore() is a static synchronized method intended to prevent "
        "further calls to setTrustedCertStore() from replacing the cert store. "
        "BUT: it checks 'if (trustedCertStore == null) return' before setting the lock flag. "
        "Since getTrustedCertStore() always returns null (PHN-F06), lockTrustedCertStore() "
        "will always return early without setting trustedCertStoreLocked=true. "
        "Therefore setTrustedCertStore() can always inject a replacement CertStore."
    ),

    "attack_scenario": (
        "A MIDlet with access to com.sun.cdc.io.j2me.ssl.SSLStreamConnection can call "
        "SSLStreamConnection.setTrustedCertStore(maliciousCertStore) where maliciousCertStore "
        "implements getCertificates(host) to return all attacker-provided certs as trusted. "
        "If J2meTrustManager uses the cert store (non-secd-proxy path), "
        "all subsequent SSL connections accept any cert."
    ),

    "prerequisites": "MIDlet sandbox escape or privileged J2ME execution context",
    "severity": "MEDIUM (requires J2ME sandbox escape to exploit; secd-proxy path may not use cert store)",

    "chain": "PHN-F06 (null store enables bypass of locking) → PHN-F07 (always injectable)",
}

# ---- Java CTL/ITL trust strings (from apps45.sbn) ----

APPS45_TRUST_STRINGS = {
    "binary": "apps45.9-4-2ES9.sbn (MIPS big-endian, 61 ELF objects embedded, 4.6MB)",
    "security_log_strings": [
        "MOD_CERT", "MOD_SSL", "MOD_CTL", "VERIFY_MIDLET",
        "CTL_UPDATE", "ITL_ITEM",
        "OK_INITIAL_CTL", "OK_INITIAL_ITL",
        "FAILED_CTL", "FAILED_ITL",
        "VPN_NO_LEAF_CERT", "VPN_UNTRUSTED",
    ],
    "note": (
        "CTL/ITL handling in 7945/7965 apps45.sbn uses the same trust framework as 8941. "
        "TOFU (PHN-F02 analogue) and TVS-absent bypass (PHN-F04 analogue) likely present. "
        "CTL/ITL code is in MIPS ELF objects within apps45.sbn — not Java layer."
    ),
}

# ---- CVM secd-proxy architecture (attack surface) ----

SECD_PROXY_SURFACE = {
    "socket":     "/tmp/sslAppSrvrSock",
    "log_string": "** no secd?! no SSL/TLS proxy srvr sock <%s>",
    "cvm_strings": [
        "Entering StcpOpenActiveSSL",
        "Leaving StcpOpenActiveSSL",
        "StcpActiveSSLConnectionStatus: eRpTcpCannotOpenActive",
        "StcpActiveSSLConnectionStatus: SUCCESS",
        "WcValidateRequest: theRequestPtr->fTlsConnectionFlag=%d  defaultPort=%d actualPort=%d hostName=%s",
        "SRST CA, bad cert arg",
        "SRST, bad cert arg",
        "secReq_setVPNCertificates",
        "secReq_vfyVPNCertificates",
        "secReq_getSrvCertAttr",
    ],
    "implication": (
        "All TLS cert validation for Java SSL connections runs through secd. "
        "The Java TrustManager (J2meTrustManager) is a stub — it calls secd via IPC. "
        "PHN-F02/F03/F04 bypass points (libsecurity.so in secd) are the real attack surface. "
        "Java-layer cert store injection (PHN-F06/F07) is only relevant if secd is killed or "
        "if a non-secd TLS path exists (e.g., MIDlet calling ssl:// directly)."
    ),
}

# ---- SSLStreamConnection constructor exception table (full) ----

CONSTRUCTOR_EXCEPTION_TABLE = {
    "range_34_427": {
        "ClassNotFoundException → 430": "throws ConnectionNotFoundException (TrustManager class missing)",
        "NoSuchMethodException → 442":  "throws ConnectionNotFoundException",
        "IllegalAccessException → 454": "throws ConnectionNotFoundException",
        "InstantiationException → 466": "prints stack trace, throws ConnectionNotFoundException",
        "InvocationTargetException → 483": (
            "if cause instanceof SSLPeerUnverifiedException: extract server cert, throw CertificateException; "
            "otherwise: throw ConnectionNotFoundException"
        ),
        "Exception (catch-all) → 668": (
            "if instanceof GeneralSecurityException: throw ConnectionNotFoundException; "
            "else: print stack trace, FALL THROUGH to offset 696 (set copen=true, return) — "
            "connection appears open with null socket. "
            "Reachable for: RuntimeException subclasses not listed above (NPE, ClassCastException, etc.)"
        ),
    },
    "offset_696": "aload_0; iconst_1; putfield copen; return — constructor returns successfully",
    "bypass_note": (
        "The Exception catch-all handler at 668 can set copen=true and return without a socket "
        "for RuntimeExceptions not matching listed exception types. "
        "openInputStream() would then throw NullPointerException on null socket. "
        "Not a TLS bypass — connection is non-functional."
    ),
}

# ---- PHN-CHAIN-7965: Attack chain ----

PHN_CHAIN_7965 = {
    "scenario": "Unauthenticated MITM on 7945/7965 SIP TLS — analogous to 8941 chain",
    "secd_layer": {
        "F02_analogue": "TOFU CTL/ITL leap-of-faith on factory reset (apps45.sbn MIPS code)",
        "F04_analogue": "TVS-absent bypass when TVS not in ITL",
        "attack": "Same DHCP option 150 redirect → serve malicious ITLFile.tlv → TOFU acceptance",
    },
    "java_layer": {
        "PHN_F07": "CertStore injection via lockTrustedCertStore null-guard bypass (requires J2ME sandbox access)",
        "note": "Java layer is secondary surface; secd native layer is primary",
    },
    "delta_from_8941": (
        "7945/7965 adds J2ME Java SSL layer on top of secd, creating PHN-F06/F07 secondary attack surface. "
        "Core trust bypass (TOFU + TVS-absent) is shared across both platforms."
    ),
}

# ---- 7945/7965 vs 8941 comparison ----

COMPARISON_7965_vs_8941 = {
    "7945_7965_sip": {
        "arch":       "MIPS big-endian + J2ME CDC (BeamishCVM) + secd native layer",
        "ssl_java":   "com.sun.cdc.io.j2me.ssl.SSLStreamConnection (JSSE facade → secd proxy)",
        "ssl_native": "secd via /tmp/sslAppSrvrSock → libsecurity.so",
        "trust_mgr":  "J2meTrustManager (CVM-native stub, not in JAR)",
        "dtls":       "No media DTLS — SDES-SRTP (SDP a=crypto:)",
        "new_surface": "PHN-F06 null CertStore / PHN-F07 lock inversion (J2ME layer)",
    },
    "8941_sip": {
        "arch":       "ARM926EJ-S + native Linux + secd",
        "ssl_java":   "None — no J2ME layer",
        "ssl_native": "libsecurity.so directly",
        "trust_mgr":  "N/A (native only)",
        "dtls":       "No media DTLS — SDES-SRTP",
        "surface":    "PHN-F02/F03/F04/F05 (native trust list + OpenSSL 0.9.8k)",
    },
    "shared": [
        "TOFU leap-of-faith CTL/ITL acceptance on factory reset",
        "TVS-absent bypass (no online revocation)",
        "SDES-SRTP (no DTLS-SRTP — key material in SDP plaintext)",
        "CAPF certificate enrollment surface",
        "CUCM registration TLS",
        "DHCP option 150 / TFTP provisioning attack vector",
    ],
}
