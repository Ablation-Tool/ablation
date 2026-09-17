"""
FortiClient Android 7.4.3 APK RE
Sources:
  - forticlient-vpn.7.4.3.apk (49MB, August 2025)
  - lib/arm64-v8a/libjni_forticlient.so (4.9MB, NOT stripped)
  - lib/arm64-v8a/lib_sslvpn_x.so (3.6MB)
  - lib/arm64-v8a/lib_ipsec_x.so (3.4MB)
  - classes.dex + classes2.dex + classes3.dex + classes4.dex (Java/Kotlin bytecode)
Product: FortiClient VPN 7.4.3 for Android
"""

# ---------------------------------------------------------
# FortiClient Android -- product context
# ---------------------------------------------------------
FCTANDROID_CONTEXT = {
    "id":       "FCLIENT-ANDROID",
    "product":  "FortiClient VPN 7.4.3 (Android)",
    "binary":   "forticlient-vpn.7.4.3.apk",
    "size":     "49MB APK (August 2025)",
    "package":  "com.fortinet.forticlient_vpn (inferred from JNI class path jni_1forticlient)",

    "apk_components": {
        "classes_dex":    "4 DEX files (classes.dex + classes2-4.dex) -- Java/Kotlin business logic",
        "lib_arm64":      "5 ARM64 native .so files",
        "lib_armeabi_v7a": "5 ARMv7 native .so files (32-bit fallback)",
        "lib_x86":        "5 x86 native .so files (emulator support)",
        "assets_dexopt":  "baseline.prof -- ART profile for JIT optimization",
    },

    "native_libraries": {
        "libjni_forticlient.so": "4.9MB arm64; main FortiClient JNI bridge; NOT stripped",
        "lib_sslvpn_x.so":       "3.6MB arm64; SSL-VPN protocol implementation",
        "lib_sslvpn2_x.so":      "3.8MB arm64; SSL-VPN v2 implementation",
        "lib_ipsec_x.so":        "3.4MB arm64; IKEv2/IPSec implementation (includes Xauth)",
    },

    "jni_classes": {
        "NativeEndpoint":   "EMS registration, VPN state, cert validation, EMS communication",
        "NativeAntivirus":  "Local antivirus signature checking",
        "NativeSandbox":    "FortiSandbox file upload and verdict retrieval",
        "NativeWebFilter":  "TUN-based web filter (intercepts DNS + raw packets)",
    },
}

# ---------------------------------------------------------
# FortiClient Android JNI exports (full list from libjni_forticlient.so)
# ---------------------------------------------------------
FCTANDROID_JNI_EXPORTS = {
    "id":     "FCLIENT-ANDROID-JNI",
    "source": "nm libjni_forticlient.so | grep Java_",

    "NativeEndpoint_methods": [
        "cancelRegistration",
        "confirmOnboardingReauth",
        "confirmOnboardingRegistration",
        "enableCloudEms",
        "forceSendRefresh",
        "getDefaultGateway",
        "getEmsGatewayAddress",
        "getFortiClientSerialNumber",
        "getFortiClientUUID",
        "getFortiOSGatewayAddress",
        "getLocalIp",
        "getPublicIP",
        "init",
        "isServerOnline",
        "logVPN",
        "logWF",
        "notifyInvalidCertChoice",   # cert bypass UI notification
        "on0232317",                  # obfuscated callback
        "on0292079",                  # obfuscated callback
        "rateUrl",
        "registerServer",
        "sendKeepAlive",
        "sendRingCmdOnRegister",
        "sendRingCmdOnStart",
        "sendRingCmdOnUpdate",
        "setAppList",
        "setFazLog",
        "setFdnRegion",
        "setMdmValues",
        "setUseLegacyFdn",
        "setUsername",
        "start",
        "testOnnetStatusAndApply",
        "unregisterServer",
        "useOnPremInvitationCode",
    ],

    "NativeAntivirus_methods": ["checkVirusSignature", "init", "start"],

    "NativeSandbox_methods": ["getScanningVerdict", "uploadFile"],

    "NativeWebFilter_methods": [
        "init", "readPacketFromTun", "readPayloadDNS",
        "setupTun", "start", "writePacketToTun", "writePayloadDNS",
    ],
}

# ---------------------------------------------------------
# FCLIENT-AND-F01: Cert bypass UI identical to Linux version
# ---------------------------------------------------------
FCLIENT_AND_F01_CERT_BYPASS = {
    "id":       "FCLIENT-AND-F01",
    "product":  "FortiClient Android 7.4.3 -- certificate bypass UI",
    "severity": "MEDIUM -- user-facing cert bypass; same class as FCLIENT-ZTPROXY-F01",
    "class":    "TLS certificate validation bypass (CWE-295)",
    "source":   "libjni_forticlient.so strings + JNI exports",

    "description": (
        "libjni_forticlient.so contains cert bypass strings and JNI methods: "
        "  notifyInvalidCertChoice -- JNI export: Java notified when cert is invalid "
        "  promptInvalidCertChoice -- prompts user to accept invalid cert "
        "  getInvalidCertChoice    -- retrieves user's stored bypass decision "
        "  getInvalidCertActionSetting -- reads admin-configured bypass action "
        "String evidence: "
        "  'potentially invalid certificate' "
        "  'Error verifying SSL cert' "
        "  'invalid certificate' "
        "This mirrors FCLIENT-ZTPROXY-F01 (Linux ztproxy disallow_invalid_server_certificate=0). "
        "The Android version has the same bypass mechanism: "
        "  (a) Admin policy can disable cert validation globally "
        "  (b) User can accept individual invalid certs via prompt "
        "A rogue FortiGate with a self-signed or mismatched cert can intercept "
        "Android FortiClient traffic if the user accepts the cert prompt."
    ),

    "related_finding": "FCLIENT-ZTPROXY-F01 (Linux), Barton CC config disallow_invalid_server_certificate=0",

    "remediation": (
        "Enforce certificate pinning for EMS connections. "
        "Remove user-facing cert bypass prompts for EMS/ZTNA connections. "
        "Admin cert bypass setting should require explicit MDM policy, not default 'allow'."
    ),
}

# ---------------------------------------------------------
# FCLIENT-AND-F02: Obfuscated JNI callback methods
# ---------------------------------------------------------
FCLIENT_AND_F02_OBFUSCATED_CALLBACKS = {
    "id":       "FCLIENT-AND-F02",
    "product":  "FortiClient Android 7.4.3 -- obfuscated NativeEndpoint callbacks",
    "severity": "INFO -- obfuscated method names conceal security-sensitive callbacks",
    "class":    "Security through obscurity (CWE-656)",
    "source":   "libjni_forticlient.so JNI exports",

    "description": (
        "Two NativeEndpoint JNI exports have numeric-only names: "
        "  on0232317 "
        "  on0292079 "
        "The 'on' prefix suggests event callbacks (Android convention: onEvent). "
        "The numeric suffix (0232317, 0292079) appears to be an obfuscated event type code. "
        "These do not correspond to standard Android lifecycle methods. "
        "The numbers may represent: "
        "  - Obfuscated message type IDs from the Fortinet protocol "
        "  - ProGuard/R8-obfuscated method names "
        "  - Internal Fortinet opcode values for undocumented callbacks "
        "Without DEX decompilation, the purpose is unknown. "
        "Likely handles critical EMS provisioning or policy push events given placement "
        "alongside registerServer, confirmOnboardingRegistration."
    ),

    "pending": "DEX decompilation (jadx/apktool) on classes.dex to identify on0232317/on0292079 callers",
}

# ---------------------------------------------------------
# FCLIENT-AND-F03: FAZ log format leaks full device identity
# ---------------------------------------------------------
FCLIENT_AND_F03_FAZ_LOG_IDENTITY_LEAK = {
    "id":       "FCLIENT-AND-F03",
    "product":  "FortiClient Android 7.4.3 -- FAZ web filter log format",
    "severity": "LOW -- web filter traffic logs include persistent device identity fields",
    "class":    "Sensitive data in logs (CWE-532 / CWE-200)",
    "source":   "libjni_forticlient.so strings",

    "description": (
        "libjni_forticlient.so contains the FortiAnalyzer log format string: "
        "  date=%s time=%s logver=2 type=traffic sessionid=N/A uid=%s emsserial=%s "
        "  level=notice vd=root devid=%s hostname=%s msg=N/A user=%s srcname=N/A "
        "  regip=%s devicemac=%s fctver=%s os=%s usingpolicy=N/A utmevent=webfilter "
        "  dstip=%s remotename=%s srcip=%s "
        "Every web filter traffic event logged to FAZ includes: "
        "  uid         -- FortiClient UUID (persistent device identifier) "
        "  emsserial   -- EMS server serial number "
        "  devid       -- device ID "
        "  hostname    -- device hostname "
        "  user        -- username at time of event "
        "  regip       -- registered IP address "
        "  devicemac   -- device MAC address "
        "  fctver      -- FortiClient version "
        "  srcip / dstip -- source and destination IPs "
        "Every browsed URL generates a FAZ log entry with full device fingerprint. "
        "If FAZ is compromised or if logs are aggregated without access controls, "
        "this is a complete audit trail of user browsing with device identity."
    ),

    "log_format": (
        "date=%s time=%s logver=2 type=traffic sessionid=N/A uid=%s emsserial=%s "
        "level=notice vd=root devid=%s hostname=%s msg=N/A user=%s srcname=N/A "
        "regip=%s devicemac=%s fctver=%s os=\"%s\" usingpolicy=N/A utmevent=webfilter "
        "dstip=%s remotename=%s srcip=%s"
    ),
}

# ---------------------------------------------------------
# FCLIENT-AND-F04: lib_sslvpn_x.so -- FortiSSL-VPN XML endpoint
# ---------------------------------------------------------
FCLIENT_AND_F04_SSLVPN_XML_ENDPOINT = {
    "id":       "FCLIENT-AND-F04",
    "product":  "FortiClient Android 7.4.3 -- SSL-VPN XML endpoint",
    "severity": "INFO -- confirms /remote/fortisslvpn_xml is Android attack surface",
    "class":    "Attack surface confirmation",
    "source":   "lib_sslvpn_x.so strings",

    "description": (
        "lib_sslvpn_x.so contains: "
        "  GET /remote/fortisslvpn_xml "
        "This is the FortiSSL-VPN XML configuration endpoint on FortiGate. "
        "This endpoint was the target of multiple critical CVEs: "
        "  CVE-2023-27997: Heap overflow pre-auth in SSL-VPN; affects /remote/ paths "
        "  CVE-2024-21762: Out-of-bounds write in SSL-VPN "
        "Android FortiClient 7.4.3 (August 2025) still uses this endpoint. "
        "Additional SSL-VPN strings confirmed: "
        "  'no password' / 'empty password' -- empty password VPN auth path "
        "  'srp_username' / 'srp_generate_client_master_secret' -- SRP auth supported "
        "  'opening session' / 'onlyuser' -- session state strings "
        "The 'no password' and 'empty password' strings suggest the SSL-VPN client "
        "handles empty-credential cases, which may allow VPN auth bypass to gateways "
        "that accept empty passwords."
    ),

    "sslvpn_endpoint": "GET /remote/fortisslvpn_xml",
    "auth_methods_confirmed": ["SRP (Secure Remote Password)", "empty password path"],

    "remediation": "Verify FortiGate rejects empty-password VPN auth attempts.",
}

# ---------------------------------------------------------
# FCLIENT-AND-F05: IPSec library -- Xauth/hybrid auth
# ---------------------------------------------------------
FCLIENT_AND_F05_IPSEC_XAUTH = {
    "id":       "FCLIENT-AND-F05",
    "product":  "FortiClient Android 7.4.3 -- IPSec Xauth implementation",
    "severity": "INFO -- Xauth (deprecated auth extension for IKEv1) confirmed in Android IPSec lib",
    "class":    "Deprecated authentication protocol (CWE-327)",
    "source":   "lib_ipsec_x.so strings",

    "description": (
        "lib_ipsec_x.so contains Xauth (IKEv1 extended authentication) strings: "
        "  'agg_i1send: Xauth vendor ID generation failed' "
        "  'Hybrid auth negotiated but peer did not succeed Xauth exchange' "
        "  'xauth group specified but modecfg not found' "
        "Xauth is an IKEv1 extension (deprecated; not part of IKEv2 standard). "
        "It was used for user authentication in IPSec VPN before EAP became standard. "
        "Xauth has known weaknesses: "
        "  - Susceptible to MITM credential capture (no mutual auth before cred exchange) "
        "  - 'Hybrid auth' variant authenticates gateway but not client before Xauth "
        "Android FortiClient 7.4.3 retains Xauth support for backward compatibility "
        "with older FortiGate deployments. "
        "The EVP_PKEY_decapsulate string also confirms KEM (Key Encapsulation Mechanism) "
        "support -- likely ML-KEM/Kyber for PQC (same as Linux ztproxy FCLIENT-ZTPROXY-F05)."
    ),

    "related_finding": "FCLIENT-ZTPROXY-F05 (Linux ML-KEM/Kyber PQC in QUIC tunnel)",
}

unique_findings = [
    "FCLIENT-AND-F01",  # MEDIUM: cert bypass UI (matches Linux FCLIENT-ZTPROXY-F01)
    "FCLIENT-AND-F02",  # INFO: obfuscated on0232317 / on0292079 callbacks
    "FCLIENT-AND-F03",  # LOW: FAZ log format exposes full device identity per web filter event
    "FCLIENT-AND-F04",  # INFO: /remote/fortisslvpn_xml endpoint + empty password path
    "FCLIENT-AND-F05",  # INFO: Xauth/hybrid auth + KEM/PQC in IPSec lib
]
