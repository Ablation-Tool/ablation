"""
Cisco Jabber Windows 11.9.1 — TLS/DTLS Cert Verification RE
Static analysis: strings, objdump, readelf on extracted MSI payload
"""

FIRMWARE = {
    "product":   "Cisco Jabber for Windows 11.9.1",
    "msi_source": "CiscoJabberSetup.msi (extracted)",
    "install_path": "Program Files/Cisco Systems/Cisco Jabber/",
    "build_path":   "J:\\BLD_11.9\\",
    "toolchain":    "MSVC 2015 (VS2015)",
    "platform":     "Win32 PE32 / x86",
}

# ─────────────────────────────────────────────────────────
# Crypto library inventory
# ─────────────────────────────────────────────────────────
CRYPTO_LIBRARIES = {
    "ssleay32.dll": {
        "sha256": "95e09b834e5737f44435b57fe0922b187f6cd97a0ba08880c46c574e0b8557c1",
        "size": 283736,
        "version_string": "CiscoSSL 1.0.2k.6.2.9-fips",
        "note": "NOT vanilla OpenSSL; Cisco FIPS-validated fork of 1.0.2k",
        "tls_versions_present": ["SSLv3", "TLSv1", "TLSv1.1", "TLSv1.2", "DTLSv1", "DTLSv1.2"],
        "cipher_suite_string": "ALL:!EXPORT:!LOW:!aNULL:!eNULL:!SSLv2",
    },
    "libeay32.dll": {
        "sha256": "422f16036fb9439537d83366634664a3d487ae6fe0fc794fae4b3ca5d5be4e24",
        "size": 1584728,
        "note": "CiscoSSL crypto engine (companion to ssleay32.dll)",
    },
    "cmcrypto.dll": {
        "sha256": "035c88f3...",  # from prior analysis
        "size": 63576,
        "imports": ["LIBEAY32.dll"],
        "exports": [
            "VerifyCertificateEx",
            "GetVerifyCertError",
            "GetVerifyCertErrorInfo",
            "CreateCertKeyPair",
            "CreateSessionKey",
            "CryptoDataEx",
            "EnvelopSessionKey",
            "EnvelopSessionKeyEx",
            "ICmCrypto",  # C++ class
        ],
        "note": "Primary TLS cert validation entry point; ICmCrypto C++ interface",
    },
}

# ─────────────────────────────────────────────────────────
# handyiron shared security library — embedded in enhanced-callcontrol_MD.dll
# Same library family as Cisco IP phones (SCCP/SIP firmware)
# ─────────────────────────────────────────────────────────
HANDYIRON_LIBRARY = {
    "dll": "enhanced-callcontrol_MD.dll",
    "sha256": "590c1ba2e9e020086f6c64dd0cf433c258d52ef0d8c5c52d2bf848d286addee4",
    "size": 7588952,
    "source_root": "J:\\BLD_11.9\\components\\ecc\\contrib\\handyiron\\",
    "key_source_files": [
        "internal/project/secCommon/src/sec_ssl_api.c",
        "internal/project/security/src/sec_certificate.c",
        "internal/project/security/src/sec_connection.c",
        "internal/project/security/src/sec_digital_signing.c",
        "internal/project/security/src/sec_random.c",
    ],
    "note": "Same handyiron codebase as Cisco IP phone firmware security layer",
}

# ─────────────────────────────────────────────────────────
# JAB-F14 — handyiron "ANY role" TLS cert bypass (CANDIDATE)
# ─────────────────────────────────────────────────────────
JAB_F14_ANY_ROLE_BYPASS = {
    "id":        "JAB-F14",
    "product":   "Cisco Jabber Windows 11.9.1",
    "dll":       "enhanced-callcontrol_MD.dll",
    "function":  "secSSLCertVerify (sec_ssl_api.c)",
    "severity":  "HIGH — TLS cert accepted without validation when role == ANY",
    "class":     "TLS Certificate Verification Bypass",

    # Two cert verification entry points, both bypass on same condition
    "entry_points": {
        "secSSLCertVerify": {
            "log_role_check":  "SSL session setup Cert Verification - Role is = %d",
            "bypass_no_plugin": "SSL session setup Cert Verification - Accept Authenticator cert. without validation - no certificate validation plugin available.",
            "bypass_any_role":  "SSL session setup Cert Verification - Accept Authenticator cert. without validation - any role is specified.",
            "normal_path_ext":  "SSL session setup Cert Verification - Invoking external certificate validation plugin.",
            "normal_path_ctl":  "SSL session setup Cert Verification - CTL file certificate is valid.",
        },
        "SecSSLValidateCertsForPeers": {
            "log_role_check":  "Role is = %d",
            "inner_function":  "verifySessionPeerCertUsingValidationHelperPlugin",
            "bypass_no_plugin": "Not validating the cert - no certificate validation plugin available.",
            "bypass_any_role":  "Not validating the cert - ANY role is specified.",
        },
    },

    # Bypass conditions (either is sufficient)
    "bypass_conditions": [
        "role parameter == eCCMSIPServiceRoleAny (integer 0 or equivalent 'any' enum)",
        "no certificate validation plugin registered (eNoCertificateVerifierSpecified state)",
    ],

    "shared_with_phones": True,
    "note": (
        "handyiron is the shared security library for Cisco Unified Communications endpoints. "
        "The same ANY-role bypass path exists in 7945/7965/7970/7971/8941/8945 phone firmware. "
        "Role value is provisioned by CTL/ITL or CUCM config — if attacker controls TFTP/CUCM "
        "config delivery, role can be set to ANY to bypass cert validation on all TLS connections."
    ),
}

# ─────────────────────────────────────────────────────────
# JAB-F15 — CCMCIP.Host.CertLevel provisioned bypass (CANDIDATE)
# ─────────────────────────────────────────────────────────
JAB_F15_CERTLEVEL_BYPASS = {
    "id":      "JAB-F15",
    "product": "Cisco Jabber Windows 11.9.1",
    "dll":     "ConfigInfo.dll + utiltp.dll",
    "severity": "HIGH — EnableCertVerification(false) disables all TLS cert validation",
    "class":   "TLS Certificate Verification Bypass — TFTP config injection",

    "api": {
        "EnableCertVerification":  "?EnableCertVerification@@YAX_N@Z   (void, bool arg)",
        "IsCertVerificationEnabled": "?IsCertVerificationEnabled@@YA_NXZ  (bool return)",
        "SetCertState":            "?SetCertState@CCmTransportOpenSsl@@QAEX_N@Z  (in utiltp.dll)",
    },

    "config_keys": {
        "CCMCIP.Host.CertLevel":   "CUCM SIP/CCMCIP host cert level (provisioned via TFTP jabber-config.xml)",
        "MeetingPlace.CertLevel":  "MeetingPlace server cert level",
        "log_string":              "cert, enable-verification: <value>",
    },

    # TFTP-provisioned jabber-config.xml attack path
    "attack_path": (
        "Attacker controls TFTP server delivering jabber-config.xml. "
        "Setting CCMCIP.Host.CertLevel=0 in the XML config is read by ConfigInfo.dll, "
        "which calls EnableCertVerification(false), disabling TLS cert verification for "
        "all CUCM/CAPF connections via CCmTransportOpenSsl::SetCertState(false). "
        "Requires MitM position on TFTP delivery or rogue CUCM provisioning."
    ),

    "notes": [
        "cert, enable-verification: log line emitted on every config load",
        "utiltp.dll: CCmTransportOpenSsl is the OpenSSL transport wrapper in jabberwerx SDK",
        "Source: J:\\BLD_11.9\\components\\jabberwerx\\utils\\platform\\utiltp\\CmTransportOpenSsl.cpp",
    ],
}

# ─────────────────────────────────────────────────────────
# JAB-F16 — IgnoreInvalidCertConditionPolicy configurable suppressors
# ─────────────────────────────────────────────────────────
JAB_F16_IGNORE_CERT_POLICY = {
    "id":      "JAB-F16",
    "product": "Cisco Jabber Windows 11.9.1",
    "dll":     "csfnetutils.dll",
    "severity": "MEDIUM — cert error suppression configurable via policy objects",
    "class":   "TLS Certificate Verification Softening",

    "source_file": "J:\\BLD_11.9\\components\\csf-netutils\\src\\cert\\IgnoreInvalidCertConditionPolicy.cpp",

    "suppressor_policies": {
        "IGNORE_REVOCATION_INFO_UNAVAILABLE_ERRORS": "Suppresses OCSP/CRL unavailable errors",
        "IGNORE_WRONG_KEY_USAGE_ERRORS_POLICY":       "Suppresses key usage validation failures",
        "IGNORE_WEAK_KEY_ERRORS_POLICY":              "Suppresses weak key strength rejections",
        "IGNORE_INVALID_CERT_CONDITION":              "Base suppression policy object",
        "DO_NOT_IGNORE_FALURE_CONDITIONS":            "Explicit 'enforce' policy (note: typo in symbol)",
    },

    "failure_management": {
        "ALWAYS_IGNORE_FAILURE": "Always ignore cert failure — highest permissiveness",
        "IGNORE_SOFT_FAILURE":   "Ignore soft failures (self-signed, expiry, etc.)",
        "IGNORE_HARD_FAILURE":   "Ignore hard failures (revoked, untrusted root)",
        "NEVER_IGNORE_FAILURE":  "Enforce all failures",
    },

    "user_interaction_policy": {
        "class": "UserInteractingInvalidCertManagementPolicy",
        "class_without_interaction": "verifyEnforceabilityWithoutUserInteraction",
        "decision_persistence": "PersistInvalidCertDecisionPolicy — user acceptance cached",
    },

    "note": (
        "Policy objects injected into the verification pipeline via policy store. "
        "ALWAYS_IGNORE_FAILURE is a static singleton — if injected or misconfigured, "
        "all cert failures are silently suppressed without user prompt."
    ),
}

# ─────────────────────────────────────────────────────────
# JAB-F17 — NoCertificateVerifier state (TelephonyService)
# ─────────────────────────────────────────────────────────
JAB_F17_NO_CERT_VERIFIER = {
    "id":      "JAB-F17",
    "product": "Cisco Jabber Windows 11.9.1",
    "dll":     "services/TelephonyService/TelephonyService.dll",
    "severity": "HIGH — NoCertificateVerifier state: no cert validation plugin → cert accepted",
    "class":   "TLS Certificate Verification Absent",

    "states": {
        "NoCertificateVerifier":     "No cert verifier available — falls through to accept in secSSLCertVerify",
        "FIPSNoCertificateVerifier": "FIPS mode variant — no verifier available in FIPS context",
        "eNoCertificateVerifierSpecified": "AuthenticationStatus enum value (enhanced-callcontrol_MD.dll)",
    },

    "trigger": (
        "When CertificateVerificationHelper cannot register an external verifier, "
        "secSSLCertVerify takes the no-plugin bypass path and accepts the cert without validation. "
        "This is structurally identical to CIPC-F01 (SECAddTvsServer returns -1) and "
        "PHN-F04 (libsecurity.so SECAddTvsServer not implemented on 894x)."
    ),

    "shared_pattern": "NoCertificateVerifier bypass = CIPC-F01 = PHN-F04 class of finding",
}

# ─────────────────────────────────────────────────────────
# CertificateVerificationHelper two-pass flow
# ─────────────────────────────────────────────────────────
CERT_VERIFICATION_HELPER = {
    "dll":     "enhanced-callcontrol_MD.dll",
    "source":  "J:\\BLD_11.9\\components\\ecc\\src\\config\\CertificateVerificationHelper.cpp",

    "flow": {
        "verifyFirstPass": {
            "fips_mode_capf":  "In FIPS mode CAPF server certificate for <host> must be verified externally.",
            "non_fips_capf":   "Current security policy requires that the CAPF server certificate for <host> <may/needs to> be verified externally.",
            "edge_mode_cucm":  "In Edge Mode CUCM (SIP) server certificate for <host> needs to be verified externally only.",
        },
        "verifySecondPass": {
            "reject_missing_verifier": "Missing required external verifier. Rejecting CAPF server certificate for <host>.",
            "success":                 "External verification succeeded for CAPF server cert <host>",
            "fallback":                "External verification of CAPF server certificate for <host> failed",
        },
        "verifyCertificate": {
            "invalid_sip_cert":   "Invalid SIP certificate",
            "name_check":         "Certificate name: <name>",
            "null_verifier":      "certVerifier is NULL.",
        },
    },

    "tvs_path": {
        "not_enabled":     "VALIDATE CERT - TVS not enabled",
        "role_exclusion":  "not using TVS for cert validation - role is TVS or SRST",
        "tvs_used":        "Using TVS for cert validation",
        "tvs_failed":      "Failed to validate cert using TVS",
        "not_in_tl":       "Not using TVS - TVS not in Trust list",
    },
}

# ─────────────────────────────────────────────────────────
# csfnetutils.dll — HTTP/XMPP cert verification layer
# ─────────────────────────────────────────────────────────
CSFNETUTILS_CERT_LAYER = {
    "dll":    "csfnetutils.dll",
    "sha256": "f1f36a878e4fa9e0d927a0c9b2aaefb9a018773bf48b511d23a31b88bc926405",
    "size":   1415768,
    "source_root": "J:\\BLD_11.9\\components\\csf-netutils\\src\\",

    "ssl_verify_callback": "csf::http::SslUtils::verifyCb  (SslUtils.cpp)",
    "http_cert_adapter":   "csf::netutils::adapters::HttpCertAdapter::verifyCertificate",
    "xmpp_verifier":       "csf::cert::XmppCertVerifier::verifyXmppCertificate[Async]",

    "protocols_enforced": {
        "SSLv2":   "DISABLED (SSL_OP_NO_SSLv2)",
        "SSLv3":   "DISABLED (SSL_OP_NO_SSLv3)",
        "TLSv1":   "optional (SSL_OP_NO_TLSv1 flag present but may not be set)",
        "TLSv1.1": "optional",
        "TLSv1.2": "enabled",
    },

    "note": "Protocol enforcement is in csfnetutils; the accept-all bypass is in handyiron. Two separate layers.",
}

# ─────────────────────────────────────────────────────────
# DLL callers of cmcrypto VerifyCertificateEx
# ─────────────────────────────────────────────────────────
VERIFY_CERT_CALLERS = {
    "cmcrypto.dll":   "DEFINES VerifyCertificateEx (ICmCrypto interface)",
    "conhelp.dll":    "CALLS VerifyCertificate — connection helper layer",
    "XmppSDK.dll":    "CALLS verifyXmppCertificate[Async] — XMPP TLS path",
    "ConfigInfo.dll": "CALLS VerifyCertificate — config validation",
    "csfnetutils.dll": "IMPORTS ICmCrypto — HTTP/XMPP/Edge TLS layer",
    "utiltp.dll":     "CALLS EnableCertVerification/IsCertVerificationEnabled",
}

# ─────────────────────────────────────────────────────────
# Comparison to JAB-F13 (Android) and CIPC/PHN findings
# ─────────────────────────────────────────────────────────
CROSS_PLATFORM_COMPARISON = {
    "JAB-F13 (Android)": {
        "mechanism":  "disableFingerprintVerification JVM flag",
        "scope":      "Android Jabber, device config XML",
        "confirmed":  True,
    },
    "JAB-F14 (Windows)": {
        "mechanism":  "secSSLCertVerify ANY-role bypass (handyiron sec_ssl_api.c)",
        "scope":      "Windows Jabber, CTL/CUCM-provisioned role parameter",
        "confirmed":  "CANDIDATE — static analysis; live device confirmation required",
    },
    "JAB-F15 (Windows)": {
        "mechanism":  "EnableCertVerification(false) via CCMCIP.Host.CertLevel=0",
        "scope":      "Windows Jabber, TFTP-provisioned jabber-config.xml",
        "confirmed":  "CANDIDATE — static analysis",
    },
    "CIPC-F01": {
        "mechanism":  "SECAddTvsServer returns -1 unconditionally (TVS structurally absent)",
        "scope":      "CIPC Windows 8.6.5.0",
        "confirmed":  True,
    },
    "PHN-F04": {
        "mechanism":  "libsecurity.so SECAddTvsServer not implemented on 894x",
        "scope":      "8941/8945 SIP and SCCP",
        "confirmed":  True,
    },
    "PHN-F04-CIPC class in JAB-F17": {
        "mechanism":  "NoCertificateVerifier state — no plugin → cert accepted in secSSLCertVerify",
        "scope":      "Windows Jabber TelephonyService",
        "confirmed":  "CANDIDATE",
    },
}
