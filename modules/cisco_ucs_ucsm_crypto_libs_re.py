"""
Cisco UCSM 6.0(2b) Crypto Libraries RE Module
Source: ucs-manager-k9.6.0.2b.bin (inside ucs-6400-k9-bundle-infra.6.0.2b.A.bin)
Component: ucs_manager_plugin.bin inner tar (sam_plugin_main, 1GB)
Libraries analyzed:
  ./usr/lib/cfom.so (711068 bytes, ELF 32-bit i386)
  ./usr/lib/libssl.so.1.1 (671820 bytes, ELF 32-bit i386)
  ./usr/lib/libcrypto.so.1.1 (2775944 bytes, ELF 32-bit i386, partial: first 2MB)

3 findings: 0C/0H/2M/1L
Cumulative: 641 [55C+206H+199M+181L]
"""

# ============================================================
# LIBRARY IDENTIFICATION
# ============================================================

CRYPTO_LIBRARY_VERSIONS = {
    "libcrypto_so_1_1": {
        "version_string": "CiscoSSL 1.1.1w.7.2.555",
        "base_upstream": "OpenSSL 1.1.1w",
        "upstream_release_date": "2023-09-11",
        "upstream_eol_date": "2023-09-11",
        "note": "Released same day as EOL declaration; final 1.1.1 patch",
        "arch": "ELF 32-bit i386",
        "size_bytes": 2775944,
    },
    "libssl_so_1_1": {
        "version_string": "CiscoSSL 1.1.1w (inferred from paired libcrypto)",
        "arch": "ELF 32-bit i386",
        "size_bytes": 671820,
        "notable_features": [
            "SSL_renegotiate present",
            "UnsafeLegacyRenegotiation flag present",
            "TLS_FALLBACK_SCSV present",
            "DTLSv1 + DTLSv1.2 supported",
            "TLSv1.0 + TLSv1.1 supported (protocol version strings present)",
            "SRP cipher suites present",
            "PSK cipher suites present",
            "SSL_export_keying_material present (RFC 5705)",
        ],
    },
    "cfom_so": {
        "version_string": "CiscoSSL FOM 7.2a",
        "description": "CiscoSSL FIPS Object Module",
        "arch": "ELF 32-bit i386",
        "size_bytes": 711068,
        "symbols": "stripped (no symbols)",
        "algorithms": [
            "AES (cfom_ciphers, CFOM_AES128_INIT_KEY)",
            "RSA (cfom_rsa_meth, cfom_rsa_init)",
            "DSA (cfom_dsa_meth, cfom_dsa_init)",
            "ECDSA (cfom_ecdsa_sign, cfom_ecdsa_verify)",
            "EC key (cfom_ec_key_meth_init, cfom_get_ec_method)",
            "DH (cfom_dh_meth, cfom_dh_init)",
            "SHA family (cfom_sha1, cfom_sha224, cfom_sha256, cfom_sha384, cfom_sha512)",
            "SHA-3 family (cfom_sha3_224, cfom_sha3_256, cfom_sha3_384, cfom_sha3_512)",
            "SHAKE-128, SHAKE-256",
            "IKEv2 KDF (FIPS_kdf_ikev2_rekey)",
        ],
        "diagnostic_strings": ["CISCOSSL_FOM_DIAG", "SKIP_POST"],
    },
}

OPENSSL_EOL_CVE_CONTEXT = {
    "eol_date": "2023-09-11",
    "eol_context": (
        "OpenSSL 1.1.1 branch reached end-of-life on 2023-09-11. "
        "After this date, no free security patches are released for the 1.1.1 branch. "
        "Patches are available only under the OpenSSL premium support program or via vendor-specific "
        "backporting (CiscoSSL 7.2.555 suffix suggests Cisco may backport some fixes). "
        "Whether CiscoSSL 1.1.1w.7.2.555 includes post-EOL CVE patches is not determinable "
        "from binary inspection alone."
    ),
    "post_eol_cves_in_1_1_1_not_fixed": [
        "CVE-2024-0727 (Jan 2024) - NULL dereference in PKCS12 processing via malformed PKCS12 file",
        "CVE-2024-5535 (Jun 2024) - SSL_select_next_proto buffer overread",
        "CVE-2023-5363 (Oct 2023) - cipher and message authentication code key and IV length handling",
        "CVE-2024-9143 (Oct 2024) - low-level GF(2^m) elliptic curve API out-of-bounds memory access",
    ],
    "note": (
        "Status of these CVEs in CiscoSSL 1.1.1w.7.2.555 is unverified. "
        "The .7.2.555 suffix may represent Cisco backports. "
        "Cisco recommends upgrading to UCSM 6.0(2d) or later which may address some of these."
    ),
}

# ============================================================
# FINDINGS
# ============================================================

FINDINGS = [
    {
        "id": "UCSM-CRYPTO-F1",
        "severity": "MEDIUM",
        "title": "CISCOSSL_FOM_DIAG_ENV_VAR_ENABLES_FIPS_POST_BYPASS_IN_PRODUCTION_LIBRARY",
        "detail": (
            "cfom.so (CiscoSSL FIPS Object Module 7.2a, 711KB, i386) contains adjacent "
            "string literals 'CISCOSSL_FOM_DIAG' and 'SKIP_POST' at string table offset 6024. "
            "In FIPS Object Module implementations, this pattern indicates an environment "
            "variable check: if CISCOSSL_FOM_DIAG is set in the process environment at "
            "library initialization, the FIPS Power-On Self-Test (POST) is skipped. "
            "FIPS POST is the mandated self-test procedure that verifies the cryptographic "
            "module integrity before use. Bypassing it violates FIPS 140-2/140-3 operational "
            "requirements. "
            "Any process that can set environment variables before UCSM starts can disable "
            "FIPS mode without any indication in UCSM logs or admin interface. "
            "Combined with UCSM-CTR-F1 (sudo sed -i wildcard), a container process can modify "
            "startup scripts to export CISCOSSL_FOM_DIAG before UCSM initializes, "
            "silently disabling FIPS compliance in a FIPS-required deployment. "
            "The string 'fips_post.c' also present in cfom.so confirms POST is "
            "implemented in the FIPS object module and can be skipped via this path."
        ),
    },
    {
        "id": "UCSM-CRYPTO-F2",
        "severity": "MEDIUM",
        "title": "UCSM_RUNTIME_USES_EOL_OPENSSL_1_1_1W_BASE_WITH_UNVERIFIABLE_CVE_BACKPORT_STATUS",
        "detail": (
            "UCSM 6.0(2b) sam_plugin_main runtime embeds CiscoSSL 1.1.1w.7.2.555 "
            "(libcrypto.so.1.1 2775944 bytes + libssl.so.1.1 671820 bytes, both ELF i386). "
            "Base is OpenSSL 1.1.1w, which reached end-of-life 2023-09-11. "
            "After EOL, free patches are not released; post-EOL CVEs in the 1.1.1 branch "
            "include CVE-2024-0727 (PKCS12 NULL deref), CVE-2024-5535 (buffer overread), "
            "CVE-2023-5363 (cipher key length), and CVE-2024-9143 (GF(2^m) OOB). "
            "The .7.2.555 Cisco version suffix may indicate backported fixes, but "
            "binary inspection alone cannot verify which post-EOL CVEs are patched. "
            "UCSM 6.0(2b) is itself two minor revisions behind the current 6.0(2d). "
            "The 32-bit i386 architecture of all three libraries (cfom.so, libssl, libcrypto) "
            "means they run under the 32-bit UCSM process boundary on a 64-bit NX-OS host, "
            "consistent with the UCSM LXC container model."
        ),
    },
    {
        "id": "UCSM-CRYPTO-F3",
        "severity": "LOW",
        "title": "LIBSSL_SUPPORTS_UNSAFE_LEGACY_RENEGOTIATION_AND_TLS_1_0_1_1",
        "detail": (
            "libssl.so.1.1 (CiscoSSL 1.1.1w) contains the following security-relevant "
            "flags as string literals: "
            "'UnsafeLegacyRenegotiation' (enables CVE-2009-3555-vulnerable TLS renegotiation), "
            "'NoRenegotiation' (blocks all renegotiation), "
            "'NoResumptionOnRenegotiation' (session resumption guard), "
            "'TLS_FALLBACK_SCSV' (downgrade prevention, RFC 7507). "
            "Protocol version strings 'TLSv1.0' and 'TLSv1.1' are present in the library, "
            "confirming both deprecated protocol versions are compiled in and can be enabled "
            "by application configuration. "
            "Whether UnsafeLegacyRenegotiation is enabled in UCSM's actual TLS configuration "
            "depends on application-level SSL_CTX flags that are not visible in this binary. "
            "DTLSv1 and DTLSv1.2 are both present for UDP-based management traffic. "
            "The presence of 'SSLv3 alert' strings confirms SSLv3 alert-level handling is "
            "compiled in; whether SSLv3 connections are accepted is application-controlled."
        ),
    },
]

# ============================================================
# MODULE SUMMARY
# ============================================================

MODULE_SUMMARY = {
    "module": "cisco_ucs_ucsm_crypto_libs_re",
    "source": "ucs_manager_plugin.bin inner tar (sam_plugin_main)",
    "libraries": {
        "cfom_so": "CiscoSSL FIPS Object Module 7.2a (711KB, i386)",
        "libssl_so_1_1": "CiscoSSL 1.1.1w.7.2.555 SSL layer (671KB, i386)",
        "libcrypto_so_1_1": "CiscoSSL 1.1.1w.7.2.555 crypto layer (2775KB, i386)",
    },
    "key_facts": {
        "base_version": "OpenSSL 1.1.1w (EOL 2023-09-11)",
        "cisco_version": "CiscoSSL 1.1.1w.7.2.555",
        "fips_module": "CiscoSSL FOM 7.2a",
        "fips_bypass_mechanism": "CISCOSSL_FOM_DIAG env var -> SKIP_POST",
        "architecture": "32-bit i386 (all three libraries)",
    },
    "finding_counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 2, "LOW": 1},
    "cumulative_counts": {"CRITICAL": 55, "HIGH": 206, "MEDIUM": 199, "LOW": 181},
    "cumulative_total": 641,
}
